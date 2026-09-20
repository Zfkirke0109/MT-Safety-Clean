package mtsafety.cli;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import mt.safety.scanner.core.Discovery;
import mt.safety.scanner.core.PluginManifest;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Verdict;

/**
 * Command line front end to the same detection engine the plugin uses.
 *
 * <p>Its point is timing: the plugin can only examine a plugin that is already installed, and the
 * safest moment to look at an {@code .mtp} is before that. This runs anywhere with a JVM, including
 * Termux on the phone itself, and needs no Android SDK.
 *
 * <p>Exit status is meant for scripts: 0 when nothing needs action, 2 when something does, 1 on error.
 */
public final class MtSafetyCli {

    /** This scanner's own plugin id, skipped in discovery results unless --include-self is given. */
    private static final String SCANNER_PLUGIN_ID = "mt.safety.scanner";

    private static final int EXIT_OK = 0;
    private static final int EXIT_ERROR = 1;
    private static final int EXIT_ACTION_NEEDED = 2;

    public static void main(String[] args) {
        List<File> targets = new ArrayList<File>();
        List<File> discoverRoots = new ArrayList<File>();
        boolean json = false;
        boolean deep = false;
        boolean includeSelf = false;
        File indicators = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--json")) {
                json = true;
            } else if (arg.equals("--deep")) {
                deep = true;
            } else if (arg.equals("--include-self")) {
                includeSelf = true;
            } else if (arg.equals("--indicators")) {
                if (++i >= args.length) {
                    fail("--indicators needs a file path");
                    return;
                }
                indicators = new File(args[i]);
            } else if (arg.equals("--scan-dir")) {
                if (++i >= args.length) {
                    fail("--scan-dir needs a directory path");
                    return;
                }
                discoverRoots.add(new File(args[i]));
            } else if (arg.equals("-h") || arg.equals("--help")) {
                usage(System.out);
                System.exit(EXIT_OK);
                return;
            } else if (arg.startsWith("-")) {
                fail("unknown option: " + arg);
                return;
            } else {
                targets.add(new File(arg));
            }
        }

        if (targets.isEmpty() && discoverRoots.isEmpty()) {
            usage(System.err);
            System.exit(EXIT_ERROR);
            return;
        }

        List<File> packages = new ArrayList<File>(targets);
        if (!discoverRoots.isEmpty()) {
            List<Discovery.Candidate> found = new Discovery().find(discoverRoots);
            for (int i = 0; i < found.size(); i++) {
                packages.add(found.get(i).path);
            }
        }
        if (!includeSelf) {
            packages = withoutScanner(packages);
        }
        if (packages.isEmpty()) {
            System.err.println("No plugin packages found. An .mtp file, or a folder holding manifest.json.");
            System.exit(EXIT_ERROR);
            return;
        }

        IocDatabase database = indicators == null ? IocDatabase.empty() : IocDatabase.load(indicators);
        PluginScanner scanner = new PluginScanner(database);
        List<ScanReport> reports = new ArrayList<ScanReport>();
        for (int i = 0; i < packages.size(); i++) {
            // --deep lifts the limits; without it a generous but bounded budget keeps a hostile package
            // from running the tool forever. This was inverted before, so --deep scanned less.
            reports.add(scanner.scan(packages.get(i), deep ? ScanBudget.unlimited() : ScanBudget.deep()));
        }
        scanner.finishSet(reports);

        System.out.print(json ? ReportFormatter.json(reports) : ReportFormatter.plainText(reports));

        boolean actionNeeded = false;
        boolean unreadable = false;
        for (int i = 0; i < reports.size(); i++) {
            Verdict verdict = reports.get(i).verdict();
            if (verdict.actionable()) {
                actionNeeded = true;
            } else if (verdict == Verdict.UNREADABLE) {
                unreadable = true;
            }
        }
        // A package that could not be read is the read error the usage text promises to report. Silent
        // success there would tell a script everything was fine about something nothing examined.
        if (actionNeeded) {
            System.exit(EXIT_ACTION_NEEDED);
        }
        System.exit(unreadable ? EXIT_ERROR : EXIT_OK);
    }

    /**
     * Drops this scanner from a discovery result.
     *
     * <p>Its own catalogue contains every string it searches for, so scanning itself produces a page of
     * findings about the tool doing its job. {@code --include-self} turns this off.
     */
    private static List<File> withoutScanner(List<File> packages) {
        List<File> out = new ArrayList<File>();
        for (int i = 0; i < packages.size(); i++) {
            File file = packages.get(i);
            if (!SCANNER_PLUGIN_ID.equals(pluginIdOf(file))) {
                out.add(file);
            }
        }
        return out;
    }

    /**
     * Reads a package's plugin id, whether it is an unpacked directory or an .mtp archive.
     *
     * <p>Handling only directories meant a discovered copy of this scanner's own .mtp was scanned and
     * reported a page of findings about the tool's rule catalogue.
     */
    private static String pluginIdOf(File file) {
        return PluginManifest.readFrom(file).pluginId;
    }

    private static void usage(java.io.PrintStream out) {
        out.println("mtsafety - inspect MT Manager plugin packages");
        out.println();
        out.println("  mtsafety [options] <package>...");
        out.println();
        out.println("A package is an .mtp file or a folder containing manifest.json.");
        out.println();
        out.println("  --scan-dir DIR     also search DIR for plugins and .mtp files");
        out.println("  --indicators FILE  load your trusted/denied lists and extra patterns");
        out.println("  --deep             lift the read limits entirely (slower on huge packages)");
        out.println("  --json             machine-readable output");
        out.println("  --include-self     do not skip this scanner's own package");
        out.println();
        out.println("Exit status: 0 nothing to act on, 2 something needs action, 1 usage or read error.");
    }

    private static void fail(String message) {
        System.err.println("mtsafety: " + message);
        System.exit(EXIT_ERROR);
    }

    private MtSafetyCli() {
    }
}
