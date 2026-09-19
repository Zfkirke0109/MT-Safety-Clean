package mt.safety.scanner;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import mt.safety.scanner.core.Discovery;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Severity;
import mt.safety.scanner.core.Signal;
import mt.safety.scanner.core.Verdict;

/**
 * Drives a scan and turns the result into rows a settings screen can show.
 *
 * <p>MT Manager builds a plugin's settings screen once, through a single {@code onBuild} call, with no
 * buttons and no way to refresh from code. That constraint shapes the whole interaction:
 *
 * <ul>
 *   <li>Opening the screen <i>is</i> the scan. Re-opening it rescans.
 *   <li>Actions are typed into one text field and run the next time the screen opens, with the outcome
 *       shown at the top. One field means a half-typed command cannot quarantine anything.
 * </ul>
 *
 * <p>Nothing here references an MT Manager class, so it can be tested on a desktop JVM.
 */
public final class ScanRunner {

    /** Config keys. */
    public static final String KEY_COMMAND = "command";
    public static final String KEY_DEEP = "deep_scan";
    public static final String KEY_EXTRA_ROOT = "extra_root";
    public static final String KEY_LAST_RESULT = "last_result";

    /** Total interactive time budget shared out across the plugins found. */
    private static final long INTERACTIVE_TOTAL_MS = 6000L;
    private static final long DEEP_TOTAL_MS = 30000L;
    private static final long BYTES_PER_PLUGIN = 16L * 1024 * 1024;

    /** One line of the settings screen. */
    public static final class Row {
        public final boolean header;
        public final String title;
        public final String summary;

        private Row(boolean header, String title, String summary) {
            this.header = header;
            this.title = title;
            this.summary = summary;
        }

        public static Row header(String title) {
            return new Row(true, title, null);
        }

        public static Row text(String title, String summary) {
            return new Row(false, title, summary);
        }
    }

    /** The outcome of one screen build. */
    public static final class Result {
        /** Findings, worst plugin first. */
        public final List<Row> rows = new ArrayList<Row>();
        /** Configuration and limitations, shown after the action widgets. */
        public final List<Row> aboutRows = new ArrayList<Row>();
        public final List<ScanReport> reports = new ArrayList<ScanReport>();
        public String commandOutcome = "";
    }

    private final Host host;
    private final Strings strings;

    public ScanRunner(Host host) {
        this.host = host;
        this.strings = Strings.forLanguage(host.language());
    }

    public Strings strings() {
        return strings;
    }

    /** Runs any pending command, then scans, then builds the rows to display. */
    public Result run() {
        Result result = new Result();
        File configFile = new File(host.filesDir(), "indicators.json");
        IocDatabase database = IocDatabase.load(configFile);

        String pending = host.config(KEY_COMMAND, "");
        if (pending != null && pending.trim().length() > 0) {
            // Cleared first: a command that somehow crashes must not run again on every open.
            host.putConfig(KEY_COMMAND, "");
            result.commandOutcome = runCommand(pending.trim(), database, configFile);
            host.putConfig(KEY_LAST_RESULT, result.commandOutcome);
            host.log("command: " + pending.trim() + " -> " + result.commandOutcome);
        } else {
            result.commandOutcome = host.config(KEY_LAST_RESULT, "");
        }

        boolean deep = host.configFlag(KEY_DEEP, false);
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.config(KEY_EXTRA_ROOT, ""));
        List<Discovery.Candidate> candidates = MtEnvironment.findPlugins(roots, host.pluginId());

        PluginScanner scanner = new PluginScanner(database);
        long totalMs = deep ? DEEP_TOTAL_MS : INTERACTIVE_TOTAL_MS;
        long slice = candidates.isEmpty() ? totalMs : Math.max(500L, totalMs / candidates.size());
        for (int i = 0; i < candidates.size(); i++) {
            ScanBudget budget = new ScanBudget(slice, BYTES_PER_PLUGIN);
            result.reports.add(scanner.scan(candidates.get(i).path, budget));
        }
        scanner.finishSet(result.reports);

        buildRows(result, database, roots, candidates.size());
        return result;
    }

    // ------------------------------------------------------------------ display

    private void buildRows(Result result, IocDatabase database, List<File> roots, int candidateCount) {
        List<Row> rows = result.rows;

        if (result.commandOutcome != null && result.commandOutcome.length() > 0) {
            rows.add(Row.header(strings.lastAction()));
            rows.add(Row.text(result.commandOutcome, ""));
        }

        rows.add(Row.header(strings.summaryHeader()));
        if (candidateCount == 0) {
            rows.add(Row.text(strings.nothingFound(), strings.nothingFoundHelp()));
        } else {
            rows.add(Row.text(ReportFormatter.overview(result.reports), strings.scannedIn(elapsed(result))));
        }

        // Worst first, so the thing that matters is the first thing on screen.
        List<ScanReport> ordered = orderByRisk(result.reports);
        for (int i = 0; i < ordered.size(); i++) {
            ScanReport report = ordered.get(i);
            rows.add(Row.header(verdictMarker(report) + " " + report.manifest.displayName()));
            rows.add(Row.text(strings.verdictLabel() + ": " + report.verdict().label()
                    + "  (" + report.score() + ")", report.verdict().advice()));
            if (report.manifest.pluginId.length() > 0) {
                rows.add(Row.text(report.manifest.pluginId,
                        strings.versionLabel() + ": "
                                + (report.manifest.versionName.length() > 0
                                        ? report.manifest.versionName : "?")));
            }

            List<Signal> signals = report.signalsBySeverity();
            int shown = 0;
            for (int j = 0; j < signals.size(); j++) {
                Signal signal = signals.get(j);
                if (signal.severity == Severity.INFO && shown > 0) {
                    continue;
                }
                if (shown >= 8) {
                    rows.add(Row.text(strings.moreFindings(signals.size() - shown), ""));
                    break;
                }
                rows.add(Row.text(signal.severity.marker() + " " + signal.title, evidenceLine(signal)));
                shown++;
            }
            if (report.truncated()) {
                rows.add(Row.text(strings.incomplete(), ""));
            }
            for (int j = 0; j < report.errors.size() && j < 3; j++) {
                rows.add(Row.text(strings.problem(), report.errors.get(j)));
            }
            rows.add(Row.text(strings.pathLabel(), report.path));
            rows.add(Row.text(strings.hashLabel(), shortHash(report.contentHash)));
        }

        List<Row> about = result.aboutRows;
        about.add(Row.header(strings.aboutHeader()));
        about.add(Row.text(strings.trustCounts(database.trustedCount(), database.deniedCount()),
                new File(host.filesDir(), "indicators.json").getAbsolutePath()));
        about.add(Row.text(strings.rootsSearched(roots.size()), describeRoots(roots)));
        about.add(Row.text(strings.selfExcluded(), host.pluginId()));
        about.add(Row.text(strings.limitsTitle(), strings.limits()));
    }

    private String elapsed(Result result) {
        long total = 0;
        for (int i = 0; i < result.reports.size(); i++) {
            total += result.reports.get(i).elapsedMs();
        }
        return total + " ms";
    }

    private static List<ScanReport> orderByRisk(List<ScanReport> reports) {
        List<ScanReport> sorted = new ArrayList<ScanReport>(reports);
        java.util.Collections.sort(sorted, new java.util.Comparator<ScanReport>() {
            @Override
            public int compare(ScanReport a, ScanReport b) {
                int byScore = b.score() - a.score();
                if (byScore != 0) {
                    return byScore;
                }
                return a.manifest.displayName().compareToIgnoreCase(b.manifest.displayName());
            }
        });
        return sorted;
    }

    private static String verdictMarker(ScanReport report) {
        Verdict verdict = report.verdict();
        if (verdict == Verdict.KNOWN_BAD || verdict == Verdict.LIKELY_MALICIOUS) {
            return "[!!!]";
        }
        if (verdict == Verdict.SUSPICIOUS) {
            return "[!! ]";
        }
        if (verdict == Verdict.REVIEW) {
            return "[!  ]";
        }
        if (verdict == Verdict.UNREADABLE) {
            return "[ ? ]";
        }
        return "[ ok]";
    }

    private static String evidenceLine(Signal signal) {
        List<Signal.Evidence> evidence = signal.evidence();
        if (evidence.isEmpty()) {
            return signal.detail;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(evidence.get(0).where);
        if (evidence.get(0).snippet.length() > 0) {
            sb.append("  |  ").append(evidence.get(0).snippet);
        }
        if (evidence.size() > 1) {
            sb.append("   (+").append(evidence.size() - 1).append(")");
        }
        return sb.toString();
    }

    private static String shortHash(String hash) {
        if (hash == null || hash.length() < 16) {
            return "(none)";
        }
        return hash.substring(0, 16);
    }

    private static String describeRoots(List<File> roots) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < roots.size() && i < 4; i++) {
            if (sb.length() > 0) {
                sb.append("  ");
            }
            sb.append(roots.get(i).getAbsolutePath());
        }
        if (roots.size() > 4) {
            sb.append("  ...");
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ commands

    /** Executes one typed command and returns a sentence describing what happened. */
    private String runCommand(String command, IocDatabase database, File configFile) {
        String[] parts = command.split("\\s+", 2);
        String verb = parts[0].toLowerCase(java.util.Locale.US);
        String argument = parts.length > 1 ? parts[1].trim() : "";
        Quarantine quarantine = new Quarantine(new File(host.filesDir(), "quarantine"));

        try {
            if (verb.equals("help")) {
                return strings.commandsHelp();
            }
            if (verb.equals("deep")) {
                host.putConfig(KEY_DEEP, "true");
                return strings.deepEnabled();
            }
            if (verb.equals("fast")) {
                host.putConfig(KEY_DEEP, "false");
                return strings.deepDisabled();
            }
            if (verb.equals("root")) {
                if (argument.length() == 0) {
                    host.putConfig(KEY_EXTRA_ROOT, "");
                    return strings.rootCleared();
                }
                File root = new File(argument);
                if (!root.isDirectory()) {
                    return strings.notADirectory(argument);
                }
                host.putConfig(KEY_EXTRA_ROOT, root.getAbsolutePath());
                return strings.rootAdded(root.getAbsolutePath());
            }
            if (verb.equals("trust") || verb.equals("untrust") || verb.equals("deny")) {
                return trustCommand(verb, argument, database, configFile);
            }
            if (verb.equals("quarantine")) {
                return quarantineCommand(argument, quarantine);
            }
            if (verb.equals("restore")) {
                Quarantine.Result result = quarantine.restore(argument);
                return result.message;
            }
            if (verb.equals("purge")) {
                Quarantine.Result result = quarantine.purge(argument);
                return result.message;
            }
            if (verb.equals("quarantined")) {
                return describeQuarantine(quarantine);
            }
            if (verb.equals("export")) {
                return exportCommand();
            }
            return strings.unknownCommand(verb);
        } catch (RuntimeException e) {
            host.log("command failed", e);
            return strings.commandFailed(String.valueOf(e.getMessage()));
        }
    }

    private String trustCommand(String verb, String argument, IocDatabase database, File configFile) {
        if (argument.length() == 0) {
            return strings.needsArgument(verb);
        }
        if (verb.equals("trust")) {
            database.trust(argument, "trusted from the scanner screen");
        } else if (verb.equals("untrust")) {
            database.untrust(argument);
        } else {
            database.deny(argument, "denied from the scanner screen");
        }
        try {
            database.save(configFile);
        } catch (IOException e) {
            return strings.couldNotSave(e.getMessage());
        }
        return strings.listUpdated(verb, argument);
    }

    /**
     * Quarantines the installed plugin whose id or folder name matches.
     *
     * <p>Resolved against the plugins actually discovered rather than against a path the user types, so
     * a typo cannot move an unrelated directory.
     */
    private String quarantineCommand(String argument, Quarantine quarantine) {
        if (argument.length() == 0) {
            return strings.needsArgument("quarantine");
        }
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.config(KEY_EXTRA_ROOT, ""));
        List<Discovery.Candidate> candidates = MtEnvironment.findPlugins(roots, host.pluginId());
        for (int i = 0; i < candidates.size(); i++) {
            Discovery.Candidate candidate = candidates.get(i);
            if (!candidate.installed) {
                continue;
            }
            ScanReport report = new PluginScanner(IocDatabase.empty())
                    .scan(candidate.path, ScanBudget.interactive());
            boolean match = argument.equals(report.manifest.pluginId)
                    || argument.equals(candidate.path.getName())
                    || argument.equalsIgnoreCase(report.manifest.displayName());
            if (match) {
                Quarantine.Result result = quarantine.quarantine(candidate.path, host.pluginId());
                return result.message;
            }
        }
        return strings.noSuchPlugin(argument);
    }

    private String describeQuarantine(Quarantine quarantine) {
        List<Quarantine.Item> items = quarantine.list();
        if (items.isEmpty()) {
            return strings.quarantineEmpty();
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (sb.length() > 0) {
                sb.append("   ");
            }
            sb.append(items.get(i).pluginId.length() > 0
                    ? items.get(i).pluginId : items.get(i).directory.getName());
        }
        return sb.toString();
    }

    /** Writes the full report next to the plugin's configuration, for opening in MT Manager. */
    private String exportCommand() {
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.config(KEY_EXTRA_ROOT, ""));
        List<Discovery.Candidate> candidates = MtEnvironment.findPlugins(roots, host.pluginId());
        IocDatabase database = IocDatabase.load(new File(host.filesDir(), "indicators.json"));
        PluginScanner scanner = new PluginScanner(database);
        List<ScanReport> reports = new ArrayList<ScanReport>();
        for (int i = 0; i < candidates.size(); i++) {
            reports.add(scanner.scan(candidates.get(i).path, ScanBudget.deep()));
        }
        scanner.finishSet(reports);

        File textFile = new File(host.filesDir(), "scan-report.txt");
        File jsonFile = new File(host.filesDir(), "scan-report.json");
        try {
            write(textFile, ReportFormatter.plainText(reports));
            write(jsonFile, ReportFormatter.json(reports));
        } catch (IOException e) {
            return strings.couldNotSave(e.getMessage());
        }
        return strings.exported(textFile.getAbsolutePath());
    }

    private static void write(File file, String content) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("could not create " + parent.getAbsolutePath());
        }
        OutputStream out = new FileOutputStream(file);
        try {
            out.write(content.getBytes("UTF-8"));
        } finally {
            out.close();
        }
    }
}
