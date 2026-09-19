package mt.safety.scanner.core;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs a full scan of one package, or of a whole set of them.
 *
 * <p>This is the only entry point the user interface needs. Everything it depends on is plain Java, so
 * the same code runs inside MT Manager on a phone and from the command line on a desktop.
 */
public final class PluginScanner {

    private final IocDatabase database;

    public PluginScanner(IocDatabase database) {
        this.database = database == null ? IocDatabase.empty() : database;
    }

    /** Scans one package: a {@code .mtp} file or an installed plugin directory. */
    public ScanReport scan(File path, ScanBudget budget) {
        long started = System.currentTimeMillis();
        PluginPackage pkg = null;
        try {
            pkg = PluginPackage.open(path);
            List<PluginPackage.Entry> entries = pkg.entries();

            // A package zipped with a wrapping folder is still a plugin; normalise before judging.
            String prefix = findRootPrefix(entries);
            if (prefix != null) {
                pkg = PluginPackage.rooted(pkg, prefix);
                entries = pkg.entries();
            }

            PluginManifest manifest = readManifest(pkg, entries, budget);
            String hash;
            try {
                hash = pkg.contentHash();
            } catch (IOException e) {
                hash = "";
            }

            ScanReport report = new ScanReport(pkg.label(), path.getAbsolutePath(), pkg.archive(),
                    manifest, hash);
            if (prefix != null) {
                report.add(new Signal("ARC008", Category.ARCHIVE, Severity.LOW,
                        "Plugin contents sit inside a wrapping folder",
                        "MT Manager expects manifest.json at the top of the package. This one is nested, which"
                                + " usually means it was rezipped after being unpacked.")
                        .withEvidence("archive", prefix));
            }

            ManifestRules.apply(report, manifest, entries);
            ArchiveRules.apply(report, pkg, entries, budget);
            int scanned = CodeRules.apply(report, pkg, entries, budget, database);

            report.setFilesScanned(scanned);
            report.setTruncated(budget.wasTruncated());
            if (report.truncated()) {
                report.add(new Signal("SCN001", Category.PROVENANCE, Severity.INFO,
                        "The scan did not read the whole package",
                        "The package was too large, or too slow to read, to examine completely. Findings below"
                                + " are real, but absence of findings proves less than usual."));
            }
            for (int i = 0; i < database.loadErrors().size(); i++) {
                report.addError(database.loadErrors().get(i));
            }

            RiskScorer.score(report, database);
            report.setElapsedMs(System.currentTimeMillis() - started);
            return report;
        } catch (IOException e) {
            ScanReport report = new ScanReport(path.getName(), path.getAbsolutePath(), !path.isDirectory(),
                    PluginManifest.missing(), "");
            report.addError("could not open the package: " + e.getMessage());
            report.setVerdict(Verdict.UNREADABLE, "The package could not be opened: " + e.getMessage());
            report.setElapsedMs(System.currentTimeMillis() - started);
            return report;
        } catch (RuntimeException e) {
            // A malformed package must never take the host application down with it.
            ScanReport report = new ScanReport(path.getName(), path.getAbsolutePath(), !path.isDirectory(),
                    PluginManifest.missing(), "");
            report.addError("the package could not be parsed: " + e);
            report.setVerdict(Verdict.UNREADABLE, "The package could not be parsed safely.");
            report.setElapsedMs(System.currentTimeMillis() - started);
            return report;
        } finally {
            if (pkg != null) {
                pkg.close();
            }
        }
    }

    /**
     * Scans several packages and applies the checks that only make sense across a set.
     *
     * <p>Each package gets its own share of the budget so one huge plugin cannot starve the rest.
     */
    public List<ScanReport> scanAll(List<File> paths, ScanBudget budget) {
        List<ScanReport> reports = new ArrayList<ScanReport>();
        for (int i = 0; i < paths.size(); i++) {
            reports.add(scan(paths.get(i), budget));
        }
        finishSet(reports);
        return reports;
    }

    /**
     * Applies the checks that only make sense once every package has been seen.
     *
     * <p>Callers that give each package its own budget, as the on-device interface does so that one
     * large plugin cannot starve the rest, run this themselves after their scanning loop.
     */
    public void finishSet(List<ScanReport> reports) {
        ManifestRules.applyLookalikeCheck(reports);
        // Lookalike findings arrive after the first pass, so anything affected is rescored.
        for (int i = 0; i < reports.size(); i++) {
            ScanReport report = reports.get(i);
            if (report.hasRule("MFT011")) {
                RiskScorer.score(report, database);
            }
        }
    }

    private PluginManifest readManifest(PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget) {
        for (PluginPackage.Entry entry : entries) {
            if (!entry.directory && entry.name.equals("manifest.json")) {
                try {
                    return PluginManifest.parse(pkg.read(entry, 512 * 1024, budget));
                } catch (IOException e) {
                    return PluginManifest.broken("could not be read: " + e.getMessage());
                }
            }
        }
        return PluginManifest.missing();
    }

    /** Returns the single wrapping directory holding manifest.json, or null when there is none. */
    private static String findRootPrefix(List<PluginPackage.Entry> entries) {
        for (PluginPackage.Entry entry : entries) {
            if (entry.name.equals("manifest.json")) {
                return null;
            }
        }
        for (PluginPackage.Entry entry : entries) {
            String name = entry.name;
            if (entry.directory || !name.endsWith("/manifest.json")) {
                continue;
            }
            String prefix = name.substring(0, name.length() - "manifest.json".length());
            // Only a single wrapping level; deeper nesting is not a repackaged plugin.
            if (prefix.indexOf('/') == prefix.length() - 1) {
                return prefix;
            }
        }
        return null;
    }
}
