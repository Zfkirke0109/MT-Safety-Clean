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
    private final SignatureDatabase signatures;

    public PluginScanner(IocDatabase database) {
        this(database, null);
    }

    /**
     * A scanner that also checks every member against known-malware signatures.
     *
     * @param signatures a database in ClamAV's text formats, or null for none
     */
    public PluginScanner(IocDatabase database, SignatureDatabase signatures) {
        this.database = database == null ? IocDatabase.empty() : database;
        this.signatures = signatures == null ? SignatureDatabase.empty() : signatures;
    }

    /** The signature database this scanner matches against; empty when none was loaded. */
    public SignatureDatabase signatures() {
        return signatures;
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
            resolvePlaceholderName(manifest, pkg, entries, budget);
            String hash;
            try {
                hash = pkg.contentHash(budget);
            } catch (IOException e) {
                hash = "";
            }

            ScanReport report = new ScanReport(pkg.label(), path.getAbsolutePath(), pkg.archive(),
                    pkg.installed(), manifest, hash);
            if (prefix != null) {
                report.add(new Signal("ARC008", Category.ARCHIVE, Severity.LOW,
                        "Plugin contents sit inside a wrapping folder",
                        "MT Manager expects manifest.json at the top of the package. This one is nested, which"
                                + " usually means it was rezipped after being unpacked.")
                        .withEvidence("archive", prefix));
            }

            ManifestRules.apply(report, manifest, pkg, entries, budget);
            ArchiveRules.apply(report, pkg, entries, budget);
            int scanned = CodeRules.apply(report, pkg, entries, budget, database, signatures);

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
            String why = describeOpenFailure(e);
            ScanReport report = new ScanReport(path.getName(), path.getAbsolutePath(), looksArchive(path),
                    path.isDirectory(), PluginManifest.missing(), "");
            report.addError("could not open the package: " + why);
            report.setVerdict(Verdict.UNREADABLE, "The package could not be opened: " + why);
            report.setElapsedMs(System.currentTimeMillis() - started);
            return report;
        } catch (RuntimeException e) {
            // A malformed package must never take the host application down with it.
            ScanReport report = new ScanReport(path.getName(), path.getAbsolutePath(), looksArchive(path),
                    path.isDirectory(), PluginManifest.missing(), "");
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
            // A fresh allowance per package: sharing one budget let the first large plugin consume it
            // and every package after it came back empty while appearing to have been scanned.
            reports.add(scan(paths.get(i), budget.fresh()));
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

    /**
     * Reads the manifest, keeping "absent" and "not read" apart.
     *
     * <p>An exhausted budget returns no bytes, and reporting that as a missing manifest produced a
     * false high-severity finding about a package whose manifest was present and perfectly readable.
     */
    /** True when {@code path} is, or wraps, a zip archive. */
    private static boolean looksArchive(File path) {
        return !path.isDirectory() || new File(path, PluginPackage.INSTALLED_ARCHIVE).isFile();
    }

    /**
     * Turns a zip library's failure into something the user can act on.
     *
     * <p>"invalid CEN header (bad compression method: 95)" is the JDK saying a member is XZ-compressed,
     * which it cannot inflate and MT Manager can. That is a limit of this scanner, and the report
     * should say so rather than leave the user guessing whether the package is corrupt.
     */
    private static String describeOpenFailure(IOException e) {
        String message = String.valueOf(e.getMessage());
        if (message.contains("bad compression method: 95")) {
            return "a member uses XZ compression (zip method 95), which this scanner cannot read and MT"
                    + " Manager can. Inspect it by hand.";
        }
        if (message.contains("bad compression method")) {
            return "a member uses a compression method this scanner cannot read (" + message + ")."
                    + " Inspect it by hand.";
        }
        return message;
    }

    /**
     * Resolves a <code>{key}</code> plugin name from the package's own language files.
     *
     * <p>MT Manager does this before showing the name; a report that prints the raw key instead is
     * not a report anyone can read. Bounded to a few small files under {@code assets/}.
     */
    private static void resolvePlaceholderName(PluginManifest manifest, PluginPackage pkg,
            List<PluginPackage.Entry> entries, ScanBudget budget) {
        if (!manifest.namePlaceholder()) {
            return;
        }
        String key = manifest.placeholderKey();
        String pack = null;
        int colon = key.indexOf(':');
        if (colon > 0) {
            pack = key.substring(0, colon);
            key = key.substring(colon + 1);
        }
        List<String> files = Mtl.candidateFiles(entries, pack, "en");
        int looked = 0;
        for (int i = 0; i < files.size() && looked < 6; i++) {
            String name = files.get(i);
            for (PluginPackage.Entry entry : entries) {
                if (!entry.name.equals(name)) {
                    continue;
                }
                looked++;
                try {
                    String value = Mtl.parse(Bytes.text(pkg.read(entry, Mtl.MAX_BYTES, budget))).get(key);
                    if (value != null && value.trim().length() > 0) {
                        manifest.setResolvedName(value.trim());
                        return;
                    }
                } catch (IOException e) {
                    // The name is cosmetic; a language file that cannot be read is not a finding.
                }
                break;
            }
        }
    }

    /** True when every member of the package sits under {@code prefix}. */
    private static boolean allUnder(List<PluginPackage.Entry> entries, String prefix) {
        for (PluginPackage.Entry entry : entries) {
            if (entry.directory) {
                continue;
            }
            if (!entry.name.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    private PluginManifest readManifest(PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget) {
        for (PluginPackage.Entry entry : entries) {
            if (!entry.directory && entry.name.equals("manifest.json")) {
                try {
                    byte[] data = pkg.read(entry, 512 * 1024, budget);
                    if (data.length == 0) {
                        budget.markTruncated();
                        return PluginManifest.unreadable("not read within the scan budget");
                    }
                    return PluginManifest.parse(data);
                } catch (IOException e) {
                    return PluginManifest.unreadable("could not be read: " + e.getMessage());
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
            // Every member has to live under it as well: treating "A/manifest.json" as the root of a
            // package that also contains "B/..." would hide everything under B from the scan
            // entirely, which is a way to carry code past a reviewer.
            if (prefix.indexOf('/') == prefix.length() - 1 && allUnder(entries, prefix)) {
                return prefix;
            }
        }
        return null;
    }
}
