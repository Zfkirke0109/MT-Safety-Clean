package mt.safety.scanner.core;

import java.util.List;

/**
 * Renders reports as text a person can act on, and as JSON a machine can keep.
 *
 * <p>The text form is written for MT Manager's settings screen, where the only available widget is a
 * row with a title and a summary line: no colour, no tables, no scroll-within-scroll. So findings are
 * ordered worst first, each carries its own evidence, and the verdict states what to do rather than
 * only what was found.
 */
public final class ReportFormatter {

    private ReportFormatter() {
    }

    /** One line per package, for a list view. */
    public static String summaryLine(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append(report.verdict().label());
        if (report.verdict() != Verdict.CLEAN && report.verdict() != Verdict.TRUSTED) {
            sb.append(" - ").append(report.verdictReason());
        }
        return sb.toString();
    }

    /** Counts by verdict, for the heading of a whole-device scan. */
    public static String overview(List<ScanReport> reports) {
        int malicious = 0;
        int suspicious = 0;
        int review = 0;
        int clean = 0;
        int unreadable = 0;
        for (int i = 0; i < reports.size(); i++) {
            switch (reports.get(i).verdict()) {
                case KNOWN_BAD:
                case LIKELY_MALICIOUS:
                    malicious++;
                    break;
                case SUSPICIOUS:
                    suspicious++;
                    break;
                case REVIEW:
                    review++;
                    break;
                case UNREADABLE:
                    unreadable++;
                    break;
                default:
                    clean++;
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append(reports.size()).append(reports.size() == 1 ? " plugin" : " plugins").append(" scanned: ");
        sb.append(malicious).append(" to remove, ");
        sb.append(suspicious).append(" suspicious, ");
        sb.append(review).append(" worth a look, ");
        sb.append(clean).append(" clean");
        if (unreadable > 0) {
            sb.append(", ").append(unreadable).append(" unreadable");
        }
        return sb.toString();
    }

    /** The full report for one package. */
    public static String plainText(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(report.manifest.displayName()).append(" ===\n");
        sb.append("Verdict : ").append(report.verdict().label())
                .append("  (risk score ").append(report.score()).append(")\n");
        sb.append("Advice  : ").append(report.verdict().advice()).append('\n');
        sb.append("Plugin  : ").append(nonEmpty(report.manifest.pluginId, "(no pluginID)"));
        if (report.manifest.versionName.length() > 0) {
            sb.append("  ").append(report.manifest.versionName);
        }
        sb.append('\n');
        sb.append("Path    : ").append(report.path).append('\n');
        sb.append("SHA-256 : ").append(nonEmpty(report.contentHash, "(not computed)")).append('\n');
        sb.append("Scanned : ").append(report.filesScanned()).append(" files in ")
                .append(report.elapsedMs()).append(" ms");
        if (report.truncated()) {
            sb.append(" (incomplete)");
        }
        sb.append("\n");

        List<Signal> signals = report.signalsBySeverity();
        if (signals.isEmpty()) {
            sb.append("\nNo findings.\n");
        } else {
            sb.append("\nFindings (worst first):\n");
            for (int i = 0; i < signals.size(); i++) {
                Signal signal = signals.get(i);
                sb.append('\n').append(signal.severity.marker()).append(' ')
                        .append(signal.severity.label().toUpperCase(java.util.Locale.US)).append("  ")
                        .append(signal.ruleId).append("  ").append(signal.title).append('\n');
                sb.append("      ").append(signal.category.label()).append('\n');
                sb.append("      ").append(signal.detail).append('\n');
                List<Signal.Evidence> evidence = signal.evidence();
                for (int j = 0; j < evidence.size(); j++) {
                    sb.append("      - ").append(evidence.get(j).where);
                    if (evidence.get(j).snippet.length() > 0) {
                        sb.append("  |  ").append(evidence.get(j).snippet);
                    }
                    sb.append('\n');
                }
            }
        }

        if (!report.errors.isEmpty()) {
            sb.append("\nProblems during the scan:\n");
            for (int i = 0; i < report.errors.size(); i++) {
                sb.append("  - ").append(report.errors.get(i)).append('\n');
            }
        }
        return sb.toString();
    }

    /** The full set of reports as text, for export or sharing. */
    public static String plainText(List<ScanReport> reports) {
        return plainText(reports, null);
    }

    /** As {@link #plainText(List)}, also stating which signature database the scan ran with. */
    public static String plainText(List<ScanReport> reports, SignatureDatabase signatures) {
        StringBuilder sb = new StringBuilder();
        sb.append("MT Manager plugin safety report\n");
        // Which rules produced this. A report read months later, or by someone else, is only
        // meaningful against the catalogue that made it.
        sb.append("Rules   : catalogue v").append(CodePatterns.CATALOGUE_VERSION)
                .append(" of ").append(CodePatterns.CATALOGUE_DATE)
                .append(" (").append(CodePatterns.ruleCount()).append(" rules)\n");
        sb.append("Signatures: ").append(signatureLine(signatures)).append('\n');
        sb.append(overview(reports)).append("\n\n");
        for (int i = 0; i < reports.size(); i++) {
            sb.append(plainText(reports.get(i))).append('\n');
        }
        sb.append("A finding is a capability, not proof of intent. Read the evidence before deleting"
                + " anything, and keep the report if you plan to report the plugin.\n");
        return sb.toString();
    }

    /** Machine-readable form, for keeping a record or diffing across scans. */
    public static String json(List<ScanReport> reports) {
        return json(reports, null);
    }

    /** As {@link #json(List)}, also recording the signature database the scan ran with. */
    public static String json(List<ScanReport> reports, SignatureDatabase signatures) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"catalogue\": {\"version\": ")
                .append(CodePatterns.CATALOGUE_VERSION)
                .append(", \"date\": ").append(Json.quote(CodePatterns.CATALOGUE_DATE))
                .append(", \"rules\": ").append(CodePatterns.ruleCount()).append("},\n");
        SignatureDatabase db = signatures == null ? SignatureDatabase.empty() : signatures;
        sb.append("  \"signatures\": {\"files\": ").append(db.fileCount())
                .append(", \"hashes\": ").append(db.hashCount())
                .append(", \"patterns\": ").append(db.patternCount())
                .append(", \"newest\": ").append(Json.quote(db.fileCount() == 0 ? "" : Dates.isoDate(db.newestMillis())))
                .append("},\n");
        sb.append("  \"reports\": [\n");
        for (int i = 0; i < reports.size(); i++) {
            appendReport(sb, reports.get(i));
            sb.append(i + 1 < reports.size() ? ",\n" : "\n");
        }
        sb.append("  ]\n}\n");
        return sb.toString();
    }

    private static void appendReport(StringBuilder sb, ScanReport report) {
        sb.append("    {\n");
        sb.append("      \"name\": ").append(Json.quote(report.manifest.displayName())).append(",\n");
        sb.append("      \"pluginId\": ").append(Json.quote(report.manifest.pluginId)).append(",\n");
        sb.append("      \"versionName\": ").append(Json.quote(report.manifest.versionName)).append(",\n");
        sb.append("      \"path\": ").append(Json.quote(report.path)).append(",\n");
        sb.append("      \"sha256\": ").append(Json.quote(report.contentHash)).append(",\n");
        sb.append("      \"verdict\": ").append(Json.quote(report.verdict().name())).append(",\n");
        sb.append("      \"score\": ").append(report.score()).append(",\n");
        sb.append("      \"reason\": ").append(Json.quote(report.verdictReason())).append(",\n");
        sb.append("      \"truncated\": ").append(report.truncated()).append(",\n");
        sb.append("      \"filesScanned\": ").append(report.filesScanned()).append(",\n");
        sb.append("      \"findings\": [\n");
        List<Signal> signals = report.signalsBySeverity();
        for (int i = 0; i < signals.size(); i++) {
            Signal signal = signals.get(i);
            sb.append("        {\"rule\": ").append(Json.quote(signal.ruleId));
            sb.append(", \"severity\": ").append(Json.quote(signal.severity.name()));
            sb.append(", \"category\": ").append(Json.quote(signal.category.name()));
            sb.append(", \"title\": ").append(Json.quote(signal.title));
            sb.append(", \"evidence\": [");
            List<Signal.Evidence> evidence = signal.evidence();
            for (int j = 0; j < evidence.size(); j++) {
                sb.append(Json.quote(evidence.get(j).where + (evidence.get(j).snippet.length() > 0
                        ? " | " + evidence.get(j).snippet : "")));
                if (j + 1 < evidence.size()) {
                    sb.append(", ");
                }
            }
            sb.append("]}");
            sb.append(i + 1 < signals.size() ? ",\n" : "\n");
        }
        sb.append("      ]\n    }");
    }

    /** One line saying what signature database, if any, a scan ran with. */
    public static String signatureLine(SignatureDatabase signatures) {
        if (signatures == null || signatures.fileCount() == 0) {
            return "none loaded";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(signatures.fileCount()).append(signatures.fileCount() == 1 ? " file, " : " files, ")
                .append(signatures.hashCount()).append(" hash signatures, ")
                .append(signatures.patternCount()).append(" byte patterns, newest dated ")
                .append(Dates.isoDate(signatures.newestMillis()));
        if (signatures.unsupportedCount() > 0) {
            sb.append(", ").append(signatures.unsupportedCount()).append(" entries unsupported");
        }
        if (signatures.cappedCount() > 0) {
            sb.append(", ").append(signatures.cappedCount()).append(" entries over the cap");
        }
        return sb.toString();
    }

    /** The full text of a file scan: what was walked, how far it got, and every hit. */
    public static String fileScanText(FileScanner.Result scan, SignatureDatabase signatures) {
        StringBuilder sb = new StringBuilder();
        sb.append("MT Manager file scan\n");
        sb.append("Signatures: ").append(signatureLine(signatures)).append('\n');
        sb.append("Folders : ");
        for (int i = 0; i < scan.roots.size(); i++) {
            sb.append(i > 0 ? "  " : "").append(scan.roots.get(i));
        }
        sb.append('\n');
        sb.append("Checked : ").append(scan.filesScanned).append(" of ").append(scan.filesSeen)
                .append(" files, ").append(Bytes.humanSize(scan.bytesRead)).append(" read, ")
                .append(scan.archivesOpened).append(" archives opened, ")
                .append(scan.elapsedMs).append(" ms");
        switch (scan.stoppedBecause) {
            case BUDGET:
                sb.append(" (stopped: scan budget exhausted)");
                break;
            case COUNT:
                sb.append(" (stopped: more files than the walk will visit)");
                break;
            case HITS:
                sb.append(" (stopped: hit limit reached)");
                break;
            default:
                break;
        }
        sb.append('\n');
        if (scan.hits.isEmpty()) {
            sb.append("\nNo file matched a signature.\n");
        } else {
            sb.append("\nMatches (").append(scan.hits.size()).append("):\n");
            for (int i = 0; i < scan.hits.size(); i++) {
                FileScanner.Hit hit = scan.hits.get(i);
                sb.append(hit.pua ? "[!! ] " : "[!!!] ").append(hit.signature)
                        .append(hit.hash ? "  (hash)  " : "  (pattern)  ")
                        .append(hit.location()).append("  ").append(Bytes.humanSize(hit.size)).append('\n');
            }
        }
        if (!scan.problems.isEmpty()) {
            sb.append("\nProblems during the scan:\n");
            for (int i = 0; i < scan.problems.size(); i++) {
                sb.append("  - ").append(scan.problems.get(i)).append('\n');
            }
        }
        sb.append("\nA signature match names a file that a database you loaded classifies as malicious"
                + " or unwanted. Nothing has been deleted; the path above is where to look.\n");
        return sb.toString();
    }

    private static String nonEmpty(String value, String fallback) {
        return value == null || value.length() == 0 ? fallback : value;
    }
}
