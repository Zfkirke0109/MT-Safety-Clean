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
        sb.append(report.dispositionLabel());
        if (report.verdict() == Verdict.CLEAN && report.coverage() == Coverage.PARTIAL) {
            sb.append(" - ").append(report.hasPackageFindings()
                    ? "Package findings observed; inspection incomplete"
                    : "No findings in inspected content; inspection incomplete");
        } else if (report.verdict() == Verdict.CLEAN && report.hasPackageFindings()) {
            sb.append(" - Lower-severity findings listed");
        } else if (report.verdict() != Verdict.CLEAN && report.verdict() != Verdict.TRUSTED) {
            sb.append(" - ").append(report.verdictReason());
        }
        return ReportText.redact(sb.toString());
    }

    /** Counts by verdict, for the heading of a whole-device scan. */
    public static String overview(List<ScanReport> reports) {
        int malicious = 0;
        int suspicious = 0;
        int review = 0;
        int clean = 0;
        int cleanWithFindings = 0;
        int incomplete = 0;
        int unreadable = 0;
        int partial = 0;
        for (int i = 0; i < reports.size(); i++) {
            ScanReport current = reports.get(i);
            if (current.coverage() == Coverage.PARTIAL) {
                partial++;
            }
            if (current.coverage() == Coverage.PARTIAL
                    && (current.verdict() == Verdict.CLEAN || current.verdict() == Verdict.TRUSTED)) {
                incomplete++;
                continue;
            }
            if (current.coverage() == Coverage.COMPLETE && current.verdict() == Verdict.CLEAN
                    && current.hasPackageFindings()) {
                cleanWithFindings++;
                continue;
            }
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
        if (cleanWithFindings > 0) {
            sb.append(", ").append(cleanWithFindings).append(" with findings below verdict threshold");
        }
        if (incomplete > 0) {
            sb.append(", ").append(incomplete).append(" incomplete");
        }
        if (unreadable > 0) {
            sb.append(", ").append(unreadable).append(" unreadable");
        }
        if (partial > 0) {
            sb.append("; ").append(partial).append(" with incomplete coverage");
        }
        return ReportText.redact(sb.toString());
    }

    /** The full report for one package. */
    public static String plainText(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(report.manifest.displayName()).append(" ===\n");
        sb.append("Verdict : ").append(report.dispositionLabel())
                .append("  (risk score ").append(report.score()).append(")\n");
        sb.append("Advice  : ").append(report.dispositionAdvice()).append('\n');
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
        sb.append("Coverage: ").append(report.coverage().label()).append('\n');
        if (report.ledger.active()) {
            sb.append("Checks  : ").append(report.ledger.members().size()).append(" member records, ")
                    .append(report.ledger.incompleteChecks()).append(" incomplete checks; ")
                    .append(report.ledger.droppedMembers()).append(" omitted by ledger limit.\n")
                    .append("The local JSON includes every recorded analyzer status and reason code.\n");
        }

        List<Signal> signals = report.signalsBySeverity();
        boolean packageFindings = report.hasPackageFindings();
        if (report.coverage() == Coverage.PARTIAL) {
            sb.append("\nCoverage warning: inspection was incomplete or some code was not in view; see"
                    + " coverage notices below. This is not a threat finding.\n");
        }
        if (report.coverage() == Coverage.COMPLETE) {
            if (!packageFindings) {
                sb.append("\nNo findings.\n");
            }
        } else if (report.coverage() == Coverage.PARTIAL) {
            if (!packageFindings) {
                sb.append("\nNo findings in inspected content; inspection incomplete.\n");
            }
        } else if (signals.isEmpty()) {
            sb.append("\nNothing could be inspected; no verdict on the contents.\n");
        }
        appendSignals(sb, signals, false);
        appendSignals(sb, signals, true);

        if (!report.errors.isEmpty()) {
            sb.append("\nProblems during the scan:\n");
            for (int i = 0; i < report.errors.size(); i++) {
                sb.append("  - ").append(report.errors.get(i)).append('\n');
            }
        }
        return ReportText.redact(sb.toString());
    }

    private static void appendSignals(StringBuilder sb, List<Signal> signals, boolean coverageNotices) {
        boolean heading = false;
        for (int i = 0; i < signals.size(); i++) {
            Signal signal = signals.get(i);
            if (ScanReport.isCoverageNotice(signal) != coverageNotices) {
                continue;
            }
            if (!heading) {
                sb.append(coverageNotices ? "\nCoverage notices:\n" : "\nFindings (worst first):\n");
                heading = true;
            }
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
        return ReportText.redact(sb.toString());
    }

    /** Machine-readable form, for keeping a record or diffing across scans. */
    public static String json(List<ScanReport> reports) {
        return json(reports, null);
    }

    /** As {@link #json(List)}, also recording the signature database the scan ran with. */
    public static String json(List<ScanReport> reports, SignatureDatabase signatures) {
        return json(reports, signatures, null);
    }

    /** Adds discovery scope without changing each package's independent inspection coverage. */
    public static String json(List<ScanReport> reports, SignatureDatabase signatures,
            List<String> discoveryProblems) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"catalogue\": {\"version\": ")
                .append(CodePatterns.CATALOGUE_VERSION)
                .append(", \"date\": ").append(quoted(CodePatterns.CATALOGUE_DATE))
                .append(", \"rules\": ").append(CodePatterns.ruleCount()).append("},\n");
        SignatureDatabase db = signatures == null ? SignatureDatabase.empty() : signatures;
        sb.append("  \"signatures\": {\"files\": ").append(db.fileCount())
                .append(", \"hashes\": ").append(db.hashCount())
                .append(", \"patterns\": ").append(db.patternCount())
                .append(", \"newest\": ").append(quoted(db.fileCount() == 0 ? "" : Dates.isoDate(db.newestMillis())))
                .append("},\n");
        if (discoveryProblems != null) {
            sb.append("  \"discoveryComplete\": ").append(discoveryProblems.isEmpty()).append(",\n");
            sb.append("  \"discoveryProblems\": [");
            for (int i = 0; i < discoveryProblems.size(); i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(quoted(discoveryProblems.get(i)));
            }
            sb.append("],\n");
        }
        sb.append("  \"reports\": [\n");
        for (int i = 0; i < reports.size(); i++) {
            appendReport(sb, reports.get(i));
            sb.append(i + 1 < reports.size() ? ",\n" : "\n");
        }
        sb.append("  ]\n}\n");
        return ReportText.redact(sb.toString());
    }

    private static String quoted(String value) {
        return Json.quote(ReportText.redact(value));
    }

    private static void appendReport(StringBuilder sb, ScanReport report) {
        sb.append("    {\n");
        sb.append("      \"name\": ").append(quoted(report.manifest.displayName())).append(",\n");
        sb.append("      \"pluginId\": ").append(quoted(report.manifest.pluginId)).append(",\n");
        sb.append("      \"versionName\": ").append(quoted(report.manifest.versionName)).append(",\n");
        sb.append("      \"path\": ").append(quoted(report.path)).append(",\n");
        sb.append("      \"sha256\": ").append(quoted(report.contentHash)).append(",\n");
        sb.append("      \"verdict\": ").append(quoted(report.verdict().name())).append(",\n");
        sb.append("      \"score\": ").append(report.score()).append(",\n");
        sb.append("      \"coverage\": ").append(quoted(report.coverage().name())).append(",\n");
        sb.append("      \"disposition\": ").append(quoted(report.dispositionLabel())).append(",\n");
        sb.append("      \"reason\": ").append(quoted(report.verdictReason())).append(",\n");
        sb.append("      \"truncated\": ").append(report.truncated()).append(",\n");
        sb.append("      \"filesScanned\": ").append(report.filesScanned()).append(",\n");
        appendLedger(sb, report.ledger);
        sb.append("      \"errors\": [");
        for (int i = 0; i < report.errors.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(quoted(report.errors.get(i)));
        }
        sb.append("],\n");
        sb.append("      \"findings\": [\n");
        List<Signal> signals = report.signalsBySeverity();
        for (int i = 0; i < signals.size(); i++) {
            Signal signal = signals.get(i);
            sb.append("        {\"rule\": ").append(quoted(signal.ruleId));
            sb.append(", \"severity\": ").append(quoted(signal.severity.name()));
            sb.append(", \"category\": ").append(quoted(signal.category.name()));
            sb.append(", \"title\": ").append(quoted(signal.title));
            sb.append(", \"evidence\": [");
            List<Signal.Evidence> evidence = signal.evidence();
            for (int j = 0; j < evidence.size(); j++) {
                sb.append(quoted(evidence.get(j).where + (evidence.get(j).snippet.length() > 0
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

    private static void appendLedger(StringBuilder sb, CoverageLedger ledger) {
        sb.append("      \"coverageLedger\": {\"schemaVersion\":1,\"active\":").append(ledger.active())
                .append(",\"memberLimit\":").append(CoverageLedger.MAX_MEMBERS)
                .append(",\"omittedMembers\":").append(ledger.droppedMembers())
                .append(",\"incompleteChecks\":").append(ledger.incompleteChecks()).append(",\"package\":{");
        int n = 0;
        for (CoverageLedger.PackageAnalyzer a : CoverageLedger.PackageAnalyzer.values()) {
            if (n++ > 0) sb.append(',');
            sb.append(quoted(a.name())).append(':'); appendCheck(sb, ledger.get(a));
        }
        sb.append("},\"members\":["); n = 0;
        for (CoverageLedger.Member member : ledger.members()) {
            if (n++ > 0) sb.append(',');
            sb.append("{\"id\":").append(member.id).append(",\"label\":").append(quoted(member.label))
                    .append(",\"nameHash\":").append(quoted(member.nameHash)).append(",\"analyzers\":{");
            int check = 0;
            for (CoverageLedger.Analyzer a : CoverageLedger.Analyzer.values()) {
                if (check++ > 0) sb.append(',');
                sb.append(quoted(a.name())).append(':'); appendCheck(sb, member.get(a));
            }
            sb.append("}}");
        }
        sb.append("]},\n");
    }

    private static void appendCheck(StringBuilder sb, CoverageLedger.Check check) {
        sb.append("{\"status\":").append(quoted(check.status.name())).append(",\"reason\":")
                .append(quoted(check.reason.name())).append(",\"bytes\":").append(check.bytes).append('}');
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
        return ReportText.redact(sb.toString());
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
        return ReportText.redact(sb.toString());
    }

    private static String nonEmpty(String value, String fallback) {
        return value == null || value.length() == 0 ? fallback : value;
    }
}
