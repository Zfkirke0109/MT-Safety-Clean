package mt.safety.scanner.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

/**
 * Explicit content-free export. Only constants, enums, counts and opaque SHA-256 IDs leave this
 * formatter. Package metadata, evidence text, diagnostic messages and signature names never do.
 * This is an allowlist, independent of credential recognition in useful local reports.
 *
 * <p>Each invocation uses a fresh unexported salt. IDs correlate locations within a report, but are
 * intentionally unsuitable for comparing exports or acting on packages. A location is the complete
 * evidence location (which may include a line), not a claim of normalized archive-member identity.
 */
public final class ShareReportFormatter {
    private static final String[] RULE_IDS = {
        "ARC001", "ARC002", "ARC003", "ARC004", "ARC005", "ARC006", "ARC007", "ARC008", "ARC009",
        "CMB001", "CMB002", "CMB003", "CMB004", "CMB005",
        "CMB101", "CMB102", "CMB103", "CMB104", "CMB105", "CMB106", "CMB107", "CTX001",
        "DES001", "DES002", "DES003", "DYN001", "DYN002", "DYN003", "DYN004", "DYN005",
        "EVA001", "EVA002", "EXE001", "EXE002", "EXE003", "EXE004", "EXE005", "IDN001", "IDN002",
        "MFT001", "MFT002", "MFT003", "MFT004", "MFT005", "MFT006", "MFT007",
        "MFT008", "MFT009", "MFT010", "MFT011", "MFT012", "MFT013",
        "NET001", "NET002", "NET003", "NET004", "NET005", "NET006",
        "OBF001", "OBF002", "OBF003", "OBF004", "OBF005", "OBF006", "OBF007", "OBF008",
        "PER001", "PER002", "PRV001", "REC001", "REC002", "REC003", "REC004", "REC005", "SCN001",
        "SEN001", "SEN002", "SEN003", "SEN004", "SEN005", "SEN006", "SIG001", "SIG002", "SIG003",
        "USR001", "XPL001", "XPL002"
    };
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final String NOTICE = "Capabilities do not establish intent. Incomplete inspection"
            + " is not an all-clear. Opaque IDs apply only to this export.";

    private ShareReportFormatter() { }

    /** Content-free text; use ReportFormatter separately for useful private/local evidence. */
    public static String text(List<ScanReport> reports) {
        byte[] salt = salt();
        StringBuilder out = new StringBuilder();
        out.append("MT Manager plugin safety report\nSHARE-SAFE: content-free export\n")
                .append("Package names, paths, snippets, errors and signature names are omitted.\n")
                .append("Reports: ").append(reports.size()).append('\n');
        for (int i = 0; i < reports.size(); i++) {
            ScanReport report = reports.get(i);
            out.append('\n').append(marker(report)).append(" Report ")
                    .append(opaque(salt, i, 'R', report.contentHash)).append('\n')
                    .append("Verdict: ").append(verdict(report)).append("; disposition: ")
                    .append(disposition(report)).append("; coverage: ").append(report.coverage().name())
                    .append("\nScore: ").append(report.score()).append("; files scanned: ")
                    .append(report.filesScanned()).append("; errors: ").append(report.errors.size())
                    .append("; findings: ").append(report.signals.size()).append('\n');
            for (Signal signal : report.signals) {
                out.append(signal.severity.marker()).append(' ').append(knownRule(signal.ruleId))
                        .append(' ').append(signal.severity.name()).append(' ').append(signal.category.name())
                        .append("; evidence: ").append(signal.evidence().size()).append('\n');
                for (Signal.Evidence evidence : signal.evidence()) {
                    out.append("  Location: ").append(opaque(salt, i, 'L', evidence.where)).append('\n');
                }
            }
        }
        return out.append('\n').append(NOTICE).append('\n').toString();
    }

    /** Strict JSON with an explicit privacy mode; contains no free-form input strings. */
    public static String json(List<ScanReport> reports) {
        byte[] salt = salt();
        StringBuilder out = new StringBuilder();
        out.append("{\"schemaVersion\":1,\"mode\":\"SHARE_SAFE\",\"reportCount\":")
                .append(reports.size()).append(",\"reports\":[");
        for (int i = 0; i < reports.size(); i++) {
            if (i > 0) { out.append(','); }
            ScanReport report = reports.get(i);
            out.append("{\"id\":").append(Json.quote(opaque(salt, i, 'R', report.contentHash)))
                    .append(",\"verdict\":").append(Json.quote(verdict(report)))
                    .append(",\"disposition\":").append(Json.quote(disposition(report)))
                    .append(",\"marker\":").append(Json.quote(marker(report)))
                    .append(",\"coverage\":").append(Json.quote(report.coverage().name()))
                    .append(",\"score\":").append(report.score())
                    .append(",\"filesScanned\":").append(report.filesScanned())
                    .append(",\"errorCount\":").append(report.errors.size())
                    .append(",\"findingCount\":").append(report.signals.size()).append(",\"findings\":[");
            for (int j = 0; j < report.signals.size(); j++) {
                if (j > 0) { out.append(','); }
                Signal signal = report.signals.get(j);
                out.append("{\"rule\":").append(Json.quote(knownRule(signal.ruleId)))
                        .append(",\"severity\":").append(Json.quote(signal.severity.name()))
                        .append(",\"category\":").append(Json.quote(signal.category.name()))
                        .append(",\"marker\":").append(Json.quote(signal.severity.marker()))
                        .append(",\"evidenceCount\":").append(signal.evidence().size())
                        .append(",\"locations\":[");
                for (int k = 0; k < signal.evidence().size(); k++) {
                    if (k > 0) { out.append(','); }
                    out.append(Json.quote(opaque(salt, i, 'L', signal.evidence().get(k).where)));
                }
                out.append("]}");
            }
            out.append("]}");
        }
        return out.append("]}\n").toString();
    }

    private static String knownRule(String input) {
        for (String rule : RULE_IDS) {
            if (rule.equals(input)) { return rule; }
        }
        return "UNRECOGNIZED_RULE";
    }

    private static String verdict(ScanReport report) {
        return report.verdict().name();
    }

    private static String disposition(ScanReport report) {
        if (report.coverage() == Coverage.PARTIAL) {
            if (report.verdict() == Verdict.CLEAN) { return "INCOMPLETE"; }
            if (report.verdict() == Verdict.TRUSTED) { return "TRUSTED_INCOMPLETE"; }
            return "FINDINGS_INCOMPLETE";
        }
        if (report.verdict() == Verdict.CLEAN && report.hasPackageFindings()) {
            return "FINDINGS_BELOW_THRESHOLD";
        }
        return verdict(report);
    }

    private static String marker(ScanReport report) {
        switch (report.verdict()) {
            case KNOWN_BAD:
            case LIKELY_MALICIOUS: return "[!!!]";
            case SUSPICIOUS: return "[!! ]";
            case REVIEW: return "[!  ]";
            case UNREADABLE: return "[ ? ]";
            default:
                if (report.coverage() != Coverage.COMPLETE) { return "[ ? ]"; }
                return report.hasPackageFindings() ? "[.  ]" : "[ ok]";
        }
    }

    private static byte[] salt() {
        byte[] value = new byte[32];
        new SecureRandom().nextBytes(value);
        return value;
    }

    /** Hash public fields as input, never mistake a digest-looking public string for trusted output. */
    private static String opaque(byte[] salt, int ordinal, char domain, String input) {
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
        digest.update(salt);
        digest.update((byte) domain);
        for (int shift = 24; shift >= 0; shift -= 8) { digest.update((byte) (ordinal >>> shift)); }
        digest.update((byte) (input == null ? 0 : 1));
        // Feed exact UTF-16 code units without allocating a potentially large intermediate byte array.
        if (input != null) {
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                digest.update((byte) (c >>> 8));
                digest.update((byte) c);
            }
        }
        byte[] hash = digest.digest();
        char[] result = new char[hash.length * 2];
        for (int i = 0; i < hash.length; i++) {
            result[i * 2] = HEX[(hash[i] & 0xff) >>> 4];
            result[i * 2 + 1] = HEX[hash[i] & 15];
        }
        return new String(result);
    }
}
