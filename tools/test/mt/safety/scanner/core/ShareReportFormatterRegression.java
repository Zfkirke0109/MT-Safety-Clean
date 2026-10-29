package mt.safety.scanner.core;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Content-free sharing is an allowlist, never a guess at which strings contain secrets. */
public final class ShareReportFormatterRegression {
    private static int checks;
    private static final String[] PRIVATE = {
        "Orchard Violet Telescope", "Meadow Quiet Satellite", "Copper Apricot Lantern",
        "Willow Paper Compass", "Plum Velvet Horizon", "Marble Cloud Basket",
        "Dawn Silver Harbor", "Cedar Amber Window", "Winter Olive Pebble",
        "Iris Green Hammock", "Tulip Evening Lantern", "Pearl Ocean Pillow",
        "Acorn Lavender Forest", "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    };

    private ShareReportFormatterRegression() { }

    public static void main(String[] args) throws Exception {
        ScanReport report = injected();
        List<ScanReport> reports = Collections.singletonList(report);
        String text = text(reports);
        String json = json(reports);
        for (String secret : PRIVATE) {
            check(!text.contains(secret), "text excludes arbitrary private metadata");
            check(!json.contains(secret), "JSON excludes arbitrary private metadata");
        }
        check(!text.contains("NET999") && !json.contains("NET999"), "rule-shaped unknown ID omitted");
        Map<String, Object> parsed = Json.parseObject(json);
        assertShareSchema(parsed);
        check("SHARE_SAFE".equals(parsed.get("mode")), "machine-readable privacy indicator");
        check(text.contains("SHARE-SAFE"), "visible privacy indicator");
        check(text.contains("[!! ]") && text.contains("PARTIAL"), "severity and coverage markers retained");
        check(json.contains("\"rule\":\"NET001\"") && json.contains("\"rule\":\"SIG001\""),
                "known rules retained");
        check(json.contains("\"rule\":\"UNRECOGNIZED_RULE\""), "unknown IDs use fixed fallback");
        check(report.score() == 73 && report.coverage() == Coverage.PARTIAL
                && report.verdict() == Verdict.SUSPICIOUS, "formatting leaves assessment unchanged");
        check(ReportFormatter.plainText(reports).contains(PRIVATE[0]), "local report remains useful");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> exported = (List<Map<String, Object>>) parsed.get("reports");
        Map<String, Object> first = exported.get(0);
        check(first.get("id").toString().matches("[0-9a-f]{64}"), "report ID is full SHA256");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> findings = (List<Map<String, Object>>) first.get("findings");
        @SuppressWarnings("unchecked")
        List<String> locations = (List<String>) findings.get(0).get("locations");
        check(locations.size() == 2 && locations.get(0).matches("[0-9a-f]{64}"), "member IDs are SHA256");
        check(locations.get(0).equals(locations.get(1)), "same location correlates within report");
        @SuppressWarnings("unchecked")
        List<String> otherLocations = (List<String>) findings.get(1).get("locations");
        check(locations.get(0).equals(otherLocations.get(0)), "same location correlates across findings");
        check(!json(reports).contains(first.get("id").toString()), "new exports cannot track report IDs");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> two = (List<Map<String, Object>>) Json.parseObject(
                json(Arrays.asList(report, report))).get("reports");
        check(!two.get(0).get("id").equals(two.get(1).get("id")), "report ordinal separates duplicate inputs");
        check("INCOMPLETE".equals(singleDisposition(Verdict.CLEAN, true, false)), "partial clean is incomplete");
        check("TRUSTED_INCOMPLETE".equals(singleDisposition(Verdict.TRUSTED, true, false)),
                "partial trusted remains qualified");
        check("FINDINGS_BELOW_THRESHOLD".equals(singleDisposition(Verdict.CLEAN, false, true)),
                "low findings are visible below clean threshold");
        check("UNREADABLE".equals(singleDisposition(Verdict.UNREADABLE, false, false)), "unreadable remains explicit");
        ScanReport rawHash = new ScanReport(PRIVATE[0], PRIVATE[1], false, false,
                PluginManifest.broken(PRIVATE[2]), PRIVATE[3]);
        check(!json(Collections.singletonList(rawHash)).contains(PRIVATE[3])
                && !text(Collections.singletonList(rawHash)).contains(PRIVATE[3]),
                "non-digest public contentHash is hashed rather than exported");
        ScanReport nullHash = new ScanReport("", "", false, false, PluginManifest.missing(), null);
        check(Json.parseObject(json(Collections.singletonList(nullHash))).get("reports") instanceof List,
                "absent hash remains valid without claiming an action identity");
        check(Json.parseObject(json(Collections.<ScanReport>emptyList())).get("reports") instanceof List,
                "empty reports are valid JSON");
        System.out.println("ShareReportFormatterRegression: " + checks + " checks passed");
    }

    private static ScanReport injected() {
        String manifestJson = "{\"name\":" + Json.quote(PRIVATE[0]) + ",\"pluginID\":" + Json.quote(PRIVATE[1])
                + ",\"versionName\":" + Json.quote(PRIVATE[2]) + ",\"description\":" + Json.quote(PRIVATE[3])
                + ",\"mainPreference\":" + Json.quote(PRIVATE[4]) + "}";
        PluginManifest manifest = PluginManifest.parse(manifestJson.getBytes(StandardCharsets.UTF_8));
        manifest.setResolvedName(PRIVATE[0]);
        ScanReport report = new ScanReport(PRIVATE[5], PRIVATE[6], true, true, manifest, PRIVATE[13]);
        report.setVerdict(Verdict.SUSPICIOUS, PRIVATE[7]);
        report.setScore(73);
        report.setFilesScanned(4);
        report.setElapsedMs(25);
        report.setTruncated(true);
        report.addError(PRIVATE[8]);
        report.traits.add(PRIVATE[9]);
        report.setDestructiveActionIdentity(true, PRIVATE[10]);
        report.add(new Signal("NET001", Category.NETWORK, Severity.HIGH, PRIVATE[11], PRIVATE[12])
                .withEvidence(PRIVATE[3], PRIVATE[4]).withEvidence(PRIVATE[3], PRIVATE[5]));
        report.add(new Signal("SIG001", Category.SIGNATURE, Severity.CRITICAL, PRIVATE[0], PRIVATE[1])
                .withEvidence(PRIVATE[3], PRIVATE[12]));
        report.add(new Signal(PRIVATE[9] + "\"\\\n\u0001", Category.PROVENANCE, Severity.INFO, PRIVATE[2], PRIVATE[3]));
        report.add(new Signal("NET999", Category.PROVENANCE, Severity.INFO, PRIVATE[4], PRIVATE[5]));
        return report;
    }

    private static String singleDisposition(Verdict verdict, boolean partial, boolean finding) throws Exception {
        ScanReport report = new ScanReport("", "", false, false, PluginManifest.missing(), "");
        report.setVerdict(verdict, PRIVATE[0]);
        report.setTruncated(partial);
        if (finding) {
            report.add(new Signal("NET001", Category.NETWORK, Severity.LOW, PRIVATE[1], PRIVATE[2]));
        }
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> reports = (List<Map<String, Object>>) Json.parseObject(
                json(Collections.singletonList(report))).get("reports");
        return reports.get(0).get("disposition").toString();
    }

    private static String text(List<ScanReport> reports) {
        return ShareReportFormatter.text(reports);
    }

    private static void assertShareSchema(Object value) {
        if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            List<String> allowedKeys = Arrays.asList("schemaVersion", "mode", "reportCount", "reports", "id",
                    "verdict", "disposition", "marker", "coverage", "score", "filesScanned", "errorCount",
                    "findingCount", "findings", "rule", "severity", "category", "evidenceCount", "locations");
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                check(allowedKeys.contains(entry.getKey()), "only scanner-authored JSON keys");
                assertShareSchema(entry.getValue());
            }
        } else if (value instanceof List) {
            for (Object item : (List<?>) value) { assertShareSchema(item); }
        } else if (value instanceof String) {
            String text = (String) value;
            check(Arrays.asList("SHARE_SAFE", "SUSPICIOUS", "FINDINGS_INCOMPLETE", "PARTIAL", "[!! ]",
                    "NET001", "SIG001", "UNRECOGNIZED_RULE", "HIGH", "CRITICAL", "INFO", "NETWORK",
                    "SIGNATURE", "PROVENANCE", "[!!!]", "[   ]").contains(text)
                    || text.matches("[0-9a-f]{64}"), "only enumerated JSON strings or SHA256 IDs");
        } else {
            check(value instanceof Number, "only numeric counters outside string enums");
        }
    }

    private static String json(List<ScanReport> reports) {
        return ShareReportFormatter.json(reports);
    }

    private static void check(boolean condition, String description) {
        checks++;
        if (!condition) {
            throw new AssertionError(description);
        }
    }
}
