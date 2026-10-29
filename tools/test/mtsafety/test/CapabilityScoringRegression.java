package mtsafety.test;

import java.io.File;
import java.nio.file.Files;

import mt.safety.scanner.core.Category;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginManifest;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.RiskScorer;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Severity;
import mt.safety.scanner.core.Signal;
import mt.safety.scanner.core.Verdict;

/** Capability co-occurrence is a review cue, not evidence that a data flow occurred. */
public final class CapabilityScoringRegression {
    private CapabilityScoringRegression() {
    }

    public static void main(String[] args) throws Exception {
        final int[] failures = {0};
        run(new ActionsTest.Checker() {
            @Override
            public void that(String description, boolean condition, String context) {
                if (!condition) {
                    failures[0]++;
                    System.out.println("FAIL " + description + ": " + context);
                } else {
                    System.out.println("PASS " + description);
                }
            }
        }, new Fixtures(Files.createTempDirectory("mtsafety-capabilities-").toFile()));
        if (failures[0] > 0) {
            throw new AssertionError(failures[0] + " capability calibration checks failed");
        }
    }

    public static void run(ActionsTest.Checker c, Fixtures fixtures) {
        Category[] categories = {Category.SENSITIVE_DATA, Category.DYNAMIC_CODE,
                Category.COMMAND_EXEC, Category.RECON};
        String[] combinations = {"CMB101", "CMB102", "CMB103", "CMB105"};
        for (int i = 0; i < categories.length; i++) {
            ScanReport report = report();
            report.add(signal("CAP001", categories[i], Severity.MEDIUM));
            report.add(signal("NET001", Category.NETWORK, Severity.LOW));
            RiskScorer.score(report, IocDatabase.empty());
            Signal combination = find(report, combinations[i]);
            c.that(combinations[i] + " is a medium capability finding",
                    combination != null && combination.severity == Severity.MEDIUM, describe(report));
            c.that(combinations[i] + " alone with ordinary network stays review",
                    report.verdict() == Verdict.REVIEW && report.score() == 23, describe(report));
            c.that(combinations[i] + " explains the missing data flow",
                    combination != null && combination.detail.contains("does not establish"),
                    combination == null ? "missing" : combination.detail);
            RiskScorer.score(report, IocDatabase.empty());
            c.that(combinations[i] + " rescoring is idempotent",
                    report.score() == 23 && count(report, combinations[i]) == 1, describe(report));
        }

        disconnected(c, fixtures, "backup", "SEN006", "CMB101",
                "new java.io.File(\"/storage/emulated/0/Documents/\").listFiles();", 16, Verdict.REVIEW);
        disconnected(c, fixtures, "private", "SEN001", "CMB101",
                "new java.io.File(\"/data/data/example.app/files\").listFiles();", 38, Verdict.SUSPICIOUS);
        disconnected(c, fixtures, "loader", "DYN001", "CMB102",
                "new dalvik.system.DexClassLoader(localPath, cache, null, parent);", 38, Verdict.SUSPICIOUS);
        disconnected(c, fixtures, "shell", "EXE001", "CMB103",
                "Runtime.getRuntime().exec(\"ls\");", 38, Verdict.SUSPICIOUS);
        disconnected(c, fixtures, "location", "REC005", "CMB105",
                "locationManager.getLastKnownLocation(provider);", 23, Verdict.REVIEW);

        sameFile(c, fixtures, "loader", "CMB002", "CMB102",
                "new dalvik.system.DexClassLoader(localPath, cache, null, parent);");
        sameFile(c, fixtures, "shell", "CMB003", "CMB103", "Runtime.getRuntime().exec(\"ls\");");

        String[] criticalRules = {"DES002", "CMB004", "OBF005"};
        Category[] criticalCategories = {Category.DESTRUCTIVE, Category.DESTRUCTIVE,
                Category.OBFUSCATION};
        for (int i = 0; i < criticalRules.length; i++) {
            ScanReport report = report();
            report.add(signal(criticalRules[i], criticalCategories[i], Severity.CRITICAL));
            report.add(signal("NET001", Category.NETWORK, Severity.LOW));
            IocDatabase db = IocDatabase.empty();
            db.trust(report.contentHash, "synthetic control");
            RiskScorer.score(report, db);
            c.that(criticalRules[i] + " critical evidence still overrides trust",
                    report.verdict() == Verdict.LIKELY_MALICIOUS, describe(report));
        }
        for (String rule : new String[] {"SIG001", "SIG002"}) {
            ScanReport report = report();
            report.add(signal(rule, Category.SIGNATURE, Severity.CRITICAL));
            IocDatabase db = IocDatabase.empty();
            db.trust(report.contentHash, "synthetic control");
            RiskScorer.score(report, db);
            c.that(rule + " retains known-bad verdict despite trust",
                    report.verdict() == Verdict.KNOWN_BAD, describe(report));
        }
        ScanReport denied = report();
        IocDatabase db = IocDatabase.empty();
        db.deny(denied.contentHash, "synthetic deny control");
        db.trust(denied.contentHash, "synthetic trust control");
        RiskScorer.score(denied, db);
        c.that("explicit denylist retains known-bad verdict",
                denied.verdict() == Verdict.KNOWN_BAD && denied.hasRule("PRV001"), describe(denied));

        ScanReport strong = report();
        strong.add(signal("SEN001", Category.SENSITIVE_DATA, Severity.HIGH));
        strong.add(signal("SEN002", Category.SENSITIVE_DATA, Severity.HIGH));
        strong.add(signal("NET003", Category.NETWORK, Severity.HIGH));
        RiskScorer.score(strong, IocDatabase.empty());
        c.that("capabilities alone cannot cross into malicious verdict through score accumulation",
                strong.verdict() == Verdict.SUSPICIOUS && strong.score() == 85, describe(strong));

        ScanReport contextual = report();
        contextual.add(signal("CROSS001", Category.CROSS_PLUGIN, Severity.HIGH));
        contextual.add(signal("NET001", Category.NETWORK, Severity.LOW));
        contextual.add(signal("DES001", Category.DESTRUCTIVE, Severity.HIGH));
        contextual.add(signal("OBF001", Category.OBFUSCATION, Severity.MEDIUM));
        contextual.add(signal("SEN005", Category.SENSITIVE_DATA, Severity.MEDIUM));
        RiskScorer.score(contextual, IocDatabase.empty());
        for (String rule : new String[] {"CMB104", "CMB106", "CMB107"}) {
            Signal finding = find(contextual, rule);
            c.that(rule + " retains high-severity contextual warning",
                    finding != null && finding.severity == Severity.HIGH, describe(contextual));
        }
        c.that("CMB104 does not claim concealment is deliberate",
                find(contextual, "CMB104").detail.contains("does not establish"), describe(contextual));
        c.that("CMB106 does not assert data was transferred",
                find(contextual, "CMB106").detail.contains("does not establish"), describe(contextual));
        c.that("CMB107 asks the reviewer to assess purpose",
                find(contextual, "CMB107").detail.contains("Review"), describe(contextual));
    }

    private static void sameFile(ActionsTest.Checker c, Fixtures fixtures, String name,
            String pairRule, String packageRule, String localOperation) {
        File plugin = fixtures.directoryPlugin("same-file-capability-" + name,
                Fixtures.manifest("demo.same" + name, "Same File Control", "demo.Local"),
                Fixtures.sources("src/demo/Local.java", "package demo; public class Local { void local() { "
                        + localOperation + " } void status() throws Exception {"
                        + " new java.net.URL(\"https://status.example.test/ping\").openConnection(); } }"));
        ScanReport report = new PluginScanner(IocDatabase.empty()).scan(plugin, ScanBudget.unlimited());
        Signal pair = find(report, pairRule);
        c.that(pairRule + " unrelated methods in one file remain a medium capability finding",
                pair != null && pair.severity == Severity.MEDIUM, describe(report));
        c.that(pairRule + " unrelated methods final verdict is calibrated",
                report.verdict() == Verdict.SUSPICIOUS && report.score() == 38, describe(report));
        c.that(pairRule + " does not assert observed data flow",
                pair != null && pair.detail.contains("does not establish"),
                pair == null ? "missing" : pair.detail);
        c.that(pairRule + " is not duplicated by the package capability rule",
                !report.hasRule(packageRule), describe(report));
    }

    private static void disconnected(ActionsTest.Checker c, Fixtures fixtures, String name,
            String directRule, String combinationRule, String localOperation, int score, Verdict verdict) {
        File plugin = fixtures.directoryPlugin("capability-" + name,
                Fixtures.manifest("demo." + name, "Capability Control", "demo.Local"),
                Fixtures.sources("src/demo/Local.java", "package demo; public class Local { void local() { "
                        + localOperation + " } }", "src/demo/Status.java",
                        "package demo; public class Status { void status() throws Exception {"
                                + " new java.net.URL(\"https://status.example.test/ping\").openConnection(); } }"));
        ScanReport report = new PluginScanner(IocDatabase.empty()).scan(plugin, ScanBudget.unlimited());
        c.that(name + " disconnected controls retain source findings",
                report.hasRule(directRule) && report.hasRule("NET001") && report.hasRule(combinationRule),
                describe(report));
        c.that(name + " disconnected control final verdict is calibrated",
                report.verdict() == verdict && report.score() == score, describe(report));
        c.that(name + " disconnected control does not acquire same-file execution evidence",
                !report.hasRule("CMB002") && !report.hasRule("CMB003"), describe(report));
    }

    private static ScanReport report() {
        return new ScanReport("control", "/inert/control", false, false,
                PluginManifest.parse(Fixtures.bytes(Fixtures.manifest("demo.control", "Control", "demo.A"))),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    }

    private static Signal signal(String id, Category category, Severity severity) {
        return new Signal(id, category, severity, "Synthetic control", "Inert scoring fixture");
    }

    private static Signal find(ScanReport report, String rule) {
        for (Signal signal : report.signals) {
            if (rule.equals(signal.ruleId)) {
                return signal;
            }
        }
        return null;
    }

    private static int count(ScanReport report, String rule) {
        int count = 0;
        for (Signal signal : report.signals) {
            if (rule.equals(signal.ruleId)) {
                count++;
            }
        }
        return count;
    }

    private static String describe(ScanReport report) {
        StringBuilder text = new StringBuilder(report.verdict() + " score=" + report.score());
        for (Signal signal : report.signals) {
            text.append(' ').append(signal.ruleId).append('=').append(signal.severity);
        }
        return text.toString();
    }
}
