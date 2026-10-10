package mtsafety.test;

import java.io.File;
import java.util.Arrays;

import mt.safety.scanner.core.Coverage;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Verdict;

/**
 * Gating checks that an incomplete scan is never presented as an unqualified all-clear. Also runnable
 * on its own: {@code java -cp ... mtsafety.test.IncompleteScanCleanRegression}.
 */
public final class IncompleteScanCleanRegression {

    private static final String BENIGN = "package demo;\n"
            + "public class A { public int n() { return 1; } }\n";

    public static void main(String[] args) {
        File root = new File(System.getProperty("java.io.tmpdir"),
                "mtsafety-incomplete-regression-" + System.currentTimeMillis());
        if (!root.mkdirs()) {
            throw new IllegalStateException("could not create " + root);
        }
        final int[] failed = {0};
        run(new ActionsTest.Checker() {
            @Override
            public void that(String description, boolean condition, String context) {
                if (!condition) {
                    failed[0]++;
                    System.out.println("FAILED: " + description + " :: " + context);
                }
            }
        }, new Fixtures(root));
        if (failed[0] > 0) {
            throw new AssertionError(failed[0] + " incomplete-scan checks failed");
        }
    }

    static void run(ActionsTest.Checker c, Fixtures fixtures) {
        File plugin = fixtures.directoryPlugin("benign-partial",
                Fixtures.manifest("demo.partial", "Benign Partial", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN));

        ScanReport complete = new PluginScanner(IocDatabase.empty()).scan(plugin, ScanBudget.unlimited());
        c.that("complete benign scan stays CLEAN", complete.verdict() == Verdict.CLEAN
                && complete.coverage() == Coverage.COMPLETE
                && ReportFormatter.summaryLine(complete).equals("Clean"),
                ReportFormatter.summaryLine(complete));

        ScanReport partial = new PluginScanner(IocDatabase.empty()).scan(plugin, new ScanBudget(0L, 0L));
        String summary = ReportFormatter.summaryLine(partial);
        c.that("budget-exhausted scan reports truncation and SCN001",
                partial.truncated() && partial.hasRule("SCN001") && partial.coverage() == Coverage.PARTIAL,
                summary);
        c.that("partial benign summary is not an unqualified Clean",
                !summary.startsWith("Clean") && summary.contains("inspection incomplete"), summary);
        c.that("partial benign text, advice and label never read Clean or Trusted",
                !partial.dispositionLabel().equals("Clean") && !partial.dispositionLabel().equals("Trusted")
                        && ReportFormatter.plainText(partial).contains("Coverage: Partial")
                        && ReportFormatter.plainText(partial).contains("Verdict : Incomplete scan")
                        && partial.dispositionAdvice().contains("not an all-clear"),
                ReportFormatter.plainText(partial));
        String json = ReportFormatter.json(Arrays.asList(partial));
        c.that("JSON keeps legacy fields and adds coverage",
                json.contains("\"verdict\": \"CLEAN\"") && json.contains("\"truncated\": true")
                        && json.contains("\"coverage\": \"PARTIAL\"")
                        && json.contains("\"disposition\": \"Incomplete scan\""), json);
        String overview = ReportFormatter.overview(Arrays.asList(complete, partial));
        c.that("overview counts partial separately from clean",
                overview.contains("1 clean") && overview.contains("1 incomplete"), overview);

        ScanReport trusted = scanTrusted(plugin, ScanBudget.unlimited());
        trusted.setTruncated(true);
        c.that("trusted identity with partial inspection is qualified", trusted.verdict() == Verdict.TRUSTED
                && trusted.dispositionLabel().contains("inspection incomplete")
                && !ReportFormatter.summaryLine(trusted).equals("Trusted"),
                ReportFormatter.summaryLine(trusted));
        ScanReport trustedFull = scanTrusted(plugin, ScanBudget.unlimited());
        c.that("complete trusted scan stays TRUSTED",
                trustedFull.verdict() == Verdict.TRUSTED
                        && ReportFormatter.summaryLine(trustedFull).equals("Trusted"),
                ReportFormatter.summaryLine(trustedFull));

        File noisy = fixtures.directoryPlugin("risky-partial",
                Fixtures.manifest("demo.risky", "Risky Partial", "demo.A"),
                Fixtures.sources("src/demo/A.java", "package demo;\n"
                        + "public class A { public void f() throws Exception {"
                        + " Runtime.getRuntime().exec(\"ls\"); } }\n"));
        ScanReport risky = new PluginScanner(IocDatabase.empty()).scan(noisy,
                new ScanBudget(10L * 1024 * 1024, 60000L));
        ScanReport riskyPartial = new PluginScanner(IocDatabase.empty()).scan(noisy, new ScanBudget(0L, 0L));
        c.that("fixture without budget pressure is flagged", risky.verdict().flagged(),
                risky.verdict().toString());
        if (riskyPartial.verdict().flagged()) {
            c.that("partial flagged scan keeps its verdict and says it is incomplete",
                    ReportFormatter.summaryLine(riskyPartial).contains("inspection incomplete")
                            && riskyPartial.verdict() == risky.verdict(),
                    ReportFormatter.summaryLine(riskyPartial));
        }
    }

    private static ScanReport scanTrusted(File plugin, ScanBudget budget) {
        ScanReport first = new PluginScanner(IocDatabase.empty()).scan(plugin, ScanBudget.unlimited());
        IocDatabase trusting = IocDatabase.empty();
        trusting.trust(first.contentHash, "test");
        return new PluginScanner(trusting).scan(plugin, budget);
    }

    private IncompleteScanCleanRegression() {
    }
}
