package mtsafety.test;

import java.io.File;

import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Verdict;

/** Explicit expected-red reproducer for the incomplete-scan CLEAN display issue. */
public final class IncompleteScanCleanRegression {

    public static void main(String[] args) {
        File root = new File(System.getProperty("java.io.tmpdir"),
                "mtsafety-incomplete-regression-" + System.currentTimeMillis());
        if (!root.mkdirs()) {
            throw new IllegalStateException("could not create " + root);
        }
        Fixtures fixtures = new Fixtures(root);
        File plugin = fixtures.directoryPlugin("benign-partial",
                Fixtures.manifest("demo.partial", "Benign Partial", "demo.A"),
                Fixtures.sources("src/demo/A.java", "package demo;\n"
                        + "public class A { public int n() { return 1; } }\n"));
        ScanReport report = new PluginScanner(IocDatabase.empty()).scan(plugin, new ScanBudget(0L, 0L));
        String summary = ReportFormatter.summaryLine(report);
        if (!report.truncated() || !report.hasRule("SCN001")) {
            throw new AssertionError("fixture did not produce the expected incomplete scan: "
                    + summary + ", truncated=" + report.truncated());
        }
        if (report.verdict() == Verdict.CLEAN || report.verdict() == Verdict.TRUSTED
                || summary.startsWith(Verdict.CLEAN.label()) || summary.startsWith(Verdict.TRUSTED.label())) {
            throw new AssertionError("incomplete package is presented as an unqualified all-clear: " + summary);
        }
    }

    private IncompleteScanCleanRegression() {
    }
}
