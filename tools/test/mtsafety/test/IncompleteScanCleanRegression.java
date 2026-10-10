package mtsafety.test;

import java.io.File;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

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

        readFailures(c, fixtures);
        riskyPartial(c, fixtures);
        qualifiedSurfaces(c, partial);
    }

    private static void qualifiedSurfaces(ActionsTest.Checker c, ScanReport partial) {
        c.that("headline of a partial scan is not a bare Clean",
                !partial.headline().startsWith("Clean") && partial.headline().startsWith("Incomplete scan"),
                partial.headline());
        String text = ReportFormatter.plainText(partial);
        c.that("plain text separates the coverage warning from threat findings even with SCN001 present",
                text.contains("Coverage warning") && text.contains("No findings in inspected content")
                        && text.contains("SCN001"), text);
        String overview = ReportFormatter.overview(Arrays.asList(partial));
        c.that("overview states the total partial count", overview.contains("1 with incomplete coverage"),
                overview);
        ScanReport bad = new PluginScanner(IocDatabase.empty()).scan(new File(partial.path),
                new ScanBudget(0L, 0L));
        bad.setVerdict(Verdict.KNOWN_BAD, "matches a signature");
        c.that("known-bad with partial coverage keeps its label, flags incompleteness and is actionable",
                bad.verdict().actionable() && bad.dispositionLabel().startsWith("Known bad")
                        && bad.dispositionLabel().contains("inspection incomplete")
                        && ReportFormatter.overview(Arrays.asList(bad)).contains("1 to remove"),
                bad.dispositionLabel() + " :: " + ReportFormatter.overview(Arrays.asList(bad)));
    }

    private static void readFailures(ActionsTest.Checker c, Fixtures fixtures) {
        // An unreadable source member in an otherwise benign plugin.
        File dir = fixtures.directoryPlugin("unreadable-member",
                Fixtures.manifest("demo.unreadable", "Unreadable Member", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN, "src/demo/B.java", BENIGN));
        File locked = new File(dir, "src/demo/B.java");
        boolean denied = locked.setReadable(false, false) && !locked.canRead();
        c.that("fixture: a member really is unreadable (needs a non-root user)", denied, locked.toString());
        ScanReport r = new PluginScanner(IocDatabase.empty()).scan(dir, ScanBudget.unlimited());
        locked.setReadable(true, false);
        c.that("unreadable member => not COMPLETE, not an unqualified CLEAN",
                r.coverage() == Coverage.PARTIAL && !r.errors.isEmpty()
                        && !ReportFormatter.summaryLine(r).startsWith("Clean")
                        && r.dispositionLabel().equals("Incomplete scan"),
                r.coverage() + " :: " + r.errors + " :: " + ReportFormatter.summaryLine(r));

        // A nested jar whose member is corrupt.
        Map<String, byte[]> inner = new LinkedHashMap<String, byte[]>();
        StringBuilder big = new StringBuilder();
        for (int i = 0; i < 400; i++) {
            big.append("line ").append(i * 7919 % 1013).append(" of harmless text\n");
        }
        inner.put("lib/Util.txt", Fixtures.bytes(big.toString()));
        byte[] jar = Fixtures.deflatedJar(inner);
        for (int i = 60; i < jar.length - 120 && i < 200; i++) {
            jar[i] = (byte) 0xFF;
        }
        Map<String, byte[]> outer = new LinkedHashMap<String, byte[]>();
        outer.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.nested", "Nested", "demo.A")));
        outer.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        outer.put("libs/broken.jar", jar);
        ScanReport nested = new PluginScanner(IocDatabase.empty()).scan(
                fixtures.deflatedArchive("nested-broken.mtp", outer), ScanBudget.unlimited());
        c.that("corrupt nested member => partial coverage and a recorded error",
                nested.coverage() == Coverage.PARTIAL && !nested.errors.isEmpty()
                        && !ReportFormatter.summaryLine(nested).startsWith("Clean"),
                nested.coverage() + " :: " + nested.errors);

        // A manifest that cannot be read.
        File mdir = fixtures.directoryPlugin("unreadable-manifest",
                Fixtures.manifest("demo.mf", "Manifest", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN));
        File mf = new File(mdir, "manifest.json");
        mf.setReadable(false, false);
        ScanReport m = new PluginScanner(IocDatabase.empty()).scan(mdir, ScanBudget.unlimited());
        mf.setReadable(true, false);
        c.that("unreadable manifest => not COMPLETE", m.coverage() != Coverage.COMPLETE
                && !ReportFormatter.summaryLine(m).startsWith("Clean"),
                m.coverage() + " :: " + ReportFormatter.summaryLine(m));
    }

    private static void riskyPartial(ActionsTest.Checker c, Fixtures fixtures) {
        String risky = "package demo;\n"
                + "public class A { public void f() throws Exception { Runtime.getRuntime().exec(\"ls\"); } }\n";
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        byte[] manifest = Fixtures.bytes(Fixtures.manifest("demo.risky", "Risky Partial", "demo.A"));
        members.put("manifest.json", manifest);
        members.put("src/demo/A.java", Fixtures.bytes(risky));
        members.put("src/demo/B.java", Fixtures.bytes(BENIGN));
        File archive = fixtures.deflatedArchive("risky-partial.mtp", members);
        ScanReport full = new PluginScanner(IocDatabase.empty()).scan(archive, ScanBudget.unlimited());
        c.that("fixture: the risky member is flagged when fully scanned",
                full.verdict().flagged() && full.coverage() == Coverage.COMPLETE, full.verdict().toString());
        long budgetBytes = manifest.length + Fixtures.bytes(risky).length + 1;
        ScanReport part = new PluginScanner(IocDatabase.empty()).scan(archive, new ScanBudget(60000L, budgetBytes));
        c.that("risky member read before the budget ran out keeps its finding, verdict and evidence",
                part.coverage() == Coverage.PARTIAL && part.verdict().flagged()
                        && part.verdict() == full.verdict() && part.hasRule("SCN001")
                        && part.signalsBySeverity().get(0).ruleId.equals(full.signalsBySeverity().get(0).ruleId)
                        && !part.signalsBySeverity().get(0).evidence().isEmpty()
                        && ReportFormatter.summaryLine(part).contains("inspection incomplete")
                        && part.dispositionLabel().contains("inspection incomplete"),
                part.coverage() + " " + part.verdict() + " :: " + ReportFormatter.summaryLine(part)
                        + " :: " + part.signals.size());
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
