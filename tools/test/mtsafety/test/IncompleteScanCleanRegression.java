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

        lowFindingSurfaces(c, fixtures, complete, partial);

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
        directoryListingCutoffs(c, fixtures);
        riskyPartial(c, fixtures);
        qualifiedSurfaces(c, partial);
    }

    private static void lowFindingSurfaces(ActionsTest.Checker c, Fixtures fixtures, ScanReport completeBenign,
            ScanReport partialBenign) {
        Map<String, byte[]> wrapped = new LinkedHashMap<String, byte[]>();
        wrapped.put("wrapper/manifest.json",
                Fixtures.bytes(Fixtures.manifest("demo.wrapped", "Wrapped", "demo.A")));
        wrapped.put("wrapper/src/demo/A.java", Fixtures.bytes(BENIGN));
        File archive = fixtures.deflatedArchive("low-finding-wrapped.mtp", wrapped);
        PluginScanner scanner = new PluginScanner(IocDatabase.empty());
        ScanReport completeLow = scanner.scan(archive, ScanBudget.unlimited());
        ScanReport partialLow = scanner.scan(archive, new ScanBudget(0L, 0L));
        String completeText = ReportFormatter.plainText(completeLow);
        String partialText = ReportFormatter.plainText(partialLow);
        c.that("complete LOW finding remains visible without a Clean/no-findings claim",
                completeLow.verdict() == Verdict.CLEAN && completeLow.hasRule("ARC008")
                        && completeLow.coverage() == Coverage.COMPLETE
                        && !ReportFormatter.summaryLine(completeLow).startsWith("Clean")
                        && ReportFormatter.summaryLine(completeLow).contains("finding")
                        && completeLow.dispositionAdvice().contains("Findings were recorded")
                        && !completeText.contains("No findings.")
                        && completeText.contains("ARC008"),
                ReportFormatter.summaryLine(completeLow) + " :: " + completeLow.dispositionAdvice()
                        + " :: " + completeText);
        c.that("partial LOW finding stays distinct from SCN001 and MFT012 coverage notices",
                partialLow.verdict() == Verdict.CLEAN && partialLow.coverage() == Coverage.PARTIAL
                        && partialLow.hasRule("ARC008") && partialLow.hasRule("SCN001")
                        && partialLow.hasRule("MFT012")
                        && ReportFormatter.summaryLine(partialLow).contains("finding")
                        && partialLow.dispositionAdvice().contains("Findings were recorded")
                        && !partialText.contains("No findings in inspected content")
                        && partialText.contains("ARC008") && partialText.contains("Coverage warning"),
                ReportFormatter.summaryLine(partialLow) + " :: " + partialLow.dispositionAdvice()
                        + " :: " + partialText);
        String mixedOverview = ReportFormatter.overview(Arrays.asList(
                completeBenign, completeLow, partialBenign, partialLow));
        c.that("mixed overview separates findings from complete and partial no-finding scans",
                mixedOverview.contains("1 clean") &&                 mixedOverview.contains("1 with findings")
                        && mixedOverview.contains("1 incomplete (no findings")
                        && mixedOverview.contains("1 incomplete with findings"),
                mixedOverview);
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
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.unreadable",
                "Unreadable Member", "demo.A")));
        members.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        members.put("src/demo/B.java", Fixtures.bytes(BENIGN));
        File archive = fixtures.deflatedArchiveWithUnreadableMember("unreadable-member.mtp", members,
                "src/demo/B.java");
        ScanReport r = new PluginScanner(IocDatabase.empty()).scan(archive, ScanBudget.unlimited());
        c.that("unreadable member => not COMPLETE, not an unqualified CLEAN",
                r.coverage() == Coverage.PARTIAL && !r.errors.isEmpty()
                        && !ReportFormatter.summaryLine(r).startsWith("Clean")
                        && !r.dispositionLabel().equals("Clean"),
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

        nestedBoundaries(c, fixtures);

        Map<String, byte[]> manifestMembers = new LinkedHashMap<String, byte[]>();
        manifestMembers.put("manifest.json",
                Fixtures.bytes(Fixtures.manifest("demo.mf", "Manifest", "demo.A")));
        manifestMembers.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        File unreadableManifest = fixtures.deflatedArchiveWithUnreadableMember(
                "unreadable-manifest.mtp", manifestMembers, "manifest.json");
        ScanReport m = new PluginScanner(IocDatabase.empty()).scan(unreadableManifest, ScanBudget.unlimited());
        c.that("unreadable manifest => PARTIAL", m.coverage() == Coverage.PARTIAL
                && !ReportFormatter.summaryLine(m).startsWith("Clean"),
                m.coverage() + " :: " + ReportFormatter.summaryLine(m));
        String mText = ReportFormatter.plainText(m);
        c.that("unreadable manifest is partial and retains its coverage notice",
                m.coverage() == Coverage.PARTIAL && m.hasRule("MFT012")
                        && mText.contains("Coverage warning") && mText.contains("MFT012"), mText);
        unsupported(c, fixtures);
        nestedBudget(c, fixtures);
    }

    private static void directoryListingCutoffs(ActionsTest.Checker c, Fixtures fixtures) {
        StringBuilder deepPath = new StringBuilder();
        for (int i = 0; i < 25; i++) {
            deepPath.append("d/");
        }
        deepPath.append("omitted.txt");
        File deep = fixtures.directoryPlugin("deep-directory-listing",
                Fixtures.manifest("demo.deep", "Deep Directory", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN, deepPath.toString(), "not inspected"));
        ScanReport depthLimited = new PluginScanner(IocDatabase.empty()).scan(deep, ScanBudget.unlimited());
        c.that("directory depth cutoff is PARTIAL and keeps SCN001 without a bare all-clear",
                depthLimited.coverage() == Coverage.PARTIAL && depthLimited.hasRule("SCN001")
                        && !ReportFormatter.summaryLine(depthLimited).equals("Clean")
                        && !ReportFormatter.summaryLine(depthLimited).equals("Trusted")
                        && depthLimited.contentHash.length() == 0,
                depthLimited.coverage() + " :: " + ReportFormatter.summaryLine(depthLimited));

        File countLimited = fixtures.directoryPlugin("count-limited-directory",
                Fixtures.manifest("demo.count", "Count Limited", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN));
        try {
            for (int i = 0; i < 8001; i++) {
                if (!new File(countLimited, String.format("f%05d.dat", i)).createNewFile()) {
                    throw new IllegalStateException("could not create count-cap fixture member " + i);
                }
            }
        } catch (java.io.IOException e) {
            throw new IllegalStateException("could not create count-cap fixture", e);
        }
        ScanReport countLimitedReport = new PluginScanner(IocDatabase.empty()).scan(countLimited,
                ScanBudget.unlimited());
        c.that("directory file-count cutoff is PARTIAL with no partial package identity",
                countLimitedReport.coverage() == Coverage.PARTIAL && countLimitedReport.hasRule("SCN001")
                        && countLimitedReport.contentHash.length() == 0
                        && !ReportFormatter.summaryLine(countLimitedReport).equals("Clean")
                        && !ReportFormatter.summaryLine(countLimitedReport).equals("Trusted"),
                countLimitedReport.coverage() + " :: " + countLimitedReport.filesScanned());

        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.sibling", "Sibling", "demo.A")));
        members.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        File installed = fixtures.installedArchive("deep-sidecar-listing", members, null);
        Fixtures.writeBytes(new File(installed, "a/b/c/d/omitted.txt"), Fixtures.bytes("not inspected"));
        ScanReport siblingsLimited = new PluginScanner(IocDatabase.empty()).scan(installed,
                ScanBudget.unlimited());
        c.that("installed sidecar depth cutoff is PARTIAL and reports SCN001",
                siblingsLimited.coverage() == Coverage.PARTIAL && siblingsLimited.hasRule("SCN001")
                        && siblingsLimited.contentHash.length() == 0
                        && !ReportFormatter.summaryLine(siblingsLimited).equals("Clean")
                        && !ReportFormatter.summaryLine(siblingsLimited).equals("Trusted"),
                siblingsLimited.coverage() + " :: " + ReportFormatter.summaryLine(siblingsLimited));

        File countLimitedSiblings = fixtures.installedArchive("count-limited-sidecars", members, null);
        try {
            for (int i = 0; i < 401; i++) {
                if (!new File(countLimitedSiblings, String.format("s%03d.dat", i)).createNewFile()) {
                    throw new IllegalStateException("could not create sidecar count fixture " + i);
                }
            }
        } catch (java.io.IOException e) {
            throw new IllegalStateException("could not create sidecar count fixture", e);
        }
        ScanReport sidecarCountLimited = new PluginScanner(IocDatabase.empty()).scan(countLimitedSiblings,
                ScanBudget.unlimited());
        c.that("installed sidecar count cutoff is PARTIAL with SCN001",
                sidecarCountLimited.coverage() == Coverage.PARTIAL && sidecarCountLimited.hasRule("SCN001")
                        && sidecarCountLimited.contentHash.length() == 0,
                sidecarCountLimited.coverage() + " :: " + sidecarCountLimited.filesScanned());
    }

    private static void unsupported(ActionsTest.Checker c, Fixtures fixtures) {
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.m95", "Method 95", "demo.A")));
        members.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        members.put("assets/opaque.bin", Fixtures.bytes("inert, deliberately non-XZ method-95 marker"));
        File archive = fixtures.unsupportedMethod95Archive("unsupported-coverage.mtp", members,
                "assets/opaque.bin");
        ScanReport r = new PluginScanner(IocDatabase.empty()).scan(archive, ScanBudget.unlimited());
        String text = ReportFormatter.plainText(r);
        String json = ReportFormatter.json(Arrays.asList(r));
        c.that("unsupported ZIP95 package has truthful coverage and no inspected-content claims",
                r.verdict() == Verdict.UNREADABLE && r.coverage() == Coverage.UNSUPPORTED_OR_UNREADABLE
                        && r.dispositionLabel().equals("Could not scan")
                        && text.contains("Coverage: Unsupported or unreadable")
                        && text.contains("Nothing could be inspected; no verdict on the contents.")
                        && !text.contains("No findings in inspected content")
                        && !ReportFormatter.summaryLine(r).startsWith("Clean")
                        && json.contains("\"coverage\": \"UNSUPPORTED_OR_UNREADABLE\"")
                        && json.contains("\"disposition\": \"Could not scan\"")
                        && json.contains("\"verdict\": \"UNREADABLE\""),
                r.coverage() + " :: " + text);
        String overview = ReportFormatter.overview(Arrays.asList(r));
        c.that("unsupported ZIP95 package is counted unreadable, never clean",
                overview.contains("1 unreadable") && overview.contains("0 clean"), overview);

        // A missing path is entirely inaccessible, unlike a readable plugin with some skipped members.
        File missing = new File(archive.getParentFile(), "does-not-exist-coverage-test.mtp");
        c.that("fixture: missing package path does not exist", !missing.exists(), missing.toString());
        ScanReport absent = new PluginScanner(IocDatabase.empty()).scan(missing, ScanBudget.unlimited());
        String absentText = ReportFormatter.plainText(absent);
        String absentJson = ReportFormatter.json(Arrays.asList(absent));
        String absentOverview = ReportFormatter.overview(Arrays.asList(absent));
        c.that("inaccessible path has no false inspected-content or clean disposition",
                absent.verdict() == Verdict.UNREADABLE
                        && absent.coverage() == Coverage.UNSUPPORTED_OR_UNREADABLE
                        && absent.dispositionLabel().equals("Could not scan")
                        && absentText.contains("Nothing could be inspected; no verdict on the contents.")
                        && !absentText.contains("No findings in inspected content")
                        && !ReportFormatter.summaryLine(absent).startsWith("Clean")
                        && absentOverview.contains("1 unreadable") && absentOverview.contains("0 clean")
                        && absentJson.contains("\"coverage\": \"UNSUPPORTED_OR_UNREADABLE\"")
                        && absentJson.contains("\"disposition\": \"Could not scan\"")
                        && absentJson.contains("\"verdict\": \"UNREADABLE\""),
                absent.coverage() + " :: " + absentText + " :: " + absentOverview);

        File invalidArchive = fixtures.unreadableArchive("unreadable-root.mtp");
        ScanReport unreadableRoot = new PluginScanner(IocDatabase.empty()).scan(invalidArchive,
                ScanBudget.unlimited());
        c.that("fully unreadable root package remains unsupported/unreadable",
                unreadableRoot.verdict() == Verdict.UNREADABLE
                        && unreadableRoot.coverage() == Coverage.UNSUPPORTED_OR_UNREADABLE
                        && ReportFormatter.overview(Arrays.asList(unreadableRoot)).contains("1 unreadable")
                        && !ReportFormatter.summaryLine(unreadableRoot).startsWith("Clean"),
                unreadableRoot.coverage() + " :: " + ReportFormatter.summaryLine(unreadableRoot));

    }

    private static void nestedBudget(ActionsTest.Checker c, Fixtures fixtures) {
        StringBuilder sb = new StringBuilder();
        while (sb.length() < 600 * 1024) {
            sb.append("harmless padding line\n");
        }
        Map<String, byte[]> inner = new LinkedHashMap<String, byte[]>();
        inner.put("big.txt", Fixtures.bytes(sb.toString()));
        inner.put("after-limit.java", Fixtures.bytes("package demo; class After { void f() throws"
                + " Exception { Runtime.getRuntime().exec(\"ls\"); } }"));
        Map<String, byte[]> outer = new LinkedHashMap<String, byte[]>();
        byte[] manifest = Fixtures.bytes(Fixtures.manifest("demo.nb", "Nested Budget", "demo.A"));
        byte[] source = Fixtures.bytes(BENIGN);
        byte[] jar = Fixtures.deflatedJar(inner);
        outer.put("manifest.json", manifest);
        outer.put("src/demo/A.java", source);
        outer.put("libs/lib.jar", jar);
        File archive = fixtures.deflatedArchive("nest-near-exhausted.mtp", outer);
        long max = manifest.length + source.length + jar.length + 4096L;
        ScanBudget budget = new ScanBudget(60000L, max);
        ScanReport r = new PluginScanner(IocDatabase.empty()).scan(archive, budget);
        c.that("near-exhausted budget: nested member is PARTIAL, charges stay within budget, later member"
                        + " is never inspected",
                r.coverage() == Coverage.PARTIAL && r.hasRule("SCN001") && budget.bytesUsed() <= max
                        && !ReportFormatter.plainText(r).contains("after-limit.java"),
                r.coverage() + " used=" + budget.bytesUsed() + " max=" + max);
    }

    private static byte[] jarOf(String name, byte[] content) {
        Map<String, byte[]> m = new LinkedHashMap<String, byte[]>();
        m.put(name, content);
        return Fixtures.deflatedJar(m);
    }

    private static ScanReport scanWithJar(Fixtures fixtures, String file, byte[] jar) {
        Map<String, byte[]> outer = new LinkedHashMap<String, byte[]>();
        outer.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.nest", "Nest", "demo.A")));
        outer.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        outer.put("libs/lib.jar", jar);
        return new PluginScanner(IocDatabase.empty()).scan(fixtures.deflatedArchive(file, outer),
                ScanBudget.unlimited());
    }

    private static void nestedBoundaries(ActionsTest.Checker c, Fixtures fixtures) {
        byte[] text = Fixtures.bytes("harmless nested text\n");
        byte[] two = jarOf("b.jar", jarOf("note.txt", text));
        ScanReport shallow = scanWithJar(fixtures, "nest-shallow.mtp", two);
        c.that("shallow nested archives stay COMPLETE and CLEAN",
                shallow.coverage() == Coverage.COMPLETE && shallow.verdict() == Verdict.CLEAN
                        && shallow.errors.isEmpty(), shallow.coverage() + " :: " + shallow.errors);

        byte[] three = jarOf("b.jar", jarOf("c.jar", jarOf("note.txt", text)));
        ScanReport deep = scanWithJar(fixtures, "nest-deep.mtp", three);
        c.that("archive nested past the depth cap is PARTIAL with a recorded reason",
                deep.coverage() == Coverage.PARTIAL && deep.hasRule("SCN001") && !deep.errors.isEmpty()
                        && !ReportFormatter.summaryLine(deep).startsWith("Clean"),
                deep.coverage() + " :: " + deep.errors);

        StringBuilder sb = new StringBuilder();
        while (sb.length() < 600 * 1024) {
            sb.append("harmless padding line\n");
        }
        ScanReport big = scanWithJar(fixtures, "nest-big.mtp", jarOf("big.txt", Fixtures.bytes(sb.toString())));
        c.that("oversized nested member is PARTIAL, not COMPLETE",
                big.coverage() == Coverage.PARTIAL && big.hasRule("SCN001")
                        && !ReportFormatter.summaryLine(big).startsWith("Clean"),
                big.coverage() + " :: " + ReportFormatter.summaryLine(big));

        // Calling ZipInputStream.getNextEntry() after a short bounded read can silently inflate
        // the entire remainder of that entry. Stop traversal instead of visiting later members.
        Map<String, byte[]> overAndAfter = new LinkedHashMap<String, byte[]>();
        overAndAfter.put("big.txt", Fixtures.bytes(sb.toString()));
        overAndAfter.put("after-limit.java", Fixtures.bytes("package demo; public class After { "
                + "void f() throws Exception { Runtime.getRuntime().exec(\\\"ls\\\"); } }"));
        ScanReport bounded = scanWithJar(fixtures, "nest-overlimit-stop.mtp",
                Fixtures.deflatedJar(overAndAfter));
        String boundedEvidence = ReportFormatter.plainText(bounded);
        c.that("nested ZIP stops after oversized member without examining the next member",
                bounded.coverage() == Coverage.PARTIAL && bounded.hasRule("SCN001")
                        && !boundedEvidence.contains("after-limit.java"),
                bounded.coverage() + " :: " + boundedEvidence);
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
