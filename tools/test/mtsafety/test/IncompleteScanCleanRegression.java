package mtsafety.test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import mt.safety.scanner.core.Category;
import mt.safety.scanner.core.Coverage;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Severity;
import mt.safety.scanner.core.Signal;
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

    private static final class ListingFailureFile extends File {
        private static final long serialVersionUID = 1L;
        private final String failurePath;

        ListingFailureFile(File file) {
            this(file, file);
        }

        ListingFailureFile(File file, File failure) {
            super(file.getPath());
            failurePath = failure.getPath();
        }

        @Override
        public File[] listFiles() {
            if (getPath().equals(failurePath)) {
                return null;
            }
            File[] children = super.listFiles();
            if (children != null) {
                for (int i = 0; i < children.length; i++) {
                    if (children[i].getPath().equals(failurePath)) {
                        children[i] = new ListingFailureFile(children[i], new File(failurePath));
                    }
                }
            }
            return children;
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

        lowSeverityCoverage(c, fixtures, partial);
        externalCodeCoverage(c, fixtures);
        directoryCutoffs(c, fixtures);

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
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest(
                "demo.unreadable", "Unreadable Member", "demo.A")));
        members.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        members.put("src/demo/B.java", Fixtures.bytes(BENIGN));
        File archive = fixtures.deflatedArchive("unreadable-member.mtp", members);
        Fixtures.makeMemberUnreadable(archive, "src/demo/B.java");
        ScanReport r = new PluginScanner(IocDatabase.empty()).scan(archive, ScanBudget.unlimited());
        c.that("unreadable member => not COMPLETE, not an unqualified CLEAN",
                r.coverage() == Coverage.PARTIAL && !r.errors.isEmpty()
                        && !ReportFormatter.summaryLine(r).startsWith("Clean")
                        && !r.dispositionLabel().startsWith("Trusted"),
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
        manifestMembers.put("manifest.json", Fixtures.bytes(
                Fixtures.manifest("demo.mf", "Manifest", "demo.A")));
        manifestMembers.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        File badManifest = fixtures.deflatedArchive("unreadable-manifest.mtp", manifestMembers);
        Fixtures.makeMemberUnreadable(badManifest, "manifest.json");
        ScanReport m = new PluginScanner(IocDatabase.empty()).scan(badManifest, ScanBudget.unlimited());
        c.that("unreadable manifest => PARTIAL", m.coverage() == Coverage.PARTIAL
                && !ReportFormatter.summaryLine(m).startsWith("Clean"),
                m.coverage() + " :: " + ReportFormatter.summaryLine(m));
        String mText = ReportFormatter.plainText(m);
        c.that("unreadable manifest is a coverage limit, so no threat findings are reported",
                m.hasRule("MFT012") && mText.contains("No findings in inspected content")
                        && mText.contains("Coverage warning"), mText);
        unsupported(c, fixtures);
        nestedBudget(c, fixtures);
    }

    private static void lowSeverityCoverage(ActionsTest.Checker c, Fixtures fixtures, ScanReport partialBenign) {
        Map<String, byte[]> wrapped = new LinkedHashMap<String, byte[]>();
        wrapped.put("Wrapper/manifest.json", Fixtures.bytes(
                Fixtures.manifest("demo.low", "Low Signal", "demo.A")));
        wrapped.put("Wrapper/src/demo/A.java", Fixtures.bytes(BENIGN));
        File archive = fixtures.deflatedArchive("low-signal-wrapped.mtp", wrapped);

        ScanReport complete = new PluginScanner(IocDatabase.empty()).scan(archive, ScanBudget.unlimited());
        c.that("complete LOW finding remains present without changing CLEAN scoring",
                complete.coverage() == Coverage.COMPLETE && complete.verdict() == Verdict.CLEAN
                        && complete.hasRule("ARC008")
                        && complete.signalsBySeverity().get(0).severity.name().equals("LOW"),
                complete.verdict() + " :: " + ReportFormatter.plainText(complete));
        c.that("complete LOW finding is disclosed by summary and advice",
                ReportFormatter.summaryLine(complete).toLowerCase().contains("lower-severity")
                        && complete.dispositionAdvice().toLowerCase().contains("lower-severity"),
                ReportFormatter.summaryLine(complete) + " :: " + complete.dispositionAdvice());

        Map<String, byte[]> infoMembers = new LinkedHashMap<String, byte[]>();
        infoMembers.put("manifest.json", Fixtures.bytes(
                Fixtures.v3Manifest("demo.info", "Info Signal", null)));
        infoMembers.put("README.md", Fixtures.bytes("build metadata"));
        ScanReport info = new PluginScanner(IocDatabase.empty()).scan(
                fixtures.deflatedArchive("info-signal.mtp", infoMembers), ScanBudget.unlimited());
        boolean infoSignal = false;
        for (int i = 0; i < info.signals.size(); i++) {
            if ("ARC002".equals(info.signals.get(i).ruleId)
                    && info.signals.get(i).severity == Severity.INFO) {
                infoSignal = true;
            }
        }
        c.that("complete INFO package signal remains visible without changing CLEAN scoring",
                info.coverage() == Coverage.COMPLETE && info.verdict() == Verdict.CLEAN && infoSignal
                        && ReportFormatter.summaryLine(info).contains("Lower-severity findings listed"),
                ReportFormatter.summaryLine(info) + " :: " + ReportFormatter.plainText(info));
        info.setTruncated(true);
        info.add(new Signal("SCN001", Category.PROVENANCE, Severity.INFO,
                "The scan did not read the whole package", "Coverage warning."));
        String infoText = ReportFormatter.plainText(info);
        c.that("partial INFO signal is distinct from coverage notices and never says no findings",
                info.hasPackageFindings() && !infoText.contains("No findings")
                        && infoText.contains("ARC002") && infoText.contains("Coverage notices:")
                        && ReportFormatter.summaryLine(info).contains("Package findings observed"),
                infoText);

        ScanReport partial = new PluginScanner(IocDatabase.empty()).scan(archive, new ScanBudget(0L, 0L));
        String summary = ReportFormatter.summaryLine(partial);
        String text = ReportFormatter.plainText(partial);
        c.that("partial CLEAN with LOW finding preserves ARC008 and does not claim no findings",
                partial.coverage() == Coverage.PARTIAL && partial.verdict() == Verdict.CLEAN
                        && partial.hasRule("ARC008") && summary.toLowerCase().contains("findings observed")
                        && !summary.contains("No findings") && text.contains("ARC008")
                        && text.contains("Package findings were observed") && !text.contains("No findings")
                        && text.contains("Coverage notices:"),
                summary + " :: " + text);
        c.that("partial CLEAN advice acknowledges the observed LOW finding",
                partial.dispositionAdvice().toLowerCase().contains("findings were observed")
                        && !partial.dispositionAdvice().contains("No findings in inspected content"),
                partial.dispositionAdvice());

        String overview = ReportFormatter.overview(Arrays.asList(complete, partial, partialBenign));
        c.that("mixed overview counts partial LOW and benign scans without claiming both have no findings",
                overview.contains("1 clean") && overview.contains("2 incomplete")
                        && !overview.contains("no findings in inspected content"), overview);
    }

    private static void externalCodeCoverage(ActionsTest.Checker c, Fixtures fixtures) {
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(
                        Fixtures.v3Manifest("demo.host.code", "Host Compiled Code", null, "demo.Main")));
        File installed = fixtures.installedArchive("host-compiled-code", members, null);
        ScanReport report = new PluginScanner(IocDatabase.empty()).scan(installed, ScanBudget.unlimited());
        String text = ReportFormatter.plainText(report);
        String json = ReportFormatter.json(Arrays.asList(report));
        c.that("host-compiled code outside the archive is a coverage limitation, not a package finding",
                        report.verdict() == Verdict.CLEAN && report.hasRule("MFT013")
                                && report.coverage() == Coverage.PARTIAL
                                && ReportFormatter.summaryLine(report).contains("inspection incomplete")
                                && report.dispositionAdvice().contains("No findings in inspected content")
                                && text.contains("Coverage notices:") && text.contains("MFT013")
                                && ReportFormatter.overview(Arrays.asList(report)).contains("1 incomplete")
                                && json.contains("\"coverage\": \"PARTIAL\"")
                                && json.contains("\"truncated\": false"),
                        report.coverage() + " :: " + ReportFormatter.summaryLine(report) + " :: " + text);
    }

    private static void directoryCutoffs(ActionsTest.Checker c, Fixtures fixtures) {
        File deep = fixtures.directoryPlugin("deep-directory",
                Fixtures.manifest("demo.deep", "Deep Directory", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN));
        File cursor = new File(deep, "tree");
        for (int i = 0; i < 26; i++) {
            cursor = new File(cursor, "d");
            if (!cursor.mkdirs() && !cursor.isDirectory()) {
                throw new IllegalStateException("could not create deep directory " + cursor);
            }
        }
        write(cursor, "omitted.txt", "not inspected");
        ScanReport directory = new PluginScanner(IocDatabase.empty()).scan(deep, ScanBudget.unlimited());
        c.that("depth-capped directory listing marks partial coverage and withholds its hash",
                directory.coverage() == Coverage.PARTIAL && directory.hasRule("SCN001")
                        && directory.contentHash.length() == 0
                        && !ReportFormatter.summaryLine(directory).startsWith("Clean"),
                directory.coverage() + " :: " + ReportFormatter.summaryLine(directory));

        File listed = fixtures.directoryPlugin("listing-failure",
                Fixtures.manifest("demo.listing", "Listing Failure", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN));
        ScanReport listingFailure = new PluginScanner(IocDatabase.empty()).scan(
                new ListingFailureFile(listed), ScanBudget.unlimited());
        c.that("null directory listing is partial, records SCN001, and yields no hash",
                listingFailure.coverage() == Coverage.PARTIAL && listingFailure.hasRule("SCN001")
                        && listingFailure.contentHash.length() == 0 && listingFailure.hasRule("MFT012")
                        && !listingFailure.hasRule("MFT001"),
                listingFailure.coverage() + " :: " + ReportFormatter.summaryLine(listingFailure));

        File absentManifest = fixtures.directoryPlugin("nested-cutoff-no-manifest",
                Fixtures.manifest("demo.nomanifest", "Nested Cutoff", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN));
        if (!new File(absentManifest, "manifest.json").delete()) {
            throw new IllegalStateException("could not remove nested-cutoff manifest fixture");
        }
        File absentCursor = new File(absentManifest, "tree");
        for (int i = 0; i < 26; i++) {
            absentCursor = new File(absentCursor, "d");
            if (!absentCursor.mkdirs() && !absentCursor.isDirectory()) {
                throw new IllegalStateException("could not create absent-manifest tree " + absentCursor);
            }
        }
        write(absentCursor, "omitted.txt", "not inspected");
        ScanReport nestedCutoffMissingManifest = new PluginScanner(IocDatabase.empty()).scan(
                absentManifest, ScanBudget.unlimited());
        c.that("nested listing cutoff does not hide a confirmed root manifest absence",
                nestedCutoffMissingManifest.coverage() == Coverage.PARTIAL
                        && nestedCutoffMissingManifest.hasRule("MFT001")
                        && !nestedCutoffMissingManifest.hasRule("MFT012"),
                nestedCutoffMissingManifest.coverage() + " :: "
                        + ReportFormatter.summaryLine(nestedCutoffMissingManifest));

        File wrapped = fixtures.directoryPlugin("wrapped-listing-failure",
                Fixtures.manifest("demo.wrapped", "Wrapped Listing Failure", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN));
        File wrapper = new File(wrapped, "Wrapper");
        if (!wrapper.mkdirs()
                || !new File(wrapped, "manifest.json").renameTo(new File(wrapper, "manifest.json"))
                || !new File(wrapped, "src").renameTo(new File(wrapper, "src"))) {
            throw new IllegalStateException("could not create wrapped listing-failure fixture");
        }
        ScanReport wrappedListingFailure = new PluginScanner(IocDatabase.empty()).scan(
                new ListingFailureFile(wrapped, wrapper), ScanBudget.unlimited());
        c.that("incomplete wrapper listing does not report a missing manifest",
                wrappedListingFailure.coverage() == Coverage.PARTIAL
                        && wrappedListingFailure.hasRule("MFT012")
                        && !wrappedListingFailure.hasRule("MFT001"),
                wrappedListingFailure.coverage() + " :: "
                        + ReportFormatter.summaryLine(wrappedListingFailure));

        File wide = fixtures.directoryPlugin("wide-directory",
                Fixtures.manifest("demo.wide", "Wide Directory", "demo.A"),
                Fixtures.sources("src/demo/A.java", BENIGN));
        for (int i = 0; i < 8010; i++) {
            try {
                if (!new File(wide, "file-" + i).createNewFile()) {
                    throw new IllegalStateException("could not create wide-tree fixture file " + i);
                }
            } catch (IOException e) {
                throw new IllegalStateException("could not create wide-tree fixture file " + i, e);
            }
        }
        ScanReport wideReport = new PluginScanner(IocDatabase.empty()).scan(wide, ScanBudget.unlimited());
        c.that("file-count-capped directory listing marks partial and has no partial-tree hash",
                wideReport.coverage() == Coverage.PARTIAL && wideReport.hasRule("SCN001")
                        && wideReport.contentHash.length() == 0,
                wideReport.coverage() + " :: " + ReportFormatter.summaryLine(wideReport));

        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest(
                "demo.siblings", "Sibling Depth", "demo.A")));
        members.put("src/demo/A.java", Fixtures.bytes(BENIGN));
        File installed = fixtures.installedArchive("sibling-depth", members, null);
        File sibling = new File(installed, "a/b/c/d");
        if (!sibling.mkdirs()) {
            throw new IllegalStateException("could not create sibling tree " + sibling);
        }
        write(sibling, "omitted.txt", "not inspected");
        ScanReport siblings = new PluginScanner(IocDatabase.empty()).scan(installed, ScanBudget.unlimited());
        c.that("installed sibling depth cutoff is reported as partial coverage",
                siblings.coverage() == Coverage.PARTIAL && siblings.hasRule("SCN001")
                        && !ReportFormatter.summaryLine(siblings).startsWith("Clean"),
                siblings.coverage() + " :: " + ReportFormatter.summaryLine(siblings));

        Map<String, byte[]> blockedSidecar = new LinkedHashMap<String, byte[]>();
        blockedSidecar.put("blocked/payload.txt", Fixtures.bytes("not listed"));
        File siblingListing = fixtures.installedArchive("sibling-listing-failure", members, blockedSidecar);
        ScanReport siblingListingFailure = new PluginScanner(IocDatabase.empty()).scan(
                new ListingFailureFile(siblingListing, new File(siblingListing, "blocked")),
                ScanBudget.unlimited());
        c.that("null installed-sibling listing is partial without claiming the archive manifest is missing",
                siblingListingFailure.coverage() == Coverage.PARTIAL && siblingListingFailure.hasRule("SCN001")
                        && !siblingListingFailure.hasRule("MFT001")
                        && siblingListingFailure.contentHash.length() > 0,
                siblingListingFailure.coverage() + " :: "
                        + ReportFormatter.summaryLine(siblingListingFailure));

        Map<String, byte[]> sidecars = new LinkedHashMap<String, byte[]>();
        for (int i = 0; i < 401; i++) {
            sidecars.put("sidecar-" + i, new byte[0]);
        }
        File manySiblings = fixtures.installedArchive("sibling-count", members, sidecars);
        ScanReport siblingCount = new PluginScanner(IocDatabase.empty()).scan(
                manySiblings, ScanBudget.unlimited());
        c.that("installed sibling count cutoff marks partial coverage",
                siblingCount.coverage() == Coverage.PARTIAL && siblingCount.hasRule("SCN001"),
                siblingCount.coverage() + " :: " + ReportFormatter.summaryLine(siblingCount));
    }

    private static void write(File parent, String name, String text) {
        File target = new File(parent, name);
        try (FileOutputStream out = new FileOutputStream(target)) {
            out.write(Fixtures.bytes(text));
        } catch (IOException e) {
            throw new IllegalStateException("could not write fixture " + target, e);
        }
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
        c.that("near-exhausted budget: nested member is PARTIAL, charges stay bounded, later member"
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

        Map<String, byte[]> directoryPayload = new LinkedHashMap<String, byte[]>();
        directoryPayload.put("folder/", Fixtures.bytes(sb.toString()));
        directoryPayload.put("after-directory.java", Fixtures.bytes(
                "package demo; class AfterDirectory { void f() { Runtime.getRuntime().exec(\"ls\"); } }"));
        ScanReport dataInDirectory = scanWithJar(fixtures, "nest-directory-payload.mtp",
                Fixtures.deflatedJar(directoryPayload));
        String directoryEvidence = ReportFormatter.plainText(dataInDirectory);
        c.that("nested directory entry with data is charged and stops before later members",
                dataInDirectory.coverage() == Coverage.PARTIAL && dataInDirectory.hasRule("SCN001")
                        && !directoryEvidence.contains("after-directory.java"),
                dataInDirectory.coverage() + " :: " + directoryEvidence);

        Map<String, byte[]> emptyDirectory = new LinkedHashMap<String, byte[]>();
        emptyDirectory.put("folder/", new byte[0]);
        emptyDirectory.put("note.txt", Fixtures.bytes("harmless"));
        ScanReport ordinaryDirectory = scanWithJar(fixtures, "nest-empty-directory.mtp",
                Fixtures.deflatedJar(emptyDirectory));
        c.that("ordinary empty nested directory entry does not truncate the scan",
                ordinaryDirectory.coverage() == Coverage.COMPLETE
                        && ordinaryDirectory.verdict() == Verdict.CLEAN,
                ordinaryDirectory.coverage() + " :: " + ordinaryDirectory.errors);
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
