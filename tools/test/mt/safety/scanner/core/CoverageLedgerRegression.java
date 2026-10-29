package mt.safety.scanner.core;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.execution.WorkerProtocol;

/** Observable completeness and transport checks, including valid empty files and omitted work. */
public final class CoverageLedgerRegression {
    private static int checks;
    private CoverageLedgerRegression() { }
    private static void check(boolean ok, String why) { checks++; if (!ok) throw new AssertionError(why); }
    private static CoverageLedger.Member member(ScanReport report, String label) {
        for (CoverageLedger.Member member : report.ledger.members()) if (member.label.equals(label)) return member;
        throw new AssertionError("Missing member " + label);
    }
    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("coverage-ledger-").toFile();
        Files.write(new File(root, "manifest.json").toPath(),
                "{\"pluginID\":\"demo.ledger\",\"name\":\"Ledger\"}".getBytes(StandardCharsets.UTF_8));
        Files.write(new File(root, "readme.txt").toPath(), "ordinary harmless text".getBytes(StandardCharsets.UTF_8));
        Files.write(new File(root, "empty.txt").toPath(), new byte[0]);
        ScanReport report = new PluginScanner(IocDatabase.empty()).scan(root, ScanBudget.unlimited());
        check(report.coverage() == Coverage.COMPLETE, "small readable package has a completed ledger");
        check(report.ledger.active() && report.ledger.members().size() == 3, "all admitted members recorded");
        check(member(report, "readme.txt").get(CoverageLedger.Analyzer.READ).status == CoverageLedger.Status.COMPLETE,
                "read outcome recorded");
        check(member(report, "readme.txt").get(CoverageLedger.Analyzer.BUILTIN_RULES).status == CoverageLedger.Status.COMPLETE,
                "analyzer outcome recorded");
        check(member(report, "empty.txt").get(CoverageLedger.Analyzer.READ).status == CoverageLedger.Status.COMPLETE
                && member(report, "empty.txt").get(CoverageLedger.Analyzer.BUILTIN_RULES).status == CoverageLedger.Status.COMPLETE,
                "valid empty member is fully inspected");
        check(member(report, "readme.txt").get(CoverageLedger.Analyzer.SIGNATURES).reason == CoverageLedger.Reason.NO_DEFINITIONS,
                "unselected signature analyzer explicitly not applicable");
        check(member(report, "manifest.json").get(CoverageLedger.Analyzer.BUILTIN_RULES).reason == CoverageLedger.Reason.MANIFEST_METADATA,
                "manifest metadata path is explicit");
        String json = ReportFormatter.json(Collections.singletonList(report));
        check(Json.parse(json) != null && json.contains("\"coverageLedger\"") && json.contains("\"analyzers\""),
                "legacy JSON remains parseable with additive ledger");
        check(ReportFormatter.plainText(report).contains("0 incomplete checks"), "text includes completion summary");
        ScanReport stopped = new PluginScanner(IocDatabase.empty()).scan(root, new ScanBudget(0, 100));
        check(stopped.coverage() == Coverage.PARTIAL && stopped.ledger.incompleteChecks() > 0,
                "unattempted work cannot appear complete");
        check(member(stopped, "readme.txt").get(CoverageLedger.Analyzer.READ).status == CoverageLedger.Status.SKIPPED
                && member(stopped, "readme.txt").get(CoverageLedger.Analyzer.READ).reason == CoverageLedger.Reason.BUDGET_EXHAUSTED,
                "skipped member preserves stable reason");
        byte[] large = new byte[1024 * 1024 + 17]; java.util.Arrays.fill(large, (byte) ' ');
        Files.write(new File(root, "Large.java").toPath(), large);
        ScanReport prefix = new PluginScanner(IocDatabase.empty()).scan(root, ScanBudget.unlimited());
        check(prefix.coverage() == Coverage.PARTIAL
                && member(prefix, "Large.java").get(CoverageLedger.Analyzer.READ).reason == CoverageLedger.Reason.MEMBER_LIMIT,
                "member prefix records size limit");
        ScanReport huge = new ScanReport("bounded", "/fixture", false, false, PluginManifest.missing(), "");
        huge.ledger.start();
        for (CoverageLedger.PackageAnalyzer a : CoverageLedger.PackageAnalyzer.values()) {
            huge.ledger.set(a, CoverageLedger.Status.COMPLETE, CoverageLedger.Reason.OK);
        }
        for (int i = 0; i < CoverageLedger.MAX_MEMBERS; i++) {
            CoverageLedger.Member m = huge.ledger.addMember("same duplicate path with a long display label " + (i / 2));
            m.notApplicable(CoverageLedger.Reason.DIRECTORY);
        }
        check(!huge.ledger.incomplete(), "bounded full ledger is complete");
        check(huge.ledger.members().get(0).nameHash.equals(huge.ledger.members().get(1).nameHash)
                && huge.ledger.members().get(0).id != huge.ledger.members().get(1).id,
                "duplicate paths retain separate identities");
        huge.ledger.addMember("overflow");
        check(huge.ledger.members().size() == CoverageLedger.MAX_MEMBERS && huge.ledger.droppedMembers() == 1
                && huge.coverage() == Coverage.PARTIAL, "ledger cap is bounded and visible");
        WorkerProtocol.Response response = new WorkerProtocol.Response(); response.result = new ScanRunner.Result();
        response.result.reports.add(huge);
        byte[] wire = WorkerProtocol.encodeResponse(response);
        check(wire.length <= WorkerProtocol.MAX_BYTES, "maximum ledger fits bounded IPC");
        ScanReport copy = WorkerProtocol.decodeResponse(wire).result.reports.get(0);
        check(copy.ledger.members().size() == CoverageLedger.MAX_MEMBERS && copy.ledger.droppedMembers() == 1
                && copy.coverage() == Coverage.PARTIAL, "all outcomes and omitted count survive worker transport");
        check(copy.ledger.members().get(CoverageLedger.MAX_MEMBERS - 1).id == CoverageLedger.MAX_MEMBERS,
                "final admitted member survives transport");
        byte[] hugeManifest = new byte[600 * 1024]; java.util.Arrays.fill(hugeManifest, (byte) ' ');
        hugeManifest[0] = '{'; hugeManifest[1] = '}'; hugeManifest[hugeManifest.length - 1] = 'x';
        File manifestPath = new File(root, "manifest.json");
        java.nio.file.Files.write(manifestPath.toPath(), hugeManifest);
        ScanReport oversizedManifest = new PluginScanner(IocDatabase.empty()).scan(root, ScanBudget.unlimited());
        check(oversizedManifest.coverage() == Coverage.PARTIAL && oversizedManifest.manifest.unreadable
                && oversizedManifest.ledger.get(CoverageLedger.PackageAnalyzer.MANIFEST).status != CoverageLedger.Status.COMPLETE,
                "manifest prefix cannot certify metadata completion");
        System.out.println(checks + " ledger checks passed");
    }
}
