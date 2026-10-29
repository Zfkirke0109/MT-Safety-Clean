package mt.safety.scanner.core;

import java.io.File;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import mtsafety.test.Fixtures;

/** Diagnostic display caps cannot hide uninspected nested work from the analyzer ledger. */
public final class CoverageCompletionRegression {
    private CoverageCompletionRegression() { }
    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("coverage-errors-").toFile(); Fixtures fixtures = new Fixtures(root);
        Map<String, byte[]> leaf = new LinkedHashMap<String, byte[]>(); leaf.put("E.java", Fixtures.bytes("class E {}"));
        byte[] nested = archive(fixtures, "leaf.jar", leaf);
        for (int i = 1; i <= 2; i++) {
            Map<String, byte[]> level = new LinkedHashMap<String, byte[]>(); level.put("level" + i + ".jar", nested);
            nested = archive(fixtures, "level" + i + ".jar", level);
        }
        Map<String, byte[]> outer = new LinkedHashMap<String, byte[]>();
        outer.put("manifest.json", Fixtures.bytes(Fixtures.manifest("test.errors", "Errors", "demo.A")));
        for (int i = 0; i < 140; i++) outer.put("bad" + i + ".bin", Fixtures.bytes("AB"));
        outer.put("libs/deep.jar", nested);
        byte[] bytes = archive(fixtures, "outer.mtp", outer);
        for (int p = 0; p + 46 < bytes.length; p++) {
            int magic = u16(bytes, p) | (u16(bytes, p + 2) << 16);
            if (magic != 0x04034b50 && magic != 0x02014b50) continue;
            boolean local = magic == 0x04034b50;
            int length = u16(bytes, p + (local ? 26 : 28)), name = p + (local ? 30 : 46);
            if (name + length <= bytes.length && new String(bytes, name, length, "UTF-8").startsWith("bad")) {
                bytes[p + (local ? 8 : 10)] = 99; bytes[p + (local ? 9 : 11)] = 0;
            }
        }
        File source = new File(root, "probe.mtp"); Files.write(source.toPath(), bytes);
        ScanReport report = new PluginScanner(IocDatabase.empty()).scan(source, ScanBudget.unlimited());
        require(report.errors.size() == 129 && report.coverage() == Coverage.PARTIAL, "diagnostic cap fixture remains partial");
        int containers = 0;
        for (CoverageLedger.Member member : report.ledger.members()) {
            if (!member.label.contains("deep")) continue;
            containers++;
            require(member.get(CoverageLedger.Analyzer.NESTED_ARCHIVE).status == CoverageLedger.Status.PARTIAL,
                    "every ancestor retains nested incompleteness despite saturated diagnostics");
        }
        require(containers == 3, "all nested containers recorded");
        System.out.println("CoverageCompletionRegression: 5 checks passed");
    }
    private static byte[] archive(Fixtures fixtures, String name, Map<String, byte[]> members) throws Exception {
        return Files.readAllBytes(fixtures.rawArchive(name, members, false).toPath());
    }
    private static int u16(byte[] bytes, int at) { return (bytes[at] & 255) | ((bytes[at + 1] & 255) << 8); }
    private static void require(boolean condition, String label) { if (!condition) throw new AssertionError(label); }
}
