package mt.safety.scanner.core;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import mtsafety.test.Fixtures;

/** Inert fixtures exercise parsing semantics and real package/file cutoff reporting. */
public final class SignatureMatchingRegression {
    private static int checks, failures;
    private SignatureMatchingRegression() { }
    public static void main(String[] args) throws Exception {
        HexSignature alternatives = HexSignature.compile("alternatives", 0, "0", "(aabb|ccdd)");
        check(alternatives.matches(new byte[] {(byte) 0xaa, (byte) 0xbb})
                && alternatives.matches(new byte[] {(byte) 0xcc, (byte) 0xdd}), "exact alternative branches match");
        check(!alternatives.matches(new byte[] {(byte) 0xaa, (byte) 0xdd})
                && !alternatives.matches(new byte[] {(byte) 0xcc, (byte) 0xbb}), "alternative branches cannot mix bytes");
        for (String pattern : new String[] {"{2}4142", "4142{2}", "4142{1}{2}4344", "4142**4344",
                "4142{4097}4344", "4142{1-4097}4344"}) {
            check(rejected(pattern, "0"), "unsupported gap refuses rather than changing semantics: " + pattern);
        }
        check(rejected("4142", "0,4097"), "oversized offset shift refuses");
        byte[] distant = new byte[5004]; distant[0] = 65; distant[1] = 66; distant[5002] = 67; distant[5003] = 68;
        check(HexSignature.compile("unbounded", 0, "0", "4142*4344").matches(distant), "star searches beyond 4096 bytes");
        check(HexSignature.compile("open", 0, "0", "4142{2-}4344").matches(distant), "open gap searches beyond 4096 bytes");
        StringBuilder deep = new StringBuilder("4141");
        for (int i = 0; i < 128; i++) deep.append("*4141");
        check(rejected(deep.toString(), "0"), "pattern recursion depth has a definition limit");

        File root = Files.createTempDirectory("signature-matching-").toFile();
        Fixtures fixtures = new Fixtures(root);
        File defs = new File(root, "cutoff.ndb");
        Fixtures.write(defs, "Test.Preserved:0:0:4141\nTest.Expensive:0:0:41*41*41*41*42\n");
        SignatureDatabase signatures = SignatureDatabase.load(defs);
        byte[] repeated = new byte[8192]; Arrays.fill(repeated, (byte) 65);
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest("test.cutoff", "Cutoff", "demo.A")));
        members.put("src/demo/A.java", repeated);
        ScanReport report = new PluginScanner(IocDatabase.empty(), signatures)
                .scan(fixtures.rawArchive("cutoff.mtp", members, false), ScanBudget.unlimited());
        check(report.hasRule("SIG002"), "cutoff preserves prior signature evidence");
        check(report.coverage() == Coverage.PARTIAL && report.errors.toString().contains("Signature matching incomplete"),
                "package matcher cutoff is explicit incomplete coverage");
        boolean ledgerCutoff = false;
        for (CoverageLedger.Member member : report.ledger.members()) {
            CoverageLedger.Check signature = member.get(CoverageLedger.Analyzer.SIGNATURES);
            ledgerCutoff |= signature.status == CoverageLedger.Status.PARTIAL;
        }
        check(ledgerCutoff, "signature analyzer records its cutoff");
        File sample = new File(root, "sample.bin"); Fixtures.writeBytes(sample, repeated);
        FileScanner.Result files = new FileScanner(signatures).scan(Arrays.asList(sample), null, ScanBudget.unlimited());
        check(!files.hits.isEmpty() && files.problems.toString().contains("Signature matching incomplete"),
                "file matcher cutoff retains hit and visible problem");
        Fixtures.write(defs, "Test.Eof:0:EOF-2:aabb\n");
        SignatureDatabase eof = SignatureDatabase.load(defs);
        byte[] endBytes = {(byte) 0xaa, (byte) 0xbb};
        check(eof.matchPatternsChecked(endBytes, 0, 3).hits.size() == 1,
                "complete blob still matches a real EOF anchor");
        check(eof.matchPatternsChecked(endBytes, 0, 3, -1L).hits.isEmpty(),
                "unknown-length decoded prefix cannot infer an EOF anchor");
        byte[] prefix = new byte[1024 * 1024 + 8];
        prefix[1024 * 1024 - 2] = (byte) 0xaa; prefix[1024 * 1024 - 1] = (byte) 0xbb;
        members.put("src/demo/A.java", prefix);
        ScanReport eofPackage = new PluginScanner(IocDatabase.empty(), eof)
                .scan(fixtures.rawArchive("eof-prefix.mtp", members, false), ScanBudget.unlimited());
        check(!eofPackage.hasRule("SIG002") && eofPackage.coverage() == Coverage.PARTIAL,
                "package prefix end never substitutes for actual EOF");
        byte[] filePrefix = new byte[FileScanner.PATTERN_BYTES + 8];
        filePrefix[FileScanner.PATTERN_BYTES - 2] = (byte) 0xaa;
        filePrefix[FileScanner.PATTERN_BYTES - 1] = (byte) 0xbb;
        Fixtures.writeBytes(sample, filePrefix);
        FileScanner.Result eofFile = new FileScanner(eof).scan(Arrays.asList(sample), null, ScanBudget.unlimited());
        check(eofFile.hits.isEmpty() && eofFile.truncated(), "selected-file prefix cannot falsely match EOF");
        Fixtures.write(defs, "Test.TrueEofOffset:0:EOF-10:aabb\n");
        FileScanner.Result offsetFile = new FileScanner(SignatureDatabase.load(defs))
                .scan(Arrays.asList(sample), null, ScanBudget.unlimited());
        check(offsetFile.hits.size() == 1 && offsetFile.truncated(),
                "EOF offset inside admitted prefix uses true logical size and retains valid hit");
        System.out.println("SignatureMatchingRegression: " + checks + " checks, " + failures + " failures");
        if (failures > 0) throw new AssertionError("signature correctness regressions");
    }
    private static boolean rejected(String pattern, String offset) {
        try { HexSignature.compile("rejection", 0, offset, pattern); return false; }
        catch (HexSignature.SyntaxException expected) { return true; }
    }
    private static void check(boolean condition, String label) {
        checks++; if (!condition) { failures++; System.out.println("FAIL " + label); }
    }
}
