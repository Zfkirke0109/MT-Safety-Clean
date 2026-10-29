package mt.safety.scanner.core;

import java.io.File;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import mtsafety.test.Fixtures;

/** Root/nested integration uses an unchanged upstream ZIP95 archive, never a method-only fake. */
public final class Zip95ContainerRegression {
    private static int checks;
    private Zip95ContainerRegression() { }
    public static void main(String[] args) throws Exception {
        run();
        System.out.println("Zip95ContainerRegression: " + checks + " checks passed");
    }
    public static void run() throws Exception {
        File root = Files.createTempDirectory("zip95-container-").toFile();
        Fixtures fixtures = new Fixtures(root);
        File source = new File("tools/test-fixtures/zip95/libarchive-xz-multi.zipx");
        byte[] genuine = Files.readAllBytes(source.toPath());
        File definitions = new File(root, "oracle.hsb");
        Fixtures.write(definitions, "4995deb0c6a2b5482ba62759f1f5bcdd19186528d99d263dc8bc61d42878798e:2245:Test.Zip95.Groundtruth\n"
                + "4973827f59fed69911bc0b3e4ad7f9ee6aac0ee120b38ded0a46a7302044dd36:6601:Test.Zip95.Profile\n");
        PluginScanner scanner = new PluginScanner(IocDatabase.empty(), SignatureDatabase.load(definitions));
        ScanReport direct = scanner.scan(source, ScanBudget.unlimited());
        check(direct.coverage() == Coverage.COMPLETE, "root genuine ZIP95 complete: " + direct.errors);
        check(direct.hasRule("SIG001"), "root ZIP95 independently known SHA256 reaches matcher");
        check(ReportFormatter.plainText(direct).contains("bash.bashrc"), "root evidence path");
        Map<String, byte[]> outer = new LinkedHashMap<String, byte[]>();
        outer.put("manifest.json", Fixtures.bytes(Fixtures.manifest("test.zip95", "XZ fixture", "demo.A")));
        outer.put("src/demo/A.java", Fixtures.bytes("package demo; public class A {}"));
        outer.put("libs/upstream.jar", genuine);
        ScanReport nested = scanner.scan(fixtures.rawArchive("nested.mtp", outer, false), ScanBudget.unlimited());
        check(nested.coverage() == Coverage.COMPLETE, "nested genuine ZIP95 complete: " + nested.errors);
        check(nested.hasRule("SIG001"), "nested ZIP95 SHA256 reaches matcher");
        check(ReportFormatter.plainText(nested).contains("libs/upstream.jar!bash.bashrc"), "nested evidence path");
        byte[] wrongCrc = genuine.clone();
        wrongCrc[14] ^= 1; // Central/local mismatch must never be accepted as complete.
        outer.put("libs/upstream.jar", wrongCrc);
        ScanReport corrupt = scanner.scan(fixtures.rawArchive("corrupt.mtp", outer, false), ScanBudget.unlimited());
        check(corrupt.coverage() == Coverage.PARTIAL, "nested metadata corruption partial");
        byte[] unknown = genuine.clone();
        unknown[8] = 94; unknown[5179 + 10] = 94;
        File mixed = new File(root, "mixed.zipx");
        Fixtures.writeBytes(mixed, unknown);
        ScanReport mixedReport = scanner.scan(mixed, ScanBudget.unlimited());
        check(mixedReport.coverage() == Coverage.PARTIAL, "unknown codec remains partial");
        check(mixedReport.filesScanned() >= 2, "supported peers survive unknown codec");
        check(mixedReport.hasRule("SIG001"), "supported peer retains whole-file signature evidence");
        File peerDefinitions = new File(root, "peer-only.hsb");
        Fixtures.write(peerDefinitions, "4973827f59fed69911bc0b3e4ad7f9ee6aac0ee120b38ded0a46a7302044dd36:6601:Test.Zip95.Profile\n");
        FileScanner fileScanner = new FileScanner(SignatureDatabase.load(peerDefinitions));
        FileScanner.Result mixedFiles = fileScanner.scan(java.util.Arrays.asList(mixed), null, ScanBudget.unlimited());
        check(mixedFiles.truncated() && mixedFiles.hits.size() == 1,
                "selected-file archive preserves later supported peer after unknown codec");
        check(completeReadCount(nested) >= 5, "root plus nested members have complete read ledger");
        for (CoverageLedger.Member member : nested.ledger.members()) {
            for (CoverageLedger.Analyzer analyzer : CoverageLedger.Analyzer.values()) {
                check(member.get(analyzer).reason != CoverageLedger.Reason.NOT_ATTEMPTED,
                        "genuine nested analysis has no unaccounted checks");
            }
        }
        outer.put("libs/upstream.jar", unknown);
        ScanReport mixedNested = scanner.scan(fixtures.rawArchive("mixed-nested.mtp", outer, false),
                ScanBudget.unlimited());
        check(mixedNested.coverage() == Coverage.PARTIAL && mixedNested.hasRule("SIG001"),
                "nested unsupported member retains later supported signature evidence");
        for (int offset : new int[] {6, 8, 14, 18, 22, 30}) {
            byte[] mismatched = genuine.clone();
            mismatched[offset] ^= 1;
            File malformed = new File(root, "mismatch-" + offset + ".zipx");
            Fixtures.writeBytes(malformed, mismatched);
            ScanReport report = scanner.scan(malformed, ScanBudget.unlimited());
            check(report.coverage() == Coverage.PARTIAL && !report.errors.isEmpty(),
                    "root local/central mismatch refuses complete: " + offset);
        }
        byte[] crc = genuine.clone();
        crc[14] ^= 1; crc[5179 + 16] ^= 1;
        File wrongPayload = new File(root, "wrong-payload-crc.zipx");
        Fixtures.writeBytes(wrongPayload, crc);
        ScanReport crcReport = scanner.scan(wrongPayload, ScanBudget.unlimited());
        check(crcReport.coverage() == Coverage.PARTIAL && crcReport.hasRule("SIG001"),
                "wrong payload CRC cannot hide later verified member evidence");
        FileScanner.Result crcFiles = fileScanner.scan(java.util.Arrays.asList(wrongPayload), null, ScanBudget.unlimited());
        check(crcFiles.truncated() && crcFiles.hits.size() == 1,
                "selected-file archive preserves later supported peer after CRC failure");
        byte[] encrypted = genuine.clone();
        encrypted[6] |= 1; encrypted[5179 + 8] |= 1;
        File encryptedFile = new File(root, "encrypted-mixed.zipx");
        Fixtures.writeBytes(encryptedFile, encrypted);
        ScanReport encryptedReport = scanner.scan(encryptedFile, ScanBudget.unlimited());
        check(encryptedReport.coverage() == Coverage.PARTIAL && encryptedReport.hasRule("SIG001"),
                "encrypted member explicit partial while supported peers still inspected");
        FileScanner.Result encryptedFiles = fileScanner.scan(java.util.Arrays.asList(encryptedFile), null, ScanBudget.unlimited());
        check(encryptedFiles.truncated() && encryptedFiles.hits.size() == 1,
                "selected-file archive preserves later supported peer after encryption refusal");
        for (int method : new int[] {95, 94}) {
            byte[] zeroSize = genuine.clone();
            zeroSize[8] = (byte) method; zeroSize[5179 + 10] = (byte) method;
            for (int i = 0; i < 4; i++) { zeroSize[22 + i] = 0; zeroSize[5179 + 24 + i] = 0; }
            File declaredEmpty = new File(root, "declared-empty-" + method + ".zipx");
            Fixtures.writeBytes(declaredEmpty, zeroSize);
            FileScanner.Result zeroFiles = fileScanner.scan(java.util.Arrays.asList(declaredEmpty), null, ScanBudget.unlimited());
            check(zeroFiles.truncated() && zeroFiles.hits.size() == 1,
                    "declared zero size cannot bypass codec/integrity checks or hide a peer: " + method);
        }
        Map<String, byte[]> duplicates = new LinkedHashMap<String, byte[]>();
        duplicates.put("manifest.json", Fixtures.bytes(Fixtures.manifest("test.dupe", "Duplicate", "demo.A")));
        duplicates.put("src/demo/A.java", Fixtures.bytes("FIRST_IDENTITY_ONLY"));
        File duplicate = fixtures.conflictingDuplicateArchive("identities.mtp", duplicates,
                Fixtures.bytes("other inert contents"));
        ScanReport duplicateReport = new PluginScanner(IocDatabase.parse(
                "{\"patterns\":[\"FIRST_IDENTITY_ONLY\"]}"))
                .scan(duplicate, ScanBudget.unlimited());
        check(duplicateReport.hasRule("ARC005") && duplicateReport.hasRule("USR001"),
                "duplicate identities preserve first member's actual bytes");
        Map<String, byte[]> descriptors = new LinkedHashMap<String, byte[]>();
        descriptors.put("manifest.json", Fixtures.bytes(Fixtures.manifest("test.dd", "Descriptor", "demo.A")));
        descriptors.put("src/demo/A.java", Fixtures.bytes("public class A {}"));
        File dd = fixtures.dataDescriptorArchive("descriptor-integrity.mtp", descriptors);
        byte[] ddData = Files.readAllBytes(dd.toPath());
        for (int i = 0; i < ddData.length - 16; i++) {
            if (ddData[i] == 'P' && ddData[i + 1] == 'K' && ddData[i + 2] == 7 && ddData[i + 3] == 8) {
                ddData[i + 4] ^= 1;
                break;
            }
        }
        Fixtures.writeBytes(dd, ddData);
        ScanReport ddReport = scanner.scan(dd, ScanBudget.unlimited());
        check(ddReport.coverage() == Coverage.PARTIAL, "descriptor CRC mismatch refused");
        descriptors.put("hidden/", Fixtures.bytes("uninspected data in a directory member"));
        ScanReport directoryPayload = scanner.scan(fixtures.rawArchive("directory-payload.mtp", descriptors, false),
                ScanBudget.unlimited());
        check(directoryPayload.coverage() == Coverage.PARTIAL, "directory payload cannot be silently skipped");
        File directoryFile = fixtures.rawArchive("file-directory-payload.zip", descriptors, false);
        check(fileScanner.scan(java.util.Arrays.asList(directoryFile), null, ScanBudget.unlimited()).truncated(),
                "selected-file directory payload is explicitly incomplete");
    }
    private static int completeReadCount(ScanReport report) {
        int count = 0;
        for (CoverageLedger.Member member : report.ledger.members()) {
            if (member.get(CoverageLedger.Analyzer.READ).status == CoverageLedger.Status.COMPLETE) { count++; }
        }
        return count;
    }
    private static void check(boolean condition, String why) {
        checks++;
        if (!condition) { throw new AssertionError(why); }
    }
}
