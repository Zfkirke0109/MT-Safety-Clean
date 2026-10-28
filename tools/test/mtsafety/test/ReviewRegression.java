package mtsafety.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import mt.safety.scanner.core.Coverage;
import mt.safety.scanner.core.Discovery;
import mt.safety.scanner.core.FileScanner;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginPackage;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.SignatureDatabase;
import mt.safety.scanner.core.Category;
import mt.safety.scanner.core.Severity;
import mt.safety.scanner.core.Signal;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.Json;
import mt.safety.scanner.core.Verdict;

/** Inert, bounded reproductions from the independent PR review. */
public final class ReviewRegression {
    private ReviewRegression() {
    }

    public static void main(String[] args) {
        StringBuilder text = new StringBuilder("password");
        for (int i = 0; i < 65000; i++) {
            text.append(' ');
        }
        text.append('x');
        new Signal("TEST", Category.PROVENANCE, Severity.INFO, "Inert", "Inert")
                .withEvidence(text.toString(), text.toString());
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 16000; i++) {
            token.append("eyJ-");
        }
        new Signal("TEST", Category.PROVENANCE, Severity.INFO, "Inert", "Inert")
                .withEvidence(token.toString(), token.toString());
    }

    public static void run(ActionsTest.Checker c, Fixtures fixtures) throws Exception {
        archiveAdmission(c, fixtures);
        nestedStructure(c, fixtures);
        definitions(c, fixtures);
        filesystemRoot(c, fixtures);
        fileCoverage(c, fixtures);
        reportRedaction(c, fixtures);
    }

    private static Map<String, byte[]> benignMembers() {
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(
                Fixtures.manifest("demo.review", "Review Control", "demo.A")));
        members.put("src/demo/A.java", Fixtures.bytes("package demo; public class A {}"));
        return members;
    }

    private static ScanReport scan(File file) {
        return new PluginScanner(IocDatabase.empty()).scan(file, ScanBudget.unlimited());
    }

    private static void archiveAdmission(ActionsTest.Checker c, Fixtures fixtures) throws Exception {
        File normal = fixtures.rawArchive("review-normal.mtp", benignMembers(), false);
        c.that("ordinary archive remains completely scannable", scan(normal).coverage() == Coverage.COMPLETE,
                "ordinary stored ZIP");
        Map<String, byte[]> many = benignMembers();
        for (int i = many.size(); i < 8001; i++) {
            many.put("empty/" + i, new byte[0]);
        }
        File wide = fixtures.rawArchive("review-wide.mtp", many, false);
        c.that("archive entry cap refuses before returning an unbounded index", refused(wide),
                "8001 central directory entries");
        c.that("unadmitted archive has no clean verdict or action identity",
                scan(wide).coverage() == Coverage.UNSUPPORTED_OR_UNREADABLE
                        && scan(wide).contentHash.length() == 0,
                "unadmitted archive");

        byte[] understated = Files.readAllBytes(wide.toPath());
        int end = understated.length - 22;
        put16(understated, end + 8, 1);
        put16(understated, end + 10, 1);
        File forged = new File(fixtures.root(), "review-understated.mtp");
        Fixtures.writeBytes(forged, understated);
        c.that("archive cap counts actual index records instead of trusting EOCD count", refused(forged),
                "8001 actual entries, declared 1");

        File longComments = new File(fixtures.root(), "review-large-index.mtp");
        char[] comment = new char[60000];
        Arrays.fill(comment, 'c');
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(longComments))) {
            for (int i = 0; i < 36; i++) {
                ZipEntry entry = new ZipEntry("e" + i);
                entry.setComment(new String(comment));
                out.putNextEntry(entry);
                out.closeEntry();
            }
        }
        c.that("archive metadata byte cap also bounds long names and comments", refused(longComments),
                "36 entries, more than 2 MiB of index metadata");

        byte[] ordinary = Files.readAllBytes(normal.toPath());
        File zip64 = new File(fixtures.root(), "review-small-zip64.mtp");
        Fixtures.writeBytes(zip64, zip64(ordinary, 2L));
        c.that("small single-disk ZIP64 remains supported", scan(zip64).coverage() == Coverage.COMPLETE,
                scan(zip64).errors.toString());
        File forged64 = new File(fixtures.root(), "review-forged-zip64.mtp");
        Fixtures.writeBytes(forged64, zip64(ordinary, 8001L));
        c.that("optional ZIP64 locator cannot override a bounded classic count", refused(forged64),
                "classic count 2, ZIP64 count 8001");
        byte[] overflow = zip64(ordinary, Long.MIN_VALUE);
        File overflow64 = new File(fixtures.root(), "review-overflow-zip64.mtp");
        Fixtures.writeBytes(overflow64, overflow);
        c.that("unsigned ZIP64 overflow is refused", refused(overflow64), "count exceeds signed long");
    }

    private static boolean refused(File path) throws IOException {
        PluginPackage pkg = PluginPackage.open(path);
        try {
            pkg.entries();
            return false;
        } catch (IOException expected) {
            return true;
        } finally {
            pkg.close();
        }
    }

    private static byte[] zip64(byte[] archive, long count) throws IOException {
        int end = archive.length - 22;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(archive, 0, end);
        long end64 = out.size();
        le(out, 0x06064b50L, 4);
        le(out, 44L, 8);
        le(out, 45L, 2);
        le(out, 45L, 2);
        le(out, 0L, 4);
        le(out, 0L, 4);
        le(out, count, 8);
        le(out, count, 8);
        out.write(archive, end + 12, 4);
        le(out, 0L, 4);
        out.write(archive, end + 16, 4);
        le(out, 0L, 4);
        le(out, 0x07064b50L, 4);
        le(out, 0L, 4);
        le(out, end64, 8);
        le(out, 1L, 4);
        out.write(archive, end, 22);
        return out.toByteArray();
    }

    private static void le(ByteArrayOutputStream out, long value, int bytes) {
        for (int i = 0; i < bytes; i++) {
            out.write((int) (value >>> (8 * i)) & 255);
        }
    }

    private static void put16(byte[] data, int offset, int value) {
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
    }

    private static void nestedStructure(ActionsTest.Checker c, Fixtures fixtures) throws Exception {
        Map<String, byte[]> members = benignMembers();
        members.put("libs/broken.jar", new byte[] {'P', 'K', 3, 4});
        ScanReport broken = scan(fixtures.rawArchive("review-nested-header.mtp", members, false));
        c.that("silent nested local-header EOF revokes complete coverage",
                broken.coverage() == Coverage.PARTIAL && broken.hasRule("SCN001") && !broken.errors.isEmpty(),
                broken.coverage() + " " + broken.errors);

        byte[] full = Fixtures.deflatedJar(benignMembers());
        int central = -1;
        for (int i = 0; i + 4 <= full.length; i++) {
            if (full[i] == 'P' && full[i + 1] == 'K' && full[i + 2] == 1 && full[i + 3] == 2) {
                central = i;
                break;
            }
        }
        if (central < 0) {
            throw new AssertionError("fixture lacks central directory");
        }
        members.put("libs/broken.jar", Arrays.copyOf(full, central));
        ScanReport missingIndex = scan(fixtures.rawArchive("review-nested-no-index.mtp", members, false));
        c.that("nested local stream without an index is partial",
                missingIndex.coverage() == Coverage.PARTIAL, missingIndex.coverage().toString());

        members.put("libs/broken.jar", Fixtures.deflatedJar(new LinkedHashMap<String, byte[]>()));
        ScanReport empty = scan(fixtures.rawArchive("review-nested-empty.mtp", members, false));
        c.that("valid empty nested ZIP stays complete", empty.coverage() == Coverage.COMPLETE,
                empty.coverage() + " " + empty.errors);

        for (boolean sameName : new boolean[] {false, true}) {
            members.put("libs/broken.jar", fencedNested(sameName));
            ScanReport fenced = scan(fixtures.rawArchive("review-fenced-" + sameName + ".mtp", members, false));
            c.that("nested coverage binds local offsets to the index, sameName=" + sameName,
                    fenced.coverage() == Coverage.PARTIAL && !fenced.errors.isEmpty(),
                    fenced.coverage() + " " + fenced.errors);
        }
        // Independently constructed: local STORED reads compressed bytes, CEN DEFLATED decodes SPEC_HIT.
        members.put("libs/broken.jar", java.util.Base64.getDecoder().decode(
                "UEsDBBQAAAAAAAAAAABoAWGJCgAAAAoAAAAFAAAAQS50eHQLDnB1jvfwDAEAUEsBAhQAFAAAAAgAAAAAAJDZwn0KAAAACAAAAAUAAAAAAAAAAAAAAAAAAAAAAEEudHh0UEsFBgAAAAABAAEAMwAAAC0AAAAAAA=="));
        ScanReport method = scan(fixtures.rawArchive("review-nested-method.mtp", members, false));
        c.that("nested local and central compression interpretation must agree",
                method.coverage() == Coverage.PARTIAL && !method.errors.isEmpty(),
                method.coverage() + " " + method.errors);

        byte[] reordered = Fixtures.deflatedJar(benignMembers());
        int end = reordered.length - 22;
        int first = get32(reordered, end + 16);
        int second = first + 46 + get16(reordered, first + 28)
                + get16(reordered, first + 30) + get16(reordered, first + 32);
        ByteArrayOutputStream reversed = new ByteArrayOutputStream();
        reversed.write(reordered, 0, first);
        reversed.write(reordered, second, end - second);
        reversed.write(reordered, first, second - first);
        reversed.write(reordered, end, 22);
        members.put("libs/broken.jar", reversed.toByteArray());
        ScanReport order = scan(fixtures.rawArchive("review-nested-index-order.mtp", members, false));
        c.that("nested index ordering need not match local header ordering",
                order.coverage() == Coverage.COMPLETE, order.coverage() + " " + order.errors);

        File descriptorFree = fixtures.rawArchive("review-stored-inner.jar", benignMembers(), false);
        members.put("libs/broken.jar", Files.readAllBytes(descriptorFree.toPath()));
        ScanReport stored = scan(fixtures.rawArchive("review-stored-nested.mtp", members, false));
        c.that("stored nested entries stay complete", stored.coverage() == Coverage.COMPLETE,
                stored.coverage() + " " + stored.errors);

        byte[] encryptedIndex = Files.readAllBytes(descriptorFree.toPath());
        int index = get32(encryptedIndex, encryptedIndex.length - 22 + 16);
        encryptedIndex[index + 8] |= 1;
        members.put("libs/broken.jar", encryptedIndex);
        ScanReport encrypted = scan(fixtures.rawArchive("review-encrypted-index.mtp", members, false));
        c.that("encrypted central metadata cannot hide behind plaintext local headers",
                encrypted.coverage() == Coverage.PARTIAL && !encrypted.errors.isEmpty(),
                encrypted.coverage() + " " + encrypted.errors);
        members.put("libs/broken.jar", java.util.Base64.getDecoder().decode(
                "UEsDBBQAAAAAAAAAAADDd1eeCAAAAAgAAAADAAAA77+9aGFybWxlc3NQSwECFAAUAAAAAAAAAAAAw3dXnggAAAAIAAAAAQAAAAAAAAAAAAAAAAAAAAAA/1BLBQYAAAAAAQABAC8AAAApAAAAAAA="));
        ScanReport encoding = scan(fixtures.rawArchive("review-invalid-index-name.mtp", members, false));
        c.that("invalid central UTF-8 is not normalized into a valid local name",
                encoding.coverage() == Coverage.PARTIAL, encoding.coverage() + " " + encoding.errors);
    }

    /** Local A, an EOF-looking fence, then local B; the sole index record refers to B. */
    private static byte[] fencedNested(boolean sameName) throws IOException {
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("A.txt", Fixtures.bytes("harmless"));
        members.put("B.txt", Fixtures.bytes("SPEC_HIT"));
        byte[] full = Fixtures.deflatedJar(members);
        int end = full.length - 22;
        int central = get32(full, end + 16);
        int secondCentral = central + 46 + get16(full, central + 28)
                + get16(full, central + 30) + get16(full, central + 32);
        int secondLocal = get32(full, secondCentral + 42);
        if (sameName) {
            full[30] = 'B';
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(full, 0, secondLocal);
        le(out, 0L, 4);
        out.write(full, secondLocal, central - secondLocal);
        int newCentral = out.size();
        byte[] onlyB = Arrays.copyOfRange(full, secondCentral, end);
        put32(onlyB, 42, secondLocal + 4);
        out.write(onlyB);
        byte[] newEnd = Arrays.copyOfRange(full, end, full.length);
        put16(newEnd, 8, 1);
        put16(newEnd, 10, 1);
        put32(newEnd, 12, onlyB.length);
        put32(newEnd, 16, newCentral);
        out.write(newEnd);
        return out.toByteArray();
    }

    private static int get16(byte[] data, int offset) {
        return (data[offset] & 255) | ((data[offset + 1] & 255) << 8);
    }

    private static int get32(byte[] data, int offset) {
        return get16(data, offset) | (get16(data, offset + 2) << 16);
    }

    private static void put32(byte[] data, int offset, int value) {
        put16(data, offset, value);
        put16(data, offset + 2, value >>> 16);
    }

    private static void definitions(ActionsTest.Checker c, Fixtures fixtures) {
        File benign = fixtures.rawArchive("review-definitions.mtp", benignMembers(), false);
        ScanReport indicators = new PluginScanner(IocDatabase.parse("{")).scan(benign, ScanBudget.unlimited());
        c.that("failed indicator parsing cannot produce an unqualified clean result",
                indicators.coverage() == Coverage.PARTIAL && indicators.verdict() == Verdict.CLEAN,
                indicators.coverage() + " " + indicators.errors);
        File db = new File(fixtures.root(), "review-invalid.hdb");
        Fixtures.write(db, "not-a-valid-signature\n");
        ScanReport signatures = new PluginScanner(IocDatabase.empty(), SignatureDatabase.load(db))
                .scan(benign, ScanBudget.unlimited());
        c.that("failed signature loading is retained as incomplete analysis",
                signatures.coverage() == Coverage.PARTIAL && !signatures.errors.isEmpty()
                        && signatures.verdict() == Verdict.CLEAN,
                signatures.coverage() + " " + signatures.errors);
    }

    private static void filesystemRoot(ActionsTest.Checker c, Fixtures fixtures) {
        File real = new File(fixtures.root(), "review-root-boundary");
        Fixtures.write(new File(real, "one.mtp"), "inert fixture");
        // Exercise the filesystem-root boundary without enumerating the machine's actual root.
        File root = new File(real.getPath()) {
            private static final long serialVersionUID = 1L;
            @Override
            public String getCanonicalPath() {
                return File.separator;
            }
        };
        Discovery discovery = new Discovery();
        c.that("filesystem root admits descendant paths during discovery",
                discovery.find(Arrays.asList(root)).size() == 1 && !discovery.incomplete(),
                discovery.problems().toString());
        FileScanner.Result files = new FileScanner(SignatureDatabase.empty()).scan(
                Arrays.asList(root), null, ScanBudget.unlimited());
        c.that("filesystem root admits descendant paths during file scanning",
                files.filesScanned == 1 && !files.truncated(), files.problems.toString());
    }

    private static void fileCoverage(ActionsTest.Checker c, Fixtures fixtures) throws IOException {
        File large = new File(fixtures.root(), "review-large-file.bin");
        try (java.io.RandomAccessFile out = new java.io.RandomAccessFile(large, "rw")) {
            out.setLength(4L * 1024 * 1024 + 1);
        }
        FileScanner.Result prefix = new FileScanner(SignatureDatabase.empty()).scan(
                Arrays.asList(large), null, ScanBudget.unlimited());
        c.that("file prefix cap records incomplete pattern coverage", prefix.truncated(),
                prefix.problems.toString());
        Map<String, byte[]> many = new LinkedHashMap<String, byte[]>();
        for (int i = 0; i < 501; i++) {
            many.put("e" + i, new byte[] {1});
        }
        File wide = fixtures.rawArchive("review-file-archive-count.zip", many, false);
        FileScanner.Result count = new FileScanner(SignatureDatabase.empty()).scan(
                Arrays.asList(wide), null, ScanBudget.unlimited());
        c.that("file archive member cap records incomplete coverage", count.truncated(),
                count.problems.toString());
        many.clear();
        many.put("large.bin", new byte[1024 * 1024 + 1]);
        File member = fixtures.deflatedArchive("review-file-member-limit.zip", many);
        FileScanner.Result limited = new FileScanner(SignatureDatabase.empty()).scan(
                Arrays.asList(member), null, ScanBudget.unlimited());
        c.that("file archive member prefix cap records incomplete coverage", limited.truncated(),
                limited.problems.toString());
    }

    private static void reportRedaction(ActionsTest.Checker c, Fixtures fixtures) throws Exception {
        String bot = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
        String bearer = "review_bearer_value_123456789";
        String password = "review_password_value_123456";
        String key = "review_api_key_123456789";
        Signal signal = new Signal("NET003", Category.NETWORK, Severity.HIGH, "Credential fixture", "Inert");
        signal.withEvidence("https://api.telegram.org/bot" + bot + "/sendDocument",
                "Authorization: Bearer " + bearer + "; password=" + password + "&api_key=" + key);
        ScanReport report = scan(fixtures.rawArchive("review-redaction.mtp", benignMembers(), false));
        report.add(signal);
        report.addError("could not load https://user:" + password + "@example.test/definitions?api_key=" + key);
        String text = ReportFormatter.plainText(report);
        String json = ReportFormatter.json(Arrays.asList(report));
        c.that("text reports redact recognized credentials while retaining rule evidence",
                !text.contains(bot) && !text.contains(bearer) && !text.contains(password) && !text.contains(key)
                        && text.contains("NET003") && text.contains("[REDACTED]"), "synthetic credentials");
        c.that("JSON reports redact recognized credentials in evidence and diagnostics",
                !json.contains(bot) && !json.contains(bearer) && !json.contains(password) && !json.contains(key)
                        && json.contains("NET003") && json.contains("[REDACTED]"), "synthetic credentials");
        c.that("UI evidence redacts credentials before display or truncation",
                !signal.evidence().get(0).where.contains(bot)
                        && !signal.evidence().get(0).snippet.contains(bearer), "synthetic credentials");
        Signal quoted = new Signal("TEST", Category.PROVENANCE, Severity.INFO, "Inert", "Inert");
        quoted.withEvidence("fixture", "password=\"alpha beta\"; secret='gamma delta'; token=\"one\\\" two\"");
        String safe = quoted.evidence().get(0).snippet;
        c.that("quoted credential redaction includes spaces and escaped quotes",
                !safe.contains("alpha") && !safe.contains("beta") && !safe.contains("gamma")
                        && !safe.contains("delta") && !safe.contains("one") && !safe.contains("two"),
                "synthetic quoted values");
        Json.parseObject(json);
    }
}
