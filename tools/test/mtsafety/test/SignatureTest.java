package mtsafety.test;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.core.Bytes;
import mt.safety.scanner.core.FileScanner;
import mt.safety.scanner.core.HexSignature;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.SignatureDatabase;
import mt.safety.scanner.core.Verdict;

/**
 * Tests for the signature engine: ClamAV's pattern syntax, its database files, and the two places
 * they are applied, inside plugin packages and across ordinary files.
 *
 * <p>The signature files here are written by the test rather than downloaded, because what is being
 * checked is that the published <i>format</i> is read correctly; the content of a real database is
 * somebody else's to maintain. Every "malicious" blob is a few inert bytes.
 */
final class SignatureTest {

    static void run(ActionsTest.Checker check, Fixtures fixtures) throws Exception {
        File area = new File(System.getProperty("java.io.tmpdir"), "mtsafety-sig-" + System.currentTimeMillis());
        if (!area.mkdirs()) {
            throw new IllegalStateException("could not create " + area);
        }
        patternSyntax(check);
        databaseFiles(check, new File(area, "db"));
        insidePackages(check, fixtures, new File(area, "db"));
        acrossFiles(check, new File(area, "tree"), new File(area, "db"));
        fromTheScreen(check, new File(area, "screen"), new File(area, "db"));
    }

    // ---------------------------------------------------------------- patterns

    private static void patternSyntax(ActionsTest.Checker check) throws Exception {
        check.that("a literal pattern matches where it occurs",
                sig("deadbeef").matches(bytes(0x00, 0xde, 0xad, 0xbe, 0xef, 0x11))
                        && !sig("deadbeef").matches(bytes(0xde, 0xad, 0xbe, 0x00)), "deadbeef");
        check.that("?? matches any one byte",
                sig("de??ef").matches(bytes(0xde, 0x12, 0xef)) && !sig("de??ef").matches(bytes(0xde, 0xef)),
                "de??ef");
        check.that("a? fixes the high nibble",
                sig("4?ccdd").matches(bytes(0x4f, 0xcc, 0xdd)) && sig("4?ccdd").matches(bytes(0x40, 0xcc, 0xdd))
                        && !sig("4?ccdd").matches(bytes(0x51, 0xcc, 0xdd)), "4?ccdd");
        check.that("?a fixes the low nibble",
                sig("?1ccdd").matches(bytes(0x41, 0xcc, 0xdd)) && sig("?1ccdd").matches(bytes(0x51, 0xcc, 0xdd))
                        && !sig("?1ccdd").matches(bytes(0x42, 0xcc, 0xdd)), "?1ccdd");
        check.that("a pattern needs at least two fixed bytes, or it would match everything",
                rejected("????", "*") && rejected("4?", "*") && rejected("4?cc", "*") && !rejected("(aa|bb)cc", "*"),
                "wildcards alone");
        check.that("* matches any run, including none",
                sig("aa*bb").matches(bytes(0xaa, 0, 0, 0xbb)) && sig("aa*bb").matches(bytes(0xaa, 0xbb))
                        && !sig("aa*bb").matches(bytes(0xbb, 0xaa)), "aa*bb");
        check.that("{n} is exactly n bytes",
                sig("aa{2}bb").matches(bytes(0xaa, 1, 2, 0xbb)) && !sig("aa{2}bb").matches(bytes(0xaa, 1, 0xbb)),
                "aa{2}bb");
        check.that("{n-m} is a range",
                sig("aa{1-3}bb").matches(bytes(0xaa, 1, 0xbb)) && sig("aa{1-3}bb").matches(bytes(0xaa, 1, 2, 3, 0xbb))
                        && !sig("aa{1-3}bb").matches(bytes(0xaa, 0xbb))
                        && !sig("aa{1-3}bb").matches(bytes(0xaa, 1, 2, 3, 4, 0xbb)), "aa{1-3}bb");
        check.that("{-m} and {n-} are open ranges",
                sig("aa{-2}bb").matches(bytes(0xaa, 0xbb)) && !sig("aa{-2}bb").matches(bytes(0xaa, 1, 2, 3, 0xbb))
                        && sig("aa{2-}bb").matches(bytes(0xaa, 1, 2, 3, 4, 0xbb))
                        && !sig("aa{2-}bb").matches(bytes(0xaa, 1, 0xbb)), "open ranges");
        check.that("(aa|bb) is a choice",
                sig("(aa|bb)cc").matches(bytes(0xaa, 0xcc)) && sig("(aa|bb)cc").matches(bytes(0xbb, 0xcc))
                        && !sig("(aa|bb)cc").matches(bytes(0xcc, 0xcc)), "(aa|bb)cc");
        check.that("alternatives of different lengths are refused",
                rejected("(aa|bbcc)dd", "*"), "silently shifting later bytes would be worse");
        check.that("an offset pins the pattern",
                HexSignature.compile("t", 0, "0", "aabb").matches(bytes(0xaa, 0xbb, 0))
                        && !HexSignature.compile("t", 0, "0", "aabb").matches(bytes(0, 0xaa, 0xbb)), "offset 0");
        HexSignature shifted = HexSignature.compile("t", 0, "4,2", "aabb");
        check.that("n,m allows a shift of up to m",
                shifted.matches(bytes(0, 0, 0, 0, 0xaa, 0xbb)) && shifted.matches(bytes(0, 0, 0, 0, 0, 0, 0xaa, 0xbb))
                        && !shifted.matches(bytes(0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb))
                        && !shifted.matches(bytes(0, 0, 0, 0xaa, 0xbb)), "4,2");
        HexSignature atEnd = HexSignature.compile("t", 0, "EOF-2", "aabb");
        check.that("EOF-n counts from the end",
                atEnd.matches(bytes(1, 2, 0xaa, 0xbb)) && !atEnd.matches(bytes(0xaa, 0xbb, 1, 2)), "EOF-2");
        check.that("syntax outside the implemented set is refused, not loaded to never fire",
                rejected("aabb", "EP+0") && rejected("!(aa|bb)cc", "*") && rejected("aa[2-4]bb", "*")
                        && rejected("aa(B)bb", "*") && rejected("aab", "*") && rejected("zz", "*"),
                "each of these must throw");
        check.that("leading fixed bytes are exposed for bucketing",
                sig("aabb*cc").firstByteHint() == 0xaa && sig("aabb*cc").secondByteHint() == 0xbb
                        && sig("??aabb").firstByteHint() == -1 && sig("(aa|bb)cc").firstByteHint() == -1
                        && sig("a?bbcc").firstByteHint() == -1 && sig("aa*bb").secondByteHint() == -1,
                "hints");

        // A pattern with several wide gaps on data that keeps matching its first block would explore
        // every combination of gap lengths. The step bound turns that into a quick miss.
        byte[] runOfA = new byte[8192];
        java.util.Arrays.fill(runOfA, (byte) 0x41);
        long started = System.currentTimeMillis();
        boolean matched = sig("41*41*41*41*42").matches(runOfA);
        long took = System.currentTimeMillis() - started;
        check.that("a pathological pattern gives up quickly rather than freezing the phone",
                !matched && took < 3000, took + " ms");
        check.that("and a satisfiable one with the same shape still matches",
                sig("41*41*41*41*41").matches(runOfA), "consecutive A's satisfy every gap at zero");
    }

    // ---------------------------------------------------------------- database files

    private static final byte[] EVIL_MD5_BLOB = Fixtures.bytes("inert blob one: known by md5");
    private static final byte[] EVIL_SHA_BLOB = Fixtures.bytes("inert blob two: known by sha256");
    private static final byte[] CLEAN_BLOB = Fixtures.bytes("inert blob three: on the clean list");
    private static final byte[] PUA_BLOB = Fixtures.bytes("inert blob four: merely unwanted");
    /** The bytes the pattern signature looks for; spelled in hex in the .ndb below. */
    private static final String PATTERN_TEXT = "com/evil/Payload";

    private static void writeDatabase(File dir) {
        dir.mkdirs();
        String md5 = Bytes.hex(Bytes.digest("MD5", EVIL_MD5_BLOB));
        String sha = Bytes.hex(Bytes.digest("SHA-256", EVIL_SHA_BLOB));
        String pua = Bytes.hex(Bytes.digest("MD5", PUA_BLOB));
        Fixtures.write(new File(dir, "test.hdb"), ""
                + "# a comment line\n"
                + md5 + ":" + EVIL_MD5_BLOB.length + ":Test.Trojan.ByMd5\n"
                + pua + ":*:PUA.Test.Unwanted\n"
                + "not a signature line\n");
        Fixtures.write(new File(dir, "test.hsb"), sha + ":*:Test.Trojan.BySha256\n");
        Fixtures.write(new File(dir, "test.ndb"), ""
                + "Test.Pattern.Anywhere:0:*:" + hex(PATTERN_TEXT) + "\n"
                + "Test.Pattern.ElfOnly:6:*:" + hex("ELF-ONLY-MARKER") + "\n"
                + "Test.Pattern.Ignored:0:*:" + hex("IGNORED-MARKER") + "\n"
                + "Test.Pattern.Unsupported:0:EP+0:" + hex("whatever") + "\n"
                + "Test.Pattern.Mail:4:*:aabbccdd\n");
        Fixtures.write(new File(dir, "test.fp"),
                Bytes.hex(Bytes.digest("MD5", CLEAN_BLOB)) + ":*:Test.Clean\n");
        Fixtures.write(new File(dir, "local.ign2"), "Test.Pattern.Ignored\n");
    }

    private static void databaseFiles(ActionsTest.Checker check, File dir) throws Exception {
        writeDatabase(dir);
        SignatureDatabase db = SignatureDatabase.load(dir);
        check.that("every signature file in the folder is read",
                db.fileCount() == 5 && db.files().contains("test.hdb") && db.files().contains("local.ign2"),
                db.files().toString());
        check.that("hash entries are counted, comments and bad lines are not",
                db.hashCount() == 3, "hashes=" + db.hashCount());
        check.that("patterns load, minus the ignored, the unsupported offset and the unscanned target",
                db.patternCount() == 2 && db.unsupportedCount() == 3,
                "patterns=" + db.patternCount() + " unsupported=" + db.unsupportedCount());
        check.that("problems are reported with file and line",
                !db.problems().isEmpty() && db.problems().get(0).startsWith("test.hdb:4"),
                db.problems().toString());
        check.that("the clean list is kept apart from the detections",
                db.cleanCount() == 1 && db.wantsMd5() && db.wantsSha256() && !db.wantsSha1(),
                "clean=" + db.cleanCount());

        SignatureDatabase.Match byMd5 = db.matchHash(db.digest(EVIL_MD5_BLOB), EVIL_MD5_BLOB.length);
        check.that("an md5 entry with a size matches that exact file",
                byMd5 != null && byMd5.name.equals("Test.Trojan.ByMd5") && byMd5.hash && !byMd5.pua,
                String.valueOf(byMd5));
        check.that("and not a file of another size",
                db.matchHash(db.digest(EVIL_MD5_BLOB), EVIL_MD5_BLOB.length + 1) == null, "size must match");
        SignatureDatabase.Match bySha = db.matchHash(db.digest(EVIL_SHA_BLOB), EVIL_SHA_BLOB.length);
        check.that("a sha256 entry with * matches at any size",
                bySha != null && bySha.name.equals("Test.Trojan.BySha256"), String.valueOf(bySha));
        SignatureDatabase.Match unwanted = db.matchHash(db.digest(PUA_BLOB), PUA_BLOB.length);
        check.that("a PUA. name is flagged as unwanted rather than malicious",
                unwanted != null && unwanted.pua, String.valueOf(unwanted));
        check.that("a clean-listed file is recognised as such",
                db.isKnownClean(db.digest(CLEAN_BLOB), CLEAN_BLOB.length)
                        && !db.isKnownClean(db.digest(EVIL_MD5_BLOB), EVIL_MD5_BLOB.length), "fp");

        byte[] textWithPattern = Fixtures.bytes("plain text mentioning " + PATTERN_TEXT + " here");
        List<SignatureDatabase.Match> hits = db.matchPatterns(textWithPattern,
                SignatureDatabase.fileType(textWithPattern, "txt"), 3);
        check.that("an untargeted pattern matches in any file",
                hits.size() == 1 && hits.get(0).name.equals("Test.Pattern.Anywhere") && !hits.get(0).hash,
                hits.toString());
        byte[] textWithElfMarker = Fixtures.bytes("text containing ELF-ONLY-MARKER but not an ELF");
        byte[] elf = new byte[64];
        elf[0] = 0x7F;
        elf[1] = 'E';
        elf[2] = 'L';
        elf[3] = 'F';
        System.arraycopy(Fixtures.bytes("ELF-ONLY-MARKER"), 0, elf, 16, 15);
        check.that("a pattern targeted at ELF files is only tried on ELF files",
                db.matchPatterns(textWithElfMarker, SignatureDatabase.fileType(textWithElfMarker, "txt"), 3).isEmpty()
                        && db.matchPatterns(elf, SignatureDatabase.fileType(elf, "so"), 3).size() == 1,
                "target types");
        byte[] ignored = Fixtures.bytes("IGNORED-MARKER");
        check.that("an .ign2 file switches a signature off by name",
                db.matchPatterns(ignored, 0, 3).isEmpty(), "ign2");

        byte[] pe = Fixtures.bytes("MZ\u0090\u0000this program cannot be run");
        byte[] pdf = Fixtures.bytes("%PDF-1.4 ...");
        check.that("file types are told apart by their leading bytes",
                SignatureDatabase.fileType(pe, "exe") == SignatureDatabase.TARGET_PE
                        && SignatureDatabase.fileType(elf, "") == SignatureDatabase.TARGET_ELF
                        && SignatureDatabase.fileType(pdf, "pdf") == SignatureDatabase.TARGET_PDF
                        && SignatureDatabase.fileType(textWithPattern, "txt") == SignatureDatabase.TARGET_ASCII
                        && SignatureDatabase.fileType(Fixtures.fakePng(64), "png") == SignatureDatabase.TARGET_GRAPHICS
                        && SignatureDatabase.fileType(Fixtures.fakeDex(64), "dex") == HexSignature.TARGET_ANY,
                "file types");

        // The date shown for a signature file comes from its modification time, through this.
        boolean datesRoundTrip = true;
        String[] dates = {"1970-01-01", "1999-12-31", "2000-02-29", "2024-02-29", "2024-03-01", "2026-09-20"};
        for (int i = 0; i < dates.length; i++) {
            long millis = mt.safety.scanner.core.Dates.epochDay(dates[i]) * 86400000L + 3600000L;
            if (!dates[i].equals(mt.safety.scanner.core.Dates.isoDate(millis))) {
                datesRoundTrip = false;
            }
        }
        check.that("an instant is rendered as the date it falls on",
                datesRoundTrip && mt.safety.scanner.core.Dates.daysBetween(0L, 2L * 86400000L) == 2, "isoDate");

        String before = SignatureDatabase.stamp(dir);
        Fixtures.write(new File(dir, "extra.hdb"), "00000000000000000000000000000000:*:Test.Extra\n");
        check.that("the folder stamp changes when a file is added, so a cache cannot go stale",
                !before.equals(SignatureDatabase.stamp(dir)) && before.length() > 0, "stamp");
        new File(dir, "extra.hdb").delete();

        File packed = new File(dir.getParentFile(), "daily.cvd");
        Fixtures.write(packed, "ClamAV-VDB:not really\n");
        SignatureDatabase fromPacked = SignatureDatabase.load(packed);
        check.that("a packed .cvd is explained rather than silently ignored",
                fromPacked.isEmpty() && !fromPacked.problems().isEmpty()
                        && fromPacked.problems().get(0).contains("sigtool"), fromPacked.problems().toString());

        // Loading stops at the cap and says how much it left out.
        File big = new File(dir.getParentFile(), "big");
        big.mkdirs();
        StringBuilder many = new StringBuilder();
        int over = 5;
        for (int i = 0; i < SignatureDatabase.MAX_PATTERNS + over; i++) {
            many.append("Test.Many.").append(i).append(":0:*:").append(String.format("%08x", i)).append("cafe\n");
        }
        Fixtures.write(new File(big, "many.ndb"), many.toString());
        SignatureDatabase capped = SignatureDatabase.load(big);
        check.that("the pattern cap holds and the overflow is counted",
                capped.patternCount() == SignatureDatabase.MAX_PATTERNS && capped.cappedCount() == over,
                capped.patternCount() + " loaded, " + capped.cappedCount() + " over");
        byte[] probe = new byte[] {0, 0, 0x27, 0x0f, (byte) 0xca, (byte) 0xfe};
        check.that("a capped database still matches what it did load",
                capped.matchPatterns(probe, 0, 3).size() == 1
                        && capped.matchPatterns(probe, 0, 3).get(0).name.equals("Test.Many.9999"),
                capped.matchPatterns(probe, 0, 3).toString());
    }

    // ---------------------------------------------------------------- inside packages

    private static void insidePackages(ActionsTest.Checker check, Fixtures fixtures, File dbDir) {
        SignatureDatabase db = SignatureDatabase.load(dbDir);
        PluginScanner scanner = new PluginScanner(IocDatabase.empty(), db);
        String benign = "package demo;\npublic class A { public int n() { return 1; } }\n";

        Map<String, byte[]> hashed = new LinkedHashMap<String, byte[]>();
        hashed.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.hashed", "Hashed", "demo.A")));
        hashed.put("src/demo/A.java", Fixtures.bytes(benign));
        hashed.put("assets/data.dat", EVIL_MD5_BLOB);
        ScanReport byHash = scanner.scan(fixtures.rawArchive("sig-hash.mtp", hashed, false), ScanBudget.unlimited());
        check.that("a member whose hash is in the database makes the package known bad",
                byHash.verdict() == Verdict.KNOWN_BAD && byHash.hasRule("SIG001"),
                byHash.verdict() + " :: " + summarise(byHash));
        check.that("the evidence names the member and the signature",
                evidence(byHash, "SIG001").contains("assets/data.dat")
                        && evidence(byHash, "SIG001").contains("Test.Trojan.ByMd5"), evidence(byHash, "SIG001"));

        Map<String, byte[]> patterned = new LinkedHashMap<String, byte[]>();
        patterned.put("manifest.json", Fixtures.bytes(Fixtures.v3Manifest("demo.patterned", "Patterned", "demo.P")));
        patterned.put("classes.dex", Fixtures.dexWithStrings("Ldemo/P;", "L" + PATTERN_TEXT + ";"));
        ScanReport byPattern = scanner.scan(fixtures.rawArchive("sig-pattern.mtp", patterned, false),
                ScanBudget.unlimited());
        check.that("a byte pattern found in compiled code makes the package known bad",
                byPattern.verdict() == Verdict.KNOWN_BAD && byPattern.hasRule("SIG002")
                        && evidence(byPattern, "SIG002").contains("Test.Pattern.Anywhere"),
                byPattern.verdict() + " :: " + summarise(byPattern));

        Map<String, byte[]> unwanted = new LinkedHashMap<String, byte[]>();
        unwanted.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.pua", "Unwanted", "demo.A")));
        unwanted.put("src/demo/A.java", Fixtures.bytes(benign));
        unwanted.put("assets/tool.dat", PUA_BLOB);
        ScanReport pua = scanner.scan(fixtures.rawArchive("sig-pua.mtp", unwanted, false), ScanBudget.unlimited());
        check.that("a PUA signature is high severity, not a conviction",
                pua.hasRule("SIG003") && pua.verdict() == Verdict.SUSPICIOUS && !pua.hasRule("SIG001"),
                pua.verdict() + " :: " + summarise(pua));

        Map<String, byte[]> clean = new LinkedHashMap<String, byte[]>();
        clean.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.clean", "Listed clean", "demo.A")));
        clean.put("src/demo/A.java", Fixtures.bytes(benign));
        clean.put("assets/known.dat", CLEAN_BLOB);
        ScanReport listed = scanner.scan(fixtures.rawArchive("sig-clean.mtp", clean, false), ScanBudget.unlimited());
        check.that("a clean-listed member is never reported",
                listed.verdict() == Verdict.CLEAN && !listed.hasRule("SIG001") && !listed.hasRule("SIG002"),
                listed.verdict() + " :: " + summarise(listed));

        Map<String, byte[]> inner = new LinkedHashMap<String, byte[]>();
        inner.put("evil/Payload.class", EVIL_SHA_BLOB);
        Map<String, byte[]> nested = new LinkedHashMap<String, byte[]>();
        nested.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.nested", "Nested", "demo.A")));
        nested.put("src/demo/A.java", Fixtures.bytes(benign));
        nested.put("libs/helper.jar", Fixtures.deflatedJar(inner));
        ScanReport insideJar = scanner.scan(fixtures.rawArchive("sig-nested.mtp", nested, false), ScanBudget.unlimited());
        check.that("a hash is checked inside an archived library too",
                insideJar.hasRule("SIG001") && evidence(insideJar, "SIG001").contains("libs/helper.jar!evil/Payload.class"),
                summarise(insideJar) + " :: " + evidence(insideJar, "SIG001"));

        IocDatabase trusting = IocDatabase.empty();
        trusting.trust(byHash.contentHash, "trusted anyway");
        ScanReport trusted = new PluginScanner(trusting, db).scan(new File(byHash.path), ScanBudget.unlimited());
        check.that("a trusted hash does not silence a signature match",
                trusted.verdict() == Verdict.KNOWN_BAD, trusted.verdict().toString());

        ScanReport without = new PluginScanner(IocDatabase.empty()).scan(new File(byHash.path), ScanBudget.unlimited());
        check.that("with no database loaded the same package is judged on capability alone",
                !without.hasRule("SIG001") && without.verdict() == Verdict.CLEAN,
                without.verdict() + " :: " + summarise(without));
    }

    // ---------------------------------------------------------------- across files

    private static void acrossFiles(ActionsTest.Checker check, File tree, File dbDir) throws Exception {
        SignatureDatabase db = SignatureDatabase.load(dbDir);
        File downloads = new File(tree, "Download");
        File deep = new File(downloads, "sub/deeper");
        File excluded = new File(tree, "scanner-own");
        deep.mkdirs();
        excluded.mkdirs();
        Fixtures.write(new File(tree, "notes.txt"), "nothing to see here\n");
        Fixtures.writeBytes(new File(downloads, "evil.bin"), EVIL_MD5_BLOB);
        Fixtures.writeBytes(new File(deep, "marker.dat"), Fixtures.bytes("xx " + PATTERN_TEXT + " xx"));
        Fixtures.writeBytes(new File(excluded, "quarantined.bin"), EVIL_MD5_BLOB);
        Fixtures.writeBytes(new File(downloads, "empty.bin"), new byte[0]);
        Map<String, byte[]> apk = new LinkedHashMap<String, byte[]>();
        apk.put("AndroidManifest.xml", Fixtures.bytes("<manifest/>"));
        apk.put("classes.dex", Fixtures.dexWithStrings("L" + PATTERN_TEXT + ";"));
        Fixtures.writeBytes(new File(downloads, "app.apk"), Fixtures.deflatedJar(apk));
        // A file too large to hold in memory whole is still hashed, streaming.
        byte[] large = new byte[FileScanner.PATTERN_BYTES + 4096];
        for (int i = 0; i < large.length; i++) {
            large[i] = (byte) (i * 7);
        }
        Fixtures.writeBytes(new File(downloads, "large.bin"), large);
        File largeDb = new File(tree.getParentFile(), "db-large");
        largeDb.mkdirs();
        Fixtures.write(new File(largeDb, "large.hdb"),
                Bytes.hex(Bytes.digest("MD5", large)) + ":" + large.length + ":Test.Large\n");

        List<File> roots = new ArrayList<File>();
        roots.add(tree);
        FileScanner.Result result = new FileScanner(db).scan(roots, excluded, ScanBudget.unlimited());
        check.that("the walk reaches every readable file outside the excluded area",
                result.filesSeen == 6 && result.filesScanned == 5 && !result.truncated(),
                "seen=" + result.filesSeen + " scanned=" + result.filesScanned + " stop=" + result.stoppedBecause);
        check.that("a hashed file, a deep pattern and a dex inside an apk are all found",
                hit(result, "evil.bin", "Test.Trojan.ByMd5") && hit(result, "marker.dat", "Test.Pattern.Anywhere")
                        && hit(result, "app.apk!classes.dex", "Test.Pattern.Anywhere"),
                describe(result));
        check.that("nothing under the excluded area is reported",
                !hit(result, "quarantined.bin", "Test.Trojan.ByMd5") && result.hits.size() == 3, describe(result));

        FileScanner.Result largeResult = new FileScanner(SignatureDatabase.load(largeDb)).scan(roots, excluded,
                ScanBudget.unlimited());
        check.that("a file larger than the in-memory read is hashed in full",
                hit(largeResult, "large.bin", "Test.Large"), describe(largeResult));

        FileScanner.Result starved = new FileScanner(db).scan(roots, excluded, new ScanBudget(60000L, 64L));
        check.that("a scan that ran out of budget says so instead of reporting a clean folder",
                starved.truncated() && starved.stoppedBecause == FileScanner.Stop.BUDGET,
                "stop=" + starved.stoppedBecause);

        String text = mt.safety.scanner.core.ReportFormatter.fileScanText(result, db);
        check.that("the file scan report lists every hit with its signature",
                text.contains("Test.Trojan.ByMd5") && text.contains("app.apk!classes.dex")
                        && text.contains("Matches (3)"), text);
    }

    // ---------------------------------------------------------------- from the screen

    private static void fromTheScreen(ActionsTest.Checker check, File area, File dbDir) throws Exception {
        File filesDir = new File(area, "a/b/c/d/files");
        File installed = new File(area, "a/plugins");
        File downloads = new File(area, "a/b/Download");
        filesDir.mkdirs();
        installed.mkdirs();
        downloads.mkdirs();
        String benign = "package x;\npublic class A { public int n() { return 1; } }\n";
        File carrier = new File(installed, "carrier");
        Fixtures.write(new File(carrier, "manifest.json"), Fixtures.manifest("demo.carrier", "Carrier", "x.A"));
        Fixtures.write(new File(carrier, "src/x/A.java"), benign);
        Fixtures.writeBytes(new File(carrier, "assets/blob.dat"), EVIL_SHA_BLOB);
        Fixtures.writeBytes(new File(downloads, "dropped.bin"), EVIL_MD5_BLOB);

        ActionsTest.FakeHost host = new ActionsTest.FakeHost(filesDir);
        host.type("definitions");
        ScanRunner.Result none = new ScanRunner(host).run();
        check.that("with no signature files the screen says so and how to get some",
                none.commandOutcome.contains("None loaded") && none.commandOutcome.contains("import"),
                none.commandOutcome);
        check.that("without signatures the carrier plugin is judged clean on capability alone",
                verdictOf(none, "demo.carrier") == Verdict.CLEAN, String.valueOf(verdictOf(none, "demo.carrier")));
        host.type("files");
        check.that("a file scan without signatures explains what it needs",
                new ScanRunner(host).run().commandOutcome.contains("No signature files"), "files with nothing loaded");

        host.type("import " + new File(dbDir, "test.hsb").getAbsolutePath());
        ScanRunner.Result imported = new ScanRunner(host).run();
        check.that("importing a signature file copies it into the plugin's signature folder",
                new File(filesDir, ScanRunner.SIGNATURE_DIR + "/test.hsb").isFile()
                        && imported.commandOutcome.startsWith("Added test.hsb: 1 hash signatures"),
                imported.commandOutcome);
        // Commands run after the scan, as every command does, so the import shows in the next build.
        check.that("the import says the next scan will use it",
                imported.commandOutcome.contains("Reopen"), imported.commandOutcome);
        ScanRunner.Result next = new ScanRunner(host).run();
        check.that("the scan that follows the import uses it",
                verdictOf(next, "demo.carrier") == Verdict.KNOWN_BAD
                        && new ScanRunner(host).actionTargets(next, "malicious").size() == 1,
                String.valueOf(verdictOf(next, "demo.carrier")));
        boolean aboutMentions = false;
        for (int i = 0; i < imported.aboutRows.size(); i++) {
            String summary = imported.aboutRows.get(i).summary;
            if (summary != null && summary.contains("1 hash signatures")) {
                aboutMentions = true;
            }
        }
        check.that("the About section shows what is loaded and how old it is", aboutMentions, "about rows");

        host.type("import " + new File(dbDir, "test.hdb").getAbsolutePath());
        ScanRunner.Result second = new ScanRunner(host).run();
        check.that("a second file adds to the first",
                second.commandOutcome.contains("Added test.hdb") && second.commandOutcome.contains("2 files"),
                second.commandOutcome);
        host.type("import " + new File(dbDir, "test.hdb").getAbsolutePath());
        check.that("importing the same file again replaces it",
                new ScanRunner(host).run().commandOutcome.startsWith("Updated test.hdb"), "re-import");

        File packed = new File(area, "daily.cvd");
        Fixtures.write(packed, "ClamAV-VDB:not really\n");
        host.type("import " + packed.getAbsolutePath());
        check.that("a packed bundle is refused with the command that unpacks it",
                new ScanRunner(host).run().commandOutcome.contains("sigtool"), "cvd");

        File junk = new File(area, "junk.ndb");
        Fixtures.write(junk, "this is not a signature\n");
        host.type("import " + junk.getAbsolutePath());
        check.that("a file with nothing usable in it is not copied into the folder",
                new ScanRunner(host).run().commandOutcome.contains("No usable signatures")
                        && !new File(filesDir, ScanRunner.SIGNATURE_DIR + "/junk.ndb").exists(), "junk");

        host.type("files " + downloads.getAbsolutePath());
        ScanRunner.Result scanned = new ScanRunner(host).run();
        check.that("the files command reports what it checked and what matched",
                scanned.commandOutcome.contains("1 match") && scanned.fileHitLines.size() == 1
                        && scanned.fileHitLines.get(0).contains("Test.Trojan.ByMd5")
                        && scanned.fileHitLines.get(0).contains("dropped.bin"),
                scanned.commandOutcome + " :: " + scanned.fileHitLines);
        check.that("the full list is written next to the other reports",
                new File(filesDir, ScanRunner.FILE_REPORT).isFile()
                        && scanned.commandOutcome.contains(ScanRunner.FILE_REPORT), scanned.commandOutcome);
        boolean listed = false;
        for (int i = 0; i < scanned.rows.size(); i++) {
            if (scanned.rows.get(i).title.contains("dropped.bin")) {
                listed = true;
            }
        }
        check.that("matched files are listed on the screen", listed, "rows");
        host.type("files " + new File(area, "no-such-folder").getAbsolutePath());
        check.that("a path that cannot be read is refused",
                new ScanRunner(host).run().commandOutcome.contains("Not a readable"), "bad path");

        mt.safety.scanner.Strings en = mt.safety.scanner.Strings.forLanguage("en");
        mt.safety.scanner.Strings zh = mt.safety.scanner.Strings.forLanguage("zh");
        check.that("both languages document the files and import commands",
                en.commandsHelp().contains("files") && zh.commandsHelp().contains("files")
                        && en.commandsHelp().contains("ClamAV") && zh.commandsHelp().contains("ClamAV"), "help");
    }

    // ---------------------------------------------------------------- helpers

    private static HexSignature sig(String hex) throws HexSignature.SyntaxException {
        return HexSignature.compile("t", 0, "*", hex);
    }

    private static boolean rejected(String hex, String offset) {
        try {
            HexSignature.compile("t", 0, offset, hex);
            return false;
        } catch (HexSignature.SyntaxException e) {
            return true;
        }
    }

    private static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    private static String hex(String ascii) {
        return Bytes.hex(Fixtures.bytes(ascii));
    }

    private static boolean hit(FileScanner.Result result, String locationSuffix, String signature) {
        for (int i = 0; i < result.hits.size(); i++) {
            FileScanner.Hit hit = result.hits.get(i);
            if (hit.location().endsWith(locationSuffix) && hit.signature.equals(signature)) {
                return true;
            }
        }
        return false;
    }

    private static String describe(FileScanner.Result result) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < result.hits.size(); i++) {
            sb.append(result.hits.get(i).signature).append('@').append(result.hits.get(i).location()).append("; ");
        }
        return sb.length() == 0 ? "(no hits)" : sb.toString();
    }

    private static String evidence(ScanReport report, String ruleId) {
        for (int i = 0; i < report.signals.size(); i++) {
            if (report.signals.get(i).ruleId.equals(ruleId)) {
                return report.signals.get(i).evidence().toString();
            }
        }
        return "(no " + ruleId + ")";
    }

    private static String summarise(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < report.signals.size(); i++) {
            sb.append(i > 0 ? ", " : "").append(report.signals.get(i).ruleId);
        }
        return sb.length() == 0 ? "(no findings)" : sb.toString();
    }

    private static Verdict verdictOf(ScanRunner.Result result, String pluginId) {
        for (int i = 0; i < result.reports.size(); i++) {
            if (pluginId.equals(result.reports.get(i).manifest.pluginId)) {
                return result.reports.get(i).verdict();
            }
        }
        return null;
    }

    private SignatureTest() {
    }
}
