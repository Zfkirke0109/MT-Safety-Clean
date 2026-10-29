package mtsafety.test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import mt.safety.scanner.core.SignatureDatabase;

/** Definition limits and cache freshness, runnable independently with a small heap. */
public final class SignatureDatabaseRegressionTest {
    private SignatureDatabaseRegressionTest() { }

    public static void main(String[] args) throws Exception {
        final int[] failures = {0};
        run(new ActionsTest.Checker() {
            @Override public void that(String description, boolean condition, String context) {
                if (!condition) {
                    failures[0]++;
                }
                System.out.println((condition ? "PASS " : "FAIL ") + description + ": " + context);
            }
        });
        if (failures[0] > 0) { throw new AssertionError(failures[0] + " failed checks"); }
    }

    public static void run(ActionsTest.Checker check) throws Exception {
        File root = Files.createTempDirectory("signature-limits-").toFile();
        File changing = new File(root, "changing.hdb");
        write(changing, "00000000000000000000000000000000:*:Old\n", 1);
        long modified = changing.lastModified();
        String oldStamp = SignatureDatabase.stamp(root);
        write(changing, "00000000000000000000000000000000:*:New\n", 1);
        if (!changing.setLastModified(modified)) { throw new IOException("restore timestamp"); }
        check.that("content replacement invalidates same-size same-mtime stamp",
                !oldStamp.equals(SignatureDatabase.stamp(root)), oldStamp);

        File clean = new File(root, "many.fp");
        write(clean, "00000000000000000000000000000000:*:Clean\n", 100001);
        SignatureDatabase db = SignatureDatabase.load(clean);
        check.that("clean entries share the global entry limit", db.cleanCount() <= 100000
                && db.cappedCount() > 0, "loaded=" + db.cleanCount());
        File ignored = new File(root, "many.ign2");
        BufferedWriter names = writer(ignored);
        try { for (int i = 0; i < 100001; i++) { names.write("Ignore" + i + "\n"); } }
        finally { names.close(); }
        db = SignatureDatabase.load(ignored);
        check.that("ignored names share the global entry limit", db.cappedCount() > 0,
                "capped=" + db.cappedCount());

        File aggregate = new File(root, "aggregate");
        if (!aggregate.mkdir()) { throw new IOException("mkdir aggregate"); }
        String comment = "#" + repeat('a', 1022) + "\n";
        write(new File(aggregate, "a.hdb"), comment, 9 * 1024);
        write(new File(aggregate, "b.hdb"), comment, 9 * 1024);
        db = SignatureDatabase.load(aggregate);
        check.that("aggregate input bytes are bounded", !db.problems().isEmpty(),
                "files=" + db.fileCount());
        check.that("over-budget stamps are never reusable",
                !SignatureDatabase.stamp(aggregate).equals(SignatureDatabase.stamp(aggregate)),
                "aggregate stamp reused");

        File longNames = new File(root, "long-names.fp");
        write(longNames, "00000000000000000000000000000000:*:" + repeat('n', 2000) + "\n", 6500);
        db = SignatureDatabase.load(longNames);
        check.that("long clean names exhaust the memory allowance before the entry cap",
                db.cappedCount() > 0 && db.cleanCount() > 0 && db.cleanCount() < 6500,
                "loaded=" + db.cleanCount());
        check.that("retained memory and aggregate read counters remain bounded",
                db.retainedBytes() <= SignatureDatabase.MAX_RETAINED_BYTES
                        && db.inputBytes() <= SignatureDatabase.MAX_INPUT_BYTES
                        && db.retainedEntryCount() <= SignatureDatabase.MAX_RETAINED_ENTRIES,
                "bytes=" + db.retainedBytes() + ", entries=" + db.retainedEntryCount());
        check.that("capped loads explicitly report incomplete and cannot be cached",
                !db.complete() && !db.problems().isEmpty()
                        && !db.sourceStamp().equals(SignatureDatabase.stamp(longNames)),
                db.problems().toString());

        File mixed = new File(root, "mixed");
        if (!mixed.mkdir()) { throw new IOException("mkdir mixed"); }
        BufferedWriter mixNames = writer(new File(mixed, "a.ign2"));
        try { for (int i = 0; i < 99999; i++) { mixNames.write("Disabled" + i + "\n"); } }
        finally { mixNames.close(); }
        write(new File(mixed, "b.fp"), "00000000000000000000000000000000:*:Clean\n", 2);
        write(new File(mixed, "c.hdb"), "00000000000000000000000000000000:*:Bad\n", 1);
        write(new File(mixed, "d.ndb"), "Pattern:0:*:4142\n", 1);
        db = SignatureDatabase.load(mixed);
        check.that("one global entry count covers ignored, clean, hash and pattern entries",
                db.retainedEntryCount() == 100000 && db.ignoredCount() == 99999
                        && db.cleanCount() == 1 && db.hashCount() == 0 && db.patternCount() == 0
                        && db.cappedCount() == 3, "retained=" + db.retainedEntryCount());

        File mutable = new File(root, "mutable.ndb");
        write(mutable, "Before:0:*:4142\n", 1);
        db = SignatureDatabase.load(new MutatingFile(mutable));
        check.that("same-metadata mutation during loading is diagnosed",
                !db.complete() && db.problems().toString().contains("changed during loading"),
                db.problems().toString());
        check.that("partial load preserves a true match and refuses its cache stamp",
                db.matchPatterns(new byte[] {65, 66}, 0, 3).size() == 1
                        && !db.sourceStamp().equals(SignatureDatabase.stamp(mutable)),
                db.sourceStamp());

        File lineRecovery = new File(root, "line-recovery.ndb");
        write(lineRecovery, repeat('x', 1024 * 1024) + "\nPreserved:0:*:4142\n", 1);
        db = SignatureDatabase.load(lineRecovery);
        check.that("stream parser discards an oversized line and preserves the following match",
                db.unsupportedCount() == 1 && db.patternCount() == 1
                        && db.matchPatterns(new byte[] {65, 66}, 0, 1).size() == 1,
                "unsupported=" + db.unsupportedCount());

        File valid = new File(root, "valid.ndb");
        write(valid, "Unicode.\u00e9:0:*:4142\r\nLast:0:0:4344", 1);
        db = SignatureDatabase.load(valid);
        check.that("UTF-8, CRLF and final line without newline remain supported",
                db.complete() && db.patternCount() == 2
                        && db.matchPatterns(new byte[] {65, 66}, 0, 3).get(0).name.equals("Unicode.\u00e9"),
                db.problems().toString());
        check.that("a complete stable load exposes exactly its content stamp",
                db.sourceStamp().equals(SignatureDatabase.stamp(valid)), db.sourceStamp());

        File manySources = new File(root, "many-sources");
        if (!manySources.mkdir()) { throw new IOException("mkdir many sources"); }
        for (int i = 0; i <= SignatureDatabase.MAX_DEFINITION_FILES; i++) {
            write(new File(manySources, i + ".hdb"), "", 0);
        }
        db = SignatureDatabase.load(manySources);
        check.that("source bookkeeping is bounded before reading contents",
                !db.complete() && db.inputBytes() == 0 && db.fileCount() == 0,
                db.problems().toString());

        Thread.currentThread().interrupt();
        try {
            db = SignatureDatabase.load(valid);
            check.that("interrupted definition loading reports incomplete and preserves interruption",
                    !db.complete() && Thread.currentThread().isInterrupted()
                            && !db.problems().isEmpty(), db.problems().toString());
        } finally { Thread.interrupted(); }

        db = SignatureDatabase.load(java.util.Arrays.asList(new ReadFailureFile(valid), valid));
        check.that("a failed definition source does not hide true matches in later sources",
                !db.complete() && db.patternCount() == 2
                        && db.matchPatterns(new byte[] {65, 66}, 0, 1).size() == 1,
                "patterns=" + db.patternCount() + ", problems=" + db.problems());

        db = SignatureDatabase.load(java.util.Arrays.asList(new File("/dev/null"), valid));
        check.that("a nonregular source does not discard independent valid definitions",
                !db.complete() && db.patternCount() == 2
                        && db.matchPatterns(new byte[] {65, 66}, 0, 1).size() == 1
                        && !db.sourceStamp().equals(SignatureDatabase.stamp(valid)),
                "patterns=" + db.patternCount() + ", problems=" + db.problems());

        String property = "mtsafety.forceDirectoryStreamUnsupported";
        String previous = System.getProperty(property);
        System.setProperty(property, "true");
        try {
            db = SignatureDatabase.load(java.util.Arrays.asList(mixed, valid));
            check.that("a failed directory backend does not discard an explicit valid definition",
                    !db.complete() && db.patternCount() == 2
                            && db.matchPatterns(new byte[] {65, 66}, 0, 1).size() == 1
                            && !db.sourceStamp().equals(SignatureDatabase.stamp(valid)),
                    "patterns=" + db.patternCount() + ", problems=" + db.problems());
        } finally {
            if (previous == null) { System.clearProperty(property); }
            else { System.setProperty(property, previous); }
        }

        db = SignatureDatabase.load(java.util.Arrays.asList(new MetadataFailureFile(valid), valid));
        check.that("metadata failure does not discard independent valid definitions",
                !db.complete() && db.patternCount() == 2
                        && db.matchPatterns(new byte[] {65, 66}, 0, 1).size() == 1
                        && db.problems().toString().contains("metadata unavailable"),
                "patterns=" + db.patternCount() + ", problems=" + db.problems());

        db = SignatureDatabase.load(java.util.Arrays.asList(new File("/dev/null"), aggregate, valid));
        check.that("individual source failures do not bypass the total input refusal",
                !db.complete() && db.fileCount() == 0 && db.patternCount() == 0
                        && db.inputBytes() == 0 && db.problems().toString().contains("aggregate"),
                db.problems().toString());
        db = SignatureDatabase.load(java.util.Arrays.asList(new File("/dev/null"), manySources, valid));
        check.that("individual source failures do not bypass the total source count refusal",
                !db.complete() && db.fileCount() == 0 && db.patternCount() == 0
                        && db.inputBytes() == 0 && db.problems().toString().contains("limit"),
                db.problems().toString());
    }

    private static final class MetadataFailureFile extends File {
        private static final long serialVersionUID = 1L;
        MetadataFailureFile(File file) { super(file.getPath()); }
        @Override public long length() { throw new IllegalStateException("metadata unavailable"); }
    }

    private static final class ReadFailureFile extends File {
        private static final long serialVersionUID = 1L;
        ReadFailureFile(File file) { super(file.getPath()); }
        @Override public String getPath() { return super.getPath() + ".missing"; }
    }

    /** Changes bytes after parsing but before the load's verification, preserving size and mtime. */
    private static final class MutatingFile extends File {
        private static final long serialVersionUID = 1L;
        private int metadataReads;

        MutatingFile(File file) { super(file.getPath()); }

        @Override public long lastModified() {
            long modified = super.lastModified();
            if (++metadataReads == 2) {
                try {
                    write(new File(getPath()), "After.:0:*:4344\n", 1);
                    if (!setLastModified(modified)) { throw new IOException("restore timestamp"); }
                } catch (IOException e) { throw new IllegalStateException(e); }
            }
            return modified;
        }
    }

    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        java.util.Arrays.fill(chars, c);
        return new String(chars);
    }

    private static BufferedWriter writer(File file) throws IOException {
        return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
    }

    private static void write(File file, String line, int count) throws IOException {
        BufferedWriter out = writer(file);
        try { for (int i = 0; i < count; i++) { out.write(line); } }
        finally { out.close(); }
    }
}
