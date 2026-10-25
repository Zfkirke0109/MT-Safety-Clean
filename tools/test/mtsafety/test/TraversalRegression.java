package mtsafety.test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import mt.safety.scanner.core.Discovery;
import mt.safety.scanner.core.FileScanner;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.SignatureDatabase;

/** Regressions for enumeration before the package-scanning byte budget is reached. */
public final class TraversalRegression {
    private TraversalRegression() {
    }

    private static final class NoArrayFile extends File {
        private static final long serialVersionUID = 1L;

        NoArrayFile(File path) {
            super(path.getPath());
        }

        @Override
        public File[] listFiles() {
            throw new AssertionError("unbounded listFiles was called");
        }
    }

    public static void main(String[] args) throws Exception {
        final int[] failed = {0};
        run(new ActionsTest.Checker() {
            @Override
            public void that(String description, boolean condition, String context) {
                System.out.println((condition ? "PASS " : "FAIL ") + description + " :: " + context);
                if (!condition) {
                    failed[0]++;
                }
            }
        });
        if (failed[0] != 0) {
            throw new AssertionError(failed[0] + " traversal checks failed");
        }
    }

    public static void run(ActionsTest.Checker c) throws Exception {
        File root = new File(System.getProperty("java.io.tmpdir"),
                "mtsafety-traversal-" + System.nanoTime());
        requireDirectory(root);
        File packages = new File(root, "packages");
        requireDirectory(packages);
        write(new File(packages, "one.mtp"), "inert fixture");
        NoArrayFile packageRoot = new NoArrayFile(packages);
        try {
            List<Discovery.Candidate> found = new Discovery().find(Arrays.<File>asList(packageRoot));
            c.that("discovery streams a File subclass path without listFiles", found.size() == 1,
                    "found=" + found.size());
        } catch (AssertionError e) {
            c.that("discovery streams a File subclass path without listFiles", false, e.toString());
        }
        try {
            FileScanner.Result result = new FileScanner(SignatureDatabase.empty()).scan(
                    Arrays.<File>asList(packageRoot), null, ScanBudget.unlimited());
            c.that("file scanning streams a File subclass path without listFiles",
                    result.filesScanned == 1, "scanned=" + result.filesScanned);
        } catch (AssertionError e) {
            c.that("file scanning streams a File subclass path without listFiles", false, e.toString());
        }

        File signatures = new File(root, "signatures");
        requireDirectory(signatures);
        write(new File(signatures, "one.hdb"), "00000000000000000000000000000000:1:Fixture\n");
        NoArrayFile signatureRoot = new NoArrayFile(signatures);
        try {
            SignatureDatabase db = SignatureDatabase.load(signatureRoot);
            c.that("signature loading streams a File subclass path without listFiles",
                    db.hashCount() == 1, "hashes=" + db.hashCount());
        } catch (AssertionError e) {
            c.that("signature loading streams a File subclass path without listFiles", false, e.toString());
        }
        try {
            String stamp = SignatureDatabase.stamp(signatureRoot);
            c.that("signature cache stamping streams a File subclass path without listFiles",
                    stamp.contains("one.hdb"), stamp);
        } catch (AssertionError e) {
            c.that("signature cache stamping streams a File subclass path without listFiles", false,
                    e.toString());
        }

        File manyPackages = new File(root, "many-packages");
        requireDirectory(manyPackages);
        for (int i = 0; i < 250; i++) {
            write(new File(manyPackages, i + ".mtp"), "fixture");
        }
        Discovery discovery = new Discovery();
        List<Discovery.Candidate> found = discovery.find(Arrays.asList(manyPackages));
        c.that("discovery limits loose archive results inside one wide directory",
                found.size() == 200 && discovery.incomplete() && !discovery.problems().isEmpty(),
                "found=" + found.size() + " incomplete=" + discovery.incomplete());

        File broad = new File(root, "broad");
        File explicit = new File(broad, "a/b/c");
        File deepPlugin = new File(explicit, "d/e/f/plugin");
        requireDirectory(deepPlugin);
        write(new File(deepPlugin, "plugin.mtp"), "inert installed fixture");
        List<Discovery.Candidate> overlap = new Discovery().find(Arrays.asList(broad, explicit));
        c.that("an explicit narrower root is searched from its own depth origin",
                overlap.size() == 1 && overlap.get(0).path.equals(deepPlugin),
                "found=" + overlap.size());

        String completeStamp = SignatureDatabase.stamp(signatures);
        c.that("complete signature directory stamps remain stable",
                completeStamp.equals(SignatureDatabase.stamp(signatures)), completeStamp);
        File wideSignatures = new File(root, "wide-signatures");
        requireDirectory(wideSignatures);
        write(new File(wideSignatures, "one.hdb"), "00000000000000000000000000000000:1:Fixture\n");
        for (int i = 0; i < SignatureDatabase.MAX_DIRECTORY_ENTRIES; i++) {
            if (!new File(wideSignatures, "ignored-" + i + ".txt").createNewFile()) {
                throw new IOException("could not create wide-directory fixture");
            }
        }
        SignatureDatabase wideDb = SignatureDatabase.load(wideSignatures);
        c.that("ignored names count toward signature directory limit and fail closed",
                wideDb.hashCount() == 0 && !wideDb.problems().isEmpty(),
                "hashes=" + wideDb.hashCount() + " problems=" + wideDb.problems());
        String incompleteStamp = SignatureDatabase.stamp(wideSignatures);
        c.that("incomplete signature listings cannot reuse a cached stamp",
                !incompleteStamp.equals(SignatureDatabase.stamp(wideSignatures))
                        && !incompleteStamp.equals(completeStamp), incompleteStamp);

        String property = "mtsafety.forceDirectoryStreamUnsupported";
        String previous = System.getProperty(property);
        try {
            System.setProperty(property, "true");
            Discovery unsupportedDiscovery = new Discovery();
            List<Discovery.Candidate> unsupported = unsupportedDiscovery.find(Arrays.asList(packages));
            c.that("unsupported streaming makes discovery explicitly incomplete",
                    unsupported.isEmpty() && unsupportedDiscovery.incomplete()
                            && !unsupportedDiscovery.problems().isEmpty(),
                    unsupportedDiscovery.problems().toString());
            FileScanner.Result files = new FileScanner(SignatureDatabase.empty()).scan(
                    Arrays.asList(packages), null, ScanBudget.unlimited());
            c.that("unsupported streaming makes file scanning incomplete",
                    files.filesScanned == 0 && files.truncated() && !files.problems.isEmpty(),
                    files.problems.toString());
            SignatureDatabase db = SignatureDatabase.load(signatures);
            c.that("unsupported streaming reports unavailable signature definitions",
                    db.hashCount() == 0 && !db.problems().isEmpty(), db.problems().toString());
            String firstUnsupportedStamp = SignatureDatabase.stamp(signatures);
            c.that("unsupported streaming invalidates complete and incomplete signature caches",
                    !firstUnsupportedStamp.equals(completeStamp)
                            && !firstUnsupportedStamp.equals(SignatureDatabase.stamp(signatures)),
                    firstUnsupportedStamp);
        } finally {
            if (previous == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, previous);
            }
        }
    }

    private static void requireDirectory(File directory) throws IOException {
        if (!directory.mkdirs()) {
            throw new IOException("could not create fixture directory " + directory);
        }
    }

    private static void write(File file, String value) throws IOException {
        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(value.getBytes("UTF-8"));
        } finally {
            out.close();
        }
    }
}
