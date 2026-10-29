package mt.safety.scanner.core;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Streaming fault fixtures live in test sources; production has no mutable global provider. */
public final class DirectoryListingRegression {
    public interface Checks {
        void that(String description, boolean condition, String context);
    }

    private DirectoryListingRegression() {
    }

    public static void main(String[] args) throws IOException {
        File root = new File(System.getProperty("java.io.tmpdir"),
                "mtsafety-streaming-" + System.nanoTime());
        if (!root.mkdirs()) {
            throw new IOException("could not create " + root);
        }
        final int[] failures = {0};
        run(new Checks() {
            @Override
            public void that(String description, boolean condition, String context) {
                System.out.println((condition ? "PASS " : "FAIL ") + description + " :: " + context);
                if (!condition) {
                    failures[0]++;
                }
            }
        }, root);
        if (failures[0] > 0) {
            throw new AssertionError(failures[0] + " streaming regressions failed");
        }
    }

    public static ScanReport scanWithListingFailure(File path, final File failingDirectory, ScanBudget budget) {
        return scan(path, budget, new DirectoryListing.Opener() {
            @Override
            public DirectoryListing.Cursor open(File directory) throws IOException {
                if (directory.getPath().equals(failingDirectory.getPath())) {
                    throw new IOException("injected streaming listing failure");
                }
                return DirectoryListing.defaultOpener().open(directory);
            }
        });
    }

    public static ScanReport scanWithExtraChild(File path, final File extraChild, ScanBudget budget) {
        return scan(path, budget, new DirectoryListing.Opener() {
            @Override
            public DirectoryListing.Cursor open(final File directory) throws IOException {
                final DirectoryListing.Cursor original = DirectoryListing.defaultOpener().open(directory);
                return new DirectoryListing.Cursor() {
                    private boolean emitted;
                    @Override
                    public File next() throws IOException {
                        File child = original.next();
                        if (child != null) {
                            return child;
                        }
                        if (!emitted && directory.equals(extraChild.getParentFile())) {
                            emitted = true;
                            return extraChild;
                        }
                        return null;
                    }
                    @Override
                    public void close() throws IOException {
                        original.close();
                    }
                };
            }
        });
    }

    private static ScanReport scan(File path, ScanBudget budget, DirectoryListing.Opener opener) {
        return new PluginScanner(IocDatabase.empty(), null, opener).scan(path, budget);
    }

    public static void run(Checks checks, File fixtureRoot) {
        try {
            final File root = new File(fixtureRoot, "streaming-regressions");
            if (!root.mkdirs()) {
                throw new IOException("could not create " + root);
            }
            subclassUsesStream(checks, root);
            rejectedEntries(checks, root, false);
            rejectedEntries(checks, root, true);
            streamFailure(checks, root, false);
            streamFailure(checks, root, true);
            entryFailure(checks, root);
            isolatedProviders(checks, root);
        } catch (IOException e) {
            throw new IllegalStateException("could not create streaming regression fixture", e);
        }
    }

    private static void subclassUsesStream(Checks checks, File root) throws IOException {
        File directory = new File(root, "subclass");
        if (!directory.mkdir() || !new File(directory, "child").createNewFile()) {
            throw new IOException("could not create subclass fixture");
        }
        final int[] arrayCalls = {0};
        File subclass = new File(directory.getPath()) {
            private static final long serialVersionUID = 1L;
            @Override
            public File[] listFiles() {
                arrayCalls[0]++;
                throw new AssertionError("directory enumeration must not allocate a File array");
            }
        };
        final int[] entries = {0};
        DirectoryListing.forEachChild(subclass, new DirectoryListing.Visitor() {
            @Override
            public void visit(File child) {
                entries[0]++;
            }
        });
        checks.that("File subclasses use the bounded runtime stream without listFiles",
                arrayCalls[0] == 0 && entries[0] == 1,
                "arrayCalls=" + arrayCalls[0] + ", streamedEntries=" + entries[0]);
    }

    private static void rejectedEntries(Checks checks, File root, boolean installed) throws IOException {
        final File directory = new File(root, installed ? "rejected-siblings" : "rejected-directory");
        if (!directory.mkdir()) {
            throw new IOException("could not create rejected-entry fixture");
        }
        if (installed) {
            try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(
                    new File(directory, PluginPackage.INSTALLED_ARCHIVE)))) {
                zip.putNextEntry(new ZipEntry("manifest.json"));
                zip.write(manifest().getBytes("UTF-8"));
                zip.closeEntry();
            }
        }
        final int maximum = installed ? 400 : 8000;
        final int[] visited = {0};
        final int[] emitted = {0};
        final int[] closed = {0};
        DirectoryListing.Opener opener = new DirectoryListing.Opener() {
            @Override
            public DirectoryListing.Cursor open(File folder) {
                return new DirectoryListing.Cursor() {
                    @Override
                    public File next() {
                        if (emitted[0] >= maximum + 100) {
                            return null;
                        }
                        final int index = emitted[0]++;
                        return new File(directory, "unresolvable-" + index) {
                            private static final long serialVersionUID = 1L;
                            @Override
                            public String getCanonicalPath() throws IOException {
                                visited[0]++;
                                throw new IOException("injected canonicalization failure");
                            }
                        };
                    }
                    @Override
                    public void close() {
                        closed[0]++;
                    }
                };
            }
        };
        ScanReport report = scan(directory, ScanBudget.unlimited(), opener);
        checks.that((installed ? "rejected installed siblings" : "rejected directory entries")
                        + " consume the entry cap and close their stream",
                visited[0] == maximum && emitted[0] <= maximum + 1 && closed[0] == 1
                        && report.coverage() == Coverage.PARTIAL && report.hasRule("SCN001")
                        && report.contentHash.length() == 0 && !report.destructiveActionIdentityComplete(),
                "canonicalCalls=" + visited[0] + ", emitted=" + emitted[0] + ", closed=" + closed[0]
                        + ", coverage=" + report.coverage());
    }

    private static void streamFailure(Checks checks, File root, final boolean closeFailure) throws IOException {
        final File directory = new File(root, closeFailure ? "close-failure" : "iterator-failure");
        if (!directory.mkdir()) {
            throw new IOException("could not create streaming failure fixture");
        }
        write(new File(directory, "manifest.json"), manifest());
        write(new File(directory, "A.java"),
                "package demo; public class A { void run() { Runtime.getRuntime(); } }");
        final int[] closed = {0};
        ScanReport report = scan(directory, ScanBudget.unlimited(), new DirectoryListing.Opener() {
            @Override
            public DirectoryListing.Cursor open(File folder) {
                return new DirectoryListing.Cursor() {
                    private int index;
                    @Override
                    public File next() {
                        if (index++ == 0) {
                            return new File(directory, "manifest.json");
                        }
                        if (index == 2) {
                            return new File(directory, "A.java");
                        }
                        if (!closeFailure) {
                            throw new IllegalStateException("injected unchecked iterator failure");
                        }
                        return null;
                    }
                    @Override
                    public void close() throws IOException {
                        closed[0]++;
                        if (closeFailure) {
                            throw new IOException("injected stream close failure");
                        }
                    }
                };
            }
        });
        checks.that((closeFailure ? "stream close failure" : "unchecked iterator failure")
                        + " retains observed content and findings with partial coverage",
                report.coverage() == Coverage.PARTIAL && report.hasRule("SCN001")
                        && report.hasRule("EXE001") && report.contentHash.length() == 0
                        && !report.destructiveActionIdentityComplete() && closed[0] == 1,
                "coverage=" + report.coverage() + ", retainedEXE001=" + report.hasRule("EXE001")
                        + ", closed=" + closed[0]);
    }

    private static void entryFailure(Checks checks, File root) throws IOException {
        final File directory = new File(root, "entry-runtime-failure");
        if (!directory.mkdir()) {
            throw new IOException("could not create entry failure fixture");
        }
        write(new File(directory, "manifest.json"), manifest());
        write(new File(directory, "A.java"),
                "package demo; public class A { void run() { Runtime.getRuntime(); } }");
        File broken = new File(directory, "inaccessible") {
            private static final long serialVersionUID = 1L;
            @Override
            public String getCanonicalPath() {
                throw new SecurityException("injected entry access failure");
            }
        };
        ScanReport report = scanWithExtraChild(directory, broken, ScanBudget.unlimited());
        checks.that("unchecked entry access failure retains findings and marks the directory partial",
                report.coverage() == Coverage.PARTIAL && report.hasRule("SCN001")
                        && report.hasRule("EXE001") && report.contentHash.length() == 0
                        && !report.destructiveActionIdentityComplete(),
                "coverage=" + report.coverage() + ", retainedEXE001=" + report.hasRule("EXE001"));
    }

    private static void isolatedProviders(Checks checks, File root) throws IOException {
        File directory = new File(root, "isolated-provider");
        if (!directory.mkdir()) {
            throw new IOException("could not create provider isolation fixture");
        }
        write(new File(directory, "manifest.json"), manifest());
        ScanReport injected = scanWithListingFailure(directory, directory, ScanBudget.unlimited());
        ScanReport normal = new PluginScanner(IocDatabase.empty()).scan(directory, ScanBudget.unlimited());
        checks.that("an injected listing failure does not alter another scanner's runtime provider",
                injected.coverage() == Coverage.PARTIAL && normal.coverage() == Coverage.COMPLETE
                        && normal.contentHash.length() > 0,
                "injected=" + injected.coverage() + ", normal=" + normal.coverage());
    }

    private static String manifest() {
        return "{\"pluginID\":\"demo.streaming\",\"name\":\"Streaming\",\"versionCode\":1,"
                + "\"versionName\":\"1\",\"mainClass\":\"demo.A\"}";
    }

    private static void write(File file, String text) throws IOException {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(text.getBytes("UTF-8"));
        }
    }
}
