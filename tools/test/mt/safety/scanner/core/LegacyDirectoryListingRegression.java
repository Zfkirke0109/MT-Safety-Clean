package mt.safety.scanner.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Fixed in-memory OS-process fixtures; never executes fixture or scanned content. */
public final class LegacyDirectoryListingRegression {
    private LegacyDirectoryListingRegression() { }

    public static void main(String[] args) throws Exception {
        final int[] failures = {0};
        run(new DirectoryListingRegression.Checks() {
            @Override public void that(String description, boolean condition, String context) {
                System.out.println((condition ? "PASS " : "FAIL ") + description + " :: " + context);
                if (!condition) failures[0]++;
            }
        }, new File(System.getProperty("java.io.tmpdir")));
        if (failures[0] != 0) throw new AssertionError(failures[0] + " legacy listing failures");
    }

    public static void run(DirectoryListingRegression.Checks checks, File root) {
        try {
            Method factory;
            try {
                factory = DirectoryListing.class.getDeclaredMethod("legacyCursor", File.class,
                        Process.class, long.class, int.class);
            } catch (NoSuchMethodException e) {
                checks.that("API24/25 bounded process cursor exists", false, "missing legacyCursor");
                return;
            }
            final File directory = new File(root, "legacy names ; $(not-code)");
            ProcessBuilder command = DirectoryListing.legacyProcessBuilder(directory);
            checks.that("legacy invocation has fixed OS argv, literal working directory and clean environment",
                    command.command().equals(Arrays.asList("/system/bin/toybox", "find", ".",
                            "-mindepth", "1", "-maxdepth", "1", "-print0"))
                            && directory.equals(command.directory()) && command.environment().size() == 1
                            && "C".equals(command.environment().get("LC_ALL"))
                            && !command.redirectErrorStream(), command.command().toString());
            FakeProcess valid = process("./plain\0./with space\0./line\nbreak\0./é\0./-exec\0");
            int count = 0;
            try (DirectoryListing.Cursor cursor = cursor(factory, directory, valid, 1000000000L, 20)) {
                File child;
                while ((child = cursor.next()) != null) {
                    if (!directory.equals(child.getParentFile())) throw new AssertionError("wrong parent");
                    count++;
                }
            }
            checks.that("legacy NUL records preserve spaces, Unicode, newlines and option-like names",
                    count == 5 && valid.destroyed && valid.closed(), "count=" + count);
            final FakeProcess slowVisitorProcess = process("./first\0./second\0");
            final DirectoryListing.Cursor slowVisitorCursor = cursor(factory, directory,
                    slowVisitorProcess, 50000000L, 20);
            final int[] slowVisitorCount = {0};
            boolean slowVisitorComplete = false;
            try {
                DirectoryListing.forEachChild(directory, new DirectoryListing.Visitor() {
                    @Override public void visit(File child) throws IOException {
                        if (++slowVisitorCount[0] == 1) {
                            try { Thread.sleep(100L); }
                            catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                throw new IOException("slow visitor interrupted", e);
                            }
                        }
                    }
                }, new DirectoryListing.Opener() {
                    @Override public DirectoryListing.Cursor open(File ignored) { return slowVisitorCursor; }
                });
                slowVisitorComplete = true;
            } catch (IOException e) { /* The assertion records the original lifetime-budget defect. */ }
            checks.that("visitor work does not consume the legacy enumeration time budget",
                    slowVisitorComplete && slowVisitorCount[0] == 2 && slowVisitorProcess.destroyed
                            && slowVisitorProcess.closed(), "complete=" + slowVisitorComplete
                            + ", visited=" + slowVisitorCount[0]);
            for (String bad : new String[]{"./../escape\0", "../escape\0", "./sub/child\0", "./\0",
                    "./.\0", "./..\0", "./unterminated", "\0", "/absolute\0"}) {
                rejected(checks, factory, directory, process(bad), "invalid child shape", 1000000000L, 20);
            }
            byte[] malformed = {'.', '/', (byte) 0xc3, (byte) 0x28, 0};
            rejected(checks, factory, directory, new FakeProcess(malformed, new byte[0], false, 0),
                    "malformed UTF-8", 1000000000L, 20);
            byte[] longName = new byte[259];
            Arrays.fill(longName, (byte) 'x'); longName[0] = '.'; longName[1] = '/'; longName[258] = 0;
            rejected(checks, factory, directory, new FakeProcess(longName, new byte[0], false, 0),
                    "oversize record", 1000000000L, 20);
            rejected(checks, factory, directory, process("./a\0./b\0"), "entry cap", 1000000000L, 1);
            rejected(checks, factory, directory, new FakeProcess(new byte[0], new byte[5000], false, 1),
                    "bounded stderr overflow", 1000000000L, 20);
            rejected(checks, factory, directory, new FakeProcess(new byte[0], new byte[]{'e'}, false, 0),
                    "stderr despite zero exit", 1000000000L, 20);
            rejected(checks, factory, directory, new FakeProcess(new byte[0], new byte[0], false, 1),
                    "nonzero exit", 1000000000L, 20);
            rejected(checks, factory, directory, new FakeProcess(new byte[0], new byte[0], true, 0),
                    "stalled process deadline", 20000000L, 20);
            FakeProcess gradual = process("./a\0./b\0./c\0./d\0./e\0./f\0./g\0./h\0"
                    + "./i\0./j\0./k\0./l\0./m\0./n\0./o\0./p\0");
            gradual.stdout.readDelayMillis = 2L;
            rejected(checks, factory, directory, gradual, "cumulative enumeration deadline",
                    50000000L, 20);
            FakeProcess stopped = new FakeProcess("./first\0".getBytes(StandardCharsets.UTF_8),
                    new byte[0], true, 0);
            final IOException stop = new IOException("visitor stop");
            final DirectoryListing.Cursor fixture = cursor(factory, directory, stopped, 1000000000L, 20);
            boolean propagated = false;
            try {
                DirectoryListing.forEachChild(directory, new DirectoryListing.Visitor() {
                    @Override public void visit(File child) throws IOException { throw stop; }
                }, new DirectoryListing.Opener() {
                    @Override public DirectoryListing.Cursor open(File ignored) { return fixture; }
                });
            } catch (IOException e) { propagated = e == stop; }
            checks.that("early visitor stop preserves its exception and closes the OS process",
                    propagated && stopped.destroyed && stopped.closed(), "propagated=" + propagated);
            FakeProcess interrupted = new FakeProcess(new byte[0], new byte[0], true, 0);
            boolean interruption = false;
            try (DirectoryListing.Cursor c = cursor(factory, directory, interrupted, 1000000000L, 20)) {
                Thread.currentThread().interrupt();
                try { c.next(); } catch (IOException e) { interruption = Thread.currentThread().isInterrupted(); }
            } finally { Thread.interrupted(); }
            checks.that("interruption aborts legacy listing and retains interrupt status",
                    interruption && interrupted.destroyed && interrupted.closed(), "interrupted=" + interruption);
            String force = "mtsafety.forceDirectoryStreamUnsupported";
            String previous = System.getProperty(force);
            System.setProperty(force, "true");
            try {
                checks.that("complete-disable seam refuses every default backend",
                        !DirectoryListing.supportedFor(directory), DirectoryListing.unsupportedReason());
            } finally { restore(force, previous); }
            String legacy = "mtsafety.forceLegacyDirectoryStream";
            previous = System.getProperty(legacy);
            System.setProperty(legacy, "true");
            try {
                boolean android = "Dalvik".equals(System.getProperty("java.vm.name"));
                checks.that("forced legacy selection does not treat desktop as Android",
                        android || !DirectoryListing.supportedFor(directory), "android=" + android);
            } finally { restore(legacy, previous); }
        } catch (Exception e) { throw new IllegalStateException("legacy listing regression failed", e); }
    }

    private static void restore(String name, String value) {
        if (value == null) System.clearProperty(name); else System.setProperty(name, value);
    }
    private static FakeProcess process(String text) {
        return new FakeProcess(text.getBytes(StandardCharsets.UTF_8), new byte[0], false, 0);
    }
    private static DirectoryListing.Cursor cursor(Method factory, File root, Process process,
                                                   long nanos, int cap) throws Exception {
        try { return (DirectoryListing.Cursor) factory.invoke(null, root, process, nanos, cap); }
        catch (InvocationTargetException e) { throw (Exception) e.getCause(); }
    }
    private static void rejected(DirectoryListingRegression.Checks checks, Method factory, File root,
                                  FakeProcess process, String why, long nanos, int cap) throws Exception {
        boolean rejected = false;
        long start = System.nanoTime();
        try (DirectoryListing.Cursor cursor = cursor(factory, root, process, nanos, cap)) {
            while (cursor.next() != null) { /* bounded by the cursor */ }
        } catch (IOException e) { rejected = true; }
        long millis = (System.nanoTime() - start) / 1000000L;
        checks.that("legacy listing rejects " + why + " and cleans up",
                rejected && process.destroyed && process.closed() && millis < 1000,
                "rejected=" + rejected + ", elapsedMs=" + millis);
    }

    private static final class TrackedInput extends ByteArrayInputStream {
        boolean closed;
        long readDelayMillis;
        TrackedInput(byte[] bytes) { super(bytes); }
        @Override public synchronized int read() {
            if (readDelayMillis > 0) {
                try { Thread.sleep(readDelayMillis); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            return super.read();
        }
        @Override public void close() { closed = true; }
    }
    private static final class FakeProcess extends Process {
        final TrackedInput stdout;
        final TrackedInput stderr;
        final ByteArrayOutputStream stdin = new ByteArrayOutputStream();
        final boolean running;
        final int exit;
        boolean destroyed;
        boolean inputClosed;
        FakeProcess(byte[] out, byte[] err, boolean running, int exit) {
            stdout = new TrackedInput(out); stderr = new TrackedInput(err);
            this.running = running; this.exit = exit;
        }
        boolean closed() { return stdout.closed && stderr.closed && inputClosed; }
        @Override public OutputStream getOutputStream() {
            return new OutputStream() {
                @Override public void write(int b) { stdin.write(b); }
                @Override public void close() { inputClosed = true; }
            };
        }
        @Override public InputStream getInputStream() { return stdout; }
        @Override public InputStream getErrorStream() { return stderr; }
        @Override public int waitFor() { return exit; }
        @Override public int exitValue() {
            if (running && !destroyed) throw new IllegalThreadStateException("running");
            return exit;
        }
        @Override public void destroy() { destroyed = true; }
    }
}
