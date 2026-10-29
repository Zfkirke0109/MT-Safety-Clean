package mt.safety.scanner.core;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Iterator;

/**
 * Enumerates directory entries without materialising an unbounded {@code File[]} first.
 *
 * <p>Runtime support for {@code java.nio.file} begins at Android API 26. This plugin supports API 24,
 * with a fixed system toybox find command as its API 24/25 fallback. Both implementations stream
 * children; File subclasses never invoke {@code listFiles()}. Unavailable OS capabilities fail closed.
 */
public final class DirectoryListing {

    /** Test seam for deterministic unsupported-runtime coverage checks. */
    private static final String FORCE_UNSUPPORTED_PROPERTY = "mtsafety.forceDirectoryStreamUnsupported";
    private static final String FORCE_LEGACY_PROPERTY = "mtsafety.forceLegacyDirectoryStream";
    private static final String UNSUPPORTED_REASON = "bounded directory streaming is unavailable or disabled"
            + " (requires java.nio.file or Android system toybox find)";
    private static final Opener NIO = Bridge.load();
    private static final Opener LEGACY = new Legacy();
    private static final Opener BRIDGE = new RuntimeOpener();

    public interface Visitor {
        void visit(File child) throws IOException;
    }

    /** Instance-scoped enumeration dependency; package-private so production callers use the bridge. */
    interface Opener {
        Cursor open(File directory) throws IOException;
    }

    interface Cursor extends Closeable {
        /** The next child, or null at the end. */
        File next() throws IOException;
    }

    private DirectoryListing() {
    }

    static Opener defaultOpener() {
        return BRIDGE;
    }

    /** True when bounded listing is available for this directory object. */
    public static boolean supportedFor(File directory) {
        return supportedFor(directory, BRIDGE);
    }

    static boolean supportedFor(File directory, Opener opener) {
        return directory != null && opener != null
                && (opener != BRIDGE || backend() != null);
    }

    public static String unsupportedReason() {
        return UNSUPPORTED_REASON;
    }

    public static void forEachChild(File directory, Visitor visitor) throws IOException {
        forEachChild(directory, visitor, BRIDGE);
    }

    static void forEachChild(File directory, Visitor visitor, Opener opener) throws IOException {
        if (directory == null) {
            throw new IOException("directory is null");
        }
        if (visitor == null) {
            throw new IOException("visitor is null");
        }
        if (!supportedFor(directory, opener)) {
            throw new IOException(UNSUPPORTED_REASON);
        }
        // Provider/iterator failures are I/O failures. Visitor exceptions are left intact: callers use
        // their own sentinel to stop at a count/depth limit without walking the remaining entries.
        try (Cursor cursor = open(opener, directory)) {
            File child;
            while ((child = next(cursor, directory)) != null) {
                visitor.visit(child);
            }
        }
    }

    private static Cursor open(Opener opener, File directory) throws IOException {
        try {
            final Cursor cursor = opener.open(directory);
            if (cursor == null) {
                throw new IOException("could not list " + directory.getPath());
            }
            return new Cursor() {
                @Override
                public File next() throws IOException {
                    return cursor.next();
                }

                @Override
                public void close() throws IOException {
                    try {
                        cursor.close();
                    } catch (RuntimeException e) {
                        throw asIo("could not close listing " + directory.getPath(), e);
                    }
                }
            };
        } catch (RuntimeException e) {
            throw asIo("could not list " + directory.getPath(), e);
        }
    }

    private static File next(Cursor cursor, File directory) throws IOException {
        try {
            return cursor.next();
        } catch (RuntimeException e) {
            throw asIo("could not list " + directory.getPath(), e);
        }
    }

    private static IOException asIo(String prefix, Throwable cause) {
        if (cause instanceof IOException) {
            return (IOException) cause;
        }
        return new IOException(prefix + ": " + cause, cause);
    }

    private static Opener backend() {
        if (Boolean.getBoolean(FORCE_UNSUPPORTED_PROPERTY)) return null;
        if (!Boolean.getBoolean(FORCE_LEGACY_PROPERTY) && NIO != null) return NIO;
        return Legacy.available() ? LEGACY : null;
    }

    private static final class RuntimeOpener implements Opener {
        @Override public Cursor open(File directory) throws IOException {
            Opener selected = backend();
            if (selected == null) throw new IOException(UNSUPPORTED_REASON);
            return selected.open(directory);
        }
    }

    private static final class Legacy implements Opener {
        private static final String TOOL = "/system/bin/toybox";

        static boolean available() {
            // A desktop JVM must never opt into an Android implementation by property alone.
            if (!"Dalvik".equals(System.getProperty("java.vm.name"))) return false;
            try {
                // The host enforces min API24. Os is a public core-runtime Android API, whereas
                // Build.VERSION initialization needs framework natives absent in plain dalvikvm.
                Class.forName("android.system.Os");
                File tool = new File(TOOL);
                return tool.isFile() && tool.canExecute() && TOOL.equals(tool.getCanonicalPath());
            } catch (ReflectiveOperationException e) {
                return false;
            } catch (LinkageError e) {
                return false;
            } catch (SecurityException e) {
                return false;
            } catch (IOException e) {
                return false;
            }
        }

        @Override public Cursor open(File directory) throws IOException {
            // No shell, PATH lookup, user supplied expression, executable or recursive traversal.
            // AOSP Android 7.0/7.1 find do_find returns no DIRTREE_SAVE; dirtree frees each child.
            return legacyCursor(directory, legacyProcessBuilder(directory).start(), 2000000000L, 8192);
        }
    }

    /** Inspectable fixed invocation; no caller-controlled argument can become a find expression. */
    static ProcessBuilder legacyProcessBuilder(File directory) {
        ProcessBuilder builder = new ProcessBuilder(Legacy.TOOL, "find", ".", "-mindepth", "1",
                "-maxdepth", "1", "-print0");
        builder.directory(directory);
        // No inherited dynamic-loader configuration or tool-specific execution environment.
        builder.environment().clear();
        builder.environment().put("LC_ALL", "C");
        return builder;
    }

    /** Instance-scoped fixture seam: the caller supplies an already started, trusted OS process. */
    static Cursor legacyCursor(File directory, Process process, long timeoutNanos, int entryCap)
            throws IOException {
        return new LegacyCursor(directory, process, timeoutNanos, entryCap);
    }

    private static final class LegacyCursor implements Cursor {
        private final File directory;
        private final Process process;
        private final InputStream stdout;
        private final InputStream stderr;
        private long enumerationNanos;
        private long nextStarted;
        private final long timeoutNanos;
        private final int entryCap;
        // Linux/Android NAME_MAX is 255 bytes, plus the fixed "./" prefix.
        private final byte[] name = new byte[257];
        private final byte[] diagnostics = new byte[4096];
        private int diagnosticBytes;
        private int entries;
        private boolean closed;
        private boolean ended;

        LegacyCursor(File directory, Process process, long timeoutNanos, int entryCap)
                throws IOException {
            this.directory = directory;
            this.process = process;
            this.timeoutNanos = timeoutNanos;
            this.entryCap = entryCap;
            stdout = process.getInputStream();
            stderr = process.getErrorStream();
            try {
                process.getOutputStream().close();
                if (timeoutNanos <= 0 || entryCap < 1) throw new IOException("invalid listing limit");
            } catch (IOException e) {
                close();
                throw e;
            }
        }

        private void check() throws IOException {
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedIOException("directory listing interrupted");
            }
            // Only charge time inside next(): visitors may scan a file or recursively enumerate
            // another directory before asking for the next sibling. Keep one cumulative budget
            // across reads so a process cannot evade the bound by emitting an occasional record.
            if (System.nanoTime() - nextStarted >= timeoutNanos - enumerationNanos) {
                throw new IOException("directory listing time limit exceeded");
            }
        }

        private void drainDiagnostics() throws IOException {
            // Drain only a fixed number of bytes per call; a noisy child cannot monopolise next().
            int count = Math.min(stderr.available(), diagnostics.length - diagnosticBytes);
            if (count > 0) {
                int read = stderr.read(diagnostics, diagnosticBytes, count);
                if (read > 0) diagnosticBytes += read;
            }
            if (diagnosticBytes == diagnostics.length) {
                throw new IOException("directory listing diagnostic limit exceeded");
            }
        }

        private int readByte() throws IOException {
            while (true) {
                check();
                drainDiagnostics();
                if (stdout.available() > 0) return stdout.read();
                try {
                    int exit = process.exitValue();
                    // The fixed find command cannot leave a descendant holding the pipe open.
                    int value = stdout.read();
                    if (value >= 0) return value;
                    drainDiagnostics();
                    if (exit != 0 || diagnosticBytes != 0) {
                        throw new IOException("Android system toybox find could not complete listing"
                                + " (exit " + exit + ", diagnostic bytes " + diagnosticBytes + ")");
                    }
                    return -1;
                } catch (IllegalThreadStateException running) {
                    try {
                        Thread.sleep(2L);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new InterruptedIOException("directory listing interrupted");
                    }
                }
            }
        }

        @Override public File next() throws IOException {
            if (ended) return null;
            if (closed) throw new IOException("directory listing is closed");
            nextStarted = System.nanoTime();
            try {
                int length = 0;
                while (true) {
                    int b = readByte();
                    if (b == -1) {
                        if (length != 0) throw new IOException("truncated directory child record");
                        ended = true;
                        return null;
                    }
                    if (b == 0) break;
                    if (length == name.length) throw new IOException("directory child name limit exceeded");
                    name[length++] = (byte) b;
                }
                if (++entries > entryCap) throw new IOException("directory listing entry limit exceeded");
                final String record;
                try {
                    record = StandardCharsets.UTF_8.newDecoder()
                            .onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(name, 0, length)).toString();
                } catch (CharacterCodingException e) {
                    throw new IOException("directory child name is not valid UTF-8", e);
                }
                if (!record.startsWith("./") || record.length() <= 2
                        || record.indexOf('/', 2) >= 0 || record.equals("./.") || record.equals("./..")) {
                    throw new IOException("invalid directory child record");
                }
                return new File(directory, record.substring(2));
            } catch (IOException e) {
                close();
                throw e;
            } finally {
                enumerationNanos += System.nanoTime() - nextStarted;
            }
        }

        @Override public void close() {
            if (closed) return;
            closed = true;
            // Never wait for a child on cancellation. Trusted toybox has default SIGTERM handling.
            try { process.destroy(); } catch (RuntimeException ignored) { /* still close all streams */ }
            try { stdout.close(); } catch (IOException ignored) { /* already failing/closing */ }
            try { stderr.close(); } catch (IOException ignored) { /* already failing/closing */ }
            try { process.getOutputStream().close(); } catch (IOException ignored) { /* closed at open */ }
        }
    }

    private static final class Bridge implements Opener {
        private final Method pathsGet;
        private final Method filesNewDirectoryStream;
        private final Method pathToFile;

        private Bridge(Method pathsGet, Method filesNewDirectoryStream, Method pathToFile) {
            this.pathsGet = pathsGet;
            this.filesNewDirectoryStream = filesNewDirectoryStream;
            this.pathToFile = pathToFile;
        }

        static Opener load() {
            try {
                Class<?> paths = Class.forName("java.nio.file.Paths");
                Class<?> path = Class.forName("java.nio.file.Path");
                Class<?> files = Class.forName("java.nio.file.Files");
                Method get = paths.getMethod("get", String.class, String[].class);
                Method stream = files.getMethod("newDirectoryStream", path);
                Method toFile = path.getMethod("toFile");
                return new Bridge(get, stream, toFile);
            } catch (ReflectiveOperationException e) {
                return null;
            } catch (LinkageError e) {
                return null;
            } catch (SecurityException e) {
                return null;
            }
        }

        @Override
        public Cursor open(File directory) throws IOException {
            final Object stream;
            try {
                Object path = pathsGet.invoke(null, directory.getPath(), new String[0]);
                stream = filesNewDirectoryStream.invoke(null, path);
            } catch (InvocationTargetException e) {
                throw asIo("could not list " + directory.getPath(), e.getTargetException());
            } catch (IllegalAccessException e) {
                throw new IOException("could not list " + directory.getPath(), e);
            }
            if (!(stream instanceof Closeable)) {
                throw new IOException("directory stream cannot be closed");
            }
            final Closeable closeable = (Closeable) stream;
            final Iterator<?> iterator;
            try {
                iterator = ((Iterable<?>) stream).iterator();
            } catch (RuntimeException e) {
                try {
                    closeable.close();
                } catch (IOException closeFailure) {
                    e.addSuppressed(closeFailure);
                }
                throw asIo("could not list " + directory.getPath(), e);
            }
            return new Cursor() {
                @Override
                public File next() throws IOException {
                    if (!iterator.hasNext()) {
                        return null;
                    }
                    Object childPath = iterator.next();
                    try {
                        return (File) pathToFile.invoke(childPath);
                    } catch (InvocationTargetException e) {
                        throw asIo("could not list " + directory.getPath(), e.getTargetException());
                    } catch (IllegalAccessException e) {
                        throw new IOException("could not list " + directory.getPath(), e);
                    }
                }

                @Override
                public void close() throws IOException {
                    closeable.close();
                }
            };
        }
    }
}
