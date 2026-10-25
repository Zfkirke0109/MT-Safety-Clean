package mt.safety.scanner.core;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Iterator;

/**
 * Enumerates directory entries without materialising an unbounded {@code File[]} first.
 *
 * <p>Runtime support for {@code java.nio.file} begins at Android API 26. This plugin supports API 24,
 * so callers fail closed when streaming is unavailable. File subclasses use the same path-based
 * streaming implementation; their {@code listFiles()} methods are never invoked.
 */
public final class DirectoryListing {

    /** Test seam for deterministic unsupported-runtime coverage checks. */
    private static final String FORCE_UNSUPPORTED_PROPERTY = "mtsafety.forceDirectoryStreamUnsupported";
    private static final String UNSUPPORTED_REASON = "bounded directory streaming requires"
            + " java.nio.file support (Android API 26+)";
    private static final Opener BRIDGE = Bridge.load();

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
                && (opener != BRIDGE || !Boolean.getBoolean(FORCE_UNSUPPORTED_PROPERTY));
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
