package mt.safety.scanner.core;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Iterator;

/**
 * Enumerates directory entries without materialising an unbounded {@code File[]} first.
 *
 * <p>Runtime support for {@code java.nio.file} begins at Android API 26. This plugin supports API 24,
 * so callers have to fail closed when streaming is unavailable rather than falling back to
 * {@code File.listFiles()} on ordinary runtime paths.
 */
public final class DirectoryListing {

    /** Test seam for deterministic unsupported-runtime coverage checks. */
    private static final String FORCE_UNSUPPORTED_PROPERTY = "mtsafety.forceDirectoryStreamUnsupported";
    private static final String UNSUPPORTED_REASON = "bounded directory streaming requires"
            + " java.nio.file support (Android API 26+)";
    private static final Bridge BRIDGE = Bridge.load();

    public interface Visitor {
        void visit(File child) throws IOException;
    }

    private DirectoryListing() {
    }

    /**
     * True when bounded listing is available for this directory object.
     *
     * <p>File subclasses are allowed through a small compatibility path so tests can inject
     * deterministic directory-listing failures.
     */
    public static boolean supportedFor(File directory) {
        if (directory != null && directory.getClass() != File.class) {
            return true;
        }
        return !Boolean.getBoolean(FORCE_UNSUPPORTED_PROPERTY) && BRIDGE != null;
    }

    public static String unsupportedReason() {
        return UNSUPPORTED_REASON;
    }

    public static void forEachChild(File directory, Visitor visitor) throws IOException {
        if (directory == null) {
            throw new IOException("directory is null");
        }
        if (visitor == null) {
            throw new IOException("visitor is null");
        }
        if (directory.getClass() != File.class) {
            File[] children = directory.listFiles();
            if (children == null) {
                throw new IOException("could not list " + directory.getPath());
            }
            for (int i = 0; i < children.length; i++) {
                visitor.visit(children[i]);
            }
            return;
        }
        if (!supportedFor(directory)) {
            throw new IOException(UNSUPPORTED_REASON);
        }
        BRIDGE.forEachChild(directory, visitor);
    }

    private static final class Bridge {
        private final Method pathsGet;
        private final Method filesNewDirectoryStream;
        private final Method pathToFile;

        private Bridge(Method pathsGet, Method filesNewDirectoryStream, Method pathToFile) {
            this.pathsGet = pathsGet;
            this.filesNewDirectoryStream = filesNewDirectoryStream;
            this.pathToFile = pathToFile;
        }

        static Bridge load() {
            try {
                Class<?> paths = Class.forName("java.nio.file.Paths");
                Class<?> path = Class.forName("java.nio.file.Path");
                Class<?> files = Class.forName("java.nio.file.Files");
                Method get = paths.getMethod("get", String.class, String[].class);
                Method stream = files.getMethod("newDirectoryStream", path);
                Method toFile = path.getMethod("toFile");
                return new Bridge(get, stream, toFile);
            } catch (Throwable unavailable) {
                return null;
            }
        }

        void forEachChild(File directory, Visitor visitor) throws IOException {
            Object stream = null;
            try {
                Object path = pathsGet.invoke(null, directory.getPath(), new String[0]);
                stream = filesNewDirectoryStream.invoke(null, path);
                Iterator<?> iterator = ((Iterable<?>) stream).iterator();
                while (iterator.hasNext()) {
                    Object childPath = iterator.next();
                    File child = (File) pathToFile.invoke(childPath);
                    visitor.visit(child);
                }
            } catch (InvocationTargetException e) {
                throw asIo("could not list " + directory.getPath(), e.getTargetException());
            } catch (IllegalAccessException e) {
                throw new IOException("could not list " + directory.getPath(), e);
            } catch (RuntimeException e) {
                Throwable cause = e.getCause();
                if (cause instanceof IOException) {
                    throw (IOException) cause;
                }
                throw e;
            } finally {
                if (stream instanceof java.io.Closeable) {
                    try {
                        ((java.io.Closeable) stream).close();
                    } catch (IOException ignored) {
                        // Nothing useful to do while closing.
                    }
                }
            }
        }

        private static IOException asIo(String prefix, Throwable cause) {
            if (cause instanceof IOException) {
                return (IOException) cause;
            }
            return new IOException(prefix + ": " + cause, cause);
        }
    }
}
