package mt.safety.scanner.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Same-directory staging for scanner-owned files, committed with one rename.
 *
 * <p>A unique file is created in an existing canonical parent. The final destination is never opened
 * for writing or deleted first, so a pre-existing destination symlink is replaced as a directory entry
 * rather than followed. A failed rename leaves that entry in place. Callers must establish that the
 * destination parent belongs to the scanner before calling this helper.
 *
 * <p>This relies on the filesystem's rename replacement semantics; unsupported replacements fail.
 * File contents are synced before rename, but directory metadata is not synced, so this is not a
 * power-loss durability guarantee. Java 8 path APIs also cannot prevent a malicious same-UID process
 * from replacing parent directories or staging entries concurrently. This is not an isolation boundary
 * against such an actor.
 */
public final class AtomicFiles {
    private AtomicFiles() { }

    private interface StagedWriter {
        void write(FileOutputStream output) throws IOException;
    }

    /** Creates an initial file without replacing any existing entry, including dangling links. */
    public static boolean createIfAbsent(File destination, byte[] content) throws IOException {
        if (destination == null || content == null) throw new IOException("Missing initial file data");
        File parent = destination.getAbsoluteFile().getParentFile();
        if (parent == null || !parent.isDirectory()) throw new IOException("Missing destination directory");
        File target = new File(parent.getCanonicalFile(), destination.getName());
        try {
            // Android disallows application hard links. Public Os.open with O_EXCL creates the
            // final entry atomically, then writes through that exact descriptor without reopening.
            Class<?> os = Class.forName("android.system.Os");
            Class<?> constants = Class.forName("android.system.OsConstants");
            int flags = 0;
            for (String name : new String[] {"O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC"}) {
                flags |= constants.getField(name).getInt(null);
            }
            java.io.FileDescriptor descriptor = (java.io.FileDescriptor) os.getMethod("open", String.class,
                    int.class, int.class).invoke(null, target.getAbsolutePath(), flags, 0600);
            try (FileOutputStream output = new FileOutputStream(descriptor)) {
                output.write(content); output.flush(); output.getFD().sync();
            }
            return true;
        } catch (ClassNotFoundException desktop) {
            return createLinkedInitialFile(target, content);
        } catch (java.lang.reflect.InvocationTargetException wrapped) {
            Throwable cause = wrapped.getCause();
            if (cause != null && "android.system.ErrnoException".equals(cause.getClass().getName())) {
                try {
                    int error = cause.getClass().getField("errno").getInt(cause);
                    int exists = Class.forName("android.system.OsConstants").getField("EEXIST").getInt(null);
                    if (error == exists) return false;
                } catch (ReflectiveOperationException unavailable) {
                    throw new IOException("Could not verify exclusive initial creation", unavailable);
                }
            }
            throw new IOException("Could not create initial file without replacement", cause);
        } catch (ReflectiveOperationException unavailable) {
            throw new IOException("No supported exclusive creation API", unavailable);
        }
    }

    /** Desktop no-replace publication; reflective NIO preserves Android API24 linkage. */
    private static boolean createLinkedInitialFile(File target, byte[] content) throws IOException {
        File temporary = File.createTempFile(".mtsafety-seed-", ".tmp", target.getParentFile());
        try {
            try (FileOutputStream output = new FileOutputStream(temporary)) {
                output.write(content); output.flush(); output.getFD().sync();
            }
            Class<?> path = Class.forName("java.nio.file.Path");
            Object from = File.class.getMethod("toPath").invoke(temporary);
            Object to = File.class.getMethod("toPath").invoke(target);
            Class.forName("java.nio.file.Files").getMethod("createLink", path, path).invoke(null, to, from);
            return true;
        } catch (java.lang.reflect.InvocationTargetException wrapped) {
            Throwable cause = wrapped.getCause();
            if (cause != null && "java.nio.file.FileAlreadyExistsException".equals(cause.getClass().getName())) return false;
            throw new IOException("Could not publish initial file without replacement", cause);
        } catch (ReflectiveOperationException unavailable) {
            throw new IOException("No supported no-replace publication API", unavailable);
        } finally {
            if (!temporary.delete()) throw new IOException("Could not remove initial-file staging entry");
        }
    }

    public static void write(File destination, final byte[] content) throws IOException {
        if (content == null) {
            throw new IOException("no content to write");
        }
        stage(destination, new StagedWriter() {
            @Override
            public void write(FileOutputStream output) throws IOException {
                output.write(content);
            }
        });
    }

    /** Copies at most maxBytes, checking the stream even when the source grows after its size check. */
    public static void copy(final File source, File destination, final long maxBytes) throws IOException {
        if (source == null || !source.isFile()) {
            throw new IOException("copy source is not a regular file");
        }
        if (maxBytes < 0) {
            throw new IOException("copy byte limit must not be negative");
        }
        if (source.length() > maxBytes) {
            throw new IOException("copy source exceeds byte limit");
        }
        stage(destination, new StagedWriter() {
            @Override
            public void write(FileOutputStream output) throws IOException {
                try (InputStream input = new FileInputStream(source)) {
                    byte[] buffer = new byte[8192];
                    long copied = 0;
                    while (true) {
                        long remaining = maxBytes - copied;
                        int request = remaining >= buffer.length ? buffer.length : (int) remaining + 1;
                        int count = input.read(buffer, 0, request);
                        if (count < 0) {
                            return;
                        }
                        if (count > remaining) {
                            throw new IOException("copy source exceeds byte limit");
                        }
                        if (count > 0) {
                            output.write(buffer, 0, count);
                            copied += count;
                        }
                    }
                }
            }
        });
    }

    private static void stage(File destination, StagedWriter writer) throws IOException {
        if (destination == null) {
            throw new IOException("no destination to write");
        }
        File absolute = destination.getAbsoluteFile();
        File parent = absolute.getParentFile();
        if (parent == null || !parent.isDirectory()) {
            throw new IOException("destination parent is not an existing directory");
        }
        parent = parent.getCanonicalFile();
        // Canonicalize only the parent: resolving the final component would follow destination links.
        File target = new File(parent, absolute.getName());
        File temporary = File.createTempFile(".mtsafety-", ".tmp", parent);
        boolean committed = false;
        IOException failure = null;
        try {
            try (FileOutputStream output = new FileOutputStream(temporary)) {
                writer.write(output);
                output.flush();
                output.getFD().sync();
            }
            if (!temporary.renameTo(target)) {
                throw new IOException("could not replace " + target.getAbsolutePath()
                        + "; the existing destination is unchanged");
            }
            committed = true;
        } catch (IOException caught) {
            failure = caught;
            throw caught;
        } finally {
            if (!committed && temporary.exists() && !temporary.delete()) {
                IOException cleanup = new IOException("could not remove staging file " + temporary.getAbsolutePath());
                if (failure == null) {
                    throw cleanup;
                }
                failure.addSuppressed(cleanup);
            }
        }
    }
}
