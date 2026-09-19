package mt.safety.scanner.core;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * A plugin to be examined, in either of the two shapes MT Manager leaves them in.
 *
 * <p>An {@code .mtp} download is a zip; an installed plugin is an unpacked directory containing the
 * same {@code manifest.json}, {@code src/}, {@code assets/} and {@code libs/} layout. Rules are
 * written against this one interface so they apply equally to a file the user is about to install
 * and to one already living in MT Manager's data directory.
 */
public abstract class PluginPackage {

    /** Largest single member the scanner will pull into memory. */
    public static final int MAX_MEMBER_BYTES = 4 * 1024 * 1024;

    /** How much an archive may claim to inflate to before the structural walk gives up on it. */
    static final long WALK_INFLATION_CAP = 512L * 1024 * 1024;

    /** One member of a package. */
    public static final class Entry {
        public final String name;
        public final long size;
        public final long compressedSize;
        public final boolean directory;

        public Entry(String name, long size, long compressedSize, boolean directory) {
            this.name = name;
            this.size = size;
            this.compressedSize = compressedSize;
            this.directory = directory;
        }

        /** The member's extension, lowercase, without the dot; empty when it has none. */
        public String extension() {
            int slash = name.lastIndexOf('/');
            int dot = name.lastIndexOf('.');
            if (dot <= slash || dot == name.length() - 1) {
                return "";
            }
            return name.substring(dot + 1).toLowerCase(java.util.Locale.US);
        }

        /** The first path segment, e.g. {@code src} for {@code src/a/B.java}. */
        public String topLevel() {
            int slash = name.indexOf('/');
            return slash < 0 ? name : name.substring(0, slash);
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /** Human readable identity of this package, used in report headings. */
    public abstract String label();

    /** Where it lives on disk. */
    public abstract File location();

    /** True for a {@code .mtp} archive, false for an unpacked installed plugin. */
    public abstract boolean archive();

    /** All members, directories included. */
    public abstract List<Entry> entries() throws IOException;

    /** Reads a member, capped at {@code limit} bytes and at whatever the budget allows. */
    public abstract byte[] read(Entry entry, int limit, ScanBudget budget) throws IOException;

    /**
     * A stable digest identifying this exact package content.
     *
     * <p>Takes the budget because this reads the package end to end: on a multi-gigabyte file it is
     * the single largest read a scan performs, and it runs on MT Manager's UI thread.
     */
    public abstract String contentHash(ScanBudget budget) throws IOException;

    /**
     * Members whose local headers disagree with the central directory, or that appear twice.
     *
     * <p>Only meaningful for archives. Duplicate names are a real packaging trick: a reviewer's tool
     * reads one copy while the installer extracts the other.
     */
    public List<String> structuralAnomalies(ScanBudget budget) throws IOException {
        return Collections.emptyList();
    }

    public void close() {
    }

    /**
     * Returns a view of {@code delegate} with {@code prefix} removed from every member name.
     *
     * <p>Packages zipped with a wrapping folder ({@code MyPlugin/manifest.json} rather than
     * {@code manifest.json}) are common enough that treating them as malformed would be unhelpful.
     * Rules see the documented layout either way.
     */
    public static PluginPackage rooted(PluginPackage delegate, String prefix) {
        if (prefix == null || prefix.length() == 0) {
            return delegate;
        }
        return new RootedPackage(delegate, prefix);
    }

    /**
     * How many bytes a read of {@code entry} should reserve.
     *
     * <p>Bounded by the member's own size as well as the caller's limit. Reserving the full limit for
     * a two-line source file would exhaust an interactive budget after a handful of members and leave
     * the rest of the package unread while reporting almost nothing consumed.
     */
    static int wanted(Entry entry, int limit) {
        long cap = Math.min((long) limit, (long) MAX_MEMBER_BYTES);
        if (entry != null && entry.size > 0) {
            cap = Math.min(cap, entry.size);
        }
        return (int) Math.max(cap, 0L);
    }

    /** Opens a path as a package, choosing the archive or directory reader. */
    public static PluginPackage open(File file) throws IOException {
        if (file == null || !file.exists()) {
            throw new IOException("no such path: " + file);
        }
        if (file.isDirectory()) {
            return new DirectoryPackage(file);
        }
        return new ArchivePackage(file);
    }

    // ------------------------------------------------------------- archive

    /** A {@code .mtp} (or {@code .zip}) file. */
    static final class ArchivePackage extends PluginPackage {
        private final File file;
        private ZipFile zip;
        private List<Entry> cached;

        ArchivePackage(File file) {
            this.file = file;
        }

        private ZipFile zip() throws IOException {
            if (zip == null) {
                zip = new ZipFile(file);
            }
            return zip;
        }

        @Override
        public String label() {
            return file.getName();
        }

        @Override
        public File location() {
            return file;
        }

        @Override
        public boolean archive() {
            return true;
        }

        @Override
        public List<Entry> entries() throws IOException {
            if (cached != null) {
                return cached;
            }
            List<Entry> out = new ArrayList<Entry>();
            Enumeration<? extends ZipEntry> en = zip().entries();
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                out.add(new Entry(ze.getName(), Math.max(ze.getSize(), 0L),
                        Math.max(ze.getCompressedSize(), 0L), ze.isDirectory()));
            }
            cached = out;
            return out;
        }

        @Override
        public byte[] read(Entry entry, int limit, ScanBudget budget) throws IOException {
            int granted = budget.reserve(wanted(entry, limit));
            if (granted <= 0) {
                return new byte[0];
            }
            ZipEntry ze = zip().getEntry(entry.name);
            if (ze == null) {
                return new byte[0];
            }
            InputStream in = zip().getInputStream(ze);
            try {
                return Bytes.readAtMost(in, granted);
            } finally {
                closeQuietly(in);
            }
        }

        @Override
        public String contentHash(ScanBudget budget) throws IOException {
            if (!affordableToHash(file.length(), budget)) {
                return "";
            }
            InputStream in = new BufferedInputStream(new FileInputStream(file));
            try {
                return Bytes.sha256(in, budget);
            } finally {
                closeQuietly(in);
            }
        }

        @Override
        public List<String> structuralAnomalies(ScanBudget budget) throws IOException {
            if (budget.exhausted()) {
                return Collections.emptyList();
            }
            List<String> problems = new ArrayList<String>();
            Set<String> seen = new HashSet<String>();
            Set<String> streamed = new HashSet<String>();
            boolean readWholeArchive = true;
            ZipInputStream zin = new ZipInputStream(new BufferedInputStream(new FileInputStream(file)));
            try {
                ZipEntry ze;
                int guard = 0;
                long declared = 0;
                while ((ze = zin.getNextEntry()) != null) {
                    // Checked every iteration, not once before the walk: a large archive would
                    // otherwise stream tens of thousands of members past the deadline, on MT
                    // Manager's UI thread.
                    //
                    // The size cap matters for a different reason: advancing to the next entry
                    // inflates whatever remains of the current one, so walking an archive built as a
                    // bomb expands it even though nothing here reads entry data on purpose.
                    declared += Math.max(ze.getSize(), 0L);
                    if (guard++ >= 20000 || declared > WALK_INFLATION_CAP || budget.exhausted()) {
                        readWholeArchive = false;
                        break;
                    }
                    String name = ze.getName();
                    streamed.add(name);
                    if (!seen.add(name)) {
                        problems.add("duplicate archive member: " + name);
                    }
                }
            } catch (IOException e) {
                readWholeArchive = false;
                problems.add("archive stream could not be read end to end: " + e.getMessage());
            } finally {
                closeQuietly(zin);
            }
            // A name present in the central directory but absent from the local stream means the two
            // views of the archive disagree. Only a complete walk can say that: stopping early leaves
            // every unread member looking absent, which would be a serious finding invented out of a
            // budget limit rather than out of the package.
            if (readWholeArchive) {
                for (Entry entry : entries()) {
                    if (!streamed.contains(entry.name)) {
                        problems.add("member listed in the archive index but missing from its data: "
                                + entry.name);
                    }
                }
            } else {
                budget.markTruncated();
            }
            return problems;
        }

        @Override
        public void close() {
            if (zip != null) {
                try {
                    zip.close();
                } catch (IOException ignored) {
                    // nothing useful to do while closing
                }
                zip = null;
            }
        }
    }

    // ----------------------------------------------------------- directory

    /** An installed plugin, already unpacked into a directory. */
    static final class DirectoryPackage extends PluginPackage {
        private static final int MAX_FILES = 8000;
        private static final int MAX_DEPTH = 24;

        private final File root;
        private List<Entry> cached;
        private boolean listingTruncated;
        private final List<String> anomalies = new ArrayList<String>();

        DirectoryPackage(File root) {
            this.root = root;
        }

        @Override
        public String label() {
            return root.getName();
        }

        @Override
        public File location() {
            return root;
        }

        @Override
        public boolean archive() {
            return false;
        }

        @Override
        public List<Entry> entries() throws IOException {
            if (cached != null) {
                return cached;
            }
            List<Entry> out = new ArrayList<Entry>();
            walk(root, "", 0, out);
            cached = out;
            return out;
        }

        private void walk(File dir, String prefix, int depth, List<Entry> out) {
            if (depth > MAX_DEPTH || out.size() >= MAX_FILES) {
                if (out.size() >= MAX_FILES) {
                    listingTruncated = true;
                    anomalies.add("directory holds more than " + MAX_FILES + " files; listing truncated");
                }
                return;
            }
            File[] children = dir.listFiles();
            if (children == null) {
                return;
            }
            for (int i = 0; i < children.length; i++) {
                File child = children[i];
                String name = prefix + child.getName();
                if (escapesRoot(child)) {
                    anomalies.add("link pointing outside the plugin directory: " + name);
                    continue;
                }
                if (child.isDirectory()) {
                    out.add(new Entry(name + "/", 0L, 0L, true));
                    walk(child, name + "/", depth + 1, out);
                } else {
                    long size = child.length();
                    out.add(new Entry(name, size, size, false));
                }
            }
        }

        /**
         * Detects a member that resolves outside the plugin directory.
         *
         * <p>{@code java.nio.file} is unavailable on the Android versions this plugin supports, so
         * symlinks are caught by comparing the canonical path with the declared one.
         */
        private boolean escapesRoot(File child) {
            try {
                String canonicalRoot = root.getCanonicalPath();
                String canonicalChild = child.getCanonicalPath();
                return !canonicalChild.equals(canonicalRoot)
                        && !canonicalChild.startsWith(canonicalRoot + File.separator);
            } catch (IOException e) {
                return false;
            }
        }

        @Override
        public byte[] read(Entry entry, int limit, ScanBudget budget) throws IOException {
            int granted = budget.reserve(wanted(entry, limit));
            if (granted <= 0) {
                return new byte[0];
            }
            File target = new File(root, entry.name);
            if (!target.isFile()) {
                return new byte[0];
            }
            InputStream in = new BufferedInputStream(new FileInputStream(target));
            try {
                return Bytes.readAtMost(in, granted);
            } finally {
                closeQuietly(in);
            }
        }

        @Override
        public String contentHash(ScanBudget budget) throws IOException {
            entries();
            if (listingTruncated) {
                // A hash over part of a directory is not an identity for the directory. Reporting none
                // is what keeps it out of a destructive plan, where a replacement differing only in
                // the unlisted files would otherwise pass for the package that was confirmed.
                return "";
            }
            List<String> lines = new ArrayList<String>();
            for (Entry entry : entries()) {
                if (entry.directory) {
                    continue;
                }
                if (!affordableToHash(entry.size, budget)) {
                    return "";
                }
                File target = new File(root, entry.name);
                if (!target.isFile()) {
                    continue;
                }
                InputStream in = new BufferedInputStream(new FileInputStream(target));
                try {
                    String memberHash = Bytes.sha256(in, budget);
                    if (memberHash.length() == 0) {
                        // The digest was abandoned mid-file, so this line would not identify the
                        // member. A directory hash missing one member is not an identity for the
                        // directory either; report none rather than a plausible-looking wrong answer.
                        return "";
                    }
                    lines.add(entry.name + ":" + memberHash);
                } finally {
                    closeQuietly(in);
                }
            }
            Collections.sort(lines);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < lines.size(); i++) {
                sb.append(lines.get(i)).append('\n');
            }
            return Bytes.sha256(sb.toString().getBytes("UTF-8"));
        }

        @Override
        public List<String> structuralAnomalies(ScanBudget budget) throws IOException {
            entries();
            return anomalies;
        }
    }

    /** A package seen through a stripped-off wrapping directory. */
    static final class RootedPackage extends PluginPackage {
        private final PluginPackage delegate;
        private final String prefix;

        RootedPackage(PluginPackage delegate, String prefix) {
            this.delegate = delegate;
            this.prefix = prefix.endsWith("/") ? prefix : prefix + "/";
        }

        @Override
        public String label() {
            return delegate.label();
        }

        @Override
        public File location() {
            return delegate.location();
        }

        @Override
        public boolean archive() {
            return delegate.archive();
        }

        @Override
        public List<Entry> entries() throws IOException {
            List<Entry> out = new ArrayList<Entry>();
            for (Entry entry : delegate.entries()) {
                if (!entry.name.startsWith(prefix)) {
                    continue;
                }
                String stripped = entry.name.substring(prefix.length());
                if (stripped.length() == 0) {
                    continue;
                }
                out.add(new Entry(stripped, entry.size, entry.compressedSize, entry.directory));
            }
            return out;
        }

        @Override
        public byte[] read(Entry entry, int limit, ScanBudget budget) throws IOException {
            return delegate.read(new Entry(prefix + entry.name, entry.size, entry.compressedSize,
                    entry.directory), limit, budget);
        }

        @Override
        public String contentHash(ScanBudget budget) throws IOException {
            return delegate.contentHash(budget);
        }

        @Override
        public List<String> structuralAnomalies(ScanBudget budget) throws IOException {
            return delegate.structuralAnomalies(budget);
        }

        @Override
        public void close() {
            delegate.close();
        }
    }

    /**
     * Budget charged for hashing, scaled down because hashing streams rather than buffers.
     *
     * <p>Charging the full length would make a single large package exhaust the whole budget before
     * any rule ran, so the cost is sampled: enough that an enormous file still stops the scan, little
     * enough that an ordinary one does not distort it.
     */
    static int hashCost(long length) {
        long cost = Math.max(length / 64L, 1L);
        return (int) Math.min(cost, (long) Integer.MAX_VALUE);
    }

    /**
     * Beyond this, a package is reported as having no verifiable identity rather than hashed.
     *
     * <p>{@link #hashCost} deliberately under-charges, so the byte allowance on its own would let a
     * granted reservation stand for a gigabyte of real reading. This is the ceiling on what that
     * discount is allowed to hide. A plugin package is tens or hundreds of kilobytes; 64 MB is already
     * far outside anything legitimate, and hashing it costs under a second even on a slow phone.
     */
    static final long MAX_HASHED_LENGTH = 64L * 1024 * 1024;

    /**
     * True when the budget can pay for hashing {@code length} bytes in full.
     *
     * <p>A partial grant is refused rather than accepted, because there is no such thing as hashing
     * part of a file: the digest either covers the whole thing or it is not an identity. {@code
     * reserve} returns whatever is left when it cannot grant the request, so checking only for a
     * positive result was enough to let an enormous package through on the strength of a few spare
     * bytes.
     */
    static boolean affordableToHash(long length, ScanBudget budget) {
        if (length < 0 || length > MAX_HASHED_LENGTH) {
            return false;
        }
        int cost = hashCost(length);
        return budget.reserve(cost) >= cost;
    }

    static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignored) {
                // nothing useful to do while closing
            }
        }
    }
}
