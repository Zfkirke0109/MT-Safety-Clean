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
 * <p>An {@code .mtp} download is a zip. An installed plugin is either an unpacked directory with the
 * same layout, or, as MT Manager actually keeps them, a folder named after the plugin id holding
 * {@code plugin.mtp} and whatever MT Manager extracted beside it. Rules are written against this one
 * interface so they apply equally to a file the user is about to install and to one already living
 * in MT Manager's data directory.
 */
public abstract class PluginPackage {

    /** Largest single member the scanner will pull into memory. */
    public static final int MAX_MEMBER_BYTES = 4 * 1024 * 1024;

    /** The name MT Manager gives the archive it keeps for each installed plugin. */
    public static final String INSTALLED_ARCHIVE = "plugin.mtp";

    /**
     * Prefix on the names of files found beside an installed plugin's archive.
     *
     * <p>MT Manager installs a plugin as {@code <id>/plugin.mtp} and may extract its compiled code
     * alongside. Those siblings are searched for indicators like any member, but they are not the
     * package's own contents, and rules about what a package carries leave them alone.
     */
    public static final String BESIDE_PREFIX = "@beside/";

    /** How much an archive may claim to inflate to before the structural walk gives up on it. */

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

    /** True for a {@code .mtp} archive, false for an unpacked directory. This is the format. */
    public abstract boolean archive();

    /**
     * True when this is a plugin MT Manager has installed, whatever its format.
     *
     * <p>An unpacked directory with a manifest is one; so is MT Manager's {@code <id>/plugin.mtp}.
     * A loose {@code .mtp} in a downloads folder is not.
     */
    public boolean installed() {
        return false;
    }

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
            throw new IOException("no such path: " + (file == null ? "null" : file.getName()));
        }
        if (file.isDirectory()) {
            File inner = new File(file, INSTALLED_ARCHIVE);
            if (!new File(file, "manifest.json").isFile() && inner.isFile()) {
                // MT Manager's own layout for an installed plugin: a folder named after the plugin
                // id holding the archive it was installed from, with whatever MT Manager extracted
                // beside it. The folder is the install unit; the archive is the package.
                return new InstalledArchivePackage(file, new ArchivePackage(inner));
            }
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

        /** How many members the archive lists, for bounding what may be added beside it. */
        int entriesCountHint() {
            try {
                return entries().size();
            } catch (IOException e) {
                return 0;
            }
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
                long inflated = 0;
                while ((ze = zin.getNextEntry()) != null) {
                    // Checked every iteration, not once before the walk: a large archive would
                    // otherwise stream tens of thousands of members past the deadline, on MT
                    // Manager's UI thread.
                    if (guard++ >= 20000 || budget.exhausted()) {
                        readWholeArchive = false;
                        break;
                    }
                    String name = ze.getName();
                    streamed.add(name);
                    if (!seen.add(name)) {
                        problems.add("duplicate archive member: " + name);
                    }

                    // Nothing here wants this member's data, but advancing past it inflates it
                    // regardless: getNextEntry closes the current entry, and closing means reading
                    // whatever is left of it. So the bytes are consumed here instead, where they can
                    // be counted and stopped.
                    //
                    // The member's declared size cannot do this job. An entry written with a data
                    // descriptor carries its size *after* its data, so getSize() is -1 at this point
                    // and a running total of it never grows -- which is exactly how a bomb would be
                    // stored. Counting what actually comes out of the inflater is the only measure
                    // that a hostile archive does not get to choose.
                    long cap = budget.walkInflationCap();
                    inflated += drain(zin, cap - inflated, budget);
                    if (inflated >= cap || budget.exhausted()) {
                        // Stop without advancing: the next getNextEntry would inflate the rest of
                        // this member in one unbounded go, which is the thing being guarded against.
                        readWholeArchive = false;
                        if (inflated >= cap) {
                            // Worth saying rather than only counting as truncation. A package that
                            // expands past what the scan will spend on reading it is the shape of a
                            // bomb, and the user is choosing whether to trust it.
                            problems.add("archive expands to more than " + Bytes.humanSize(cap)
                                    + " while being read; stopped at " + name);
                        }
                        break;
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

        /** Enough anomalies to explain what went wrong, not enough for a hostile tree to fill memory. */
        private static final int MAX_ANOMALIES = 40;

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
        public boolean installed() {
            return true;
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

        /**
         * Lists the tree, recording every point at which it gave up.
         *
         * <p>Each cutoff has to mark the listing truncated, not just the file-count cap. A hash over a
         * listing that quietly omitted a deep subtree or an unreadable folder is not an identity for
         * the directory: a replacement differing only in the omitted files would hash the same, pass
         * the re-verification a destructive action does, and be quarantined or deleted in place of the
         * package that was actually examined.
         */
        private void walk(File dir, String prefix, int depth, List<Entry> out) {
            if (out.size() >= MAX_FILES) {
                listingTruncated = true;
                noteAnomaly("directory holds more than " + MAX_FILES + " files; listing truncated");
                return;
            }
            if (depth > MAX_DEPTH) {
                listingTruncated = true;
                noteAnomaly("directory nested more than " + MAX_DEPTH + " levels deep; listing truncated");
                return;
            }
            File[] children = dir.listFiles();
            if (children == null) {
                listingTruncated = true;
                noteAnomaly("could not list "
                        + (prefix.length() == 0 ? "the plugin directory itself" : prefix));
                return;
            }
            for (int i = 0; i < children.length; i++) {
                File child = children[i];
                String name = prefix + child.getName();
                if (escapesRoot(child)) {
                    noteAnomaly("link pointing outside the plugin directory: " + name);
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
        /** Records an anomaly once, and stops well short of letting a hostile tree fill memory. */
        private void noteAnomaly(String message) {
            if (anomalies.size() >= MAX_ANOMALIES) {
                return;
            }
            if (anomalies.size() == MAX_ANOMALIES - 1) {
                anomalies.add("more problems than can be listed here");
                return;
            }
            if (!anomalies.contains(message)) {
                anomalies.add(message);
            }
        }

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

    /**
     * An installed plugin in MT Manager's own layout: {@code <id>/plugin.mtp} plus whatever MT
     * Manager extracted beside it.
     *
     * <p>Members come from the archive. Regular files found in the folder (up to a small depth and
     * count) are added under {@link #BESIDE_PREFIX} so their contents are searched too: when MT
     * Manager unpacks a v3 plugin's dex next to the package, that dex is where the code is. The
     * package's identity stays the archive's hash; MT Manager rewriting its own extracted artefacts
     * must not read as the plugin having changed.
     */
    static final class InstalledArchivePackage extends PluginPackage {
        private static final int MAX_SIBLINGS = 400;
        private static final int MAX_SIBLING_DEPTH = 3;

        private final File dir;
        private final ArchivePackage delegate;
        private List<Entry> cached;

        InstalledArchivePackage(File dir, ArchivePackage delegate) {
            this.dir = dir;
            this.delegate = delegate;
        }

        @Override
        public String label() {
            return dir.getName();
        }

        @Override
        public File location() {
            return dir;
        }

        @Override
        public boolean archive() {
            return true;
        }

        @Override
        public boolean installed() {
            return true;
        }

        @Override
        public List<Entry> entries() throws IOException {
            if (cached != null) {
                return cached;
            }
            List<Entry> out = new ArrayList<Entry>(delegate.entries());
            String rootCanonical;
            try {
                rootCanonical = dir.getCanonicalPath();
            } catch (IOException e) {
                rootCanonical = null;
            }
            collectSiblings(dir, "", 0, out, rootCanonical);
            cached = out;
            return out;
        }

        private void collectSiblings(File folder, String prefix, int depth, List<Entry> out, String rootCanonical) {
            if (depth > MAX_SIBLING_DEPTH || out.size() >= delegate.entriesCountHint() + MAX_SIBLINGS) {
                return;
            }
            File[] children = folder.listFiles();
            if (children == null) {
                return;
            }
            for (int i = 0; i < children.length; i++) {
                File child = children[i];
                String name = prefix + child.getName();
                if (depth == 0 && child.getName().equals(INSTALLED_ARCHIVE)) {
                    continue;
                }
                if (rootCanonical != null && escapes(child, rootCanonical)) {
                    continue;
                }
                if (child.isDirectory()) {
                    collectSiblings(child, name + "/", depth + 1, out, rootCanonical);
                } else if (child.isFile()) {
                    long size = child.length();
                    out.add(new Entry(BESIDE_PREFIX + name, size, size, false));
                }
            }
        }

        private static boolean escapes(File child, String rootCanonical) {
            try {
                String canonical = child.getCanonicalPath();
                return !canonical.equals(rootCanonical) && !canonical.startsWith(rootCanonical + File.separator);
            } catch (IOException e) {
                return true;
            }
        }

        @Override
        public byte[] read(Entry entry, int limit, ScanBudget budget) throws IOException {
            if (!entry.name.startsWith(BESIDE_PREFIX)) {
                return delegate.read(entry, limit, budget);
            }
            int granted = budget.reserve(wanted(entry, limit));
            if (granted <= 0) {
                return new byte[0];
            }
            File target = new File(dir, entry.name.substring(BESIDE_PREFIX.length()));
            InputStream in = new BufferedInputStream(new FileInputStream(target));
            try {
                return Bytes.readAtMost(in, granted);
            } finally {
                closeQuietly(in);
            }
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
        public boolean installed() {
            return delegate.installed();
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

    /**
     * Consumes at most {@code limit} bytes of the archive stream's current member.
     *
     * <p>Returns how many bytes it actually took, which is how the caller measures inflation without
     * trusting anything the archive declares about itself. Stops early on the scan deadline as well as
     * on the limit, because a bomb that inflates slowly is still a frozen UI.
     */
    private static long drain(ZipInputStream zin, long limit, ScanBudget budget) throws IOException {
        if (limit <= 0) {
            return 0;
        }
        byte[] buffer = new byte[1 << 16];
        long total = 0;
        while (total < limit) {
            int want = (int) Math.min((long) buffer.length, limit - total);
            int read = zin.read(buffer, 0, want);
            if (read <= 0) {
                return total;
            }
            total += read;
            if (budget.exhausted()) {
                return total;
            }
        }
        return total;
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
