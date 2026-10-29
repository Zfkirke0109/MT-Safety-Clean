package mt.safety.scanner.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * A set of known-malware signatures in ClamAV's published text formats.
 *
 * <p>This is the "real antivirus" half of the scanner, and it is deliberately format-compatible with
 * the one free and open-source antivirus whose signatures anyone can download and read: a user can
 * take ClamAV's own database, or a third-party feed written for it, and load it here without
 * conversion. The formats are documented at clamav.net and are plain text:
 *
 * <ul>
 *   <li>{@code .hdb} / {@code .hdu} - {@code MD5:size:name}, a hash of a whole file.</li>
 *   <li>{@code .hsb} / {@code .hsu} - {@code SHA1-or-SHA256:size:name}, the same with a stronger hash.</li>
 *   <li>{@code .ndb} / {@code .ndu} - {@code name:target:offset:hexpattern}, a byte pattern with
 *       wildcards, optionally restricted to one kind of file and one position.</li>
 *   <li>{@code .fp} / {@code .sfp} - hashes of files known to be clean, which are never reported.</li>
 *   <li>{@code .ign2} - names of signatures to ignore.</li>
 * </ul>
 *
 * <p>Nothing ships in the plugin: a signature list is something the user obtains from a source they
 * trust and imports on purpose, for the same reason the indicator file starts empty. The packed
 * {@code .cvd} and {@code .cld} bundles ClamAV distributes are not read directly; {@code sigtool
 * --unpack} turns one into the text files above, and the README explains how to pick out the part of
 * it that fits on a phone.
 *
 * <p>Everything is bounded. A phone cannot hold ClamAV's several million entries, so loading stops at
 * a cap and says so; each pattern's matching cost is bounded by {@link HexSignature}; and the whole
 * database is indexed by leading bytes so a scan tries a handful of patterns per position rather
 * than all of them.
 */
public final class SignatureDatabase {

    /** All hash classes also share the global entry and memory budgets below. */
    public static final int MAX_HASHES = 100000;
    /** Kept below the memory budget even for ordinary short patterns during indexing. */
    public static final int MAX_PATTERNS = 16000;
    public static final int MAX_INPUT_BYTES = 16 * 1024 * 1024;
    public static final int MAX_FILE_BYTES = MAX_INPUT_BYTES;
    public static final long MAX_RETAINED_BYTES = 32L * 1024 * 1024;
    public static final int MAX_RETAINED_ENTRIES = 100000;
    /** Bounds source bookkeeping as well as file contents. */
    public static final int MAX_DEFINITION_FILES = 256;
    private static final int MAX_LINE_CHARS = 64 * 1024;
    private static final int MAX_PROBLEMS = 20;
    private static final int MAX_PROBLEM_CHARS = 512;
    public static final int MAX_DIRECTORY_ENTRIES = 4096;
    private static final long DIRECTORY_LIST_NANOS = 4000000000L;
    private static final long LOAD_NANOS = 10000000000L;
    private static long incompleteStampSequence;

    /** ClamAV target types this scanner can recognise a file as. */
    public static final int TARGET_PE = 1;
    public static final int TARGET_OLE2 = 2;
    public static final int TARGET_HTML = 3;
    public static final int TARGET_GRAPHICS = 5;
    public static final int TARGET_ELF = 6;
    public static final int TARGET_ASCII = 7;
    public static final int TARGET_MACHO = 9;
    public static final int TARGET_PDF = 10;
    public static final int TARGET_FLASH = 11;
    public static final int TARGET_JAVA = 12;

    /** One signature that fired. */
    public static final class Match {
        public final String name;
        /** True for a whole-file hash match, false for a byte pattern. */
        public final boolean hash;
        /** True for a "potentially unwanted application" signature, which ClamAV names {@code PUA.*}. */
        public final boolean pua;

        Match(String name, boolean hash) {
            this.name = name;
            this.hash = hash;
            this.pua = name.regionMatches(true, 0, "PUA.", 0, 4);
        }
    }

    /**
     * A table of fixed-width digests, sorted for binary search.
     *
     * <p>Kept as one packed byte array rather than a map of strings: large collections of entries
     * are ordinary for a hash database, and at that size the object overhead of a map keyed by
     * hex strings is most of the memory the plugin would ever use.
     */
    private static final class HashTable {
        final int width;
        private final List<byte[]> pending = new ArrayList<byte[]>();
        private final List<String> pendingNames = new ArrayList<String>();
        private final List<Long> pendingSizes = new ArrayList<Long>();
        private byte[] packed = new byte[0];
        private String[] names = new String[0];
        private long[] sizes = new long[0];
        private int count;

        HashTable(int width) {
            this.width = width;
        }

        void add(byte[] digest, long size, String name) {
            pending.add(digest);
            pendingNames.add(name);
            pendingSizes.add(Long.valueOf(size));
        }

        int size() {
            return count + pending.size();
        }

        boolean isEmpty() {
            return size() == 0;
        }

        /** Sorts what was added, dropping any entry whose name is in {@code ignored}. */
        void index(Set<String> ignored) {
            List<Integer> order = new ArrayList<Integer>(pending.size() + count);
            List<byte[]> all = new ArrayList<byte[]>(pending.size() + count);
            List<String> allNames = new ArrayList<String>();
            List<Long> allSizes = new ArrayList<Long>();
            for (int i = 0; i < count; i++) {
                all.add(Arrays.copyOfRange(packed, i * width, (i + 1) * width));
                allNames.add(names[i]);
                allSizes.add(Long.valueOf(sizes[i]));
            }
            for (int i = 0; i < pending.size(); i++) {
                if (ignored.contains(pendingNames.get(i))) {
                    continue;
                }
                all.add(pending.get(i));
                allNames.add(pendingNames.get(i));
                allSizes.add(pendingSizes.get(i));
            }
            for (int i = 0; i < all.size(); i++) {
                order.add(Integer.valueOf(i));
            }
            final List<byte[]> keys = all;
            Collections.sort(order, new Comparator<Integer>() {
                @Override
                public int compare(Integer a, Integer b) {
                    return compareDigests(keys.get(a.intValue()), 0, keys.get(b.intValue()), 0, width);
                }
            });
            packed = new byte[all.size() * width];
            names = new String[all.size()];
            sizes = new long[all.size()];
            for (int i = 0; i < order.size(); i++) {
                int from = order.get(i).intValue();
                System.arraycopy(all.get(from), 0, packed, i * width, width);
                names[i] = allNames.get(from);
                sizes[i] = allSizes.get(from).longValue();
            }
            count = all.size();
            pending.clear();
            pendingNames.clear();
            pendingSizes.clear();
        }

        /** The name of the entry matching {@code digest} and {@code size}, or null. */
        String lookup(byte[] digest, long size) {
            if (digest == null || digest.length != width || count == 0) {
                return null;
            }
            int low = 0;
            int high = count - 1;
            while (low <= high) {
                int mid = (low + high) >>> 1;
                int cmp = compareDigests(packed, mid * width, digest, 0, width);
                if (cmp < 0) {
                    low = mid + 1;
                } else if (cmp > 0) {
                    high = mid - 1;
                } else {
                    // Several entries can share a digest with different size constraints; walk both
                    // ways from the one found so a size-specific entry is not missed.
                    int i = mid;
                    while (i > 0 && compareDigests(packed, (i - 1) * width, digest, 0, width) == 0) {
                        i--;
                    }
                    for (; i < count && compareDigests(packed, i * width, digest, 0, width) == 0; i++) {
                        if (sizes[i] < 0 || sizes[i] == size) {
                            return names[i];
                        }
                    }
                    return null;
                }
            }
            return null;
        }
    }

    private final HashTable md5 = new HashTable(16);
    private final HashTable sha1 = new HashTable(20);
    private final HashTable sha256 = new HashTable(32);
    private final HashTable cleanMd5 = new HashTable(16);
    private final HashTable cleanSha1 = new HashTable(20);
    private final HashTable cleanSha256 = new HashTable(32);
    private final Set<String> ignoredNames = new HashSet<String>();

    private final List<HexSignature> patterns = new ArrayList<HexSignature>();
    /** Patterns whose first two bytes are fixed, by those bytes; built by {@link #index}. */
    private HexSignature[][] byTwoBytes;
    /** Patterns with one fixed leading byte, by that byte. */
    private HexSignature[][] byOneByte;
    /** Patterns that could start with anything, tried everywhere. */
    private HexSignature[] unbucketed = new HexSignature[0];
    /** Patterns pinned to an offset, tried once each. */
    private HexSignature[] anchored = new HexSignature[0];

    private final List<String> files = new ArrayList<String>();
    private final List<String> problems = new ArrayList<String>();
    private int unsupported;
    private int capped;
    private long newestMillis;
    private boolean indexed;
    private long inputBytes;
    private final long loadStarted = System.nanoTime();
    // Covers overlapping source snapshots (256 paths of <=4096 chars), bounded line/diagnostic
    // scratch, fixed bucket tables and reference arrays during indexing, with allowance to spare.
    private long retainedBytes = 8L * 1024 * 1024;
    private int retainedEntries;
    private String sourceStamp = incompleteStamp();

    private SignatureDatabase() {
    }

    /** A database with nothing in it. */
    public static SignatureDatabase empty() {
        SignatureDatabase db = new SignatureDatabase();
        db.index();
        return db;
    }

    /**
     * Loads one signature file, or every signature file directly inside a directory.
     *
     * <p>A missing path is an empty database, not an error: the folder the plugin reads from does
     * not exist until the first import.
     */
    public static SignatureDatabase load(File path) {
        List<File> paths = new ArrayList<File>();
        paths.add(path);
        return load(paths);
    }

    /** Loads several files or directories into one database. */
    public static SignatureDatabase load(List<File> paths) {
        SignatureDatabase db = new SignatureDatabase();
        try {
            List<Source> sources = sources(paths, db);
            MessageDigest digest = newDigest();
            for (Source source : sources) {
                checkDeadline(db.loadStarted);
                try {
                    db.readFile(source, digest);
                } catch (IOException e) {
                    db.problem("could not completely read " + source.file.getName() + ": " + e.getMessage());
                } catch (RuntimeException e) {
                    db.problem("could not safely read " + source.file.getName() + ": "
                            + e.getClass().getSimpleName());
                }
            }
            String parsedStamp = finishStamp(digest, sources);
            String currentStamp = fingerprint(paths);
            if (!parsedStamp.equals(currentStamp)) {
                db.problem("signature definitions changed during loading; reload before relying on them");
            } else if (db.problems.isEmpty() && db.capped == 0 && db.unsupported == 0) {
                db.sourceStamp = parsedStamp;
            }
        } catch (IOException e) {
            db.problem("could not completely load definitions: " + e.getMessage());
        } catch (RuntimeException e) {
            db.problem("could not safely load definitions: " + e.getClass().getSimpleName());
        }
        db.index();
        return db;
    }

    /** True for a file name in one of the formats this database reads. */
    public static boolean isSignatureFile(String name) {
        String ext = extensionOf(name);
        return ext.equals("hdb") || ext.equals("hdu") || ext.equals("hsb") || ext.equals("hsu")
                || ext.equals("ndb") || ext.equals("ndu") || ext.equals("fp") || ext.equals("sfp")
                || ext.equals("ign2");
    }

    /** True for a ClamAV bundle this database cannot open directly, so the user can be told why. */
    public static boolean isPackedBundle(String name) {
        String ext = extensionOf(name);
        return ext.equals("cvd") || ext.equals("cld") || ext.equals("cud");
    }

    /** Bounded SHA-256 fingerprint of source paths, metadata and their complete contents. */
    public static String stamp(File path) {
        try {
            return fingerprint(Collections.singletonList(path));
        } catch (IOException e) {
            return incompleteStamp();
        } catch (RuntimeException e) {
            return incompleteStamp();
        }
    }

    /** Only a complete, unchanged load can be reused by a cache. */
    public String sourceStamp() {
        return sourceStamp;
    }

    private static synchronized String incompleteStamp() {
        return "!incomplete-signature-definitions:" + ++incompleteStampSequence;
    }

    private static final class Source {
        final File file;
        final long size;
        final long modified;

        Source(File file) throws IOException {
            this.file = file;
            if (!file.isFile()) { throw new IOException("definition source is not a regular file"); }
            size = file.length();
            modified = file.lastModified();
            if (file.getAbsolutePath().length() > 4096 || size < 0 || size > MAX_FILE_BYTES) {
                throw new DefinitionLimitException("definition source path or file byte limit reached");
            }
        }

        void header(MessageDigest digest) throws IOException {
            // Explicit lengths avoid ambiguity between file names and contents.
            byte[] path = file.getAbsolutePath().getBytes("UTF-8");
            digest.update((path.length + ":").getBytes("UTF-8"));
            digest.update(path);
            digest.update((":" + size + ":" + modified + ":").getBytes("UTF-8"));
        }

        void verify(long read) throws IOException {
            if (!file.isFile() || read != size || file.length() != size
                    || file.lastModified() != modified) {
                throw new IOException("signature definitions changed during reading");
            }
        }
    }

    /** Global limits refuse the set; independent source failures must not discard usable sources. */
    private static final class DefinitionLimitException extends IOException {
        private static final long serialVersionUID = 1L;
        DefinitionLimitException(String message) { super(message); }
    }

    private static List<Source> sources(List<File> paths) throws IOException {
        return sources(paths, null);
    }

    private static List<Source> sources(List<File> paths, SignatureDatabase diagnostics) throws IOException {
        List<Source> out = new ArrayList<Source>();
        if (paths.size() > MAX_DIRECTORY_ENTRIES) {
            throw new DefinitionLimitException("definition source count limit reached");
        }
        long total = 0;
        long started = System.nanoTime();
        for (File path : paths) {
            checkDeadline(started);
            if (path == null) { continue; }
            List<File> files;
            try {
                if (!path.exists()) { continue; }
                files = path.isDirectory() ? signatureFiles(path, started)
                        : Collections.singletonList(path);
            } catch (IOException e) {
                collectionProblem(diagnostics, path, e);
                continue;
            } catch (RuntimeException e) {
                collectionProblem(diagnostics, path, e);
                continue;
            }
            for (File file : files) {
                if (out.size() >= MAX_DEFINITION_FILES) {
                    throw new DefinitionLimitException("definition file count limit reached (" + MAX_DEFINITION_FILES + ")");
                }
                Source source;
                try {
                    source = new Source(file);
                } catch (IOException e) {
                    collectionProblem(diagnostics, file, e);
                    continue;
                } catch (RuntimeException e) {
                    collectionProblem(diagnostics, file, e);
                    continue;
                }
                total += source.size;
                if (total > MAX_INPUT_BYTES) {
                    throw new DefinitionLimitException("aggregate definition input exceeds " + Bytes.humanSize(MAX_INPUT_BYTES));
                }
                out.add(source);
            }
        }
        return out;
    }

    private static void collectionProblem(SignatureDatabase diagnostics, File path, Exception failure)
            throws IOException {
        if (failure instanceof DefinitionLimitException) { throw (DefinitionLimitException) failure; }
        String message = "could not inspect definition source " + path.getName() + ": "
                + failure.getClass().getSimpleName() + ": " + failure.getMessage();
        if (diagnostics == null) { throw new IOException(message, failure); }
        diagnostics.problem(message);
    }

    private static MessageDigest newDigest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static String fingerprint(List<File> paths) throws IOException {
        MessageDigest digest = newDigest();
        long total = 0;
        long started = System.nanoTime();
        List<Source> snapshot = sources(paths);
        for (Source source : snapshot) {
            source.header(digest);
            long count = 0;
            try (InputStream in = new FileInputStream(source.file)) {
                byte[] buffer = new byte[8192];
                int n;
                while (count < source.size) {
                    checkDeadline(started);
                    n = in.read(buffer, 0, (int) Math.min(buffer.length, source.size - count));
                    if (n == -1) { break; }
                    count += n;
                    total += n;
                    if (total > MAX_INPUT_BYTES || count > source.size) {
                        throw new IOException("definition input byte limit or mutation detected");
                    }
                    digest.update(buffer, 0, n);
                }
            }
            source.verify(count);
        }
        checkDeadline(started);
        List<Source> current = sources(paths);
        if (current.size() != snapshot.size()) { throw new IOException("definitions changed during fingerprinting"); }
        for (int i = 0; i < current.size(); i++) {
            Source a = snapshot.get(i);
            Source b = current.get(i);
            if (!a.file.equals(b.file) || a.size != b.size || a.modified != b.modified) {
                throw new IOException("definitions changed during fingerprinting");
            }
        }
        return finishStamp(digest, snapshot);
    }

    private static void checkDeadline(long started) throws IOException {
        if (Thread.currentThread().isInterrupted() || System.nanoTime() - started >= LOAD_NANOS) {
            throw new IOException("definition loading interrupted or time limit reached");
        }
    }

    private static String finishStamp(MessageDigest digest, List<Source> sources) {
        StringBuilder stamp = new StringBuilder(Bytes.hex(digest.digest()));
        for (Source source : sources) { stamp.append('\n').append(source.file.getName()); }
        return stamp.toString();
    }

    /** Collects only a bounded directory, then preserves the existing sorted load/stamp order. */
    private static List<File> signatureFiles(File directory, final long collectionStarted) throws IOException {
        final List<File> files = new ArrayList<File>();
        final int[] visited = {0};
        final long started = System.nanoTime();
        DirectoryListing.forEachChild(directory, new DirectoryListing.Visitor() {
            @Override
            public void visit(File child) throws IOException {
                checkDeadline(collectionStarted);
                if (++visited[0] > MAX_DIRECTORY_ENTRIES
                        || System.nanoTime() - started >= DIRECTORY_LIST_NANOS) {
                    throw new DefinitionLimitException("signature directory entry or time limit reached");
                }
                if (child.isFile() && isSignatureFile(child.getName())) {
                    if (files.size() >= MAX_DEFINITION_FILES || child.getAbsolutePath().length() > 4096) {
                        throw new DefinitionLimitException("definition file count or path limit reached");
                    }
                    files.add(child);
                }
            }
        });
        Collections.sort(files);
        return files;
    }

    private void readFile(Source source, MessageDigest digest) throws IOException {
        File file = source.file;
        String name = file.getName();
        String ext = extensionOf(name);
        if (isPackedBundle(name)) {
            problem(name + " is a packed ClamAV bundle; unpack it first with sigtool --unpack");
            return;
        }
        if (!isSignatureFile(name)) {
            problem(name + " is not a signature file this scanner reads (.hdb .hsb .ndb .fp .sfp .ign2)");
            return;
        }
        source.header(digest);
        long count = 0;
        int lineNumber = 0;
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        boolean oversized = false;
        try (InputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int n;
            while (count < source.size) {
                checkDeadline(loadStarted);
                n = in.read(buffer, 0, (int) Math.min(buffer.length, source.size - count));
                if (n == -1) { break; }
                count += n;
                inputBytes += n;
                if (inputBytes > MAX_INPUT_BYTES || count > source.size) {
                    throw new IOException("definition input byte limit or mutation detected");
                }
                digest.update(buffer, 0, n);
                for (int i = 0; i < n; i++) {
                    if (buffer[i] == '\n') {
                        finishLine(name, ext, line, oversized, ++lineNumber);
                        line.reset();
                        oversized = false;
                    } else if (line.size() < MAX_LINE_CHARS * 4) {
                        line.write(buffer[i]);
                    } else {
                        oversized = true;
                    }
                }
            }
        }
        if (line.size() > 0 || oversized) {
            finishLine(name, ext, line, oversized, ++lineNumber);
        }
        source.verify(count);
        files.add(name);
        newestMillis = Math.max(newestMillis, source.modified);
    }

    private void finishLine(String file, String ext, ByteArrayOutputStream bytes,
            boolean oversized, int number) {
        if (oversized) { unsupported++; return; }
        String line = Bytes.text(bytes.toByteArray());
        if (line.length() > MAX_LINE_CHARS) { unsupported++; return; }
        line = line.trim();
        if (line.length() > 0 && line.charAt(0) != '#') { readLine(file, ext, line, number); }
    }

    /** Conservative allocation allowance: includes construction, sorting, indexes and UTF-16 names. */
    private boolean reserve(long bytes) {
        if (retainedEntries >= MAX_RETAINED_ENTRIES || bytes > MAX_RETAINED_BYTES - retainedBytes) {
            capped++;
            if (capped == 1) {
                problem("definition retained entry or memory limit reached (" + MAX_RETAINED_ENTRIES
                        + " entries, " + Bytes.humanSize(MAX_RETAINED_BYTES) + ")");
            }
            return false;
        }
        retainedEntries++;
        retainedBytes += bytes;
        return true;
    }

    private void readLine(String fileName, String ext, String line, int lineNumber) {
        if (ext.equals("ign2")) {
            if (!ignoredNames.contains(line) && reserve(192L + 4L * line.length())) {
                ignoredNames.add(line);
            }
            return;
        }
        if (ext.equals("ndb") || ext.equals("ndu")) {
            readPattern(fileName, line, lineNumber);
            return;
        }
        // Every hash format is digest:size:name, with optional trailing fields.
        String[] parts = line.split(":", -1);
        if (parts.length < 3) {
            unsupported++;
            problem(fileName + ":" + lineNumber + " is not digest:size:name");
            return;
        }
        byte[] digest = Bytes.fromHex(parts[0].trim());
        long size = parseSize(parts[1].trim());
        String name = parts[2].trim();
        if (digest == null || size == Long.MIN_VALUE || name.length() == 0) {
            unsupported++;
            problem(fileName + ":" + lineNumber + " has an unreadable digest, size or name");
            return;
        }
        boolean clean = ext.equals("fp") || ext.equals("sfp");
        HashTable table;
        if (digest.length == 16) {
            table = clean ? cleanMd5 : md5;
        } else if (digest.length == 20) {
            table = clean ? cleanSha1 : sha1;
        } else if (digest.length == 32) {
            table = clean ? cleanSha256 : sha256;
        } else {
            unsupported++;
            problem(fileName + ":" + lineNumber + " digest is not MD5, SHA-1 or SHA-256");
            return;
        }
        if (!clean && hashCount() >= MAX_HASHES) {
            capped++;
            return;
        }
        if (reserve(320L + 4L * name.length())) { table.add(digest, size, name); }
    }

    private void readPattern(String fileName, String line, int lineNumber) {
        String[] parts = line.split(":", -1);
        if (parts.length < 4) {
            unsupported++;
            problem(fileName + ":" + lineNumber + " is not name:target:offset:pattern");
            return;
        }
        String name = parts[0].trim();
        int target;
        try {
            target = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            unsupported++;
            problem(fileName + ":" + lineNumber + " has an unreadable target type");
            return;
        }
        if (!supportedTarget(target)) {
            // Mail, and the internal target types newer ClamAV releases added, describe files this
            // scanner never classifies a member as. Loading such a pattern would inflate the count
            // with entries that can never fire.
            unsupported++;
            return;
        }
        if (patterns.size() >= MAX_PATTERNS) {
            capped++;
            return;
        }
        try {
            String body = parts[3].trim();
            // Literal/gap positions need under 64 bytes per character, including compile scratch.
            // Alternatives allocate 256-byte membership tables per position: allow 192 per char.
            long allowance = 512L + 4L * name.length() + 64L * body.length();
            boolean alternative = false;
            for (int i = 0; i < body.length(); i++) {
                if (body.charAt(i) == '(') { alternative = true; }
                if (alternative) { allowance += 128; }
                if (body.charAt(i) == ')') { alternative = false; }
            }
            if (allowance > MAX_RETAINED_BYTES - retainedBytes
                    || retainedEntries >= MAX_RETAINED_ENTRIES) {
                reserve(allowance);
                return;
            }
            HexSignature signature = HexSignature.compile(name, target, parts[2].trim(), body);
            if (reserve(allowance)) { patterns.add(signature); }
        } catch (HexSignature.SyntaxException e) {
            unsupported++;
            problem(fileName + ":" + lineNumber + " " + e.getMessage());
        }
    }

    private static boolean supportedTarget(int target) {
        switch (target) {
            case HexSignature.TARGET_ANY:
            case TARGET_PE:
            case TARGET_OLE2:
            case TARGET_HTML:
            case TARGET_GRAPHICS:
            case TARGET_ELF:
            case TARGET_ASCII:
            case TARGET_MACHO:
            case TARGET_PDF:
            case TARGET_FLASH:
            case TARGET_JAVA:
                return true;
            default:
                return false;
        }
    }

    /** The size field: a number, or {@code *} for any size. Returns {@code Long.MIN_VALUE} if unreadable. */
    private static long parseSize(String text) {
        if (text.equals("*")) {
            return -1L;
        }
        try {
            long size = Long.parseLong(text);
            return size < 0 ? Long.MIN_VALUE : size;
        } catch (NumberFormatException e) {
            return Long.MIN_VALUE;
        }
    }

    /** Sorts the hash tables and buckets the patterns. Called once after loading. */
    private void index() {
        md5.index(ignoredNames);
        sha1.index(ignoredNames);
        sha256.index(ignoredNames);
        cleanMd5.index(Collections.<String>emptySet());
        cleanSha1.index(Collections.<String>emptySet());
        cleanSha256.index(Collections.<String>emptySet());

        List<List<HexSignature>> two = new ArrayList<List<HexSignature>>();
        List<List<HexSignature>> one = new ArrayList<List<HexSignature>>();
        for (int i = 0; i < 65536; i++) {
            two.add(null);
        }
        for (int i = 0; i < 256; i++) {
            one.add(null);
        }
        List<HexSignature> loose = new ArrayList<HexSignature>();
        List<HexSignature> pinned = new ArrayList<HexSignature>();
        java.util.Iterator<HexSignature> it = patterns.iterator();
        while (it.hasNext()) {
            HexSignature signature = it.next();
            if (ignoredNames.contains(signature.name())) {
                it.remove();
                continue;
            }
            if (signature.anchored()) {
                pinned.add(signature);
                continue;
            }
            int first = signature.firstByteHint();
            int second = signature.secondByteHint();
            if (first >= 0 && second >= 0) {
                int key = (first << 8) | second;
                if (two.get(key) == null) {
                    two.set(key, new ArrayList<HexSignature>());
                }
                two.get(key).add(signature);
            } else if (first >= 0) {
                if (one.get(first) == null) {
                    one.set(first, new ArrayList<HexSignature>());
                }
                one.get(first).add(signature);
            } else {
                loose.add(signature);
            }
        }
        byTwoBytes = toArrays(two);
        byOneByte = toArrays(one);
        unbucketed = loose.toArray(new HexSignature[loose.size()]);
        anchored = pinned.toArray(new HexSignature[pinned.size()]);
        indexed = true;
    }

    private static HexSignature[][] toArrays(List<List<HexSignature>> lists) {
        HexSignature[][] out = new HexSignature[lists.size()][];
        for (int i = 0; i < lists.size(); i++) {
            List<HexSignature> list = lists.get(i);
            out[i] = list == null ? null : list.toArray(new HexSignature[list.size()]);
        }
        return out;
    }

    // ------------------------------------------------------------------ matching

    /** True when there is nothing to match against. */
    public boolean isEmpty() {
        return hashCount() == 0 && patterns.isEmpty();
    }

    public boolean wantsMd5() {
        return !md5.isEmpty() || !cleanMd5.isEmpty();
    }

    public boolean wantsSha1() {
        return !sha1.isEmpty() || !cleanSha1.isEmpty();
    }

    public boolean wantsSha256() {
        return !sha256.isEmpty() || !cleanSha256.isEmpty();
    }

    /** True when any hash signature is loaded, so a caller knows whether to digest at all. */
    public boolean wantsHashes() {
        return wantsMd5() || wantsSha1() || wantsSha256();
    }

    /** Digests of {@code data} under exactly the algorithms this database needs. */
    public Digests digest(byte[] data) {
        return Digests.of(data, wantsMd5(), wantsSha1(), wantsSha256());
    }

    /** True when the file is on the clean list and must not be reported, whatever else matches. */
    public boolean isKnownClean(Digests digests, long size) {
        if (digests == null) {
            return false;
        }
        return cleanMd5.lookup(digests.md5(), size) != null
                || cleanSha1.lookup(digests.sha1(), size) != null
                || cleanSha256.lookup(digests.sha256(), size) != null;
    }

    /** The hash signature matching a whole file, or null. */
    public Match matchHash(Digests digests, long size) {
        if (digests == null) {
            return null;
        }
        String name = md5.lookup(digests.md5(), size);
        if (name == null) {
            name = sha1.lookup(digests.sha1(), size);
        }
        if (name == null) {
            name = sha256.lookup(digests.sha256(), size);
        }
        return name == null ? null : new Match(name, true);
    }

    /**
     * The byte patterns found in {@code data}, at most {@code limit} of them.
     *
     * <p>Bounded per position by the bucket index: at each byte only the patterns that could start
     * there are tried. Patterns that could start with anything are tried once each over the whole
     * blob, which is why they are worth keeping rare.
     */
    /** Matches retained before a cutoff remain valid; complete is independent of hits. */
    public static final class PatternResult {
        public final List<Match> hits;
        public final boolean complete;
        private PatternResult(List<Match> hits, boolean complete) {
            this.hits = Collections.unmodifiableList(hits); this.complete = complete;
        }
    }

    /** Legacy list view. Production scans use matchPatternsChecked to retain completeness. */
    public List<Match> matchPatterns(byte[] data, int fileType, int limit) {
        return matchPatternsChecked(data, fileType, limit).hits;
    }

    public PatternResult matchPatternsChecked(byte[] data, int fileType, int limit) {
        return matchPatternsChecked(data, fileType, limit, data == null ? -1L : data.length);
    }

    /** Match an admitted prefix without interpreting its boundary as the logical end of file. */
    public PatternResult matchPatternsChecked(byte[] data, int fileType, int limit, long logicalSize) {
        List<Match> out = new ArrayList<Match>();
        if (!indexed || data == null || data.length == 0 || patterns.isEmpty()) {
            return new PatternResult(out, true);
        }
        if (limit <= 0) return new PatternResult(out, false);
        Set<String> seen = new HashSet<String>();
        HexSignature.Work work = new HexSignature.Work(8 * HexSignature.MAX_STEPS);
        try {
            for (HexSignature signature : anchored) {
                work.step();
                if (signature.appliesTo(fileType) && signature.matches(data, work, logicalSize)) {
                    record(out, seen, signature);
                    if (out.size() >= limit) return new PatternResult(out, false);
                }
            }
            for (HexSignature signature : unbucketed) {
                work.step();
                if (signature.appliesTo(fileType) && signature.matches(data, work, logicalSize)) {
                    record(out, seen, signature);
                    if (out.size() >= limit) return new PatternResult(out, false);
                }
            }
            for (int at = 0; at < data.length; at++) {
                work.step();
                int first = data[at] & 0xFF;
                if (at + 1 < data.length) {
                    HexSignature[] bucket = byTwoBytes[(first << 8) | (data[at + 1] & 0xFF)];
                    if (bucket != null) tryBucket(bucket, data, at, fileType, out, seen, limit, work);
                }
                HexSignature[] bucket = byOneByte[first];
                if (bucket != null) tryBucket(bucket, data, at, fileType, out, seen, limit, work);
            }
            return new PatternResult(out, true);
        } catch (HexSignature.LimitReached cutoff) {
            return new PatternResult(out, false);
        }
    }

    private static void tryBucket(HexSignature[] bucket, byte[] data, int at, int fileType,
            List<Match> out, Set<String> seen, int limit, HexSignature.Work work) {
        for (HexSignature signature : bucket) {
            work.step();
            if (signature.appliesTo(fileType) && !seen.contains(signature.name())
                    && signature.matchesAt(data, at, work)) {
                record(out, seen, signature);
                if (out.size() >= limit) throw new HexSignature.LimitReached();
            }
        }
    }

    private static void record(List<Match> out, Set<String> seen, HexSignature signature) {
        if (seen.add(signature.name())) {
            out.add(new Match(signature.name(), false));
        }
    }

    /**
     * The ClamAV target type of a blob, from its leading bytes and, for text, its name.
     *
     * <p>Only kinds this scanner can recognise are returned; anything else is {@link
     * HexSignature#TARGET_ANY}, against which only untargeted patterns run. Text normalisation, which
     * ClamAV applies before matching its HTML and ASCII targets, is not done here, so a pattern for
     * those targets is matched against the raw bytes and may miss what ClamAV would catch.
     */
    public static int fileType(byte[] head, String extension) {
        if (head == null || head.length < 4) {
            return HexSignature.TARGET_ANY;
        }
        if (head[0] == 'M' && head[1] == 'Z') {
            return TARGET_PE;
        }
        if (Bytes.looksLikeElf(head)) {
            return TARGET_ELF;
        }
        int b0 = head[0] & 0xFF;
        int b1 = head[1] & 0xFF;
        int b2 = head[2] & 0xFF;
        int b3 = head[3] & 0xFF;
        if (b0 == 0xCA && b1 == 0xFE && b2 == 0xBA && b3 == 0xBE) {
            return TARGET_JAVA;
        }
        if ((b0 == 0xFE && b1 == 0xED && b2 == 0xFA && (b3 == 0xCE || b3 == 0xCF))
                || ((b0 == 0xCE || b0 == 0xCF) && b1 == 0xFA && b2 == 0xED && b3 == 0xFE)) {
            return TARGET_MACHO;
        }
        if (head[0] == '%' && head[1] == 'P' && head[2] == 'D' && head[3] == 'F') {
            return TARGET_PDF;
        }
        if (b0 == 0xD0 && b1 == 0xCF && b2 == 0x11 && b3 == 0xE0) {
            return TARGET_OLE2;
        }
        if ((head[0] == 'F' || head[0] == 'C' || head[0] == 'Z') && head[1] == 'W' && head[2] == 'S') {
            return TARGET_FLASH;
        }
        String kind = Bytes.detectKind(head);
        if ("png".equals(kind) || "jpeg".equals(kind) || "gif".equals(kind) || "webp".equals(kind)
                || "bmp".equals(kind)) {
            return TARGET_GRAPHICS;
        }
        if (kind != null) {
            return HexSignature.TARGET_ANY;
        }
        String ext = extension == null ? "" : extension.toLowerCase(Locale.US);
        if (ext.equals("html") || ext.equals("htm") || startsWithIgnoreCase(head, "<!DOCTYPE html")
                || startsWithIgnoreCase(head, "<html")) {
            return TARGET_HTML;
        }
        return looksLikeText(head) ? TARGET_ASCII : HexSignature.TARGET_ANY;
    }

    private static boolean startsWithIgnoreCase(byte[] head, String prefix) {
        if (head.length < prefix.length()) {
            return false;
        }
        for (int i = 0; i < prefix.length(); i++) {
            if (Character.toLowerCase((char) (head[i] & 0xFF)) != Character.toLowerCase(prefix.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /** Text: no NUL and nearly everything printable or whitespace in the first few hundred bytes. */
    private static boolean looksLikeText(byte[] head) {
        int limit = Math.min(head.length, 512);
        int odd = 0;
        for (int i = 0; i < limit; i++) {
            int b = head[i] & 0xFF;
            if (b == 0) {
                return false;
            }
            if (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
                odd++;
            }
        }
        return odd * 20 < limit;
    }

    // ------------------------------------------------------------------ description

    /** Names of the files that were loaded, in the order they were read. */
    public List<String> files() {
        return files;
    }

    public int fileCount() {
        return files.size();
    }

    public int hashCount() {
        return md5.size() + sha1.size() + sha256.size();
    }

    public int patternCount() {
        return patterns.size();
    }

    /** Entries in the clean list, which suppress reports rather than produce them. */
    public int cleanCount() {
        return cleanMd5.size() + cleanSha1.size() + cleanSha256.size();
    }

    /** Accepted entries across all classes; includes entries later disabled by ign2. */
    public int retainedEntryCount() { return retainedEntries; }

    /** Conservative allocation high-water allowance, not a measured JVM heap size. */
    public long retainedBytes() { return retainedBytes; }

    public long inputBytes() { return inputBytes; }

    public int ignoredCount() { return ignoredNames.size(); }

    public boolean complete() { return problems.isEmpty() && unsupported == 0 && capped == 0; }

    /** Lines that were readable but use syntax or targets this scanner does not implement. */
    public int unsupportedCount() {
        return unsupported;
    }

    /** Entries refused because a cap was reached. */
    public int cappedCount() {
        return capped;
    }

    /** Problems worth showing the user, at most a screenful. */
    public List<String> problems() {
        return problems;
    }

    /** When the newest loaded file was last written, in epoch milliseconds, or 0 with no files. */
    public long newestMillis() {
        return newestMillis;
    }

    private void problem(String message) {
        if (message.length() > MAX_PROBLEM_CHARS) {
            message = message.substring(0, MAX_PROBLEM_CHARS) + "...";
        }
        if (problems.size() < MAX_PROBLEMS - 1) {
            problems.add(message);
        } else if (problems.size() == MAX_PROBLEMS - 1) {
            problems.add("more problems than can be listed here");
        }
    }

    private static String extensionOf(String name) {
        int dot = name.lastIndexOf('.');
        return dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.US);
    }

    /** Unsigned lexicographic comparison of two digests. */
    static int compareDigests(byte[] a, int aOffset, byte[] b, int bOffset, int width) {
        for (int i = 0; i < width; i++) {
            int x = a[aOffset + i] & 0xFF;
            int y = b[bOffset + i] & 0xFF;
            if (x != y) {
                return x - y;
            }
        }
        return 0;
    }
}
