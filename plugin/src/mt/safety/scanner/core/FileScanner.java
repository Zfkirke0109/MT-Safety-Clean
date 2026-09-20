package mt.safety.scanner.core;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Checks ordinary files, not just plugin packages, against a signature database.
 *
 * <p>A plugin runs inside MT Manager, so what it can reach is what MT Manager can reach: the
 * download folder, MT Manager's own storage, and whatever the user has pointed it at. Malware that
 * arrives on a phone rarely arrives as an MT plugin; it arrives as an APK in Downloads. This walks
 * those folders and asks the signature database about every file it can read, the way a desktop
 * antivirus scans a folder.
 *
 * <p>Only signatures apply here. The capability rules are written for plugin packages and would say
 * nothing useful about a photo or a PDF. And everything is bounded: the walk stops at a number of
 * entries, a depth, a hit count, and the scan budget, and the result says which limit it hit,
 * because a scan that quietly covered half a folder is worse than one that says so.
 */
public final class FileScanner {

    /** Directory entries looked at before the walk stops. */
    public static final int MAX_VISITED = 50000;
    public static final int MAX_DEPTH = 16;
    /** Hits reported before the walk stops; past this the answer is already "clean this up". */
    public static final int MAX_HITS = 200;
    private static final int MAX_PROBLEMS = 20;
    private static final int MAX_QUEUE = 20000;

    /** How much of each file is read into memory for pattern matching. */
    public static final int PATTERN_BYTES = 4 * 1024 * 1024;
    /** Members of an archive are read up to this much each, and this many of them. */
    private static final int ARCHIVE_MEMBER_BYTES = 1024 * 1024;
    private static final int MAX_ARCHIVE_MEMBERS = 500;
    /** Distinct patterns reported per file. */
    private static final int MAX_PATTERN_HITS = 3;

    /** One file, or one member of an archive, that matched. */
    public static final class Hit {
        public final String path;
        /** The member inside an archive, or an empty string for the file itself. */
        public final String member;
        public final String signature;
        public final boolean hash;
        public final boolean pua;
        public final long size;

        Hit(String path, String member, SignatureDatabase.Match match, long size) {
            this.path = path;
            this.member = member;
            this.signature = match.name;
            this.hash = match.hash;
            this.pua = match.pua;
            this.size = size;
        }

        /** {@code path} or {@code path!member}, the way the plugin scan names nested evidence. */
        public String location() {
            return member.length() == 0 ? path : path + "!" + member;
        }
    }

    /** Why a walk stopped before it ran out of files. */
    public enum Stop {
        /** It did not; every reachable file was checked. */
        NONE,
        /** The scan budget's time or byte allowance ran out. */
        BUDGET,
        /** More entries than the walk will visit. */
        COUNT,
        /** Enough hits to stop counting. */
        HITS
    }

    /** What a walk found and how far it got. */
    public static final class Result {
        public final List<String> roots = new ArrayList<String>();
        public int filesSeen;
        public int filesScanned;
        public int archivesOpened;
        public long bytesRead;
        public Stop stoppedBecause = Stop.NONE;
        public final List<Hit> hits = new ArrayList<Hit>();
        public final List<String> problems = new ArrayList<String>();
        public long elapsedMs;

        public boolean truncated() {
            return stoppedBecause != Stop.NONE;
        }

        void problem(String message) {
            if (problems.size() < MAX_PROBLEMS - 1) {
                problems.add(message);
            } else if (problems.size() == MAX_PROBLEMS - 1) {
                problems.add("more problems than can be listed here");
            }
        }
    }

    /** One directory waiting to be listed. */
    private static final class Pending {
        final File dir;
        final int depth;
        final String rootCanonical;

        Pending(File dir, int depth, String rootCanonical) {
            this.dir = dir;
            this.depth = depth;
            this.rootCanonical = rootCanonical;
        }
    }

    private final SignatureDatabase signatures;

    public FileScanner(SignatureDatabase signatures) {
        this.signatures = signatures == null ? SignatureDatabase.empty() : signatures;
    }

    /**
     * Walks every root and checks each readable file.
     *
     * <p>Breadth first, so that with a budget too small for everything the files near the top of each
     * root, which is where downloads land, are checked before a deep media folder consumes the rest.
     *
     * @param excludedArea a directory to skip entirely, typically the scanner's own, or null
     */
    public Result scan(List<File> roots, File excludedArea, ScanBudget budget) {
        long started = System.currentTimeMillis();
        Result result = new Result();
        String excluded = excludedArea == null ? "" : canonical(excludedArea);
        List<Pending> queue = new ArrayList<Pending>();
        int visited = 0;

        for (int i = 0; i < roots.size(); i++) {
            File root = roots.get(i);
            if (root == null || !root.exists() || !root.canRead()) {
                continue;
            }
            result.roots.add(root.getAbsolutePath());
            if (root.isFile()) {
                scanFile(root, result, budget);
            } else if (root.isDirectory()) {
                queue.add(new Pending(root, 0, canonical(root)));
            }
        }

        int head = 0;
        while (head < queue.size() && result.stoppedBecause == Stop.NONE) {
            if (budget.exhausted()) {
                result.stoppedBecause = Stop.BUDGET;
                break;
            }
            Pending pending = queue.get(head++);
            if (isUnder(pending.dir, excluded)) {
                continue;
            }
            File[] children = pending.dir.listFiles();
            if (children == null) {
                result.problem("could not list " + pending.dir.getAbsolutePath());
                continue;
            }
            Arrays.sort(children);
            for (int i = 0; i < children.length; i++) {
                File child = children[i];
                if (++visited > MAX_VISITED) {
                    result.stoppedBecause = Stop.COUNT;
                    break;
                }
                if (escapes(child, pending.rootCanonical)) {
                    // A link out of the root leads somewhere the user did not point at.
                    continue;
                }
                if (child.isDirectory()) {
                    if (pending.depth + 1 > MAX_DEPTH || queue.size() >= MAX_QUEUE) {
                        result.stoppedBecause = Stop.COUNT;
                        break;
                    }
                    queue.add(new Pending(child, pending.depth + 1, pending.rootCanonical));
                } else if (child.isFile()) {
                    if (budget.exhausted()) {
                        result.stoppedBecause = Stop.BUDGET;
                        break;
                    }
                    scanFile(child, result, budget);
                    if (result.hits.size() >= MAX_HITS) {
                        result.stoppedBecause = Stop.HITS;
                        break;
                    }
                }
            }
        }
        // Directories still queued when the loop ended were never listed.
        if (result.stoppedBecause == Stop.NONE && head < queue.size()) {
            result.stoppedBecause = Stop.BUDGET;
        }
        result.elapsedMs = System.currentTimeMillis() - started;
        return result;
    }

    private void scanFile(File file, Result result, ScanBudget budget) {
        long size = file.length();
        result.filesSeen++;
        if (size <= 0) {
            return;
        }
        int granted = budget.reserve((int) Math.min(size, (long) PATTERN_BYTES));
        if (granted <= 0) {
            result.stoppedBecause = Stop.BUDGET;
            return;
        }
        byte[] data;
        try {
            InputStream in = new BufferedInputStream(new FileInputStream(file));
            try {
                data = Bytes.readAtMost(in, granted);
            } finally {
                PluginPackage.closeQuietly(in);
            }
        } catch (IOException e) {
            result.problem("could not read " + file.getAbsolutePath() + ": " + e.getMessage());
            return;
        }
        if (data.length == 0) {
            return;
        }
        result.bytesRead += data.length;
        result.filesScanned++;

        Digests digests = null;
        if (signatures.wantsHashes()) {
            if (data.length >= size) {
                digests = signatures.digest(data);
            } else if (size <= PluginPackage.MAX_HASHED_LENGTH) {
                digests = hashWhole(file, data, size, result, budget);
            }
        }
        String path = file.getAbsolutePath();
        if (check(path, "", data, digests, size, extensionOf(file.getName()), result)) {
            return;
        }
        if (Bytes.looksLikeZip(data)) {
            scanArchive(file, result, budget);
        }
    }

    /**
     * Applies the database to one blob and records what matched.
     *
     * @return true when the blob was recognised, by a hash either way, so nothing more is needed
     */
    private boolean check(String path, String member, byte[] data, Digests digests, long size,
            String extension, Result result) {
        if (digests != null) {
            if (signatures.isKnownClean(digests, size)) {
                return true;
            }
            SignatureDatabase.Match hit = signatures.matchHash(digests, size);
            if (hit != null) {
                result.hits.add(new Hit(path, member, hit, size));
                return true;
            }
        }
        int fileType = SignatureDatabase.fileType(data, extension);
        List<SignatureDatabase.Match> hits = signatures.matchPatterns(data, fileType, MAX_PATTERN_HITS);
        for (int i = 0; i < hits.size(); i++) {
            result.hits.add(new Hit(path, member, hits.get(i), size));
        }
        return false;
    }

    /**
     * Digests a file larger than the in-memory read, continuing from where that read stopped.
     *
     * <p>Charged to the budget the way a package hash is, and abandoned if the deadline passes: a
     * hash of part of a file identifies nothing, so there is no partial answer worth keeping.
     */
    private Digests hashWhole(File file, byte[] head, long size, Result result, ScanBudget budget) {
        if (!PluginPackage.affordableToHash(size - head.length, budget)) {
            return null;
        }
        Digests digests = new Digests(signatures.wantsMd5(), signatures.wantsSha1(), signatures.wantsSha256());
        digests.update(head, 0, head.length);
        try {
            InputStream in = new BufferedInputStream(new FileInputStream(file));
            try {
                long toSkip = head.length;
                while (toSkip > 0) {
                    long skipped = in.skip(toSkip);
                    if (skipped <= 0) {
                        // Some streams refuse to skip; read and discard instead.
                        byte[] scratch = new byte[(int) Math.min(toSkip, 65536L)];
                        int n = in.read(scratch);
                        if (n <= 0) {
                            return null;
                        }
                        skipped = n;
                    }
                    toSkip -= skipped;
                }
                byte[] buffer = new byte[1 << 16];
                int n;
                long sinceCheck = 0;
                while ((n = in.read(buffer)) > 0) {
                    digests.update(buffer, 0, n);
                    result.bytesRead += n;
                    sinceCheck += n;
                    if (sinceCheck >= (1 << 22)) {
                        sinceCheck = 0;
                        if (budget.exhausted()) {
                            return null;
                        }
                    }
                }
            } finally {
                PluginPackage.closeQuietly(in);
            }
        } catch (IOException e) {
            result.problem("could not hash " + file.getAbsolutePath() + ": " + e.getMessage());
            return null;
        }
        digests.finish();
        return digests;
    }

    /**
     * Looks inside an archive, because an APK's malware is in its {@code classes.dex}, not in the
     * zip container's bytes.
     */
    private void scanArchive(File file, Result result, ScanBudget budget) {
        PluginPackage pkg = null;
        try {
            pkg = PluginPackage.open(file);
            List<PluginPackage.Entry> entries = pkg.entries();
            result.archivesOpened++;
            int count = 0;
            for (int i = 0; i < entries.size(); i++) {
                PluginPackage.Entry entry = entries.get(i);
                if (entry.directory || entry.size <= 0) {
                    continue;
                }
                if (++count > MAX_ARCHIVE_MEMBERS || result.hits.size() >= MAX_HITS) {
                    break;
                }
                if (budget.exhausted()) {
                    result.stoppedBecause = Stop.BUDGET;
                    break;
                }
                byte[] member = pkg.read(entry, ARCHIVE_MEMBER_BYTES, budget);
                if (member.length == 0) {
                    continue;
                }
                result.bytesRead += member.length;
                Digests digests = null;
                if (signatures.wantsHashes() && member.length >= entry.size) {
                    digests = signatures.digest(member);
                }
                check(file.getAbsolutePath(), entry.name, member, digests, entry.size, entry.extension(), result);
            }
        } catch (IOException e) {
            result.problem("could not open " + file.getAbsolutePath() + ": " + e.getMessage());
        } catch (RuntimeException e) {
            // A malformed archive is data, not a reason to stop the walk.
            result.problem("could not read inside " + file.getAbsolutePath() + ": " + e);
        } finally {
            if (pkg != null) {
                pkg.close();
            }
        }
    }

    private static boolean isUnder(File dir, String area) {
        if (area.length() == 0) {
            return false;
        }
        String path = canonical(dir);
        return path.equals(area) || path.startsWith(area + File.separator);
    }

    private static boolean escapes(File child, String rootCanonical) {
        if (rootCanonical.length() == 0) {
            return false;
        }
        String path = canonical(child);
        return !path.equals(rootCanonical) && !path.startsWith(rootCanonical + File.separator);
    }

    private static String canonical(File file) {
        try {
            return file.getCanonicalPath();
        } catch (IOException e) {
            return file.getAbsolutePath();
        }
    }

    private static String extensionOf(String name) {
        int dot = name.lastIndexOf('.');
        return dot < 0 || dot == name.length() - 1 ? "" : name.substring(dot + 1).toLowerCase(Locale.US);
    }
}
