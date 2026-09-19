package mt.safety.scanner.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Byte-level helpers used by the detection rules.
 *
 * <p>Everything here avoids APIs that are missing on old Android (no {@code java.nio.file}, no
 * {@code java.util.Base64}, which only arrived in API 26) so the same code runs inside MT Manager
 * on Android 5 and on a desktop JVM under test.
 */
public final class Bytes {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Bytes() {
    }

    /** Reads at most {@code limit} bytes from {@code in}; never throws on a short stream. */
    public static byte[] readAtMost(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(limit, 1 << 16));
        byte[] buf = new byte[8192];
        int total = 0;
        while (total < limit) {
            int want = Math.min(buf.length, limit - total);
            int n = in.read(buf, 0, want);
            if (n < 0) {
                break;
            }
            out.write(buf, 0, n);
            total += n;
        }
        return out.toByteArray();
    }

    /** Lowercase hex SHA-256 of {@code data}. */
    public static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return hex(md.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** How often the streaming hash stops to ask whether the scan still has time. */
    private static final int HASH_DEADLINE_CHECK_BYTES = 1 << 22;

    /** Streaming SHA-256; the stream is not closed. */
    public static String sha256(InputStream in) throws IOException {
        return sha256(in, null);
    }

    /**
     * Streaming SHA-256 that abandons the digest rather than outrunning the scan's deadline.
     *
     * <p>The byte allowance alone cannot bound this. Hashing is charged at a fraction of a file's
     * length (see {@code PluginPackage.hashCost}) so that reserving it does not starve the rules that
     * run afterwards, which means a reservation the budget grants can still stand for hundreds of
     * megabytes of actual reading. On MT Manager's UI thread that is a freeze. So the loop rechecks
     * the budget as it goes and gives up if the deadline passes, returning no hash at all: the report
     * already treats an empty hash as an identity it could not establish, and keeps such a package out
     * of any destructive plan.
     *
     * @param budget the scan budget to respect, or {@code null} to hash unconditionally
     * @return the hex digest, or {@code ""} if the budget ran out before the stream ended
     */
    public static String sha256(InputStream in, ScanBudget budget) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[1 << 16];
            int n;
            int sinceCheck = 0;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
                if (budget == null) {
                    continue;
                }
                sinceCheck += n;
                if (sinceCheck >= HASH_DEADLINE_CHECK_BYTES) {
                    sinceCheck = 0;
                    if (budget.exhausted()) {
                        return "";
                    }
                }
            }
            return hex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (int i = 0; i < data.length; i++) {
            int b = data[i] & 0xFF;
            sb.append(HEX[b >>> 4]).append(HEX[b & 0x0F]);
        }
        return sb.toString();
    }

    /**
     * Decodes {@code data} as text for pattern matching.
     *
     * <p>Source files are UTF-8 in practice, but a package under suspicion may contain anything, so
     * malformed sequences are replaced rather than raising. Compiled artefacts are handled by
     * {@link #extractStrings} instead.
     */
    public static String text(byte[] data) {
        try {
            return new String(data, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return new String(data);
        }
    }

    /**
     * Pulls printable ASCII runs out of a binary blob.
     *
     * <p>This is how compiled code (a {@code .jar}'s class files, a {@code .dex}) is searched: DEX
     * and class constant pools store method and class names as length-prefixed MUTF-8, so a plain
     * scan for printable runs surfaces {@code Ljava/lang/Runtime;}, URLs and file paths without
     * needing a real DEX parser.
     *
     * @param minRun shortest run to keep, in characters
     */
    public static List<String> extractStrings(byte[] data, int minRun) {
        List<String> out = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            int c = data[i] & 0xFF;
            if (c >= 0x20 && c < 0x7F) {
                current.append((char) c);
            } else {
                if (current.length() >= minRun) {
                    out.add(current.toString());
                }
                current.setLength(0);
            }
        }
        if (current.length() >= minRun) {
            out.add(current.toString());
        }
        return out;
    }

    /** Joins extracted strings with newlines so one regex pass can cover a whole binary. */
    public static String extractedText(byte[] data, int minRun) {
        List<String> parts = extractStrings(data, minRun);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            sb.append(parts.get(i)).append('\n');
        }
        return sb.toString();
    }

    /**
     * Shannon entropy of {@code data} in bits per byte, 0.0 to 8.0.
     *
     * <p>Used to tell an ordinary asset from an encrypted or packed payload: text sits near 4-5,
     * compressed or encrypted data near 7.9.
     */
    public static double entropy(byte[] data) {
        if (data.length == 0) {
            return 0.0;
        }
        int[] counts = new int[256];
        for (int i = 0; i < data.length; i++) {
            counts[data[i] & 0xFF]++;
        }
        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (counts[i] == 0) {
                continue;
            }
            double p = (double) counts[i] / (double) data.length;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }

    /**
     * Decodes standard or URL-safe Base64, ignoring whitespace.
     *
     * @return the decoded bytes, or null when {@code text} is not valid Base64
     */
    public static byte[] base64Decode(String text) {
        if (text == null) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(text.length() * 3 / 4 + 3);
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
                continue;
            }
            if (c == '=') {
                break;
            }
            int value = base64Value(c);
            if (value < 0) {
                return null;
            }
            buffer = (buffer << 6) | value;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((buffer >> bits) & 0xFF);
            }
        }
        return out.toByteArray();
    }

    private static int base64Value(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+' || c == '-') {
            return 62;
        }
        if (c == '/' || c == '_') {
            return 63;
        }
        return -1;
    }

    /**
     * Identifies a blob by its leading magic bytes, independent of what it is called.
     *
     * <p>Renaming a payload is the oldest trick there is, so every decision about what a member "is"
     * goes through this rather than through its file extension.
     *
     * @return one of {@code dex}, {@code elf}, {@code class}, {@code zip}, {@code png}, {@code jpeg},
     *         {@code gif}, {@code webp}, {@code ogg}, {@code mp3}, or null when nothing is recognised
     */
    public static String detectKind(byte[] head) {
        if (looksLikeDex(head)) {
            return "dex";
        }
        if (looksLikeElf(head)) {
            return "elf";
        }
        if (head.length >= 4 && (head[0] & 0xFF) == 0xCA && (head[1] & 0xFF) == 0xFE
                && (head[2] & 0xFF) == 0xBA && (head[3] & 0xFF) == 0xBE) {
            return "class";
        }
        if (looksLikeZip(head)) {
            return "zip";
        }
        if (head.length >= 8 && (head[0] & 0xFF) == 0x89 && head[1] == 'P' && head[2] == 'N'
                && head[3] == 'G') {
            return "png";
        }
        if (head.length >= 3 && (head[0] & 0xFF) == 0xFF && (head[1] & 0xFF) == 0xD8
                && (head[2] & 0xFF) == 0xFF) {
            return "jpeg";
        }
        if (head.length >= 4 && head[0] == 'G' && head[1] == 'I' && head[2] == 'F' && head[3] == '8') {
            return "gif";
        }
        if (head.length >= 12 && head[0] == 'R' && head[1] == 'I' && head[2] == 'F' && head[3] == 'F'
                && head[8] == 'W' && head[9] == 'E' && head[10] == 'B' && head[11] == 'P') {
            return "webp";
        }
        if (head.length >= 4 && head[0] == 'O' && head[1] == 'g' && head[2] == 'g' && head[3] == 'S') {
            return "ogg";
        }
        if (head.length >= 3 && head[0] == 'I' && head[1] == 'D' && head[2] == '3') {
            return "mp3";
        }
        if (head.length >= 2 && head[0] == 'B' && head[1] == 'M') {
            return "bmp";
        }
        if (head.length >= 12 && head[0] == 'R' && head[1] == 'I' && head[2] == 'F' && head[3] == 'F'
                && head[8] == 'W' && head[9] == 'A' && head[10] == 'V' && head[11] == 'E') {
            return "wav";
        }
        if (head.length >= 12 && head[4] == 'f' && head[5] == 't' && head[6] == 'y' && head[7] == 'p') {
            return "mp4";
        }
        if (head.length >= 4 && head[0] == 'w' && head[1] == 'O' && head[2] == 'F' && head[3] == 'F') {
            return "woff";
        }
        if (head.length >= 4 && head[0] == 'w' && head[1] == 'O' && head[2] == 'F' && head[3] == '2') {
            return "woff2";
        }
        if (head.length >= 4 && head[0] == 'O' && head[1] == 'T' && head[2] == 'T' && head[3] == 'O') {
            return "otf";
        }
        if (head.length >= 4 && ((head[0] == 0x00 && head[1] == 0x01 && head[2] == 0x00 && head[3] == 0x00)
                || (head[0] == 't' && head[1] == 'r' && head[2] == 'u' && head[3] == 'e')
                || (head[0] == 't' && head[1] == 't' && head[2] == 'c' && head[3] == 'f'))) {
            return "ttf";
        }
        return null;
    }

    /**
     * True when a member's contents match what its file name claims.
     *
     * <p>Unrecognised contents count as consistent: plenty of legitimate members (text, fonts, raw
     * data) have no magic number, and treating every one of them as a disguise would bury the user in
     * noise. What this rules out is the case that matters, contents that are recognisably something
     * else.
     */
    public static boolean contentMatchesExtension(String extension, byte[] head) {
        String kind = detectKind(head);
        if (kind == null) {
            return true;
        }
        String ext = extension == null ? "" : extension.toLowerCase(java.util.Locale.US);
        if (kind.equals("zip")) {
            // Every one of these formats legitimately is a zip.
            return ext.equals("zip") || ext.equals("jar") || ext.equals("apk") || ext.equals("mtp")
                    || ext.equals("aar") || ext.equals("docx") || ext.equals("xlsx")
                    || ext.equals("odt") || ext.equals("epub");
        }
        if (kind.equals("jpeg")) {
            return ext.equals("jpg") || ext.equals("jpeg");
        }
        if (kind.equals("mp3")) {
            return ext.equals("mp3");
        }
        if (kind.equals("ogg")) {
            return ext.equals("ogg") || ext.equals("oga");
        }
        if (kind.equals("mp4")) {
            return ext.equals("mp4") || ext.equals("m4a") || ext.equals("m4v") || ext.equals("mov");
        }
        if (kind.equals("ttf")) {
            // A TrueType collection and a bare TrueType font share this signature.
            return ext.equals("ttf") || ext.equals("ttc") || ext.equals("otf");
        }
        return kind.equals(ext);
    }

    /** True when the blob starts with the ZIP local-header magic, i.e. it is an apk/jar/mtp. */
    public static boolean looksLikeZip(byte[] data) {
        if (data.length < 4 || data[0] != 'P' || data[1] != 'K') {
            return false;
        }
        // Both signature bytes, not just the first: PK\3\4 is a local header, PK\5\6 an end-of-central
        // directory, PK\7\8 a spanning marker. Checking one of the pair matches data that merely
        // begins "PK" followed by a stray 3, 5 or 7.
        return (data[2] == 3 && data[3] == 4)
                || (data[2] == 5 && data[3] == 6)
                || (data[2] == 7 && data[3] == 8);
    }

    /** True when the blob starts with the Dalvik executable magic. */
    public static boolean looksLikeDex(byte[] data) {
        return data.length >= 8 && data[0] == 'd' && data[1] == 'e' && data[2] == 'x' && data[3] == '\n';
    }

    /** True when the blob starts with the ELF magic, i.e. a native {@code .so} or executable. */
    public static boolean looksLikeElf(byte[] data) {
        return data.length >= 4 && (data[0] & 0xFF) == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
    }

    /** Human readable size, for report lines. */
    public static String humanSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        if (bytes < 1024L * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        }
        return String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}
