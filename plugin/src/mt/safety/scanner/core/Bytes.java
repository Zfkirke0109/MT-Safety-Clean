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

    /** Streaming SHA-256; the stream is not closed. */
    public static String sha256(InputStream in) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
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

    /** True when the blob starts with the ZIP local-header magic, i.e. it is an apk/jar/mtp. */
    public static boolean looksLikeZip(byte[] data) {
        return data.length >= 4 && data[0] == 'P' && data[1] == 'K'
                && (data[2] == 3 || data[2] == 5 || data[2] == 7);
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
