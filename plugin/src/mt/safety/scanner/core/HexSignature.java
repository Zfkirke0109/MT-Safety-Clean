package mt.safety.scanner.core;

import java.util.ArrayList;
import java.util.List;

/**
 * One ClamAV-style byte-pattern signature, compiled for matching.
 *
 * <p>This is the body of an {@code .ndb} entry: a hex string that may contain wildcards, plus the
 * offset it must be found at and the kind of file it is written for. Supporting the real format
 * rather than inventing one matters, because it means a user can take a signature set published by
 * someone else and use it here unchanged.
 *
 * <p>Supported syntax, which is the part of ClamAV's format that carries essentially all published
 * signatures:
 *
 * <ul>
 *   <li>{@code aabbcc} - literal bytes.</li>
 *   <li>{@code ??} - any one byte; {@code a?} and {@code ?a} - one byte with a fixed nibble.</li>
 *   <li>{@code *} - any number of bytes, including none.</li>
 *   <li>{@code {n}} - exactly n bytes; {@code {n-m}}, {@code {-m}}, {@code {n-}} - a range.</li>
 *   <li>{@code (aa|bb|cc)} - any one of several alternatives, each the same length.</li>
 *   <li>Offsets {@code *}, {@code n}, {@code n,m} (n with up to m bytes of shift) and {@code EOF-n}.</li>
 * </ul>
 *
 * <p>A signature that uses syntax outside this set is rejected at parse time and counted, rather than
 * silently matching nothing: a signature set that is quietly half-loaded is worse than one that says
 * what it could not read.
 */
public final class HexSignature {

    /** Thrown for a pattern this implementation cannot represent. */
    public static class SyntaxException extends Exception {
        private static final long serialVersionUID = 1L;

        public SyntaxException(String message) {
            super(message);
        }
    }

    /**
     * One run of byte positions with no wildcard gap inside it.
     *
     * <p>Stored as a value and a mask per position rather than a 256-entry table per position: a
     * signature database holds tens of thousands of these, and on a phone the difference is the
     * difference between loading and running out of memory. Alternatives, which are rare, get a table
     * only at the positions that use them.
     */
    private static final class Block {
        final byte[] value;
        final byte[] mask;
        final boolean[][] alternatives;

        Block(byte[] value, byte[] mask, boolean[][] alternatives) {
            this.value = value;
            this.mask = mask;
            this.alternatives = alternatives;
        }

        int length() {
            return value.length;
        }

        boolean matchesAt(byte[] data, int at) {
            if (at < 0 || at + value.length > data.length) {
                return false;
            }
            for (int i = 0; i < value.length; i++) {
                int b = data[at + i] & 0xFF;
                boolean[] allowed = alternatives == null ? null : alternatives[i];
                if (allowed != null) {
                    if (!allowed[b]) {
                        return false;
                    }
                } else if ((b & (mask[i] & 0xFF)) != (value[i] & 0xFF)) {
                    return false;
                }
            }
            return true;
        }
    }

    /** A gap between blocks: anywhere from {@code min} to {@code max} bytes. */
    private static final class Gap {
        final int min;
        final int max;

        Gap(int min, int max) {
            this.min = min;
            this.max = max;
        }
    }

    /** One position under construction: value, mask, and an optional alternative table. */
    private static final class Position {
        byte value;
        byte mask;
        boolean[] alternatives;
    }

    /** Unbounded gaps are capped so a hostile signature cannot make matching quadratic forever. */
    public static final int MAX_GAP = 4096;

    /**
     * How much work one match attempt may do before it gives up.
     *
     * <p>Several wide gaps in one signature multiply: on data that keeps matching the first block, a
     * pattern like {@code 41*41*41*41} would otherwise explore every combination of gap lengths.
     * Giving up is safe in the direction that matters, a miss on a contrived input, and it keeps a
     * signature file from being able to freeze the phone that loaded it.
     */
    static final int MAX_STEPS = 1 << 20;

    /** The ClamAV target type that means "any file". */
    public static final int TARGET_ANY = 0;

    private final String name;
    private final int target;
    private final List<Block> blocks = new ArrayList<Block>();
    /** Gaps between block i and block i+1; one shorter than {@link #blocks}. */
    private final List<Gap> gaps = new ArrayList<Gap>();
    private final int anchoredOffset;
    private final int shift;
    private final boolean fromEnd;

    private HexSignature(String name, int target, int anchoredOffset, int shift, boolean fromEnd) {
        this.name = name;
        this.target = target;
        this.anchoredOffset = anchoredOffset;
        this.shift = shift;
        this.fromEnd = fromEnd;
    }

    public String name() {
        return name;
    }

    /** The ClamAV target type: 0 for any file, otherwise one of the numbered kinds. */
    public int target() {
        return target;
    }

    /** True when this signature is written for files of {@code fileType}, or for any file. */
    public boolean appliesTo(int fileType) {
        return target == TARGET_ANY || target == fileType;
    }

    /** True when the pattern must sit at a fixed place rather than anywhere in the file. */
    public boolean anchored() {
        return anchoredOffset >= 0;
    }

    /**
     * The first byte the signature can start with, or -1 when it could be anything.
     *
     * <p>Used to bucket signatures so a scan tries only the plausible ones per position instead of
     * every signature in the database, which is the difference between a scan that finishes on a
     * phone and one that does not.
     */
    public int firstByteHint() {
        return fixedByteAt(0);
    }

    /** The second byte, when it is fixed and sits in the same block as the first; else -1. */
    public int secondByteHint() {
        return fixedByteAt(1);
    }

    private int fixedByteAt(int index) {
        if (blocks.isEmpty()) {
            return -1;
        }
        Block first = blocks.get(0);
        if (index >= first.length()) {
            return -1;
        }
        boolean[] allowed = first.alternatives == null ? null : first.alternatives[index];
        if (allowed != null) {
            int only = -1;
            for (int b = 0; b < 256; b++) {
                if (allowed[b]) {
                    if (only != -1) {
                        return -1;
                    }
                    only = b;
                }
            }
            return only;
        }
        if ((first.mask[index] & 0xFF) != 0xFF) {
            return -1;
        }
        return first.value[index] & 0xFF;
    }

    /** The length of the first fixed block. */
    public int firstBlockLength() {
        return blocks.isEmpty() ? 0 : blocks.get(0).length();
    }

    /**
     * Compiles a signature body.
     *
     * @param name   what to report when it matches
     * @param target the ClamAV target type field
     * @param offset the ndb offset field: {@code *} for anywhere, {@code n}, {@code n,m} or {@code EOF-n}
     * @param hex    the hex pattern
     */
    public static HexSignature compile(String name, int target, String offset, String hex)
            throws SyntaxException {
        int anchored = -1;
        int shift = 0;
        boolean fromEnd = false;
        String spec = offset == null ? "*" : offset.trim();
        if (spec.length() > 0 && !spec.equals("*")) {
            // Only positions in the file itself are honoured. ClamAV's EP+n, Sx+n and SL+n forms
            // describe places inside a PE image, which mean nothing for the files this scanner
            // looks at, and VI names a version resource. Those are rejected rather than guessed at.
            if (spec.toUpperCase(java.util.Locale.US).startsWith("EOF-")) {
                fromEnd = true;
                spec = spec.substring(4);
            }
            String shiftText = null;
            int comma = spec.indexOf(',');
            if (comma >= 0) {
                shiftText = spec.substring(comma + 1).trim();
                spec = spec.substring(0, comma).trim();
            }
            try {
                anchored = Integer.parseInt(spec);
                if (shiftText != null) {
                    shift = Integer.parseInt(shiftText);
                }
            } catch (NumberFormatException e) {
                throw new SyntaxException("unsupported offset: " + offset);
            }
            if (anchored < 0 || shift < 0) {
                throw new SyntaxException("negative offset: " + offset);
            }
            shift = Math.min(shift, MAX_GAP);
        }
        HexSignature signature = new HexSignature(name, target, anchored, shift, fromEnd);
        String body = hex == null ? "" : hex.trim();
        if (body.length() == 0) {
            throw new SyntaxException("empty pattern");
        }
        List<Position> current = new ArrayList<Position>();
        int pendingMin = -1;
        int pendingMax = -1;
        int i = 0;
        while (i < body.length()) {
            char c = body.charAt(i);
            if (c == '*') {
                signature.closeBlock(current, pendingMin, pendingMax);
                pendingMin = 0;
                pendingMax = MAX_GAP;
                current = new ArrayList<Position>();
                i++;
            } else if (c == '{') {
                int close = body.indexOf('}', i);
                if (close < 0) {
                    throw new SyntaxException("unclosed { in " + body);
                }
                int[] range = parseRange(body.substring(i + 1, close));
                signature.closeBlock(current, pendingMin, pendingMax);
                pendingMin = range[0];
                pendingMax = range[1];
                current = new ArrayList<Position>();
                i = close + 1;
            } else if (c == '(') {
                int close = body.indexOf(')', i);
                if (close < 0) {
                    throw new SyntaxException("unclosed ( in " + body);
                }
                appendAlternatives(current, body.substring(i + 1, close));
                i = close + 1;
            } else if (c == '?') {
                if (i + 1 >= body.length()) {
                    throw new SyntaxException("lone ? in " + body);
                }
                char next = body.charAt(i + 1);
                Position position = new Position();
                if (next == '?') {
                    position.mask = 0;
                    position.value = 0;
                } else if (isHexDigit(next)) {
                    // ?a: the low nibble is fixed, the high one is anything.
                    position.mask = 0x0F;
                    position.value = (byte) hexValue(next);
                } else {
                    throw new SyntaxException("lone ? in " + body);
                }
                current.add(position);
                i += 2;
            } else if (isHexDigit(c)) {
                if (i + 1 >= body.length()) {
                    throw new SyntaxException("odd hex digit in " + body);
                }
                char next = body.charAt(i + 1);
                Position position = new Position();
                if (next == '?') {
                    // a?: the high nibble is fixed, the low one is anything.
                    position.mask = (byte) 0xF0;
                    position.value = (byte) (hexValue(c) << 4);
                } else if (isHexDigit(next)) {
                    position.mask = (byte) 0xFF;
                    position.value = (byte) ((hexValue(c) << 4) | hexValue(next));
                } else {
                    throw new SyntaxException("odd hex digit in " + body);
                }
                current.add(position);
                i += 2;
            } else if (c == ' ' || c == '\t') {
                i++;
            } else if (c == '!' || c == '[') {
                // Negated alternatives and floating anchors are real ClamAV syntax that this
                // matcher does not implement. Saying so beats loading a pattern that cannot fire.
                throw new SyntaxException("unsupported syntax '" + c + "' in " + body);
            } else {
                throw new SyntaxException("unsupported character '" + c + "' in " + body);
            }
        }
        signature.closeBlock(current, pendingMin, pendingMax);
        // A pattern of wildcards alone would match every file. ClamAV requires fixed bytes too, and
        // two is the least that makes a pattern say anything.
        if (signature.fixedBytes() < 2) {
            throw new SyntaxException("pattern has fewer than two fixed bytes: " + body);
        }
        return signature;
    }

    /** Positions whose value is fully determined, by a literal or a set of alternatives. */
    private int fixedBytes() {
        int fixed = 0;
        for (int b = 0; b < blocks.size(); b++) {
            Block block = blocks.get(b);
            for (int i = 0; i < block.length(); i++) {
                boolean[] allowed = block.alternatives == null ? null : block.alternatives[i];
                if (allowed != null || (block.mask[i] & 0xFF) == 0xFF) {
                    fixed++;
                }
            }
        }
        return fixed;
    }

    private void closeBlock(List<Position> current, int gapMin, int gapMax) {
        if (current.isEmpty()) {
            return;
        }
        if (!blocks.isEmpty()) {
            gaps.add(new Gap(Math.max(gapMin, 0), gapMax < 0 ? 0 : gapMax));
        }
        byte[] value = new byte[current.size()];
        byte[] mask = new byte[current.size()];
        boolean[][] alternatives = null;
        for (int i = 0; i < current.size(); i++) {
            Position position = current.get(i);
            value[i] = position.value;
            mask[i] = position.mask;
            if (position.alternatives != null) {
                if (alternatives == null) {
                    alternatives = new boolean[current.size()][];
                }
                alternatives[i] = position.alternatives;
            }
        }
        blocks.add(new Block(value, mask, alternatives));
    }

    private static int[] parseRange(String text) throws SyntaxException {
        String body = text.trim();
        try {
            int dash = body.indexOf('-');
            if (dash < 0) {
                int n = Integer.parseInt(body);
                if (n < 0) {
                    throw new SyntaxException("bad range {" + body + "}");
                }
                return new int[] {Math.min(n, MAX_GAP), Math.min(n, MAX_GAP)};
            }
            String left = body.substring(0, dash).trim();
            String right = body.substring(dash + 1).trim();
            int min = left.length() == 0 ? 0 : Integer.parseInt(left);
            int max = right.length() == 0 ? MAX_GAP : Integer.parseInt(right);
            if (min < 0 || max < min) {
                throw new SyntaxException("bad range {" + body + "}");
            }
            return new int[] {Math.min(min, MAX_GAP), Math.min(max, MAX_GAP)};
        } catch (NumberFormatException e) {
            throw new SyntaxException("bad range {" + body + "}");
        }
    }

    private static void appendAlternatives(List<Position> current, String body) throws SyntaxException {
        String[] parts = body.split("\\|", -1);
        int width = -1;
        List<Position> positions = new ArrayList<Position>();
        for (int p = 0; p < parts.length; p++) {
            String option = parts[p].trim();
            if (option.length() == 0 || option.length() % 2 != 0) {
                throw new SyntaxException("bad alternative (" + body + ")");
            }
            int bytes = option.length() / 2;
            if (width == -1) {
                width = bytes;
                for (int b = 0; b < bytes; b++) {
                    Position position = new Position();
                    position.alternatives = new boolean[256];
                    positions.add(position);
                }
            } else if (bytes != width) {
                // ClamAV allows only same-length alternatives in this form, and honouring a
                // different length silently would shift every following byte.
                throw new SyntaxException("alternatives differ in length: (" + body + ")");
            }
            for (int b = 0; b < bytes; b++) {
                char hi = option.charAt(b * 2);
                char lo = option.charAt(b * 2 + 1);
                if (!isHexDigit(hi) || !isHexDigit(lo)) {
                    throw new SyntaxException("bad alternative (" + body + ")");
                }
                positions.get(b).alternatives[(hexValue(hi) << 4) | hexValue(lo)] = true;
            }
        }
        current.addAll(positions);
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static int hexValue(char c) {
        if (c <= '9') {
            return c - '0';
        }
        return (Character.toLowerCase(c) - 'a') + 10;
    }

    /** True when this signature matches somewhere in {@code data}, honouring its offset. */
    public boolean matches(byte[] data) {
        if (data == null || blocks.isEmpty()) {
            return false;
        }
        int[] steps = new int[] {MAX_STEPS};
        if (anchoredOffset >= 0) {
            int base = fromEnd ? data.length - anchoredOffset : anchoredOffset;
            for (int start = base; start <= base + shift; start++) {
                if (start >= 0 && matchFrom(data, start, 0, steps)) {
                    return true;
                }
            }
            return false;
        }
        Block first = blocks.get(0);
        int last = data.length - first.length();
        for (int start = 0; start <= last; start++) {
            if (first.matchesAt(data, start) && matchFrom(data, start, 0, steps)) {
                return true;
            }
        }
        return false;
    }

    /**
     * True when the pattern matches starting exactly at {@code start}.
     *
     * <p>For the bucketed search a database runs: it has already established that the leading bytes
     * fit, so only the rest needs checking here.
     */
    public boolean matchesAt(byte[] data, int start) {
        if (data == null || blocks.isEmpty()) {
            return false;
        }
        return matchFrom(data, start, 0, new int[] {MAX_STEPS});
    }

    /**
     * Matches block {@code index} at {@code at}, then the rest.
     *
     * <p>Iterative over the gap rather than recursive per byte: a signature with several wide gaps
     * would otherwise recurse thousands of frames deep on a large file. The step budget bounds the
     * branching a run of variable gaps can cause.
     */
    private boolean matchFrom(byte[] data, int at, int index, int[] steps) {
        int position = at;
        int block = index;
        while (true) {
            if (--steps[0] < 0) {
                return false;
            }
            Block current = blocks.get(block);
            if (!current.matchesAt(data, position)) {
                return false;
            }
            position += current.length();
            block++;
            if (block >= blocks.size()) {
                return true;
            }
            Gap gap = gaps.get(block - 1);
            if (gap.min == gap.max) {
                position += gap.min;
                continue;
            }
            // A variable gap is the only place that needs to branch.
            for (int skip = gap.min; skip <= gap.max; skip++) {
                if (position + skip > data.length) {
                    break;
                }
                if (matchFrom(data, position + skip, block, steps)) {
                    return true;
                }
                if (steps[0] < 0) {
                    return false;
                }
            }
            return false;
        }
    }
}
