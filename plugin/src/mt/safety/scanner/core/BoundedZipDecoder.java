package mt.safety.scanner.core;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.tukaani.xz.ArrayCache;
import org.tukaani.xz.SingleXZInputStream;

/**
 * Decodes one already-admitted ZIP payload, without extraction or archive-wide platform indexing.
 * The caller must validate the central/local headers, flags, exact raw offset and member identity.
 * This layer verifies complete payload sizes, CRC32 and codec termination. Prefix reads explicitly
 * mark coverage incomplete because their unseen remainder and integrity have not been verified.
 */
final class BoundedZipDecoder {
    static final int XZ_MEMORY_KIB = 8192;
    static final long MAX_COMPRESSED_BYTES = 8L * 1024 * 1024;
    private static final int CHUNK = 8192;

    private BoundedZipDecoder() { }

    /**
     * Owns and closes raw, including on unsupported-method, budget, and validation failures.
     * compressedSize covers only codec payload bytes, excluding local headers and descriptors;
     * it is capped before any payload read and the wrapper never crosses that interval. Bit 3
     * is allowed for methods 0/8/95 only because the caller validates the descriptor separately.
     * Bit 11 is allowed; bits 1/2 are allowed only for deflate. No encryption flag is accepted.
     */
    static byte[] read(InputStream raw, int method, int flags, long compressedSize, long size,
            long expectedCrc, int limit, ScanBudget budget) throws IOException {
        return read(raw, method, flags, compressedSize, size, expectedCrc, limit, budget, true);
    }

    /** Intentional metadata probes may defer prefix completeness to the later content pass. */
    static byte[] read(InputStream raw, int method, int flags, long compressedSize, long size,
            long expectedCrc, int limit, ScanBudget budget, boolean markPrefixPartial) throws IOException {
        InputStream decoded = null;
        Inflater inflater = null;
        try {
            if ((flags & 0x2041) != 0) {
                throw new IOException("encrypted ZIP member is unsupported without a key");
            }
            // Bits 1/2 are deflate options; bit 3 is the separately validated data descriptor;
            // bit 11 denotes UTF-8 names. Other reserved/patched/strong-encryption forms refuse.
            int supportedFlags = 0x0808 | (method == 8 ? 6 : 0);
            if ((flags & ~supportedFlags) != 0) {
                throw new IOException("unsupported ZIP member flags");
            }
            if (method != 0 && method != 8 && method != 95) {
                throw new IOException("unsupported ZIP compression method " + method);
            }
            if (compressedSize < 0 || compressedSize > MAX_COMPRESSED_BYTES || size < 0
                    || expectedCrc < 0 || expectedCrc > 0xffffffffL) {
                throw new IOException("ZIP payload size or CRC exceeds decoder bounds");
            }
            if (method == 0 && compressedSize != size) {
                throw new IOException("stored ZIP payload size mismatch");
            }
            if (budget.exhausted()) {
                budget.markTruncated();
                return new byte[0];
            }
            int wanted = (int) Math.min(size, (long) Math.max(0,
                    Math.min(limit, PluginPackage.MAX_MEMBER_BYTES)));
            int granted = budget.reserve(wanted);
            if (granted < size && markPrefixPartial) { budget.markTruncated(); }
            if (granted == 0 && size != 0) { return new byte[0]; }
            // The output reservation already paid for these reads. Poll time/cancellation
            // independently so an exact byte grant remains usable.
            if (budget.stopped()) {
                budget.markTruncated();
                return new byte[0];
            }
            BoundedInput input = new BoundedInput(raw, compressedSize, budget);
            if (method == 95) {
                decoded = new SingleXZInputStream(input, XZ_MEMORY_KIB, true,
                        ArrayCache.getDummyCache());
            } else if (method == 8) {
                inflater = new Inflater(true);
                decoded = new InflaterInputStream(input, inflater, CHUNK);
            } else {
                decoded = input;
            }
            byte[] output = new byte[granted];
            CRC32 crc = new CRC32();
            int used = 0;
            while (used < granted) {
                if (budget.stopped()) {
                    budget.markTruncated();
                    return Arrays.copyOf(output, used);
                }
                int count = decoded.read(output, used, Math.min(CHUNK, granted - used));
                if (count < 0) { throw new IOException("ZIP decoded size is shorter than declared"); }
                if (count == 0) { throw new IOException("ZIP decoder made no progress"); }
                crc.update(output, used, count);
                used += count;
            }
            if (granted < size) { return output; }
            // The one-byte probe is necessary even when the declared size is zero: it consumes
            // codec footer/index/check data and rejects hidden additional decompressed content.
            if (decoded.read() != -1) { throw new IOException("ZIP decoded size exceeds declaration"); }
            if (input.remaining != 0 || (inflater != null && inflater.getRemaining() != 0)) {
                throw new IOException("trailing ZIP compressed data or concatenated XZ streams");
            }
            if (crc.getValue() != expectedCrc) { throw new IOException("ZIP payload CRC mismatch"); }
            return output;
        } catch (IOException e) {
            budget.markTruncated();
            throw e;
        } finally {
            if (decoded != null) { PluginPackage.closeQuietly(decoded); }
            PluginPackage.closeQuietly(raw);
            if (inflater != null) { inflater.end(); }
        }
    }

    /** Never reads beyond the admitted compressed interval, even when the underlying view does. */
    private static final class BoundedInput extends InputStream {
        private final InputStream raw;
        private final ScanBudget budget;
        private long remaining;

        BoundedInput(InputStream raw, long remaining, ScanBudget budget) {
            this.raw = raw;
            this.remaining = remaining;
            this.budget = budget;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (length == 0) { return 0; }
            if (remaining == 0) { return -1; }
            if (budget.stopped()) {
                throw new IOException("ZIP decoder stopped at scan deadline or cancellation");
            }
            int count = raw.read(buffer, offset, (int) Math.min(remaining, Math.min(length, CHUNK)));
            if (count < 0) { throw new IOException("truncated ZIP compressed payload"); }
            if (count == 0) { throw new IOException("ZIP compressed input made no progress"); }
            remaining -= count;
            return count;
        }
    }
}
