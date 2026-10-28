package mt.safety.scanner.core;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;

/**
 * Admits bounded ZIP metadata before ZipFile can allocate its central-directory index.
 *
 * <p>This checks the single-disk ZIP/ZIP64 record envelope, not compression or payload integrity.
 * Offsets are absolute; split, encrypted-index, padded and ambiguous end-record layouts refuse with
 * an I/O diagnostic. No untrusted length determines an allocation. Concurrent replacement between
 * this check and opening ZipFile is not made atomic by this read-only preflight.
 */
final class ArchiveIndex {
    static final int MAX_ENTRIES = 8000;
    private static final int MAX_INDEX_BYTES = 2 * 1024 * 1024;
    private static final int MAX_END_BYTES = 22 + 65535;
    private static final int MAX_ZIP64_EXTENSION = 65535;

    /** Only nested archives retain indexed identities, within the same metadata/count bounds. */
    static final class Member {
        final String name;
        final int method;
        final long crc;
        final long compressedSize;
        final long size;

        Member(String name, byte[] header) {
            this.name = name;
            method = u16(header, 10);
            crc = u32(header, 16);
            compressedSize = u32(header, 20);
            size = u32(header, 24);
        }

        boolean matches(ZipEntry entry) {
            return name.equals(entry.getName()) && method == entry.getMethod()
                    && crc == entry.getCrc() && size == entry.getSize()
                    && compressedSize == entry.getCompressedSize();
        }
    }

    private interface Source {
        long length();
        void read(long offset, byte[] target) throws IOException;
    }

    private ArchiveIndex() {
    }

    static int inspect(File file) throws IOException {
        try (final RandomAccessFile input = new RandomAccessFile(file, "r")) {
            final long length = input.length();
            return inspect(new Source() {
                @Override
                public long length() {
                    return length;
                }

                @Override
                public void read(long offset, byte[] target) throws IOException {
                    checkRange(offset, target.length, length);
                    input.seek(offset);
                    input.readFully(target);
                }
            }, null);
        }
    }

    static Map<Long, Member> nestedEntries(final byte[] data) throws IOException {
        Map<Long, Member> entries = new HashMap<Long, Member>();
        inspect(new Source() {
            @Override
            public long length() {
                return data.length;
            }

            @Override
            public void read(long offset, byte[] target) throws IOException {
                checkRange(offset, target.length, data.length);
                System.arraycopy(data, (int) offset, target, 0, target.length);
            }
        }, entries);
        return entries;
    }

    private static int inspect(Source input, Map<Long, Member> localEntries) throws IOException {
        long length = input.length();
        if (length < 22) {
            throw invalid("missing or truncated end record");
        }
        byte[] tail = new byte[(int) Math.min(length, MAX_END_BYTES)];
        long tailOffset = length - tail.length;
        input.read(tailOffset, tail);
        int end = -1;
        // Use the reverse-most possible end signature, as the platform ZIP readers do. Never skip
        // an ambiguous later candidate to admit an earlier, cheaper index than ZipFile may select.
        for (int i = tail.length - 22; i >= 0; i--) {
            if (u32(tail, i) == 0x06054b50L) {
                end = i;
                break;
            }
        }
        if (end < 0 || end + 22 + u16(tail, end + 20) != tail.length) {
            throw invalid("missing, padded or ambiguous end record");
        }
        long endOffset = tailOffset + end;
        int disk = u16(tail, end + 4);
        int indexDisk = u16(tail, end + 6);
        long diskEntries = u16(tail, end + 8);
        long entries = u16(tail, end + 10);
        long indexBytes = u32(tail, end + 12);
        long indexOffset = u32(tail, end + 16);
        long indexEnd = endOffset;

        byte[] locator = new byte[20];
        boolean zip64 = false;
        if (endOffset >= locator.length) {
            input.read(endOffset - locator.length, locator);
            zip64 = u32(locator, 0) == 0x07064b50L;
        }
        if (zip64) {
            if (u32(locator, 4) != 0 || u32(locator, 16) != 1) {
                throw invalid("split ZIP64 is unsupported");
            }
            long recordOffset = u64(locator, 8);
            byte[] record = new byte[56];
            input.read(recordOffset, record);
            long recordBytes = u64(record, 4);
            if (u32(record, 0) != 0x06064b50L || recordBytes < 44
                    || recordBytes > 44L + MAX_ZIP64_EXTENSION
                    || recordOffset > endOffset - 20
                    || recordBytes != endOffset - 20 - recordOffset - 12
                    || u32(record, 16) != 0 || u32(record, 20) != 0) {
                throw invalid("invalid or unsupported ZIP64 end record");
            }
            long entries64 = u64(record, 32);
            long indexBytes64 = u64(record, 40);
            long indexOffset64 = u64(record, 48);
            // Some platform readers fall back to classic fields when ZIP64 disagrees. Require
            // agreement for every non-sentinel field so both readers admit the same bounded index.
            if ((disk != 0 && disk != 65535) || (indexDisk != 0 && indexDisk != 65535)
                    || !agrees(diskEntries, u64(record, 24), 65535L)
                    || !agrees(entries, entries64, 65535L)
                    || !agrees(indexBytes, indexBytes64, 0xffffffffL)
                    || !agrees(indexOffset, indexOffset64, 0xffffffffL)
                    || u64(record, 24) != entries64) {
                throw invalid("classic and ZIP64 index records disagree");
            }
            entries = entries64;
            diskEntries = entries64;
            indexBytes = indexBytes64;
            indexOffset = indexOffset64;
            indexEnd = recordOffset;
        } else if (disk != 0 || indexDisk != 0 || entries == 65535L
                || indexBytes == 0xffffffffL || indexOffset == 0xffffffffL) {
            throw invalid("split or missing ZIP64 index is unsupported");
        }
        if (entries != diskEntries || entries > MAX_ENTRIES || indexBytes > MAX_INDEX_BYTES) {
            throw invalid("index exceeds entry or metadata byte limit");
        }
        if (indexOffset > indexEnd || indexBytes != indexEnd - indexOffset
                || entries > indexBytes / 46L) {
            throw invalid("index bounds or record count are inconsistent");
        }
        byte[] header = new byte[46];
        long position = indexOffset;
        int count = 0;
        while (position < indexEnd) {
            if (++count > MAX_ENTRIES || indexEnd - position < header.length) {
                throw invalid("too many or truncated central directory records");
            }
            input.read(position, header);
            if (u32(header, 0) != 0x02014b50L || u16(header, 34) != 0) {
                throw invalid("unsupported central directory record");
            }
            long recordLength = 46L + u16(header, 28) + u16(header, 30) + u16(header, 32);
            if (recordLength > indexEnd - position) {
                throw invalid("truncated central directory member");
            }
            if (localEntries != null) {
                if ((u16(header, 8) & 0x2041) != 0) {
                    throw invalid("encrypted nested member metadata is unsupported");
                }
                long localOffset = u32(header, 42);
                // An in-memory nested archive is at most MAX_MEMBER_BYTES. A ZIP64 local-offset
                // sentinel is not needed for that range; decline that form rather than guess.
                if (localOffset == 0xffffffffL || localOffset >= indexOffset) {
                    throw invalid("unsupported or invalid nested local offset");
                }
                byte[] name = new byte[u16(header, 28)];
                input.read(position + 46, name);
                String decoded = new String(name, "UTF-8");
                if (!java.util.Arrays.equals(name, decoded.getBytes("UTF-8"))) {
                    throw invalid("nested member name is not valid UTF-8");
                }
                if (localEntries.put(localOffset, new Member(decoded, header)) != null) {
                    throw invalid("multiple index records refer to one nested local header");
                }
            }
            position += recordLength;
        }
        if (count != entries) {
            throw invalid("declared and actual central directory counts disagree");
        }
        return count;
    }

    private static boolean agrees(long classic, long extended, long sentinel) {
        return classic == sentinel || classic == extended;
    }

    private static void checkRange(long offset, int size, long length) throws IOException {
        if (offset < 0 || offset > length || size > length - offset) {
            throw invalid("record offset is outside the archive");
        }
    }

    private static int u16(byte[] data, int offset) {
        return (data[offset] & 255) | ((data[offset + 1] & 255) << 8);
    }

    private static long u32(byte[] data, int offset) {
        return (long) u16(data, offset) | ((long) u16(data, offset + 2) << 16);
    }

    private static long u64(byte[] data, int offset) throws IOException {
        long high = u32(data, offset + 4);
        if (high > 0x7fffffffL) {
            throw invalid("ZIP64 value exceeds supported signed range");
        }
        return u32(data, offset) | (high << 32);
    }

    private static IOException invalid(String why) {
        return new IOException("archive index was not admitted: " + why);
    }
}
