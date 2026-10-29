package mt.safety.scanner.core;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Closeable;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;

/**
 * Admits bounded single-disk ZIP/ZIP64 metadata and binds every entry to its exact raw interval.
 * Central and local metadata each have a 2 MiB cap; record counts are capped before indexing.
 * Local mismatches remain explicit member failures so supported peers can still be inspected.
 * Files retain one read-only descriptor for hashing, structure and content, avoiding a second
 * path open between preflight and payload reads. In-place concurrent writes are still I/O failures
 * or require the caller's later action-identity recheck; this parser never extracts or executes.
 */
final class ArchiveIndex {
    static final int MAX_ENTRIES = 8000;
    private static final int MAX_INDEX_BYTES = 2 * 1024 * 1024;
    private static final int MAX_END_BYTES = 22 + 65535;
    private static final int MAX_ZIP64_EXTENSION = 65535;

    /** Exact central-directory identity, including duplicate names at distinct local offsets. */
    static final class Member {
        final String name;
        final int method;
        final long crc;
        final long compressedSize;
        final long size;
        final int flags;
        final long localOffset;
        final byte[] rawName;
        long dataOffset;
        long endOffset;
        String problem;

        Member(String name, byte[] header, byte[] rawName, byte[] extra) throws IOException {
            this.name = name;
            method = u16(header, 10);
            crc = u32(header, 16);
            flags = u16(header, 8);
            this.rawName = rawName;
            long[] extended = extended(extra, u32(header, 24), u32(header, 20), u32(header, 42));
            size = extended[0];
            compressedSize = extended[1];
            localOffset = extended[2];
        }

        boolean matches(ZipEntry entry) {
            return name.equals(entry.getName()) && method == entry.getMethod()
                    && crc == entry.getCrc() && size == entry.getSize()
                    && compressedSize == entry.getCompressedSize();
        }
    }

    private interface Source extends Closeable {
        long length();
        void read(long offset, byte[] target, int start, int count) throws IOException;
        default void read(long offset, byte[] target) throws IOException {
            read(offset, target, 0, target.length);
        }
    }

    /** Bounded central identities and exact local extents over one stable, read-only source. */
    static final class View implements Closeable {
        final Source source;
        final List<Member> members;
        final List<Member> localOrder;
        final long centralOffset;
        final List<String> problems = new ArrayList<String>();

        View(Source source, List<Member> members, long centralOffset) throws IOException {
            this.source = source;
            this.members = Collections.unmodifiableList(members);
            this.centralOffset = centralOffset;
            localOrder = new ArrayList<Member>(members);
            Collections.sort(localOrder, new Comparator<Member>() {
                @Override public int compare(Member a, Member b) {
                    return Long.compare(a.localOffset, b.localOffset);
                }
            });
            long expected = 0;
            long[] localMetadataBytes = {0};
            java.util.Set<String> names = new java.util.HashSet<String>();
            for (Member member : localOrder) {
                if (!names.add(member.name) && problems.size() < 40) {
                    problems.add("duplicate archive member: " + member.name);
                }
                try {
                    validateLocal(source, member, centralOffset, localMetadataBytes);
                    if (member.localOffset != expected) {
                        throw invalid("unindexed, overlapping or padded local member layout");
                    }
                } catch (IOException e) {
                    member.problem = e.getMessage();
                    if (problems.size() < 40) { problems.add(member.name + ": " + member.problem); }
                }
                expected = Math.max(expected, member.endOffset);
            }
            if (expected != centralOffset && problems.size() < 40) {
                problems.add("local members do not exactly cover the indexed data interval");
            }
        }

        boolean legacyMethodsOnly() {
            for (Member member : members) {
                if ((member.method != 0 && member.method != 8) || (member.flags & 0x2041) != 0) {
                    return false;
                }
            }
            return true;
        }

        InputStream stream(final Member member) throws IOException {
            if (member.problem != null) { throw invalid(member.problem); }
            return slice(member.dataOffset, member.compressedSize);
        }

        long length() { return source.length(); }
        InputStream wholeStream() { return slice(0, source.length()); }

        private InputStream slice(final long offset, final long size) {
            return new InputStream() {
                private long position = offset;
                private long left = size;
                @Override public int read() throws IOException {
                    byte[] one = new byte[1];
                    return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
                }
                @Override public int read(byte[] target, int start, int count) throws IOException {
                    if (count == 0) { return 0; }
                    if (left == 0) { return -1; }
                    int take = (int) Math.min(left, count);
                    source.read(position, target, start, take);
                    position += take;
                    left -= take;
                    return take;
                }
            };
        }

        @Override public void close() throws IOException { source.close(); }
    }

    static View open(File file) throws IOException {
        final RandomAccessFile input = new RandomAccessFile(file, "r");
        final long length = input.length();
        Source source = new Source() {
            @Override public long length() { return length; }
            @Override public void read(long offset, byte[] target, int start, int count) throws IOException {
                checkRange(offset, count, length);
                input.seek(offset);
                input.readFully(target, start, count);
            }
            @Override public void close() throws IOException { input.close(); }
        };
        try { return open(source); } catch (IOException | RuntimeException e) {
            source.close();
            throw e;
        }
    }

    static View open(final byte[] data) throws IOException {
        return open(new Source() {
            @Override public long length() { return data.length; }
            @Override public void read(long offset, byte[] target, int start, int count) throws IOException {
                checkRange(offset, count, data.length);
                System.arraycopy(data, (int) offset, target, start, count);
            }
            @Override public void close() { }
        });
    }

    private static View open(Source source) throws IOException {
        List<Member> members = new ArrayList<Member>();
        long[] central = new long[1];
        inspect(source, members, central);
        return new View(source, members, central[0]);
    }

    private ArchiveIndex() {
    }

    static int inspect(File file) throws IOException {
        try (View view = open(file)) { return view.members.size(); }
    }

    static Map<Long, Member> nestedEntries(final byte[] data) throws IOException {
        Map<Long, Member> entries = new HashMap<Long, Member>();
        try (View view = open(data)) {
            for (String problem : view.problems) {
                if (!problem.startsWith("duplicate archive member:")) { throw invalid(problem); }
            }
            for (Member member : view.members) {
                if ((member.flags & 0x2041) != 0) { throw invalid("encrypted member metadata is unsupported"); }
                if (entries.put(member.localOffset, member) != null) {
                    throw invalid("multiple index records refer to one local header");
                }
            }
        }
        return entries;
    }

    private static int inspect(Source input, List<Member> ordered, long[] central) throws IOException {
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
            byte[] name = new byte[u16(header, 28)];
            input.read(position + 46, name);
            String decoded = new String(name, "UTF-8");
            if (!Arrays.equals(name, decoded.getBytes("UTF-8"))) {
                throw invalid("member name is not valid UTF-8");
            }
            byte[] extra = new byte[u16(header, 30)];
            input.read(position + 46 + name.length, extra);
            Member member = new Member(decoded, header, name, extra);
            ordered.add(member);
            position += recordLength;
        }
        if (count != entries) {
            throw invalid("declared and actual central directory counts disagree");
        }
        central[0] = indexOffset;
        return count;
    }

    private static long[] extended(byte[] extra, long size, long compressed, long offset) throws IOException {
        if (size != 0xffffffffL && compressed != 0xffffffffL && offset != 0xffffffffL) {
            return new long[] {size, compressed, offset};
        }
        for (int p = 0; p + 4 <= extra.length;) {
            int tag = u16(extra, p), length = u16(extra, p + 2);
            p += 4;
            if (length > extra.length - p) { throw invalid("truncated ZIP extra field"); }
            if (tag == 1) {
                int end = p + length;
                long[] values = {size, compressed, offset};
                for (int i = 0; i < values.length; i++) {
                    if (values[i] == 0xffffffffL) {
                        if (end - p < 8) { throw invalid("missing ZIP64 member field"); }
                        values[i] = u64(extra, p);
                        p += 8;
                    }
                }
                return values;
            }
            p += length;
        }
        throw invalid("missing ZIP64 member extension");
    }

    private static void validateLocal(Source input, Member member, long central,
            long[] metadataBytes) throws IOException {
        if (member.localOffset < 0 || member.localOffset >= central) {
            throw invalid("invalid local offset");
        }
        byte[] header = new byte[30];
        input.read(member.localOffset, header);
        if (u32(header, 0) != 0x04034b50L || u16(header, 6) != member.flags
                || u16(header, 8) != member.method || u16(header, 26) != member.rawName.length) {
            throw invalid("local and central name, flags or method disagree");
        }
        metadataBytes[0] += 30L + u16(header, 26) + u16(header, 28);
        if (metadataBytes[0] > MAX_INDEX_BYTES) {
            throw invalid("local metadata exceeds byte limit");
        }
        long headerBytes = 30L + u16(header, 26) + u16(header, 28);
        if (headerBytes > central - member.localOffset) {
            throw invalid("local header crosses the central directory");
        }
        long payload = member.localOffset + headerBytes;
        if (member.compressedSize > central - payload) {
            throw invalid("member payload crosses the central directory");
        }
        byte[] name = new byte[member.rawName.length];
        input.read(member.localOffset + 30, name);
        if (!Arrays.equals(member.rawName, name)) { throw invalid("local and central names disagree"); }
        byte[] extra = new byte[u16(header, 28)];
        input.read(member.localOffset + 30 + name.length, extra);
        long[] sizes = extended(extra, u32(header, 22), u32(header, 18), 0);
        long crc = u32(header, 14);
        boolean descriptor = (member.flags & 8) != 0;
        if ((!descriptor && (crc != member.crc || sizes[0] != member.size
                || sizes[1] != member.compressedSize))
                || (descriptor && ((crc != 0 && crc != member.crc)
                || (sizes[0] != 0 && sizes[0] != member.size)
                || (sizes[1] != 0 && sizes[1] != member.compressedSize)))) {
            throw invalid("local and central CRC or sizes disagree");
        }
        member.dataOffset = payload;
        long end = payload + member.compressedSize;
        if (descriptor) {
            byte[] first = new byte[4];
            input.read(end, first);
            boolean signature = u32(first, 0) == 0x08074b50L;
            boolean wide = u32(header, 18) == 0xffffffffL || u32(header, 22) == 0xffffffffL
                    || member.size >= 0xffffffffL || member.compressedSize >= 0xffffffffL;
            int descriptorBytes = (signature ? 4 : 0) + (wide ? 20 : 12);
            if (descriptorBytes > central - end) { throw invalid("truncated data descriptor"); }
            byte[] dd = new byte[descriptorBytes];
            input.read(end, dd);
            int start = signature ? 4 : 0;
            long compressed = wide ? u64(dd, start + 4) : u32(dd, start + 4);
            long size = wide ? u64(dd, start + 12) : u32(dd, start + 8);
            if (u32(dd, start) != member.crc || compressed != member.compressedSize || size != member.size) {
                throw invalid("data descriptor and central metadata disagree");
            }
            end += descriptorBytes;
        }
        member.endOffset = end;
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
