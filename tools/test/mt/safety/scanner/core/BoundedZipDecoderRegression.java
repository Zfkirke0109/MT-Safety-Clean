package mt.safety.scanner.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/** Genuine upstream ZIP95 and hostile stream regressions; never executes fixture contents. */
public final class BoundedZipDecoderRegression {
    private static int checks;
    private BoundedZipDecoderRegression() { }

    public static void main(String[] args) throws Exception {
        run();
        System.out.println("BoundedZipDecoderRegression: " + checks + " checks passed");
    }

    public static void run() throws Exception {
        byte[] archive = Files.readAllBytes(new File(
                "tools/test-fixtures/zip95/libarchive-xz-multi.zipx").toPath());
        check(Bytes.sha256(archive).equals(
                "d4ba4b1fa117e8170ffb4e0ded734c5da9006064daf35c9056671c66da21bb74"), "upstream fixture hash");
        String[] names = {"bash.bashrc", "pacman.conf", "profile"};
        int[] lengths = {2245, 2566, 6601};
        long[] crcs = {0xf751b8c9L, 0xb20b7f88L, 0x2329f054L};
        String[] hashes = {
            "4995deb0c6a2b5482ba62759f1f5bcdd19186528d99d263dc8bc61d42878798e",
            "6024bbf50cc92236b7b437430cb9e4180da91925cdc19a5a7910fe172931cfb6",
            "4973827f59fed69911bc0b3e4ad7f9ee6aac0ee120b38ded0a46a7302044dd36"};
        int position = 0;
        byte[] first = null;
        for (int i = 0; i < 3; i++) {
            check(u32(archive, position) == 0x04034b50L, "local signature");
            check(u16(archive, position + 6) == 0, "fixture flags");
            check(u16(archive, position + 8) == 95, "genuine XZ method");
            int compressed = (int) u32(archive, position + 18);
            int nameLength = u16(archive, position + 26);
            int start = position + 30 + nameLength + u16(archive, position + 28);
            check(names[i].equals(new String(archive, position + 30, nameLength, "UTF-8")), "upstream name");
            check(u32(archive, position + 14) == crcs[i], "upstream CRC oracle");
            check(u32(archive, position + 22) == lengths[i], "upstream size");
            byte[] input = Arrays.copyOfRange(archive, start, start + compressed);
            byte[] output = read(input, 95, 0, lengths[i], crcs[i], 10000, ScanBudget.unlimited());
            check(output.length == lengths[i], "decoded byte count");
            check(Bytes.sha256(output).equals(hashes[i]), "independent liblzma output SHA256");
            if (i == 0) { first = input; }
            position = start + compressed;
        }
        check(position == 5179, "exact central directory start");
        int central = position;
        for (int i = 0; i < 3; i++) {
            check(u32(archive, central) == 0x02014b50L, "central signature");
            check(u16(archive, central + 8) == 0 && u16(archive, central + 10) == 95, "central flags/method");
            check(u32(archive, central + 16) == crcs[i]
                    && u32(archive, central + 24) == lengths[i], "central CRC/size oracle");
            check(names[i].equals(new String(archive, central + 46,
                    u16(archive, central + 28), "UTF-8")), "central name oracle");
            check(u32(archive, central + 42) == new int[] {0, 1257, 2642}[i],
                    "central local-header offset");
            central += 46 + u16(archive, central + 28) + u16(archive, central + 30) + u16(archive, central + 32);
        }
        check(u32(archive, central) == 0x06054b50L && u16(archive, central + 10) == 3,
                "three-member end record");
        check(central + 22 == archive.length, "no trailing archive data");
        expectFailure(first, 95, 1, lengths[0], crcs[0], "encrypted");
        expectFailure(first, 95, 0x40, lengths[0], crcs[0], "encrypted");
        expectFailure(first, 95, 0x2000, lengths[0], crcs[0], "encrypted");
        expectFailure(first, 99, 0, lengths[0], crcs[0], "unsupported");
        expectFailure(first, 95, 0x10, lengths[0], crcs[0], "flags");
        expectFailure(first, 95, 0, lengths[0], crcs[0] ^ 1, "CRC");
        expectFailure(first, 95, 0, lengths[0] - 1, crcs[0], "size");
        expectFailure(first, 95, 0, lengths[0] + 1, crcs[0], "size");
        for (int drop : new int[] {1, 12, 40, first.length - 1}) {
            expectFailure(Arrays.copyOf(first, first.length - drop), 95, 0, lengths[0], crcs[0], null);
        }
        expectFailure(Arrays.copyOf(first, first.length + 4), 95, 0, lengths[0], crcs[0], "trailing");
        byte[] concatenated = new byte[first.length * 2];
        System.arraycopy(first, 0, concatenated, 0, first.length);
        System.arraycopy(first, 0, concatenated, first.length, first.length);
        expectFailure(concatenated, 95, 0, lengths[0], crcs[0], "trailing");
        byte[] hugeDictionary = first.clone();
        hugeDictionary[16] = 30; // LZMA2 128 MiB dictionary property in valid block header.
        CRC32 headerCrc = new CRC32();
        headerCrc.update(hugeDictionary, 12, 8);
        put32(hugeDictionary, 20, headerCrc.getValue());
        expectFailure(hugeDictionary, 95, 0, lengths[0], crcs[0], "KiB");
        byte[] corrupt = first.clone();
        corrupt[corrupt.length - 5] ^= 1;
        expectFailure(corrupt, 95, 0, lengths[0], crcs[0], null);
        byte[] checked = java.util.Base64.getDecoder().decode(
                "/Td6WFoAAAFpIt42AgAhAQAAAAA3J5fWAQAdc2Nhbm5lci1vd25lZCBYWiBjaGVja3N1bSB0ZXN0AAAAcbv3yAABMh453Pk3kEKZDQEAAAAAAVla");
        byte[] checkPlain = "scanner-owned XZ checksum test".getBytes("UTF-8");
        CRC32 checkCrc = new CRC32(); checkCrc.update(checkPlain);
        check(Arrays.equals(checkPlain, read(checked, 95, 0, checkPlain.length,
                checkCrc.getValue(), 1000, ScanBudget.unlimited())), "XZ CRC32 check stream");
        checked[60] ^= 1; // Corrupt XZ data check only; uncompressed bytes and ZIP CRC unchanged.
        expectFailure(checked, 95, 0, checkPlain.length, checkCrc.getValue(), null);
        ScanBudget limited = ScanBudget.unlimited();
        byte[] prefix = read(first, 95, 0, lengths[0], crcs[0], 20, limited);
        check(prefix.length == 20 && limited.wasTruncated(), "partial output is explicit");
        ScanBudget exact = new ScanBudget(10000, lengths[0]);
        byte[] exactOutput = read(first, 95, 0, lengths[0], crcs[0], 10000, exact);
        check(exactOutput.length == lengths[0] && exact.bytesUsed() == lengths[0]
                && !exact.wasTruncated(), "exact reservation completes including footer verification");
        check(Bytes.sha256(exactOutput).equals(hashes[0]), "exact reservation output identity");
        ScanBudget tiny = new ScanBudget(10000, 10);
        byte[] tinyOutput = read(first, 95, 0, lengths[0], crcs[0], 10000, tiny);
        check(tinyOutput.length == 10 && tiny.wasTruncated() && tiny.bytesUsed() == 10,
                "partial reservation is usable and budget cap explicit");
        final int[] observed = {0, 0};
        java.io.InputStream oversized = new java.io.InputStream() {
            @Override public int read() { observed[0]++; return 0; }
            @Override public void close() { observed[1]++; }
        };
        try {
            BoundedZipDecoder.read(oversized, 95, 0, 8L * 1024 * 1024 + 1,
                    10, 0, 100, ScanBudget.unlimited());
            throw new AssertionError("oversized compressed input accepted");
        } catch (IOException expected) {
            check(observed[0] == 0 && observed[1] == 1, "oversize refused before input and closed");
        }
        ScanBudget expired = new ScanBudget(0, 10000);
        check(read(first, 95, 0, lengths[0], crcs[0], 10000, expired).length == 0
                && expired.wasTruncated(), "expired scan stops before decoding");
        check(read(new byte[0], 0, 0, 0, 0, 1000, ScanBudget.unlimited()).length == 0,
                "empty stored member verifies");
        byte[] plain = "scanner-owned stored/deflate regression".getBytes("UTF-8");
        CRC32 crc = new CRC32(); crc.update(plain);
        check(Arrays.equals(plain, read(plain, 0, 0, plain.length, crc.getValue(), 1000,
                ScanBudget.unlimited())), "stored method");
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(6, true);
        try (DeflaterOutputStream out = new DeflaterOutputStream(compressed, deflater)) {
            out.write(plain);
        } finally { deflater.end(); }
        check(Arrays.equals(plain, read(compressed.toByteArray(), 8, 0, plain.length,
                crc.getValue(), 1000, ScanBudget.unlimited())), "deflate method");
        byte[] deflateTail = Arrays.copyOf(compressed.toByteArray(), compressed.size() + 1);
        expectFailure(deflateTail, 8, 0, plain.length, crc.getValue(), "trailing");
    }

    private static byte[] read(byte[] input, int method, int flags, long size, long crc,
            int limit, ScanBudget budget) throws IOException {
        return BoundedZipDecoder.read(new ByteArrayInputStream(input), method, flags,
                input.length, size, crc, limit, budget);
    }

    private static void expectFailure(byte[] input, int method, int flags, long size,
            long crc, String message) throws IOException {
        ScanBudget budget = ScanBudget.unlimited();
        try {
            read(input, method, flags, size, crc, 10000, budget);
            throw new AssertionError("expected decoder refusal: " + message);
        } catch (IOException expected) {
            check(message == null || expected.getMessage().contains(message),
                    "refusal diagnostic: " + expected.getMessage());
            check(budget.wasTruncated(), "failed decoder cannot claim completeness");
        }
    }

    private static void check(boolean ok, String why) {
        checks++;
        if (!ok) { throw new AssertionError(why); }
    }
    private static int u16(byte[] data, int p) { return (data[p] & 255) | ((data[p + 1] & 255) << 8); }
    private static long u32(byte[] data, int p) { return u16(data, p) | ((long) u16(data, p + 2) << 16); }
    private static void put32(byte[] data, int p, long value) {
        for (int i = 0; i < 4; i++) { data[p + i] = (byte) (value >>> (8 * i)); }
    }
}
