package mtsafety.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;

/**
 * Builds synthetic plugin packages for the test suite.
 *
 * <p>The hostile fixtures are deliberately inert: a handful of lines that name the APIs a real implant
 * would use, with no working logic behind them. They exist to exercise the detection rules, and they
 * are never compiled or executed by anything.
 *
 * <p>The raw ZIP writer is here because {@code ZipOutputStream} refuses to create the archives that
 * matter most for testing: it rejects a duplicate member name outright, and those are exactly the
 * shapes the structural rules exist to catch.
 */
public final class Fixtures {

    private final File root;

    public Fixtures(File root) {
        this.root = root;
    }

    /** A plugin laid out as an installed directory. */
    public File directoryPlugin(String name, String manifestJson, Map<String, String> sources) {
        File dir = new File(root, name);
        writeFile(new File(dir, "manifest.json"), manifestJson);
        for (Map.Entry<String, String> entry : sources.entrySet()) {
            writeFile(new File(dir, entry.getKey()), entry.getValue());
        }
        return dir;
    }

    /**
     * A plugin in MT Manager's real installed layout: a folder named for the id holding
     * {@code plugin.mtp}, with any extra members MT Manager extracted beside it.
     */
    public File installedArchive(String id, Map<String, byte[]> archiveMembers, Map<String, byte[]> beside) {
        File dir = new File(root, id);
        dir.mkdirs();
        rawArchiveAt(new File(dir, "plugin.mtp"), archiveMembers);
        if (beside != null) {
            for (Map.Entry<String, byte[]> e : beside.entrySet()) {
                writeBytes(new File(dir, e.getKey()), e.getValue());
            }
        }
        return dir;
    }


    /** The same content packaged as an .mtp archive. */
    public File archivePlugin(String name, String manifestJson, Map<String, String> sources) {
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", bytes(manifestJson));
        for (Map.Entry<String, String> entry : sources.entrySet()) {
            members.put(entry.getKey(), bytes(entry.getValue()));
        }
        return rawArchive(name, members, false);
    }

    /**
     * Writes a ZIP whose members declare their sizes only *after* their data, in a data descriptor.
     *
     * <p>A real shape, produced by any writer that streams without knowing a member's length in
     * advance, and the shape that defeated the walk's inflation guard: the local header carries zeroes
     * for the sizes and sets bit 3 of the general purpose flag, so {@code ZipEntry.getSize()} is -1
     * while the stream is being walked. A guard that added up declared sizes therefore never grew, and
     * a single member could inflate without limit. The central directory still carries the true sizes,
     * which is why {@code ZipFile} sees this archive as ordinary.
     */
    public File dataDescriptorArchive(String name, Map<String, byte[]> members) {
        File file = new File(root, name);
        file.getParentFile().mkdirs();

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        ByteArrayOutputStream central = new ByteArrayOutputStream();
        int count = 0;
        try {
            for (Map.Entry<String, byte[]> member : members.entrySet()) {
                byte[] data = member.getValue();
                int offset = body.size();
                CRC32 crc = new CRC32();
                crc.update(data);
                byte[] deflated = deflate(data);
                byte[] nameBytes = member.getKey().getBytes("UTF-8");

                // Local file header: deflated, flag bit 3 set, sizes withheld.
                writeInt(body, 0x04034b50);
                writeShort(body, 20);
                writeShort(body, 0x0008);
                writeShort(body, 8);
                writeShort(body, 0);
                writeShort(body, 0);
                writeInt(body, 0);
                writeInt(body, 0);
                writeInt(body, 0);
                writeShort(body, nameBytes.length);
                writeShort(body, 0);
                body.write(nameBytes);
                body.write(deflated);

                // Data descriptor, carrying what the header left out.
                writeInt(body, 0x08074b50);
                writeInt(body, (int) crc.getValue());
                writeInt(body, deflated.length);
                writeInt(body, data.length);

                // The central directory tells the truth, as a real writer's would.
                writeInt(central, 0x02014b50);
                writeShort(central, 20);
                writeShort(central, 20);
                writeShort(central, 0x0008);
                writeShort(central, 8);
                writeShort(central, 0);
                writeShort(central, 0);
                writeInt(central, (int) crc.getValue());
                writeInt(central, deflated.length);
                writeInt(central, data.length);
                writeShort(central, nameBytes.length);
                writeShort(central, 0);
                writeShort(central, 0);
                writeShort(central, 0);
                writeShort(central, 0);
                writeInt(central, 0);
                writeInt(central, offset);
                central.write(nameBytes);
                count++;
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(body.toByteArray());
            int centralOffset = body.size();
            out.write(central.toByteArray());
            writeInt(out, 0x06054b50);
            writeShort(out, 0);
            writeShort(out, 0);
            writeShort(out, count);
            writeShort(out, count);
            writeInt(out, central.size());
            writeInt(out, centralOffset);
            writeShort(out, 0);

            OutputStream fileOut = new FileOutputStream(file);
            try {
                fileOut.write(out.toByteArray());
            } finally {
                fileOut.close();
            }
        } catch (IOException e) {
            throw new IllegalStateException("could not write " + file, e);
        }
        return file;
    }

    /** Raw deflate, no zlib wrapper, as a ZIP member stores it. */
    private static byte[] deflate(byte[] data) {
        java.util.zip.Deflater deflater = new java.util.zip.Deflater(9, true);
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1 << 16];
        while (!deflater.finished()) {
            int n = deflater.deflate(buffer);
            out.write(buffer, 0, n);
        }
        deflater.end();
        return out.toByteArray();
    }

    /**
     * Writes a ZIP by hand.
     *
     * @param duplicateFirstMember when true, the first member is written into the archive twice, so the
     *                             file a reviewer reads need not be the file that is extracted
     */
    public void rawArchiveAt(File file, Map<String, byte[]> members) {
        rawArchiveInto(file, members, false);
    }

    public File rawArchive(String name, Map<String, byte[]> members, boolean duplicateFirstMember) {
        File file = new File(root, name);
        file.getParentFile().mkdirs();
        return rawArchiveInto(file, members, duplicateFirstMember);
    }

    private File rawArchiveInto(File file, Map<String, byte[]> members, boolean duplicateFirstMember) {
        file.getParentFile().mkdirs();

        List<String> names = new ArrayList<String>(members.keySet());
        if (duplicateFirstMember && !names.isEmpty()) {
            names.add(1, names.get(0));
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        ByteArrayOutputStream central = new ByteArrayOutputStream();
        int count = 0;
        try {
            for (int i = 0; i < names.size(); i++) {
                String memberName = names.get(i);
                byte[] data = members.get(memberName);
                int offset = body.size();
                CRC32 crc = new CRC32();
                crc.update(data);

                // Local file header, stored (uncompressed).
                writeInt(body, 0x04034b50);
                writeShort(body, 20);
                writeShort(body, 0);
                writeShort(body, 0);
                writeShort(body, 0);
                writeShort(body, 0);
                writeInt(body, (int) crc.getValue());
                writeInt(body, data.length);
                writeInt(body, data.length);
                byte[] nameBytes = memberName.getBytes("UTF-8");
                writeShort(body, nameBytes.length);
                writeShort(body, 0);
                body.write(nameBytes);
                body.write(data);

                // Matching central directory record.
                writeInt(central, 0x02014b50);
                writeShort(central, 20);
                writeShort(central, 20);
                writeShort(central, 0);
                writeShort(central, 0);
                writeShort(central, 0);
                writeShort(central, 0);
                writeInt(central, (int) crc.getValue());
                writeInt(central, data.length);
                writeInt(central, data.length);
                writeShort(central, nameBytes.length);
                writeShort(central, 0);
                writeShort(central, 0);
                writeShort(central, 0);
                writeShort(central, 0);
                writeInt(central, 0);
                writeInt(central, offset);
                central.write(nameBytes);
                count++;
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(body.toByteArray());
            int centralOffset = body.size();
            out.write(central.toByteArray());
            writeInt(out, 0x06054b50);
            writeShort(out, 0);
            writeShort(out, 0);
            writeShort(out, count);
            writeShort(out, count);
            writeInt(out, central.size());
            writeInt(out, centralOffset);
            writeShort(out, 0);

            OutputStream fileOut = new FileOutputStream(file);
            try {
                fileOut.write(out.toByteArray());
            } finally {
                fileOut.close();
            }
        } catch (IOException e) {
            throw new IllegalStateException("could not build fixture " + file.getName(), e);
        }
        return file;
    }

    // ------------------------------------------------------------------ content

    /** A manifest with the documented v2 fields. */
    public static String manifest(String pluginId, String name, String mainPreference) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"pluginSdkVersion\": 2,\n");
        sb.append("  \"pluginID\": \"").append(pluginId).append("\",\n");
        sb.append("  \"versionCode\": 1,\n");
        sb.append("  \"versionName\": \"v1.0\",\n");
        sb.append("  \"name\": \"").append(name).append("\",\n");
        sb.append("  \"description\": \"fixture\",\n");
        sb.append("  \"interfaces\": [],\n");
        sb.append("  \"mainPreference\": \"").append(mainPreference).append("\"\n");
        sb.append("}\n");
        return sb.toString();
    }

    public static Map<String, String> sources(String... pathsAndBodies) {
        Map<String, String> out = new LinkedHashMap<String, String>();
        for (int i = 0; i + 1 < pathsAndBodies.length; i += 2) {
            out.put(pathsAndBodies[i], pathsAndBodies[i + 1]);
        }
        return out;
    }

    /** Base64 of {@code data}, so a fixture can embed an encoded payload. */
    public static String base64(byte[] data) {
        final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 3) {
            int b0 = data[i] & 0xFF;
            int b1 = i + 1 < data.length ? data[i + 1] & 0xFF : 0;
            int b2 = i + 2 < data.length ? data[i + 2] & 0xFF : 0;
            sb.append(alphabet.charAt(b0 >> 2));
            sb.append(alphabet.charAt(((b0 & 0x03) << 4) | (b1 >> 4)));
            sb.append(i + 1 < data.length ? alphabet.charAt(((b1 & 0x0F) << 2) | (b2 >> 6)) : '=');
            sb.append(i + 2 < data.length ? alphabet.charAt(b2 & 0x3F) : '=');
        }
        return sb.toString();
    }

    /** Bytes that begin like a Dalvik executable, for the encoded-payload fixture. */
    public static byte[] fakeDex(int length) {
        byte[] out = new byte[Math.max(length, 16)];
        byte[] magic = bytes("dex\n035\u0000");
        System.arraycopy(magic, 0, out, 0, Math.min(magic.length, out.length));
        for (int i = magic.length; i < out.length; i++) {
            out[i] = (byte) ((i * 31 + 7) & 0xFF);
        }
        return out;
    }

    /**
     * A deflated jar built in memory.
     *
     * <p>Compression is the point: the raw bytes of a deflated archive contain none of the strings its
     * members do, which is exactly why an archive has to be opened rather than skimmed.
     */
    public static byte[] deflatedJar(Map<String, byte[]> members) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(out);
            zip.setMethod(java.util.zip.ZipOutputStream.DEFLATED);
            zip.setLevel(9);
            for (Map.Entry<String, byte[]> member : members.entrySet()) {
                zip.putNextEntry(new java.util.zip.ZipEntry(member.getKey()));
                zip.write(member.getValue());
                zip.closeEntry();
            }
            zip.close();
        } catch (IOException e) {
            throw new IllegalStateException("could not build a jar fixture", e);
        }
        return out.toByteArray();
    }

    /** Bytes that begin with the real PNG signature, so a genuine image can be tested too. */
    public static byte[] fakePng(int length) {
        byte[] out = new byte[Math.max(length, 16)];
        byte[] magic = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
        System.arraycopy(magic, 0, out, 0, magic.length);
        for (int i = magic.length; i < out.length; i++) {
            out[i] = (byte) ((i * 17 + 3) & 0xFF);
        }
        return out;
    }

    /**
     * A minimal but structurally valid dex file whose string table holds exactly {@code strings}.
     *
     * <p>Enough for the declared-class check, which reads the string table and nothing else. The
     * header is real: magic, size, and the string_ids table at its documented offset, followed by the
     * string data items each as a ULEB128 length, modified UTF-8 and a NUL.
     */
    public static byte[] dexWithStrings(String... strings) {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        int[] offsets = new int[strings.length];
        int dataStart = 0x70 + strings.length * 4;
        for (int i = 0; i < strings.length; i++) {
            offsets[i] = dataStart + data.size();
            byte[] utf = bytes(strings[i]);
            int len = strings[i].length();
            // ULEB128 of the UTF-16 length
            do {
                int b = len & 0x7F;
                len >>>= 7;
                data.write(len != 0 ? (b | 0x80) : b);
            } while (len != 0);
            data.write(utf, 0, utf.length);
            data.write(0);
        }
        int total = dataStart + data.size();
        ByteArrayOutputStream out = new ByteArrayOutputStream(total);
        out.write(bytes("dex\n035\0"), 0, 8);
        writeInt(out, 0); // checksum
        for (int i = 0; i < 20; i++) {
            out.write(0); // signature
        }
        writeInt(out, total); // file_size
        writeInt(out, 0x70); // header_size
        writeInt(out, 0x12345678); // endian_tag
        writeInt(out, 0); // link_size
        writeInt(out, 0); // link_off
        writeInt(out, 0); // map_off
        writeInt(out, strings.length); // string_ids_size  @0x38
        writeInt(out, 0x70); // string_ids_off   @0x3C
        for (int i = 0; i < 12; i++) {
            writeInt(out, 0); // type/proto/field/method/class ids and data section
        }
        for (int i = 0; i < strings.length; i++) {
            writeInt(out, offsets[i]);
        }
        out.write(data.toByteArray(), 0, data.size());
        return out.toByteArray();
    }

    /** Bytes that the detector recognises as a WebP image, as real plugins ship their icons. */
    public static byte[] fakeWebp(int length) {
        byte[] out = new byte[Math.max(length, 20)];
        byte[] head = bytes("RIFF____WEBPVP8 ");
        System.arraycopy(head, 0, out, 0, head.length);
        for (int i = head.length; i < out.length; i++) {
            out[i] = (byte) ((i * 31 + 7) & 0xFF);
        }
        return out;
    }

    /** A manifest as MT Manager's v3 packager writes one. */
    public static String v3Manifest(String pluginId, String name, String mainPreference, String... interfaces) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"minAndroidVersion\": 21,\n  \"minHostVersion\": 26022600,\n");
        sb.append("  \"pluginSdkVersion\": 3,\n  \"pluginID\": \"").append(pluginId).append("\",\n");
        sb.append("  \"versionCode\": 1,\n  \"versionName\": \"v1.0\",\n");
        sb.append("  \"name\": \"").append(name).append("\",\n  \"description\": \"{plugin_description}\",\n");
        if (mainPreference != null && mainPreference.length() > 0) {
            sb.append("  \"mainPreference\": \"").append(mainPreference).append("\",\n");
        }
        if (interfaces.length > 0) {
            sb.append("  \"interfaces\": [");
            for (int i = 0; i < interfaces.length; i++) {
                sb.append(i > 0 ? ", " : "").append('"').append(interfaces[i]).append('"');
            }
            sb.append("],\n");
        }
        sb.append("  \"dexMode\": true\n}\n");
        return sb.toString();
    }

    /**
     * An installed plugin in MT Manager's own layout: {@code <root>/installed/<id>/plugin.mtp}.
     *
     * @return the plugin's folder, which is the install unit the scanner sees
     */
    public File installedArchive(String id, Map<String, byte[]> members) {
        File archive = rawArchive("installed/" + id + "/plugin.mtp", members, false);
        return archive.getParentFile();
    }

    /** Near-random bytes, for the packed-payload fixture. */
    public static byte[] highEntropy(int length) {
        byte[] out = new byte[length];
        long state = 0x9E3779B97F4A7C15L;
        for (int i = 0; i < length; i++) {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            out[i] = (byte) (state & 0xFF);
        }
        return out;
    }

    public static byte[] bytes(String text) {
        try {
            return text.getBytes("UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The directory fixtures are built under. */
    public File root() {
        return root;
    }

    /** Writes a file, for tests that need one outside the plugin layout. */
    public static void writeBytes(File file, byte[] content) {
        file.getParentFile().mkdirs();
        try {
            java.io.OutputStream out = new FileOutputStream(file);
            try {
                out.write(content);
            } finally {
                out.close();
            }
        } catch (IOException e) {
            throw new IllegalStateException("could not write " + file, e);
        }
    }

    public static void write(File file, String content) {
        writeFile(file, content);
    }

    private static void writeFile(File file, String content) {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("could not create " + parent);
        }
        try {
            OutputStream out = new FileOutputStream(file);
            try {
                out.write(bytes(content));
            } finally {
                out.close();
            }
        } catch (IOException e) {
            throw new IllegalStateException("could not write " + file, e);
        }
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >>> 24) & 0xFF);
    }
}
