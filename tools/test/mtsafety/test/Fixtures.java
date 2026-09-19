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
     * Writes a ZIP by hand.
     *
     * @param duplicateFirstMember when true, the first member is written into the archive twice, so the
     *                             file a reviewer reads need not be the file that is extracted
     */
    public File rawArchive(String name, Map<String, byte[]> members, boolean duplicateFirstMember) {
        File file = new File(root, name);
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
            throw new IllegalStateException("could not build fixture " + name, e);
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
