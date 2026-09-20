package mt.safety.scanner.core;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads MT Manager's {@code .mtl} language files, enough to resolve a plugin's display name.
 *
 * <p>The format is one {@code key: value} per line, {@code #} comments, a trailing backslash
 * continuing onto the next line, and the usual escapes. It is what a v3 package's
 * <code>{plugin_name}</code> manifest entry points at, in {@code assets/strings.mtl} or a sibling
 * with a language suffix.
 */
public final class Mtl {

    /** Largest language file worth reading for one name. */
    public static final int MAX_BYTES = 64 * 1024;

    private Mtl() {
    }

    /** Parses {@code text}; malformed lines are skipped rather than failing the whole file. */
    public static Map<String, String> parse(String text) {
        Map<String, String> out = new LinkedHashMap<String, String>();
        if (text == null) {
            return out;
        }
        String[] lines = text.split("\r?\n");
        int i = 0;
        while (i < lines.length) {
            String line = lines[i++];
            String trimmed = line.trim();
            if (trimmed.length() == 0 || trimmed.startsWith("#")) {
                continue;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String key = line.substring(0, colon).trim();
            StringBuilder value = new StringBuilder(line.substring(colon + 1).trim());
            while (value.length() > 0 && value.charAt(value.length() - 1) == '\\' && i < lines.length) {
                value.setLength(value.length() - 1);
                value.append(lines[i++].trim());
            }
            if (key.length() > 0) {
                out.put(key, unescape(value.toString()));
            }
        }
        return out;
    }

    /**
     * The file names to try for a key, best first.
     *
     * <p>MT Manager's documented default pack is {@code strings}, the v2 examples use {@code String},
     * and real plugins use both. A language-suffixed file is preferred for {@code language} when one
     * exists; the base file is the fallback MT Manager itself uses.
     *
     * @param pack the pack a <code>{pack:key}</code> reference names, or null for the default pack
     */
    public static List<String> candidateFiles(List<PluginPackage.Entry> entries, String pack, String language) {
        List<String> preferred = new java.util.ArrayList<String>();
        List<String> base = new java.util.ArrayList<String>();
        List<String> other = new java.util.ArrayList<String>();
        for (PluginPackage.Entry entry : entries) {
            String name = entry.name;
            if (entry.directory || !name.startsWith("assets/") || !name.endsWith(".mtl")
                    || name.indexOf('/', "assets/".length()) >= 0) {
                continue;
            }
            String stem = name.substring("assets/".length(), name.length() - ".mtl".length());
            int dash = stem.indexOf('-');
            String filePack = dash < 0 ? stem : stem.substring(0, dash);
            String lang = dash < 0 ? "" : stem.substring(dash + 1);
            // A bare {key} is looked up in the default pack; {pack:key} names its pack. A file from
            // some other pack is only a last resort, for a plugin whose single pack has an odd name.
            boolean wanted = pack != null
                    ? filePack.equalsIgnoreCase(pack)
                    : filePack.equalsIgnoreCase("strings") || filePack.equalsIgnoreCase("string");
            boolean languageMatch = language != null && language.length() > 0 && lang.equalsIgnoreCase(language);
            if (wanted && languageMatch) {
                preferred.add(name);
            } else if (wanted && lang.length() == 0) {
                base.add(name);
            } else if (lang.length() == 0 || languageMatch) {
                other.add(name);
            }
        }
        preferred.addAll(base);
        preferred.addAll(other);
        return preferred;
    }

    private static String unescape(String value) {
        if (value.indexOf('\\') < 0) {
            return value;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) {
                sb.append(c);
                continue;
            }
            char next = value.charAt(++i);
            switch (next) {
                case 'n':
                    sb.append('\n');
                    break;
                case 'r':
                    sb.append('\r');
                    break;
                case 't':
                    sb.append('\t');
                    break;
                default:
                    sb.append(next);
            }
        }
        return sb.toString();
    }
}
