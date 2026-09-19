package mt.safety.scanner.core;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * The user's own trust decisions and indicator lists.
 *
 * <p>Deliberately local and user-owned. The scanner ships no list of "known malicious plugin hashes",
 * because a hash list invented by its author would be worthless and a hash list fetched from a server
 * would give the scanner a remote dependency exactly where the user needs certainty. Instead:
 *
 * <ul>
 *   <li><b>trusted</b> - content hashes the user has decided are fine. A match silences the report.
 *   <li><b>denied</b> - content hashes or plugin ids the user, or someone they trust, has marked bad.
 *   <li><b>patterns</b> - extra regular expressions to treat as high severity, so a user can add an
 *       endpoint or string from an advisory without waiting for a new build.
 * </ul>
 */
public final class IocDatabase {

    /** One entry in the trusted or denied list. */
    public static final class Record {
        public final String value;
        public final String note;

        public Record(String value, String note) {
            this.value = value;
            this.note = note == null ? "" : note;
        }
    }

    private final Map<String, Record> trusted = new LinkedHashMap<String, Record>();
    private final Map<String, Record> denied = new LinkedHashMap<String, Record>();
    private final List<Pattern> patterns = new ArrayList<Pattern>();
    private final List<String> patternSources = new ArrayList<String>();
    private final List<String> loadErrors = new ArrayList<String>();

    /** An empty database, used when no file exists yet. */
    public static IocDatabase empty() {
        return new IocDatabase();
    }

    /** Parses a database from JSON text; malformed input yields an empty database plus an error. */
    public static IocDatabase parse(String json) {
        IocDatabase db = new IocDatabase();
        if (json == null || json.trim().length() == 0) {
            return db;
        }
        try {
            Map<String, Object> root = Json.parseObject(json);
            db.readRecords(Json.objectList(root, "trusted"), db.trusted);
            db.readRecords(Json.objectList(root, "denied"), db.denied);
            List<String> regexes = Json.stringList(root, "patterns");
            for (int i = 0; i < regexes.size(); i++) {
                String regex = regexes.get(i);
                try {
                    db.patterns.add(Pattern.compile(regex, Pattern.CASE_INSENSITIVE));
                    db.patternSources.add(regex);
                } catch (PatternSyntaxException e) {
                    db.loadErrors.add("ignored invalid pattern: " + regex);
                }
            }
        } catch (Json.JsonException e) {
            db.loadErrors.add("could not read the indicator file: " + e.getMessage());
        }
        return db;
    }

    /** Reads a database from disk; a missing file is not an error. */
    public static IocDatabase load(File file) {
        if (file == null || !file.isFile()) {
            return empty();
        }
        try {
            java.io.InputStream in = new java.io.FileInputStream(file);
            try {
                byte[] data = Bytes.readAtMost(in, 2 * 1024 * 1024);
                return parse(Bytes.text(data));
            } finally {
                PluginPackage.closeQuietly(in);
            }
        } catch (IOException e) {
            IocDatabase db = new IocDatabase();
            db.loadErrors.add("could not open " + file.getName() + ": " + e.getMessage());
            return db;
        }
    }

    private void readRecords(List<Map<String, Object>> items, Map<String, Record> into) {
        for (int i = 0; i < items.size(); i++) {
            Map<String, Object> item = items.get(i);
            String value = Json.str(item, "value", "");
            if (value.length() == 0) {
                continue;
            }
            into.put(value.toLowerCase(java.util.Locale.US),
                    new Record(value, Json.str(item, "note", "")));
        }
    }

    public boolean isTrusted(String contentHash) {
        return contentHash != null && trusted.containsKey(contentHash.toLowerCase(java.util.Locale.US));
    }

    public Record trustedRecord(String contentHash) {
        return contentHash == null ? null : trusted.get(contentHash.toLowerCase(java.util.Locale.US));
    }

    /** Returns the denylist entry matching a hash or plugin id, or null. */
    public Record deniedRecord(String contentHash, String pluginId) {
        if (contentHash != null) {
            Record byHash = denied.get(contentHash.toLowerCase(java.util.Locale.US));
            if (byHash != null) {
                return byHash;
            }
        }
        if (pluginId != null && pluginId.length() > 0) {
            return denied.get(pluginId.toLowerCase(java.util.Locale.US));
        }
        return null;
    }

    public List<Pattern> patterns() {
        return patterns;
    }

    public List<String> patternSources() {
        return patternSources;
    }

    public List<String> loadErrors() {
        return loadErrors;
    }

    public int trustedCount() {
        return trusted.size();
    }

    public int deniedCount() {
        return denied.size();
    }

    /** Records a content hash as trusted. */
    public void trust(String contentHash, String note) {
        if (contentHash != null && contentHash.length() > 0) {
            trusted.put(contentHash.toLowerCase(java.util.Locale.US), new Record(contentHash, note));
        }
    }

    /** Removes a content hash from the trusted list. */
    public void untrust(String contentHash) {
        if (contentHash != null) {
            trusted.remove(contentHash.toLowerCase(java.util.Locale.US));
        }
    }

    /** Records a hash or plugin id as known bad. */
    public void deny(String value, String note) {
        if (value != null && value.length() > 0) {
            denied.put(value.toLowerCase(java.util.Locale.US), new Record(value, note));
        }
    }

    /** Serialises the database as JSON. */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"trusted\": [\n");
        appendRecords(sb, trusted);
        sb.append("  ],\n  \"denied\": [\n");
        appendRecords(sb, denied);
        sb.append("  ],\n  \"patterns\": [\n");
        for (int i = 0; i < patternSources.size(); i++) {
            sb.append("    ").append(Json.quote(patternSources.get(i)));
            sb.append(i + 1 < patternSources.size() ? ",\n" : "\n");
        }
        sb.append("  ]\n}\n");
        return sb.toString();
    }

    private void appendRecords(StringBuilder sb, Map<String, Record> records) {
        int index = 0;
        for (Record record : records.values()) {
            sb.append("    {\"value\": ").append(Json.quote(record.value));
            sb.append(", \"note\": ").append(Json.quote(record.note)).append("}");
            sb.append(++index < records.size() ? ",\n" : "\n");
        }
    }

    /** Writes the database to disk, creating parent directories as needed. */
    public void save(File file) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("could not create " + parent.getAbsolutePath());
        }
        Writer writer = new OutputStreamWriter(new FileOutputStream(file), "UTF-8");
        try {
            writer.write(toJson());
        } finally {
            PluginPackage.closeQuietly(writer);
        }
    }
}
