package mt.safety.scanner.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The {@code manifest.json} every MT plugin must carry, as far as we can trust it.
 *
 * <p>Fields follow MT Manager's documented v2 plugin structure: {@code pluginSdkVersion},
 * {@code pluginID}, {@code versionCode}, {@code versionName}, {@code name}, {@code description},
 * {@code interfaces} and the optional {@code mainPreference}. Everything here is attacker-controlled
 * input, so parse failures are recorded rather than thrown.
 */
public final class PluginManifest {

    public final boolean present;
    public final String parseError;
    public final int sdkVersion;
    public final String pluginId;
    public final int versionCode;
    public final String versionName;
    public final String name;
    public final String description;
    public final List<String> interfaces;
    public final String mainPreference;
    public final Map<String, Object> raw;

    private PluginManifest(boolean present, String parseError, Map<String, Object> raw) {
        this.present = present;
        this.parseError = parseError;
        this.raw = raw;
        if (raw == null) {
            this.sdkVersion = -1;
            this.pluginId = "";
            this.versionCode = -1;
            this.versionName = "";
            this.name = "";
            this.description = "";
            this.interfaces = Collections.emptyList();
            this.mainPreference = "";
            return;
        }
        this.sdkVersion = Json.integer(raw, "pluginSdkVersion", -1);
        this.pluginId = Json.str(raw, "pluginID", "");
        this.versionCode = Json.integer(raw, "versionCode", -1);
        this.versionName = Json.str(raw, "versionName", "");
        this.name = localized(raw, "name");
        this.description = localized(raw, "description");
        this.interfaces = Json.stringList(raw, "interfaces");
        this.mainPreference = Json.str(raw, "mainPreference", "");
    }

    /** A manifest that could not be found in the package. */
    public static PluginManifest missing() {
        return new PluginManifest(false, null, null);
    }

    /** A manifest that was found but is not usable. */
    public static PluginManifest broken(String parseError) {
        return new PluginManifest(true, parseError, null);
    }

    /** Parses manifest bytes; never throws. */
    public static PluginManifest parse(byte[] data) {
        if (data == null || data.length == 0) {
            return missing();
        }
        try {
            return new PluginManifest(true, null, Json.parseObject(Bytes.text(data)));
        } catch (Json.JsonException e) {
            return broken(e.getMessage());
        }
    }

    public boolean usable() {
        return present && raw != null;
    }

    /** The class names this plugin declares as entry points, preference screen included. */
    public List<String> declaredClasses() {
        List<String> out = new ArrayList<String>(interfaces);
        if (mainPreference != null && mainPreference.length() > 0) {
            out.add(mainPreference);
        }
        return out;
    }

    /** Best display name, falling back to the id. */
    public String displayName() {
        if (name != null && name.length() > 0) {
            return name;
        }
        return pluginId != null && pluginId.length() > 0 ? pluginId : "(unnamed)";
    }

    /**
     * Reads a field that MT Manager allows to be localized.
     *
     * <p>Such a field is either a plain string or an object keyed by language code, so both shapes
     * are accepted and an object collapses to its English entry, or its first entry.
     */
    @SuppressWarnings("unchecked")
    private static String localized(Map<String, Object> raw, String key) {
        Object value = raw.get(key);
        if (value instanceof String) {
            return (String) value;
        }
        if (value instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) value;
            Object english = map.get("en");
            if (english instanceof String) {
                return (String) english;
            }
            for (Object item : map.values()) {
                if (item instanceof String) {
                    return (String) item;
                }
            }
        }
        return Json.str(raw, key, "");
    }
}
