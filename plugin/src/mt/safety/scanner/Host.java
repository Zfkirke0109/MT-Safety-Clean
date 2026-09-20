package mt.safety.scanner;

import java.io.File;

/**
 * Everything the scanner needs from its surroundings.
 *
 * <p>This interface is the seam between the scanner and MT Manager. All the logic sits behind it, so
 * only one small class ({@code ui.ScannerPreference}) mentions an MT type at all. That matters
 * practically: MT Manager renamed the plugin context between plugin SDK v2 ({@code MTPluginContext})
 * and v3 ({@code PluginContext}), and porting between them means editing that one file rather than
 * hunting through the scanner.
 */
public interface Host {

    /** A directory this plugin owns and may write to. */
    File filesDir();

    /** Persisted configuration value, or {@code fallback}. */
    String config(String key, String fallback);

    /** Persisted flag, or {@code fallback}. */
    boolean configFlag(String key, boolean fallback);

    /** Stores a configuration value. Passing null removes the key. */
    void putConfig(String key, String value);

    /**
     * Stores a flag.
     *
     * <p>Separate from {@link #putConfig} because the host stores values by type: a switch written as
     * the string "true" is not a boolean the host can read back, and the widget bound to the same key
     * fails on it.
     */
    void putFlag(String key, boolean value);

    /** Two-letter language code, e.g. {@code en} or {@code zh}. */
    String language();

    /** Writes to the host's plugin log. */
    void log(String message);

    /** Writes a failure to the host's plugin log. */
    void log(String message, Throwable error);

    /** Shows a brief message to the user. */
    void toast(String message);

    /** This plugin's own id, so the scanner can leave itself out of its results. */
    String pluginId();

    /**
     * The package name of the MT Manager this plugin runs inside, e.g. {@code bin.mt.plus}.
     *
     * <p>MT Manager keeps installed plugins under its own private storage, so knowing which build
     * of it is hosting us is what turns "search likely places" into "look in the right one".
     */
    String hostPackage();
}
