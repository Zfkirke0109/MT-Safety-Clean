package mt.safety.scanner.ui;

import android.content.SharedPreferences;

import java.io.File;

import bin.mt.plugin.api.MTPluginContext;
import bin.mt.plugin.api.preference.PluginPreference;

import mt.safety.scanner.Host;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.Strings;

/**
 * The plugin's settings screen, and the only class that touches an MT Manager type.
 *
 * <p>MT Manager gives a plugin one place to put a user interface: the screen named by
 * {@code mainPreference} in {@code manifest.json}, built once through {@code onBuild} out of headers,
 * read-only text rows, switches and text inputs. There is no button, no click callback and no way to
 * redraw. So opening this screen performs the scan and the screen is the report; typed commands take
 * effect the next time it opens, which also means a partly typed command can never act.
 *
 * <p>Keeping every MT reference in this one file is deliberate. MT Manager's plugin SDK renamed the
 * context type between v2 ({@code MTPluginContext}) and v3 ({@code PluginContext}); porting this plugin
 * to v3 means editing this file alone. See {@code variants/} in the repository.
 */
public class ScannerPreference implements PluginPreference {

    @Override
    public void onBuild(MTPluginContext context, Builder builder) {
        seedIndicatorFile(context);
        ScanRunner runner = new ScanRunner(new MtHost(context));
        Strings strings = runner.strings();

        ScanRunner.Result result;
        try {
            result = runner.run();
        } catch (RuntimeException e) {
            // A failure here would otherwise leave the user with an empty screen and no explanation.
            context.log("scan failed", e);
            builder.addHeader(safe(strings.screenTitle()));
            builder.addText(safe(strings.problem())).summary(safe(String.valueOf(e)));
            return;
        }

        builder.addHeader(safe(strings.screenTitle()));
        builder.addText(safe(strings.screenSubtitle())).summary(safe(strings.limits()));

        render(builder, result.rows);

        builder.addHeader(safe(strings.commandsHeader()));
        builder.addSwitch(safe(strings.deepSwitchTitle()), ScanRunner.KEY_DEEP)
                .defaultValue(false)
                .summaryOn(safe(strings.deepOn()))
                .summaryOff(safe(strings.deepOff()));
        builder.addInput(safe(strings.commandFieldTitle()), ScanRunner.KEY_COMMAND);
        builder.addText(safe(strings.commandsHelpTitle())).summary(safe(strings.commandsHelp()));

        render(builder, result.aboutRows);
    }

    /**
     * Renders rows.
     *
     * <p>{@code java.util.List} is spelled out in full here: implementing {@link PluginPreference}
     * brings its nested {@code List} option type into scope, which shadows the collection type.
     */
    private void render(Builder builder, java.util.List<ScanRunner.Row> rows) {
        for (int i = 0; i < rows.size(); i++) {
            ScanRunner.Row row = rows.get(i);
            if (row.header) {
                builder.addHeader(safe(row.title));
            } else {
                builder.addText(safe(row.title)).summary(safe(row.summary));
            }
        }
    }

    /**
     * Puts a documented, empty indicator file in the plugin's folder on first run.
     *
     * <p>Without this the user has to invent the file's format before they can record a trust
     * decision. The copy is only ever created, never overwritten, so their edits survive updates.
     */
    private static void seedIndicatorFile(MTPluginContext context) {
        try {
            File target = new File(context.getFilesDir(), "indicators.json");
            if (target.exists()) {
                return;
            }
            File parent = target.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                return;
            }
            java.io.InputStream in = context.getAssetsAsStream("indicators.json");
            if (in == null) {
                return;
            }
            try {
                java.io.OutputStream out = new java.io.FileOutputStream(target);
                try {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                    }
                } finally {
                    out.close();
                }
            } finally {
                in.close();
            }
        } catch (java.io.IOException e) {
            context.log("could not create indicators.json", e);
        } catch (RuntimeException e) {
            context.log("could not create indicators.json", e);
        }
    }

    /**
     * Makes a string safe to hand to MT Manager's preference builder.
     *
     * <p>MT Manager resolves <code>{name}</code> in preference text against the plugin's language files.
     * Report lines quote source code, which is full of braces, so braces are replaced before display.
     * Without this, evidence from a scanned plugin would drive lookups in this plugin's own resources.
     */
    private static String safe(String value) {
        if (value == null) {
            return "";
        }
        String flat = value.replace('{', '(').replace('}', ')');
        return flat.length() > 1000 ? flat.substring(0, 997) + "..." : flat;
    }

    /** Adapts MT Manager's plugin context to the scanner's {@link Host} interface. */
    private static final class MtHost implements Host {
        private final MTPluginContext context;

        MtHost(MTPluginContext context) {
            this.context = context;
        }

        @Override
        public File filesDir() {
            return context.getFilesDir();
        }

        @Override
        public String config(String key, String fallback) {
            try {
                SharedPreferences prefs = context.getPreferences();
                return prefs == null ? fallback : prefs.getString(key, fallback);
            } catch (RuntimeException e) {
                return fallback;
            }
        }

        @Override
        public boolean configFlag(String key, boolean fallback) {
            try {
                SharedPreferences prefs = context.getPreferences();
                if (prefs == null) {
                    return fallback;
                }
                return prefs.getBoolean(key, fallback);
            } catch (ClassCastException e) {
                // A switch and a command sharing a key type would land here; prefer the default.
                return fallback;
            } catch (RuntimeException e) {
                return fallback;
            }
        }

        @Override
        public void putConfig(String key, String value) {
            try {
                SharedPreferences prefs = context.getPreferences();
                if (prefs == null) {
                    return;
                }
                if (value == null) {
                    prefs.edit().remove(key).apply();
                } else {
                    prefs.edit().putString(key, value).apply();
                }
            } catch (RuntimeException e) {
                context.log("could not store " + key, e);
            }
        }

        @Override
        public void putFlag(String key, boolean value) {
            try {
                SharedPreferences prefs = context.getPreferences();
                if (prefs != null) {
                    // Stored as a boolean because MT Manager's switch widget is bound to this same key
                    // and reads it with getBoolean, outside this plugin's own error handling.
                    prefs.edit().putBoolean(key, value).apply();
                }
            } catch (RuntimeException e) {
                context.log("could not store " + key, e);
            }
        }

        @Override
        public String language() {
            try {
                return context.getLanguage();
            } catch (RuntimeException e) {
                return "en";
            }
        }

        @Override
        public void log(String message) {
            context.log(message);
        }

        @Override
        public void log(String message, Throwable error) {
            context.log(message, error);
        }

        @Override
        public void toast(String message) {
            context.showToast(message);
        }

        @Override
        public String pluginId() {
            try {
                return context.getPluginId();
            } catch (RuntimeException e) {
                return "mt.safety.scanner";
            }
        }
    }
}
