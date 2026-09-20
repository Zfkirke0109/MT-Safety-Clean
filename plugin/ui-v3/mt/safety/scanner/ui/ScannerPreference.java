package mt.safety.scanner.ui;

import android.content.SharedPreferences;

import java.io.File;

import bin.mt.plugin.api.PluginContext;
import bin.mt.plugin.api.preference.PluginPreference;
import bin.mt.plugin.api.ui.PluginUI;
import bin.mt.plugin.api.ui.dialog.PluginDialog;

import mt.safety.scanner.Host;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.Strings;

import mt.safety.scanner.core.ScanReport;

/**
 * The plugin's settings screen, for MT Manager plugin SDK v3, and the only class that touches an MT
 * Manager type.
 *
 * <p>v3 is the reason this file differs from its v2 sibling. v2 gave a plugin one screen built once
 * out of read-only rows and switches, with no click callback: the design there was to arm an action
 * with a switch and run it on the next open. v3 gives a plugin real click callbacks
 * ({@link PluginPreference.Text#onClick}) and real dialogs ({@link PluginUI#buildDialog}), so this
 * screen offers a button under each flagged plugin that opens a Quarantine / Remove / Cancel dialog
 * and acts at once, and a "Quarantine all" / "Remove all" button for the whole malicious set. The
 * dialog the user confirms is the confirmation the typed path used to get from a code.
 *
 * <p>Everything below the click is the same pure-Java core the v2 build uses, reached through
 * {@link Host}. Porting between v2 and v3 is editing this one file: the context type changed from
 * {@code MTPluginContext} to {@code PluginContext}, and the scan and actions did not.
 */
public class ScannerPreference implements PluginPreference {

    private PluginContext context;
    private ScanRunner runner;
    private Strings strings;
    private ScanRunner.Result result;
    private PreferenceScreen screen;

    @Override
    public void onBuild(PluginContext context, Builder builder) {
        this.context = context;
        seedIndicatorFile(context);
        this.runner = new ScanRunner(new MtHost(context));
        this.strings = runner.strings();

        try {
            this.result = runner.run();
        } catch (RuntimeException e) {
            context.log("scan failed", e);
            builder.title(safe(strings.screenTitle()));
            builder.addText(safe(strings.problem())).summary(safe(String.valueOf(e)));
            return;
        }

        builder.title(safe(strings.screenTitle()));
        builder.subtitle(safe(strings.screenSubtitle()));

        // Keep the screen so an action can rebuild it in place after moving a plugin.
        builder.onCreated(new OnPreferenceScreenCreatedListener() {
            @Override
            public void onPreferenceScreenCreated(PluginUI ui, PreferenceScreen created) {
                screen = created;
            }
        });

        int malicious = runner.actionTargets(result, "malicious").size();
        int suspicious = runner.actionTargets(result, "suspicious").size();
        if (malicious > 0 || suspicious > 0) {
            builder.addHeader(safe(strings.actionsHeader()));
            if (malicious > 0) {
                addBulkButton(builder, "malicious", true, malicious);
                addBulkButton(builder, "malicious", false, malicious);
            }
            if (suspicious > malicious) {
                addBulkButton(builder, "suspicious", false, suspicious);
            }
        }

        renderRows(builder, result.rows);

        builder.addHeader(safe(strings.commandsHeader()));
        builder.addSwitch(safe(strings.deepSwitchTitle()), ScanRunner.KEY_DEEP)
                .defaultValue(false)
                .summaryOn(safe(strings.deepOn()))
                .summaryOff(safe(strings.deepOff()));
        builder.addInput(safe(strings.commandFieldTitle()), ScanRunner.KEY_COMMAND);
        builder.addText(safe(strings.commandsHelpTitle())).summary(safe(strings.commandsHelp()));

        renderRows(builder, result.aboutRows);
    }

    /** A "Quarantine/Remove all X (N)" button that confirms in a dialog before acting. */
    private void addBulkButton(Builder builder, final String scope, final boolean remove, int count) {
        builder.addText(safe(strings.bulkButton(remove ? "remove" : "quarantine", scope, count)))
                .summary(safe(strings.bulkButtonHelp(remove)))
                .onClick(new OnTextItemClickListener() {
                    @Override
                    public void onClick(PluginUI ui, PreferenceItem item) {
                        confirmBulk(ui, scope, remove);
                    }
                });
    }

    private void confirmBulk(final PluginUI ui, final String scope, final boolean remove) {
        StringBuilder names = new StringBuilder();
        java.util.List<ScanReport> targets = runner.actionTargets(result, scope);
        for (int i = 0; i < targets.size() && i < 12; i++) {
            if (names.length() > 0) {
                names.append('\n');
            }
            names.append("• ").append(safe(targets.get(i).manifest.displayName()));
        }
        if (targets.size() > 12) {
            names.append('\n').append(safe(strings.andMore(targets.size() - 12)));
        }
        ui.buildDialog()
                .setTitle(safe(strings.confirmTitle(remove ? "remove" : "quarantine")))
                .setMessage(safe(strings.confirmBody(remove, targets.size()) + "\n\n" + names))
                .setPositiveButton(safe(strings.confirmAct(remove)), new PluginDialog.OnClickListener() {
                    @Override
                    public void onClick(PluginDialog dialog, int which) {
                        String outcome = runner.actOnScope(result, scope, remove);
                        finishAction(ui, outcome);
                    }
                })
                .setNegativeButton(safe(strings.cancel()), null)
                .show();
    }

    /** One flagged plugin's row: a button that opens a Quarantine / Remove / Cancel dialog. */
    private void addPluginButton(Builder builder, final ScanReport report, String title, String summary) {
        builder.addText(safe(title)).summary(safe(summary)).onClick(new OnTextItemClickListener() {
            @Override
            public void onClick(PluginUI ui, PreferenceItem item) {
                ui.buildDialog()
                        .setTitle(safe(report.manifest.displayName()))
                        .setMessage(safe(strings.actOneBody(report.verdict().label())))
                        .setPositiveButton(safe(strings.confirmAct(false)), new PluginDialog.OnClickListener() {
                            @Override
                            public void onClick(PluginDialog dialog, int which) {
                                finishAction(ui, runner.actOnOne(result, report, false));
                            }
                        })
                        .setNeutralButton(safe(strings.confirmAct(true)), new PluginDialog.OnClickListener() {
                            @Override
                            public void onClick(PluginDialog dialog, int which) {
                                finishAction(ui, runner.actOnOne(result, report, true));
                            }
                        })
                        .setNegativeButton(safe(strings.cancel()), null)
                        .show();
            }
        });
    }

    /** Reports the outcome and rebuilds the screen so acted-on plugins drop off the list. */
    private void finishAction(PluginUI ui, String outcome) {
        if (outcome != null && outcome.length() > 0) {
            ui.showToast(safe(outcome));
            context.log("action: " + outcome);
        }
        if (screen != null) {
            screen.recreate();
        }
    }

    /**
     * Renders the scanner's rows.
     *
     * <p>A row the core marked actionable becomes a button that acts on that one plugin; every other
     * row is read-only text. {@code java.util.List} is spelled out because implementing
     * {@link PluginPreference} brings its nested {@code List} option type into scope.
     */
    private void renderRows(Builder builder, java.util.List<ScanRunner.Row> rows) {
        for (int i = 0; i < rows.size(); i++) {
            ScanRunner.Row row = rows.get(i);
            if (row.header) {
                builder.addHeader(safe(row.title));
            } else if (row.toggle && row.report != null) {
                addPluginButton(builder, row.report, row.title, row.summary);
            } else {
                builder.addText(safe(row.title)).summary(safe(row.summary));
            }
        }
    }

    /**
     * Puts a documented, empty indicator file in the plugin's folder on first run, so the user has a
     * file to record a trust decision in. Only ever created, never overwritten.
     */
    private static void seedIndicatorFile(PluginContext context) {
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
     * Makes a string safe to display. MT Manager resolves <code>{name}</code> in preference and dialog
     * text against the plugin's language files; report lines quote source code full of braces, so the
     * braces are neutralised before display or they would drive lookups in this plugin's own resources.
     */
    private static String safe(String value) {
        if (value == null) {
            return "";
        }
        String flat = value.replace('{', '(').replace('}', ')');
        return flat.length() > 4000 ? flat.substring(0, 3997) + "..." : flat;
    }

    /** Adapts MT Manager's v3 plugin context to the scanner's {@link Host} interface. */
    private static final class MtHost implements Host {
        private final PluginContext context;

        MtHost(PluginContext context) {
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
                return prefs == null ? fallback : prefs.getBoolean(key, fallback);
            } catch (ClassCastException e) {
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

        @Override
        public String hostPackage() {
            try {
                String pkg = context.getHostPackageName();
                return pkg == null || pkg.length() == 0 ? "bin.mt.plus" : pkg;
            } catch (RuntimeException e) {
                return "bin.mt.plus";
            }
        }
    }
}
