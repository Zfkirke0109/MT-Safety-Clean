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
        int flagged = runner.actionTargets(result, "flagged").size();
        int pending = runner.uninstallTargets(result).size();
        int held = runner.quarantinedCount();
        if (flagged > 0 || pending > 0 || held > 0) {
            builder.addHeader(safe(strings.actionsHeader()));
            // The button the switches below feed into. Shown even at zero, so the count is visible
            // as switches are turned on and it is obvious what they are for.
            addUninstallButton(builder, pending, held);
            if (flagged > 0) {
                addBulkButton(builder, "flagged", false, flagged);
            }
            if (malicious > 0) {
                addBulkButton(builder, "malicious", true, malicious);
            }
        }

        renderRows(builder, result.rows);

        builder.addHeader(safe(strings.commandsHeader()));
        // The file scan: the same signatures the plugin scan uses, run over the folders MT Manager
        // can read. Offered here rather than under Actions because it changes nothing; it reports.
        addFileScanButton(builder);
        builder.addSwitch(safe(strings.deepSwitchTitle()), ScanRunner.KEY_DEEP)
                .defaultValue(false)
                .summaryOn(safe(strings.deepOn()))
                .summaryOff(safe(strings.deepOff()));
        builder.addInput(safe(strings.commandFieldTitle()), ScanRunner.KEY_COMMAND);
        builder.addText(safe(strings.commandsHelpTitle())).summary(safe(strings.commandsHelp()));

        renderRows(builder, result.aboutRows);
    }

    /**
     * The uninstall button: deletes everything selected by a switch, everything the scan called
     * malicious, and everything already sitting in quarantine.
     */
    private void addUninstallButton(Builder builder, final int targets, final int held) {
        builder.addText(safe(strings.uninstallButton(targets + held)))
                .summary(safe(strings.uninstallButtonHelp()))
                .onClick(new OnTextItemClickListener() {
                    @Override
                    public void onClick(PluginUI ui, PreferenceItem item) {
                        confirmUninstall(ui, targets, held);
                    }
                });
    }

    private void confirmUninstall(final PluginUI ui, int targets, int held) {
        StringBuilder names = new StringBuilder();
        java.util.List<ScanReport> list = runner.uninstallTargets(result);
        for (int i = 0; i < list.size() && i < 12; i++) {
            if (names.length() > 0) {
                names.append('\n');
            }
            names.append("\u2022 ").append(safe(list.get(i).manifest.displayName()));
        }
        if (list.size() > 12) {
            names.append('\n').append(safe(strings.andMore(list.size() - 12)));
        }
        String body = strings.uninstallBody(targets, held);
        if (names.length() > 0) {
            body = body + "\n\n" + names;
        }
        ui.buildDialog()
                .setTitle(safe(strings.uninstallTitle()))
                .setMessage(safe(body))
                .setPositiveButton(safe(strings.confirmAct(true)), new PluginDialog.OnClickListener() {
                    @Override
                    public void onClick(PluginDialog dialog, int which) {
                        finishAction(ui, runner.uninstallSelection(result));
                    }
                })
                .setNegativeButton(safe(strings.cancel()), null)
                .show();
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

    /**
     * A button that checks the files this plugin can read against the loaded malware signatures.
     *
     * <p>With no signatures loaded the row still appears, saying what it needs: a button that only
     * shows up once the user has done the thing it depends on is a button they never find.
     */
    private void addFileScanButton(Builder builder) {
        final int signatures = runner.signatureCount();
        builder.addText(safe(strings.filesButton()))
                .summary(safe(strings.filesButtonHelp(signatures)))
                .onClick(new OnTextItemClickListener() {
                    @Override
                    public void onClick(PluginUI ui, PreferenceItem item) {
                        if (signatures == 0) {
                            ui.showToast(safe(strings.noSignatures()));
                            return;
                        }
                        confirmFileScan(ui, signatures);
                    }
                });
    }

    private void confirmFileScan(final PluginUI ui, int signatures) {
        StringBuilder roots = new StringBuilder();
        java.util.List<File> list = runner.fileScanRoots();
        for (int i = 0; i < list.size() && i < 8; i++) {
            if (roots.length() > 0) {
                roots.append('\n');
            }
            roots.append("\u2022 ").append(list.get(i).getAbsolutePath());
        }
        if (list.size() > 8) {
            roots.append('\n').append(safe(strings.andMore(list.size() - 8)));
        }
        boolean deep = false;
        try {
            SharedPreferences prefs = context.getPreferences();
            deep = prefs != null && prefs.getBoolean(ScanRunner.KEY_DEEP, false);
        } catch (RuntimeException e) {
            // A missing preference store means the quick scan, which is the safe default.
        }
        ui.buildDialog()
                .setTitle(safe(strings.filesConfirmTitle()))
                .setMessage(safe(strings.filesConfirmBody(roots.toString(), signatures, deep)))
                .setPositiveButton(safe(strings.scanAction()), new PluginDialog.OnClickListener() {
                    @Override
                    public void onClick(PluginDialog dialog, int which) {
                        runFileScan(ui);
                    }
                })
                .setNegativeButton(safe(strings.cancel()), null)
                .show();
    }

    /** Runs the scan and shows what it found in a dialog; the screen itself needs no rebuild. */
    private void runFileScan(PluginUI ui) {
        java.util.List<String> hits = new java.util.ArrayList<String>();
        String outcome;
        try {
            outcome = runner.scanFiles("", hits);
        } catch (RuntimeException e) {
            context.log("file scan failed", e);
            outcome = strings.commandFailed(String.valueOf(e.getMessage()));
        }
        context.log("file scan: " + outcome);
        StringBuilder body = new StringBuilder(outcome);
        for (int i = 0; i < hits.size(); i++) {
            body.append("\n\n").append(hits.get(i));
        }
        ui.buildDialog()
                .setTitle(safe(strings.filesResultTitle()))
                .setMessage(safe(body.toString()))
                .setPositiveButton(safe(strings.dismiss()), null)
                .show();
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
            } else if (row.toggle && row.key != null) {
                // A switch, not an action: it marks this plugin for the uninstall button. Nothing
                // happens while the screen is open, so one touched by accident can be turned off.
                builder.addSwitch(safe(row.title), row.key)
                        .defaultValue(false)
                        .summaryOn(safe(strings.selectedOn()))
                        .summaryOff(safe(row.summary));
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
