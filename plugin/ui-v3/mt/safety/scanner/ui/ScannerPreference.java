package mt.safety.scanner.ui;

import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import java.lang.ref.WeakReference;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import mt.safety.scanner.execution.SingleFlight;

import java.io.File;

import bin.mt.plugin.api.PluginContext;
import bin.mt.plugin.api.preference.PluginPreference;
import bin.mt.plugin.api.ui.PluginUI;
import bin.mt.plugin.api.ui.dialog.PluginDialog;

import mt.safety.scanner.Host;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.Strings;


/**
 * SDK3 scan/report screen. Other-plugin file management stays in MT Manager's own controls.
 * Scanner work and local report exports run in the bounded scanner-owned worker.
 */
public class ScannerPreference implements PluginPreference {

    private PluginContext context;
    private IsolatedRunner runner;
    private Strings strings;
    private ScanRunner.Result result;
    private WeakReference<PreferenceScreen> screen = new WeakReference<PreferenceScreen>(null);
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final SingleFlight WORK = new SingleFlight(new Executor() {
        @Override public void execute(Runnable task) { MAIN.post(task); }
    });
    private boolean busy, renderCached;
    private long operationGeneration, viewGeneration;
    private int operation;
    private String status = "";
    private static final int SCAN = 1, FILES = 2, EXPORT = 3;


    @Override
    public void onBuild(PluginContext context, Builder builder) {
        this.context = context;
        final long view = ++viewGeneration;
        if (runner == null) {
            runner = new IsolatedRunner(context, new MtHost(context));
            strings = runner.strings();
        }
        builder.title(safe(strings.screenTitle()));
        builder.subtitle(safe(strings.screenSubtitle()));
        builder.onCreated(new OnPreferenceScreenCreatedListener() {
            @Override public void onPreferenceScreenCreated(PluginUI ui, PreferenceScreen created) {
                if (view == viewGeneration) screen = new WeakReference<PreferenceScreen>(created);
            }
        });
        if (!busy && !renderCached) startWork(SCAN);
        renderCached = false;
        if (busy) {
            builder.addText(operation == SCAN ? "Scanning plugins…" : operation == FILES ? "Scanning files…" : "Exporting share-safe report…")
                    .summary("You can leave this screen. Results appear when the operation finishes.");
            if (operation == SCAN || operation == FILES || operation == EXPORT) {
                builder.addText("Cancel operation").onClick(new OnTextItemClickListener() {
                    @Override public void onClick(PluginUI ui, PreferenceItem item) {
                        if (busy) {
                            WORK.cancel();
                            item.setSummary("Cancellation requested; waiting for the worker to stop.");
                        }
                    }
                });
            }
            return;
        }
        if (status.length() > 0) builder.addText("Scanner status").summary(safe(status));
        builder.addText("Scan again / run command").onClick(new OnTextItemClickListener() {
            @Override public void onClick(PluginUI ui, PreferenceItem item) {
                if (!busy) { startWork(SCAN); redraw(); }
            }
        });
        builder.addText("Export share-safe report")
                .summary("Save a content-free report for sharing, with findings and coverage but no evidence snippets.")
                .onClick(new OnTextItemClickListener() {
                    @Override public void onClick(PluginUI ui, PreferenceItem item) {
                        if (!busy) { startWork(EXPORT); redraw(); }
                    }
                });
        builder.addHeader(safe(strings.managementDelegatedTitle()));
        builder.addText(safe(strings.managementDelegatedTitle())).summary(safe(strings.managementDelegated()));
        if (result == null) return;
        int held = runner.quarantinedCount();
        if (held > 0) {
            builder.addText("Historical quarantine")
                    .summary("Stored entries: " + held + ". Review or manage these files in MT Manager. The scanner leaves them unchanged.");
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
        if (busy) return;
        final long view = viewGeneration;
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
                        if (view != viewGeneration || busy) return;
                        startWork(FILES);
                        redraw();
                    }
                })
                .setNegativeButton(safe(strings.cancel()), null)
                .show();
    }

    /** Scan, definition reads and report exports never run on a UI callback. */
    private void startWork(int kind) {
        if (busy) return;
        long token = ++operationGeneration;
        operation = kind;
        busy = true;
        status = "";
        boolean accepted = WORK.submit(new Operation(context, runner, kind), new Completion(this, token, kind));
        if (!accepted) {
            busy = false;
            status = "Another scanner operation is still running. Wait for it to finish and scan again.";
        }
    }

    private void redraw() {
        renderCached = true;
        PreferenceScreen current = screen.get();
        if (current != null) {
            try { current.recreate(); }
            catch (RuntimeException detached) { screen.clear(); }
        }
    }

    private static final class Outcome {
        ScanRunner.Result scan;
        String text = "";
    }

    /** Holds no preference-screen or PluginUI reference while the background work is running. */
    private static final class Operation implements Callable<Outcome> {
        private final PluginContext context;
        private final IsolatedRunner runner;
        private final int kind;
        Operation(PluginContext context, IsolatedRunner runner, int kind) {
            this.context = context; this.runner = runner; this.kind = kind;
        }
        @Override public Outcome call() throws Exception {
            Outcome outcome = new Outcome();
            if (kind == SCAN || kind == EXPORT) {
                seedIndicatorFile(context);
                outcome.scan = kind == SCAN ? runner.run() : runner.exportShareSafeReport();
            } else {
                java.util.List<String> hits = new java.util.ArrayList<String>();
                StringBuilder body = new StringBuilder(runner.scanFiles("", hits));
                for (String hit : hits) body.append("\n\n").append(hit);
                outcome.text = body.toString();
            }
            return outcome;
        }
    }

    private static final class Completion implements SingleFlight.Callback<Outcome> {
        private final WeakReference<ScannerPreference> owner;
        private final long token;
        private final int kind;
        Completion(ScannerPreference owner, long token, int kind) {
            this.owner = new WeakReference<ScannerPreference>(owner); this.token = token; this.kind = kind;
        }
        @Override public void completed(Outcome outcome, Throwable error) {
            ScannerPreference current = owner.get();
            if (current == null || current.operationGeneration != token) return;
            current.busy = false;
            if (error != null) {
                current.result = null;
                current.status = kind == EXPORT
                        ? "Export unavailable, cancelled or incomplete. No completed share-safe export was confirmed."
                        : "Scan unavailable, cancelled or incomplete. No all-clear was produced. "
                                + (error.getMessage() == null ? "Worker failed." : error.getMessage());
            } else if (kind == SCAN || kind == EXPORT) {
                current.result = outcome.scan;
                current.status = kind == EXPORT ? outcome.scan.commandOutcome
                        : "Scan finished. Review the findings and coverage below.";
            } else {
                current.status = outcome.text;
            }
            current.redraw();
        }
    }

    /** Findings remain read-only, including legacy action rows returned by an older report. */
    private void renderRows(Builder builder, java.util.List<ScanRunner.Row> rows) {
        for (int i = 0; i < rows.size(); i++) {
            ScanRunner.Row row = rows.get(i);
            if (row.header) {
                builder.addHeader(safe(row.title));
            } else if (row.toggle) {
                builder.addText(safe(strings.managementDelegatedTitle())).summary(safe(strings.managementDelegated()));
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
                byte[] content = mt.safety.scanner.core.Bytes.readAtMost(in, 1024 * 1024 + 1);
                if (content.length > 1024 * 1024) throw new java.io.IOException("Indicator asset limit");
                mt.safety.scanner.core.AtomicFiles.createIfAbsent(target, content);
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
