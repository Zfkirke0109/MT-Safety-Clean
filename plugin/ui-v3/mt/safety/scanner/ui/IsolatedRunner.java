package mt.safety.scanner.ui;

import java.io.*;
import java.util.*;
import bin.mt.plugin.api.PluginContext;
import mt.safety.scanner.*;
import mt.safety.scanner.execution.*;

/** Android-only process adapter. Unsupported/denied runtime launch fails closed, never in-process. */
final class IsolatedRunner {
    private final PluginContext context;
    private final Host host;
    private final Strings strings;
    private int signatures, quarantined;
    private final List<File> roots = new ArrayList<File>();

    IsolatedRunner(PluginContext context, Host host) {
        this.context = context; this.host = host; this.strings = Strings.forLanguage(host.language());
    }
    Strings strings() { return strings; }
    int signatureCount() { return signatures; }
    int quarantinedCount() { return quarantined; }
    List<File> fileScanRoots() { return new ArrayList<File>(roots); }
    ScanRunner.Result run() throws IOException { return runWithCommand(""); }
    ScanRunner.Result exportShareSafeReport() throws IOException { return runWithCommand("export-shareable"); }
    private ScanRunner.Result runWithCommand(String command) throws IOException {
        WorkerProtocol.Response response = execute(WorkerProtocol.RUN, command);
        if (response.result == null) throw new IOException("Worker returned no scan; inspection incomplete");
        signatures = response.signatures; quarantined = response.quarantined; roots.clear();
        for (String path : response.roots) roots.add(new File(path));
        return response.result;
    }
    String scanFiles(String argument, List<String> hits) throws IOException {
        WorkerProtocol.Response response = execute(WorkerProtocol.FILES, argument);
        hits.addAll(response.hits); return response.outcome;
    }
    private WorkerProtocol.Snapshot snapshot() throws IOException {
        WorkerProtocol.Snapshot snapshot = new WorkerProtocol.Snapshot();
        snapshot.directory = host.filesDir().getCanonicalPath(); snapshot.pluginId = host.pluginId();
        snapshot.hostPackage = host.hostPackage(); snapshot.language = host.language();
        // Only current settings are part of a worker request. Per-package arm_/sel_ flags from
        // older scanner versions can accumulate without bound and have no role in read-only scans.
        snapshot.values.put(ScanRunner.KEY_COMMAND, host.config(ScanRunner.KEY_COMMAND, ""));
        snapshot.values.put(ScanRunner.KEY_EXTRA_ROOT, host.config(ScanRunner.KEY_EXTRA_ROOT, ""));
        snapshot.values.put(ScanRunner.KEY_LAST_RESULT, host.config(ScanRunner.KEY_LAST_RESULT, ""));
        snapshot.values.put(ScanRunner.KEY_PENDING_PLAN, host.config(ScanRunner.KEY_PENDING_PLAN, ""));
        snapshot.flags.put(ScanRunner.KEY_DEEP, host.configFlag(ScanRunner.KEY_DEEP, false));
        return snapshot;
    }
    private WorkerProtocol.Response execute(int operation, String argument) throws IOException {
        if (operation != WorkerProtocol.RUN && operation != WorkerProtocol.FILES) {
            throw new IOException("Unsupported read-only worker operation");
        }
        WorkerProtocol.Request request = new WorkerProtocol.Request(); request.operation = operation;
        request.host = snapshot(); request.argument = operation == WorkerProtocol.FILES ? argument : "";
        // A button-triggered export must neither execute nor erase an unrelated typed command.
        final boolean preservePendingCommand = operation == WorkerProtocol.RUN && argument.length() > 0;
        if (preservePendingCommand) request.host.values.put(ScanRunner.KEY_COMMAND, argument);
        byte[] encoded = WorkerProtocol.encodeRequest(request);
        ProcessSupervisor.checkAvailable();
        File dex = extractWorker();
        Process process = null;
        try {
            // Consume a typed command before dispatch so an interrupted operation is not replayed.
            if (operation == WorkerProtocol.RUN && !preservePendingCommand
                    && request.host.config(ScanRunner.KEY_COMMAND, "").length() > 0) {
                host.putConfig(ScanRunner.KEY_COMMAND, "");
            }
            ProcessBuilder builder = AndroidWorkerLaunch.builder(dex);
            process = builder.start();
            byte[] reply = ProcessSupervisor.exchange(process, encoded,
                    request.host.configFlag(ScanRunner.KEY_DEEP, false) ? 90000L : 45000L,
                    new ProcessSupervisor.Terminator() {
                        @Override public void terminate(Process child, int trustedPid) {
                            try { child.exitValue(); }
                            catch (IllegalThreadStateException alive) {
                                try {
                                    if (trustedPid > 0 && trustedPid != android.os.Process.myPid()) {
                                        android.os.Process.killProcess(trustedPid);
                                    }
                                } finally { child.destroy(); }
                            }
                        }
                    });
            WorkerProtocol.Response response = WorkerProtocol.decodeResponse(reply);
            for (Map.Entry<String, String> e : response.changedValues.entrySet()) {
                if (!preservePendingCommand || !ScanRunner.KEY_COMMAND.equals(e.getKey())) {
                    host.putConfig(e.getKey(), e.getValue());
                }
            }
            for (Map.Entry<String, Boolean> e : response.changedFlags.entrySet()) host.putFlag(e.getKey(), e.getValue());
            return response;
        } catch (SecurityException denied) {
            throw new IOException("Scanner worker launch denied; inspection unavailable", denied);
        } finally {
            if (process != null) process.destroy();
            if (!dex.delete()) dex.deleteOnExit();
        }
    }
    private File extractWorker() throws IOException {
        File directory = context.getFilesDir().getCanonicalFile();
        if (!directory.isDirectory()) throw new IOException("Scanner private directory unavailable");
        File target = File.createTempFile("scanner-worker-", ".dex", directory);
        boolean complete = false;
        try {
            if (!target.getCanonicalFile().getParentFile().equals(directory)) throw new IOException("Worker path escaped private directory");
            InputStream in = context.getAssetsAsStream("scanner-worker.dex");
            if (in == null) throw new IOException("Scanner worker asset missing; inspection unavailable");
            try {
                OutputStream out = new FileOutputStream(target);
                try {
                    // Android 14 requires dynamically loaded code to be read-only before loading.
                    // Mark after opening the private write descriptor and before writing any code.
                    if (!target.setReadOnly()) throw new IOException("Could not protect scanner worker asset");
                    byte[] buffer = new byte[8192]; int n, total = 0;
                    while ((n = in.read(buffer)) != -1) {
                        total += n;
                        if (total > WorkerProtocol.MAX_BYTES) throw new IOException("Scanner worker asset limit");
                        out.write(buffer, 0, n);
                    }
                    if (total < 8) throw new IOException("Scanner worker asset incomplete");
                } finally { out.close(); }
            } finally { in.close(); }
            complete = true; return target;
        } finally { if (!complete) target.delete(); }
    }
}
