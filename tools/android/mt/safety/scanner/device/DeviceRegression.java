package mt.safety.scanner.device;

import java.io.*;
import java.util.*;
import android.system.Os;
import android.system.OsConstants;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.core.*;
import mt.safety.scanner.execution.*;

/** Scanner-owned ART harness. Uses only newly created fixtures beneath the supplied scratch root. */
public final class DeviceRegression {
    private static int checks;
    private DeviceRegression() { }
    public static void main(String[] args) throws Exception {
        if (args.length == 1 && "--stall".equals(args[0])) {
            DataOutputStream output = new DataOutputStream(System.out);
            output.writeInt(WorkerProtocol.MAGIC); output.writeInt(Os.getpid()); output.flush();
            Thread.sleep(60000); return;
        }
        if (args.length != 2) throw new IllegalArgumentException("worker.dex scratch-directory required");
        File worker = new File(args[0]).getCanonicalFile(), root = new File(args[1]).getCanonicalFile();
        if (!root.isDirectory() || !worker.isFile()) throw new IOException("Missing dedicated harness inputs");
        File fixtures = new File(root, "fixtures");
        require(fixtures.mkdir(), "fresh fixture directory");
        byte[] content = "inert device signature fixture".getBytes("UTF-8");
        File sample = new File(fixtures, "sample.bin");
        require(AtomicFiles.createIfAbsent(sample, content), "no-overwrite initial publication");
        require(!AtomicFiles.createIfAbsent(sample, new byte[] {0}), "existing file survives publication");
        File absent = new File(fixtures, "absent"), link = new File(fixtures, "dangling-link");
        Os.symlink(absent.getAbsolutePath(), link.getAbsolutePath());
        require(!AtomicFiles.createIfAbsent(link, content) && !absent.exists(), "dangling link is never followed");
        File special = new File(fixtures, "spaces and\nnewlines;$literal");
        require(AtomicFiles.createIfAbsent(special, new byte[] {1}), "special-name fixture");
        final List<String> names = new ArrayList<String>();
        System.setProperty("mtsafety.forceLegacyDirectoryStream", "true");
        try {
            DirectoryListing.forEachChild(fixtures, new DirectoryListing.Visitor() {
                @Override public void visit(File file) { names.add(file.getName()); }
            });
        } finally { System.clearProperty("mtsafety.forceLegacyDirectoryStream"); }
        require(names.size() == 3 && names.contains(special.getName()), "legacy toybox listing preserves exact names");

        ProcessBuilder probeBuilder = AndroidWorkerLaunch.builder(worker);
        probeBuilder.command().add("--probe");
        Process probe = probeBuilder.start();
        String text = read(probe.getInputStream());
        require(probe.waitFor() == 0 && text.contains("MT_WORKER_PROBE"), "app UID launches actual worker");
        long heap = Long.parseLong(text.trim().substring(text.indexOf("maxHeap=") + 8));
        require(heap <= 100L * 1024 * 1024, "worker heap allowance is enforced");
        System.out.println(text.trim());

        File scanner = new File(root, "scanner"); require(scanner.mkdir(), "fresh scanner directory");
        File definitions = new File(scanner, ScanRunner.SIGNATURE_DIR); require(definitions.mkdir(), "fresh definitions");
        byte[] definition = (Bytes.hex(Bytes.digest("MD5", content)) + ":" + content.length
                + ":Test.Device.Inert\n").getBytes("UTF-8");
        require(AtomicFiles.createIfAbsent(new File(definitions, "inert.hdb"), definition), "inert signature fixture");
        WorkerProtocol.Request request = new WorkerProtocol.Request(); request.operation = WorkerProtocol.FILES;
        request.host = new WorkerProtocol.Snapshot(); request.host.directory = scanner.getPath();
        request.host.pluginId = "mt.safety.scanner"; request.host.hostPackage = "test.scanner.harness";
        request.host.language = "en"; request.argument = sample.getPath();
        Process child = AndroidWorkerLaunch.builder(worker).start();
        WorkerProtocol.Response response = WorkerProtocol.decodeResponse(ProcessSupervisor.exchange(child,
                WorkerProtocol.encodeRequest(request), 10000, terminator()));
        require(response.hits.size() == 1 && response.hits.get(0).contains("Test.Device.Inert"), "real worker IPC returns exact fixture hit");
        require(child.exitValue() == 0, "successful worker exits");

        Process stalled = start(System.getenv("CLASSPATH"), DeviceRegression.class.getName(), "--stall");
        long began = System.nanoTime(); boolean timedOut = false;
        try { ProcessSupervisor.exchange(stalled, WorkerProtocol.encodeRequest(request), 200, terminator()); }
        catch (IOException expected) { timedOut = expected.getMessage().contains("timed out"); }
        require(timedOut && (System.nanoTime() - began) / 1000000L < 3000, "supervisor enforces wall deadline");
        require(exited(stalled), "timed-out child termination is confirmed");

        final Process cancelled = start(System.getenv("CLASSPATH"), DeviceRegression.class.getName(), "--stall");
        final byte[] wire = WorkerProtocol.encodeRequest(request); final boolean[] interrupted = {false};
        Thread caller = new Thread(new Runnable() {
            @Override public void run() {
                try { ProcessSupervisor.exchange(cancelled, wire, 10000, terminator()); }
                catch (IOException expected) { interrupted[0] = expected.getMessage().contains("cancelled"); }
            }
        });
        caller.start(); Thread.sleep(200); caller.interrupt(); caller.join(3000);
        require(!caller.isAlive() && interrupted[0] && exited(cancelled), "cancellation confirms child termination");
        ProcessSupervisor.checkAvailable();
        System.out.println("DeviceRegression: " + checks + " checks passed; uid=" + Os.getuid());
    }
    private static Process start(String classpath, String main, String... arguments) throws IOException {
        List<String> argv = new ArrayList<String>(Arrays.asList(AndroidWorkerLaunch.runtime(), "-Xmx96m", "-cp", classpath, main));
        Collections.addAll(argv, arguments); ProcessBuilder builder = new ProcessBuilder(argv);
        builder.environment().put("CLASSPATH", classpath); builder.environment().remove("LD_PRELOAD");
        return builder.start();
    }
    private static ProcessSupervisor.Terminator terminator() {
        return new ProcessSupervisor.Terminator() {
            @Override public void terminate(Process process, int pid) {
                if (!exited(process)) {
                    try {
                        if (pid > 0 && pid != Os.getpid()) Os.kill(pid, OsConstants.SIGKILL);
                    } catch (android.system.ErrnoException failure) {
                        throw new IllegalStateException("Could not terminate owned harness child", failure);
                    }
                    finally { process.destroy(); }
                }
            }
        };
    }
    private static boolean exited(Process process) {
        try { process.exitValue(); return true; } catch (IllegalThreadStateException alive) { return false; }
    }
    private static String read(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(); byte[] buffer = new byte[1024]; int n;
        while ((n = input.read(buffer)) >= 0) {
            if (output.size() + n > 4096) throw new IOException("Probe output limit");
            output.write(buffer, 0, n);
        }
        return new String(output.toByteArray(), "UTF-8");
    }
    private static void require(boolean condition, String label) {
        checks++; if (!condition) throw new AssertionError(label); System.out.println("PASS " + label);
    }
}
