package mt.safety.scanner.execution;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.core.*;

/** Own-code child fixtures exercise actual pipes, process death and bounded IPC on the desktop JVM. */
public final class WorkerBoundaryRegression {
    private static int checks;
    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "child".equals(args[0])) { child(args[1]); return; }
        if (args.length == 3 && "request".equals(args[0])) {
            FileOutputStream out = new FileOutputStream(args[1]);
            try { WorkerProtocol.writeMessage(out, WorkerProtocol.encodeRequest(request(args[2]))); }
            finally { out.close(); }
            return;
        }
        if (args.length == 2 && "decode".equals(args[0])) {
            DataInputStream in = new DataInputStream(new FileInputStream(args[1]));
            try {
                check(in.readInt() == WorkerProtocol.MAGIC, "Android handshake magic");
                int pid = in.readInt();
                WorkerProtocol.Response response = WorkerProtocol.decodeResponse(WorkerProtocol.readMessage(in));
                System.out.println("Android worker response pid=" + pid + " outcomeCharacters=" + response.outcome.length());
            } finally { in.close(); }
            return;
        }
        WorkerProtocol.Response response = new WorkerProtocol.Response(); response.result = new ScanRunner.Result();
        PluginManifest manifest = PluginManifest.parse("{\"pluginID\":\"fixture.id\",\"name\":\"Fixture\"}".getBytes("UTF-8"));
        ScanReport report = new ScanReport("fixture", "/fixture/plugin.mtp", true, true, manifest, "digest");
        report.setVerdict(Verdict.KNOWN_BAD, "exact signature"); report.setTruncated(true); report.setScore(100);
        report.setDestructiveActionIdentity(true, "/fixture");
        report.add(new Signal("SIG001", Category.values()[0], Severity.CRITICAL, "Exact hit", "fixture"));
        response.result.reports.add(report); response.result.rows.add(ScanRunner.Row.toggle("Fixture", "Detail", "key", report));
        response.changedValues.put("removed", null); response.changedFlags.put("selected", false);
        WorkerProtocol.Response roundtrip = WorkerProtocol.decodeResponse(WorkerProtocol.encodeResponse(response));
        ScanReport copy = roundtrip.result.reports.get(0);
        check(copy.verdict() == Verdict.KNOWN_BAD && copy.truncated(), "malware and partial coverage survive transport");
        check(copy.destructiveActionIdentityComplete() && "/fixture".equals(copy.actionIdentityPath()), "action identity survives transport");
        check(copy.manifest.pluginId.equals("fixture.id") && copy.contentHash.equals("digest"), "identity fields survive transport");
        check(roundtrip.result.rows.get(0).report == copy, "row references preserve report identity");
        check(roundtrip.changedValues.containsKey("removed") && roundtrip.changedValues.get("removed") == null, "preference removals preserved");
        expectBad(new byte[WorkerProtocol.MAX_BYTES + 1], "oversized message rejected");
        byte[] valid = WorkerProtocol.encodeResponse(response);
        expectBad(Arrays.copyOf(valid, valid.length - 1), "truncated response rejected");
        expectBad(Arrays.copyOf(valid, valid.length + 1), "trailing response rejected");
        WorkerProtocol.Request request = request(System.getProperty("java.io.tmpdir") + "/mt-worker-fixture-empty");
        new File(request.host.directory).mkdirs();
        byte[] wire = WorkerProtocol.encodeRequest(request);
        Process process = launch("ok");
        byte[] reply = ProcessSupervisor.exchange(process, wire, 3000, terminator());
        check(WorkerProtocol.decodeResponse(reply).outcome.length() > 0, "actual child scanner invocation completed");
        for (String mode : new String[] {"hang", "flood", "oversize", "oom", "bad-handshake", "no-handshake"}) {
            process = launch(mode); long begin = System.nanoTime(); boolean rejected = false;
            try { ProcessSupervisor.exchange(process, wire, 400, terminator()); }
            catch (IOException expected) { rejected = true; }
            check(rejected, mode + " fails closed");
            check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begin) < 2500, mode + " has bounded return");
            check(process.waitFor(2, TimeUnit.SECONDS), mode + " child is dead after supervision");
        }
        final FakeLiveProcess deniedKill = new FakeLiveProcess();
        boolean failedStop = false;
        try { ProcessSupervisor.exchange(deniedKill, wire, 20, new ProcessSupervisor.Terminator() {
            @Override public void terminate(Process child, int pid) { }
        }); } catch (IOException expected) { failedStop = true; }
        check(failedStop, "unconfirmed termination fails closed");
        boolean blocked = false;
        try { ProcessSupervisor.checkAvailable(); } catch (IOException expected) { blocked = true; }
        check(blocked, "unconfirmed child prevents repeated worker launches");
        deniedKill.alive = false; ProcessSupervisor.checkAvailable();
        check(true, "launch gate recovers only after previous child exit is confirmed");
        System.out.println("PASS WorkerBoundaryRegression (" + checks + " checks)");
    }
    private static final class FakeLiveProcess extends Process {
        volatile boolean alive = true;
        @Override public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
        @Override public InputStream getInputStream() { return new ByteArrayInputStream(new byte[0]); }
        @Override public InputStream getErrorStream() { return new ByteArrayInputStream(new byte[0]); }
        @Override public int waitFor() { return 0; }
        @Override public int exitValue() { if (alive) throw new IllegalThreadStateException(); return 0; }
        @Override public void destroy() { }
    }
    private static WorkerProtocol.Request request(String directory) {
        WorkerProtocol.Request request = new WorkerProtocol.Request(); request.operation = WorkerProtocol.FILES;
        request.host = new WorkerProtocol.Snapshot(); request.host.directory = directory;
        request.host.language = "en"; request.host.pluginId = "mt.safety.scanner"; request.host.hostPackage = "fixture.none";
        return request;
    }
    private static Process launch(String mode) throws IOException {
        return new ProcessBuilder(new File(System.getProperty("java.home"), "bin/java").getPath(), "-Xmx24m", "-cp",
                System.getProperty("java.class.path"), WorkerBoundaryRegression.class.getName(), "child", mode).start();
    }
    private static ProcessSupervisor.Terminator terminator() {
        return new ProcessSupervisor.Terminator() {
            @Override public void terminate(Process child, int pid) { child.destroyForcibly(); }
        };
    }
    private static void child(String mode) throws Exception {
        if ("no-handshake".equals(mode)) { Thread.sleep(30000); return; }
        DataOutputStream out = new DataOutputStream(System.out);
        out.writeInt("bad-handshake".equals(mode) ? 0 : WorkerProtocol.MAGIC); out.writeInt(12345); out.flush();
        if ("ok".equals(mode)) { ScannerWorker.serve(System.in, out); return; }
        if ("oversize".equals(mode)) { out.writeInt(WorkerProtocol.MAX_BYTES + 1); out.flush(); return; }
        if ("flood".equals(mode)) { byte[] bytes = new byte[1024]; while (true) System.err.write(bytes); }
        if ("oom".equals(mode)) {
            List<byte[]> memory = new ArrayList<byte[]>(); while (true) memory.add(new byte[1024 * 1024]);
        }
        Thread.sleep(30000);
    }
    private static void expectBad(byte[] bytes, String label) throws Exception {
        boolean bad = false; try { WorkerProtocol.decodeResponse(bytes); } catch (IOException expected) { bad = true; }
        check(bad, label);
    }
    private static void check(boolean ok, String label) { checks++; if (!ok) throw new AssertionError(label); }
}
