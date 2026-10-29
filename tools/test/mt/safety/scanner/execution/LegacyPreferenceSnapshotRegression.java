package mt.safety.scanner.execution;

import java.io.*;
import java.lang.reflect.*;
import java.nio.file.Files;
import java.util.*;
import mt.safety.scanner.Host;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.core.Bytes;

/** Executes the real UI adapter's snapshot with SDK interfaces backed by a large preference store. */
public final class LegacyPreferenceSnapshotRegression {
    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("mt-legacy-preferences-").toFile();
        final FixtureHost host = new FixtureHost(new File(root, "scanner"));
        if (!host.root.mkdir()) throw new IOException("Could not create fixture scanner directory");
        for (int i = 0; i < 5000; i++) host.stored.put((i % 2 == 0 ? "arm_" : "sel_") + i, i % 3 == 0);
        host.stored.put(ScanRunner.KEY_COMMAND, "");
        host.stored.put(ScanRunner.KEY_EXTRA_ROOT, new File(root, "visible").getPath());
        host.stored.put(ScanRunner.KEY_LAST_RESULT, "last fixture result");
        host.stored.put(ScanRunner.KEY_PENDING_PLAN, "old pending fixture");
        host.stored.put(ScanRunner.KEY_DEEP, true);
        Class<?> preferenceType = Class.forName("android.content.SharedPreferences");
        final Object preferences = Proxy.newProxyInstance(preferenceType.getClassLoader(), new Class<?>[] {preferenceType},
                new InvocationHandler() {
                    @Override public Object invoke(Object proxy, Method method, Object[] arguments) {
                        if ("getAll".equals(method.getName())) return host.stored;
                        throw new AssertionError("Unexpected direct preference access: " + method.getName());
                    }
                });
        Class<?> contextType = Class.forName("bin.mt.plugin.api.PluginContext");
        Object context = Proxy.newProxyInstance(contextType.getClassLoader(), new Class<?>[] {contextType},
                new InvocationHandler() {
                    @Override public Object invoke(Object proxy, Method method, Object[] arguments) {
                        if ("getPreferences".equals(method.getName())) return preferences;
                        throw new AssertionError("Unexpected context access: " + method.getName());
                    }
                });
        Class<?> adapter = Class.forName("mt.safety.scanner.ui.IsolatedRunner");
        Constructor<?> constructor = adapter.getDeclaredConstructor(contextType, Host.class);
        constructor.setAccessible(true);
        Object runner = constructor.newInstance(context, host);
        Method snapshotMethod = adapter.getDeclaredMethod("snapshot"); snapshotMethod.setAccessible(true);
        WorkerProtocol.Snapshot snapshot;
        try { snapshot = (WorkerProtocol.Snapshot) snapshotMethod.invoke(runner); }
        catch (InvocationTargetException error) {
            throw new AssertionError("5000 historical flags must not prevent a scanner snapshot", error.getCause());
        }
        require(snapshot.values.size() == 4 && snapshot.flags.size() == 1, "Only five live settings cross IPC");
        require(snapshot.configFlag(ScanRunner.KEY_DEEP, false), "Deep scan preference survives");
        require("last fixture result".equals(snapshot.config(ScanRunner.KEY_LAST_RESULT, "")), "Live string survives");
        require(host.stored.size() == 5005, "Snapshot leaves historical stored state unchanged");
        require(host.reads.size() == 5, "Snapshot performs bounded point lookups independent of store size");

        File definitions = new File(host.root, ScanRunner.SIGNATURE_DIR); require(definitions.mkdir(), "Fixture definition directory");
        byte[] content = "inert known-signature fixture".getBytes("UTF-8");
        File sample = new File(root, "sample.bin"); Files.write(sample.toPath(), content);
        String signature = Bytes.hex(Bytes.digest("MD5", content)) + ":" + content.length + ":Test.HistoricalPreferenceFixture\n";
        Files.write(new File(definitions, "fixture.hdb").toPath(), signature.getBytes("UTF-8"));
        WorkerProtocol.Request request = new WorkerProtocol.Request(); request.operation = WorkerProtocol.FILES;
        request.host = snapshot; request.argument = sample.getPath();
        byte[] encoded = WorkerProtocol.encodeRequest(request);
        require(encoded.length < 2048, "5000 legacy flags cannot inflate the worker request");
        ByteArrayOutputStream requestWire = new ByteArrayOutputStream(); WorkerProtocol.writeMessage(requestWire, encoded);
        ByteArrayOutputStream responseWire = new ByteArrayOutputStream();
        ScannerWorker.serve(new ByteArrayInputStream(requestWire.toByteArray()), responseWire);
        WorkerProtocol.Response response = WorkerProtocol.decodeResponse(
                WorkerProtocol.readMessage(new ByteArrayInputStream(responseWire.toByteArray())));
        require(response.hits.size() == 1 && response.hits.get(0).contains("Test.HistoricalPreferenceFixture"),
                "Worker still scans and returns the exact fixture signature hit");
        System.out.println("PASS LegacyPreferenceSnapshotRegression (8 assertions, 5000 legacy flags, requestBytes=" + encoded.length + ")");
    }
    private static void require(boolean condition, String label) { if (!condition) throw new AssertionError(label); }
    private static final class FixtureHost implements Host {
        final File root;
        final Map<String, Object> stored = new LinkedHashMap<String, Object>();
        final Set<String> reads = new HashSet<String>();
        FixtureHost(File root) { this.root = root; }
        @Override public File filesDir() { return root; }
        @Override public String config(String key, String fallback) {
            reads.add(key); Object value = stored.get(key); return value instanceof String ? (String) value : fallback;
        }
        @Override public boolean configFlag(String key, boolean fallback) {
            reads.add(key); Object value = stored.get(key); return value instanceof Boolean ? (Boolean) value : fallback;
        }
        @Override public void putConfig(String key, String value) { throw new AssertionError("Snapshot must not mutate settings"); }
        @Override public void putFlag(String key, boolean value) { throw new AssertionError("Snapshot must not mutate settings"); }
        @Override public String language() { return "en"; }
        @Override public void log(String message) { }
        @Override public void log(String message, Throwable error) { }
        @Override public void toast(String message) { }
        @Override public String pluginId() { return "mt.safety.scanner"; }
        @Override public String hostPackage() { return "fixture.host"; }
    }
}
