package mtsafety.test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import mt.safety.scanner.Host;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Verdict;

/** Exercises real scan orchestration, private exports and same-metadata signature replacement. */
public final class RunnerExportRegression {
    private static int checks;
    private RunnerExportRegression() { }
    private static void check(boolean ok, String why) { checks++; if (!ok) throw new AssertionError(why); }
    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("runner-export-").toFile();
        File files = new File(root, "a/b/c/d/files"); if (!files.mkdirs()) throw new AssertionError("mkdir");
        final ActionsTest.FakeHost delegate = new ActionsTest.FakeHost(files);
        final int[] retiredWrites = {0};
        Host host = new Host() {
            public File filesDir() { return delegate.filesDir(); }
            public String config(String key, String fallback) { return delegate.config(key, fallback); }
            public boolean configFlag(String key, boolean fallback) { return delegate.configFlag(key, fallback); }
            public void putConfig(String key, String value) { delegate.putConfig(key, value); }
            public void putFlag(String key, boolean value) {
                if (key.startsWith(ScanRunner.KEY_ARM_PREFIX) || key.startsWith(ScanRunner.KEY_SELECT_PREFIX)) retiredWrites[0]++;
                delegate.putFlag(key, value);
            }
            public String language() { return delegate.language(); }
            public String pluginId() { return delegate.pluginId(); }
            public String hostPackage() { return delegate.hostPackage(); }
            public void log(String message) { }
            public void log(String message, Throwable error) { }
            public void toast(String message) { }
        };
        File plugins = new File(root, "a/plugins"); if (!plugins.mkdir()) throw new AssertionError("mkdir plugins");
        String secret = "private albatross orchard phrase";
        new Fixtures(plugins).directoryPlugin("private-plugin",
                Fixtures.manifest("demo.export", secret, "demo.A"),
                Fixtures.sources("src/demo/A.java", "package demo; public class A { String value=\"AB\"; } // " + secret));
        delegate.putConfig(ScanRunner.KEY_EXTRA_ROOT, plugins.getAbsolutePath());
        ScanRunner runner = new ScanRunner(host);
        ScanRunner.Result initial = runner.run();
        check(initial.reports.size() == 1, "only fixture discovered");
        check(retiredWrites[0] == 0, "read-only scans do not create retired preference keys");
        delegate.type("export-shareable");
        ScanRunner.Result shared = runner.run();
        String text = read(new File(files, "scan-report-share-safe.txt"));
        String json = read(new File(files, "scan-report-share-safe.json"));
        check(shared.commandOutcome.startsWith("SHARE_SAFE:"), "explicit share-safe command succeeds");
        check(text.contains("SHARE-SAFE") && json.contains("SHARE_SAFE"), "privacy mode is explicit in both exports");
        check(!text.contains(secret) && !json.contains(secret) && !json.contains(plugins.getAbsolutePath())
                && !json.contains(initial.reports.get(0).contentHash), "arbitrary content, identity and source hashes absent");
        check(json.contains("\"discoveryComplete\":true") && json.contains("\"unscannedCandidates\":0"),
                "share export includes bounded discovery scope");
        delegate.type("export"); runner.run();
        check(read(new File(files, "scan-report.txt")).contains(secret)
                && read(new File(files, "scan-report.json")).contains("coverageLedger"),
                "local export retains useful private evidence and ledger");
        File defs = new File(files, ScanRunner.SIGNATURE_DIR); if (!defs.mkdir()) throw new AssertionError("mkdir defs");
        File ndb = new File(defs, "cache.ndb");
        Files.write(ndb.toPath(), "CacheRule:0:*:4142\n".getBytes(StandardCharsets.UTF_8));
        check(forId(runner.run(), "demo.export").verdict() == Verdict.KNOWN_BAD, "initial cached signature applies");
        long modified = ndb.lastModified();
        Files.write(ndb.toPath(), "CacheRule:0:*:4344\n".getBytes(StandardCharsets.UTF_8));
        check(ndb.setLastModified(modified), "restore signature mtime");
        check(forId(runner.run(), "demo.export").verdict() != Verdict.KNOWN_BAD,
                "runner refreshes same-size same-mtime replaced definitions");
        check(retiredWrites[0] == 0, "exports and changed scans do not accumulate action flags");
        byte[] large = new byte[4 * 1024 * 1024 + 100]; java.util.Arrays.fill(large, (byte) 'A');
        File prefix = new File(root, "prefix.bin"); Files.write(prefix.toPath(), large);
        String incomplete = runner.scanFiles(prefix.getPath(), new java.util.ArrayList<String>());
        check(incomplete.toLowerCase(java.util.Locale.US).contains("incomplete"),
                "immediate file summary exposes prefix or matcher limits");
        System.out.println(checks + " runner/export checks passed");
    }
    private static String read(File file) throws Exception { return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8); }
    private static ScanReport forId(ScanRunner.Result result, String id) {
        for (ScanReport report : result.reports) if (id.equals(report.manifest.pluginId)) return report;
        throw new AssertionError("report not found");
    }
}
