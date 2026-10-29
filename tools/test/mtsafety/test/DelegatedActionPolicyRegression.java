package mtsafety.test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import mt.safety.scanner.Quarantine;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.Strings;
import mt.safety.scanner.core.Coverage;
import mt.safety.scanner.core.PluginPackage;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;

/** Every compatibility action entry refuses while preserving complete source/store snapshots. */
public final class DelegatedActionPolicyRegression {
    private DelegatedActionPolicyRegression() { }

    public static void main(String[] args) throws Exception {
        final int[] counts = {0, 0};
        run(new ActionsTest.Checker() {
            @Override
            public void that(String description, boolean condition, String context) {
                counts[condition ? 0 : 1]++;
                System.out.println((condition ? "PASS " : "FAIL ") + description + ": " + context);
            }
        });
        System.out.println(counts[0] + " passed, " + counts[1] + " failed");
        if (counts[1] > 0) {
            throw new AssertionError("delegation failures: " + counts[1]);
        }
    }

    static void run(ActionsTest.Checker c) throws Exception {
        File root = Files.createTempDirectory("mtsafety-delegation-").toFile();
        File files = new File(root, "a/b/c/d/files");
        if (!files.mkdirs()) { throw new IOException("cannot create fixture"); }
        Fixtures fixtures = new Fixtures(new File(root, "a/plugins"));
        Map<String, String> risky = Collections.singletonMap("src/x/A.java",
                "package x; public class A { void f() { Runtime.getRuntime().exec(\"rm -rf /sdcard\"); } }");
        File source = fixtures.directoryPlugin("victim", Fixtures.manifest("victim.one", "Victim", "x.A"), risky);
        Fixtures.write(new File(source, "plugin-owned.txt"), "plugin-owned metadata must survive");
        File store = new File(files, "quarantine");
        File held = new File(store, "old-victim");
        Fixtures.write(new File(held, "payload.bin"), "historically held bytes");
        File recovery = new File(root, "original-parent/recovered-plugin");
        Fixtures.write(new File(held, "quarantine-info.json"), "{\"pluginId\":\"old.victim\",\"originalPath\":"
                + mt.safety.scanner.core.Json.quote(recovery.getAbsolutePath()) + ",\"quarantinedAt\":\"123\"}");
        Map<String, String> beforeSource = snapshot(source);
        Map<String, String> beforeStore = snapshot(store);
        ActionsTest.FakeHost host = new ActionsTest.FakeHost(files);
        ScanRunner runner = new ScanRunner(host);
        ScanRunner.Result result = runner.run();
        ScanReport report = reportFor(result, "victim.one");
        c.that("installed directory retains scan identity and risky findings", report != null
                && report.contentHash.length() > 0 && report.destructiveActionIdentityComplete()
                && report.verdict().flagged(), String.valueOf(report));
        if (report == null) { throw new AssertionError("fixture not discovered"); }

        for (int i = 0; i < 6; i++) {
            String outcome;
            if (i < 2) { outcome = runner.actOnOne(result, report, i == 1); }
            else if (i < 4) { outcome = runner.actOnScope(result, "flagged", i == 3); }
            else if (i == 4) { outcome = runner.uninstallSelection(result); }
            else { outcome = runner.actOnOne(null, null, true); }
            c.that("public runner action " + i + " delegates", delegated(outcome), outcome);
            survives(c, "public runner action " + i, source, store, recovery, beforeSource, beforeStore);
        }
        host.putFlag(ScanRunner.selectKey(report), true);
        c.that("all action target APIs are empty even with selected risky plugin",
                runner.actionTargets(result, "flagged").isEmpty()
                && runner.actionTargets(result, "malicious").isEmpty()
                && runner.selectedTargets(result).isEmpty() && runner.uninstallTargets(result).isEmpty(),
                "no scanner mutation targets");
        c.that("selection uninstall delegates", delegated(runner.uninstallSelection(result)), "selected entry");
        survives(c, "selected uninstall", source, store, recovery, beforeSource, beforeStore);
        String[] commands = {"quarantine victim.one", "quarantine malicious", "quarantine suspicious",
                "quarantine flagged", "quarantine all", "quarantine worth-a-look", "quarantine-all",
                "remove victim.one", "remove malicious", "remove suspicious", "remove flagged", "remove-all",
                "restore old.victim", "purge old.victim", "confirm 1234", "quarantine", "remove", "restore", "purge"};
        for (String command : commands) {
            host.putConfig(ScanRunner.KEY_PENDING_PLAN,
                    "{\"action\":\"remove\",\"scope\":\"flagged\",\"targets\":[],\"code\":\"1234\"}");
            host.type(command);
            ScanRunner.Result typed = runner.run();
            c.that("typed " + command + " delegates", delegated(typed.commandOutcome), typed.commandOutcome);
            c.that("typed " + command + " clears retired pending plan",
                    host.config(ScanRunner.KEY_PENDING_PLAN, "").length() == 0, "pending plan");
            c.that("typed " + command + " never records a successful mutation", typed.actioned.isEmpty(), "actioned");
            survives(c, "typed " + command, source, store, recovery, beforeSource, beforeStore);
        }
        host.type("");
        host.putFlag(ScanRunner.armKey(report), true);
        ScanRunner.Result armed = runner.run();
        c.that("legacy armed switches delegate and are cleared", delegated(armed.commandOutcome)
                && !host.configFlag(ScanRunner.armKey(report), false), armed.commandOutcome);
        c.that("no action or selection controls remain in report rows", !hasActionRow(armed), "report rows");
        survives(c, "armed switch", source, store, recovery, beforeSource, beforeStore);
        host.type("quarantined");
        String listing = runner.run().commandOutcome;
        c.that("historical quarantine listing includes original path and manual recovery guidance",
                listing.contains("old.victim") && listing.contains(recovery.getAbsolutePath())
                        && listing.contains(held.getAbsolutePath()) && listing.contains("MT Manager"), listing);
        c.that("historical quarantine count is retained", runner.quarantinedCount() == 1, "count");
        survives(c, "historical listing", source, store, recovery, beforeSource, beforeStore);
        String english = Strings.forLanguage("en").commandsHelp();
        String chinese = Strings.forLanguage("zh").commandsHelp();
        c.that("both command help translations delegate management", english.contains("MT Manager")
                && chinese.contains("MT") && !english.contains("confirm CODE")
                && !english.contains("quarantine ID - move"), english);
        archiveIdentity(c, fixtures);
    }

    private static void archiveIdentity(ActionsTest.Checker c, Fixtures fixtures) throws Exception {
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest("archive.one", "Archive", "x.A")));
        members.put("src/x/A.java", Fixtures.bytes("package x; public class A {}"));
        File archive = fixtures.installedArchive("archive", members, null);
        PluginPackage pkg = PluginPackage.open(archive);
        try {
            c.that("archive-only install keeps complete content identity", pkg.destructiveActionIdentityComplete()
                    && pkg.contentHash(ScanBudget.unlimited()).length() > 0, "archive identity");
        } finally { pkg.close(); }
        File sibling = fixtures.installedArchive("sibling", members,
                Collections.singletonMap("sidecar.java", Fixtures.bytes("Runtime.getRuntime().exec(\"ls\");")));
        ScanReport report = new PluginScanner(mt.safety.scanner.core.IocDatabase.empty()).scan(sibling, ScanBudget.unlimited());
        String json = ReportFormatter.json(Collections.singletonList(report));
        c.that("complete sibling scan retains findings, hash, coverage and legacy fields",
                report.contentHash.length() > 0 && !report.destructiveActionIdentityComplete()
                && report.coverage() == Coverage.COMPLETE && report.verdict().flagged()
                && json.contains("\"verdict\": \"" + report.verdict().name() + "\"")
                && json.contains("\"truncated\": false"), json);
        Map<String, byte[]> many = new LinkedHashMap<String, byte[]>();
        for (int i = 0; i < 401; i++) { many.put("sidecar-" + i, new byte[0]); }
        File partial = fixtures.installedArchive("partial-siblings", members, many);
        ScanReport incomplete = new PluginScanner(mt.safety.scanner.core.IocDatabase.empty())
                .scan(partial, ScanBudget.unlimited());
        c.that("truncated sibling enumeration still withholds full installed identity",
                incomplete.contentHash.length() == 0 && !incomplete.destructiveActionIdentityComplete()
                        && incomplete.coverage() != Coverage.COMPLETE, incomplete.dispositionLabel());
    }

    static boolean delegated(String message) {
        return message != null && message.contains("MT Manager") && message.contains("not performed");
    }

    static Map<String, String> snapshot(File root) throws IOException {
        Map<String, String> out = new TreeMap<String, String>();
        snapshot(root, root, out);
        return out;
    }

    private static void snapshot(File root, File file, Map<String, String> out) throws IOException {
        String path = root.toPath().relativize(file.toPath()).toString();
        if (Files.isSymbolicLink(file.toPath())) {
            out.put(path, "LINK:" + Files.readSymbolicLink(file.toPath()));
        } else if (file.isDirectory()) {
            out.put(path, "DIR");
            File[] children = file.listFiles();
            if (children == null) { throw new IOException("fixture listing failed"); }
            for (File child : children) { snapshot(root, child, out); }
        } else if (file.isFile()) {
            out.put(path, mt.safety.scanner.core.Bytes.sha256(Files.readAllBytes(file.toPath())));
        }
    }

    static void survives(ActionsTest.Checker c, String label, File source, File store, File recovery,
            Map<String, String> beforeSource, Map<String, String> beforeStore) throws IOException {
        c.that(label + " preserves all source paths and bytes", beforeSource.equals(snapshot(source)), "source snapshot");
        c.that(label + " preserves all held paths and metadata bytes", beforeStore.equals(snapshot(store)), "store snapshot");
        c.that(label + " creates no recovery path or parent", !recovery.getParentFile().exists(), "recovery destination");
    }

    private static ScanReport reportFor(ScanRunner.Result result, String id) {
        for (ScanReport report : result.reports) {
            if (id.equals(report.manifest.pluginId)) { return report; }
        }
        return null;
    }

    private static boolean hasActionRow(ScanRunner.Result result) {
        for (ScanRunner.Row row : result.rows) {
            if (row.toggle || row.report != null) { return true; }
        }
        return false;
    }
}
