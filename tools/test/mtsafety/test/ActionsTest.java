package mtsafety.test;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import mt.safety.scanner.Host;
import mt.safety.scanner.Quarantine;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Verdict;

/**
 * Tests for quarantining plugins from the settings screen.
 *
 * <p>These drive the real {@link ScanRunner} through a stand-in {@link Host}, so a test exercises the
 * same path a tap does: scan, act, report. That is possible only because nothing in the runner
 * references an MT Manager type.
 *
 * <p>Bulk removal deletes a user's plugins, so most of what is checked here is the refusals: a plan
 * does nothing until it is confirmed, a wrong or stale code does nothing, and the scanner is never a
 * target.
 */
public final class ActionsTest {

    /** A Host backed by maps and a temporary directory. */
    static final class FakeHost implements Host {
        private final File filesDir;
        private final Map<String, String> values = new HashMap<String, String>();
        private final Map<String, Boolean> flags = new HashMap<String, Boolean>();

        FakeHost(File filesDir) {
            this.filesDir = filesDir;
        }

        @Override
        public File filesDir() {
            return filesDir;
        }

        @Override
        public String config(String key, String fallback) {
            String v = values.get(key);
            return v == null ? fallback : v;
        }

        @Override
        public boolean configFlag(String key, boolean fallback) {
            Boolean v = flags.get(key);
            return v == null ? fallback : v.booleanValue();
        }

        @Override
        public void putConfig(String key, String value) {
            if (value == null) {
                values.remove(key);
            } else {
                values.put(key, value);
            }
        }

        @Override
        public void putFlag(String key, boolean value) {
            flags.put(key, Boolean.valueOf(value));
        }

        @Override
        public String language() {
            return "en";
        }

        @Override
        public void log(String message) {
        }

        @Override
        public void log(String message, Throwable error) {
        }

        @Override
        public void toast(String message) {
        }

        @Override
        public String pluginId() {
            return "mt.safety.scanner";
        }

        void type(String command) {
            values.put(ScanRunner.KEY_COMMAND, command);
        }
    }

    private static final String HOSTILE = ""
            + "package x;\n"
            + "public class A {\n"
            + "  String p = \"/data/data/com.whatsapp/databases\";\n"
            + "  void f() throws Exception {"
            + " new java.net.URL(\"https://api.telegram.org/bot1/x\").openConnection(); }\n"
            + "}\n";
    private static final String RISKY = ""
            + "package x;\n"
            + "public class A { void f() throws Exception { Runtime.getRuntime().exec(\"ls\"); } }\n";
    private static final String HARMLESS = "package x;\npublic class A { public int n() { return 1; } }\n";

    private ActionsTest() {
    }

    /** Runs every check, reporting through the shared harness. */
    static void run(Checker check) throws Exception {
        File iso = new File(System.getProperty("java.io.tmpdir"),
                "mtsafety-actions-" + System.currentTimeMillis());
        // Nested so that the roots derived from it, its four ancestors, stay inside this test's area.
        File filesDir = new File(iso, "a/b/c/d/files");
        File installed = new File(iso, "a/plugins");
        if (!filesDir.mkdirs() || !installed.mkdirs()) {
            throw new IllegalStateException("could not create " + iso);
        }

        writePlugin(new File(installed, "evil"), "evil.one", "Evil One", HOSTILE);
        writePlugin(new File(installed, "shady"), "shady.two", "Shady Two", RISKY);
        writePlugin(new File(installed, "fine"), "fine.three", "Fine Three", HARMLESS);

        FakeHost host = new FakeHost(filesDir);
        Quarantine quarantine = new Quarantine(new File(filesDir, "quarantine"));

        // The scan has to see all three before anything else means much.
        ScanRunner.Result first = new ScanRunner(host).run();
        check.that("the scan finds the installed plugins", first.reports.size() == 3,
                "found " + first.reports.size());
        check.that("verdicts split as expected",
                verdictOf(first, "evil.one") == Verdict.LIKELY_MALICIOUS
                        && verdictOf(first, "shady.two") == Verdict.SUSPICIOUS
                        && verdictOf(first, "fine.three") == Verdict.CLEAN,
                verdictOf(first, "evil.one") + "/" + verdictOf(first, "shady.two") + "/"
                        + verdictOf(first, "fine.three"));

        // A switch arms the action; it happens on the next build, not while the screen is open.
        String armKey = ScanRunner.armKey(reportFor(first, "shady.two"));
        host.putFlag(armKey, true);
        check.that("arming alone moves nothing",
                new File(installed, "shady").isDirectory(), "still installed before the next build");
        ScanRunner.Result second = new ScanRunner(host).run();
        check.that("the armed switch quarantines that plugin on the next build",
                !new File(installed, "shady").isDirectory() && quarantine.list().size() == 1,
                second.commandOutcome);
        check.that("the switch is cleared afterwards, so it cannot fire twice",
                !host.configFlag(armKey, false), "switch should be off again");
        check.that("a quarantined plugin is not rediscovered as installed",
                new ScanRunner(host).run().reports.size() == 2,
                "quarantine lives inside the plugin's own folder, which sits under a scan root");

        quarantine.restore("shady.two");

        // A bulk action plans first and touches nothing.
        host.type("quarantine malicious");
        ScanRunner.Result planned = new ScanRunner(host).run();
        String code = codeFrom(planned.commandOutcome);
        check.that("a bulk action lists what it would do and waits",
                code != null && new File(installed, "evil").isDirectory()
                        && planned.commandOutcome.contains("Evil One"),
                planned.commandOutcome);
        check.that("the plan covers only the malicious one",
                !planned.commandOutcome.contains("Fine Three")
                        && !planned.commandOutcome.contains("Shady Two"),
                planned.commandOutcome);

        host.type("confirm 0000");
        ScanRunner.Result wrong = new ScanRunner(host).run();
        check.that("a wrong confirmation code does nothing",
                new File(installed, "evil").isDirectory(), wrong.commandOutcome);

        host.type("confirm " + code);
        ScanRunner.Result confirmed = new ScanRunner(host).run();
        check.that("the confirmed action quarantines exactly the malicious plugin",
                !new File(installed, "evil").isDirectory()
                        && new File(installed, "fine").isDirectory()
                        && new File(installed, "shady").isDirectory(),
                confirmed.commandOutcome);
        quarantine.restore("evil.one");

        // A code stops being valid once the set it covered changes.
        host.type("quarantine suspicious");
        String staleCode = codeFrom(new ScanRunner(host).run().commandOutcome);
        writePlugin(new File(installed, "extra"), "extra.four", "Extra Four", HOSTILE);
        host.type("confirm " + staleCode);
        ScanRunner.Result stale = new ScanRunner(host).run();
        check.that("a plan that no longer matches the installed plugins is refused",
                new File(installed, "evil").isDirectory() && new File(installed, "extra").isDirectory(),
                stale.commandOutcome);
        deleteTree(new File(installed, "extra"));

        // Cancelling clears the plan rather than leaving it primed.
        host.type("quarantine malicious");
        new ScanRunner(host).run();
        host.type("cancel");
        new ScanRunner(host).run();
        host.type("confirm " + code);
        ScanRunner.Result afterCancel = new ScanRunner(host).run();
        check.that("a cancelled plan cannot be confirmed later",
                new File(installed, "evil").isDirectory(), afterCancel.commandOutcome);

        // Permanent removal really is permanent: nothing left in quarantine either.
        host.type("remove malicious");
        String removeCode = codeFrom(new ScanRunner(host).run().commandOutcome);
        host.type("confirm " + removeCode);
        ScanRunner.Result removed = new ScanRunner(host).run();
        check.that("remove deletes the plugin and keeps no quarantined copy",
                !new File(installed, "evil").isDirectory() && quarantine.list().isEmpty(),
                removed.commandOutcome);
        check.that("removal leaves the other plugins alone",
                new File(installed, "fine").isDirectory() && new File(installed, "shady").isDirectory(),
                removed.commandOutcome);

        // The scanner must never be a target of its own bulk actions.
        writePlugin(new File(installed, "self"), "mt.safety.scanner", "Scanner", HOSTILE);
        host.type("quarantine suspicious");
        ScanRunner.Result selfPlan = new ScanRunner(host).run();
        check.that("the scanner is never included in a bulk action",
                !selfPlan.commandOutcome.contains("Scanner")
                        && new File(installed, "self").isDirectory(),
                selfPlan.commandOutcome);

        host.type("remove");
        ScanRunner.Result bareRemove = new ScanRunner(host).run();
        check.that("remove without a scope explains itself instead of guessing",
                bareRemove.commandOutcome.contains("remove malicious"), bareRemove.commandOutcome);
    }

    /** What the harness needs from its caller. */
    interface Checker {
        void that(String description, boolean condition, String context);
    }

    private static Verdict verdictOf(ScanRunner.Result result, String pluginId) {
        ScanReport report = reportFor(result, pluginId);
        return report == null ? null : report.verdict();
    }

    private static ScanReport reportFor(ScanRunner.Result result, String pluginId) {
        List<ScanReport> reports = result.reports;
        for (int i = 0; i < reports.size(); i++) {
            if (pluginId.equals(reports.get(i).manifest.pluginId)) {
                return reports.get(i);
            }
        }
        return null;
    }

    /** Pulls the confirmation code out of the message the runner produced. */
    private static String codeFrom(String message) {
        if (message == null) {
            return null;
        }
        int at = message.indexOf("confirm ");
        if (at < 0) {
            return null;
        }
        int start = at + "confirm ".length();
        int end = start;
        while (end < message.length() && Character.isLetterOrDigit(message.charAt(end))) {
            end++;
        }
        return end > start ? message.substring(start, end) : null;
    }

    private static void writePlugin(File dir, String pluginId, String name, String source) {
        File src = new File(dir, "src/x");
        if (!src.isDirectory() && !src.mkdirs()) {
            throw new IllegalStateException("could not create " + src);
        }
        Fixtures.write(new File(dir, "manifest.json"), Fixtures.manifest(pluginId, name, "x.A"));
        Fixtures.write(new File(src, "A.java"), source);
    }

    private static void deleteTree(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (int i = 0; i < children.length; i++) {
                deleteTree(children[i]);
            }
        }
        file.delete();
    }
}
