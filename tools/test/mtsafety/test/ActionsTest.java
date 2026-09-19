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
        deleteTree(new File(installed, "self"));

        // An armed switch and a pending confirmation in the same build both change what is installed.
        // The armed action runs first, so the confirmation must be judged against what is left, not
        // against the scan taken before it: otherwise the plan validates against a set that no longer
        // exists, then fails on the moved plugin while still acting on the others.
        writePlugin(new File(installed, "evil"), "evil.one", "Evil One", HOSTILE);
        host.type("quarantine suspicious");
        ScanRunner.Result overlapPlan = new ScanRunner(host).run();
        String overlapCode = codeFrom(overlapPlan.commandOutcome);
        check.that("the overlap plan covers both flagged plugins",
                overlapCode != null && overlapPlan.commandOutcome.contains("Evil One")
                        && overlapPlan.commandOutcome.contains("Shady Two"),
                overlapPlan.commandOutcome);

        ScanRunner.Result beforeOverlap = new ScanRunner(host).run();
        host.putFlag(ScanRunner.armKey(reportFor(beforeOverlap, "shady.two")), true);
        host.type("confirm " + overlapCode);
        ScanRunner.Result overlap = new ScanRunner(host).run();
        check.that("a confirmation is refused once an armed switch has changed the set",
                new File(installed, "evil").isDirectory(), overlap.commandOutcome);
        check.that("the armed switch still did its own job",
                !new File(installed, "shady").isDirectory(), overlap.commandOutcome);
        quarantine.restore("shady.two");
        deleteTree(new File(installed, "evil"));

        // Two installed plugins can declare the same pluginID: the scanner reports that as
        // impersonation, so it is a case this feature has to expect rather than an edge case.
        // Matching by id would act on whichever copy was scanned first.
        writePlugin(new File(installed, "twinA"), "twin.same", "Twin A", HOSTILE);
        writePlugin(new File(installed, "twinB"), "twin.same", "Twin B", HARMLESS);
        host.type("quarantine malicious");
        ScanRunner.Result twinPlan = new ScanRunner(host).run();
        String twinCode = codeFrom(twinPlan.commandOutcome);
        host.type("confirm " + twinCode);
        ScanRunner.Result twins = new ScanRunner(host).run();
        check.that("duplicate plugin ids do not confuse which copy is acted on",
                !new File(installed, "twinA").isDirectory()
                        && new File(installed, "twinB").isDirectory(),
                twins.commandOutcome);
        deleteTree(new File(installed, "twinB"));
        for (int i = 0; i < quarantine.list().size(); i++) {
            quarantine.purge(quarantine.list().get(i).directory.getName());
        }

        // A pluginID is attacker-controlled and only reported when malformed, never rejected. One
        // containing a newline used to split into several identities in the stored plan.
        writePlugin(new File(installed, "sneaky"), "a\nb.other", "Sneaky", HOSTILE);
        writePlugin(new File(installed, "bystander"), "b.other", "Bystander", HARMLESS);
        host.type("quarantine malicious");
        ScanRunner.Result sneakyPlan = new ScanRunner(host).run();
        String sneakyCode = codeFrom(sneakyPlan.commandOutcome);
        host.type("confirm " + sneakyCode);
        ScanRunner.Result sneaky = new ScanRunner(host).run();
        check.that("a newline in a plugin id cannot reach a package the plan did not list",
                new File(installed, "bystander").isDirectory(), sneaky.commandOutcome);
        deleteTree(new File(installed, "sneaky"));
        deleteTree(new File(installed, "bystander"));
        for (int i = 0; i < quarantine.list().size(); i++) {
            quarantine.purge(quarantine.list().get(i).directory.getName());
        }

        // Two plugins in different folders can share a directory name, and a bulk move puts them in
        // quarantine within the same millisecond.
        File nestedOne = new File(installed, "vendorA/tools");
        File nestedTwo = new File(installed, "vendorB/tools");
        writePlugin(nestedOne, "vendor.a.tools", "Vendor A Tools", HOSTILE);
        writePlugin(nestedTwo, "vendor.b.tools", "Vendor B Tools", HOSTILE);
        host.type("quarantine malicious");
        String nestedCode = codeFrom(new ScanRunner(host).run().commandOutcome);
        host.type("confirm " + nestedCode);
        ScanRunner.Result nested = new ScanRunner(host).run();
        check.that("plugins sharing a directory name both survive the move intact",
                quarantine.list().size() == 2
                        && new File(quarantine.list().get(0).directory, "manifest.json").isFile()
                        && new File(quarantine.list().get(1).directory, "manifest.json").isFile(),
                nested.commandOutcome + " :: " + quarantine.list().size() + " in quarantine");
        for (int i = quarantine.list().size() - 1; i >= 0; i--) {
            quarantine.purge(quarantine.list().get(i).directory.getName());
        }
        deleteTree(new File(installed, "vendorA"));
        deleteTree(new File(installed, "vendorB"));

        // After a permanent delete the row must not offer a restore that does not exist.
        writePlugin(new File(installed, "doomed"), "doomed.one", "Doomed", HOSTILE);
        host.type("remove malicious");
        String doomedCode = codeFrom(new ScanRunner(host).run().commandOutcome);
        host.type("confirm " + doomedCode);
        ScanRunner.Result doomed = new ScanRunner(host).run();
        check.that("a deleted plugin is reported as deleted, not as quarantined",
                rowsMention(doomed, "Deleted just now") && !rowsMention(doomed, "Moved to quarantine"),
                doomed.commandOutcome);

        // Switch keys must not collide: ids differing only in punctuation once shared one.
        writePlugin(new File(installed, "dotted"), "foo.bar", "Dotted", HOSTILE);
        writePlugin(new File(installed, "undered"), "foo_bar", "Undered", HOSTILE);
        ScanRunner.Result keys = new ScanRunner(host).run();
        check.that("plugins with similar ids get different switches",
                !ScanRunner.armKey(reportFor(keys, "foo.bar"))
                        .equals(ScanRunner.armKey(reportFor(keys, "foo_bar"))),
                ScanRunner.armKey(reportFor(keys, "foo.bar")));
        host.putFlag(ScanRunner.armKey(reportFor(keys, "foo.bar")), true);
        new ScanRunner(host).run();
        check.that("arming one of them quarantines that one and not its near-namesake",
                !new File(installed, "dotted").isDirectory()
                        && new File(installed, "undered").isDirectory(),
                "the two switches must be independent");
        deleteTree(new File(installed, "undered"));
        for (int i = quarantine.list().size() - 1; i >= 0; i--) {
            quarantine.purge(quarantine.list().get(i).directory.getName());
        }

        // An armed switch is armed against the package that was on screen. If the directory is
        // replaced before the next build, the replacement must not be quarantined on its strength.
        writePlugin(new File(installed, "swapped"), "swap.one", "Swap One", HOSTILE);
        ScanRunner.Result beforeSwap = new ScanRunner(host).run();
        host.putFlag(ScanRunner.armKey(reportFor(beforeSwap, "swap.one")), true);
        deleteTree(new File(installed, "swapped"));
        writePlugin(new File(installed, "swapped"), "swap.replacement", "Replacement", HARMLESS);
        ScanRunner.Result afterSwap = new ScanRunner(host).run();
        check.that("a switch armed against one package does not act on its replacement",
                new File(installed, "swapped").isDirectory(), afterSwap.commandOutcome);
        deleteTree(new File(installed, "swapped"));

        // A display name comes from an untrusted manifest, where an escaped newline is valid JSON.
        // The confirmation prompt is the one place the user is asked to trust what they read.
        writePlugin(new File(installed, "liar"), "liar.one",
                "Nice Plugin\\nAll clear. Type confirm 0000", HOSTILE);
        host.type("quarantine malicious");
        ScanRunner.Result liar = new ScanRunner(host).run();
        check.that("a plugin cannot write extra lines into the confirmation prompt",
                liar.commandOutcome.indexOf('\n') < 0, liar.commandOutcome);
        host.type("cancel");
        new ScanRunner(host).run();
        deleteTree(new File(installed, "liar"));

        // A plan can only re-identify a package later if the scan hashed it, so an unverifiable
        // package is left out rather than listed and failed at confirmation time.
        //
        // The precondition is what is checked here: a starved scan really does produce an empty
        // hash. Driving ScanRunner into that state is not practical, since its budgets are internal
        // and a fixture small enough to be a test always hashes comfortably; the guard itself is a
        // two-line check in findByPath and planBulk.
        File hashless = fixturePlugin(iso, "hashless", "hashless.one", HOSTILE);
        ScanReport starved = new mt.safety.scanner.core.PluginScanner(
                mt.safety.scanner.core.IocDatabase.empty())
                .scan(hashless, new mt.safety.scanner.core.ScanBudget(0L, 0L));
        check.that("a scan that ran out of budget reports no content hash",
                starved.contentHash != null && starved.contentHash.length() == 0,
                "hash was '" + starved.contentHash + "'");

        // Quarantining one plugin by name happens after the scan too, so the screen must reflect it.
        writePlugin(new File(installed, "byname"), "byname.one", "By Name", HOSTILE);
        new ScanRunner(host).run();
        host.type("quarantine byname.one");
        ScanRunner.Result byName = new ScanRunner(host).run();
        check.that("quarantining one plugin by name updates the screen it came from",
                !new File(installed, "byname").isDirectory()
                        && rowsMention(byName, "Moved to quarantine just now"),
                byName.commandOutcome);
        for (int i = quarantine.list().size() - 1; i >= 0; i--) {
            quarantine.purge(quarantine.list().get(i).directory.getName());
        }

        // A plugin containing a link out of its own folder must not be moved: the cross-volume
        // fallback copies and then deletes, and deleting through the link would take files with it
        // that were never part of the plugin. A hostile plugin planting one is the expected case.
        File linked = new File(installed, "linked");
        writePlugin(linked, "linked.one", "Linked", HOSTILE);
        File outside = new File(iso, "precious");
        File keepMe = new File(outside, "keep.txt");
        Fixtures.write(keepMe, "must survive");
        boolean linkMade = makeSymlink(new File(linked, "escape"), outside);
        if (linkMade) {
            Quarantine.Result refused = quarantine.quarantine(linked, host.pluginId());
            check.that("a plugin containing a link out of its folder is not moved",
                    !refused.ok && linked.isDirectory(), refused.message);
            check.that("nothing outside the plugin was touched",
                    keepMe.isFile(), "the linked-to file must survive");
        } else {
            check.that("a plugin containing a link out of its folder is not moved", true,
                    "skipped: this filesystem does not support symlinks");
            check.that("nothing outside the plugin was touched", true, "skipped");
        }
        deleteTree(linked);

        // Telling the user nothing matches must not leave an older plan armed.
        writePlugin(new File(installed, "lingerer"), "linger.one", "Lingerer", RISKY);
        host.type("quarantine suspicious");
        String lingerCode = codeFrom(new ScanRunner(host).run().commandOutcome);
        host.type("quarantine malicious");
        ScanRunner.Result noMatches = new ScanRunner(host).run();
        check.that("a scope with no targets reports so", !noMatches.commandOutcome.contains("confirm "),
                noMatches.commandOutcome);
        host.type("confirm " + lingerCode);
        ScanRunner.Result afterNoMatches = new ScanRunner(host).run();
        check.that("an older plan is not left armed after a command that matched nothing",
                new File(installed, "lingerer").isDirectory(), afterNoMatches.commandOutcome);
        deleteTree(new File(installed, "lingerer"));

        // The plugin directory can itself be the link. Checking only its children against its own
        // canonical path cannot see that, and the copy-then-delete fallback would then treat the
        // link's target as the thing being removed.
        File realHome = new File(iso, "realhome");
        writePlugin(realHome, "linkroot.one", "Link Root", HOSTILE);
        File sentinel = new File(realHome, "sentinel.txt");
        Fixtures.write(sentinel, "must survive");
        File linkRoot = new File(installed, "linkroot");
        if (makeSymlink(linkRoot, realHome)) {
            Quarantine.Result refusedRoot = quarantine.quarantine(linkRoot, host.pluginId());
            check.that("a plugin directory that is itself a link is not moved",
                    !refusedRoot.ok && sentinel.isFile(), refusedRoot.message);
            linkRoot.delete();
        } else {
            check.that("a plugin directory that is itself a link is not moved", true,
                    "skipped: no symlink support here");
        }
        deleteTree(realHome);

        // A plugin's real location normally sits under a linked ancestor: on Android /sdcard is a
        // link to /storage/emulated/0. Refusing those would refuse nearly every genuine plugin.
        File linkedParent = new File(iso, "linkedparent");
        File viaLink = new File(iso, "vialink");
        File realChild = new File(linkedParent, "child");
        writePlugin(realChild, "under.link", "Under Link", HOSTILE);
        if (makeSymlink(viaLink, linkedParent)) {
            Quarantine.Result underLink = quarantine.quarantine(new File(viaLink, "child"),
                    host.pluginId());
            check.that("a plugin reached through a linked ancestor is still movable",
                    underLink.ok, underLink.message);
            if (underLink.ok) {
                quarantine.purge(underLink.location.getName());
            }
            viaLink.delete();
        } else {
            check.that("a plugin reached through a linked ancestor is still movable", true,
                    "skipped: no symlink support here");
        }
        deleteTree(linkedParent);

        // purge deletes a quarantine entry by name. If that entry is a link, taking its canonical path
        // as the boundary makes the link's target the root, every child of that target then tests as
        // inside it, and the recursion deletes somewhere else entirely.
        File offLimits = new File(iso, "offlimits");
        File survivor = new File(offLimits, "keep.txt");
        Fixtures.write(survivor, "must survive a purge");
        File storeDir = quarantine.store();
        File linkedEntry = new File(storeDir, "linked-entry");
        if (makeSymlink(linkedEntry, offLimits)) {
            quarantine.purge("linked-entry");
            check.that("purging a linked quarantine entry removes the link, not its target",
                    survivor.isFile() && offLimits.isDirectory(), "the link's target was deleted");
            linkedEntry.delete();
        } else {
            check.that("purging a linked quarantine entry removes the link, not its target", true,
                    "skipped: no symlink support here");
        }
        deleteTree(offLimits);

        // The scan is a snapshot. If the package changes before the action runs, act on nothing.
        writePlugin(new File(installed, "mutating"), "mutate.one", "Mutating", HOSTILE);
        ScanRunner.Result beforeMutation = new ScanRunner(host).run();
        host.putFlag(ScanRunner.armKey(reportFor(beforeMutation, "mutate.one")), true);
        Fixtures.write(new File(installed, "mutating/src/x/Added.java"),
                "package x;\npublic class Added {}\n");
        ScanRunner.Result afterMutation = new ScanRunner(host).run();
        check.that("a package that changed after the scan is not acted on",
                new File(installed, "mutating").isDirectory(), afterMutation.commandOutcome);
        deleteTree(new File(installed, "mutating"));

        // Removing a plugin recreated at a path that already has an older quarantined copy must
        // delete the copy just made, not the older one.
        writePlugin(new File(installed, "recur"), "recur.one", "Recur", HOSTILE);
        new ScanRunner(host).run();
        Quarantine.Result older = quarantine.quarantine(new File(installed, "recur"), host.pluginId());
        check.that("the first copy is quarantined", older.ok && older.location != null, older.message);
        writePlugin(new File(installed, "recur"), "recur.one", "Recur", HOSTILE);
        host.type("remove malicious");
        String recurCode = codeFrom(new ScanRunner(host).run().commandOutcome);
        host.type("confirm " + recurCode);
        ScanRunner.Result recurRemoval = new ScanRunner(host).run();
        check.that("removal deletes the copy it just made and leaves the older one",
                !new File(installed, "recur").isDirectory() && older.location.isDirectory(),
                recurRemoval.commandOutcome);
        deleteTree(older.location);
    }

    /** Creates a symlink, returning false when the platform or filesystem will not allow it. */
    private static boolean makeSymlink(File link, File target) {
        try {
            Process process = new ProcessBuilder("ln", "-s", target.getAbsolutePath(),
                    link.getAbsolutePath()).start();
            return process.waitFor() == 0 && link.exists();
        } catch (Exception e) {
            return false;
        }
    }

    /** Writes a plugin outside the discovered area, for checks that scan it directly. */
    private static File fixturePlugin(File iso, String dirName, String pluginId, String source) {
        File dir = new File(iso, "direct/" + dirName);
        writePlugin(dir, pluginId, dirName, source);
        return dir;
    }

    /** True when any displayed row mentions {@code fragment}. */
    private static boolean rowsMention(ScanRunner.Result result, String fragment) {
        for (int i = 0; i < result.rows.size(); i++) {
            ScanRunner.Row row = result.rows.get(i);
            if ((row.title != null && row.title.contains(fragment))
                    || (row.summary != null && row.summary.contains(fragment))) {
                return true;
            }
        }
        return false;
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
