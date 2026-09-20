package mt.safety.scanner;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import mt.safety.scanner.core.Bytes;
import mt.safety.scanner.core.Discovery;
import mt.safety.scanner.core.Json;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginManifest;
import mt.safety.scanner.core.PluginPackage;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Severity;
import mt.safety.scanner.core.Signal;
import mt.safety.scanner.core.Verdict;

/**
 * Drives a scan and turns the result into rows a settings screen can show.
 *
 * <p>MT Manager builds a plugin's settings screen once, through a single {@code onBuild} call, with no
 * buttons and no way to refresh from code. That constraint shapes the whole interaction:
 *
 * <ul>
 *   <li>Opening the screen <i>is</i> the scan. Re-opening it rescans.
 *   <li>Actions are typed into one text field and run the next time the screen opens, with the outcome
 *       shown at the top. One field means a half-typed command cannot quarantine anything.
 * </ul>
 *
 * <p>Nothing here references an MT Manager class, so it can be tested on a desktop JVM.
 */
public final class ScanRunner {

    /** Config keys. */
    public static final String KEY_COMMAND = "command";
    public static final String KEY_DEEP = "deep_scan";
    public static final String KEY_EXTRA_ROOT = "extra_root";
    public static final String KEY_LAST_RESULT = "last_result";
    /** Prefix for the per-plugin "quarantine this one" switches. */
    public static final String KEY_ARM_PREFIX = "arm_";

    /**
     * Prefix for the per-plugin "selected" switch.
     *
     * <p>Selection is not action. A switch here only marks a plugin for the uninstall button to pick
     * up, so turning one on does nothing until the button is pressed and its dialog confirmed, and a
     * switch touched by accident can simply be turned off again. Kept apart from {@link
     * #KEY_ARM_PREFIX}, whose switches quarantine on the next screen build.
     */
    public static final String KEY_SELECT_PREFIX = "sel_";
    /** The bulk action awaiting confirmation. */
    public static final String KEY_PENDING_PLAN = "pending_plan";

    /** Total interactive time budget shared out across the plugins found. */
    private static final long INTERACTIVE_TOTAL_MS = 6000L;
    private static final long DEEP_TOTAL_MS = 30000L;
    private static final long BYTES_PER_PLUGIN = 16L * 1024 * 1024;

    /** One line of the settings screen. */
    public static final class Row {
        public final boolean header;
        /** True for a switch row; {@link #key} then holds the preference it is bound to. */
        public final boolean toggle;
        public final String key;
        public final String title;
        public final String summary;
        /**
         * The plugin this row acts on, for an actionable row, or null.
         *
         * <p>The v2 screen has no callback, so it arms an action with a switch bound to {@link #key}.
         * The v3 screen has real click callbacks, so it acts on this report directly. One row type
         * serves both: v2 reads the key, v3 reads the report.
         */
        public final ScanReport report;

        private Row(boolean header, boolean toggle, String key, String title, String summary,
                ScanReport report) {
            this.header = header;
            this.toggle = toggle;
            this.key = key;
            this.title = title;
            this.summary = summary;
            this.report = report;
        }

        public static Row header(String title) {
            return new Row(true, false, null, title, null, null);
        }

        public static Row text(String title, String summary) {
            return new Row(false, false, null, title, summary, null);
        }

        /**
         * A switch that arms an action on one plugin.
         *
         * <p>The settings screen has no buttons, so a switch is the only thing a user can tap to mean
         * "this one". It is read on the next build, which is also what keeps it safe: nothing happens
         * while the screen is open, and the action is listed before it runs.
         */
        public static Row toggle(String title, String summary, String key, ScanReport report) {
            return new Row(false, true, key, title, summary, report);
        }
    }

    /** The outcome of one screen build. */
    public static final class Result {
        /** Findings, worst plugin first. */
        public final List<Row> rows = new ArrayList<Row>();
        /** Configuration and limitations, shown after the action widgets. */
        public final List<Row> aboutRows = new ArrayList<Row>();
        public final List<ScanReport> reports = new ArrayList<ScanReport>();
        /** Plugins found but not reached before the scan's overall deadline. */
        public int unscanned;
        /**
         * What happened to each package acted on during this build, keyed by path.
         *
         * <p>Values are {@code quarantined} or {@code removed}. Kept apart because a row that says
         * "moved to quarantine" after a permanent delete promises a copy the user could restore, and
         * there is none.
         */
        public final java.util.Map<String, String> actioned = new java.util.HashMap<String, String>();
        public String commandOutcome = "";
    }

    private final Host host;
    private final Strings strings;

    public ScanRunner(Host host) {
        this.host = host;
        this.strings = Strings.forLanguage(host.language());
    }

    public Strings strings() {
        return strings;
    }

    /**
     * Scans, then acts, then builds the rows to display.
     *
     * <p>The order is part of the safety contract rather than an implementation detail. Acting comes
     * after scanning because a bulk action has to know what the scan found, and every action is judged
     * against what is installed once the earlier actions in the same build have run.
     */
    public Result run() {
        Result result = new Result();
        File configFile = new File(host.filesDir(), "indicators.json");
        IocDatabase database = IocDatabase.load(configFile);

        scanInto(result, database);

        // Acting comes after scanning, because a bulk action has to know what the scan found: which
        // plugins are malicious, and which of those are installed rather than a download sitting in a
        // folder. Settings that shape the scan itself take effect on the next open, which is how this
        // screen has always worked.
        StringBuilder outcome = new StringBuilder();
        String armed = runArmedSwitches(result);
        if (armed.length() > 0) {
            outcome.append(armed);
        }
        String pending = host.config(KEY_COMMAND, "");
        if (pending != null && pending.trim().length() > 0) {
            // Cleared first: a command that somehow crashes must not run again on every open.
            host.putConfig(KEY_COMMAND, "");
            String commandResult = runCommand(pending.trim(), database, configFile, result);
            host.log("command: " + pending.trim() + " -> " + commandResult);
            if (outcome.length() > 0) {
                outcome.append("   ");
            }
            outcome.append(commandResult);
        }
        if (outcome.length() > 0) {
            result.commandOutcome = outcome.toString();
            host.putConfig(KEY_LAST_RESULT, result.commandOutcome);
        } else {
            result.commandOutcome = host.config(KEY_LAST_RESULT, "");
        }

        buildRows(result, database,
                MtEnvironment.candidateRoots(host.filesDir(), host.hostPackage(), host.config(KEY_EXTRA_ROOT, "")),
                result.reports.size() + result.unscanned);
        return result;
    }

    /** Runs the scan itself, filling {@code result.reports}. */
    private void scanInto(Result result, IocDatabase database) {
        boolean deep = host.configFlag(KEY_DEEP, false);
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.hostPackage(), host.config(KEY_EXTRA_ROOT, ""));
        List<Discovery.Candidate> candidates = MtEnvironment.findPlugins(roots, host.pluginId(), host.filesDir());

        PluginScanner scanner = new PluginScanner(database);
        long totalMs = deep ? DEEP_TOTAL_MS : INTERACTIVE_TOTAL_MS;
        long slice = candidates.isEmpty() ? totalMs : Math.max(300L, totalMs / candidates.size());
        // The per-package slice has a floor so a small scan is not starved, which means the slices can
        // add up past the total. The overall deadline is what actually keeps the settings screen
        // responsive: with many plugins installed, the rest are listed as unscanned rather than
        // freezing MT Manager for a minute and a half.
        long deadline = System.currentTimeMillis() + totalMs;
        int scannedCount = 0;
        for (int i = 0; i < candidates.size(); i++) {
            if (System.currentTimeMillis() >= deadline && scannedCount > 0) {
                result.unscanned = candidates.size() - scannedCount;
                break;
            }
            ScanBudget budget = new ScanBudget(slice, BYTES_PER_PLUGIN);
            result.reports.add(scanner.scan(candidates.get(i).path, budget));
            scannedCount++;
        }
        scanner.finishSet(result.reports);
    }

    // ------------------------------------------------------------------ actions

    /** The preference key for one plugin's "quarantine this one" switch. */
    public static String armKey(ScanReport report) {
        // A digest of the location and the contents, for two reasons. Collision-free, because
        // sanitizing an id mapped "foo.bar" and "foo_bar" onto one key and toggling either would have
        // moved the other. And bound to the package that was on screen: if the directory is replaced
        // between arming the switch and reopening, the key changes, the old flag matches nothing, and
        // the replacement is not quarantined on the strength of a switch armed against something else.
        return KEY_ARM_PREFIX + identityDigest(report);
    }

    /** A short digest of where a package is and what is in it, shared by both switch kinds. */
    private static String identityDigest(ScanReport report) {
        String identity = report.path + "|" + report.contentHash;
        try {
            return Bytes.sha256(identity.getBytes("UTF-8")).substring(0, 16);
        } catch (java.io.UnsupportedEncodingException e) {
            return Integer.toHexString(identity.hashCode());
        }
    }

    /** The preference key for one plugin's "select for removal" switch. */
    public static String selectKey(ScanReport report) {
        return KEY_SELECT_PREFIX + identityDigest(report);
    }

    /**
     * Quarantines the plugins whose switch was left on, then clears those switches.
     *
     * <p>This is the one-tap path: turn on the switch under a plugin, reopen the screen, it is gone.
     * Nothing happens while the screen is open, so a switch touched by accident can be turned off
     * again before it does anything.
     */
    private String runArmedSwitches(Result result) {
        Quarantine quarantine = new Quarantine(new File(host.filesDir(), "quarantine"));
        StringBuilder done = new StringBuilder();
        for (int i = 0; i < result.reports.size(); i++) {
            ScanReport report = result.reports.get(i);
            if (report.contentHash == null || report.contentHash.length() == 0) {
                // The key is not package-bound without a hash, so an armed flag here could belong to
                // whatever used to be at this path. Never act on it.
                continue;
            }
            String key = armKey(report);
            if (!host.configFlag(key, false)) {
                continue;
            }
            host.putFlag(key, false);
            if (!report.installed) {
                // A file sitting in a downloads folder is not something this plugin should delete.
                append(done, strings.notInstalled(report.manifest.displayName()));
                continue;
            }
            if (!stillMatches(report)) {
                append(done, strings.changedSinceScan(flatten(report.manifest.displayName())));
                continue;
            }
            Quarantine.Result moved = quarantine.quarantine(new File(report.path), host.pluginId());
            if (moved.ok) {
                result.actioned.put(report.path, "quarantined");
            }
            append(done, moved.message);
        }
        return done.toString();
    }

    /**
     * Works out which plugins a bulk action would touch, and asks for confirmation first.
     *
     * <p>The confirmation code is derived from the action and the exact set of plugins it covers, so a
     * code confirms the list the user was shown and nothing else. If the set changes before it is
     * typed, the code no longer matches and the action is refused rather than applied to a different
     * set of plugins.
     */
    private String planBulk(String action, String scope, Result result) {
        List<ScanReport> all = bulkTargets(scope, result);
        List<ScanReport> targets = verifiable(all);
        int unverifiable = all.size() - targets.size();
        if (targets.isEmpty()) {
            // Clearing matters here: leaving an older plan armed after telling the user nothing
            // matches means a later confirm still carries out an action they were just told was not
            // pending.
            host.putConfig(KEY_PENDING_PLAN, "");
            return unverifiable > 0 ? strings.noneVerifiable(unverifiable) : strings.nothingMatches(scope);
        }
        StringBuilder names = new StringBuilder();
        for (int i = 0; i < targets.size(); i++) {
            if (i > 0) {
                names.append(", ");
            }
            names.append(flatten(targets.get(i).manifest.displayName()));
        }
        String ids = targetIds(scope, result);
        String code = confirmationCode(action, scope, ids);
        StringBuilder plan = new StringBuilder();
        plan.append("{\"action\": ").append(Json.quote(action));
        plan.append(", \"scope\": ").append(Json.quote(scope));
        plan.append(", \"targets\": ").append(ids);
        plan.append(", \"code\": ").append(Json.quote(code)).append("}");
        host.putConfig(KEY_PENDING_PLAN, plan.toString());

        String message = strings.planned(action, targets.size(), names.toString(), code);
        return unverifiable > 0 ? message + "   " + strings.someUnverifiable(unverifiable) : message;
    }

    /** Executes a plan once its code is typed back. */
    private String confirmBulk(String code, Result result) {
        String stored = host.config(KEY_PENDING_PLAN, "");
        if (stored == null || stored.trim().length() == 0) {
            return strings.nothingToConfirm();
        }
        String action;
        String scope;
        String ids;
        String expected;
        List<java.util.Map<String, Object>> targets;
        try {
            java.util.Map<String, Object> plan = Json.parseObject(stored);
            action = Json.str(plan, "action", "");
            scope = Json.str(plan, "scope", "");
            expected = Json.str(plan, "code", "");
            targets = Json.objectList(plan, "targets");
            ids = rebuildTargetList(targets);
        } catch (Json.JsonException e) {
            host.putConfig(KEY_PENDING_PLAN, "");
            return strings.nothingToConfirm();
        }
        if (expected.length() == 0 || !expected.equalsIgnoreCase(code.trim())) {
            return strings.wrongCode(expected);
        }
        // Compare the stored list against the plugins that match right now. Recomputing the code from
        // the stored ids would only prove the plan agrees with itself; what matters is that the set
        // has not changed since the user read it, so a confirmation applies to the list they saw.
        if (!ids.equals(targetIds(scope, result))) {
            host.putConfig(KEY_PENDING_PLAN, "");
            return strings.planStale();
        }
        host.putConfig(KEY_PENDING_PLAN, "");

        Quarantine quarantine = new Quarantine(new File(host.filesDir(), "quarantine"));
        boolean permanent = action.equals("remove");
        int removed = 0;
        int quarantined = 0;
        StringBuilder problems = new StringBuilder();
        for (int i = 0; i < targets.size(); i++) {
            String path = Json.str(targets.get(i), "path", "");
            String sha = Json.str(targets.get(i), "sha", "");
            if (path.length() == 0) {
                continue;
            }
            // Matched on the package's location, not its declared id. Two installed plugins can carry
            // the same pluginID, which the scanner itself reports as impersonation, and matching by id
            // could act on the copy the plan never listed.
            ScanReport match = findByPath(path, sha, result);
            if (match == null || !match.installed) {
                append(problems, strings.noSuchPlugin(path));
                continue;
            }
            int[] counts = new int[2];
            String problem = moveTarget(quarantine, match, permanent, result, counts);
            removed += counts[0];
            quarantined += counts[1];
            if (problem.length() > 0) {
                append(problems, problem);
            }
        }
        String summary = permanent ? strings.bulkDone("remove", removed)
                : strings.bulkDone("quarantine", quarantined);
        if (permanent && quarantined > 0) {
            summary = summary + "   " + strings.someOnlyQuarantined(quarantined);
        }
        return problems.length() == 0 ? summary : summary + "   " + problems;
    }

    /**
     * Moves one scanned plugin aside, re-verifying it still matches the scan first.
     *
     * <p>The single place a plugin is actually moved, shared by the typed {@code confirm} path and
     * the v3 button path so the two cannot drift. {@code counts[0]} is incremented for a removal that
     * completed, {@code counts[1]} for a quarantine (including a removal whose purge failed and so
     * left a restorable copy). Returns a problem to report, or an empty string on success.
     */
    private String moveTarget(Quarantine quarantine, ScanReport match, boolean permanent, Result result,
            int[] counts) {
        if (!stillMatches(match)) {
            return strings.changedSinceScan(flatten(match.manifest.displayName()));
        }
        Quarantine.Result moved = quarantine.quarantine(new File(match.path), host.pluginId());
        if (!moved.ok) {
            return moved.message;
        }
        // Counted by what actually happened. A removal whose purge failed left a restorable copy
        // behind, so it is a quarantine, and reporting it as deleted would tell the user there is
        // nothing left to recover when there is.
        if (permanent) {
            Quarantine.Result purged = purgeExact(quarantine, moved.location, match.path);
            if (purged.ok) {
                result.actioned.put(match.path, "removed");
                counts[0]++;
                return "";
            }
            result.actioned.put(match.path, "quarantined");
            counts[1]++;
            return purged.message;
        }
        result.actioned.put(match.path, "quarantined");
        counts[1]++;
        return "";
    }

    /**
     * The installed plugins a scope covers right now, for a UI that offers a button per action.
     *
     * <p>v3 MT Manager gives a plugin real click callbacks and dialogs, so a bulk action can be
     * confirmed in a dialog rather than by typing a code back. This exposes the same set the typed
     * plan would cover, so both paths act on exactly the plugins the user was shown.
     */
    public List<ScanReport> actionTargets(Result result, String scope) {
        return verifiable(bulkTargets(scope, result));
    }

    /**
     * Quarantines, or removes, one scanned plugin. For the v3 button path, where the dialog the user
     * confirmed is the confirmation the typed path gets from its code.
     */
    public String actOnOne(Result result, ScanReport report, boolean remove) {
        if (report == null || !report.installed) {
            return strings.noSuchPlugin(report == null ? "" : report.path);
        }
        Quarantine quarantine = new Quarantine(new File(host.filesDir(), "quarantine"));
        int[] counts = new int[2];
        String problem = moveTarget(quarantine, report, remove, result, counts);
        if (problem.length() > 0) {
            return problem;
        }
        return remove ? strings.bulkDone("remove", counts[0]) : strings.bulkDone("quarantine", counts[1]);
    }

    /**
     * The installed plugins whose "select for removal" switch is on.
     *
     * <p>A selection is bound to the package it was made against: the key carries a digest of the
     * path and the contents, so if the directory is replaced between selecting and pressing the
     * button, the key no longer matches and the replacement is not removed on the strength of a
     * choice made about something else.
     */
    public List<ScanReport> selectedTargets(Result result) {
        List<ScanReport> out = new ArrayList<ScanReport>();
        for (int i = 0; i < result.reports.size(); i++) {
            ScanReport report = result.reports.get(i);
            if (!report.installed || result.actioned.containsKey(report.path)) {
                continue;
            }
            if (report.contentHash == null || report.contentHash.length() == 0) {
                continue;
            }
            if (host.pluginId().equals(report.manifest.pluginId)) {
                continue;
            }
            if (host.configFlag(selectKey(report), false)) {
                out.add(report);
            }
        }
        return out;
    }

    /** Everything the uninstall button would delete: what is selected, plus anything malicious. */
    public List<ScanReport> uninstallTargets(Result result) {
        List<ScanReport> out = new ArrayList<ScanReport>(selectedTargets(result));
        List<ScanReport> malicious = actionTargets(result, "malicious");
        for (int i = 0; i < malicious.size(); i++) {
            if (!out.contains(malicious.get(i))) {
                out.add(malicious.get(i));
            }
        }
        return out;
    }

    /** How many plugins are sitting in quarantine, which the uninstall button also clears out. */
    public int quarantinedCount() {
        return new Quarantine(new File(host.filesDir(), "quarantine")).list().size();
    }

    /**
     * Deletes every plugin the user selected, every plugin the scan called malicious, and everything
     * already sitting in quarantine. This is the uninstall button.
     *
     * <p>Permanent by design: quarantine is the reversible action, and this is the one that finishes
     * the job. Each package is re-read and refused if it changed since the scan, and a selection is
     * cleared once it has been acted on so it cannot fire twice.
     */
    public String uninstallSelection(Result result) {
        Quarantine quarantine = new Quarantine(new File(host.filesDir(), "quarantine"));
        List<ScanReport> targets = uninstallTargets(result);
        List<Quarantine.Item> held = quarantine.list();
        if (targets.isEmpty() && held.isEmpty()) {
            return strings.nothingSelected();
        }
        int[] counts = new int[2];
        StringBuilder problems = new StringBuilder();
        for (int i = 0; i < targets.size(); i++) {
            ScanReport report = targets.get(i);
            String problem = moveTarget(quarantine, report, true, result, counts);
            // Cleared either way: a selection that failed has been reported, and leaving it on would
            // act again unprompted the next time the button is pressed.
            host.putFlag(selectKey(report), false);
            if (problem.length() > 0) {
                append(problems, problem);
            }
        }
        int purged = 0;
        for (int i = 0; i < held.size(); i++) {
            Quarantine.Result result2 = quarantine.purge(held.get(i).directory.getName());
            if (result2.ok) {
                purged++;
            } else {
                append(problems, result2.message);
            }
        }
        String summary = strings.uninstalled(counts[0], purged);
        if (counts[1] > 0) {
            summary = summary + "   " + strings.someOnlyQuarantined(counts[1]);
        }
        return problems.length() == 0 ? summary : summary + "   " + problems;
    }

    /** Quarantines, or removes, every installed plugin a scope covers. For the v3 "all" button. */
    public String actOnScope(Result result, String scope, boolean remove) {
        List<ScanReport> targets = actionTargets(result, scope);
        if (targets.isEmpty()) {
            return strings.nothingMatches(scope);
        }
        Quarantine quarantine = new Quarantine(new File(host.filesDir(), "quarantine"));
        int[] counts = new int[2];
        StringBuilder problems = new StringBuilder();
        for (int i = 0; i < targets.size(); i++) {
            String problem = moveTarget(quarantine, targets.get(i), remove, result, counts);
            if (problem.length() > 0) {
                append(problems, problem);
            }
        }
        String summary = remove ? strings.bulkDone("remove", counts[0])
                : strings.bulkDone("quarantine", counts[1]);
        if (remove && counts[1] > 0) {
            summary = summary + "   " + strings.someOnlyQuarantined(counts[1]);
        }
        return problems.length() == 0 ? summary : summary + "   " + problems;
    }

    /**
     * Deletes the copy this move just created.
     *
     * <p>Identified by the directory the move allocated, not by where it came from: an older copy of
     * the same plugin can still be in quarantine, and purging that one would leave the new copy behind
     * while reporting the plugin as permanently deleted.
     */
    private Quarantine.Result purgeExact(Quarantine quarantine, File location, String originalPath) {
        if (location != null) {
            return quarantine.purge(location.getName());
        }
        return new Quarantine.Result(false, strings.couldNotPurge(originalPath));
    }

    /**
     * The identities a scope covers right now, in a stable order.
     *
     * <p>Sorted so that a plan and its later confirmation compare equal whenever the same plugins are
     * present, regardless of the order the scan happened to return them in.
     */
    private String targetIds(String scope, Result result) {
        List<ScanReport> targets = verifiable(bulkTargets(scope, result));
        List<String> entries = new ArrayList<String>();
        for (int i = 0; i < targets.size(); i++) {
            ScanReport report = targets.get(i);
            entries.add("{\"path\": " + Json.quote(report.path)
                    + ", \"sha\": " + Json.quote(report.contentHash) + "}");
        }
        // Sorted so a plan and its confirmation compare equal whenever the same plugins are present,
        // and written as JSON rather than joined with a delimiter: plugin ids come from an untrusted
        // manifest, and one containing a newline used to split into several identities, which could
        // match packages the plan never listed.
        java.util.Collections.sort(entries);
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(entries.get(i));
        }
        return sb.append("]").toString();
    }

    /**
     * The subset whose contents the scan managed to hash.
     *
     * <p>A package with no hash cannot be re-identified when the confirmation arrives, so it is left
     * out of both the displayed list and the stored plan. Those two have to agree: a plan that
     * silently covers something the user was not shown is exactly what the confirmation exists to
     * prevent.
     */
    private static List<ScanReport> verifiable(List<ScanReport> reports) {
        List<ScanReport> out = new ArrayList<ScanReport>();
        for (int i = 0; i < reports.size(); i++) {
            ScanReport report = reports.get(i);
            if (report.contentHash != null && report.contentHash.length() > 0) {
                out.add(report);
            }
        }
        return out;
    }

    /** The installed plugins a scope covers, never including this scanner. */
    private List<ScanReport> bulkTargets(String scope, Result result) {
        List<ScanReport> out = new ArrayList<ScanReport>();
        for (int i = 0; i < result.reports.size(); i++) {
            ScanReport report = result.reports.get(i);
            if (!report.installed) {
                continue;
            }
            // The reports are the scan from before this build acted on anything. A plugin an armed
            // switch has just moved is no longer installed, and counting it here would let a pending
            // confirmation validate against a set that no longer exists: the check would pass, then
            // the action would fail on the moved plugin while still processing the rest.
            if (result.actioned.containsKey(report.path)) {
                continue;
            }
            if (host.pluginId().equals(report.manifest.pluginId)) {
                continue;
            }
            Verdict verdict = report.verdict();
            boolean malicious = verdict == Verdict.LIKELY_MALICIOUS || verdict == Verdict.KNOWN_BAD;
            boolean suspicious = malicious || verdict == Verdict.SUSPICIOUS;
            boolean matches;
            if (scope.equals("malicious")) {
                matches = malicious;
            } else if (scope.equals("flagged")) {
                // Everything the scan called out, "worth a look" included. This is the widest scope,
                // and the one the quarantine-all command uses.
                matches = verdict.flagged();
            } else {
                matches = suspicious;
            }
            if (matches) {
                out.add(report);
            }
        }
        return out;
    }

    /** Finds the report for an exact package location whose contents still match the plan. */
    private static ScanReport findByPath(String path, String sha, Result result) {
        for (int i = 0; i < result.reports.size(); i++) {
            ScanReport report = result.reports.get(i);
            if (result.actioned.containsKey(report.path)) {
                continue;
            }
            // No wildcard: a report whose hash could not be computed, or a plan that recorded none,
            // cannot prove the package here is the one that was listed, and this deletes things.
            if (report.path.equals(path) && sha.length() > 0 && sha.equals(report.contentHash)) {
                return report;
            }
        }
        return null;
    }

    /** Rebuilds the canonical target list from a stored plan, for comparison with the current one. */
    private static String rebuildTargetList(List<java.util.Map<String, Object>> targets) {
        List<String> entries = new ArrayList<String>();
        for (int i = 0; i < targets.size(); i++) {
            entries.add("{\"path\": " + Json.quote(Json.str(targets.get(i), "path", ""))
                    + ", \"sha\": " + Json.quote(Json.str(targets.get(i), "sha", "")) + "}");
        }
        java.util.Collections.sort(entries);
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(entries.get(i));
        }
        return sb.append("]").toString();
    }

    /** Short code binding a confirmation to one action over one exact set of plugins. */
    private static String confirmationCode(String action, String scope, String ids) {
        try {
            String digest = Bytes.sha256((action + "|" + scope + "|" + ids).getBytes("UTF-8"));
            return digest.substring(0, 4);
        } catch (java.io.UnsupportedEncodingException e) {
            return "0000";
        }
    }

    /**
     * Makes an untrusted display name safe to put in a prompt.
     *
     * <p>Names come from manifest.json, where an escaped newline is perfectly valid JSON. Left as they
     * are, a plugin could break the confirmation message across lines or write a convincing fake
     * "confirm ..." instruction into the list of things about to be deleted. The prompt is the one
     * place the user is asked to trust what they read, so control characters are flattened and the
     * name is bounded.
     */
    static String flatten(String name) {
        if (name == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length() && sb.length() < 60; i++) {
            char c = name.charAt(i);
            sb.append(c < 0x20 || (c >= 0x7F && c <= 0x9F) ? ' ' : c);
        }
        String flat = sb.toString().trim();
        return flat.length() == 0 ? "(unnamed)" : flat;
    }

    /**
     * True when the package at a report's path still has the contents the scan saw.
     *
     * <p>The scan is a snapshot taken earlier in this build, and MT Manager or a running plugin can
     * change the filesystem in between. Re-reading costs one more hash per target, which is a small
     * price on the path that moves and deletes a user's plugins.
     */
    private static boolean stillMatches(ScanReport report) {
        if (report.contentHash == null || report.contentHash.length() == 0) {
            return false;
        }
        PluginPackage pkg = null;
        try {
            pkg = PluginPackage.open(new File(report.path));
            String now = pkg.contentHash(ScanBudget.unlimited());
            return now.length() > 0 && now.equals(report.contentHash);
        } catch (java.io.IOException e) {
            return false;
        } catch (RuntimeException e) {
            return false;
        } finally {
            if (pkg != null) {
                pkg.close();
            }
        }
    }

    private static void append(StringBuilder sb, String message) {
        if (message == null || message.length() == 0) {
            return;
        }
        if (sb.length() > 0) {
            sb.append("   ");
        }
        sb.append(message);
    }

    // ------------------------------------------------------------------ display

    private void buildRows(Result result, IocDatabase database, List<File> roots, int candidateCount) {
        List<Row> rows = result.rows;

        if (result.commandOutcome != null && result.commandOutcome.length() > 0) {
            rows.add(Row.header(strings.lastAction()));
            rows.add(Row.text(result.commandOutcome, ""));
        }

        rows.add(Row.header(strings.summaryHeader()));
        if (candidateCount == 0) {
            rows.add(Row.text(strings.nothingFound(), strings.nothingFoundHelp()));
        } else {
            rows.add(Row.text(ReportFormatter.overview(result.reports), strings.scannedIn(elapsed(result))));
            if (result.unscanned > 0) {
                rows.add(Row.text(strings.notReached(result.unscanned), strings.notReachedHelp()));
            }
            int malicious = bulkTargets("malicious", result).size();
            int suspicious = bulkTargets("suspicious", result).size();
            if (suspicious > 0) {
                rows.add(Row.text(strings.bulkOffer(malicious, suspicious), strings.bulkOfferHelp()));
            }
        }

        // Worst first, so the thing that matters is the first thing on screen.
        List<ScanReport> ordered = orderByRisk(result.reports);
        for (int i = 0; i < ordered.size(); i++) {
            ScanReport report = ordered.get(i);
            rows.add(Row.header(verdictMarker(report) + " " + report.manifest.displayName()));
            String happened = result.actioned.get(report.path);
            if (happened != null) {
                boolean removed = "removed".equals(happened);
                rows.add(Row.text(removed ? strings.actedOnRemoved() : strings.actedOn(),
                        removed ? strings.actedOnRemovedHelp() : strings.actedOnHelp()));
            }
            rows.add(Row.text(strings.verdictLabel() + ": " + report.verdict().label()
                    + "  (" + report.score() + ")", report.verdict().advice()));
            // A switch to select this plugin for the uninstall button. Offered for anything the scan
            // flagged at all, since "worth a look" is exactly what a user wants to sweep, and only for
            // installed packages that were hashed: without a hash the key is the same for whatever
            // replaces this directory, and a stale selection would act on the replacement.
            if (report.installed && report.verdict().flagged()
                    && report.contentHash != null && report.contentHash.length() > 0
                    && !host.pluginId().equals(report.manifest.pluginId)
                    && !result.actioned.containsKey(report.path)) {
                rows.add(Row.toggle(strings.selectThis(), strings.selectThisHelp(),
                        selectKey(report), report));
            }
            if (report.manifest.pluginId.length() > 0) {
                rows.add(Row.text(report.manifest.pluginId,
                        strings.versionLabel() + ": "
                                + (report.manifest.versionName.length() > 0
                                        ? report.manifest.versionName : "?")));
            }

            List<Signal> signals = report.signalsBySeverity();
            int shown = 0;
            for (int j = 0; j < signals.size(); j++) {
                Signal signal = signals.get(j);
                if (signal.severity == Severity.INFO && shown > 0) {
                    continue;
                }
                if (shown >= 8) {
                    rows.add(Row.text(strings.moreFindings(signals.size() - shown), ""));
                    break;
                }
                rows.add(Row.text(signal.severity.marker() + " " + signal.title, evidenceLine(signal)));
                shown++;
            }
            if (report.truncated()) {
                rows.add(Row.text(strings.incomplete(), ""));
            }
            for (int j = 0; j < report.errors.size() && j < 3; j++) {
                rows.add(Row.text(strings.problem(), report.errors.get(j)));
            }
            rows.add(Row.text(strings.pathLabel(), report.path));
            // Shown in full: this is the value the trust command takes, and a truncated one cannot be
            // used for anything the screen offers.
            rows.add(Row.text(strings.hashLabel(), fullHash(report.contentHash)));
        }

        List<Row> about = result.aboutRows;
        about.add(Row.header(strings.aboutHeader()));
        about.add(Row.text(strings.trustCounts(database.trustedCount(), database.deniedCount()),
                new File(host.filesDir(), "indicators.json").getAbsolutePath()));
        about.add(Row.text(strings.rootsSearched(roots.size()), describeRoots(roots)));
        about.add(Row.text(strings.selfExcluded(), host.pluginId()));
        about.add(Row.text(strings.limitsTitle(), strings.limits()));
    }

    private String elapsed(Result result) {
        long total = 0;
        for (int i = 0; i < result.reports.size(); i++) {
            total += result.reports.get(i).elapsedMs();
        }
        return total + " ms";
    }

    private static List<ScanReport> orderByRisk(List<ScanReport> reports) {
        List<ScanReport> sorted = new ArrayList<ScanReport>(reports);
        java.util.Collections.sort(sorted, new java.util.Comparator<ScanReport>() {
            @Override
            public int compare(ScanReport a, ScanReport b) {
                int byScore = b.score() - a.score();
                if (byScore != 0) {
                    return byScore;
                }
                return a.manifest.displayName().compareToIgnoreCase(b.manifest.displayName());
            }
        });
        return sorted;
    }

    private static String verdictMarker(ScanReport report) {
        Verdict verdict = report.verdict();
        if (verdict == Verdict.KNOWN_BAD || verdict == Verdict.LIKELY_MALICIOUS) {
            return "[!!!]";
        }
        if (verdict == Verdict.SUSPICIOUS) {
            return "[!! ]";
        }
        if (verdict == Verdict.REVIEW) {
            return "[!  ]";
        }
        if (verdict == Verdict.UNREADABLE) {
            return "[ ? ]";
        }
        return "[ ok]";
    }

    private static String evidenceLine(Signal signal) {
        List<Signal.Evidence> evidence = signal.evidence();
        if (evidence.isEmpty()) {
            return signal.detail;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(evidence.get(0).where);
        if (evidence.get(0).snippet.length() > 0) {
            sb.append("  |  ").append(evidence.get(0).snippet);
        }
        if (evidence.size() > 1) {
            sb.append("   (+").append(evidence.size() - 1).append(")");
        }
        return sb.toString();
    }

    private static String fullHash(String hash) {
        return hash == null || hash.length() == 0 ? "(none)" : hash;
    }

    private static String describeRoots(List<File> roots) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < roots.size() && i < 4; i++) {
            if (sb.length() > 0) {
                sb.append("  ");
            }
            sb.append(roots.get(i).getAbsolutePath());
        }
        if (roots.size() > 4) {
            sb.append("  ...");
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ commands

    /** Executes one typed command and returns a sentence describing what happened. */
    private String runCommand(String command, IocDatabase database, File configFile, Result result) {
        String[] parts = command.split("\\s+", 2);
        String verb = parts[0].toLowerCase(java.util.Locale.US);
        String argument = parts.length > 1 ? parts[1].trim() : "";
        Quarantine quarantine = new Quarantine(new File(host.filesDir(), "quarantine"));

        try {
            if (verb.equals("help")) {
                return strings.commandsHelp();
            }
            if (verb.equals("deep")) {
                host.putFlag(KEY_DEEP, true);
                return strings.deepEnabled();
            }
            if (verb.equals("fast")) {
                host.putFlag(KEY_DEEP, false);
                return strings.deepDisabled();
            }
            if (verb.equals("root")) {
                if (argument.length() == 0) {
                    host.putConfig(KEY_EXTRA_ROOT, "");
                    return strings.rootCleared();
                }
                File root = new File(argument);
                if (!root.isDirectory()) {
                    return strings.notADirectory(argument);
                }
                host.putConfig(KEY_EXTRA_ROOT, root.getAbsolutePath());
                return strings.rootAdded(root.getAbsolutePath());
            }
            if (verb.equals("trust") || verb.equals("untrust") || verb.equals("deny")) {
                return trustCommand(verb, argument, database, configFile);
            }
            // quarantine-all covers everything the scan flagged, "worth a look" included, which is
            // wider than "suspicious" and is the sweep most people actually want.
            if (verb.equals("quarantine-all") || verb.equals("remove-all")) {
                return planBulk(verb.substring(0, verb.indexOf('-')), "flagged", result);
            }
            if (verb.equals("quarantine") || verb.equals("remove")) {
                // A scope quarantines or removes everything the scan flagged; anything else names one
                // plugin, which only quarantine does.
                String scope = argument.toLowerCase(java.util.Locale.US);
                if (scope.equals("flagged") || scope.equals("worth-a-look")) {
                    return planBulk(verb, "flagged", result);
                }
                if (scope.equals("malicious") || scope.equals("suspicious") || scope.equals("all")) {
                    return planBulk(verb, scope.equals("all") ? "suspicious" : scope, result);
                }
                if (verb.equals("remove")) {
                    return strings.removeNeedsScope();
                }
                return quarantineCommand(argument, quarantine, result);
            }
            if (verb.equals("confirm")) {
                return confirmBulk(argument, result);
            }
            if (verb.equals("cancel")) {
                host.putConfig(KEY_PENDING_PLAN, "");
                return strings.planCancelled();
            }
            if (verb.equals("restore")) {
                return quarantine.restore(argument).message;
            }
            if (verb.equals("purge")) {
                return quarantine.purge(argument).message;
            }
            if (verb.equals("quarantined")) {
                return describeQuarantine(quarantine);
            }
            if (verb.equals("export")) {
                return exportCommand();
            }
            return strings.unknownCommand(verb);
        } catch (RuntimeException e) {
            host.log("command failed", e);
            return strings.commandFailed(String.valueOf(e.getMessage()));
        }
    }

    private String trustCommand(String verb, String argument, IocDatabase database, File configFile) {
        if (argument.length() == 0) {
            return strings.needsArgument(verb);
        }
        if (verb.equals("trust")) {
            database.trust(argument, "trusted from the scanner screen");
        } else if (verb.equals("untrust")) {
            database.untrust(argument);
        } else {
            database.deny(argument, "denied from the scanner screen");
        }
        try {
            database.save(configFile);
        } catch (IOException e) {
            return strings.couldNotSave(e.getMessage());
        }
        return strings.listUpdated(verb, argument);
    }

    /**
     * Quarantines the installed plugin whose id or folder name matches.
     *
     * <p>Resolved against the plugins actually discovered rather than against a path the user types, so
     * a typo cannot move an unrelated directory.
     */
    private String quarantineCommand(String argument, Quarantine quarantine, Result result) {
        if (argument.length() == 0) {
            return strings.needsArgument("quarantine");
        }
        for (int i = 0; i < result.reports.size(); i++) {
            ScanReport report = result.reports.get(i);
            if (!report.installed || result.actioned.containsKey(report.path)) {
                continue;
            }
            boolean match = argument.equals(report.manifest.pluginId)
                    || argument.equals(new File(report.path).getName())
                    || argument.equalsIgnoreCase(report.manifest.displayName());
            if (match) {
                if (!stillMatches(report)) {
                    return strings.changedSinceScan(flatten(report.manifest.displayName()));
                }
                Quarantine.Result moved = quarantine.quarantine(new File(report.path), host.pluginId());
                if (moved.ok) {
                    // Recorded so the rebuilt screen shows this as moved rather than still installed
                    // with a live switch: the scan ran before this command did.
                    result.actioned.put(report.path, "quarantined");
                }
                return moved.message;
            }
        }
        return strings.noSuchPlugin(argument);
    }

    private String describeQuarantine(Quarantine quarantine) {
        List<Quarantine.Item> items = quarantine.list();
        if (items.isEmpty()) {
            return strings.quarantineEmpty();
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (sb.length() > 0) {
                sb.append("   ");
            }
            sb.append(items.get(i).pluginId.length() > 0
                    ? items.get(i).pluginId : items.get(i).directory.getName());
        }
        return sb.toString();
    }

    /** Writes the full report next to the plugin's configuration, for opening in MT Manager. */
    private String exportCommand() {
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.hostPackage(), host.config(KEY_EXTRA_ROOT, ""));
        List<Discovery.Candidate> candidates = MtEnvironment.findPlugins(roots, host.pluginId(), host.filesDir());
        IocDatabase database = IocDatabase.load(new File(host.filesDir(), "indicators.json"));
        PluginScanner scanner = new PluginScanner(database);
        List<ScanReport> reports = new ArrayList<ScanReport>();
        for (int i = 0; i < candidates.size(); i++) {
            reports.add(scanner.scan(candidates.get(i).path, ScanBudget.deep()));
        }
        scanner.finishSet(reports);

        File textFile = new File(host.filesDir(), "scan-report.txt");
        File jsonFile = new File(host.filesDir(), "scan-report.json");
        try {
            write(textFile, ReportFormatter.plainText(reports));
            write(jsonFile, ReportFormatter.json(reports));
        } catch (IOException e) {
            return strings.couldNotSave(e.getMessage());
        }
        return strings.exported(textFile.getAbsolutePath());
    }

    private static void write(File file, String content) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("could not create " + parent.getAbsolutePath());
        }
        OutputStream out = new FileOutputStream(file);
        try {
            out.write(content.getBytes("UTF-8"));
        } finally {
            out.close();
        }
    }
}
