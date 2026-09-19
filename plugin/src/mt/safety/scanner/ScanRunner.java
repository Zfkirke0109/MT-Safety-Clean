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

        private Row(boolean header, boolean toggle, String key, String title, String summary) {
            this.header = header;
            this.toggle = toggle;
            this.key = key;
            this.title = title;
            this.summary = summary;
        }

        public static Row header(String title) {
            return new Row(true, false, null, title, null);
        }

        public static Row text(String title, String summary) {
            return new Row(false, false, null, title, summary);
        }

        /**
         * A switch that arms an action on one plugin.
         *
         * <p>The settings screen has no buttons, so a switch is the only thing a user can tap to mean
         * "this one". It is read on the next build, which is also what keeps it safe: nothing happens
         * while the screen is open, and the action is listed before it runs.
         */
        public static Row toggle(String title, String summary, String key) {
            return new Row(false, true, key, title, summary);
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
        /** Absolute paths acted on during this build, so the report can say so. */
        public final java.util.Set<String> actioned = new java.util.HashSet<String>();
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

    /** Runs any pending command, then scans, then builds the rows to display. */
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
                MtEnvironment.candidateRoots(host.filesDir(), host.config(KEY_EXTRA_ROOT, "")),
                result.reports.size() + result.unscanned);
        return result;
    }

    /** Runs the scan itself, filling {@code result.reports}. */
    private void scanInto(Result result, IocDatabase database) {
        boolean deep = host.configFlag(KEY_DEEP, false);
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.config(KEY_EXTRA_ROOT, ""));
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
        String id = report.manifest.pluginId;
        if (id == null || id.length() == 0) {
            id = report.label;
        }
        StringBuilder sb = new StringBuilder(KEY_ARM_PREFIX);
        for (int i = 0; i < id.length() && i < 64; i++) {
            char c = id.charAt(i);
            sb.append(Character.isLetterOrDigit(c) ? c : '_');
        }
        return sb.toString();
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
            String key = armKey(report);
            if (!host.configFlag(key, false)) {
                continue;
            }
            host.putFlag(key, false);
            if (report.archive) {
                // A file sitting in a downloads folder is not something this plugin should delete.
                append(done, strings.notInstalled(report.manifest.displayName()));
                continue;
            }
            Quarantine.Result moved = quarantine.quarantine(new File(report.path), host.pluginId());
            if (moved.ok) {
                result.actioned.add(report.path);
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
        List<ScanReport> targets = bulkTargets(scope, result);
        if (targets.isEmpty()) {
            return strings.nothingMatches(scope);
        }
        StringBuilder names = new StringBuilder();
        for (int i = 0; i < targets.size(); i++) {
            if (i > 0) {
                names.append(", ");
            }
            names.append(targets.get(i).manifest.displayName());
        }
        String ids = targetIds(scope, result);
        String code = confirmationCode(action, scope, ids);
        StringBuilder plan = new StringBuilder();
        plan.append("{\"action\": ").append(Json.quote(action));
        plan.append(", \"scope\": ").append(Json.quote(scope));
        plan.append(", \"ids\": ").append(Json.quote(ids));
        plan.append(", \"code\": ").append(Json.quote(code)).append("}");
        host.putConfig(KEY_PENDING_PLAN, plan.toString());

        return strings.planned(action, targets.size(), names.toString(), code);
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
        try {
            java.util.Map<String, Object> plan = Json.parseObject(stored);
            action = Json.str(plan, "action", "");
            scope = Json.str(plan, "scope", "");
            ids = Json.str(plan, "ids", "");
            expected = Json.str(plan, "code", "");
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
        String[] wanted = ids.split("\n");
        int done = 0;
        StringBuilder problems = new StringBuilder();
        for (int i = 0; i < wanted.length; i++) {
            String id = wanted[i].trim();
            if (id.length() == 0) {
                continue;
            }
            ScanReport match = findByIdentity(id, result);
            if (match == null || match.archive) {
                append(problems, strings.noSuchPlugin(id));
                continue;
            }
            Quarantine.Result moved = quarantine.quarantine(new File(match.path), host.pluginId());
            if (!moved.ok) {
                append(problems, moved.message);
                continue;
            }
            result.actioned.add(match.path);
            done++;
            if (permanent) {
                Quarantine.Result purged = purgeByOriginalPath(quarantine, match.path);
                if (!purged.ok) {
                    append(problems, purged.message);
                }
            }
        }
        String summary = strings.bulkDone(action, done);
        return problems.length() == 0 ? summary : summary + "   " + problems;
    }

    /** Deletes the quarantined copy that came from {@code originalPath}. */
    private Quarantine.Result purgeByOriginalPath(Quarantine quarantine, String originalPath) {
        List<Quarantine.Item> items = quarantine.list();
        for (int i = 0; i < items.size(); i++) {
            if (originalPath.equals(items.get(i).originalPath)) {
                return quarantine.purge(items.get(i).directory.getName());
            }
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
        List<ScanReport> targets = bulkTargets(scope, result);
        List<String> ids = new ArrayList<String>();
        for (int i = 0; i < targets.size(); i++) {
            ids.add(identityOf(targets.get(i)));
        }
        java.util.Collections.sort(ids);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            if (i > 0) {
                sb.append('\n');
            }
            sb.append(ids.get(i));
        }
        return sb.toString();
    }

    /** The installed plugins a scope covers, never including this scanner. */
    private List<ScanReport> bulkTargets(String scope, Result result) {
        List<ScanReport> out = new ArrayList<ScanReport>();
        for (int i = 0; i < result.reports.size(); i++) {
            ScanReport report = result.reports.get(i);
            if (report.archive) {
                continue;
            }
            // The reports are the scan from before this build acted on anything. A plugin an armed
            // switch has just moved is no longer installed, and counting it here would let a pending
            // confirmation validate against a set that no longer exists: the check would pass, then
            // the action would fail on the moved plugin while still processing the rest.
            if (result.actioned.contains(report.path)) {
                continue;
            }
            if (host.pluginId().equals(report.manifest.pluginId)) {
                continue;
            }
            Verdict verdict = report.verdict();
            boolean malicious = verdict == Verdict.LIKELY_MALICIOUS || verdict == Verdict.KNOWN_BAD;
            boolean suspicious = malicious || verdict == Verdict.SUSPICIOUS;
            if (scope.equals("malicious") ? malicious : suspicious) {
                out.add(report);
            }
        }
        return out;
    }

    private static String identityOf(ScanReport report) {
        String id = report.manifest.pluginId;
        return id != null && id.length() > 0 ? id : new File(report.path).getName();
    }

    private static ScanReport findByIdentity(String id, Result result) {
        for (int i = 0; i < result.reports.size(); i++) {
            ScanReport report = result.reports.get(i);
            if (result.actioned.contains(report.path)) {
                continue;
            }
            if (identityOf(report).equals(id)) {
                return report;
            }
        }
        return null;
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
            if (result.actioned.contains(report.path)) {
                rows.add(Row.text(strings.actedOn(), strings.actedOnHelp()));
            }
            rows.add(Row.text(strings.verdictLabel() + ": " + report.verdict().label()
                    + "  (" + report.score() + ")", report.verdict().advice()));
            // One tap beats typing an id, and only for the installed plugins this can actually move.
            if (!report.archive && report.verdict().actionable()
                    && !host.pluginId().equals(report.manifest.pluginId)
                    && !result.actioned.contains(report.path)) {
                rows.add(Row.toggle(strings.quarantineThis(), strings.quarantineThisHelp(),
                        armKey(report)));
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
            rows.add(Row.text(strings.hashLabel(), shortHash(report.contentHash)));
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

    private static String shortHash(String hash) {
        if (hash == null || hash.length() < 16) {
            return "(none)";
        }
        return hash.substring(0, 16);
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
            if (verb.equals("quarantine") || verb.equals("remove")) {
                // A scope quarantines or removes everything the scan flagged; anything else names one
                // plugin, which only quarantine does.
                String scope = argument.toLowerCase(java.util.Locale.US);
                if (scope.equals("malicious") || scope.equals("suspicious") || scope.equals("all")) {
                    return planBulk(verb, scope.equals("all") ? "suspicious" : scope, result);
                }
                if (verb.equals("remove")) {
                    return strings.removeNeedsScope();
                }
                return quarantineCommand(argument, quarantine);
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
    private String quarantineCommand(String argument, Quarantine quarantine) {
        if (argument.length() == 0) {
            return strings.needsArgument("quarantine");
        }
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.config(KEY_EXTRA_ROOT, ""));
        List<Discovery.Candidate> candidates = MtEnvironment.findPlugins(roots, host.pluginId(), host.filesDir());
        for (int i = 0; i < candidates.size(); i++) {
            Discovery.Candidate candidate = candidates.get(i);
            if (!candidate.installed) {
                continue;
            }
            // Only the plugin's identity is needed here. Scanning each candidate in full would cost
            // pattern matching, archive rules and hashing to learn one string, on the UI thread.
            PluginManifest manifest = PluginManifest.readFrom(candidate.path);
            boolean match = argument.equals(manifest.pluginId)
                    || argument.equals(candidate.path.getName())
                    || argument.equalsIgnoreCase(manifest.displayName());
            if (match) {
                Quarantine.Result result = quarantine.quarantine(candidate.path, host.pluginId());
                return result.message;
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
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.config(KEY_EXTRA_ROOT, ""));
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
