package mt.safety.scanner;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import mt.safety.scanner.core.Bytes;
import mt.safety.scanner.core.AtomicFiles;
import mt.safety.scanner.core.Coverage;
import mt.safety.scanner.core.CodePatterns;
import mt.safety.scanner.core.Dates;
import mt.safety.scanner.core.Discovery;
import mt.safety.scanner.core.FileScanner;
import mt.safety.scanner.core.Json;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ShareReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Severity;
import mt.safety.scanner.core.Signal;
import mt.safety.scanner.core.SignatureDatabase;
import mt.safety.scanner.core.Verdict;

/**
 * Drives a scan and turns the result into rows a settings screen can show.
 *
 * <p>The scan reports capabilities and coverage. Plugin file management is delegated to MT Manager;
 * legacy mutation commands and preferences only return guidance and clear retired action state.
 *
 * <p>Nothing here references an MT Manager class, so it can be tested on a desktop JVM.
 */
public final class ScanRunner {

    /** Config keys. */
    public static final String KEY_COMMAND = "command";
    public static final String KEY_DEEP = "deep_scan";
    public static final String KEY_EXTRA_ROOT = "extra_root";
    public static final String KEY_LAST_RESULT = "last_result";
    /** Legacy action preference keys retained so old state can be safely retired. */
    public static final String KEY_ARM_PREFIX = "arm_";
    public static final String KEY_SELECT_PREFIX = "sel_";
    public static final String KEY_PENDING_PLAN = "pending_plan";

    /** The folder, inside this plugin's own directory, holding imported signature files. */
    public static final String SIGNATURE_DIR = "signatures";
    /** Where the last file scan's full list is written. */
    public static final String FILE_REPORT = "files-report.txt";

    /** How many matched files the screen lists before pointing at the report file. */
    private static final int MAX_FILE_HIT_ROWS = 20;

    /**
     * The last signature database loaded, kept while its folder is unchanged.
     *
     * <p>Loading a large database is the slowest thing the plugin does, and the settings screen is
     * rebuilt on every open and after every action. The folder's stamp, which covers the files'
     * names, sizes and modification times, decides whether the cached copy still stands.
     */
    private static SignatureDatabase cachedSignatures;
    private static String cachedSignatureStamp;

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
        /** Compatibility metadata for older callers; scanner report rows never expose action targets. */
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

        /** Compatibility factory; scanner reports no longer create management switches. */
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
        /** Compatibility field. Delegated actions never add successful mutation outcomes. */
        public final java.util.Map<String, String> actioned = new java.util.HashMap<String, String>();
        public String commandOutcome = "";
        /** A bounded diagnostic when package discovery could not inspect every search directory. */
        public String discoveryProblem = "";
        /** Files a {@code files} command in this build found matching a signature, one line each. */
        public final List<String> fileHitLines = new ArrayList<String>();
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

    /** Scans, retires legacy action state, then builds the rows to display. */
    public Result run() {
        Result result = new Result();
        File configFile = new File(host.filesDir(), "indicators.json");
        IocDatabase database = IocDatabase.load(configFile);
        SignatureDatabase signatures = loadSignatures(new File(host.filesDir(), SIGNATURE_DIR));

        scanInto(result, database, signatures);

        // Management state is retired only after read-only scanning supplies current preference keys.
        StringBuilder outcome = new StringBuilder();
        String armed = runArmedSwitches(result);
        if (armed.length() > 0) {
            outcome.append(armed);
        }
        String pending = host.config(KEY_COMMAND, "");
        if (pending != null && pending.trim().length() > 0) {
            // Cleared first: a command that somehow crashes must not run again on every open.
            host.putConfig(KEY_COMMAND, "");
            String commandResult = runCommand(pending.trim(), database, signatures, configFile, result);
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

        // Reloaded rather than reused: an import in this build changed the folder.
        buildRows(result, database, loadSignatures(new File(host.filesDir(), SIGNATURE_DIR)),
                MtEnvironment.candidateRoots(host.filesDir(), host.hostPackage(), host.config(KEY_EXTRA_ROOT, "")),
                result.reports.size() + result.unscanned);
        return result;
    }

    /** Loads the signature folder, reusing the previous load while the folder is unchanged. */
    static synchronized SignatureDatabase loadSignatures(File folder) {
        String stamp = SignatureDatabase.stamp(folder);
        if (cachedSignatures != null && stamp.equals(cachedSignatureStamp)) {
            return cachedSignatures;
        }
        SignatureDatabase loaded = SignatureDatabase.load(folder);
        cachedSignatures = loaded;
        cachedSignatureStamp = loaded.sourceStamp();
        return loaded;
    }

    /** Runs the scan itself, filling {@code result.reports}. */
    private void scanInto(Result result, IocDatabase database, SignatureDatabase signatures) {
        boolean deep = host.configFlag(KEY_DEEP, false);
        List<File> roots = MtEnvironment.candidateRoots(host.filesDir(), host.hostPackage(), host.config(KEY_EXTRA_ROOT, ""));
        Discovery discovery = new Discovery();
        List<Discovery.Candidate> candidates = MtEnvironment.findPlugins(roots, host.pluginId(), host.filesDir(),
                discovery);
        if (discovery.incomplete()) {
            result.discoveryProblem = discovery.problems().isEmpty()
                    ? "Plugin discovery did not inspect every search directory."
                    : discovery.problems().get(0);
        }

        PluginScanner scanner = new PluginScanner(database, signatures);
        long totalMs = deep ? DEEP_TOTAL_MS : INTERACTIVE_TOTAL_MS;
        long slice = candidates.isEmpty() ? totalMs : Math.max(300L, totalMs / candidates.size());
        // The per-package slice has a floor so a small scan is not starved, which means the slices can
        // add up past the total. The overall deadline is what actually keeps the settings screen
        // responsive: with many plugins installed, the rest are listed as unscanned rather than
        // freezing MT Manager for a minute and a half.
        long startedNanos = System.nanoTime();
        int scannedCount = 0;
        for (int i = 0; i < candidates.size(); i++) {
            if ((Thread.currentThread().isInterrupted()
                    || System.nanoTime() - startedNanos >= totalMs * 1000000L) && scannedCount > 0) {
                result.unscanned = candidates.size() - scannedCount;
                break;
            }
            ScanBudget budget = new ScanBudget(slice, BYTES_PER_PLUGIN);
            result.reports.add(scanner.scan(candidates.get(i).path, budget));
            scannedCount++;
        }
        scanner.finishSet(result.reports);
    }

    // ------------------------------------------------------------------ delegated management

    public static String armKey(ScanReport report) {
        return KEY_ARM_PREFIX + identityDigest(report);
    }

    private static String identityDigest(ScanReport report) {
        String identity = report.path + "|" + report.contentHash;
        try {
            return Bytes.sha256(identity.getBytes("UTF-8")).substring(0, 16);
        } catch (java.io.UnsupportedEncodingException e) {
            return Integer.toHexString(identity.hashCode());
        }
    }

    public static String selectKey(ScanReport report) {
        return KEY_SELECT_PREFIX + identityDigest(report);
    }

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

    /** Retire stored scanner action state without reading or mutating plugin files. */
    private String runArmedSwitches(Result result) {
        String pending = host.config(KEY_PENDING_PLAN, "");
        boolean retired = pending != null && pending.length() > 0;
        host.putConfig(KEY_PENDING_PLAN, "");
        for (ScanReport report : result.reports) {
            String arm = armKey(report);
            String select = selectKey(report);
            boolean armed = host.configFlag(arm, false);
            boolean selected = host.configFlag(select, false);
            retired |= armed || selected;
            if (armed) host.putFlag(arm, false);
            if (selected) host.putFlag(select, false);
        }
        return retired ? strings.managementDelegated() : "";
    }

    public List<ScanReport> actionTargets(Result result, String scope) {
        return new ArrayList<ScanReport>();
    }

    public String actOnOne(Result result, ScanReport report, boolean remove) {
        return delegateManagement();
    }

    public List<ScanReport> selectedTargets(Result result) {
        return new ArrayList<ScanReport>();
    }

    public List<ScanReport> uninstallTargets(Result result) {
        return new ArrayList<ScanReport>();
    }

    /** Read-only count retained for historical recovery information. */
    public int quarantinedCount() {
        return new Quarantine(new File(host.filesDir(), "quarantine")).list().size();
    }

    public String uninstallSelection(Result result) {
        return delegateManagement();
    }

    public String actOnScope(Result result, String scope, boolean remove) {
        return delegateManagement();
    }

    private String delegateManagement() {
        host.putConfig(KEY_PENDING_PLAN, "");
        return strings.managementDelegated();
    }

    /** Read-only scope counts used for review guidance. Never mutation eligibility. */
    private List<ScanReport> reviewTargets(String scope, Result result) {
        List<ScanReport> out = new ArrayList<ScanReport>();
        for (int i = 0; i < result.reports.size(); i++) {
            ScanReport report = result.reports.get(i);
            if (!report.installed) {
                continue;
            }
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
                // Read-only review counts include everything the scan called out.
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

    // ------------------------------------------------------------------ display

    private void buildRows(Result result, IocDatabase database, SignatureDatabase signatures, List<File> roots,
            int candidateCount) {
        List<Row> rows = result.rows;

        if (result.commandOutcome != null && result.commandOutcome.length() > 0) {
            rows.add(Row.header(strings.lastAction()));
            rows.add(Row.text(result.commandOutcome, ""));
        }
        if (!result.fileHitLines.isEmpty()) {
            rows.add(Row.header(strings.filesHeader()));
            for (int i = 0; i < result.fileHitLines.size(); i++) {
                rows.add(Row.text(result.fileHitLines.get(i), ""));
            }
        }

        rows.add(Row.header(strings.summaryHeader()));
        if (result.discoveryProblem.length() > 0) {
            rows.add(Row.text("Plugin discovery was incomplete",
                    "Absence of reported packages is not an all-clear. " + result.discoveryProblem));
        }
        if (candidateCount == 0) {
            rows.add(Row.text(strings.nothingFound(), strings.nothingFoundHelp()));
        } else {
            rows.add(Row.text(ReportFormatter.overview(result.reports), strings.scannedIn(elapsed(result))));
            if (result.unscanned > 0) {
                rows.add(Row.text(strings.notReached(result.unscanned), strings.notReachedHelp()));
            }
            int malicious = reviewTargets("malicious", result).size();
            int suspicious = reviewTargets("suspicious", result).size();
            if (suspicious > 0) {
                rows.add(Row.text(strings.bulkOffer(malicious, suspicious), strings.bulkOfferHelp()));
            }
        }

        // Worst first, so the thing that matters is the first thing on screen.
        List<ScanReport> ordered = orderByRisk(result.reports);
        for (int i = 0; i < ordered.size(); i++) {
            ScanReport report = ordered.get(i);
            rows.add(Row.header(verdictMarker(report) + " " + report.manifest.displayName()));
            rows.add(Row.text(strings.verdictLabel() + ": " + report.dispositionLabel()
                    + "  (" + report.score() + ")", report.dispositionAdvice()));
            if (report.installed && report.verdict().flagged()
                    && !host.pluginId().equals(report.manifest.pluginId)) {
                rows.add(Row.text(strings.managementDelegatedTitle(), strings.managementDelegated()));
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
        long now = System.currentTimeMillis();
        // Where the detection comes from, and how old it is. A scanner that cannot tell you this is
        // asking to be trusted on nothing.
        about.add(Row.text(strings.rulesTitle(CodePatterns.CATALOGUE_VERSION),
                strings.rulesLine(CodePatterns.CATALOGUE_VERSION, CodePatterns.CATALOGUE_DATE,
                        CodePatterns.ruleCount(), Dates.daysSince(CodePatterns.CATALOGUE_DATE, now))));
        about.add(Row.text(strings.indicatorTitle(),
                strings.indicatorLine(database.version(), database.updated(),
                        database.trustedCount(), database.deniedCount(), database.patternCount(),
                        database.undated() ? Dates.UNKNOWN : Dates.daysSince(database.updated(), now))));
        about.add(Row.text(strings.trustCounts(database.trustedCount(), database.deniedCount()),
                new File(host.filesDir(), "indicators.json").getAbsolutePath()));
        about.add(Row.text(strings.signatureTitle(), signatureLine(signatures, now)));
        about.add(Row.text(strings.signatureFolder(),
                new File(host.filesDir(), SIGNATURE_DIR).getAbsolutePath()));
        if (!signatures.problems().isEmpty()) {
            about.add(Row.text(strings.signatureProblems(signatures.problems().size(),
                    signatures.problems().get(0)), ""));
        }
        about.add(Row.text(strings.rootsSearched(roots.size()), describeRoots(roots)));
        about.add(Row.text(strings.selfExcluded(), host.pluginId()));
        about.add(Row.text(strings.limitsTitle(), strings.limits()));
    }

    /** The signature database's state as one sentence, for the About section and definitions. */
    private String signatureLine(SignatureDatabase signatures, long now) {
        String newest = signatures.fileCount() == 0 ? "" : Dates.isoDate(signatures.newestMillis());
        long age = signatures.fileCount() == 0 ? Dates.UNKNOWN
                : Dates.daysBetween(signatures.newestMillis(), now);
        return strings.signatureLine(signatures.fileCount(), signatures.hashCount(),
                signatures.patternCount(), newest, age, signatures.unsupportedCount(),
                signatures.cappedCount());
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
        if (report.coverage() == Coverage.PARTIAL) {
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
    private String runCommand(String command, IocDatabase database, SignatureDatabase signatures,
            File configFile, Result result) {
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
            if (verb.equals("quarantine-all") || verb.equals("remove-all")
                    || verb.equals("quarantine") || verb.equals("remove")
                    || verb.equals("restore") || verb.equals("purge") || verb.equals("confirm")) {
                return delegateManagement();
            }
            if (verb.equals("cancel")) {
                host.putConfig(KEY_PENDING_PLAN, "");
                return strings.planCancelled();
            }
            if (verb.equals("definitions") || verb.equals("defs")) {
                return describeDefinitions(database, signatures);
            }
            if (verb.equals("import")) {
                return importCommand(argument, database, configFile);
            }
            if (verb.equals("files")) {
                return scanFiles(argument, result.fileHitLines);
            }
            if (verb.equals("quarantined")) {
                return describeQuarantine(quarantine);
            }
            if (verb.equals("export") || verb.equals("export-shareable")) {
                return exportCommand(result, signatures, verb.equals("export-shareable"));
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
     * Where the detection came from and how old it is.
     *
     * <p>Two separate things, and they update differently. The rule catalogue is compiled into the
     * plugin, so it moves when the plugin is updated. The indicator file is the user's own, and moves
     * when they edit or import one.
     */
    private String describeDefinitions(IocDatabase database, SignatureDatabase signatures) {
        long now = System.currentTimeMillis();
        StringBuilder sb = new StringBuilder();
        sb.append(strings.rulesLine(CodePatterns.CATALOGUE_VERSION, CodePatterns.CATALOGUE_DATE,
                CodePatterns.ruleCount(), Dates.daysSince(CodePatterns.CATALOGUE_DATE, now)));
        sb.append("   ");
        sb.append(strings.indicatorLine(database.version(), database.updated(),
                database.trustedCount(), database.deniedCount(), database.patternCount(),
                database.undated() ? Dates.UNKNOWN : Dates.daysSince(database.updated(), now)));
        if (database.source().length() > 0) {
            sb.append("   ").append(strings.indicatorSource(database.source()));
        }
        sb.append("   ").append(strings.signatureTitle()).append(": ").append(signatureLine(signatures, now));
        if (!signatures.problems().isEmpty()) {
            sb.append("   ").append(strings.signatureProblems(signatures.problems().size(),
                    signatures.problems().get(0)));
        }
        return sb.toString();
    }

    /**
     * Folds an indicator file the user obtained themselves into their own.
     *
     * <p>A file, not a download. The scanner has no network code at all, which is the point: a list
     * fetched over the wire would put a server in the middle of a security decision and give this
     * plugin a capability it spends its time reporting other plugins for having. So an update is a
     * file you chose, from a source you trust, imported deliberately.
     */
    private String importCommand(String argument, IocDatabase database, File configFile) {
        if (argument.length() == 0) {
            return strings.needsArgument("import");
        }
        File source = new File(argument);
        if (!source.isFile()) {
            return strings.noSuchFile(argument);
        }
        if (SignatureDatabase.isPackedBundle(source.getName())) {
            return strings.importFailed(source.getName()
                    + " is a packed ClamAV bundle; unpack it first with sigtool --unpack");
        }
        if (SignatureDatabase.isSignatureFile(source.getName())) {
            return importSignatures(source, database);
        }
        IocDatabase incoming = IocDatabase.load(source);
        if (!incoming.loadErrors().isEmpty()) {
            return strings.importFailed(incoming.loadErrors().get(0));
        }
        int[] added = database.mergeFrom(incoming);
        try {
            database.save(configFile);
        } catch (IOException e) {
            return strings.couldNotSave(e.getMessage());
        }
        return strings.imported(added[0], added[1], added[2])
                + "   " + describeDefinitions(database, loadSignatures(new File(host.filesDir(), SIGNATURE_DIR)));
    }

    /**
     * Copies a ClamAV-format signature file into the plugin's signature folder.
     *
     * <p>Parsed first, so a file that is not what it claims is refused rather than left in the
     * folder to be reported as a problem on every open. Copying a file of the same name replaces
     * it, which is how a newer version of the same list is installed.
     */
    private String importSignatures(File source, IocDatabase database) {
        SignatureDatabase incoming = SignatureDatabase.load(source);
        if (incoming.hashCount() + incoming.patternCount() + incoming.cleanCount() == 0) {
            String why = strings.signaturesEmptyImport(source.getName());
            return incoming.problems().isEmpty() ? why : why + "   " + incoming.problems().get(0);
        }
        File folder;
        File target;
        boolean replaced;
        try {
            File own = host.filesDir().getCanonicalFile();
            folder = new File(own, SIGNATURE_DIR);
            if (!folder.getCanonicalFile().equals(folder.getAbsoluteFile())) {
                throw new IOException("signature directory redirects outside scanner storage");
            }
            if (!folder.isDirectory() && !folder.mkdir()) throw new IOException("could not create signature directory");
            target = new File(folder, source.getName());
            replaced = target.exists();
            copy(source, target);
        } catch (IOException e) {
            return strings.couldNotSave(e.getMessage());
        }
        synchronized (ScanRunner.class) {
            // The stamp would notice the change on its own; this makes sure of it even when the
            // copy lands within the same second as the file it replaced.
            cachedSignatureStamp = null;
        }
        return strings.signaturesImported(source.getName(), incoming.hashCount(), incoming.patternCount(),
                incoming.unsupportedCount(), replaced)
                + "   " + describeDefinitions(database, loadSignatures(folder));
    }

    /**
     * Checks the files this plugin can read against the loaded signatures.
     *
     * <p>Shared by the typed {@code files} command and the v3 button. Returns the outcome as one
     * paragraph; up to a screenful of matched files is appended to {@code hitLines}, and the full
     * list is written next to the plugin's other reports. Nothing is deleted: a signature hit on a
     * file in a download folder is something to show the user, not something to act on for them.
     *
     * @param argument a file or folder to check instead of the usual roots, or empty
     */
    public String scanFiles(String argument, List<String> hitLines) {
        SignatureDatabase signatures = loadSignatures(new File(host.filesDir(), SIGNATURE_DIR));
        boolean definitionsIncomplete = !signatures.complete() || !signatures.problems().isEmpty()
                || signatures.unsupportedCount() > 0 || signatures.cappedCount() > 0;
        if (signatures.isEmpty()) {
            return strings.noSignatures() + (definitionsIncomplete ? "   " + strings.filesIncomplete() : "");
        }
        List<File> roots;
        if (argument != null && argument.trim().length() > 0) {
            File target = new File(argument.trim());
            if (!target.exists() || !target.canRead()) {
                return strings.filesNeedsPath(argument.trim());
            }
            roots = new ArrayList<File>();
            roots.add(target);
        } else {
            roots = fileScanRoots();
        }
        boolean deep = host.configFlag(KEY_DEEP, false);
        FileScanner.Result scan = new FileScanner(signatures).scan(roots, host.filesDir(), ScanBudget.files(deep));

        StringBuilder sb = new StringBuilder();
        sb.append(strings.filesSummary(scan.filesScanned, scan.filesSeen, Bytes.humanSize(scan.bytesRead),
                scan.elapsedMs, scan.hits.size()));
        switch (scan.stoppedBecause) {
            case BUDGET:
                sb.append("   ").append(strings.filesStoppedBudget());
                break;
            case COUNT:
                sb.append("   ").append(strings.filesStoppedCount());
                break;
            case HITS:
                sb.append("   ").append(strings.filesStoppedHits());
                break;
            default:
                break;
        }
        boolean incomplete = scan.truncated() || definitionsIncomplete;
        if (incomplete) sb.append("   ").append(strings.filesIncomplete());
        if (scan.hits.isEmpty() && !incomplete) {
            sb.append("   ").append(strings.noFileHits());
        }
        for (int i = 0; i < scan.hits.size() && i < MAX_FILE_HIT_ROWS; i++) {
            FileScanner.Hit hit = scan.hits.get(i);
            hitLines.add((hit.pua ? Severity.HIGH.marker() : Severity.CRITICAL.marker()) + " "
                    + flatten(hit.signature) + "  |  " + hit.location());
        }
        if (scan.hits.size() > MAX_FILE_HIT_ROWS) {
            hitLines.add(strings.andMore(scan.hits.size() - MAX_FILE_HIT_ROWS));
        }
        File reportFile = new File(host.filesDir(), FILE_REPORT);
        try {
            write(reportFile, ReportFormatter.fileScanText(scan, signatures));
            sb.append("   ").append(strings.fileReportWritten(reportFile.getAbsolutePath()));
        } catch (IOException e) {
            sb.append("   ").append(strings.couldNotSave(e.getMessage()));
        }
        host.log("files: " + sb);
        return sb.toString();
    }

    /** The folders a file scan walks by default: the same places the plugin scan searches. */
    public List<File> fileScanRoots() {
        return MtEnvironment.candidateRoots(host.filesDir(), host.hostPackage(), host.config(KEY_EXTRA_ROOT, ""));
    }

    /** How many signatures are loaded, for the button that offers a file scan. */
    public int signatureCount() {
        SignatureDatabase signatures = loadSignatures(new File(host.filesDir(), SIGNATURE_DIR));
        return signatures.hashCount() + signatures.patternCount();
    }

    private static void copy(File from, File to) throws IOException {
        AtomicFiles.copy(from, to, SignatureDatabase.MAX_INPUT_BYTES);
    }

    private String describeQuarantine(Quarantine quarantine) {
        List<Quarantine.Item> items = quarantine.list();
        if (quarantine.listingProblem() != null) {
            return quarantine.listingProblem();
        }
        if (items.isEmpty()) {
            return strings.quarantineEmpty();
        }
        StringBuilder sb = new StringBuilder(strings.managementDelegated());
        for (int i = 0; i < items.size(); i++) {
            if (sb.length() > 0) {
                sb.append("   ");
            }
            sb.append(items.get(i).pluginId.length() > 0
                    ? items.get(i).pluginId : items.get(i).directory.getName());
            sb.append(" | held: ").append(items.get(i).directory.getAbsolutePath());
            sb.append(" | original: ").append(items.get(i).originalPath);
        }
        return sb.toString();
    }

    /** Exports the completed operation, including scope limits, without running a second scan. */
    private String exportCommand(Result result, SignatureDatabase signatures, boolean shareable) {
        List<ScanReport> reports = result.reports;
        boolean discoveryComplete = result.discoveryProblem.length() == 0;
        String scope = "Discovery complete: " + discoveryComplete + "; unscanned candidates: " + result.unscanned + "\n";
        String text = scope + (shareable ? ShareReportFormatter.text(reports)
                : ReportFormatter.plainText(reports, signatures));
        List<String> problems = new ArrayList<String>();
        if (!discoveryComplete) problems.add(result.discoveryProblem);
        String json = shareable ? "{\"discoveryComplete\":" + discoveryComplete
                + ",\"unscannedCandidates\":" + result.unscanned + ",\"report\":"
                + ShareReportFormatter.json(reports) + "}\n"
                : ReportFormatter.json(reports, signatures, problems);
        File textFile = new File(host.filesDir(), shareable ? "scan-report-share-safe.txt" : "scan-report.txt");
        File jsonFile = new File(host.filesDir(), shareable ? "scan-report-share-safe.json" : "scan-report.json");
        try {
            write(textFile, text);
            write(jsonFile, json);
        } catch (IOException e) {
            return strings.couldNotSave(e.getMessage());
        }
        return (shareable ? "SHARE_SAFE: " : "Local report contains package content; review before sharing. ")
                + strings.exported(textFile.getAbsolutePath());
    }

    private static void write(File file, String content) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("could not create " + parent.getAbsolutePath());
        }
        AtomicFiles.write(file, content.getBytes("UTF-8"));
    }
}
