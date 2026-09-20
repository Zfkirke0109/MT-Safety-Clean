package mt.safety.scanner.core;

import java.util.HashSet;
import java.util.Set;

/**
 * Turns a list of findings into a verdict.
 *
 * <p>Three ideas do the work here.
 *
 * <ol>
 *   <li><b>Combinations decide.</b> Network access is ordinary; reading private app data is odd;
 *       together they are exfiltration. Escalations are applied across the whole package, because a
 *       careful attacker puts the collection and the upload in different files.
 *   <li><b>Purpose excuses capability.</b> A translation engine must reach the network. Charging it for
 *       that produces a scary-looking report about a plugin doing its job, which trains the user to
 *       ignore reports.
 *   <li><b>The user's own trust wins.</b> A hash the user marked trusted is trusted, unless something
 *       critical turns up, in which case they should hear about it anyway.
 * </ol>
 */
public final class RiskScorer {

    private RiskScorer() {
    }

    /** Rule ids this class derives rather than detects, cleared before each scoring pass. */
    private static final String[] DERIVED_RULES = {
        "PRV001", "CTX001", "CMB101", "CMB102", "CMB103", "CMB104", "CMB105", "CMB106", "CMB107"
    };

    /**
     * Scores {@code report} in place and sets its verdict.
     *
     * <p>Idempotent: scoring twice gives the same answer. The set-level pass rescores any package
     * whose lookalike finding arrived late, and without clearing what a previous pass derived, every
     * combination finding was added and counted a second time.
     */
    public static void score(ScanReport report, IocDatabase database) {
        IocDatabase db = database == null ? IocDatabase.empty() : database;
        removeDerivedSignals(report);

        IocDatabase.Record denied = db.deniedRecord(report.contentHash, report.manifest.pluginId);
        if (denied != null) {
            report.add(new Signal("PRV001", Category.PROVENANCE, Severity.CRITICAL,
                    "Matches an entry in your denylist",
                    "You, or a list you imported, previously marked this exact package or plugin id as bad.")
                    .withEvidence("denylist", denied.value
                            + (denied.note.length() > 0 ? " - " + denied.note : "")));
        }

        Set<String> excused = excuseExpectedCapabilities(report);
        applyCombinationEscalations(report);

        int total = 0;
        Set<String> counted = new HashSet<String>();
        for (Signal signal : report.signals) {
            if (excused.contains(signal.ruleId)) {
                continue;
            }
            // Each rule counts once. Evidence is what grows with repetition, not the score: a plugin
            // that declares twenty entry points is not twenty times as dangerous as one that
            // declares one, and adding them up rated an ordinary text-editor helper as malicious.
            if (!counted.add(signal.ruleId)) {
                continue;
            }
            total += signal.severity.weight();
        }
        report.setScore(total);
        report.setVerdict(decide(report, db, denied != null, excused), reasonFor(report, excused));
    }

    /**
     * Downgrades findings that a plugin of this kind is expected to trigger.
     *
     * <p>Only ever applied to LOW findings, and never when the package also does something the trait
     * cannot explain: a translation engine is excused for opening a connection, not for reading
     * {@code /data/data} while it does so.
     */
    private static Set<String> excuseExpectedCapabilities(ScanReport report) {
        Set<String> excused = new HashSet<String>();
        boolean handlesPrivateData = report.categories().contains(Category.SENSITIVE_DATA)
                || report.categories().contains(Category.DYNAMIC_CODE)
                || report.categories().contains(Category.COMMAND_EXEC);

        if (report.traits.contains("translation-engine") && !handlesPrivateData) {
            for (Signal signal : report.signals) {
                if (signal.severity == Severity.LOW && signal.category == Category.NETWORK) {
                    excused.add(signal.ruleId);
                }
            }
            if (!excused.isEmpty()) {
                report.add(new Signal("CTX001", Category.PROVENANCE, Severity.INFO,
                        "Network access is expected for this plugin",
                        "This plugin registers a translation engine, which cannot work without reaching a"
                                + " translation service, so ordinary network use is not counted against it."));
            }
        }
        return excused;
    }

    /** Adds findings for combinations that only become visible across the whole package. */
    private static void applyCombinationEscalations(ScanReport report) {
        Set<Category> categories = report.categories();

        if (categories.contains(Category.SENSITIVE_DATA) && categories.contains(Category.NETWORK)) {
            report.add(new Signal("CMB101", Category.SENSITIVE_DATA, Severity.CRITICAL,
                    "Reads private data and has a way to send it out",
                    "The package both reaches for data that is not its own and talks to the network. That is"
                            + " the shape of data theft, whatever the individual files look like."));
        }
        if (categories.contains(Category.DYNAMIC_CODE) && categories.contains(Category.NETWORK)
                && !report.hasRule("CMB002")) {
            report.add(new Signal("CMB102", Category.DYNAMIC_CODE, Severity.CRITICAL,
                    "Can fetch and run code chosen after installation",
                    "Network access plus a class loader means what you reviewed is not necessarily what will"
                            + " run."));
        }
        if (categories.contains(Category.COMMAND_EXEC) && categories.contains(Category.NETWORK)
                && !report.hasRule("CMB003")) {
            report.add(new Signal("CMB103", Category.COMMAND_EXEC, Severity.CRITICAL,
                    "Can run commands and take instructions from the network",
                    "Process execution combined with network access is remote control."));
        }
        if (categories.contains(Category.RECON) && categories.contains(Category.NETWORK)) {
            report.add(new Signal("CMB105", Category.RECON, Severity.CRITICAL,
                    "Captures what you do and can send it out",
                    "Clipboard, screen, camera or location capture together with network access is"
                            + " surveillance."));
        }
        if (categories.contains(Category.CROSS_PLUGIN) && categories.contains(Category.NETWORK)) {
            report.add(new Signal("CMB106", Category.CROSS_PLUGIN, Severity.HIGH,
                    "Reaches into MT Manager's files and has network access",
                    "A plugin that reads MT Manager's own data and can reach the network can take whatever"
                            + " it finds there off the device."));
        }
        if (categories.contains(Category.DESTRUCTIVE) && categories.contains(Category.OBFUSCATION)) {
            report.add(new Signal("CMB104", Category.DESTRUCTIVE, Severity.HIGH,
                    "Destructive behaviour that has been hidden",
                    "Bulk deletion or encryption combined with concealment. Nothing legitimate needs to hide"
                            + " that it deletes your files."));
        }

        int breadth = 0;
        for (Category category : categories) {
            if (category == Category.MANIFEST || category == Category.PROVENANCE
                    || category == Category.ARCHIVE) {
                continue;
            }
            if (worstIn(report, category).atLeast(Severity.MEDIUM)) {
                breadth++;
            }
        }
        if (breadth >= 4) {
            report.add(new Signal("CMB107", Category.PROVENANCE, Severity.HIGH,
                    "Does far more than a plugin needs to",
                    "Capabilities across " + breadth + " unrelated areas. Even if every one had an"
                            + " explanation, the combination does not belong in a file-manager plugin."));
        }
    }

    /** Drops the signals a previous scoring pass added, so this one starts from the detected set. */
    private static void removeDerivedSignals(ScanReport report) {
        java.util.Iterator<Signal> it = report.signals.iterator();
        while (it.hasNext()) {
            String ruleId = it.next().ruleId;
            for (int i = 0; i < DERIVED_RULES.length; i++) {
                if (DERIVED_RULES[i].equals(ruleId)) {
                    it.remove();
                    break;
                }
            }
        }
    }

    private static Severity worstIn(ScanReport report, Category category) {
        Severity worst = Severity.INFO;
        for (Signal signal : report.signals) {
            if (signal.category == category && signal.severity.atLeast(worst)) {
                worst = signal.severity;
            }
        }
        return worst;
    }

    private static Verdict decide(ScanReport report, IocDatabase db, boolean denylisted, Set<String> excused) {
        if (denylisted) {
            return Verdict.KNOWN_BAD;
        }
        boolean critical = false;
        for (Signal signal : report.signals) {
            if (signal.severity == Severity.CRITICAL && !excused.contains(signal.ruleId)) {
                critical = true;
                break;
            }
        }
        if (db.isTrusted(report.contentHash) && !critical) {
            return Verdict.TRUSTED;
        }
        if (critical) {
            return Verdict.LIKELY_MALICIOUS;
        }
        int score = report.score();
        if (score >= Severity.CRITICAL.weight()) {
            return Verdict.LIKELY_MALICIOUS;
        }
        if (score >= Severity.HIGH.weight()) {
            return Verdict.SUSPICIOUS;
        }
        if (score >= Severity.MEDIUM.weight()) {
            return Verdict.REVIEW;
        }
        return Verdict.CLEAN;
    }

    /** One sentence explaining the verdict, which is what the user actually reads. */
    private static String reasonFor(ScanReport report, Set<String> excused) {
        Signal worst = null;
        for (Signal signal : report.signals) {
            if (excused.contains(signal.ruleId)) {
                continue;
            }
            if (worst == null || signal.severity.atLeast(worst.severity)) {
                if (worst == null || signal.severity.ordinal() > worst.severity.ordinal()) {
                    worst = signal;
                }
            }
        }
        if (worst == null || worst.severity == Severity.INFO) {
            return "Nothing of concern was found in this package.";
        }
        int others = report.countAtLeast(Severity.MEDIUM) - 1;
        String suffix = others > 0 ? " Plus " + others + " other finding" + (others == 1 ? "" : "s") + "." : "";
        return worst.title + "." + suffix;
    }
}
