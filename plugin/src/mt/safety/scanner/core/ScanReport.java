package mt.safety.scanner.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Everything the scanner concluded about one plugin package. */
public final class ScanReport {

    public final String label;
    public final String path;
    /** True when the package is a zip file rather than an unpacked directory. This is its format. */
    public final boolean archive;
    /**
     * True when this is a plugin MT Manager has installed, as opposed to a download sitting in a
     * folder. This is its standing, and it is what decides whether the scanner may act on it.
     *
     * <p>Kept apart from {@link #archive} because the two used to be conflated, and on a real device
     * every installed plugin is an archive: MT Manager keeps them as {@code <id>/plugin.mtp}. Gating
     * actions on "not an archive" hid every switch the user was looking for.
     */
    public final boolean installed;
    public final PluginManifest manifest;
    public final String contentHash;
    public final List<Signal> signals = new ArrayList<Signal>();
    public final List<String> errors = new ArrayList<String>();
    /**
     * What the package appears to be, e.g. {@code translation-engine}.
     *
     * <p>Scoring uses this to avoid punishing a plugin for a capability its whole purpose requires:
     * a translation engine must reach the network, so saying so would be noise rather than a finding.
     */
    public final Set<String> traits = new HashSet<String>();

    private Verdict verdict = Verdict.CLEAN;
    private int score;
    private boolean truncated;
    private int filesScanned;
    private long elapsedMs;
    private String verdictReason = "";
    private boolean destructiveActionIdentityComplete;
    private String actionIdentityPath = "";

    public ScanReport(String label, String path, boolean archive, boolean installed, PluginManifest manifest,
            String contentHash) {
        this.label = label;
        this.path = path;
        this.archive = archive;
        this.installed = installed;
        this.manifest = manifest;
        this.contentHash = contentHash;
    }

    public void add(Signal signal) {
        if (signal != null) {
            signals.add(signal);
        }
    }

    public void addError(String message) {
        if (message != null) {
            errors.add(message);
        }
    }

    /** Findings ordered worst first, which is the only order a phone screen should show them in. */
    public List<Signal> signalsBySeverity() {
        List<Signal> sorted = new ArrayList<Signal>(signals);
        Collections.sort(sorted, new Comparator<Signal>() {
            @Override
            public int compare(Signal a, Signal b) {
                int bySeverity = b.severity.ordinal() - a.severity.ordinal();
                if (bySeverity != 0) {
                    return bySeverity;
                }
                return a.ruleId.compareTo(b.ruleId);
            }
        });
        return sorted;
    }

    /** The distinct behaviour categories this package triggered. */
    public Set<Category> categories() {
        Set<Category> out = EnumSet.noneOf(Category.class);
        for (Signal signal : signals) {
            if (signal.severity.atLeast(Severity.LOW)) {
                out.add(signal.category);
            }
        }
        return out;
    }

    /** The worst severity present, or INFO when there are no findings. */
    public Severity worstSeverity() {
        Severity worst = Severity.INFO;
        for (Signal signal : signals) {
            if (signal.severity.atLeast(worst)) {
                worst = signal.severity;
            }
        }
        return worst;
    }

    public int countAtLeast(Severity floor) {
        int count = 0;
        for (Signal signal : signals) {
            if (signal.severity.atLeast(floor)) {
                count++;
            }
        }
        return count;
    }

    public boolean hasRule(String ruleId) {
        for (Signal signal : signals) {
            if (signal.ruleId.equals(ruleId)) {
                return true;
            }
        }
        return false;
    }

    /** True when the package produced any signal other than a coverage-only notice. */
    public boolean hasPackageFindings() {
        for (Signal signal : signals) {
            if (!isCoverageNotice(signal)) {
                return true;
            }
        }
        return false;
    }

    /** Coverage notices describe scan limits rather than findings against the package. */
    public static boolean isCoverageNotice(Signal signal) {
        return signal != null && ("SCN001".equals(signal.ruleId) || "MFT012".equals(signal.ruleId)
                || "MFT013".equals(signal.ruleId));
    }

    public Verdict verdict() {
        return verdict;
    }

    public void setVerdict(Verdict verdict, String reason) {
        this.verdict = verdict;
        this.verdictReason = reason == null ? "" : reason;
    }

    /** What was inspected. The legacy {@link #verdict()} says nothing about this. */
    public Coverage coverage() {
        if (verdict == Verdict.UNREADABLE) {
            return Coverage.UNSUPPORTED_OR_UNREADABLE;
        }
        if (truncated) {
            return Coverage.PARTIAL;
        }
        for (Signal signal : signals) {
            if (isCoverageNotice(signal)) {
                return Coverage.PARTIAL;
            }
        }
        return Coverage.COMPLETE;
    }

    /**
     * The verdict as it should be shown to a person. Identical to the legacy label when the scan was
     * complete; otherwise it never reads as an unqualified Clean or Trusted.
     */
    public String dispositionLabel() {
        if (coverage() != Coverage.PARTIAL) {
            return verdict.label();
        }
        if (verdict == Verdict.CLEAN) {
            return "Incomplete scan";
        }
        if (verdict == Verdict.TRUSTED) {
            return "Trusted identity (inspection incomplete)";
        }
        return verdict.label() + " (inspection incomplete)";
    }

    /** Advice matching {@link #dispositionLabel()}. */
    public String dispositionAdvice() {
        if (verdict == Verdict.CLEAN && hasPackageFindings()) {
            if (coverage() == Coverage.PARTIAL) {
                return "Package findings were observed; inspection incomplete. This is not an all-clear.";
            }
            return "No medium-or-higher risk was detected; review the lower-severity findings below.";
        }
        if (coverage() != Coverage.PARTIAL) {
            return verdict.advice();
        }
        if (verdict == Verdict.CLEAN) {
            return "No findings in inspected content; inspection incomplete. This is not an all-clear.";
        }
        if (verdict == Verdict.TRUSTED) {
            return "You marked this exact version as trusted, but the scan did not read all of it."
                    + " Inspection incomplete.";
        }
        return verdict.advice() + " The scan was incomplete, so there may be more.";
    }

    public String verdictReason() {
        return verdictReason;
    }

    public int score() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public boolean truncated() {
        return truncated;
    }

    public void setTruncated(boolean truncated) {
        this.truncated = truncated;
    }

    public int filesScanned() {
        return filesScanned;
    }

    public void setFilesScanned(int filesScanned) {
        this.filesScanned = filesScanned;
    }

    public long elapsedMs() {
        return elapsedMs;
    }

    public void setElapsedMs(long elapsedMs) {
        this.elapsedMs = elapsedMs;
    }

    /** True only when the package digest identifies every file a destructive action would affect. */
    public boolean destructiveActionIdentityComplete() {
        return destructiveActionIdentityComplete;
    }

    public String actionIdentityPath() {
        return actionIdentityPath;
    }

    public void setDestructiveActionIdentity(boolean complete, String canonicalPath) {
        destructiveActionIdentityComplete = complete && canonicalPath != null && canonicalPath.length() > 0;
        actionIdentityPath = destructiveActionIdentityComplete ? canonicalPath : "";
    }

    /** Short one-line summary used in list views. */
    public String headline() {
        return dispositionLabel() + " (" + score + ") - " + manifest.displayName();
    }
}
