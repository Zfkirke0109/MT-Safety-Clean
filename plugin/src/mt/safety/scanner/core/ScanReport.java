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
    public final boolean archive;
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

    public ScanReport(String label, String path, boolean archive, PluginManifest manifest, String contentHash) {
        this.label = label;
        this.path = path;
        this.archive = archive;
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

    public Verdict verdict() {
        return verdict;
    }

    public void setVerdict(Verdict verdict, String reason) {
        this.verdict = verdict;
        this.verdictReason = reason == null ? "" : reason;
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

    /** Short one-line summary used in list views. */
    public String headline() {
        return verdict.label() + " (" + score + ") - " + manifest.displayName();
    }
}
