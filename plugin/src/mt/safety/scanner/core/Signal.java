package mt.safety.scanner.core;

import java.util.ArrayList;
import java.util.List;

/** One finding: a rule fired, why it fired, and where the evidence is. */
public final class Signal {

    /** A single piece of supporting evidence, kept short enough to show on a phone. */
    public static final class Evidence {
        public final String where;
        public final String snippet;

        public Evidence(String where, String snippet) {
            this.where = ReportText.bounded(where, 320);
            this.snippet = ReportText.bounded(snippet, 160);
        }

        @Override
        public String toString() {
            return where + ": " + snippet;
        }
    }

    public final String ruleId;
    public final Category category;
    public final Severity severity;
    public final String title;
    public final String detail;
    private final List<Evidence> evidence = new ArrayList<Evidence>();

    public Signal(String ruleId, Category category, Severity severity, String title, String detail) {
        this.ruleId = ruleId;
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.detail = detail;
    }

    public Signal withEvidence(String where, String snippet) {
        if (evidence.size() < 12) {
            evidence.add(new Evidence(where, snippet));
        }
        return this;
    }

    public List<Evidence> evidence() {
        return evidence;
    }

    @Override
    public String toString() {
        return ruleId + " " + severity + " " + title;
    }
}
