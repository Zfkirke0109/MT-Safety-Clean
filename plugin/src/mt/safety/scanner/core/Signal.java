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
            this.where = where;
            this.snippet = snippet;
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
            evidence.add(new Evidence(where, trim(snippet)));
        }
        return this;
    }

    public List<Evidence> evidence() {
        return evidence;
    }

    /** Evidence lines are shown verbatim in the report, so they are bounded and single-line. */
    private static String trim(String snippet) {
        if (snippet == null) {
            return "";
        }
        String flat = snippet.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim();
        if (flat.length() > 160) {
            flat = flat.substring(0, 157) + "...";
        }
        return flat;
    }

    @Override
    public String toString() {
        return ruleId + " " + severity + " " + title;
    }
}
