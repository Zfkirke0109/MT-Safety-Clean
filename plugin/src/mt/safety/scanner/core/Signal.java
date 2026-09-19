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
        // Every control character goes, not just the line breaks. This text is quoted from the package
        // under examination and ends up on a terminal through the command line report, where an escape
        // sequence could recolour or rewrite what the user is reading about the thing that produced it.
        // That includes the C1 range: a lone U+009B is CSI to a terminal, doing the same job as ESC [
        // without needing an ESC to be filtered out first.
        StringBuilder sb = new StringBuilder(snippet.length());
        for (int i = 0; i < snippet.length(); i++) {
            char c = snippet.charAt(i);
            boolean control = c < 0x20 || (c >= 0x7F && c <= 0x9F);
            sb.append(control ? ' ' : c);
        }
        String flat = sb.toString().trim();
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
