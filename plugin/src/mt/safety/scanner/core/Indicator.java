package mt.safety.scanner.core;

import java.util.regex.Pattern;

/**
 * One pattern-based indicator.
 *
 * <p>An indicator says "this text appears in the package", never "this package is malware". The
 * verdict is {@link RiskScorer}'s job, because almost every individual indicator here has a
 * legitimate use: what condemns a plugin is the combination.
 */
public final class Indicator {

    /** Which member kinds an indicator is worth applying to. */
    public enum Scope {
        /** Java sources shipped in {@code src/}. */
        SOURCE,
        /** Strings pulled out of compiled artefacts under {@code libs/} and elsewhere. */
        BINARY,
        /** Plain text members such as assets and configuration. */
        TEXT,
        /**
         * Java sources and compiled artefacts: the members that can actually call an API.
         *
         * <p>Most indicators name Android or Java APIs, and an API name only means something where
         * code can invoke it. In a data file it is a word: a syntax highlighter's keyword table lists
         * {@code chmod} and {@code chown}, a config file's comment says "allow screenshot", a MIME
         * table names {@code package-archive}. Matching those as capabilities is how a Markdown
         * previewer came to be rated more dangerous than a root shell.
         */
        CODE,
        /** Every kind. */
        ANY
    }

    public final String ruleId;
    public final Category category;
    public final Severity severity;
    public final String title;
    public final String detail;
    public final Pattern pattern;
    public final Scope scope;

    public Indicator(String ruleId, Category category, Severity severity, String title, String detail,
            String regex, Scope scope) {
        this.ruleId = ruleId;
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.detail = detail;
        this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        this.scope = scope;
    }

    public boolean appliesTo(Scope memberScope) {
        if (scope == Scope.ANY || scope == memberScope) {
            return true;
        }
        return scope == Scope.CODE && (memberScope == Scope.SOURCE || memberScope == Scope.BINARY);
    }
}
