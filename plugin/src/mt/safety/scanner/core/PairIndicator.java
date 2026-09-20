package mt.safety.scanner.core;

import java.util.regex.Pattern;

/**
 * An indicator that only fires when two patterns appear in the same member.
 *
 * <p>Some behaviour is only meaningful in combination but too far apart in the file for a single
 * regex to span without pathological backtracking. Writing a stream and naming an {@code .apk} is
 * one example: either alone is nothing, together they are a dropper.
 */
public final class PairIndicator {

    public final String ruleId;
    public final Category category;
    public final Severity severity;
    public final String title;
    public final String detail;
    public final Pattern first;
    public final Pattern second;
    public final Indicator.Scope scope;

    public PairIndicator(String ruleId, Category category, Severity severity, String title, String detail,
            String firstRegex, String secondRegex, Indicator.Scope scope) {
        this.ruleId = ruleId;
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.detail = detail;
        this.first = Pattern.compile(firstRegex, Pattern.CASE_INSENSITIVE);
        this.second = Pattern.compile(secondRegex, Pattern.CASE_INSENSITIVE);
        this.scope = scope;
    }

    public boolean appliesTo(Indicator.Scope memberScope) {
        if (scope == Indicator.Scope.ANY || scope == memberScope) {
            return true;
        }
        // CODE means "anywhere code can run", which is source and compiled members alike.
        return scope == Indicator.Scope.CODE
                && (memberScope == Indicator.Scope.SOURCE || memberScope == Indicator.Scope.BINARY);
    }
}
