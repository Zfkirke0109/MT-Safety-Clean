package mt.safety.scanner.core;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/** Redacts recognizable credential forms at display/export boundaries, without changing detection. */
final class ReportText {
    private static final Pattern TELEGRAM = Pattern.compile(
            "(?i)(https?://api\\.telegram\\.org/bot)[A-Za-z0-9:_-]+");
    private static final Pattern URL_PASSWORD = Pattern.compile(
            "(?i)(https?://)[^\\s/@:]+:[^\\s/@]+@");
    private static final Pattern AUTH = Pattern.compile("(?i)(\\b(?:Bearer|Basic)\\s+)[A-Za-z0-9._~+/=-]+");
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)\\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization)"
                    + "\\b\\s*+(?:[\"']\\s*+)?[:=]\\s*+");
    private static final Pattern OPENAI_KEY = Pattern.compile("\\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}");
    private static final Pattern AWS_KEY = Pattern.compile("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b");
    private static final Pattern JWT = Pattern.compile(
            "(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])");

    private ReportText() {
    }

    static String redact(String text) {
        if (text == null) {
            return "";
        }
        String safe = TELEGRAM.matcher(text).replaceAll("$1[REDACTED]");
        safe = URL_PASSWORD.matcher(safe).replaceAll("$1[REDACTED]@");
        // Redact the whole auth value before the more general key=value matcher sees its prefix.
        safe = AUTH.matcher(safe).replaceAll("$1[REDACTED]");
        safe = redactAssignments(safe);
        safe = OPENAI_KEY.matcher(safe).replaceAll("[REDACTED]");
        safe = AWS_KEY.matcher(safe).replaceAll("[REDACTED]");
        return JWT.matcher(safe).replaceAll("[REDACTED]");
    }

    private static String redactAssignments(String text) {
        Matcher matcher = ASSIGNMENT.matcher(text);
        StringBuilder safe = new StringBuilder(text.length());
        int copied = 0;
        while (matcher.find()) {
            int start = matcher.end();
            if (start == text.length()) {
                break;
            }
            safe.append(text, copied, start);
            char quote = text.charAt(start);
            int end = start;
            if (quote == '\'' || quote == '"') {
                end++;
                boolean escaped = false;
                while (end < text.length()) {
                    char c = text.charAt(end);
                    if (!escaped && c == quote) {
                        break;
                    }
                    if (!escaped && c == '\\') {
                        escaped = true;
                    } else {
                        escaped = false;
                    }
                    end++;
                }
                safe.append(quote).append("[REDACTED]");
                if (end < text.length()) {
                    safe.append(quote);
                    end++;
                }
            } else {
                while (end < text.length() && !Character.isWhitespace(text.charAt(end))
                        && "\"'&<>;,)}\\".indexOf(text.charAt(end)) < 0) {
                    end++;
                }
                safe.append("[REDACTED]");
            }
            copied = end;
            matcher.region(end, text.length());
        }
        safe.append(text, copied, text.length());
        return safe.toString();
    }

    static String bounded(String text, int limit) {
        String safe = redact(text);
        StringBuilder flat = new StringBuilder(Math.min(safe.length(), limit));
        for (int i = 0; i < safe.length() && flat.length() < limit; i++) {
            char c = safe.charAt(i);
            flat.append(c < 0x20 || (c >= 0x7f && c <= 0x9f) ? ' ' : c);
        }
        if (safe.length() > limit && limit >= 3) {
            flat.replace(limit - 3, limit, "...");
        }
        return flat.toString().trim();
    }
}
