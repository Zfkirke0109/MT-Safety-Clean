package mt.safety.scanner.core;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import mt.safety.scanner.core.Indicator.Scope;

/**
 * Applies the indicator catalogue to every readable member of a package.
 *
 * <p>Findings are collapsed per rule rather than per match, so a plugin that mentions {@code Runtime}
 * in twelve files produces one finding with twelve pieces of evidence. On a phone screen that is the
 * difference between a report and a wall of text.
 */
public final class CodeRules {

    /**
     * How a plugin declares itself a translation engine, which excuses ordinary network use.
     *
     * <p>Deliberately narrow: only a class declaration that extends or implements the engine type
     * counts, and only in a file the manifest names as an entry point. Matching the bare word anywhere
     * would let a plugin switch off its own network scoring with a comment.
     */
    private static final Pattern TRANSLATION_ENGINE = Pattern.compile(
            "(extends|implements)\\s+(Base)?TranslationEngine\\b");

    /** Long unbroken Base64 runs, the usual shape of an embedded payload. */
    private static final Pattern BASE64_BLOB = Pattern.compile("[A-Za-z0-9+/]{512,}={0,2}");

    /** How much of a single member is read, by kind. */
    private static final int SOURCE_LIMIT = 1024 * 1024;
    private static final int BINARY_LIMIT = 4 * 1024 * 1024;

    private static final Set<String> SKIP_EXTENSIONS = new HashSet<String>();
    private static final Set<String> SOURCE_EXTENSIONS = new HashSet<String>();
    private static final Set<String> TEXT_EXTENSIONS = new HashSet<String>();

    static {
        SKIP_EXTENSIONS.add("png");
        SKIP_EXTENSIONS.add("jpg");
        SKIP_EXTENSIONS.add("jpeg");
        SKIP_EXTENSIONS.add("webp");
        SKIP_EXTENSIONS.add("gif");
        SKIP_EXTENSIONS.add("bmp");
        SKIP_EXTENSIONS.add("ttf");
        SKIP_EXTENSIONS.add("otf");
        SKIP_EXTENSIONS.add("woff");
        SKIP_EXTENSIONS.add("woff2");
        SKIP_EXTENSIONS.add("mp3");
        SKIP_EXTENSIONS.add("mp4");
        SKIP_EXTENSIONS.add("ogg");
        SKIP_EXTENSIONS.add("wav");

        SOURCE_EXTENSIONS.add("java");
        SOURCE_EXTENSIONS.add("kt");

        TEXT_EXTENSIONS.add("json");
        TEXT_EXTENSIONS.add("txt");
        TEXT_EXTENSIONS.add("xml");
        TEXT_EXTENSIONS.add("properties");
        TEXT_EXTENSIONS.add("lang");
        TEXT_EXTENSIONS.add("md");
        TEXT_EXTENSIONS.add("cfg");
        TEXT_EXTENSIONS.add("ini");
        TEXT_EXTENSIONS.add("csv");
        TEXT_EXTENSIONS.add("js");
        TEXT_EXTENSIONS.add("html");
        TEXT_EXTENSIONS.add("sh");
        TEXT_EXTENSIONS.add("py");
        TEXT_EXTENSIONS.add("yaml");
        TEXT_EXTENSIONS.add("yml");
    }

    private CodeRules() {
    }

    /** Scans members and records findings; returns the number of members actually read. */
    public static int apply(ScanReport report, PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget, IocDatabase database) {
        Map<String, Signal> byRule = new HashMap<String, Signal>();
        int scanned = 0;

        for (PluginPackage.Entry entry : entries) {
            if (entry.directory) {
                continue;
            }
            if (budget.exhausted()) {
                budget.markTruncated();
                break;
            }
            String ext = entry.extension();
            if (SKIP_EXTENSIONS.contains(ext) && reallyIsMedia(pkg, entry, budget)) {
                continue;
            }
            Scope scope = classify(ext);
            int limit = scope == Scope.SOURCE ? SOURCE_LIMIT : BINARY_LIMIT;

            byte[] data;
            try {
                data = pkg.read(entry, limit, budget);
            } catch (IOException e) {
                report.addError("could not read " + entry.name + ": " + e.getMessage());
                continue;
            }
            if (data.length == 0) {
                continue;
            }
            scanned++;

            String text = scope == Scope.BINARY ? Bytes.extractedText(data, 6) : Bytes.text(data);
            if (scope == Scope.SOURCE && isDeclaredEntryPoint(entry.name, report)
                    && TRANSLATION_ENGINE.matcher(text).find()) {
                report.traits.add("translation-engine");
            }
            matchIndicators(report, byRule, entry, scope, text);
            matchUserPatterns(report, byRule, entry, text, database);
            matchPairs(report, byRule, entry, scope, text);
            if (scope == Scope.SOURCE) {
                checkSourceShape(report, byRule, entry, text);
            }
            checkEncodedPayloads(report, byRule, entry, text);
        }
        return scanned;
    }

    /**
     * Applies the extra patterns the user added to their indicator file.
     *
     * <p>This is the escape hatch that keeps the scanner useful between releases: an endpoint or string
     * from an advisory can be added locally and is treated as a high-severity match.
     */
    private static void matchUserPatterns(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry entry, String text, IocDatabase database) {
        if (database == null) {
            return;
        }
        List<Pattern> userPatterns = database.patterns();
        for (int i = 0; i < userPatterns.size(); i++) {
            Matcher matcher = userPatterns.get(i).matcher(text);
            if (!matcher.find()) {
                continue;
            }
            Signal signal = signalFor(report, byRule, "USR001", Category.PROVENANCE, Severity.HIGH,
                    "Matches a pattern from your own indicator list",
                    "One of the patterns in your indicator file was found in this package.");
            signal.withEvidence(location(entry, text, matcher.start()),
                    database.patternSources().get(i) + " -> " + snippet(text, matcher.start(), matcher.end()));
        }
    }

    /**
     * True when a media member's bytes really are that media format.
     *
     * <p>Skipping images by file name alone would mean a payload renamed to {@code banner.png} was
     * never searched at all, so the skip is only granted once the magic bytes agree.
     */
    private static boolean reallyIsMedia(PluginPackage pkg, PluginPackage.Entry entry, ScanBudget budget) {
        try {
            byte[] head = pkg.read(entry, 32, budget);
            if (head.length < 4) {
                return true;
            }
            return Bytes.contentMatchesExtension(entry.extension(), head);
        } catch (IOException e) {
            return true;
        }
    }

    /** True when the manifest names this source file as an interface or the settings screen. */
    private static boolean isDeclaredEntryPoint(String memberName, ScanReport report) {
        java.util.List<String> declared = report.manifest.declaredClasses();
        for (int i = 0; i < declared.size(); i++) {
            String className = declared.get(i);
            if (className == null || className.length() == 0) {
                continue;
            }
            String asPath = className.replace('.', '/') + ".java";
            if (memberName.endsWith(asPath)) {
                return true;
            }
            int lastDot = className.lastIndexOf('.');
            String simple = lastDot >= 0 ? className.substring(lastDot + 1) : className;
            if (memberName.endsWith("/" + simple + ".java") || memberName.equals(simple + ".java")) {
                return true;
            }
        }
        return false;
    }

    private static Scope classify(String extension) {
        if (SOURCE_EXTENSIONS.contains(extension)) {
            return Scope.SOURCE;
        }
        if (TEXT_EXTENSIONS.contains(extension)) {
            return Scope.TEXT;
        }
        // Unknown and compiled members are searched for printable runs, which is safe either way.
        return Scope.BINARY;
    }

    private static void matchIndicators(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry entry, Scope scope, String text) {
        List<Indicator> indicators = CodePatterns.indicators();
        for (int i = 0; i < indicators.size(); i++) {
            Indicator indicator = indicators.get(i);
            if (!indicator.appliesTo(scope)) {
                continue;
            }
            Matcher matcher = indicator.pattern.matcher(text);
            if (!matcher.find()) {
                continue;
            }
            Signal signal = signalFor(report, byRule, indicator.ruleId, indicator.category,
                    indicator.severity, indicator.title, indicator.detail);
            signal.withEvidence(location(entry, text, matcher.start()), snippet(text, matcher.start(), matcher.end()));
        }
    }

    private static void matchPairs(ScanReport report, Map<String, Signal> byRule, PluginPackage.Entry entry,
            Scope scope, String text) {
        List<PairIndicator> pairs = CodePatterns.pairs();
        for (int i = 0; i < pairs.size(); i++) {
            PairIndicator pair = pairs.get(i);
            if (!pair.appliesTo(scope)) {
                continue;
            }
            Matcher firstMatch = pair.first.matcher(text);
            if (!firstMatch.find()) {
                continue;
            }
            Matcher secondMatch = pair.second.matcher(text);
            if (!secondMatch.find()) {
                continue;
            }
            Signal signal = signalFor(report, byRule, pair.ruleId, pair.category, pair.severity,
                    pair.title, pair.detail);
            signal.withEvidence(location(entry, text, firstMatch.start()),
                    snippet(text, firstMatch.start(), firstMatch.end()) + "  +  "
                            + snippet(text, secondMatch.start(), secondMatch.end()));
        }
    }

    /**
     * Heuristics on the shape of Java source rather than its contents.
     *
     * <p>A v2 plugin ships source precisely so it can be read. Source that has been mechanically
     * shortened or squeezed onto single lines has had that property removed on purpose.
     */
    private static void checkSourceShape(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry entry, String text) {
        int longestLine = 0;
        int lineStart = 0;
        for (int i = 0; i <= text.length(); i++) {
            if (i == text.length() || text.charAt(i) == '\n') {
                longestLine = Math.max(longestLine, i - lineStart);
                lineStart = i + 1;
            }
        }
        if (longestLine > 2000) {
            Signal signal = signalFor(report, byRule, "OBF007", Category.OBFUSCATION, Severity.MEDIUM,
                    "Source has been squeezed onto very long lines",
                    "MT plugins ship source so it can be read. Source formatted this way is not meant to be.");
            signal.withEvidence(entry.name, "longest line is " + longestLine + " characters");
        }

        // Only type declarations count. An earlier version also matched `int i`, which made every
        // ordinary for-loop look like obfuscation; obfuscators rename types, so that is what to look at.
        int singleLetterDeclarations = countMatches(text,
                Pattern.compile("\\b(class|interface|enum)\\s+[a-zA-Z]\\b"));
        if (singleLetterDeclarations >= 5) {
            Signal signal = signalFor(report, byRule, "OBF008", Category.OBFUSCATION, Severity.MEDIUM,
                    "Identifiers look machine-shortened",
                    "Many one-character class, method and field names, which is what an obfuscator leaves"
                            + " behind. Unusual in source a plugin ships for review.");
            signal.withEvidence(entry.name, singleLetterDeclarations + " single-letter declarations");
        }
    }

    /**
     * Decodes long embedded Base64 and looks at what comes out.
     *
     * <p>This is where an "empty-looking" plugin gives itself away: the source reads harmlessly and the
     * payload sits in a string constant. Decoding one level is enough to see an archive header, Dalvik
     * bytecode, or a drop endpoint.
     */
    private static void checkEncodedPayloads(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry entry, String text) {
        Matcher matcher = BASE64_BLOB.matcher(text);
        int examined = 0;
        while (matcher.find() && examined < 4) {
            examined++;
            byte[] decoded = Bytes.base64Decode(matcher.group());
            if (decoded == null || decoded.length < 64) {
                continue;
            }
            String kind = null;
            if (Bytes.looksLikeZip(decoded)) {
                kind = "a zip, apk or mtp archive";
            } else if (Bytes.looksLikeDex(decoded)) {
                kind = "Dalvik bytecode";
            } else if (Bytes.looksLikeElf(decoded)) {
                kind = "a native executable";
            } else if (decoded.length > 4 && decoded[0] == (byte) 0xCA && decoded[1] == (byte) 0xFE) {
                kind = "a Java class file";
            }
            if (kind != null) {
                Signal signal = signalFor(report, byRule, "OBF005", Category.OBFUSCATION, Severity.CRITICAL,
                        "An encoded blob in the source decodes to executable code",
                        "The package hides code inside a text constant. This is how a plugin passes review"
                                + " looking harmless and then runs something else.");
                signal.withEvidence(location(entry, text, matcher.start()),
                        Bytes.humanSize(decoded.length) + " of " + kind);
                continue;
            }

            // Not code, but the decoded text may still name where data is being sent.
            String decodedText = Bytes.text(decoded);
            List<Indicator> indicators = CodePatterns.indicators();
            for (int i = 0; i < indicators.size(); i++) {
                Indicator indicator = indicators.get(i);
                if (!indicator.severity.atLeast(Severity.MEDIUM)) {
                    continue;
                }
                Matcher inner = indicator.pattern.matcher(decodedText);
                if (inner.find()) {
                    Signal signal = signalFor(report, byRule, "OBF006", Category.OBFUSCATION, Severity.HIGH,
                            "An encoded blob hides a risky reference",
                            "Something the plugin would rather a reader did not see is stored encoded"
                                    + " instead of in plain text.");
                    signal.withEvidence(location(entry, text, matcher.start()),
                            indicator.ruleId + " inside decoded data: "
                                    + snippet(decodedText, inner.start(), inner.end()));
                    break;
                }
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Returns the existing finding for a rule, or registers a new one. */
    private static Signal signalFor(ScanReport report, Map<String, Signal> byRule, String ruleId,
            Category category, Severity severity, String title, String detail) {
        Signal existing = byRule.get(ruleId);
        if (existing != null) {
            return existing;
        }
        Signal created = new Signal(ruleId, category, severity, title, detail);
        byRule.put(ruleId, created);
        report.add(created);
        return created;
    }

    /** "src/Foo.java:42" for source, plain member name otherwise. */
    private static String location(PluginPackage.Entry entry, String text, int offset) {
        String ext = entry.extension();
        if (!SOURCE_EXTENSIONS.contains(ext) && !TEXT_EXTENSIONS.contains(ext)) {
            return entry.name;
        }
        int line = 1;
        int limit = Math.min(offset, text.length());
        for (int i = 0; i < limit; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return entry.name + ":" + line;
    }

    /** A short, single-line excerpt centred on the match. */
    private static String snippet(String text, int start, int end) {
        int from = Math.max(0, start - 24);
        int to = Math.min(text.length(), Math.max(end + 32, start + 48));
        String raw = text.substring(from, to);
        return raw.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim();
    }

    private static int countMatches(String text, Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find() && count < 1000) {
            count++;
        }
        return count;
    }
}
