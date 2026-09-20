package mt.safety.scanner.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

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

    /** Bounds on looking inside an archived member such as a jar under libs/. */
    private static final int NESTED_MEMBER_LIMIT = 512 * 1024;
    private static final int MAX_NESTED_ENTRIES = 400;
    private static final int MAX_NESTED_DEPTH = 2;

    private static final Set<String> SOURCE_EXTENSIONS = new HashSet<String>();
    private static final Set<String> TEXT_EXTENSIONS = new HashSet<String>();

    static {
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

    /**
     * Scans members and records findings; returns the number of members actually read.
     *
     * <p>No member is exempt on the strength of its name or its first few bytes. An earlier version
     * skipped anything with a media extension whose magic bytes matched, which sounds safe and is not:
     * image decoders tolerate trailing junk, so a genuine PNG header followed by an appended payload
     * satisfied the check and then bypassed every indicator, user pattern and encoded-payload rule.
     * Reading an ordinary icon costs a fraction of the byte allowance; letting one carry a payload
     * costs the whole point of the scan. Binary members are searched for printable runs rather than
     * decoded whole, so real image data contributes nothing to match against.
     *
     * <p>The cost is real for a package that ships large media: those members now draw on the same
     * byte allowance as everything else, and a package big enough to exhaust it is reported as
     * truncated. That is the intended degradation. A scan that admits it did not finish is useful; one
     * that reports Clean because it agreed not to look is not.
     */
    public static int apply(ScanReport report, PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget, IocDatabase database) {
        Map<String, Signal> byRule = new HashMap<String, Signal>();
        int scanned = 0;

        for (PluginPackage.Entry entry : entries) {
            if (entry.directory) {
                continue;
            }
            // The manifest is metadata, judged by ManifestRules on what it declares. Searching its
            // text for indicators reported a plugin for naming its own classes under bin.mt.plugin
            // and for the dexMode flag every v3 package carries.
            if (entry.name.equals("manifest.json")) {
                continue;
            }
            if (budget.exhausted()) {
                budget.markTruncated();
                break;
            }
            String ext = entry.extension();
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
            if (entry.size > limit) {
                // Only the first part of this member was read, so a finding could be sitting past the
                // cap. The report says the scan was incomplete rather than implying full coverage.
                budget.markTruncated();
            }
            scanned++;

            // A jar's members are deflated, so searching the container's raw bytes finds nothing at
            // all. libs/ is the documented home for third-party jars, which makes it the obvious
            // place to hide a payload: it has to be opened, not just skimmed.
            if (Bytes.looksLikeZip(data)) {
                scanNestedArchive(report, byRule, entry.name, data, budget, database, 1);
            }

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
     * Opens an archived member and applies the same rules to what is inside it.
     *
     * <p>Bounded in every direction: entry count, bytes per entry, nesting depth, and the scan budget,
     * because the archive being opened is the untrusted thing under examination.
     *
     * <p>Evidence keeps the path that leads to it, {@code libs/helper.jar!evil/Evil.class}, so a
     * finding can be traced back to the file it actually came from.
     */
    private static void scanNestedArchive(ScanReport report, Map<String, Signal> byRule, String parentName,
            byte[] data, ScanBudget budget, IocDatabase database, int depth) {
        if (depth > MAX_NESTED_DEPTH) {
            return;
        }
        Signal executableInside = null;
        ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(data));
        try {
            ZipEntry ze;
            int count = 0;
            while ((ze = zin.getNextEntry()) != null) {
                if (count++ >= MAX_NESTED_ENTRIES || budget.exhausted()) {
                    budget.markTruncated();
                    break;
                }
                if (ze.isDirectory()) {
                    continue;
                }
                int granted = budget.reserve(NESTED_MEMBER_LIMIT);
                if (granted <= 0) {
                    budget.markTruncated();
                    break;
                }
                byte[] child;
                try {
                    child = Bytes.readAtMost(zin, granted);
                } catch (IOException e) {
                    report.addError("could not read " + parentName + "!" + ze.getName() + ": "
                            + e.getMessage());
                    continue;
                }
                if (child.length == 0) {
                    continue;
                }

                String childName = parentName + "!" + ze.getName();
                PluginPackage.Entry synthetic =
                        new PluginPackage.Entry(childName, child.length, child.length, false);

                // Dalvik bytecode or a native library inside a library archive is not a library.
                String kind = Bytes.detectKind(child);
                if ("dex".equals(kind) || "elf".equals(kind)) {
                    if (executableInside == null) {
                        executableInside = signalFor(report, byRule, "ARC009", Category.PERSISTENCE,
                                Severity.HIGH,
                                "An archived library contains executable code",
                                "A jar under libs/ is expected to hold Java classes. Dalvik bytecode or a"
                                        + " native binary inside one is a payload travelling in a wrapper.");
                    }
                    executableInside.withEvidence(childName, kind + ", " + Bytes.humanSize(child.length));
                }

                Scope childScope = classify(synthetic.extension());
                String childText = childScope == Scope.BINARY
                        ? Bytes.extractedText(child, 6) : Bytes.text(child);
                matchIndicators(report, byRule, synthetic, childScope, childText);
                matchPairs(report, byRule, synthetic, childScope, childText);
                matchUserPatterns(report, byRule, synthetic, childText, database);
                checkEncodedPayloads(report, byRule, synthetic, childText);

                if (Bytes.looksLikeZip(child)) {
                    scanNestedArchive(report, byRule, childName, child, budget, database, depth + 1);
                }
            }
        } catch (IOException e) {
            report.addError("could not open " + parentName + ": " + e.getMessage());
        } catch (RuntimeException e) {
            // A malformed archive must not take the scan down with it.
            report.addError("could not read inside " + parentName + ": " + e);
        } finally {
            PluginPackage.closeQuietly(zin);
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
