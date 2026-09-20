package mt.safety.scanner.core;

import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks on {@code manifest.json}: is this a well-formed plugin, and is it honest about what it is.
 *
 * <p>Metadata is the first thing a user sees in MT Manager's plugin list and the cheapest thing for
 * an attacker to fake, so it gets its own rules: a package whose declared entry points do not exist,
 * or whose name is engineered to read as something it is not.
 */
public final class ManifestRules {

    /** MT Manager documents plugin ids as letters, numbers, underscores and dots. */
    private static final Pattern LEGAL_ID = Pattern.compile("^[A-Za-z0-9_.]+$");

    /** Characters that change how text renders without being visible themselves. */
    private static final Pattern INVISIBLE =
            Pattern.compile("[\\u202A-\\u202E\\u2066-\\u2069\\u200B-\\u200F\\u2060\\uFEFF\\u00AD]");

    /** Claims of official provenance, in the languages MT Manager's audience actually uses. */
    private static final Pattern OFFICIAL_CLAIM = Pattern.compile(
            "\\b(?<!un)official\\b|\\bverified\\b|\u5b98\u65b9|\u6b63\u7248|\u8ba4\u8bc1|\u5b98\u7f51",
            Pattern.CASE_INSENSITIVE);

    private ManifestRules() {
    }

    /** Runs every manifest rule, adding findings to {@code report}. */
    public static void apply(ScanReport report, PluginManifest manifest, PluginPackage pkg,
            List<PluginPackage.Entry> entries, ScanBudget budget) {
        if (!manifest.present) {
            report.add(new Signal("MFT001", Category.MANIFEST, Severity.HIGH,
                    "No manifest.json",
                    "Every MT plugin must contain manifest.json. This package is either not a plugin or has"
                            + " been repacked."));
            return;
        }
        if (manifest.unreadable) {
            report.add(new Signal("MFT012", Category.MANIFEST, Severity.LOW,
                    "manifest.json was not read",
                    "The manifest is present but the scanner could not read it, so nothing below is"
                            + " based on what this plugin declares about itself. This is a limit of the"
                            + " scan, not a finding against the package.")
                    .withEvidence("manifest.json", String.valueOf(manifest.parseError)));
            return;
        }
        if (!manifest.usable()) {
            report.add(new Signal("MFT002", Category.MANIFEST, Severity.HIGH,
                    "manifest.json is not valid JSON",
                    "MT Manager may still accept a manifest a reviewer's tools cannot read, which is a way"
                            + " to hide what a plugin declares.")
                    .withEvidence("manifest.json", String.valueOf(manifest.parseError)));
            return;
        }

        if (manifest.nonStandardJson) {
            // Same rule id, because it is the same observation; a different weight, because what it
            // means is different. MT Manager's own parser accepts comments and unquoted keys, and
            // every field is present, so this is a note about tooling, not concealment.
            report.add(new Signal("MFT002", Category.MANIFEST, Severity.LOW,
                    "manifest.json is not standard JSON",
                    "The manifest uses comments, unquoted keys or trailing commas. MT Manager accepts"
                            + " that; strict JSON tools will not, so review it with MT Manager or by eye.")
                    .withEvidence("manifest.json", String.valueOf(manifest.parseError)));
        }

        if (manifest.pluginId == null || manifest.pluginId.length() == 0) {
            report.add(new Signal("MFT003", Category.MANIFEST, Severity.MEDIUM,
                    "No pluginID declared",
                    "A plugin without an id cannot be told apart from another, which defeats update and"
                            + " removal by id."));
        } else if (!LEGAL_ID.matcher(manifest.pluginId).matches()) {
            report.add(new Signal("MFT004", Category.MANIFEST, Severity.MEDIUM,
                    "pluginID contains unexpected characters",
                    "MT Manager documents ids as letters, numbers, underscores and dots. Anything else is"
                            + " either a mistake or an attempt to confuse tooling.")
                    .withEvidence("manifest.json", "pluginID = " + manifest.pluginId));
        }

        if (manifest.sdkVersion != 2 && manifest.sdkVersion != 3) {
            report.add(new Signal("MFT005", Category.MANIFEST, Severity.LOW,
                    "Unrecognised pluginSdkVersion",
                    "Known plugin SDK versions are 2 and 3. An unknown value may simply be newer than this"
                            + " scanner.")
                    .withEvidence("manifest.json", "pluginSdkVersion = " + manifest.sdkVersion));
        }

        checkDeclaredClasses(report, manifest, pkg, entries, budget);
        checkMetadataText(report, manifest);
    }

    /** The dex descriptor of the API type every translation plugin implements. */
    private static final String TRANSLATION_ENGINE_DESCRIPTOR =
            "Lbin/mt/plugin/api/translation/TranslationEngine;";

    /**
     * Verifies that every declared entry point actually exists in the package.
     *
     * <p>A mismatch cuts both ways: a class named but absent means the package was repacked, and code
     * present but declared nowhere means a reviewer reading only the manifest never looks at it.
     *
     * <p>For a compiled plugin the check is exact rather than guessed: the class is looked up as a
     * descriptor in the dex string table. Guessing from file names was the single largest source of
     * noise on a real device, where every v3 plugin was reported as missing every class it declared,
     * because a dex has no file per class. And when MT Manager keeps the compiled code outside the
     * package it installs, as it does, the absence is MT Manager's layout and not the plugin's doing,
     * so nothing is reported beyond a note that the code was not in view.
     */
    private static void checkDeclaredClasses(ScanReport report, PluginManifest manifest, PluginPackage pkg,
            List<PluginPackage.Entry> entries, ScanBudget budget) {
        boolean hasSource = false;
        boolean hasJar = false;
        java.util.Set<String> dexStrings = new java.util.HashSet<String>();
        int dexFiles = 0;
        for (PluginPackage.Entry entry : entries) {
            if (entry.directory) {
                continue;
            }
            String ext = entry.extension();
            if (ext.equals("java")) {
                hasSource = true;
            } else if (ext.equals("jar")) {
                hasJar = true;
            } else if (ext.equals("dex") && dexFiles < 8) {
                dexFiles++;
                try {
                    byte[] data = pkg.read(entry, PluginPackage.MAX_MEMBER_BYTES, budget);
                    dexStrings.addAll(Bytes.dexStrings(data, 200000, 512));
                } catch (java.io.IOException e) {
                    report.addError("could not read " + entry.name + ": " + e.getMessage());
                }
            }
        }
        boolean compiled = manifest.dexMode;
        boolean codeInView = hasSource || dexFiles > 0 || hasJar;

        List<String> missing = new java.util.ArrayList<String>();
        List<String> unverifiable = new java.util.ArrayList<String>();
        for (String className : manifest.declaredClasses()) {
            if (className == null || className.length() == 0) {
                continue;
            }
            if (className.endsWith("TranslationEngine")) {
                // MT Manager's own plugins and every third-party translator name the class this way,
                // and the trait is what excuses a translator for talking to the network.
                report.traits.add("translation-engine");
            }
            if (classPresent(className, entries)) {
                continue;
            }
            if (dexFiles > 0 && dexStrings.contains("L" + className.replace('.', '/') + ";")) {
                continue;
            }
            if (compiled && dexFiles == 0) {
                // Nothing to check against: MT Manager installs a v3 plugin's dex beside the
                // package rather than inside it. Not a finding.
                continue;
            }
            if (dexFiles == 0 && hasJar && !hasSource) {
                unverifiable.add(className);
                continue;
            }
            missing.add(className);
        }
        if (dexStrings.contains(TRANSLATION_ENGINE_DESCRIPTOR)) {
            report.traits.add("translation-engine");
        }

        if (!missing.isEmpty()) {
            // One finding with every class as evidence. Twenty-three separate findings for a plugin
            // with twenty-three entry points added up to a "likely malicious" score out of nothing.
            Signal signal = new Signal("MFT006", Category.MANIFEST, Severity.MEDIUM,
                    "Declared classes not found in the package",
                    "The manifest registers entry points whose code is not present. The package may have"
                            + " been repacked after review.");
            for (int i = 0; i < missing.size(); i++) {
                signal.withEvidence("manifest.json", missing.get(i));
            }
            report.add(signal);
        }
        if (!unverifiable.isEmpty()) {
            Signal signal = new Signal("MFT006", Category.MANIFEST, Severity.LOW,
                    "Declared classes could not be located",
                    "The entry points may live inside a bundled jar, which this check does not open."
                            + " Worth a look if nothing else explains them.");
            for (int i = 0; i < unverifiable.size(); i++) {
                signal.withEvidence("manifest.json", unverifiable.get(i));
            }
            report.add(signal);
        }
        if (compiled && dexFiles == 0 && !manifest.declaredClasses().isEmpty()) {
            report.add(new Signal("MFT013", Category.MANIFEST, Severity.INFO,
                    "Compiled code is kept outside the package",
                    "This is a compiled (v3) plugin, and MT Manager keeps its code beside the installed"
                            + " package rather than inside it. The code was not in view of this scan, so"
                            + " findings here rest on the manifest and assets."));
        }

        if (manifest.declaredClasses().isEmpty() && codeInView) {
            report.add(new Signal("MFT007", Category.MANIFEST, Severity.MEDIUM,
                    "Ships code but declares no entry point",
                    "The manifest registers no interfaces and no settings screen, yet the package contains"
                            + " code. Undeclared code is code nobody reviews."));
        }
    }

    /** True when a declared class name maps onto a member of the package. */
    private static boolean classPresent(String className, List<PluginPackage.Entry> entries) {
        String asPath = className.replace('.', '/');
        String simpleName = className;
        int lastDot = className.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < className.length() - 1) {
            simpleName = className.substring(lastDot + 1);
        }
        for (PluginPackage.Entry entry : entries) {
            if (entry.directory) {
                continue;
            }
            String name = entry.name;
            if (name.endsWith(asPath + ".java") || name.endsWith(asPath + ".class")) {
                return true;
            }
            // A plugin may keep sources flat, without mirroring its package in directories.
            if (name.endsWith("/" + simpleName + ".java") || name.equals(simpleName + ".java")) {
                return true;
            }
        }
        return false;
    }

    /** Looks for metadata engineered to mislead the person reading MT Manager's plugin list. */
    private static void checkMetadataText(ScanReport report, PluginManifest manifest) {
        String name = manifest.name == null ? "" : manifest.name;
        String description = manifest.description == null ? "" : manifest.description;
        String id = manifest.pluginId == null ? "" : manifest.pluginId;

        Matcher invisible = INVISIBLE.matcher(name + "\u0000" + description + "\u0000" + id);
        if (invisible.find()) {
            report.add(new Signal("MFT009", Category.MANIFEST, Severity.HIGH,
                    "Invisible characters in the plugin's name or id",
                    "Zero-width or direction-changing characters make the name shown in MT Manager differ"
                            + " from the real one. Their only purpose is to mislead you.")
                    .withEvidence("manifest.json", "at offset " + invisible.start()));
        }

        if (OFFICIAL_CLAIM.matcher(name).find() || OFFICIAL_CLAIM.matcher(description).find()) {
            report.add(new Signal("MFT008", Category.MANIFEST, Severity.MEDIUM,
                    "Claims to be official or verified",
                    "MT Manager does not certify plugins. Treat a claim of official status as marketing at"
                            + " best, and check where you got the file.")
                    .withEvidence("manifest.json", firstLine(name + " / " + description)));
        }

        if (description.length() > 4000 || countLines(description) > 60) {
            report.add(new Signal("MFT010", Category.MANIFEST, Severity.LOW,
                    "Unusually long description",
                    "A very long description can push meaningful text out of view in the plugin list.")
                    .withEvidence("manifest.json", "description is " + description.length() + " characters"));
        }
    }

    /**
     * Flags two installed plugins whose identities are confusingly close.
     *
     * <p>Rather than shipping a list of "known good" ids, which would go stale and could be wrong, the
     * scanner compares the packages actually present: a near-duplicate of a plugin you already have is
     * a strong signal on its own.
     */
    public static void applyLookalikeCheck(List<ScanReport> reports) {
        for (int i = 0; i < reports.size(); i++) {
            for (int j = i + 1; j < reports.size(); j++) {
                ScanReport a = reports.get(i);
                ScanReport b = reports.get(j);
                if (!a.manifest.usable() || !b.manifest.usable()) {
                    continue;
                }
                // Only installed plugins are compared. A downloaded .mtp sitting beside the copy
                // installed from it shares its identity by definition, and calling that impersonation
                // would flag the most ordinary situation there is.
                if (!a.installed || !b.installed) {
                    continue;
                }
                String idA = a.manifest.pluginId;
                String idB = b.manifest.pluginId;
                // The resolved display name, never the raw field: an unresolved {key} placeholder is
                // the same literal string in every plugin that uses one, and comparing those reported
                // every such plugin as a lookalike of every other. displayName falls back to the id
                // when a name has not resolved, so a real difference still shows.
                String nameA = a.manifest.namePlaceholder() ? "" : a.manifest.displayName();
                String nameB = b.manifest.namePlaceholder() ? "" : b.manifest.displayName();
                boolean idLookalike = confusable(idA, idB);
                boolean nameLookalike = confusable(nameA, nameB);
                if (!idLookalike && !nameLookalike) {
                    continue;
                }
                boolean identical = (idA != null && idA.equals(idB)) || (nameA != null && nameA.equals(nameB));
                String detail = identical
                        ? "Two installed plugins claim the same identity. One is a copy of the other, or"
                                + " an impersonation; keep only the one you can trace to its author."
                        : "Two installed plugins have near-identical identities. One of them may be"
                                + " impersonating the other; keep the one you can trace to its author.";
                a.add(new Signal("MFT011", Category.PROVENANCE, Severity.HIGH,
                        "Nearly identical to another installed plugin", detail)
                        .withEvidence(a.label, describe(a) + "  vs  " + describe(b)));
                b.add(new Signal("MFT011", Category.PROVENANCE, Severity.HIGH,
                        "Nearly identical to another installed plugin", detail)
                        .withEvidence(b.label, describe(b) + "  vs  " + describe(a)));
            }
        }
    }

    private static String describe(ScanReport report) {
        return report.manifest.displayName() + " [" + report.manifest.pluginId + "]";
    }

    /** True when two identities differ only in ways a human eye slides over. */
    public static boolean confusable(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        String x = normalise(a);
        String y = normalise(b);
        if (x.length() < 4 || y.length() < 4) {
            return false;
        }
        if (x.equals(y)) {
            // Same identity after folding decoration. Two packages claiming one identity is worth
            // reporting whether or not the raw strings differ: a byte-identical id is a straight
            // clone, which is the strongest form of this, not a reason to stay quiet.
            return true;
        }
        return editDistance(x, y) == 1;
    }

    /** Folds away the decorations used to make two names look alike: case, separators, homoglyphs. */
    private static String normalise(String value) {
        String lower = value.toLowerCase(Locale.US);
        StringBuilder out = new StringBuilder(lower.length());
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            switch (c) {
                case '0':
                    out.append('o');
                    break;
                case '1':
                case '|':
                    out.append('l');
                    break;
                case '5':
                    out.append('s');
                    break;
                case '\u0430':
                    out.append('a');
                    break;
                case '\u0435':
                    out.append('e');
                    break;
                case '\u043e':
                    out.append('o');
                    break;
                case '\u0440':
                    out.append('p');
                    break;
                case '\u0441':
                    out.append('c');
                    break;
                case '-':
                case '_':
                case '.':
                case ' ':
                    break;
                default:
                    out.append(c);
            }
        }
        return out.toString();
    }

    /** Levenshtein distance, capped early because only distance 1 matters here. */
    public static int editDistance(String a, String b) {
        if (Math.abs(a.length() - b.length()) > 1) {
            return 2;
        }
        int[] previous = new int[b.length() + 1];
        int[] current = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                current[j] = Math.min(Math.min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
            }
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        return previous[b.length()];
    }

    private static String firstLine(String value) {
        int newline = value.indexOf('\n');
        String line = newline < 0 ? value : value.substring(0, newline);
        return line.length() > 120 ? line.substring(0, 117) + "..." : line;
    }

    private static int countLines(String value) {
        int lines = 1;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '\n') {
                lines++;
            }
        }
        return lines;
    }
}
