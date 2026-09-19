package mt.safety.scanner.core;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Checks on the shape of the package rather than its code.
 *
 * <p>MT Manager's documented v2 layout is {@code manifest.json}, an optional {@code icon.png} or
 * {@code icon.jpg}, and the directories {@code src/}, {@code assets/} and {@code libs/}. Anything
 * outside that is worth a look, and a few shapes are hostile on their own: a member that writes
 * outside the extraction directory, a payload that only inflates once installed, two members with the
 * same name so that the file a reviewer reads is not the file that runs.
 */
public final class ArchiveRules {

    /** Inflated size beyond which an extreme compression ratio becomes a real problem. */
    private static final long BOMB_MIN_INFLATED = 64L * 1024 * 1024;
    private static final long BOMB_RATIO = 150L;

    /** Members large enough that near-random contents are worth reporting. */
    private static final int ENTROPY_MIN_BYTES = 64 * 1024;
    private static final double ENTROPY_THRESHOLD = 7.8;

    private static final Set<String> EXPECTED_TOP_LEVEL = new HashSet<String>();
    private static final Set<String> EXECUTABLE_EXTENSIONS = new HashSet<String>();

    static {
        EXPECTED_TOP_LEVEL.add("manifest.json");
        EXPECTED_TOP_LEVEL.add("icon.png");
        EXPECTED_TOP_LEVEL.add("icon.jpg");
        EXPECTED_TOP_LEVEL.add("src");
        EXPECTED_TOP_LEVEL.add("assets");
        EXPECTED_TOP_LEVEL.add("libs");

        EXECUTABLE_EXTENSIONS.add("apk");
        EXECUTABLE_EXTENSIONS.add("mtp");
        EXECUTABLE_EXTENSIONS.add("dex");
        EXECUTABLE_EXTENSIONS.add("so");
        EXECUTABLE_EXTENSIONS.add("elf");
        EXECUTABLE_EXTENSIONS.add("sh");
        EXECUTABLE_EXTENSIONS.add("bin");
    }

    private ArchiveRules() {
    }

    /** Runs every structural rule, adding findings to {@code report}. */
    public static void apply(ScanReport report, PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget) {
        checkPaths(report, entries);
        checkPayloads(report, pkg, entries, budget, report.manifest.sdkVersion == 3);
        checkCompressionRatio(report, entries);
        checkStructuralAnomalies(report, pkg, budget);
        checkEntropy(report, pkg, entries, budget);
    }

    /** Member names that would escape the directory they are extracted into. */
    private static void checkPaths(ScanReport report, List<PluginPackage.Entry> entries) {
        Signal traversal = null;
        Signal odd = null;
        for (PluginPackage.Entry entry : entries) {
            String name = entry.name;
            boolean escapes = name.startsWith("/") || name.startsWith("\\")
                    || name.contains("../") || name.contains("..\\")
                    || (name.length() > 1 && name.charAt(1) == ':');
            if (escapes) {
                if (traversal == null) {
                    traversal = new Signal("ARC001", Category.ARCHIVE, Severity.CRITICAL,
                            "A member is named so that it unpacks outside the plugin folder",
                            "Extracting this package could overwrite files elsewhere on the device, including"
                                    + " MT Manager's own. No legitimate plugin needs this.");
                    report.add(traversal);
                }
                traversal.withEvidence("archive", name);
                continue;
            }
            boolean unusual = name.contains("\\") || name.startsWith(".") || name.contains("/.")
                    || name.indexOf('\n') >= 0 || name.indexOf('\r') >= 0 || name.indexOf('\u0000') >= 0;
            if (unusual) {
                if (odd == null) {
                    odd = new Signal("ARC006", Category.ARCHIVE, Severity.LOW,
                            "Hidden or oddly named members",
                            "Dot-files and unusual separators are easy to miss when looking through a package"
                                    + " by hand.");
                    report.add(odd);
                }
                odd.withEvidence("archive", name);
            }
        }
    }

    /** Members that are themselves installable or executable, and members outside the known layout. */
    private static void checkPayloads(ScanReport report, PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget, boolean compiledExpected) {
        Signal payload = null;
        Signal unexpected = null;
        for (PluginPackage.Entry entry : entries) {
            if (entry.directory) {
                continue;
            }
            String ext = entry.extension();
            String top = entry.topLevel();

            // A plugin SDK v3 package is built by Gradle and carries compiled code rather than the
            // sources a v2 package ships, so Java bytecode is what it is supposed to contain. Native
            // libraries, installable packages and shell scripts stay reportable at any SDK version.
            if (compiledExpected && expectedCompiledOutput(entry, ext)) {
                continue;
            }
            if (EXECUTABLE_EXTENSIONS.contains(ext)) {
                if (payload == null) {
                    payload = new Signal("ARC003", Category.PERSISTENCE, Severity.HIGH,
                            "Carries an installable or executable file",
                            "A plugin is Java source plus resources. A bundled apk, dex, native library or"
                                    + " shell script is a payload waiting to be run.");
                    report.add(payload);
                }
                payload.withEvidence(entry.name, Bytes.humanSize(entry.size));
                continue;
            }

            // Content, not just the extension: a payload renamed to .png is the usual dodge.
            if (!budget.exhausted() && entry.size >= 512 && looksExecutable(pkg, entry, budget)) {
                if (payload == null) {
                    payload = new Signal("ARC003", Category.PERSISTENCE, Severity.HIGH,
                            "Carries an installable or executable file",
                            "A member's contents are an archive, Dalvik bytecode or a native binary,"
                                    + " whatever its file name says.");
                    report.add(payload);
                }
                payload.withEvidence(entry.name, "contents are not what the extension suggests");
                continue;
            }

            if (!EXPECTED_TOP_LEVEL.contains(top)) {
                if (unexpected == null) {
                    unexpected = new Signal("ARC002", Category.ARCHIVE, Severity.MEDIUM,
                            "Members outside MT Manager's plugin layout",
                            "A plugin package holds manifest.json, an optional icon, and src, assets and libs."
                                    + " Other content is not part of the documented format.");
                    report.add(unexpected);
                }
                unexpected.withEvidence(entry.name, Bytes.humanSize(entry.size));
            }
        }
    }

    /**
     * True for the compiled members a v3 package is expected to carry.
     *
     * <p>The exemption is about the normal build outputs, not about every member whose name happens to
     * end in {@code .dex} or {@code .jar}. An arbitrary {@code assets/payload.dex} is still a payload,
     * and a top-level {@code evil.jar} is still outside MT Manager's layout.
     */
    private static boolean expectedCompiledOutput(PluginPackage.Entry entry, String ext) {
        if (ext.equals("dex")) {
            return entry.name.equals("classes.dex")
                    || entry.name.matches("classes[0-9]+\\.dex");
        }
        return ext.equals("jar") && entry.name.startsWith("libs/");
    }

    /**
     * Reads a member's first bytes to see whether its contents match its name.
     *
     * <p>No extension is exempt. Exempting image extensions here would have meant that renaming a
     * payload to {@code banner.png} hid it from this rule entirely, which is precisely the dodge the
     * rule exists to catch. Whether a member is allowed to be an archive or a binary is decided from
     * its magic bytes against its declared type, in {@link Bytes#contentMatchesExtension}.
     */
    private static boolean looksExecutable(PluginPackage pkg, PluginPackage.Entry entry, ScanBudget budget) {
        try {
            byte[] head = pkg.read(entry, 512, budget);
            if (head.length < 4) {
                return false;
            }
            return !Bytes.contentMatchesExtension(entry.extension(), head);
        } catch (IOException e) {
            return false;
        }
    }

    /** A member that stays small on disk and only becomes huge once unpacked. */
    private static void checkCompressionRatio(ScanReport report, List<PluginPackage.Entry> entries) {
        for (PluginPackage.Entry entry : entries) {
            if (entry.directory || entry.compressedSize <= 0 || entry.size < BOMB_MIN_INFLATED) {
                continue;
            }
            long ratio = entry.size / Math.max(entry.compressedSize, 1L);
            if (ratio >= BOMB_RATIO) {
                report.add(new Signal("ARC004", Category.ARCHIVE, Severity.HIGH,
                        "A member expands enormously when unpacked",
                        "Unpacking this could fill the device's storage. It is a denial of service rather than"
                                + " a data theft, but it is not an accident at this ratio.")
                        .withEvidence(entry.name, Bytes.humanSize(entry.compressedSize) + " becomes "
                                + Bytes.humanSize(entry.size) + " (" + ratio + "x)"));
                return;
            }
        }
    }

    /** Disagreements between the archive's index and its contents. */
    private static void checkStructuralAnomalies(ScanReport report, PluginPackage pkg, ScanBudget budget) {
        try {
            List<String> problems = pkg.structuralAnomalies(budget);
            if (problems.isEmpty()) {
                return;
            }
            Signal signal = new Signal("ARC005", Category.ARCHIVE, Severity.HIGH,
                    "The package's contents could not be established",
                    "When an archive lists a member twice or lists one it does not contain, the file a"
                            + " reviewer inspects need not be the file that gets installed. When part of"
                            + " a folder could not be listed, the same is true of whatever was missed.");
            for (int i = 0; i < problems.size() && i < 8; i++) {
                signal.withEvidence("archive", problems.get(i));
            }
            report.add(signal);
        } catch (IOException e) {
            report.addError("could not re-read the package structure: " + e.getMessage());
        }
    }

    /** Large members whose contents look encrypted or packed rather than like data. */
    private static void checkEntropy(ScanReport report, PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget) {
        Signal signal = null;
        for (PluginPackage.Entry entry : entries) {
            if (entry.directory || entry.size < ENTROPY_MIN_BYTES || budget.exhausted()) {
                continue;
            }
            try {
                byte[] sample = pkg.read(entry, 128 * 1024, budget);
                if (sample.length < ENTROPY_MIN_BYTES) {
                    continue;
                }
                // Already-compressed formats are legitimately high entropy, but only when the contents
                // really are that format: the exemption follows the magic bytes, not the file name.
                String kind = Bytes.detectKind(sample);
                if (kind != null && Bytes.contentMatchesExtension(entry.extension(), sample)
                        && !kind.equals("dex") && !kind.equals("elf") && !kind.equals("class")) {
                    continue;
                }
                double entropy = Bytes.entropy(sample);
                if (entropy >= ENTROPY_THRESHOLD) {
                    if (signal == null) {
                        signal = new Signal("ARC007", Category.OBFUSCATION, Severity.MEDIUM,
                                "A large member looks encrypted or packed",
                                "Contents this random are not text, code or an image. Something in this package"
                                        + " is not meant to be read.");
                        report.add(signal);
                    }
                    signal.withEvidence(entry.name,
                            String.format("%.2f bits per byte over %s", entropy, Bytes.humanSize(entry.size)));
                }
            } catch (IOException e) {
                report.addError("could not read " + entry.name + ": " + e.getMessage());
            }
        }
    }
}
