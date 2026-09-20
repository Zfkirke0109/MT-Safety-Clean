package mt.safety.scanner.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import mt.safety.scanner.core.Indicator.Scope;

/**
 * The indicator catalogue.
 *
 * <p>Two facts about MT plugins shape every entry here. First, a v2 plugin ships readable Java
 * sources in {@code src/}, so most detection is done on source text rather than on compiled code.
 * Second, a plugin's code runs inside MT Manager's own process, so it inherits MT Manager's storage
 * and network access: the documented "plugins only affect MT Manager" boundary is a statement of
 * intent, not something the runtime enforces. That is exactly why a plugin reading
 * {@code /data/data} or opening a socket is worth telling the user about.
 *
 * <p>Regexes match both source spelling ({@code Runtime.getRuntime}) and the form that survives in a
 * compiled constant pool ({@code Ljava/lang/Runtime;}), so the same catalogue works on a {@code .jar}
 * under {@code libs/} and on a v3 package's {@code classes.dex}.
 *
 * <p>Scopes are not decoration. A first run against a real device rated all 31 installed plugins,
 * including MT Manager's own, as suspicious or worse, and most of that came from API names matched
 * in data files: a syntax highlighter's keyword list, an XMP namespace in an icon, a config comment.
 * Indicators that name an API are scoped to {@link Scope#CODE}; only indicators about data itself,
 * such as endpoints, private paths and shell commands, apply to every member.
 */
public final class CodePatterns {

    private static final List<Indicator> INDICATORS = new ArrayList<Indicator>();
    private static final List<PairIndicator> PAIRS = new ArrayList<PairIndicator>();

    private CodePatterns() {
    }

    public static List<Indicator> indicators() {
        return Collections.unmodifiableList(INDICATORS);
    }

    public static List<PairIndicator> pairs() {
        return Collections.unmodifiableList(PAIRS);
    }

    private static void add(String id, Category category, Severity severity, String title, String detail,
            String regex, Scope scope) {
        INDICATORS.add(new Indicator(id, category, severity, title, detail, regex, scope));
    }

    private static void add(String id, Category category, Severity severity, String title, String detail,
            String regex, Scope scope, String notPrecededBy) {
        INDICATORS.add(new Indicator(id, category, severity, title, detail, regex, scope, notPrecededBy));
    }

    private static void pair(String id, Category category, Severity severity, String title, String detail,
            String first, String second, Scope scope) {
        PAIRS.add(new PairIndicator(id, category, severity, title, detail, first, second, scope));
    }

    static {
        // ---------------------------------------------------------- shell and root

        add("EXE001", Category.COMMAND_EXEC, Severity.HIGH,
                "Runs operating system commands",
                "The plugin starts external processes. A plugin that only extends MT Manager's own"
                        + " features has no reason to shell out.",
                "Runtime\\s*\\.\\s*getRuntime\\s*\\(\\s*\\)|java[/.]lang[/.]Runtime|new\\s+ProcessBuilder|java[/.]lang[/.]ProcessBuilder",
                Scope.CODE);

        add("EXE002", Category.COMMAND_EXEC, Severity.HIGH,
                "Asks for root privileges",
                "References the su binary or a root manager. With root, anything the plugin does is"
                        + " unrestricted by Android's app sandbox.",
                "\"su\"|'su'|/system/x?bin/su\\b|\\bsu\\s+-c\\b|\\bsu\\s+root\\b|magisk|supersu|superuser\\.apk",
                Scope.ANY);

        add("EXE003", Category.COMMAND_EXEC, Severity.HIGH,
                "Drives the Android package manager",
                "Installs, removes or re-permissions apps from the command line.",
                "\\bpm\\s+(install|uninstall|disable|enable|grant|revoke)\\b|\\bcmd\\s+package\\b|\\bam\\s+start\\b",
                Scope.ANY);

        add("EXE004", Category.COMMAND_EXEC, Severity.MEDIUM,
                "Changes file permissions or mounts",
                "Alters permissions or remounts filesystems, usually to make a protected area writable.",
                "\\bchmod\\s+(-R\\s+)?([0-7]{3,4}|[ugoa]*[+\\-=][rwxst]+)\\s+\\S*/|\\bchown\\s+(-R\\s+)?[\\w.\\-]+(:[\\w.\\-]+)?\\s+\\S*/"
                        + "|\\bmount\\s+-o\\s*(rw,)?remount\\b|\\bremount,rw\\b",
                Scope.ANY);

        add("EXE005", Category.COMMAND_EXEC, Severity.MEDIUM,
                "Reads or sets system properties",
                "Uses setprop/getprop or service controls, which are system administration, not plugin work.",
                "\\bsetprop\\s|\\bgetprop\\s|\\bsvc\\s+(wifi|data|usb|power)\\b",
                Scope.ANY);

        // ------------------------------------------------- loading code from outside

        add("DYN001", Category.DYNAMIC_CODE, Severity.HIGH,
                "Loads code that is not in this package",
                "Uses a class loader to run code from a file or download. Anything reviewed here can be"
                        + " replaced at runtime by code nobody has seen.",
                "DexClassLoader|InMemoryDexClassLoader|PathClassLoader|BaseDexClassLoader|URLClassLoader|defineClass\\s*\\(|dalvik[/.]system[/.]Dex",
                Scope.CODE);

        add("DYN002", Category.DYNAMIC_CODE, Severity.HIGH,
                "Loads a native library",
                "MT plugins are Java only. Loading a .so means native code the scanner cannot read.",
                "System\\s*\\.\\s*load(Library)?\\s*\\(|\\.so\"|lib[a-z0-9_]+\\.so",
                Scope.CODE);

        add("DYN003", Category.DYNAMIC_CODE, Severity.MEDIUM,
                "Uses reflection",
                "Reflection is common in plugins, but it is also how code reaches APIs it was not given.",
                "Class\\s*\\.\\s*forName|getDeclaredMethod|getDeclaredField|setAccessible\\s*\\(\\s*true|getMethod\\s*\\(",
                Scope.CODE);

        add("DYN004", Category.DYNAMIC_CODE, Severity.HIGH,
                "Reaches for MT Manager's application context",
                "The plugin API deliberately hands out no Android Context. Obtaining one gives the plugin"
                        + " MT Manager's full app identity and permissions.",
                "ActivityThread|currentApplication|AppGlobals|getApplicationContext\\s*\\(|android[/.]app[/.]ActivityThread",
                Scope.CODE);

        add("DYN005", Category.DYNAMIC_CODE, Severity.HIGH,
                "Compiles or evaluates code on the fly",
                "Ships a compiler or script engine, so its real behaviour is decided at runtime.",
                "javax[/.]script|ScriptEngine(Manager)?|dexmaker|javassist|com[/.]android[/.]dx\\b|bsh[/.]Interpreter"
                        + "|BeanShell|org[/.]luaj[/.]vm2|org[/.]mozilla[/.]javascript|groovy[/.]lang[/.]GroovyShell",
                Scope.CODE);

        // ------------------------------------------------------------------ network

        add("NET001", Category.NETWORK, Severity.LOW,
                "Makes network requests",
                "Expected for a translation engine or an update check; listed so you know it talks to the"
                        + " network at all.",
                "HttpURLConnection|HttpsURLConnection|openConnection\\s*\\(|okhttp3|retrofit2|java[/.]net[/.]Socket|DatagramSocket|SSLSocket",
                Scope.CODE);

        add("NET002", Category.NETWORK, Severity.MEDIUM,
                "Contacts a hardcoded IP address",
                "Real services are reached by hostname. A bare address, whether in a URL or handed"
                        + " straight to a socket, is typical of a private collection server.",
                "https?://(\\d{1,3}\\.){3}\\d{1,3}"
                        + "|\"(?!127\\.0\\.0\\.1|0\\.0\\.0\\.0|255\\.255)(\\d{1,3}\\.){3}\\d{1,3}(:\\d{2,5})?\"",
                Scope.ANY);

        add("NET003", Category.NETWORK, Severity.HIGH,
                "Sends data to an anonymous drop or bot endpoint",
                "These endpoints exist to receive data without an identifiable owner. They are how stolen"
                        + " data usually leaves a device.",
                "api\\.telegram\\.org/bot|discord(app)?\\.com/api/webhooks|webhook\\.site|requestbin|pipedream\\.net"
                        + "|pastebin\\.com/(api|raw)|hastebin|paste\\.ee|dpaste|termbin\\.com|transfer\\.sh"
                        + "|anonfiles|gofile\\.io|file\\.io|0x0\\.st|bashupload|oshi\\.at|catbox\\.moe",
                Scope.ANY);

        add("NET004", Category.NETWORK, Severity.MEDIUM,
                "Uses a tunnel, dynamic DNS or shortened address",
                "Hides where the traffic actually goes, and lets the operator move the server at will.",
                "ngrok\\.(io|app|dev)|trycloudflare\\.com|localtunnel|serveo\\.net|loclx\\.io"
                        + "|duckdns\\.org|no-ip\\.(org|com)|ddns\\.net|hopto\\.org|zapto\\.org|serveftp|freedns"
                        + "|bit\\.ly/|tinyurl\\.com/|is\\.gd/|t\\.cn/|cutt\\.ly/",
                Scope.ANY);

        add("NET005", Category.NETWORK, Severity.LOW,
                "Transfers over plain HTTP",
                "Unencrypted transport, so anything sent is readable on the network path.",
                "\"http://(?!localhost|127\\.0\\.0\\.1|(www\\.)?w3\\.org|schemas\\.|purl\\.org|ns\\.adobe\\.com|xml\\.|xmlns\\."
                        + "|java\\.sun\\.com|(www\\.)?apache\\.org|(www\\.)?iptc\\.org|xmlpull\\.org|creativecommons\\.org"
                        + "|(www\\.)?gnu\\.org|opensource\\.org|(www\\.)?ietf\\.org|json-schema\\.org|namespaces\\.|(www\\.)?eclipse\\.org)",
                Scope.ANY);

        add("NET006", Category.NETWORK, Severity.MEDIUM,
                "Uploads file bodies",
                "Builds multipart or raw file uploads, which is how bulk data is shipped off a device.",
                "multipart/form-data|Content-Disposition:\\s*form-data|application/octet-stream",
                Scope.CODE);

        // ------------------------------------------------------- private user data

        add("SEN001", Category.SENSITIVE_DATA, Severity.HIGH,
                "Reads app-private storage paths",
                "Paths under /data/data or /data/user hold other apps' private files, including MT"
                        + " Manager's own. A plugin has no business there.",
                "/data/data/|/data/user/\\d?/|/data/user_de/|getFilesDir\\s*\\(\\s*\\)\\s*\\.\\s*getParent",
                Scope.ANY);

        add("SEN002", Category.SENSITIVE_DATA, Severity.HIGH,
                "Looks for key, wallet or seed material",
                "Searches for the exact artefacts used to take over accounts and crypto wallets.",
                "seed\\s?phrase|private_key|privateKey|wallet\\.dat|\\.jks\\b|id_rsa|/\\.ssh/"
                        + "|BEGIN\\s+(RSA|DSA|EC|OPENSSH|PGP)?\\s*PRIVATE\\s+KEY|metamask|trustwallet",
                Scope.ANY);

        add("SEN003", Category.SENSITIVE_DATA, Severity.MEDIUM,
                "Handles stored credentials or session tokens",
                "A plugin needing its own API key is normal; reaching for saved passwords, cookies or"
                        + " session tokens is not.",
                "accounts\\.db|cookies?\\.(db|sqlite|txt)|getPrimaryClip|saved[_ ]?password|stored[_ ]?password"
                        + "|access[_ ]?token|refresh[_ ]?token|session[_ ]?id|authenticator|\\botp\\b|two[_ -]?factor",
                Scope.CODE);

        add("SEN004", Category.SENSITIVE_DATA, Severity.HIGH,
                "Reads other applications' data folders",
                "Targets messaging and social app storage, which holds private conversations and media.",
                "/WhatsApp/|com\\.whatsapp|/Telegram/|org\\.telegram|MicroMsg|com\\.tencent\\.mm|/Signal/"
                        + "|com\\.instagram|jp\\.naver\\.line|com\\.kakao|com\\.viber|com\\.discord",
                Scope.ANY);

        add("SEN005", Category.SENSITIVE_DATA, Severity.MEDIUM,
                "Reads contacts, messages or call history",
                "Personal data with no connection to editing files or translating text.",
                "content://sms|content://call_log|content://mms|ContactsContract|content://com\\.android\\.contacts"
                        + "|READ_SMS|READ_CONTACTS|READ_CALL_LOG",
                Scope.CODE);

        add("SEN006", Category.SENSITIVE_DATA, Severity.LOW,
                "Walks shared media folders",
                "Ordinary for a file tool, worth noting only if the plugin also sends data out.",
                "/DCIM|/Pictures/|/Documents/|/Download/|MediaStore",
                Scope.CODE);

        // ------------------------------------------------------------- identifiers

        add("IDN001", Category.DEVICE_IDENTITY, Severity.MEDIUM,
                "Collects device identifiers",
                "Builds a durable fingerprint of the device or SIM, used to track a victim across installs.",
                "getDeviceId|getImei\\b|getSubscriberId|getSimSerialNumber|ANDROID_ID|android_id|getSerial\\b"
                        + "|getMacAddress|getLine1Number|Build\\.SERIAL",
                Scope.CODE);

        add("IDN002", Category.DEVICE_IDENTITY, Severity.LOW,
                "Enumerates installed applications",
                "Inventories what else is on the device.",
                "getInstalledPackages|getInstalledApplications|queryIntentActivities",
                Scope.CODE);

        // ------------------------------------------- MT Manager and other plugins

        add("XPL001", Category.CROSS_PLUGIN, Severity.HIGH,
                "Reads or writes MT Manager's own files",
                "Hardcodes a path into MT Manager's private storage. That reaches MT's settings,"
                        + " licence state and every other installed plugin. (A class merely named under"
                        + " bin.mt.plugin is not this: that is the namespace plugin authors use.)",
                "/data/(data|user/\\d+|user_de/\\d+)/bin\\.mt\\.plus|Android/(data|obb)/bin\\.mt\\.plus"
                        + "|bin\\.mt\\.plus/(files|shared_prefs|databases|cache)",
                Scope.ANY);

        add("XPL002", Category.CROSS_PLUGIN, Severity.HIGH,
                "Escapes its own plugin directory",
                "Walks up out of the directory MT Manager gave it, which is where other plugins live.",
                "getParentFile\\s*\\(\\s*\\)\\s*\\.\\s*getParentFile|\"\\.\\./|/\\.\\./|getFilesDir\\s*\\(\\s*\\)\\s*\\.\\s*getParentFile",
                Scope.SOURCE);

        // ------------------------------------------------------------ destructive

        add("DES001", Category.DESTRUCTIVE, Severity.HIGH,
                "Deletes files in bulk",
                "Recursive deletion. In a plugin you did not ask to clean anything, this is a wiper.",
                "\\brm\\s+-rf?\\b|deleteRecursive|deleteDirectory|FileUtils\\.deleteQuietly|walkFileTree",
                Scope.ANY);

        add("DES002", Category.DESTRUCTIVE, Severity.CRITICAL,
                "Contains extortion text",
                "Ransom wording. There is no benign reason for this in a file-manager plugin.",
                "your\\s+files\\s+(have\\s+been|are)\\s+encrypted|ransom|decryption\\s+key|pay\\s+\\d+\\s*(btc|usdt|eth)"
                        + "|bitcoin\\s+address|send\\s+\\d+\\s*(btc|usdt)",
                Scope.ANY);

        add("DES003", Category.DESTRUCTIVE, Severity.MEDIUM,
                "Overwrites file contents in place",
                "Rewrites or truncates existing files rather than creating new ones.",
                "RandomAccessFile|setLength\\s*\\(\\s*0\\s*\\)|FileChannel\\s*\\.\\s*truncate",
                Scope.CODE);

        // ----------------------------------------------------------- obfuscation

        add("OBF001", Category.OBFUSCATION, Severity.MEDIUM,
                "Decrypts or unscrambles strings at runtime",
                "Hides what the code actually references. Legitimate plugins rarely need to.",
                "Cipher\\s*\\.\\s*getInstance|SecretKeySpec|IvParameterSpec|javax[/.]crypto|\"AES/|\"DES/"
                        + "|\\^\\s*0x[0-9a-f]{1,2}|\\^\\s*\\d+\\s*\\)\\s*;",
                Scope.CODE);

        add("OBF002", Category.OBFUSCATION, Severity.MEDIUM,
                "Embeds a long encoded blob",
                "A large Base64 or hex blob in source is usually a payload rather than data.",
                "[A-Za-z0-9+/]{512,}={0,2}|(\\\\u00[0-9a-f]{2}){12,}|(0x[0-9a-f]{2}\\s*,\\s*){24,}",
                Scope.ANY,
                // An inline data: URI is an embedded image or font, not a hidden payload. Minified
                // libraries carry dozens, and reporting them made a Markdown previewer look packed.
                ";base64,\\s*$");

        add("OBF003", Category.OBFUSCATION, Severity.HIGH,
                "Uses bidirectional or invisible Unicode in source",
                "Characters that make the code a reviewer reads differ from the code that runs"
                        + " (a Trojan Source trick).",
                "[\\u202A-\\u202E\\u2066-\\u2069\\u200B-\\u200F\\u2060\\uFEFF]",
                Scope.SOURCE);

        add("OBF004", Category.OBFUSCATION, Severity.LOW,
                "Decodes Base64 at runtime",
                "Common and usually harmless; only interesting next to a large embedded blob.",
                "Base64\\s*\\.\\s*(decode|getDecoder)|android[/.]util[/.]Base64",
                Scope.CODE);

        // -------------------------------------------------------------- evasion

        add("EVA001", Category.EVASION, Severity.MEDIUM,
                "Checks whether it is being analysed",
                "Looks for an emulator, debugger or root, typically to behave differently while watched.",
                "ro\\.kernel\\.qemu|generic_x86|goldfish|ranchu|isDebuggerConnected|android[/.]os[/.]Debug"
                        + "|Build\\.FINGERPRINT|/proc/self/status|TracerPid",
                Scope.CODE);

        add("EVA002", Category.EVASION, Severity.MEDIUM,
                "Defers its work on a long timer",
                "Long sleeps and schedulers delay behaviour past the moment you would be watching.",
                "Thread\\s*\\.\\s*sleep\\s*\\(\\s*\\d{5,}|AlarmManager|ScheduledExecutorService|postDelayed\\s*\\(\\s*[^,]{0,40},\\s*\\d{5,}",
                Scope.CODE);

        // ----------------------------------------------------------- persistence

        add("PER001", Category.PERSISTENCE, Severity.MEDIUM,
                "Names installable or executable files",
                "Mentions apk, dex, mtp or so files. Meaningful when the plugin also writes files.",
                "\\.apk\\b|\\.dex\\b|\\.mtp\\b|\\.so\\b|\\.jar\\b",
                Scope.SOURCE);

        add("PER002", Category.PERSISTENCE, Severity.HIGH,
                "Triggers an application install",
                "Hands Android a package to install, which is how a plugin becomes a permanent app.",
                "application/vnd\\.android\\.package-archive|ACTION_INSTALL_PACKAGE|REQUEST_INSTALL_PACKAGES",
                Scope.CODE);

        // ---------------------------------------------------------------- recon

        add("REC001", Category.RECON, Severity.HIGH,
                "Reads the clipboard",
                "The clipboard is where passwords, recovery phrases and one-time codes pass through.",
                "ClipboardManager|getPrimaryClip|ClipData\\s*\\.",
                Scope.CODE);

        add("REC002", Category.RECON, Severity.HIGH,
                "Captures the screen",
                "Screen capture records whatever you are looking at, including other apps.",
                "MediaProjection|createVirtualDisplay|takeScreenshot|\\bscreencap\\b",
                Scope.CODE);

        add("REC003", Category.RECON, Severity.HIGH,
                "Uses accessibility automation",
                "Accessibility APIs can read and tap any screen. This is the standard route for Android"
                        + " banking fraud.",
                "AccessibilityService|AccessibilityNodeInfo|performGlobalAction|dispatchGesture",
                Scope.CODE);

        add("REC004", Category.RECON, Severity.MEDIUM,
                "Uses the microphone or camera",
                "Audio or image capture from a plugin that should only touch files.",
                "MediaRecorder|AudioRecord|CameraManager|android[/.]hardware[/.]Camera|takePicture",
                Scope.CODE);

        add("REC005", Category.RECON, Severity.MEDIUM,
                "Reads device location",
                "Location has no role in editing files.",
                "LocationManager|getLastKnownLocation|FusedLocationProvider|requestLocationUpdates",
                Scope.CODE);

        // --------------------------------------------- combinations within a file

        pair("CMB001", Category.PERSISTENCE, Severity.HIGH,
                "Writes an installable or executable file",
                "The same file both opens an output stream and names an apk, dex, mtp or so file: it drops"
                        + " a payload onto storage.",
                "FileOutputStream|BufferedOutputStream|RandomAccessFile|\\.write\\s*\\(",
                "\\.apk\"|\\.dex\"|\\.mtp\"|\\.so\"|\\.jar\"",
                Scope.CODE);

        pair("CMB002", Category.DYNAMIC_CODE, Severity.CRITICAL,
                "Downloads code and loads it",
                "Network access and a class loader in one file. Whatever this plugin does today, its"
                        + " operator can change tomorrow.",
                "HttpURLConnection|openConnection\\s*\\(|okhttp3|java[/.]net[/.]Socket",
                "DexClassLoader|InMemoryDexClassLoader|PathClassLoader|URLClassLoader|defineClass\\s*\\(",
                Scope.CODE);

        pair("CMB003", Category.COMMAND_EXEC, Severity.CRITICAL,
                "Runs shell commands on instructions from the network",
                "Process execution and network access in one file, the shape of a remote control channel.",
                "Runtime\\s*\\.\\s*getRuntime|ProcessBuilder",
                "HttpURLConnection|openConnection\\s*\\(|java[/.]net[/.]Socket|okhttp3",
                Scope.CODE);

        pair("CMB004", Category.DESTRUCTIVE, Severity.CRITICAL,
                "Encrypts files and then deletes the originals",
                "Encryption together with bulk deletion in one file is the ransomware pattern.",
                "Cipher\\s*\\.\\s*getInstance|SecretKeySpec|javax[/.]crypto",
                "\\brm\\s+-rf?\\b|deleteRecursive|deleteDirectory|\\.delete\\s*\\(\\s*\\)",
                Scope.CODE);

        pair("CMB005", Category.OBFUSCATION, Severity.HIGH,
                "Decodes a hidden blob and runs or loads it",
                "Decoding feeding straight into execution or class loading hides the real payload from"
                        + " review.",
                "Base64\\s*\\.\\s*decode|base64Decode|Cipher\\s*\\.\\s*getInstance",
                "DexClassLoader|defineClass\\s*\\(|Runtime\\s*\\.\\s*getRuntime|ProcessBuilder|System\\s*\\.\\s*load",
                Scope.CODE);
    }
}
