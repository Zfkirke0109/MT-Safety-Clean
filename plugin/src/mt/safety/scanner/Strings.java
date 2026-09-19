package mt.safety.scanner;

/**
 * User-facing text, in English and Chinese.
 *
 * <p>MT Manager's own localization works by resolving <code>{key}</code> placeholders from language
 * files in the package. This scanner does not use it, for one deliberate reason: any text the scanner
 * displays can contain a snippet taken from the package being examined, and a snippet of Java source
 * routinely contains braces. Feeding that through a placeholder resolver risks either mangled output or
 * a lookup driven by attacker-controlled text. So strings live here, no placeholder syntax is used, and
 * the view strips braces from anything quoted out of a scanned file.
 *
 * <p>Both languages are provided because MT Manager's users are largely Chinese-speaking. Rule titles
 * and evidence stay in English, since the rule catalogue is written there; that is a stated limitation
 * rather than an oversight.
 */
public final class Strings {

    private final boolean zh;

    private Strings(boolean zh) {
        this.zh = zh;
    }

    /** Picks a language from a two-letter code. */
    public static Strings forLanguage(String language) {
        return new Strings(language != null && language.toLowerCase(java.util.Locale.US).startsWith("zh"));
    }

    private String pick(String english, String chinese) {
        return zh ? chinese : english;
    }

    public String screenTitle() {
        return pick("Plugin safety scanner", "\u63d2\u4ef6\u5b89\u5168\u626b\u63cf");
    }

    public String screenSubtitle() {
        return pick("Checks the plugins installed in MT Manager",
                "\u68c0\u67e5 MT \u7ba1\u7406\u5668\u5df2\u5b89\u88c5\u7684\u63d2\u4ef6");
    }

    public String summaryHeader() {
        return pick("Result", "\u626b\u63cf\u7ed3\u679c");
    }

    public String lastAction() {
        return pick("Last action", "\u4e0a\u6b21\u64cd\u4f5c");
    }

    public String nothingFound() {
        return pick("No other plugins found", "\u672a\u53d1\u73b0\u5176\u4ed6\u63d2\u4ef6");
    }

    public String nothingFoundHelp() {
        return pick("Either nothing else is installed, or this plugin cannot read where they are kept."
                + " Add a folder with the root command below, then reopen this screen.",
                "\u53ef\u80fd\u672a\u5b89\u88c5\u5176\u4ed6\u63d2\u4ef6\uff0c\u6216\u672c\u63d2\u4ef6\u65e0\u6cd5"
                + "\u8bfb\u53d6\u5176\u5b58\u653e\u4f4d\u7f6e\u3002\u53ef\u7528\u4e0b\u65b9 root \u547d\u4ee4"
                + "\u6dfb\u52a0\u76ee\u5f55\u540e\u91cd\u65b0\u6253\u5f00\u672c\u9875\u3002");
    }

    public String scannedIn(String elapsed) {
        return pick("Scanned in " + elapsed + ". Reopen this screen to scan again.",
                "\u8017\u65f6 " + elapsed + "\u3002\u91cd\u65b0\u6253\u5f00\u672c\u9875\u53ef\u518d\u6b21\u626b\u63cf\u3002");
    }

    public String verdictLabel() {
        return pick("Verdict", "\u7ed3\u8bba");
    }

    public String versionLabel() {
        return pick("Version", "\u7248\u672c");
    }

    public String pathLabel() {
        return pick("Location", "\u8def\u5f84");
    }

    public String hashLabel() {
        return pick("SHA-256 (first 16)", "SHA-256 \u524d16\u4f4d");
    }

    public String moreFindings(int count) {
        return pick("... and " + count + " more findings, use export for the full report",
                "... \u5176\u4f59 " + count + " \u9879\uff0c\u8bf7\u7528 export \u5bfc\u51fa\u5b8c\u6574\u62a5\u544a");
    }

    public String incomplete() {
        return pick("The scan did not finish reading this package",
                "\u672a\u80fd\u5b8c\u6574\u8bfb\u53d6\u8be5\u63d2\u4ef6");
    }

    public String problem() {
        return pick("Problem", "\u95ee\u9898");
    }

    public String commandsHeader() {
        return pick("Actions", "\u64cd\u4f5c");
    }

    public String commandFieldTitle() {
        return pick("Command", "\u547d\u4ee4");
    }

    public String commandsHelpTitle() {
        return pick("Type a command above, then reopen this screen",
                "\u5728\u4e0a\u65b9\u8f93\u5165\u547d\u4ee4\uff0c\u7136\u540e\u91cd\u65b0\u6253\u5f00\u672c\u9875");
    }

    public String commandsHelp() {
        return pick("deep / fast - thorough or quick scanning."
                + "   export - write the full report to this plugin's folder."
                + "   trust HASH - accept a package by its SHA-256."
                + "   untrust HASH, deny HASH_OR_ID - undo, or mark as bad."
                + "   quarantine ID - move an installed plugin aside, reversibly."
                + "   restore ID, purge ID, quarantined - manage what was moved."
                + "   root PATH - also search a folder.",
                "deep / fast - \u6df1\u5ea6\u6216\u5feb\u901f\u626b\u63cf\u3002"
                + "   export - \u5bfc\u51fa\u5b8c\u6574\u62a5\u544a\u5230\u672c\u63d2\u4ef6\u76ee\u5f55\u3002"
                + "   trust HASH - \u6309 SHA-256 \u6807\u8bb0\u4e3a\u53ef\u4fe1\u3002"
                + "   untrust HASH\u3001deny HASH_OR_ID - \u6492\u9500\u6216\u6807\u8bb0\u4e3a\u6076\u610f\u3002"
                + "   quarantine ID - \u53ef\u6062\u590d\u5730\u9694\u79bb\u5df2\u5b89\u88c5\u63d2\u4ef6\u3002"
                + "   restore ID\u3001purge ID\u3001quarantined - \u7ba1\u7406\u5df2\u9694\u79bb\u9879\u3002"
                + "   root PATH - \u989d\u5916\u641c\u7d22\u67d0\u76ee\u5f55\u3002");
    }

    public String deepSwitchTitle() {
        return pick("Thorough scan", "\u6df1\u5ea6\u626b\u63cf");
    }

    public String deepOn() {
        return pick("Reads more of each package. Slower to open this screen.",
                "\u8bfb\u53d6\u66f4\u591a\u5185\u5bb9\uff0c\u6253\u5f00\u672c\u9875\u8f83\u6162\u3002");
    }

    public String deepOff() {
        return pick("Quick scan, bounded so this screen opens promptly.",
                "\u5feb\u901f\u626b\u63cf\uff0c\u4ee5\u4fdd\u8bc1\u672c\u9875\u53ca\u65f6\u6253\u5f00\u3002");
    }

    public String aboutHeader() {
        return pick("About", "\u5173\u4e8e");
    }

    public String trustCounts(int trusted, int denied) {
        return pick("Your lists: " + trusted + " trusted, " + denied + " denied",
                "\u81ea\u5b9a\u4e49\u540d\u5355\uff1a\u53ef\u4fe1 " + trusted + "\uff0c\u6076\u610f " + denied);
    }

    public String rootsSearched(int count) {
        return pick("Folders searched: " + count, "\u5df2\u641c\u7d22\u76ee\u5f55\uff1a" + count);
    }

    public String selfExcluded() {
        return pick("This scanner excludes itself from results",
                "\u672c\u63d2\u4ef6\u4e0d\u626b\u63cf\u81ea\u8eab");
    }

    public String limitsTitle() {
        return pick("What this can and cannot tell you",
                "\u80fd\u529b\u4e0e\u5c40\u9650");
    }

    public String limits() {
        return pick("Findings describe what a plugin is able to do, read from its files. That is evidence,"
                + " not proof of intent: a plugin can be flagged and still be honest, and code hidden well"
                + " enough can pass. Read the evidence, then decide.",
                "\u7ed3\u679c\u63cf\u8ff0\u63d2\u4ef6\u201c\u80fd\u505a\u4ec0\u4e48\u201d\uff0c\u800c\u975e"
                + "\u8bc1\u660e\u5176\u610f\u56fe\uff1a\u88ab\u6807\u8bb0\u7684\u63d2\u4ef6\u53ef\u80fd\u662f"
                + "\u65e0\u5bb3\u7684\uff0c\u9690\u85cf\u8db3\u591f\u5de7\u5999\u7684\u4ee3\u7801\u4e5f\u53ef"
                + "\u80fd\u9003\u8fc7\u68c0\u6d4b\u3002\u8bf7\u5148\u9605\u8bfb\u8bc1\u636e\u518d\u505a\u51b3\u5b9a\u3002");
    }

    // ------------------------------------------------------------ command replies

    public String deepEnabled() {
        return pick("Thorough scanning is on.", "\u5df2\u5f00\u542f\u6df1\u5ea6\u626b\u63cf\u3002");
    }

    public String deepDisabled() {
        return pick("Quick scanning is on.", "\u5df2\u5207\u6362\u4e3a\u5feb\u901f\u626b\u63cf\u3002");
    }

    public String rootCleared() {
        return pick("Extra folder cleared.", "\u5df2\u6e05\u9664\u989d\u5916\u76ee\u5f55\u3002");
    }

    public String rootAdded(String path) {
        return pick("Also searching " + path, "\u5df2\u6dfb\u52a0\u641c\u7d22\u76ee\u5f55\uff1a" + path);
    }

    public String notADirectory(String path) {
        return pick("Not a readable folder: " + path,
                "\u4e0d\u662f\u53ef\u8bfb\u76ee\u5f55\uff1a" + path);
    }

    public String needsArgument(String verb) {
        return pick("The " + verb + " command needs something after it.",
                verb + " \u547d\u4ee4\u9700\u8981\u53c2\u6570\u3002");
    }

    public String listUpdated(String verb, String value) {
        return pick("Recorded: " + verb + " " + value,
                "\u5df2\u8bb0\u5f55\uff1a" + verb + " " + value);
    }

    public String couldNotSave(String reason) {
        return pick("Could not save: " + reason, "\u4fdd\u5b58\u5931\u8d25\uff1a" + reason);
    }

    public String noSuchPlugin(String argument) {
        return pick("No installed plugin found matching " + argument,
                "\u672a\u627e\u5230\u5339\u914d\u7684\u5df2\u5b89\u88c5\u63d2\u4ef6\uff1a" + argument);
    }

    public String quarantineEmpty() {
        return pick("Nothing is in quarantine.", "\u9694\u79bb\u533a\u4e3a\u7a7a\u3002");
    }

    public String exported(String path) {
        return pick("Report written to " + path, "\u62a5\u544a\u5df2\u5bfc\u51fa\u5230 " + path);
    }

    public String unknownCommand(String verb) {
        return pick("Unknown command: " + verb, "\u672a\u77e5\u547d\u4ee4\uff1a" + verb);
    }

    public String commandFailed(String reason) {
        return pick("The command failed: " + reason, "\u547d\u4ee4\u6267\u884c\u5931\u8d25\uff1a" + reason);
    }
}
