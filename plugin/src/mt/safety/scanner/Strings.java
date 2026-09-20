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
        return pick("SHA-256 (for the trust command)", "SHA-256\uff08\u7528\u4e8e trust \u547d\u4ee4\uff09");
    }

    public String moreFindings(int count) {
        return pick("... and " + count + " more findings, use export for the full report",
                "... \u5176\u4f59 " + count + " \u9879\uff0c\u8bf7\u7528 export \u5bfc\u51fa\u5b8c\u6574\u62a5\u544a");
    }

    public String incomplete() {
        return pick("The scan did not finish reading this package",
                "\u672a\u80fd\u5b8c\u6574\u8bfb\u53d6\u8be5\u63d2\u4ef6");
    }

    public String notReached(int count) {
        return pick(count + " more plugin(s) were not scanned this time",
                "\u8fd8\u6709 " + count + " \u4e2a\u63d2\u4ef6\u672c\u6b21\u672a\u626b\u63cf");
    }

    public String notReachedHelp() {
        return pick("The scan stopped at its time limit so this screen stays responsive."
                + " Use the deep command, or export, to scan everything.",
                "\u4e3a\u4fdd\u8bc1\u9875\u9762\u54cd\u5e94\uff0c\u626b\u63cf\u5df2\u8fbe"
                + "\u65f6\u95f4\u4e0a\u9650\u3002\u8bf7\u4f7f\u7528 deep \u6216 export "
                + "\u626b\u63cf\u5168\u90e8\u3002");
    }

    public String quarantineThis() {
        return pick("Quarantine this plugin", "\u9694\u79bb\u6b64\u63d2\u4ef6");
    }

    public String quarantineThisHelp() {
        return pick("Turn this on, then reopen this screen. The plugin is moved aside and can be put"
                + " back with the restore command.",
                "\u6253\u5f00\u540e\u91cd\u65b0\u6253\u5f00\u672c\u9875\u5373\u53ef\u3002"
                + "\u63d2\u4ef6\u5c06\u88ab\u79fb\u8d70\uff0c\u53ef\u7528 restore \u6062\u590d\u3002");
    }

    public String armedOn() {
        return pick("Armed. Reopen this screen to carry it out, or turn this off to call it off.",
                "\u5df2\u5c31\u7eea\u3002\u91cd\u65b0\u6253\u5f00\u672c\u9875\u5373\u6267"
                + "\u884c\uff0c\u5173\u95ed\u5219\u53d6\u6d88\u3002");
    }

    public String actedOn() {
        return pick("Moved to quarantine just now", "\u521a\u521a\u5df2\u9694\u79bb");
    }

    public String actedOnHelp() {
        return pick("Restart MT Manager, then reopen this screen to confirm it is gone.",
                "\u8bf7\u91cd\u542f MT \u7ba1\u7406\u5668\u540e\u91cd\u65b0\u6253\u5f00\u672c"
                + "\u9875\u786e\u8ba4\u3002");
    }

    public String changedSinceScan(String name) {
        return pick(name + " changed since it was scanned, so nothing was done to it. Reopen this"
                + " screen to scan it again.",
                name + " \u5728\u626b\u63cf\u540e\u5df2\u53d8\u66f4\uff0c\u672a\u5bf9\u5176"
                + "\u6267\u884c\u4efb\u4f55\u64cd\u4f5c\u3002\u8bf7\u91cd\u65b0\u6253\u5f00"
                + "\u672c\u9875\u91cd\u65b0\u626b\u63cf\u3002");
    }

    public String actedOnRemoved() {
        return pick("Deleted just now", "\u521a\u521a\u5df2\u5220\u9664");
    }

    public String actedOnRemovedHelp() {
        return pick("Permanently removed, so there is no quarantined copy to restore. Restart MT"
                + " Manager, then reopen this screen to confirm.",
                "\u5df2\u6c38\u4e45\u5220\u9664\uff0c\u65e0\u53ef\u6062\u590d\u7684\u526f"
                + "\u672c\u3002\u8bf7\u91cd\u542f MT \u7ba1\u7406\u5668\u540e\u91cd\u65b0"
                + "\u6253\u5f00\u672c\u9875\u786e\u8ba4\u3002");
    }

    public String bulkOffer(int malicious, int suspicious) {
        return pick(malicious + " to remove, " + suspicious + " flagged in total",
                "\u5efa\u8bae\u79fb\u9664 " + malicious + " \u4e2a\uff0c\u5171\u6807\u8bb0 "
                        + suspicious + " \u4e2a");
    }

    public String bulkOfferHelp() {
        return pick("Commands: \"quarantine malicious\" or \"quarantine suspicious\" to move them all"
                + " aside reversibly, \"remove malicious\" or \"remove suspicious\" to delete them for"
                + " good. Each one lists what it will touch and waits for a confirmation code.",
                "\u547d\u4ee4\uff1a\"quarantine malicious\" \u6216 \"quarantine suspicious\" "
                + "\u53ef\u6062\u590d\u5730\u6279\u91cf\u9694\u79bb\uff1b\"remove malicious\" \u6216 "
                + "\"remove suspicious\" \u5f7b\u5e95\u5220\u9664\u3002\u6267\u884c\u524d\u4f1a\u5148\u5217\u51fa"
                + "\u6e05\u5355\u5e76\u7b49\u5f85\u786e\u8ba4\u7801\u3002");
    }

    public String planned(String action, int count, String names, String code) {
        String verb = action.equals("remove") ? "permanently delete" : "quarantine";
        String zhVerb = action.equals("remove") ? "\u5f7b\u5e95\u5220\u9664" : "\u9694\u79bb";
        return pick("This will " + verb + " " + count + " plugin(s): " + names
                + ".  Type \"confirm " + code + "\" to go ahead, or \"cancel\" to drop it.",
                "\u5c06" + zhVerb + " " + count + " \u4e2a\u63d2\u4ef6\uff1a" + names
                + "\u3002\u8f93\u5165 \"confirm " + code + "\" \u786e\u8ba4\uff0c\u6216 \"cancel\" "
                + "\u53d6\u6d88\u3002");
    }

    public String bulkDone(String action, int count) {
        String verb = action.equals("remove") ? "Deleted" : "Quarantined";
        String zhVerb = action.equals("remove") ? "\u5df2\u5220\u9664" : "\u5df2\u9694\u79bb";
        return pick(verb + " " + count + " plugin(s). Restart MT Manager.",
                zhVerb + " " + count + " \u4e2a\u63d2\u4ef6\u3002\u8bf7\u91cd\u542f MT \u7ba1\u7406\u5668\u3002");
    }

    public String someOnlyQuarantined(int count) {
        return pick(count + " could not be deleted and were left in quarantine, so they can still be"
                + " restored or purged.",
                "\u5176\u4e2d " + count + " \u4e2a\u65e0\u6cd5\u5220\u9664\uff0c\u5df2\u7559"
                + "\u5728\u9694\u79bb\u533a\uff0c\u4ecd\u53ef\u6062\u590d\u6216\u6e05\u9664\u3002");
    }

    public String nothingMatches(String scope) {
        return pick("Nothing matches \"" + scope + "\".",
                "\u6ca1\u6709\u5339\u914d \"" + scope + "\" \u7684\u9879\u3002");
    }

    public String noneVerifiable(int count) {
        return pick(count + " flagged plugin(s) could not be read completely enough to act on safely."
                + " Run \"deep\", reopen this screen, then try again.",
                "\u6709 " + count + " \u4e2a\u88ab\u6807\u8bb0\u7684\u63d2\u4ef6\u672a\u80fd"
                + "\u5b8c\u6574\u8bfb\u53d6\uff0c\u65e0\u6cd5\u5b89\u5168\u5904\u7406\u3002"
                + "\u8bf7\u5148\u6267\u884c \"deep\" \u5e76\u91cd\u65b0\u6253\u5f00\u672c\u9875\u3002");
    }

    public String someUnverifiable(int count) {
        return pick("(" + count + " more could not be read completely enough to include; run \"deep\""
                + " to cover them.)",
                "\uff08\u53e6\u6709 " + count + " \u4e2a\u672a\u80fd\u5b8c\u6574\u8bfb\u53d6"
                + "\u800c\u672a\u5217\u5165\uff0c\u53ef\u6267\u884c \"deep\" \u540e\u91cd\u8bd5\u3002\uff09");
    }

    public String nothingToConfirm() {
        return pick("There is nothing waiting to be confirmed.",
                "\u6ca1\u6709\u5f85\u786e\u8ba4\u7684\u64cd\u4f5c\u3002");
    }

    public String wrongCode(String expected) {
        return pick("That code does not match. Type \"confirm " + expected + "\", or \"cancel\".",
                "\u786e\u8ba4\u7801\u4e0d\u5339\u914d\u3002\u8bf7\u8f93\u5165 \"confirm "
                        + expected + "\" \u6216 \"cancel\"\u3002");
    }

    public String planStale() {
        return pick("The plugins changed since that list was made, so nothing was done. Run the command"
                + " again to see the current list.",
                "\u81ea\u751f\u6210\u6e05\u5355\u540e\u63d2\u4ef6\u5df2\u53d8\u5316\uff0c"
                + "\u672a\u6267\u884c\u4efb\u4f55\u64cd\u4f5c\u3002\u8bf7\u91cd\u65b0\u8fd0"
                + "\u884c\u547d\u4ee4\u3002");
    }

    public String planCancelled() {
        return pick("Cancelled. Nothing was changed.",
                "\u5df2\u53d6\u6d88\uff0c\u672a\u505a\u4efb\u4f55\u66f4\u6539\u3002");
    }

    public String removeNeedsScope() {
        return pick("\"remove\" works on a group: try \"remove malicious\" or \"remove suspicious\"."
                + " To delete one plugin, quarantine it first, then use \"purge\".",
                "\"remove\" \u7528\u4e8e\u6279\u91cf\uff1a\u8bf7\u7528 \"remove malicious\" "
                + "\u6216 \"remove suspicious\"\u3002\u5220\u9664\u5355\u4e2a\u63d2\u4ef6\u8bf7"
                + "\u5148\u9694\u79bb\u518d\u7528 \"purge\"\u3002");
    }

    public String notInstalled(String name) {
        return pick(name + " is a package file, not an installed plugin, so it was left alone.",
                name + " \u662f\u5b89\u88c5\u5305\u6587\u4ef6\u800c\u975e\u5df2\u5b89\u88c5"
                        + "\u63d2\u4ef6\uff0c\u5df2\u8df3\u8fc7\u3002");
    }

    public String couldNotPurge(String path) {
        return pick("Quarantined, but the copy could not be deleted: " + path,
                "\u5df2\u9694\u79bb\uff0c\u4f46\u526f\u672c\u5220\u9664\u5931\u8d25\uff1a" + path);
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
        return pick("definitions - where the rules and signatures came from and how old they are."
                + "   import PATH - fold in an indicator list, or add a ClamAV-format signature file"
                + " (.hdb, .hsb, .ndb)."
                + "   files [PATH] - check the files this plugin can read against the loaded signatures."
                + "   "
                + "quarantine-all - move every flagged plugin aside, worth-a-look included."
                + "quarantine malicious / quarantine suspicious - move every flagged plugin aside,"
                + " reversibly.   remove malicious / remove suspicious - delete them for good."
                + "   confirm CODE / cancel - go ahead with, or drop, the listed action."
                + "   deep / fast - thorough or quick scanning."
                + "   export - write the full report to this plugin's folder."
                + "   trust HASH - accept a package by its SHA-256."
                + "   untrust HASH, deny HASH_OR_ID - undo, or mark as bad."
                + "   quarantine ID - move an installed plugin aside, reversibly."
                + "   restore ID, purge ID, quarantined - manage what was moved."
                + "   root PATH - also search a folder.",
                "definitions - 规则与特征库的来源及时效。"
                + "   import 路径 - 导入指标清单，或添加 ClamAV 格式特征库文件（.hdb、.hsb、.ndb）。"
                + "   files [路径] - 用已加载的特征库检查本插件可读取的文件。"
                + "   quarantine-all - 隔离所有被标记的插件，包括“值得一看”。"
                + "   quarantine malicious / quarantine suspicious - \u53ef\u6062\u590d\u5730\u6279"
                + "\u91cf\u9694\u79bb\u6240\u6709\u88ab\u6807\u8bb0\u7684\u63d2\u4ef6\u3002"
                + "   remove malicious / remove suspicious - \u5f7b\u5e95\u5220\u9664\u3002"
                + "   confirm CODE / cancel - \u786e\u8ba4\u6216\u53d6\u6d88\u5df2\u5217\u51fa"
                + "\u7684\u64cd\u4f5c\u3002"
                + "   deep / fast - \u6df1\u5ea6\u6216\u5feb\u901f\u626b\u63cf\u3002"
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

    public String selectThis() {
        return pick("Select for removal", "选中以便删除");
    }

    public String selectThisHelp() {
        return pick("Nothing happens until you press the uninstall button.",
                "在按下卸载按钮前不会执行任何操作。");
    }

    public String selectedOn() {
        return pick("Selected. The uninstall button will delete this.",
                "已选中，卸载按钮将删除它。");
    }

    public String uninstallButton(int count) {
        return pick("Uninstall selected, quarantined and malicious (" + count + ")",
                "卸载已选中、已隔离和恶意插件（" + count + "）");
    }

    public String uninstallButtonHelp() {
        return pick("Deletes them for good. Quarantine first if you want it reversible.",
                "永久删除。如需可恢复，请先隔离。");
    }

    public String uninstallTitle() {
        return pick("Uninstall plugins?", "卸载插件？");
    }

    public String uninstallBody(int targets, int held) {
        return pick("This deletes " + targets + " installed plugin(s) and clears " + held
                        + " already in quarantine. It cannot be undone.",
                "将删除 " + targets + " 个已安装插件，并清空隔离区的 "
                        + held + " 个。此操作无法撤销。");
    }

    public String uninstalled(int removed, int purged) {
        return pick("Uninstalled " + removed + ", cleared " + purged + " from quarantine. Restart MT Manager.",
                "已卸载 " + removed + " 个，清理隔离区 " + purged
                        + " 个。请重启 MT 管理器。");
    }

    public String nothingSelected() {
        return pick("Nothing is selected, malicious or quarantined, so nothing was done.",
                "没有已选中、恶意或已隔离的插件，未执行操作。");
    }

    // ---------------------------------------------------- where detection comes from

    public String rulesTitle(int version) {
        return pick("Detection rules: catalogue v" + version,
                "检测规则：规则库 v" + version);
    }

    public String rulesLine(int version, String date, int count, long ageDays) {
        return pick(count + " rules, built " + date + " (" + age(ageDays) + "). Written and reviewed"
                        + " in the open; updated by installing a new build of this plugin.",
                count + " 条规则，版本日期 " + date + "（" + age(ageDays)
                        + "）。规则公开可查，通过安装"
                        + "新版插件更新。");
    }

    public String indicatorTitle() {
        return pick("Your indicator file", "您的指标文件");
    }

    public String indicatorLine(String version, String updated, int trusted, int denied,
            int patterns, long ageDays) {
        String counts = trusted + " trusted, " + denied + " denied, " + patterns + " patterns";
        String zhCounts = trusted + " 信任、" + denied + " 拒绝、" + patterns
                + " 模式";
        if (updated == null || updated.length() == 0) {
            return pick(counts + ". No date recorded; it ships empty and holds only what you put in"
                            + " it. Use \"import PATH\" to fold in a list you obtained yourself.",
                    zhCounts + "。未记录日期；默认为空，"
                            + "仅包含您自己添加的内容。"
                            + "可用 \"import PATH\" 导入外部清单。");
        }
        String v = version == null || version.length() == 0 ? "" : " v" + version;
        return pick("Version" + v + ", dated " + updated + " (" + age(ageDays) + "). " + counts + ".",
                "版本" + v + "，日期 " + updated + "（" + age(ageDays) + "）。"
                        + zhCounts + "。");
    }

    public String indicatorSource(String source) {
        return pick("Source: " + source, "来源：" + source);
    }

    /** Plain-language age, since "0 days" reads worse than "today". */
    private String age(long days) {
        if (days == mt.safety.scanner.core.Dates.UNKNOWN) {
            return pick("age unknown", "日期未知");
        }
        if (days < 0) {
            return pick("dated in the future; check this device's clock",
                    "日期晚于当前，请检查本机时间");
        }
        if (days == 0) {
            return pick("today", "今天");
        }
        if (days == 1) {
            return pick("1 day old", "1 天前");
        }
        return pick(days + " days old", days + " 天前");
    }

    public String noSuchFile(String path) {
        return pick("No such file: " + path, "文件不存在：" + path);
    }

    public String importFailed(String reason) {
        return pick("Could not import: " + reason, "导入失败：" + reason);
    }

    public String imported(int trusted, int denied, int patterns) {
        return pick("Imported: " + trusted + " trusted, " + denied + " denied, " + patterns
                        + " patterns added.",
                "已导入：新增 " + trusted + " 信任、" + denied
                        + " 拒绝、" + patterns + " 模式。");
    }

    // ------------------------------------------------------------ v3 button UI

    public String actionsHeader() {
        return pick("Act on what was found", "\u5904\u7406\u626b\u63cf\u7ed3\u679c");
    }

    /** Label for a "quarantine/remove all X (N)" button. */
    public String bulkButton(String action, String scope, int count) {
        String act = actionWord(action);
        String kind;
        if (scope.equals("malicious")) {
            kind = pick("malicious", "\u6076\u610f");
        } else if (scope.equals("flagged")) {
            kind = pick("flagged", "\u88ab\u6807\u8bb0\u7684");
        } else {
            kind = pick("suspicious", "\u53ef\u7591");
        }
        return pick(act + " all " + kind + " (" + count + ")",
                act + "\u6240\u6709" + kind + "\u63d2\u4ef6\uff08" + count + "\uff09");
    }

    public String bulkButtonHelp(boolean remove) {
        return remove
                ? pick("Tap to review and delete them for good.",
                        "\u70b9\u51fb\u67e5\u770b\u5e76\u6c38\u4e45\u5220\u9664\u3002")
                : pick("Tap to review and move them aside. Restore undoes it.",
                        "\u70b9\u51fb\u67e5\u770b\u5e76\u79fb\u51fa\u3002\u53ef\u901a\u8fc7 restore \u6062\u590d\u3002");
    }

    public String confirmTitle(String action) {
        return pick(actionWord(action) + " plugins?", actionWord(action) + "\u63d2\u4ef6\uff1f");
    }

    public String confirmBody(boolean remove, int count) {
        String n = String.valueOf(count);
        return remove
                ? pick("Delete these " + n + " plugins for good? This cannot be undone.",
                        "\u6c38\u4e45\u5220\u9664\u8fd9 " + n + " \u4e2a\u63d2\u4ef6\uff1f\u6b64\u64cd\u4f5c\u65e0\u6cd5\u64a4\u9500\u3002")
                : pick("Move these " + n + " plugins aside? Restore undoes it.",
                        "\u79fb\u51fa\u8fd9 " + n + " \u4e2a\u63d2\u4ef6\uff1f\u53ef\u901a\u8fc7 restore \u6062\u590d\u3002");
    }

    public String actOneBody(String verdict) {
        return pick("This plugin was rated: " + verdict + ". Quarantine moves it aside so restore can"
                        + " undo it; remove deletes it for good.",
                "\u8be5\u63d2\u4ef6\u8bc4\u7ea7\uff1a" + verdict + "\u3002\u9694\u79bb\u53ef\u6062\u590d\uff0c"
                        + "\u5220\u9664\u4e0d\u53ef\u6062\u590d\u3002");
    }

    public String confirmAct(boolean remove) {
        return remove ? pick("Remove", "\u5220\u9664") : pick("Quarantine", "\u9694\u79bb");
    }

    public String cancel() {
        return pick("Cancel", "\u53d6\u6d88");
    }

    public String andMore(int count) {
        return pick("and " + count + " more", "\u7b49\u53e6\u5916 " + count + " \u4e2a");
    }

    private String actionWord(String action) {
        return action.equals("remove") ? pick("Remove", "\u5220\u9664") : pick("Quarantine", "\u9694\u79bb");
    }

    // ------------------------------------------------------------- signatures and file scans

    public String signatureTitle() {
        return pick("Malware signatures (ClamAV format)", "恶意软件特征库（ClamAV 格式）");
    }

    /** What is loaded and how old it is; or, with no files, how to get some. */
    public String signatureLine(int files, int hashes, int patterns, String newest, long ageDays,
            int unsupported, int capped) {
        if (files == 0) {
            return pick("None loaded. Import a ClamAV-format .hdb, .hsb or .ndb file with \"import PATH\";"
                            + " the README says where to get one and how to keep it small enough for a phone.",
                    "未加载。可用 \"import 路径\" 导入 ClamAV 格式的 .hdb、.hsb 或 .ndb 文件；"
                            + "README 说明了获取方式，以及如何精简到手机可承受的大小。");
        }
        StringBuilder en = new StringBuilder();
        en.append(files).append(files == 1 ? " file: " : " files: ").append(hashes)
                .append(" hash signatures, ").append(patterns).append(" byte patterns. Newest file dated ")
                .append(newest).append(" (").append(age(ageDays)).append(").");
        StringBuilder zh = new StringBuilder();
        zh.append(files).append(" 个文件：").append(hashes).append(" 条哈希特征、").append(patterns)
                .append(" 条字节模式。最新文件日期 ").append(newest).append("（").append(age(ageDays)).append("）。");
        if (unsupported > 0) {
            en.append(' ').append(unsupported).append(" entries use syntax this scanner does not read.");
            zh.append(' ').append(unsupported).append(" 条使用了本扫描器不支持的语法。");
        }
        if (capped > 0) {
            en.append(' ').append(capped).append(" entries were not loaded because a cap was reached.");
            zh.append(' ').append(capped).append(" 条因超出上限未加载。");
        }
        return pick(en.toString(), zh.toString());
    }

    public String signatureFolder() {
        return pick("Signature folder (drop ClamAV-format files here, or use import)",
                "特征库目录（可将 ClamAV 格式文件放入此处，或使用 import）");
    }

    public String signatureProblems(int count, String first) {
        return pick("Problems loading signatures (" + count + "): " + first,
                "加载特征库时出现 " + count + " 个问题：" + first);
    }

    public String signaturesImported(String name, int hashes, int patterns, int unsupported, boolean replaced) {
        String en = (replaced ? "Updated " : "Added ") + name + ": " + hashes + " hash signatures, "
                + patterns + " byte patterns" + (unsupported > 0 ? ", " + unsupported + " entries skipped" : "")
                + ". Reopen this screen to scan with it.";
        String zh = (replaced ? "已更新 " : "已添加 ") + name + "：" + hashes + " 条哈希特征、"
                + patterns + " 条字节模式" + (unsupported > 0 ? "，跳过 " + unsupported + " 条" : "")
                + "。重新打开本页即可用它扫描。";
        return pick(en, zh);
    }

    public String signaturesEmptyImport(String name) {
        return pick("No usable signatures in " + name + ". It should be a ClamAV-format .hdb, .hsb or .ndb"
                        + " text file; a packed .cvd must be unpacked first with sigtool.",
                name + " 中没有可用的特征。应为 ClamAV 格式的 .hdb、.hsb 或 .ndb 文本文件；"
                        + "打包的 .cvd 需先用 sigtool 解包。");
    }

    public String noSignatures() {
        return pick("No signature files are loaded, so there is nothing to check files against. Import a"
                        + " ClamAV-format .hdb, .hsb or .ndb file first.",
                "尚未加载任何特征库，无法检查文件。请先导入 ClamAV 格式的 .hdb、.hsb 或 .ndb 文件。");
    }

    public String filesHeader() {
        return pick("Files matching a signature", "命中特征的文件");
    }

    public String filesSummary(int scanned, int seen, String bytes, long ms, int hits) {
        return pick("Checked " + scanned + " of " + seen + " files (" + bytes + ") in " + ms + " ms: "
                        + hits + (hits == 1 ? " match." : " matches."),
                "已检查 " + scanned + " / " + seen + " 个文件（" + bytes + "），用时 " + ms + " 毫秒："
                        + "命中 " + hits + " 项。");
    }

    public String filesStoppedBudget() {
        return pick("Stopped early: the scan budget ran out. Turn on deep scanning for a longer run, or"
                        + " point the files command at one folder.",
                "提前停止：扫描预算已用尽。可开启深度扫描以延长时间，或用 files 命令指定单个目录。");
    }

    public String filesStoppedCount() {
        return pick("Stopped early: more files than one scan will visit. Point the files command at a"
                        + " smaller folder.",
                "提前停止：文件数量超过单次扫描上限。请用 files 命令指定较小的目录。");
    }

    public String filesStoppedHits() {
        return pick("Stopped early: enough matches to stop counting.", "提前停止：命中数量已达上限。");
    }

    public String fileReportWritten(String path) {
        return pick("Full list: " + path, "完整列表：" + path);
    }

    public String noFileHits() {
        return pick("No file matched a signature.", "没有文件命中特征。");
    }

    public String filesNeedsPath(String path) {
        return pick("Not a readable file or folder: " + path, "不是可读取的文件或目录：" + path);
    }

    public String filesButton() {
        return pick("Scan files for known malware", "扫描文件中的已知恶意软件");
    }

    public String filesButtonHelp(int signatures) {
        if (signatures == 0) {
            return pick("Needs a signature file first: see Malware signatures under About.",
                    "需要先导入特征库：见“关于”中的恶意软件特征库。");
        }
        return pick("Checks every readable file under the folders this plugin searches (Download, MT2, MT"
                        + " Manager's own storage, any root you added) against the " + signatures
                        + " loaded signatures. Nothing is changed or deleted.",
                "用已加载的 " + signatures + " 条特征检查本插件搜索的目录（Download、MT2、MT 管理器自身存储、"
                        + "以及您添加的目录）下的所有可读文件。不会修改或删除任何内容。");
    }

    public String filesConfirmTitle() {
        return pick("Scan files?", "扫描文件？");
    }

    public String filesConfirmBody(String roots, int signatures, boolean deep) {
        return pick("Every readable file under:\n\n" + roots + "\n\nwill be checked against " + signatures
                        + " signatures. MT Manager will be busy for up to " + (deep ? 90 : 6)
                        + " seconds. Nothing is changed or deleted.",
                "将用 " + signatures + " 条特征检查以下目录中的所有可读文件：\n\n" + roots
                        + "\n\nMT 管理器最多会忙碌 " + (deep ? 90 : 6) + " 秒。不会修改或删除任何内容。");
    }

    public String filesResultTitle() {
        return pick("File scan", "文件扫描");
    }

    public String scanAction() {
        return pick("Scan", "扫描");
    }

    public String dismiss() {
        return pick("Close", "关闭");
    }
}
