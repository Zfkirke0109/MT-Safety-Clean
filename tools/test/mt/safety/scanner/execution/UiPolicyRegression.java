package mt.safety.scanner.execution;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Source-boundary guard: the SDK3 adapter must not reintroduce scanner-owned file actions. */
public final class UiPolicyRegression {
    public static void main(String[] args) throws Exception {
        String ui = read("plugin/ui-v3/mt/safety/scanner/ui/ScannerPreference.java");
        String proxy = read("plugin/ui-v3/mt/safety/scanner/ui/IsolatedRunner.java");
        require(!ui.contains("confirmUninstall") && !ui.contains("confirmBulk")
                && !ui.contains("addUninstallButton") && !ui.contains("addBulkButton"),
                "SDK3 UI must have no scanner-owned mutation buttons or confirmation dialogs");
        require(!ui.contains("runner.uninstallSelection") && !ui.contains("runner.actOnScope"),
                "Background UI callbacks must have no mutation dispatch");
        require(!ui.contains("builder.addSwitch(safe(row.title)"),
                "Action rows must not become selection or arming switches");
        require(ui.contains("managementDelegatedTitle()") && ui.contains("managementDelegated()"),
                "MT Manager guidance must remain visible");
        require(ui.contains("Export share-safe report") && ui.contains("runner.exportShareSafeReport()"),
                "Share-safe export needs an explicit UI affordance");
        require(!proxy.contains("WorkerProtocol.UNINSTALL") && !proxy.contains("WorkerProtocol.BULK")
                && !proxy.contains("uninstallSelection(") && !proxy.contains("actOnScope("),
                "UI proxy must expose no mutation request operation");
        require(proxy.contains("export-shareable"), "Export must use the dedicated share-safe command");
        require(proxy.contains("preservePendingCommand"), "Dedicated export must preserve an unrelated typed command");
        System.out.println("PASS UiPolicyRegression (8 SDK3 source-boundary assertions)");
    }
    private static String read(String path) throws Exception {
        return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
