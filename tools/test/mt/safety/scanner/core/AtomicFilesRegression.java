package mt.safety.scanner.core;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Scanner-owned writes cannot follow predictable staging or destination symlinks. */
public final class AtomicFilesRegression {
    private static int passed;
    private static int failed;

    private AtomicFilesRegression() { }

    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("mtsafety-atomic-files-").toFile();
        File scanner = new File(root, "scanner");
        if (!scanner.mkdir()) { throw new IOException("fixture directory"); }
        File sentinel = new File(root, "other-plugin/payload.txt");
        bytes(sentinel, "KEEP INNOCENT BYTES");
        byte[] originalSentinel = Files.readAllBytes(sentinel.toPath());
        File indicators = new File(scanner, "indicators.json");
        File predictable = new File(scanner, "indicators.json.tmp");
        Files.createSymbolicLink(predictable.toPath(), sentinel.toPath());
        IocDatabase decisions = IocDatabase.empty();
        decisions.trust("first-hash", "first decision");
        decisions.save(indicators);
        check("IOC save never follows a preplanted predictable temporary symlink",
                Arrays.equals(originalSentinel, Files.readAllBytes(sentinel.toPath())));
        check("IOC save preserves the pre-existing staging path itself", Files.isSymbolicLink(predictable.toPath())
                && Files.readSymbolicLink(predictable.toPath()).equals(sentinel.toPath()));
        check("IOC save actually stores the trust decision", IocDatabase.load(indicators).isTrusted("first-hash"));
        decisions.trust("second-hash", "second decision");
        decisions.save(indicators);
        check("IOC replacement retains both decisions", IocDatabase.load(indicators).trustedCount() == 2);
        check("IOC replacement creates no backup or unique staging debris",
                !new File(scanner, "indicators.json.bak").exists() && uniqueStages(scanner) == 0);

        Class<?> helper;
        try {
            helper = Class.forName("mt.safety.scanner.core.AtomicFiles");
        } catch (ClassNotFoundException expected) {
            check("shared safe staging helper exists", false);
            finish();
            return;
        }
        Method write = helper.getMethod("write", File.class, byte[].class);
        Method copy = helper.getMethod("copy", File.class, File.class, long.class);
        byte[] replacement = "NEW CONFIG BYTES".getBytes("UTF-8");
        File destinationLink = new File(scanner, "linked-config.json");
        Files.createSymbolicLink(destinationLink.toPath(), sentinel.toPath());
        invoke(write, destinationLink, replacement);
        check("write replaces destination link itself", !Files.isSymbolicLink(destinationLink.toPath())
                && Arrays.equals(replacement, Files.readAllBytes(destinationLink.toPath())));
        check("write leaves destination link target intact", Arrays.equals(originalSentinel, Files.readAllBytes(sentinel.toPath())));

        File source = new File(root, "import-source.hdb");
        bytes(source, "SIGNATURE SOURCE");
        byte[] originalSource = Files.readAllBytes(source.toPath());
        File imported = new File(scanner, "imported.hdb");
        File importedTmp = new File(scanner, "imported.hdb.tmp");
        Files.createSymbolicLink(importedTmp.toPath(), sentinel.toPath());
        invoke(copy, source, imported, (long) originalSource.length);
        check("copy never follows a predictable temporary symlink", Arrays.equals(originalSentinel, Files.readAllBytes(sentinel.toPath()))
                && Files.isSymbolicLink(importedTmp.toPath()));
        check("copy commits full bytes without changing source", Arrays.equals(originalSource, Files.readAllBytes(imported.toPath()))
                && Arrays.equals(originalSource, Files.readAllBytes(source.toPath())));
        File importedLink = new File(scanner, "import-link.hdb");
        Files.createSymbolicLink(importedLink.toPath(), sentinel.toPath());
        invoke(copy, source, importedLink, (long) originalSource.length);
        check("copy replaces destination link without changing target", !Files.isSymbolicLink(importedLink.toPath())
                && Arrays.equals(originalSource, Files.readAllBytes(importedLink.toPath()))
                && Arrays.equals(originalSentinel, Files.readAllBytes(sentinel.toPath())));
        File dangling = new File(scanner, "dangling.hdb");
        File missingTarget = new File(root, "do-not-create");
        Files.createSymbolicLink(dangling.toPath(), missingTarget.toPath());
        invoke(copy, source, dangling, (long) originalSource.length);
        check("copy replaces dangling destination without creating target", dangling.isFile()
                && !Files.isSymbolicLink(dangling.toPath()) && !missingTarget.exists());

        File blocked = new File(scanner, "blocked");
        File blockedChild = new File(blocked, "existing-trust-list.json");
        bytes(blockedChild, "PRESERVE EXISTING DESTINATION");
        Map<String, byte[]> before = children(scanner);
        check("failed write rename reports failure", fails(write, blocked, replacement));
        check("failed write rename preserves destination and cleans staging", equalChildren(before, children(scanner)));
        check("failed copy rename reports failure", fails(copy, source, blocked, 1024L));
        check("failed copy rename preserves destination and cleans staging", equalChildren(before, children(scanner)));
        check("over-limit source is refused", fails(copy, source, imported, 1L));
        check("over-limit source retains previous destination and cleans staging", equalChildren(before, children(scanner)));
        check("negative copy cap is refused", fails(copy, source, imported, -1L));
        check("negative cap retains previous destination and cleans staging", equalChildren(before, children(scanner)));
        File empty = new File(root, "empty");
        bytes(empty, "");
        File emptyDestination = new File(scanner, "empty-copy");
        invoke(copy, empty, emptyDestination, 0L);
        check("zero-byte cap admits an empty source", emptyDestination.isFile() && emptyDestination.length() == 0);

        File growingPath = new File(root, "growing-source");
        bytes(growingPath, "x");
        File growing = new GrowingFile(growingPath);
        before = children(scanner);
        check("copy enforces cap after a source grows beyond observed length", fails(copy, growing, imported, 1L));
        check("source-growth refusal preserves destination and cleans staging", equalChildren(before, children(scanner)));
        check("source-growth refusal never edits source bytes", "xyyyyyyyy".equals(new String(Files.readAllBytes(growingPath.toPath()), "UTF-8")));
        check("all successful operations clean their unique staging files", uniqueStages(scanner) == 0);
        File missingParent = new File(root, "absent-parent/output");
        check("helper refuses nonexistent parent without creating it", fails(write, missingParent, replacement)
                && !missingParent.getParentFile().exists());
        File blocker = new File(root, "parent-is-file");
        bytes(blocker, "BLOCKER");
        check("IOC parent creation failure still throws", saveFails(decisions, new File(blocker, "indicators.json")));
        check("IOC can still create its own missing parent", saveSucceeds(decisions, new File(root, "new-own-parent/indicators.json")));
        finish();
    }

    private static final class GrowingFile extends File {
        private static final long serialVersionUID = 1L;
        private boolean grew;
        GrowingFile(File source) { super(source.getAbsolutePath()); }
        @Override
        public long length() {
            long original = super.length();
            if (!grew) {
                grew = true;
                try (FileOutputStream output = new FileOutputStream(this, true)) {
                    output.write("yyyyyyyy".getBytes("UTF-8"));
                } catch (IOException failure) { throw new IllegalStateException(failure); }
            }
            return original;
        }
    }

    private static void invoke(Method method, Object... arguments) throws Exception {
        try { method.invoke(null, arguments); }
        catch (InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof Exception) { throw (Exception) cause; }
            throw failure;
        }
    }
    private static boolean fails(Method method, Object... arguments) throws Exception {
        try { invoke(method, arguments); return false; }
        catch (IOException expected) { return true; }
    }
    private static boolean saveFails(IocDatabase database, File file) {
        try { database.save(file); return false; } catch (IOException expected) { return true; }
    }
    private static boolean saveSucceeds(IocDatabase database, File file) {
        try { database.save(file); return IocDatabase.load(file).trustedCount() == 2; }
        catch (IOException failure) { return false; }
    }
    private static void bytes(File file, String text) throws IOException {
        File parent = file.getParentFile();
        if (!parent.isDirectory() && !parent.mkdirs()) { throw new IOException("fixture parent"); }
        Files.write(file.toPath(), text.getBytes("UTF-8"));
    }
    private static int uniqueStages(File parent) {
        int found = 0;
        File[] entries = parent.listFiles();
        if (entries == null) { throw new IllegalStateException("fixture listing"); }
        for (File entry : entries) { if (entry.getName().startsWith(".mtsafety-")) { found++; } }
        return found;
    }
    private static Map<String, byte[]> children(File parent) throws IOException {
        Map<String, byte[]> out = new LinkedHashMap<String, byte[]>();
        File[] entries = parent.listFiles();
        if (entries == null) { throw new IOException("fixture listing"); }
        for (File entry : entries) {
            byte[] value = Files.isSymbolicLink(entry.toPath()) ? Files.readSymbolicLink(entry.toPath()).toString().getBytes("UTF-8")
                    : entry.isDirectory() ? "DIRECTORY".getBytes("UTF-8") : Files.readAllBytes(entry.toPath());
            out.put(entry.getName(), value);
            if (entry.isDirectory() && !Files.isSymbolicLink(entry.toPath())) {
                for (Map.Entry<String, byte[]> child : children(entry).entrySet()) {
                    out.put(entry.getName() + "/" + child.getKey(), child.getValue());
                }
            }
        }
        return out;
    }
    private static boolean equalChildren(Map<String, byte[]> first, Map<String, byte[]> second) {
        if (!first.keySet().equals(second.keySet())) { return false; }
        for (String key : first.keySet()) { if (!Arrays.equals(first.get(key), second.get(key))) { return false; } }
        return true;
    }
    private static void check(String description, boolean condition) {
        System.out.println((condition ? "PASS " : "FAIL ") + description);
        if (condition) { passed++; } else { failed++; }
    }
    private static void finish() {
        System.out.println("AtomicFilesRegression: " + passed + " passed, " + failed + " failed");
        if (failed > 0) { throw new AssertionError("safe staging failures: " + failed); }
    }
}
