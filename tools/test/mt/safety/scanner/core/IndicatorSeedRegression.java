package mt.safety.scanner.core;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;

/** Executes no-overwrite publication against ordinary files and dangling links. */
public final class IndicatorSeedRegression {
    private IndicatorSeedRegression() { }
    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("indicator-seed-").toFile();
        File target = new File(root, "indicators.json");
        byte[] initial = "{\"version\":\"initial\"}".getBytes("UTF-8");
        java.lang.reflect.Method create = AtomicFiles.class.getMethod("createIfAbsent", File.class, byte[].class);
        require((Boolean) create.invoke(null, target, initial), "new file is published");
        require(!(Boolean) create.invoke(null, target, "replacement".getBytes("UTF-8")), "existing file is preserved");
        require(Arrays.equals(initial, Files.readAllBytes(target.toPath())), "existing bytes survive");
        File absent = new File(root, "absent.json"), link = new File(root, "link.json");
        Files.createSymbolicLink(link.toPath(), absent.toPath());
        require(!(Boolean) create.invoke(null, link, initial), "dangling destination symlink is preserved");
        require(!absent.exists() && Files.isSymbolicLink(link.toPath()), "no linked target is created");
        require(root.list().length == 2, "all staging files are cleaned up");
        System.out.println("IndicatorSeedRegression: 6 checks passed");
    }
    private static void require(boolean condition, String label) { if (!condition) throw new AssertionError(label); }
}
