package mt.safety.scanner.core;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import mtsafety.test.Fixtures;

/** Oversized or nonregular selected definitions cannot be treated as complete empty inputs. */
public final class IndicatorLoadingRegression {
    private IndicatorLoadingRegression() { }
    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("indicator-loading-").toFile();
        byte[] oversized = new byte[2 * 1024 * 1024 + 1]; Arrays.fill(oversized, (byte) ' ');
        oversized[0] = '{'; oversized[1] = '}'; oversized[oversized.length - 1] = 'x';
        File file = new File(root, "oversized.json"); Fixtures.writeBytes(file, oversized);
        require(!IocDatabase.load(file).loadErrors().isEmpty(), "oversized suffix must be diagnosed");
        require(!IocDatabase.load(root).loadErrors().isEmpty(), "nonregular selected definition must be diagnosed");
        require(IocDatabase.load(new File(root, "absent.json")).loadErrors().isEmpty(), "optional absent input remains allowed");
        Fixtures.write(file, "{\"patterns\":[\"INERT\"]}");
        require(IocDatabase.load(file).patterns().size() == 1, "complete ordinary definition loads");
        System.out.println("IndicatorLoadingRegression: 4 checks passed");
    }
    private static void require(boolean condition, String label) { if (!condition) throw new AssertionError(label); }
}
