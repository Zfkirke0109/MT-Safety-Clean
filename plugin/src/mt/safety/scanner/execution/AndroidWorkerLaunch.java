package mt.safety.scanner.execution;

import java.io.File;
import java.io.IOException;
import java.util.Map;

/** Fixed trusted ART runtime locations; never resolves an executable through user-controlled PATH. */
public final class AndroidWorkerLaunch {
    public static final long MAX_HEAP_BYTES = 96L * 1024 * 1024;
    private AndroidWorkerLaunch() { }

    public static String runtime() throws IOException {
        for (String path : new String[] {"/apex/com.android.art/bin/dalvikvm",
                "/apex/com.android.runtime/bin/dalvikvm", "/system/bin/dalvikvm"}) {
            File executable = new File(path);
            if (executable.isFile() && executable.canExecute()) return path;
        }
        throw new IOException("Trusted ART command unavailable; inspection incomplete");
    }

    public static ProcessBuilder builder(File scannerDex) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(runtime(), "-Xmx96m", "-cp", scannerDex.getAbsolutePath(),
                "mt.safety.scanner.ui.AndroidWorkerMain");
        Map<String, String> environment = builder.environment();
        for (String name : new String[] {"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "JAVA_TOOL_OPTIONS",
                "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"}) environment.remove(name);
        environment.put("CLASSPATH", scannerDex.getAbsolutePath());
        return builder;
    }
}
