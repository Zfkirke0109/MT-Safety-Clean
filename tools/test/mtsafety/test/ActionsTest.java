package mtsafety.test;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import mt.safety.scanner.Host;
import mt.safety.scanner.Quarantine;
import mt.safety.scanner.ScanRunner;

/** Shared test host and checks for delegation to MT Manager. */
public final class ActionsTest {

    /** A Host backed by maps and a temporary directory. */
    static final class FakeHost implements Host {
        interface Hook {
            void run();
        }

        private final File filesDir;
        private final Map<String, String> values = new HashMap<String, String>();
        private final Map<String, Boolean> flags = new HashMap<String, Boolean>();
        private Hook beforeCommandRead;

        FakeHost(File filesDir) {
            this.filesDir = filesDir;
        }

        @Override
        public File filesDir() {
            return filesDir;
        }

        @Override
        public String config(String key, String fallback) {
            if (ScanRunner.KEY_COMMAND.equals(key) && beforeCommandRead != null) {
                Hook hook = beforeCommandRead;
                beforeCommandRead = null;
                hook.run();
            }
            String v = values.get(key);
            return v == null ? fallback : v;
        }

        @Override
        public boolean configFlag(String key, boolean fallback) {
            Boolean v = flags.get(key);
            return v == null ? fallback : v.booleanValue();
        }

        @Override
        public void putConfig(String key, String value) {
            if (value == null) {
                values.remove(key);
            } else {
                values.put(key, value);
            }
        }

        @Override
        public void putFlag(String key, boolean value) {
            flags.put(key, Boolean.valueOf(value));
        }

        @Override
        public String language() {
            return "en";
        }

        @Override
        public void log(String message) {
        }

        @Override
        public void log(String message, Throwable error) {
        }

        @Override
        public void toast(String message) {
        }

        @Override
        public String pluginId() {
            return "mt.safety.scanner";
        }

        @Override
        public String hostPackage() {
            return "bin.mt.plus";
        }

        void type(String command) {
            values.put(ScanRunner.KEY_COMMAND, command);
        }

        void beforeCommandRead(Hook hook) {
            beforeCommandRead = hook;
        }
    }

    private ActionsTest() { }

    /** The former mutation tests are replaced by complete path/byte survival checks. */
    static void run(Checker check) throws Exception {
        DelegatedActionPolicyRegression.run(check);
        QuarantineGuardRegression.run(check);
    }

    static Quarantine.Result guardedQuarantine(Quarantine quarantine, final File directory,
            String ownPluginId) {
        return quarantine.quarantine(directory, ownPluginId, new Quarantine.MoveGuard() {
            @Override
            public boolean allow(File source) {
                return true;
            }
        });
    }

    interface Checker {
        void that(String description, boolean condition, String context);
    }
}
