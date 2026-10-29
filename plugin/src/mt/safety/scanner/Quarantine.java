package mt.safety.scanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import mt.safety.scanner.core.Bytes;
import mt.safety.scanner.core.DirectoryListing;
import mt.safety.scanner.core.Json;
import mt.safety.scanner.core.ScanBudget;

/** Read-only access to historical quarantine data. Plugin management is delegated to MT Manager. */
public final class Quarantine {
    private static final String INFO_FILE = "quarantine-info.json";
    private static final int MAX_ACTION_ENTRIES = 8000;
    private final File store;
    private String listingProblem;

    /** Every mutation API returns this outcome without inspecting targets or invoking guards. */
    public static final String DELEGATED_MESSAGE = "Action not performed. Use MT Manager's plugin management"
            + " screen to manage installed plugins. Inspect historical quarantine files and their original"
            + " paths in MT Manager for manual recovery; this scanner preserves all held data.";

    public interface MoveGuard {
        boolean allow(File pluginDir);

        /** An existing source approval never implies approval of different copied bytes. */
        default boolean allowCopyTarget(File sourceDir, File copiedTarget) {
            return false;
        }
    }

    public static final class Result {
        public final boolean ok;
        public final String message;
        /** Where the plugin was moved to, when it was moved. Null otherwise. */
        public final File location;

        public Result(boolean ok, String message) {
            this(ok, message, null);
        }

        public Result(boolean ok, String message, File location) {
            this.ok = ok;
            this.message = message;
            this.location = location;
        }
    }

    public static final class Item {
        public final File directory;
        public final String pluginId;
        public final String originalPath;
        public final String quarantinedAt;

        Item(File directory, String pluginId, String originalPath, String quarantinedAt) {
            this.directory = directory;
            this.pluginId = pluginId;
            this.originalPath = originalPath;
            this.quarantinedAt = quarantinedAt;
        }
    }

    public Quarantine(File store) {
        this.store = store;
    }

    public File store() {
        return store;
    }

    public String listingProblem() {
        return listingProblem;
    }

    private String storeProblem() {
        if (store.exists() && !store.isDirectory()) {
            return "The quarantine folder at " + store.getAbsolutePath() + " is not a directory, so"
                    + " nothing was done.";
        }
        try {
            if (store.exists() && isLink(store)) {
                return "The quarantine folder at " + store.getAbsolutePath() + " is a link to somewhere"
                        + " else, so nothing was done. Inspect it in MT Manager for manual recovery.";
            }
        } catch (IOException e) {
            return "The quarantine folder at " + store.getAbsolutePath() + " could not be resolved ("
                    + e.getMessage() + "), so nothing was done.";
        }
        return null;
    }

    private static final class ActionTraversal {
        private final ScanBudget budget = ScanBudget.interactive();
        private int entries;

        void visit() throws IOException {
            if (++entries > MAX_ACTION_ENTRIES || budget.exhausted()) {
                throw new IOException("directory safety check exceeded its entry or time limit");
            }
        }
    }

    /** Retained compatibility entry; management is delegated even when a guard approves. */
    public Result quarantine(File pluginDir, String ownPluginId) {
        return new Result(false, DELEGATED_MESSAGE);
    }

    public Result quarantine(File pluginDir, String ownPluginId, MoveGuard guard) {
        return new Result(false, DELEGATED_MESSAGE);
    }

    public Result restore(String identifier) {
        return new Result(false, DELEGATED_MESSAGE);
    }

    public Result purge(String identifier) {
        return new Result(false, DELEGATED_MESSAGE);
    }

    public List<Item> list() {
        final List<Item> out = new ArrayList<Item>();
        final ActionTraversal traversal = new ActionTraversal();
        listingProblem = storeProblem();
        if (listingProblem != null) {
            // Whatever is behind a linked store is not this plugin's to report as quarantined.
            return out;
        }
        if (!store.exists()) {
            return out;
        }
        if (!DirectoryListing.supportedFor(store)) {
            listingProblem = "The quarantine listing is unavailable (" + DirectoryListing.unsupportedReason()
                    + "); use MT Manager for manual recovery.";
            return out;
        }
        try {
            DirectoryListing.forEachChild(store, new DirectoryListing.Visitor() {
                @Override
                public void visit(File child) throws IOException {
                    traversal.visit();
                    if (!child.isDirectory()) {
                        return;
                    }
                    String pluginId = "";
                    String originalPath = "";
                    String stamp = "";
                    File info = new File(child, INFO_FILE);
                    if (info.isFile()) {
                        try {
                            InputStream in = new FileInputStream(info);
                            try {
                                java.util.Map<String, Object> parsed =
                                        Json.parseObject(Bytes.text(Bytes.readAtMost(in, 64 * 1024)));
                                pluginId = Json.str(parsed, "pluginId", "");
                                originalPath = Json.str(parsed, "originalPath", "");
                                stamp = Json.str(parsed, "quarantinedAt", "");
                            } finally {
                                in.close();
                            }
                        } catch (IOException e) {
                            // Fall through with whatever was read.
                        } catch (Json.JsonException e) {
                            // Fall through with whatever was read.
                        }
                    }
                    out.add(new Item(child, pluginId, originalPath, stamp));
                }
            });
        } catch (IOException failure) {
            // A listing failure means "do not trust this as a quarantine list".
            listingProblem = "The quarantine listing was incomplete (" + failure.getMessage()
                    + "); use MT Manager for manual recovery.";
            return new ArrayList<Item>();
        }
        return out;
    }

    private static boolean isLink(File file) throws IOException {
        File parent = file.getParentFile();
        if (parent == null) {
            return false;
        }
        String expected = parent.getCanonicalPath() + File.separator + file.getName();
        return !expected.equals(file.getCanonicalPath());
    }
}
