package mt.safety.scanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import mt.safety.scanner.core.Bytes;
import mt.safety.scanner.core.Json;
import mt.safety.scanner.core.PluginManifest;

/**
 * Moves a plugin out of the way without destroying it.
 *
 * <p>Deleting is the wrong default for three reasons: MT Manager keeps its own record of installed
 * plugins and removing files underneath it can leave that record inconsistent; a plugin the user was
 * wrong about is gone for good; and a plugin worth reporting to others is evidence. So quarantine moves
 * the plugin's directory into this scanner's own storage, records where it came from, and can put it
 * back.
 *
 * <p>The recommended route is still MT Manager's own plugin management screen, which uninstalls
 * cleanly. Quarantine is for the cases that route does not cover: a plugin that misbehaves on load, or
 * one the user wants preserved before removal.
 */
public final class Quarantine {

    private static final String INFO_FILE = "quarantine-info.json";
    private static final int MAX_DEPTH = 24;

    /** What happened, in a sentence fit to show the user. */
    public static final class Result {
        public final boolean ok;
        public final String message;

        Result(boolean ok, String message) {
            this.ok = ok;
            this.message = message;
        }
    }

    /** A quarantined plugin. */
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

    private final File store;

    /**
     * @param store a directory this plugin owns, normally a subdirectory of
     *              {@code MTPluginContext.getFilesDir()}
     */
    public Quarantine(File store) {
        this.store = store;
    }

    public File store() {
        return store;
    }

    /**
     * Moves {@code pluginDir} into the quarantine store.
     *
     * <p>Refuses anything that is not recognisably an installed plugin, and refuses to act on itself,
     * so a mistyped command cannot take out the scanner or an unrelated folder.
     */
    public Result quarantine(File pluginDir, String ownPluginId) {
        if (pluginDir == null || !pluginDir.isDirectory()) {
            return new Result(false, "Not a directory: " + pluginDir);
        }
        File manifest = new File(pluginDir, "manifest.json");
        if (!manifest.isFile()) {
            return new Result(false, "No manifest.json here, so this is not an installed plugin: "
                    + pluginDir.getName());
        }
        String pluginId = readPluginId(manifest);
        if (ownPluginId != null && ownPluginId.equals(pluginId)) {
            return new Result(false, "That is this scanner. Uninstall it from MT Manager's plugin list"
                    + " if you want it gone.");
        }
        if (!store.isDirectory() && !store.mkdirs()) {
            return new Result(false, "Could not create the quarantine folder at " + store.getAbsolutePath());
        }

        String stamp = Long.toString(System.currentTimeMillis());
        File target = new File(store, stamp + "-" + safeName(pluginDir.getName()));
        String originalPath = pluginDir.getAbsolutePath();

        boolean moved = pluginDir.renameTo(target);
        if (!moved) {
            // A rename across storage volumes fails, so fall back to copying and then removing.
            try {
                copyTree(pluginDir, target, 0);
            } catch (IOException e) {
                deleteTree(target, 0);
                return new Result(false, "Could not move the plugin: " + e.getMessage());
            }
            if (!deleteTree(pluginDir, 0)) {
                return new Result(false, "Copied the plugin to quarantine but could not remove the original"
                        + " at " + originalPath + ". Remove it from MT Manager's plugin list instead.");
            }
        }

        writeInfo(target, pluginId, originalPath);
        return new Result(true, "Quarantined " + (pluginId.length() > 0 ? pluginId : pluginDir.getName())
                + ". Restart MT Manager, then check its plugin list. Use \"restore\" to undo.");
    }

    /** Puts a quarantined plugin back where it came from. */
    public Result restore(String identifier) {
        List<Item> items = list();
        for (int i = 0; i < items.size(); i++) {
            Item item = items.get(i);
            if (!matches(item, identifier)) {
                continue;
            }
            File destination = new File(item.originalPath);
            if (destination.exists()) {
                return new Result(false, "Something already exists at " + item.originalPath
                        + ". Move it aside first.");
            }
            File parent = destination.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                return new Result(false, "Could not recreate " + parent.getAbsolutePath());
            }
            new File(item.directory, INFO_FILE).delete();
            if (item.directory.renameTo(destination)) {
                return new Result(true, "Restored to " + item.originalPath + ". Restart MT Manager.");
            }
            try {
                copyTree(item.directory, destination, 0);
                deleteTree(item.directory, 0);
                return new Result(true, "Restored to " + item.originalPath + ". Restart MT Manager.");
            } catch (IOException e) {
                // Leave nothing half-written at the destination: MT Manager would try to load it, and
                // the next restore attempt would refuse because something already exists there.
                deleteTree(destination, 0);
                writeInfo(item.directory, item.pluginId, item.originalPath);
                return new Result(false, "Could not restore: " + e.getMessage()
                        + ". The plugin is still in quarantine and nothing was left behind.");
            }
        }
        return new Result(false, "Nothing in quarantine matches \"" + identifier + "\".");
    }

    /** Permanently deletes a quarantined plugin. */
    public Result purge(String identifier) {
        List<Item> items = list();
        for (int i = 0; i < items.size(); i++) {
            Item item = items.get(i);
            if (!matches(item, identifier)) {
                continue;
            }
            if (deleteTree(item.directory, 0)) {
                return new Result(true, "Deleted " + item.directory.getName() + " permanently.");
            }
            return new Result(false, "Could not delete " + item.directory.getAbsolutePath());
        }
        return new Result(false, "Nothing in quarantine matches \"" + identifier + "\".");
    }

    /** Everything currently held in quarantine. */
    public List<Item> list() {
        List<Item> out = new ArrayList<Item>();
        File[] children = store.listFiles();
        if (children == null) {
            return out;
        }
        for (int i = 0; i < children.length; i++) {
            File child = children[i];
            if (!child.isDirectory()) {
                continue;
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
        return out;
    }

    private boolean matches(Item item, String identifier) {
        if (identifier == null || identifier.length() == 0) {
            return false;
        }
        return identifier.equals(item.pluginId) || identifier.equals(item.directory.getName())
                || item.directory.getName().endsWith("-" + identifier);
    }

    private void writeInfo(File directory, String pluginId, String originalPath) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"pluginId\": ").append(Json.quote(pluginId)).append(",\n");
        sb.append("  \"originalPath\": ").append(Json.quote(originalPath)).append(",\n");
        sb.append("  \"quarantinedAt\": ").append(Json.quote(String.valueOf(System.currentTimeMillis())));
        sb.append("\n}\n");
        try {
            OutputStream out = new FileOutputStream(new File(directory, INFO_FILE));
            try {
                out.write(sb.toString().getBytes("UTF-8"));
            } finally {
                out.close();
            }
        } catch (IOException e) {
            // Losing the note only costs the ability to restore automatically.
        }
    }

    private String readPluginId(File manifest) {
        try {
            InputStream in = new FileInputStream(manifest);
            try {
                return PluginManifest.parse(Bytes.readAtMost(in, 512 * 1024)).pluginId;
            } finally {
                in.close();
            }
        } catch (IOException e) {
            return "";
        }
    }

    private static String safeName(String name) {
        StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            sb.append(Character.isLetterOrDigit(c) || c == '.' || c == '_' || c == '-' ? c : '_');
        }
        return sb.length() == 0 ? "plugin" : sb.toString();
    }

    private static void copyTree(File from, File to, int depth) throws IOException {
        if (depth > MAX_DEPTH) {
            throw new IOException("directory nested too deeply: " + from.getName());
        }
        if (from.isDirectory()) {
            if (!to.isDirectory() && !to.mkdirs()) {
                throw new IOException("could not create " + to.getAbsolutePath());
            }
            File[] children = from.listFiles();
            if (children == null) {
                return;
            }
            for (int i = 0; i < children.length; i++) {
                copyTree(children[i], new File(to, children[i].getName()), depth + 1);
            }
            return;
        }
        InputStream in = new FileInputStream(from);
        try {
            OutputStream out = new FileOutputStream(to);
            try {
                byte[] buffer = new byte[1 << 16];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
    }

    private static boolean deleteTree(File file, int depth) {
        if (file == null || !file.exists() || depth > MAX_DEPTH) {
            return false;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (int i = 0; i < children.length; i++) {
                    deleteTree(children[i], depth + 1);
                }
            }
        }
        return file.delete();
    }
}
