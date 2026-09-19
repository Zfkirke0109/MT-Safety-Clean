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
     * Why the quarantine store must not be used, or {@code null} when it is sound.
     *
     * <p>The link checks elsewhere cover the plugin being moved and the entries already held. The store
     * itself was the gap: replace {@code filesDir/quarantine} with a link and every plugin this tool
     * moves aside lands wherever that link points, {@code list} reads whatever is sitting there as
     * though it were quarantined, and {@code restore} will copy it back out to a path taken from an
     * {@code .info} file someone else wrote. Nothing downstream can recover from that, so it is refused
     * at the door.
     *
     * <p>A linked ancestor is still fine, and has to be: on Android {@code /sdcard} is itself a link to
     * {@code /storage/emulated/0}. Only the last path component is in question.
     */
    private String storeProblem() {
        try {
            if (store.exists() && isLink(store)) {
                return "The quarantine folder at " + store.getAbsolutePath() + " is a link to somewhere"
                        + " else, so nothing was done. Delete or inspect it by hand before using"
                        + " quarantine again.";
            }
        } catch (IOException e) {
            return "The quarantine folder at " + store.getAbsolutePath() + " could not be resolved ("
                    + e.getMessage() + "), so nothing was done.";
        }
        return null;
    }

    /**
     * Moves {@code pluginDir} into the quarantine store.
     *
     * <p>Refuses anything that is not recognisably an installed plugin, and refuses to act on itself,
     * so a mistyped command cannot take out the scanner or an unrelated folder.
     */
    public Result quarantine(File pluginDir, String ownPluginId) {
        String storeProblem = storeProblem();
        if (storeProblem != null) {
            return new Result(false, storeProblem);
        }
        if (pluginDir == null || !pluginDir.isDirectory()) {
            return new Result(false, "Not a directory: " + pluginDir);
        }
        File manifest = new File(pluginDir, "manifest.json");
        if (!manifest.isFile()) {
            return new Result(false, "No manifest.json here, so this is not an installed plugin: "
                    + pluginDir.getName());
        }
        // A cross-volume move falls back to copy-then-delete, and a directory link inside the plugin
        // would take that delete outside the plugin entirely. This is a tool for removing hostile
        // plugins, so a hostile plugin planting such a link is the expected case, not a freak one.
        String escaping = findEscapingLink(pluginDir);
        if (escaping != null) {
            return new Result(false, "This plugin contains a link pointing outside its own folder ("
                    + escaping + "). Moving it could affect files elsewhere, so nothing was done."
                    + " Inspect it by hand.");
        }
        String pluginId = readPluginId(manifest);
        if (ownPluginId != null && ownPluginId.equals(pluginId)) {
            return new Result(false, "That is this scanner. Uninstall it from MT Manager's plugin list"
                    + " if you want it gone.");
        }
        if (!store.isDirectory() && !store.mkdirs()) {
            return new Result(false, "Could not create the quarantine folder at " + store.getAbsolutePath());
        }

        // A bulk action moves several plugins in a tight loop, so the timestamp alone is not unique:
        // two plugins with the same directory name can land in the same millisecond, and the copy
        // fallback would then write into an existing quarantine directory and merge the two.
        File target = freeDestination(pluginDir.getName());
        if (target == null) {
            return new Result(false, "Could not find a free name in the quarantine folder for "
                    + pluginDir.getName());
        }
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

        if (!writeInfo(target, pluginId, originalPath)) {
            // Without the note there is nothing recording where this came from, so "use restore" would
            // be a promise the quarantine cannot keep. Say where it went instead.
            return new Result(true, "Moved " + (pluginId.length() > 0 ? pluginId : pluginDir.getName())
                    + " to " + target.getAbsolutePath() + ", but its restore note could not be written,"
                    + " so it cannot be restored automatically. Move it back by hand if you need it.",
                    target);
        }
        return new Result(true, "Quarantined " + (pluginId.length() > 0 ? pluginId : pluginDir.getName())
                + ". Restart MT Manager, then check its plugin list. Use \"restore\" to undo.", target);
    }

    /** Puts a quarantined plugin back where it came from. */
    public Result restore(String identifier) {
        String storeProblem = storeProblem();
        if (storeProblem != null) {
            return new Result(false, storeProblem);
        }
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
                // The plugin is back either way, but a copy left behind is worth saying out loud:
                // silence here would leave the user with a duplicate they never hear about.
                if (!deleteTree(item.directory, 0)) {
                    return new Result(true, "Restored to " + item.originalPath
                            + ", but the quarantined copy could not be removed. Delete it with"
                            + " \"purge " + item.directory.getName() + "\". Restart MT Manager.");
                }
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
        String storeProblem = storeProblem();
        if (storeProblem != null) {
            return new Result(false, storeProblem);
        }
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
        if (storeProblem() != null) {
            // Whatever is behind a linked store is not this plugin's to report as quarantined.
            return out;
        }
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

    private boolean writeInfo(File directory, String pluginId, String originalPath) {
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
            return true;
        } catch (IOException e) {
            return false;
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

    /** An unused directory inside the store, or null when even the suffixed names are taken. */
    private File freeDestination(String sourceName) {
        String base = System.currentTimeMillis() + "-" + safeName(sourceName);
        File candidate = new File(store, base);
        for (int suffix = 2; candidate.exists() && suffix < 1000; suffix++) {
            candidate = new File(store, base + "-" + suffix);
        }
        return candidate.exists() ? null : candidate;
    }

    private static String safeName(String name) {
        StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            sb.append(Character.isLetterOrDigit(c) || c == '.' || c == '_' || c == '-' ? c : '_');
        }
        return sb.length() == 0 ? "plugin" : sb.toString();
    }

    /**
     * Returns the first entry that resolves outside {@code root}, or null when there is none.
     *
     * <p>{@code java.nio.file} is unavailable on the Android versions this supports, so a link is
     * identified the same way the scanner identifies one: by comparing canonical paths.
     */
    private static String findEscapingLink(File root) {
        try {
            if (isLink(root)) {
                return root.getName();
            }
            return walkForEscape(root, root.getCanonicalPath(), 0);
        } catch (IOException e) {
            // If the tree cannot even be resolved, treat it as unsafe to move.
            return root.getName();
        }
    }

    /**
     * True when {@code file}'s own last path component is a link.
     *
     * <p>Compared against the canonical form of its parent rather than against its own absolute path,
     * because a plugin's real location routinely sits under a linked ancestor: on Android
     * {@code /sdcard} is itself a link to {@code /storage/emulated/0}, so rejecting anything whose
     * canonical path differs from its absolute path would refuse nearly every genuine plugin. What
     * matters is whether this directory is a door to somewhere else, not whether the road to it was.
     */
    private static boolean isLink(File file) throws IOException {
        File parent = file.getParentFile();
        if (parent == null) {
            return false;
        }
        String expected = parent.getCanonicalPath() + File.separator + file.getName();
        return !expected.equals(file.getCanonicalPath());
    }

    private static String walkForEscape(File dir, String rootCanonical, int depth) throws IOException {
        if (depth > MAX_DEPTH) {
            return dir.getName();
        }
        File[] children = dir.listFiles();
        if (children == null) {
            return null;
        }
        for (int i = 0; i < children.length; i++) {
            File child = children[i];
            String canonical = child.getCanonicalPath();
            if (!canonical.equals(rootCanonical) && !canonical.startsWith(rootCanonical + File.separator)) {
                return child.getName();
            }
            if (child.isDirectory()) {
                String found = walkForEscape(child, rootCanonical, depth + 1);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
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

    /**
     * Deletes a tree, refusing to treat a linked root as the root.
     *
     * <p>Taking the canonical path of {@code file} as the boundary is only correct once {@code file} is
     * known not to be a link itself. If it is, its target becomes the boundary, every child of that
     * target then tests as inside it, and the recursion deletes somewhere else entirely. A quarantine
     * entry replaced by a link to {@code /sdcard/DCIM} would have taken the photo library with it. The
     * link is removed as the link it is; whatever it points at is left alone.
     */
    private static boolean deleteTree(File file, int depth) {
        if (file == null) {
            return false;
        }
        try {
            if (isLink(file)) {
                return file.delete();
            }
        } catch (IOException e) {
            // Unresolvable means unverifiable. Deleting the name alone is the only safe move left.
            return file.delete();
        }
        return deleteTree(file, canonicalOrNull(file), depth);
    }

    /**
     * Deletes a tree without following anything that leaves it.
     *
     * <p>A child resolving outside the root is deleted as the link it is, never descended into:
     * deleting through a link would take files with it that were never part of what was removed.
     */
    private static boolean deleteTree(File file, String rootCanonical, int depth) {
        if (file == null || !file.exists() || depth > MAX_DEPTH) {
            return false;
        }
        if (file.isDirectory() && !escapes(file, rootCanonical)) {
            File[] children = file.listFiles();
            if (children != null) {
                for (int i = 0; i < children.length; i++) {
                    deleteTree(children[i], rootCanonical, depth + 1);
                }
            }
        }
        return file.delete();
    }

    private static boolean escapes(File file, String rootCanonical) {
        if (rootCanonical == null) {
            return true;
        }
        String canonical = canonicalOrNull(file);
        if (canonical == null) {
            return true;
        }
        return !canonical.equals(rootCanonical) && !canonical.startsWith(rootCanonical + File.separator);
    }

    private static String canonicalOrNull(File file) {
        try {
            return file.getCanonicalPath();
        } catch (IOException e) {
            return null;
        }
    }
}
