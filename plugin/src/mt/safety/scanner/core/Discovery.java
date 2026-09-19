package mt.safety.scanner.core;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Finds plugin packages to scan.
 *
 * <p>MT Manager's documentation does not state where installed plugins live on disk, and the location
 * has moved between versions and between rooted and unrooted devices. Rather than hard-coding one path
 * and silently finding nothing, discovery is content-based: a directory containing {@code manifest.json}
 * with a {@code pluginID} is an installed plugin, and a {@code .mtp} file is one waiting to be
 * installed. Candidate roots are searched; unreadable ones are skipped without complaint, because on an
 * unrooted device most of them will be.
 */
public final class Discovery {

    /** How deep to search below each root before giving up. */
    private static final int MAX_DEPTH = 5;
    private static final int MAX_RESULTS = 200;
    private static final int MAX_VISITS = 6000;

    /** A discovered candidate. */
    public static final class Candidate {
        public final File path;
        public final boolean installed;

        Candidate(File path, boolean installed) {
            this.path = path;
            this.installed = installed;
        }
    }

    private int visits;

    /** Searches every readable root and returns the plugin packages found, de-duplicated. */
    public List<Candidate> find(List<File> roots) {
        List<Candidate> found = new ArrayList<Candidate>();
        Set<String> seen = new HashSet<String>();
        visits = 0;
        for (int i = 0; i < roots.size(); i++) {
            File root = roots.get(i);
            if (root == null || !root.exists() || !root.canRead()) {
                continue;
            }
            walk(root, 0, found, seen);
        }
        Collections.sort(found, new Comparator<Candidate>() {
            @Override
            public int compare(Candidate a, Candidate b) {
                if (a.installed != b.installed) {
                    return a.installed ? -1 : 1;
                }
                return a.path.getName().compareToIgnoreCase(b.path.getName());
            }
        });
        return found;
    }

    private void walk(File dir, int depth, List<Candidate> found, Set<String> seen) {
        if (depth > MAX_DEPTH || found.size() >= MAX_RESULTS || ++visits > MAX_VISITS) {
            return;
        }
        if (isInstalledPlugin(dir)) {
            record(dir, true, found, seen);
            // An installed plugin's own subdirectories are part of it, not further plugins.
            return;
        }
        File[] children = dir.listFiles();
        if (children == null) {
            return;
        }
        for (int i = 0; i < children.length; i++) {
            File child = children[i];
            if (child.isDirectory()) {
                walk(child, depth + 1, found, seen);
            } else if (isPackageFile(child)) {
                record(child, false, found, seen);
            }
        }
    }

    private void record(File path, boolean installed, List<Candidate> found, Set<String> seen) {
        try {
            String key = path.getCanonicalPath();
            if (seen.add(key)) {
                found.add(new Candidate(path, installed));
            }
        } catch (java.io.IOException e) {
            found.add(new Candidate(path, installed));
        }
    }

    /** True for a directory that holds a plugin manifest naming a pluginID. */
    public static boolean isInstalledPlugin(File dir) {
        File manifest = new File(dir, "manifest.json");
        if (!manifest.isFile() || manifest.length() > 512 * 1024) {
            return false;
        }
        try {
            java.io.InputStream in = new java.io.FileInputStream(manifest);
            try {
                byte[] data = Bytes.readAtMost(in, 512 * 1024);
                PluginManifest parsed = PluginManifest.parse(data);
                // A broken manifest still marks this as a plugin directory: it is exactly the case the
                // user needs told about, and skipping it would hide it from the report.
                return !parsed.usable() || parsed.pluginId.length() > 0
                        || parsed.sdkVersion > 0 || !parsed.interfaces.isEmpty();
            } finally {
                PluginPackage.closeQuietly(in);
            }
        } catch (java.io.IOException e) {
            return false;
        }
    }

    /** True for a file that is an MT plugin package by name. */
    public static boolean isPackageFile(File file) {
        String name = file.getName().toLowerCase(java.util.Locale.US);
        return file.isFile() && file.length() > 0 && name.endsWith(".mtp");
    }
}
