package mt.safety.scanner;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import mt.safety.scanner.core.Discovery;

/**
 * Works out where this device keeps its MT Manager plugins.
 *
 * <p>MT Manager's plugin documentation does not publish an installation path, and it differs between
 * versions, between Android versions and between rooted and unrooted devices. Guessing one absolute
 * path would mean a scanner that quietly reports "no plugins found" on most phones.
 *
 * <p>So the primary root is derived from the plugin's own directory instead. MT Manager hands each
 * plugin a private directory through {@code MTPluginContext.getFilesDir()}; the sibling directories of
 * its ancestors are where the other plugins live. Walking up from a path MT Manager itself provided is
 * correct by construction, whatever the layout happens to be. Known public locations are then added as
 * extra candidates, and anything unreadable is skipped.
 */
public final class MtEnvironment {

    /** How far up from our own files directory to look for the shared plugin area. */
    private static final int MAX_ASCENT = 4;

    private MtEnvironment() {
    }

    /**
     * Builds the list of directories to search.
     *
     * @param ownFilesDir the directory MT Manager gave this plugin, or null when unknown
     * @param extraRoot   an additional directory the user configured, or null
     */
    public static List<File> candidateRoots(File ownFilesDir, String extraRoot) {
        return candidateRoots(ownFilesDir, "bin.mt.plus", extraRoot);
    }

    /**
     * Builds the list of directories to search, starting from the host's own plugin folder.
     *
     * <p>On a device the installed plugins live at {@code /data/user/0/<host>/files/plugin/<id>/},
     * which is derived here from the host package name MT Manager reports about itself. The
     * ancestor walk and the public locations remain as fallbacks for layouts this has not seen.
     */
    public static List<File> candidateRoots(File ownFilesDir, String hostPackage, String extraRoot) {
        List<File> roots = new ArrayList<File>();

        if (hostPackage != null && hostPackage.matches("[A-Za-z0-9_.]+")) {
            addIfUseful(roots, "/data/user/0/" + hostPackage + "/files/plugin");
            addIfUseful(roots, "/data/data/" + hostPackage + "/files/plugin");
            addIfUseful(roots, "/data/user/0/" + hostPackage + "/files");
            addIfUseful(roots, "/data/data/" + hostPackage + "/files");
        }

        // Derived from a path MT Manager itself supplied: the reliable one.
        if (ownFilesDir != null) {
            File cursor = ownFilesDir;
            for (int i = 0; i < MAX_ASCENT && cursor != null; i++) {
                cursor = cursor.getParentFile();
                if (cursor != null && cursor.isDirectory() && cursor.canRead()) {
                    roots.add(cursor);
                }
            }
        }

        // Public locations worth a look. Most will not exist or not be readable; that is fine.
        addIfUseful(roots, "/storage/emulated/0/Android/data/bin.mt.plus");
        addIfUseful(roots, "/sdcard/Android/data/bin.mt.plus");
        addIfUseful(roots, "/storage/emulated/0/Android/data/bin.mt.plus.pro");
        addIfUseful(roots, "/data/data/bin.mt.plus");
        addIfUseful(roots, "/data/user/0/bin.mt.plus");

        // Where an .mtp file usually sits before it is installed.
        addIfUseful(roots, "/storage/emulated/0/Download");
        addIfUseful(roots, "/sdcard/Download");
        addIfUseful(roots, "/storage/emulated/0/MT2");
        addIfUseful(roots, "/sdcard/MT2");

        if (extraRoot != null && extraRoot.trim().length() > 0) {
            addIfUseful(roots, extraRoot.trim());
        }
        return dedupe(roots);
    }

    private static void addIfUseful(List<File> roots, String path) {
        File file = new File(path);
        if (file.isDirectory() && file.canRead()) {
            roots.add(file);
        }
    }

    /** Drops duplicates and any root already covered by an ancestor in the list. */
    private static List<File> dedupe(List<File> roots) {
        List<File> out = new ArrayList<File>();
        List<String> canonical = new ArrayList<String>();
        for (int i = 0; i < roots.size(); i++) {
            String path = canonicalPath(roots.get(i));
            boolean covered = false;
            for (int j = 0; j < canonical.size(); j++) {
                String existing = canonical.get(j);
                if (path.equals(existing) || path.startsWith(existing + File.separator)) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                canonical.add(path);
                out.add(roots.get(i));
            }
        }
        return out;
    }

    private static String canonicalPath(File file) {
        if (file == null) {
            return "";
        }
        try {
            return file.getCanonicalPath();
        } catch (java.io.IOException e) {
            return file.getAbsolutePath();
        }
    }

    /**
     * Finds plugin packages, leaving this scanner itself out of the results.
     *
     * <p>Self-exclusion is not vanity: the scanner's own source contains every string it looks for, so
     * scanning itself would produce a page of findings about the tool doing its job. The exclusion is by
     * plugin id, and it is stated in the report so nothing is hidden silently.
     */
    public static List<Discovery.Candidate> findPlugins(List<File> roots, String ownPluginId,
            File ownFilesDir) {
        // Excluded during the walk: the quarantine store lives here and would otherwise use up the
        // bounded number of directories discovery is willing to visit.
        List<Discovery.Candidate> found = new Discovery().find(roots, ownFilesDir);
        String ownArea = ownFilesDir == null ? "" : canonicalPath(ownFilesDir);
        List<Discovery.Candidate> out = new ArrayList<Discovery.Candidate>();
        for (int i = 0; i < found.size(); i++) {
            Discovery.Candidate candidate = found.get(i);
            if (ownPluginId != null && ownPluginId.length() > 0
                    && isSelf(candidate.path, ownPluginId)) {
                continue;
            }
            // This plugin's own directory holds the quarantine store, and a quarantined plugin still
            // looks exactly like an installed one. Without this, everything moved aside comes back in
            // the next report as though it were still installed, and a bulk action tries to quarantine
            // the quarantined copy.
            if (ownFilesDir != null && isUnder(candidate.path, ownArea)) {
                continue;
            }
            out.add(candidate);
        }
        return out;
    }

    /** True when {@code path} sits inside the directory whose canonical form is {@code area}. */
    private static boolean isUnder(File path, String area) {
        if (area == null || area.length() == 0) {
            return false;
        }
        String candidate = canonicalPath(path);
        return candidate.equals(area) || candidate.startsWith(area + File.separator);
    }

    /** True when a candidate is this scanner: same plugin id, or a directory named after it. */
    private static boolean isSelf(File path, String ownPluginId) {
        if (path.getName().equals(ownPluginId)) {
            return true;
        }
        return ownPluginId.equals(mt.safety.scanner.core.PluginManifest.readFrom(path).pluginId);
    }
}
