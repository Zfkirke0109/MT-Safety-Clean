package bin.mt.plugin.api;

import android.content.SharedPreferences;

import java.io.File;
import java.io.InputStream;

/**
 * Compile-only stub of MT Manager's plugin context (plugin SDK v2). Not shipped.
 *
 * <p>Mirrors the methods documented at <https://mt.cc/guide/plugin/api-plugin-context.html>.
 */
public interface MTPluginContext {

    String getPluginId();

    int getPluginVersionCode();

    String getPluginVersionName();

    SharedPreferences getPreferences();

    String getLanguage();

    String getCountry();

    String getLanguageCountry();

    LocalString getLocalString();

    LocalString getAssetLocalString(String name);

    LocalString getFileLocalString(File dir, String name);

    LocalString getLanguageNameLocalString();

    InputStream getAssetsAsStream(String name);

    File getFilesDir();

    void log(String message);

    void log(String message, Throwable error);

    void log(Throwable error);

    void showToast(String message);

    void showToastL(String message);
}
