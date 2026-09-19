package android.content;

import java.util.Map;
import java.util.Set;

/** Compile-only stub of Android's SharedPreferences. Not shipped. */
public interface SharedPreferences {

    String getString(String key, String defaultValue);

    Set<String> getStringSet(String key, Set<String> defaultValues);

    int getInt(String key, int defaultValue);

    long getLong(String key, long defaultValue);

    float getFloat(String key, float defaultValue);

    boolean getBoolean(String key, boolean defaultValue);

    boolean contains(String key);

    Map<String, ?> getAll();

    Editor edit();

    /** Compile-only stub of SharedPreferences.Editor. */
    interface Editor {
        Editor putString(String key, String value);

        Editor putInt(String key, int value);

        Editor putLong(String key, long value);

        Editor putFloat(String key, float value);

        Editor putBoolean(String key, boolean value);

        Editor remove(String key);

        Editor clear();

        boolean commit();

        void apply();
    }
}
