package bin.mt.plugin.api.preference;

import bin.mt.plugin.api.LocalString;
import bin.mt.plugin.api.MTPluginContext;

/**
 * Compile-only stub of MT Manager's preference-screen interface (plugin SDK v2). Not shipped.
 *
 * <p>Mirrors <https://mt.cc/guide/plugin/api-plugin-preference.html>. Builder and the option types are
 * nested here, which is how real plugins use them: an implementing class refers to {@code Builder}
 * unqualified, so the name has to come from the interface's own scope.
 */
public interface PluginPreference {

    void onBuild(MTPluginContext context, Builder builder);

    /** Assembles the screen. */
    interface Builder {
        void setLocalString(LocalString localString);

        void addHeader(String title);

        Text addText(String title);

        Input addInput(String title, String key);

        Switch addSwitch(String title, String key);

        List addList(String title, String key);
    }

    /** A read-only row. */
    interface Text {
        Text summary(String summary);

        Text url(String url);
    }

    /** A text entry row. */
    interface Input {
        Input defaultValue(String defaultValue);

        Input summary(String summary);

        Input valueAsSummary();

        Input inputType(int inputType);

        Input validator(Validator validator);

        /** Returns null to accept a value, or a message to reject it. */
        interface Validator {
            String validate(String value);
        }
    }

    /** An on/off row. */
    interface Switch {
        Switch defaultValue(boolean defaultValue);

        Switch summary(String summary);

        Switch summaryOn(String summary);

        Switch summaryOff(String summary);
    }

    /** A single-choice row. */
    interface List {
        List defaultValue(String defaultValue);

        List summary(String summary);

        Item addItem(String name, String value);

        /** One choice. */
        interface Item {
            Item summary(String summary);

            Item addItem(String name, String value);
        }
    }
}
