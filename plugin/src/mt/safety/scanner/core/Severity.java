package mt.safety.scanner.core;

/**
 * How much a single finding should move the needle.
 *
 * <p>The weights are the whole scoring model, so they are stated in one place. They are deliberately
 * non-linear: a plugin doing one medium-risk thing is usually just a plugin, while a plugin doing
 * one clearly hostile thing is enough on its own.
 */
public enum Severity {

    /** Context for the reader; contributes nothing to the score. */
    INFO(0, "Info"),
    /** Normal for some plugins; only interesting in combination. */
    LOW(3, "Low"),
    /** Capability a plugin rarely needs, worth the user's attention. */
    MEDIUM(10, "Medium"),
    /** Capability that is hard to justify in a file-manager plugin. */
    HIGH(25, "High"),
    /** Behaviour with no legitimate explanation; alone enough to condemn a plugin. */
    CRITICAL(60, "Critical");

    private final int weight;
    private final String label;

    Severity(int weight, String label) {
        this.weight = weight;
        this.label = label;
    }

    public int weight() {
        return weight;
    }

    public String label() {
        return label;
    }

    /** A short marker that survives MT Manager's plain-text preference rows. */
    public String marker() {
        switch (this) {
            case CRITICAL:
                return "[!!!]";
            case HIGH:
                return "[!! ]";
            case MEDIUM:
                return "[!  ]";
            case LOW:
                return "[.  ]";
            default:
                return "[   ]";
        }
    }

    public boolean atLeast(Severity other) {
        return ordinal() >= other.ordinal();
    }
}
