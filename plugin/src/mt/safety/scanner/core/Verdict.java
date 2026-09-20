package mt.safety.scanner.core;

/** The scanner's bottom line for one package. */
public enum Verdict {

    /** Content hash matches an entry the user themselves marked as trusted. */
    TRUSTED("Trusted", "You marked this exact version as trusted. Nothing to do."),
    /** Nothing of concern found. */
    CLEAN("Clean", "No risky behaviour found. Keep it."),
    /** Only ordinary capabilities, listed so the user knows what it can do. */
    REVIEW("Worth a look", "Nothing hostile, but it can do more than it may need. Keep it unless you do not recognise it."),
    /** A combination that deserves a decision from the user. */
    SUSPICIOUS("Suspicious", "Remove it unless you trust the author and know why it needs this."),
    /** Behaviour with no benign reading. */
    LIKELY_MALICIOUS("Likely malicious", "Remove this now, then change any password or key you opened on this device."),
    /** Matches the local denylist, or a known-malware signature the user loaded. */
    KNOWN_BAD("Known bad", "This matches a known-malware signature or an entry in your denylist. Remove it now."),
    /** The package could not be read. */
    UNREADABLE("Could not scan", "The package could not be read. Inspect it by hand before trusting it.");

    private final String label;
    private final String advice;

    Verdict(String label, String advice) {
        this.label = label;
        this.advice = advice;
    }

    public String label() {
        return label;
    }

    public String advice() {
        return advice;
    }

    /** True when the user should act on this package. */
    /** True for anything the scan flagged at all, "worth a look" included. */
    public boolean flagged() {
        return this == REVIEW || actionable();
    }

    public boolean actionable() {
        return this == SUSPICIOUS || this == LIKELY_MALICIOUS || this == KNOWN_BAD;
    }
}
