package mt.safety.scanner.core;

/** How much of a package the scan actually inspected, independent of what it found. */
public enum Coverage {

    /** Everything the scanner is meant to read was read. */
    COMPLETE("Complete"),
    /** A budget, size cap or read failure stopped the scan early; absence of findings proves less. */
    PARTIAL("Partial"),
    /** The package could not be opened, or uses a format the scanner cannot read. */
    UNSUPPORTED_OR_UNREADABLE("Unsupported or unreadable");

    private final String label;

    Coverage(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
