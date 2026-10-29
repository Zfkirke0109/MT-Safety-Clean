package mt.safety.scanner.core;

/**
 * The kind of behaviour a finding describes.
 *
 * <p>Categories let {@link RiskScorer} consider capabilities across the whole package, not just the
 * raw score. Sensitive-data and network indicators may warrant review together, but their
 * co-occurrence does not establish that any data was transferred.
 */
public enum Category {

    MANIFEST("Package metadata"),
    ARCHIVE("Package structure"),
    COMMAND_EXEC("Shell and root commands"),
    DYNAMIC_CODE("Loading code from outside the package"),
    NETWORK("Network access"),
    SENSITIVE_DATA("Access to private or credential data"),
    DEVICE_IDENTITY("Device and user identifiers"),
    CROSS_PLUGIN("Reaching into MT Manager or other plugins"),
    DESTRUCTIVE("Deleting or encrypting user files"),
    OBFUSCATION("Hidden or encoded payloads"),
    EVASION("Anti-analysis behaviour"),
    PERSISTENCE("Writing installable or executable files"),
    RECON("Screen, clipboard and accessibility capture"),
    PROVENANCE("Identity and trust of the package"),
    SIGNATURE("Known malware signatures");

    private final String label;

    Category(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
