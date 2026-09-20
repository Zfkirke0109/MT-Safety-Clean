package mt.safety.scanner.core;

import java.util.List;
import java.util.Map;

/**
 * Applies a loaded signature database to one member of a package.
 *
 * <p>Runs inside the same member loop as the pattern rules, so each member is read once. A hash
 * signature needs the whole member, so it is only tried when the read was complete; a byte pattern
 * is tried against whatever was read, since a pattern near the start of a large member is still a
 * pattern.
 *
 * <p>A match is reported by the signature's own name, which is the only description the database
 * carries. That name is data from a file the user imported, and is shown as such.
 */
public final class SignatureRules {

    /** Distinct patterns reported per member; one is usually enough to say what it is. */
    private static final int MAX_PATTERN_HITS = 3;

    private SignatureRules() {
    }

    /**
     * Checks one member against the database and records findings on the report.
     *
     * @param complete true when {@code data} holds the entire member, so a whole-file hash is valid
     */
    public static void match(ScanReport report, Map<String, Signal> byRule, PluginPackage.Entry entry,
            byte[] data, boolean complete, SignatureDatabase signatures) {
        if (signatures == null || signatures.isEmpty() || data == null || data.length == 0) {
            return;
        }
        Digests digests = null;
        if (complete && signatures.wantsHashes()) {
            digests = signatures.digest(data);
            if (signatures.isKnownClean(digests, data.length)) {
                return;
            }
            SignatureDatabase.Match hit = signatures.matchHash(digests, data.length);
            if (hit != null) {
                report(report, byRule, entry, hit);
                // A hash names the exact file; a pattern hit on the same bytes adds nothing.
                return;
            }
        }
        int fileType = SignatureDatabase.fileType(data, entry.extension());
        List<SignatureDatabase.Match> hits = signatures.matchPatterns(data, fileType, MAX_PATTERN_HITS);
        for (int i = 0; i < hits.size(); i++) {
            report(report, byRule, entry, hits.get(i));
        }
    }

    private static void report(ScanReport report, Map<String, Signal> byRule, PluginPackage.Entry entry,
            SignatureDatabase.Match hit) {
        Signal signal;
        if (hit.pua) {
            signal = CodeRules.signalFor(report, byRule, "SIG003", Category.SIGNATURE, Severity.HIGH,
                    "Matches a potentially-unwanted-program signature",
                    "A PUA signature from the database you loaded matched. ClamAV uses these for adware,"
                            + " riskware and tools that are not malware outright but that most people"
                            + " would not want installed unknowingly.");
        } else if (hit.hash) {
            signal = CodeRules.signalFor(report, byRule, "SIG001", Category.SIGNATURE, Severity.CRITICAL,
                    "Matches a known-malware hash signature",
                    "The file's checksum is listed in a signature database you loaded, in ClamAV's"
                            + " format. A hash identifies one exact file that has been seen and"
                            + " classified before, so this is as close to certainty as a scanner gets.");
        } else {
            signal = CodeRules.signalFor(report, byRule, "SIG002", Category.SIGNATURE, Severity.CRITICAL,
                    "Matches a known-malware byte pattern",
                    "A byte sequence from a signature database you loaded, in ClamAV's format, appears"
                            + " in this file. The signature's name says what it was written to catch."
                            + " Patterns can occasionally match an innocent file, so read the name.");
        }
        signal.withEvidence(entry.name, hit.name);
    }
}
