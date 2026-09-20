package mt.safety.scanner.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The hashes a signature database asks for, computed in one pass over the data.
 *
 * <p>ClamAV hash signatures come in MD5, SHA-1 and SHA-256, and a database usually holds only one or
 * two of those. Computing only what is wanted matters on a phone: hashing every file three times over
 * would triple the cost of the step that dominates a file scan.
 */
public final class Digests {

    private final MessageDigest md5;
    private final MessageDigest sha1;
    private final MessageDigest sha256;
    private byte[] md5Result;
    private byte[] sha1Result;
    private byte[] sha256Result;

    public Digests(boolean wantMd5, boolean wantSha1, boolean wantSha256) {
        md5 = wantMd5 ? instance("MD5") : null;
        sha1 = wantSha1 ? instance("SHA-1") : null;
        sha256 = wantSha256 ? instance("SHA-256") : null;
    }

    /** True when at least one algorithm was asked for. */
    public boolean any() {
        return md5 != null || sha1 != null || sha256 != null;
    }

    public void update(byte[] data, int offset, int length) {
        if (md5 != null) {
            md5.update(data, offset, length);
        }
        if (sha1 != null) {
            sha1.update(data, offset, length);
        }
        if (sha256 != null) {
            sha256.update(data, offset, length);
        }
    }

    /** Finishes every digest; results are then available from the accessors. */
    public void finish() {
        md5Result = md5 == null ? null : md5.digest();
        sha1Result = sha1 == null ? null : sha1.digest();
        sha256Result = sha256 == null ? null : sha256.digest();
    }

    /** The raw MD5, or null when it was not wanted. */
    public byte[] md5() {
        return md5Result;
    }

    /** The raw SHA-1, or null when it was not wanted. */
    public byte[] sha1() {
        return sha1Result;
    }

    /** The raw SHA-256, or null when it was not wanted. */
    public byte[] sha256() {
        return sha256Result;
    }

    /** All wanted digests of a complete in-memory blob. */
    public static Digests of(byte[] data, boolean wantMd5, boolean wantSha1, boolean wantSha256) {
        Digests digests = new Digests(wantMd5, wantSha1, wantSha256);
        digests.update(data, 0, data.length);
        digests.finish();
        return digests;
    }

    private static MessageDigest instance(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algorithm + " unavailable", e);
        }
    }
}
