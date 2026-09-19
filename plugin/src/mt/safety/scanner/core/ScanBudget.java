package mt.safety.scanner.core;

/**
 * Bounds the work a single scan may do.
 *
 * <p>The scan runs on MT Manager's UI thread when the plugin's settings screen is opened, and the
 * packages it reads are untrusted: a plugin can trivially ship a 2 GB asset or a zip bomb. Every
 * read goes through a budget so a hostile or merely huge package degrades into a truncated report
 * instead of freezing MT Manager.
 */
public final class ScanBudget {

    private final long timeLimitMs;
    private final long deadlineMs;
    private final long maxBytes;
    private long bytesUsed;
    private boolean truncated;

    /** A budget suited to an interactive scan: bounded wall clock and bounded bytes read. */
    public static ScanBudget interactive() {
        return new ScanBudget(4000L, 24L * 1024 * 1024);
    }

    /** A deep scan, for when the user explicitly asks for one. */
    public static ScanBudget deep() {
        return new ScanBudget(20000L, 256L * 1024 * 1024);
    }

    /** An effectively unlimited budget, for offline command line use and tests. */
    public static ScanBudget unlimited() {
        return new ScanBudget(Long.MAX_VALUE / 4, Long.MAX_VALUE / 4);
    }

    public ScanBudget(long timeLimitMs, long maxBytes) {
        this.timeLimitMs = timeLimitMs;
        this.deadlineMs = now() + timeLimitMs;
        this.maxBytes = maxBytes;
    }

    /**
     * A new budget with the same limits, its clock starting now.
     *
     * <p>Used to give each package in a set its own allowance, so one large plugin cannot consume the
     * whole scan and leave the rest of the list unexamined.
     */
    public ScanBudget fresh() {
        return new ScanBudget(timeLimitMs, maxBytes);
    }

    /** True once the time or byte budget is gone; callers should stop reading and report. */
    public boolean exhausted() {
        if (bytesUsed >= maxBytes || now() > deadlineMs) {
            truncated = true;
            return true;
        }
        return false;
    }

    /**
     * Reserves {@code bytes} of the read budget.
     *
     * @return the number of bytes the caller may actually read, possibly 0
     */
    public int reserve(int bytes) {
        if (exhausted()) {
            return 0;
        }
        long remaining = maxBytes - bytesUsed;
        if (remaining <= 0) {
            truncated = true;
            return 0;
        }
        int granted = (int) Math.min((long) bytes, remaining);
        bytesUsed += granted;
        if (granted < bytes) {
            truncated = true;
        }
        return granted;
    }

    /** True when any part of the scan was cut short; the report says so. */
    public boolean wasTruncated() {
        return truncated;
    }

    /**
     * How many bytes a structural archive walk may inflate before it gives up.
     *
     * <p>Advancing through an archive inflates each member whether or not anything reads it, so this is
     * the bound that stops a zip bomb. It is derived from the read allowance rather than fixed: a walk
     * permitted to inflate half a gigabyte inside an interactive scan that allows 24 MB of reading was
     * never in proportion to it, and a fixed constant could not be exercised by a test without a
     * fixture that size.
     *
     * <p>Generous relative to the allowance, because inflating is cheaper than the rules that follow
     * and an ordinary package must not trip this. The ceiling is what keeps an unlimited budget from
     * meaning an unlimited walk.
     */
    public long walkInflationCap() {
        if (maxBytes >= WALK_INFLATION_CEILING / WALK_INFLATION_FACTOR) {
            return WALK_INFLATION_CEILING;
        }
        return Math.max(maxBytes * WALK_INFLATION_FACTOR, WALK_INFLATION_FLOOR);
    }

    private static final long WALK_INFLATION_FACTOR = 8L;
    private static final long WALK_INFLATION_CEILING = 512L * 1024 * 1024;
    private static final long WALK_INFLATION_FLOOR = 256L * 1024;

    /** Marks the scan as incomplete without consuming budget. */
    public void markTruncated() {
        truncated = true;
    }

    public long bytesUsed() {
        return bytesUsed;
    }

    private static long now() {
        return System.currentTimeMillis();
    }
}
