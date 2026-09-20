package mt.safety.scanner.core;

/**
 * Just enough calendar arithmetic to say how old a set of definitions is.
 *
 * <p>Deliberately dependency-free. {@code java.time} needs desugaring below Android API 26, and
 * {@code SimpleDateFormat} is locale- and timezone-sensitive in ways that would make "how many days
 * old" wrong for some users. This is plain integer arithmetic on a civil date, which is neither.
 */
public final class Dates {

    /** Returned when a date cannot be read. */
    public static final long UNKNOWN = Long.MIN_VALUE;

    private Dates() {
    }

    /**
     * Days since 1970-01-01 for an ISO {@code yyyy-MM-dd} date, or {@link #UNKNOWN}.
     *
     * <p>The civil-date algorithm, which is exact for any proleptic Gregorian date and needs no
     * lookup tables.
     */
    public static long epochDay(String isoDate) {
        if (isoDate == null || isoDate.length() < 10) {
            return UNKNOWN;
        }
        String text = isoDate.trim();
        if (text.length() < 10 || text.charAt(4) != '-' || text.charAt(7) != '-') {
            return UNKNOWN;
        }
        long year;
        int month;
        int day;
        try {
            year = Long.parseLong(text.substring(0, 4));
            month = Integer.parseInt(text.substring(5, 7));
            day = Integer.parseInt(text.substring(8, 10));
        } catch (NumberFormatException e) {
            return UNKNOWN;
        }
        if (month < 1 || month > 12 || day < 1 || day > 31) {
            return UNKNOWN;
        }
        long y = year - (month <= 2 ? 1 : 0);
        long era = (y >= 0 ? y : y - 399) / 400;
        long yearOfEra = y - era * 400;
        long dayOfYear = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
        long dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
        return era * 146097 + dayOfEra - 719468;
    }

    /**
     * Whole days from an ISO date until {@code nowMillis}, or {@link #UNKNOWN}.
     *
     * <p>Negative when the date is in the future, which is worth showing rather than hiding: a
     * definition file dated ahead of the device usually means the clock is wrong.
     */
    public static long daysSince(String isoDate, long nowMillis) {
        long then = epochDay(isoDate);
        if (then == UNKNOWN) {
            return UNKNOWN;
        }
        return Math.floorDiv(nowMillis, 86400000L) - then;
    }
}
