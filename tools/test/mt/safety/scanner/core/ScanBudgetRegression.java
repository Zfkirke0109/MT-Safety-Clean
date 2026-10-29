package mt.safety.scanner.core;

/** Boundary checks for byte grants, cancellation propagation and monotonic time allowances. */
public final class ScanBudgetRegression {
    private static int checks;
    private ScanBudgetRegression() { }
    private static void check(boolean ok, String why) {
        checks++; if (!ok) throw new AssertionError(why);
    }
    public static void main(String[] args) {
        ScanBudget exact = new ScanBudget(10000, 1);
        check(exact.reserve(1) == 1, "exact grant");
        check(!exact.stopped(), "reserved bytes do not revoke the granted read");
        check(exact.exhausted() && exact.reserve(1) == 0, "subsequent reads stop at cap");
        ScanBudget source = new ScanBudget(10000, 100);
        ScanBudget before = source.fresh(); source.cancel();
        check(source.stopped() && before.stopped() && source.fresh().stopped(), "fresh budgets share cancellation");
        check(before.reserve(1) == 0 && before.wasTruncated(), "cancelled reads record partial");
        ScanBudget expired = new ScanBudget(0, 100);
        check(expired.stopped() && expired.wasTruncated(), "zero duration expires immediately");
        ScanBudget unlimited = ScanBudget.unlimited();
        check(!unlimited.stopped() && unlimited.reserve(1) == 1, "long durations do not overflow");
        ScanBudget interrupted = new ScanBudget(10000, 100);
        Thread.currentThread().interrupt();
        try {
            check(interrupted.stopped() && interrupted.reserve(1) == 0, "interrupt stops reads");
            check(Thread.currentThread().isInterrupted(), "interruption remains observable");
        } finally { Thread.interrupted(); }
        long used = unlimited.bytesUsed();
        try { unlimited.reserve(-1); throw new AssertionError("negative reservation accepted"); }
        catch (IllegalArgumentException expected) { check(unlimited.bytesUsed() == used, "negative reservation cannot mint allowance"); }
        try { new ScanBudget(-1, 1); throw new AssertionError("negative time accepted"); }
        catch (IllegalArgumentException expected) { check(true, "negative time rejected"); }
        try { new ScanBudget(1, -1); throw new AssertionError("negative bytes accepted"); }
        catch (IllegalArgumentException expected) { check(true, "negative bytes rejected"); }
        System.out.println(checks + " budget checks passed");
    }
}
