package mt.safety.scanner.execution;

import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Focused lifecycle tests: no Android stubs or clocks are needed. */
public final class SingleFlightRegression {
    public static void main(String[] args) throws Exception {
        final AtomicReference<Runnable> delivery = new AtomicReference<Runnable>();
        Executor main = new Executor() {
            @Override public void execute(Runnable task) { delivery.set(task); }
        };
        SingleFlight worker = new SingleFlight(main);
        final CountDownLatch started = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final CountDownLatch ended = new CountDownLatch(1);
        final AtomicReference<String> value = new AtomicReference<String>();
        SingleFlight.Callback<String> callback = new SingleFlight.Callback<String>() {
            @Override public void completed(String result, Throwable error) {
                value.set(error == null ? result : "failed");
                ended.countDown();
            }
        };
        check(worker.submit(new Callable<String>() {
            @Override public String call() throws Exception {
                started.countDown();
                // Model a parser that does not stop when interrupted.
                boolean done = false;
                while (!done) {
                    try { release.await(); done = true; } catch (InterruptedException ignored) { }
                }
                return "ok";
            }
        }, callback), "first operation accepted");
        check(started.await(2, TimeUnit.SECONDS), "operation started off caller");
        check(!worker.submit(new Callable<String>() {
            @Override public String call() { throw new AssertionError("overlap"); }
        }, callback), "overlap rejected without queue");
        worker.cancel();
        check(worker.isBusy(), "cancel must not claim uninterruptible work stopped");
        check(!worker.submit(new Callable<String>() {
            @Override public String call() { return "overlap"; }
        }, callback), "cancel cannot free occupied worker");
        release.countDown();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (delivery.get() == null && System.nanoTime() < deadline) { Thread.yield(); }
        check(value.get() == null, "completion must use requested dispatcher");
        check(delivery.get() != null, "completion dispatched");
        delivery.getAndSet(null).run();
        check(ended.await(2, TimeUnit.SECONDS), "completion delivered");
        check("failed".equals(value.get()), "cancelled result must not be presented as complete");
        check(!worker.isBusy(), "slot released only when work ended");
        check(worker.submit(new Callable<String>() {
            @Override public String call() { throw new IllegalStateException("fixture failure"); }
        }, callback), "subsequent operation accepted");
        deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (delivery.get() == null && System.nanoTime() < deadline) { Thread.yield(); }
        check(delivery.get() != null, "failure dispatched");
        delivery.getAndSet(null).run();
        check("failed".equals(value.get()), "failure is explicit");
        System.out.println("PASS SingleFlightRegression (13 lifecycle assertions)");
    }
    private static void check(boolean ok, String label) {
        if (!ok) throw new AssertionError(label);
    }
}
