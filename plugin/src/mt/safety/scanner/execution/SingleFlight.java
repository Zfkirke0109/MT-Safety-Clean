package mt.safety.scanner.execution;

import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;

/** One bounded, non-queuing operation. Interruption never pretends that a worker has stopped. */
public final class SingleFlight {
    public interface Callback<T> { void completed(T result, Throwable error); }
    private final Executor dispatcher;
    private Thread active;
    private boolean cancelled;

    public SingleFlight(Executor dispatcher) { this.dispatcher = dispatcher; }
    public synchronized boolean isBusy() { return active != null; }
    public synchronized void cancel() {
        if (active != null) { cancelled = true; active.interrupt(); }
    }
    public synchronized <T> boolean submit(final Callable<T> operation, final Callback<T> callback) {
        if (active != null) return false;
        cancelled = false;
        active = new Thread(new Runnable() {
            @Override public void run() {
                T value = null;
                Throwable failure = null;
                try { value = operation.call(); }
                catch (Throwable e) { failure = e; }
                synchronized (SingleFlight.this) {
                    if (cancelled) failure = new CancellationException("Operation cancelled; inspection incomplete");
                    active = null;
                }
                final T result = value;
                final Throwable error = failure;
                dispatcher.execute(new Runnable() {
                    @Override public void run() { callback.completed(result, error); }
                });
            }
        }, "mt-safety-operation");
        active.setDaemon(true);
        active.start();
        return true;
    }
}
