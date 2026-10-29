package mt.safety.scanner.execution;

import java.io.*;
import java.util.concurrent.*;

/** Bounded IPC with an independent monotonic wall deadline. API24: no Process API26 methods. */
public final class ProcessSupervisor {
    public interface Terminator { void terminate(Process process, int trustedPid); }
    private static Process unconfirmed;
    private ProcessSupervisor() { }
    /** Prevent repeated starts if the OS has not confirmed that the previous child exited. */
    public static synchronized void checkAvailable() throws IOException {
        if (unconfirmed == null) return;
        try { unconfirmed.exitValue(); unconfirmed = null; }
        catch (IllegalThreadStateException alive) {
            throw new IOException("Previous worker termination is unconfirmed; inspection unavailable");
        }
    }
    private static boolean confirmExit(Process process) {
        boolean interrupted = Thread.interrupted();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
        try {
            do {
                try { process.exitValue(); return true; }
                catch (IllegalThreadStateException alive) {
                    try { Thread.sleep(5); } catch (InterruptedException stop) { interrupted = true; }
                }
            } while (System.nanoTime() < deadline);
            synchronized (ProcessSupervisor.class) { unconfirmed = process; }
            return false;
        } finally { if (interrupted) Thread.currentThread().interrupt(); }
    }
    public static byte[] exchange(final Process process, final byte[] request, long timeoutMs,
            final Terminator terminator) throws IOException {
        checkAvailable();
        if (request.length > WorkerProtocol.MAX_BYTES || timeoutMs < 1 || timeoutMs > 120000)
            throw new IOException("Invalid worker limits");
        final int[] pid = {0};
        final FutureTask<byte[]> response = new FutureTask<byte[]>(new Callable<byte[]>() {
            @Override public byte[] call() throws IOException {
                DataInputStream input = new DataInputStream(process.getInputStream());
                if (input.readInt() != WorkerProtocol.MAGIC) throw new IOException("Worker handshake failed");
                int announced = input.readInt();
                if (announced <= 0) throw new IOException("Invalid worker identity");
                synchronized (pid) { pid[0] = announced; }
                byte[] bytes = WorkerProtocol.readMessage(input);
                if (input.read() != -1) throw new IOException("Unexpected worker output");
                return bytes;
            }
        });
        FutureTask<Void> writer = new FutureTask<Void>(new Callable<Void>() {
            @Override public Void call() throws IOException {
                OutputStream output = process.getOutputStream();
                WorkerProtocol.writeMessage(output, request); output.close(); return null;
            }
        });
        // A separate bounded stderr drain prevents either pipe from stalling the child. Content is
        // discarded: ART errors and scan paths must not leak into host logs or findings.
        FutureTask<Void> errors = new FutureTask<Void>(new Callable<Void>() {
            @Override public Void call() throws IOException {
                InputStream in = process.getErrorStream(); byte[] buffer = new byte[1024]; int total = 0, n;
                while ((n = in.read(buffer)) != -1) {
                    total += n;
                    if (total > 65536) throw new IOException("Worker diagnostic limit");
                }
                return null;
            }
        });
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        start(response, "mt-safety-output"); start(writer, "mt-safety-input"); start(errors, "mt-safety-errors");
        try {
            // Check every pipe; a diagnostic flood must terminate instead of blocking until timeout.
            while (!response.isDone()) {
                checkCompleted(writer); checkCompleted(errors);
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) throw new TimeoutException();
                try { response.get(Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(25)), TimeUnit.NANOSECONDS); }
                catch (TimeoutException stillRunning) { /* monotonic deadline above */ }
            }
            byte[] result = response.get();
            writer.get(Math.max(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            while (true) {
                try {
                    if (process.exitValue() != 0) throw new IOException("Scanner worker failed; inspection incomplete");
                    break;
                } catch (IllegalThreadStateException running) {
                    if (System.nanoTime() >= deadline) throw new TimeoutException();
                    Thread.sleep(5);
                }
            }
            errors.get(Math.max(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            return result;
        } catch (InterruptedException cancelled) {
            Thread.currentThread().interrupt(); throw new IOException("Scanner cancelled; inspection incomplete", cancelled);
        } catch (TimeoutException timeout) {
            throw new IOException("Scanner worker timed out; inspection incomplete", timeout);
        } catch (ExecutionException failed) {
            throw new IOException("Scanner worker unavailable or failed; inspection incomplete", failed.getCause());
        } finally {
            int trustedPid; synchronized (pid) { trustedPid = pid[0]; }
            try { terminator.terminate(process, trustedPid); }
            catch (RuntimeException denied) { process.destroy(); }
            response.cancel(true); writer.cancel(true); errors.cancel(true);
            // Do not free the launch gate, or block closing a pipe, while a child might still live.
            if (!confirmExit(process)) throw new IOException("Worker termination unconfirmed; inspection unavailable");
            close(process.getOutputStream()); close(process.getInputStream()); close(process.getErrorStream());
        }
    }
    private static void checkCompleted(FutureTask<?> task) throws InterruptedException, ExecutionException {
        if (task.isDone()) task.get();
    }
    private static void start(Runnable runnable, String name) {
        Thread thread = new Thread(runnable, name); thread.setDaemon(true); thread.start();
    }
    private static void close(Closeable stream) { try { stream.close(); } catch (IOException ignored) { } }
}
