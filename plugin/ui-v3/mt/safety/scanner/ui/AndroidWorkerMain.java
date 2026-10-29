package mt.safety.scanner.ui;

import java.io.DataOutputStream;
import mt.safety.scanner.execution.ScannerWorker;
import mt.safety.scanner.execution.WorkerProtocol;
import mt.safety.scanner.execution.AndroidWorkerLaunch;

/** Only scanner-owned code is loaded by the trusted OS runtime; never an inspected payload. */
public final class AndroidWorkerMain {
    private AndroidWorkerMain() { }
    public static void main(String[] arguments) throws Exception {
        if (Runtime.getRuntime().maxMemory() > AndroidWorkerLaunch.MAX_HEAP_BYTES) {
            throw new IllegalStateException("Scanner heap limit was not enforced; inspection unavailable");
        }
        if (arguments.length == 1 && "--probe".equals(arguments[0])) {
            System.out.println("MT_WORKER_PROBE pid=" + android.system.Os.getpid()
                    + " uid=" + android.system.Os.getuid() + " maxHeap=" + Runtime.getRuntime().maxMemory());
            return;
        }
        if (arguments.length != 0) throw new IllegalArgumentException("Unsupported worker argument");
        Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        DataOutputStream out = new DataOutputStream(System.out);
        out.writeInt(WorkerProtocol.MAGIC); out.writeInt(android.system.Os.getpid()); out.flush();
        ScannerWorker.serve(System.in, out);
    }
}
