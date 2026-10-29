package mt.safety.scanner.execution;

import java.io.*;
import java.util.*;
import mt.safety.scanner.ScanRunner;

/** The scanner's own child entry logic. All inspected packages remain data. */
public final class ScannerWorker {
    private ScannerWorker() { }
    public static void serve(InputStream input, OutputStream output) throws IOException {
        WorkerProtocol.Request request = WorkerProtocol.decodeRequest(WorkerProtocol.readMessage(input));
        ScanRunner runner = new ScanRunner(request.host);
        WorkerProtocol.Response response = new WorkerProtocol.Response();
        switch (request.operation) {
            case WorkerProtocol.RUN:
                response.result = runner.run();
                response.signatures = runner.signatureCount();
                response.quarantined = runner.quarantinedCount();
                for (File root : runner.fileScanRoots()) response.roots.add(root.getAbsolutePath());
                break;
            case WorkerProtocol.FILES:
                response.outcome = runner.scanFiles(request.argument, response.hits);
                break;
            case WorkerProtocol.UNINSTALL:
                response.outcome = runner.uninstallSelection(request.prior);
                break;
            case WorkerProtocol.BULK:
                response.outcome = runner.actOnScope(request.prior, request.argument, request.remove);
                break;
            default: throw new IOException("Unknown worker operation");
        }
        response.changedValues.putAll(request.host.changedValues);
        response.changedFlags.putAll(request.host.changedFlags);
        WorkerProtocol.writeMessage(output, WorkerProtocol.encodeResponse(response));
    }
}
