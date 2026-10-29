package mt.safety.scanner.execution;

import java.io.*;
import java.util.*;
import mt.safety.scanner.*;
import mt.safety.scanner.core.*;

/** Versioned, length-bounded data IPC. Never Java serialization or input-supplied classes. */
public final class WorkerProtocol {
    public static final int MAGIC = 0x4d545331;
    public static final int MAX_BYTES = 4 * 1024 * 1024;
    private static final int MAX_STRING = 32768;
    public static final int RUN = 1, FILES = 2, UNINSTALL = 3, BULK = 4;
    private WorkerProtocol() { }

    public static final class Snapshot implements Host {
        public String directory, language, pluginId, hostPackage;
        public final Map<String, String> values = new LinkedHashMap<String, String>();
        public final Map<String, Boolean> flags = new LinkedHashMap<String, Boolean>();
        public final Map<String, String> changedValues = new LinkedHashMap<String, String>();
        public final Map<String, Boolean> changedFlags = new LinkedHashMap<String, Boolean>();
        @Override public File filesDir() { return new File(directory); }
        @Override public String config(String key, String fallback) { return values.containsKey(key) ? values.get(key) : fallback; }
        @Override public boolean configFlag(String key, boolean fallback) { return flags.containsKey(key) ? flags.get(key) : fallback; }
        @Override public void putConfig(String key, String value) {
            if (value == null) values.remove(key); else values.put(key, value);
            changedValues.put(key, value);
        }
        @Override public void putFlag(String key, boolean value) { flags.put(key, value); changedFlags.put(key, value); }
        @Override public String language() { return language; }
        @Override public String pluginId() { return pluginId; }
        @Override public String hostPackage() { return hostPackage; }
        // No content-bearing logs or toast callbacks cross the process boundary.
        @Override public void log(String message) { }
        @Override public void log(String message, Throwable error) { }
        @Override public void toast(String message) { }
    }
    public static final class Request {
        public int operation;
        public Snapshot host;
        public ScanRunner.Result prior;
        public String argument = "";
        public boolean remove;
    }
    public static final class Response {
        public ScanRunner.Result result;
        public int signatures, quarantined;
        public final List<String> roots = new ArrayList<String>();
        public String outcome = "";
        public final List<String> hits = new ArrayList<String>();
        public final Map<String, String> changedValues = new LinkedHashMap<String, String>();
        public final Map<String, Boolean> changedFlags = new LinkedHashMap<String, Boolean>();
    }
    public static byte[] encodeRequest(Request r) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = output(bytes);
        out.writeInt(MAGIC); out.writeInt(r.operation);
        string(out, r.host.directory); string(out, r.host.language); string(out, r.host.pluginId); string(out, r.host.hostPackage);
        values(out, r.host.values); flags(out, r.host.flags);
        string(out, r.argument); out.writeBoolean(r.remove);
        out.writeBoolean(r.prior != null); if (r.prior != null) result(out, r.prior);
        out.flush(); return bytes.toByteArray();
    }
    public static Request decodeRequest(byte[] bytes) throws IOException {
        DataInputStream in = input(bytes);
        if (in.readInt() != MAGIC) throw new IOException("Worker protocol mismatch");
        Request r = new Request(); r.operation = in.readInt();
        if (r.operation < RUN || r.operation > BULK) throw new IOException("Unknown worker operation");
        r.host = new Snapshot(); r.host.directory = string(in); r.host.language = string(in);
        r.host.pluginId = string(in); r.host.hostPackage = string(in);
        values(in, r.host.values); flags(in, r.host.flags);
        r.argument = string(in); r.remove = in.readBoolean();
        if (in.readBoolean()) r.prior = result(in);
        if (in.read() != -1) throw new IOException("Trailing request data");
        if ((r.operation == UNINSTALL || r.operation == BULK) && r.prior == null) throw new IOException("Missing action identity");
        return r;
    }
    public static byte[] encodeResponse(Response r) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(); DataOutputStream out = output(bytes);
        out.writeInt(MAGIC); out.writeBoolean(r.result != null); if (r.result != null) result(out, r.result);
        out.writeInt(r.signatures); out.writeInt(r.quarantined); strings(out, r.roots);
        string(out, r.outcome); strings(out, r.hits); values(out, r.changedValues); flags(out, r.changedFlags);
        out.flush(); return bytes.toByteArray();
    }
    public static Response decodeResponse(byte[] bytes) throws IOException {
        DataInputStream in = input(bytes);
        if (in.readInt() != MAGIC) throw new IOException("Worker protocol mismatch");
        Response r = new Response(); if (in.readBoolean()) r.result = result(in);
        r.signatures = in.readInt(); r.quarantined = in.readInt(); strings(in, r.roots);
        r.outcome = string(in); strings(in, r.hits); values(in, r.changedValues); flags(in, r.changedFlags);
        if (in.read() != -1) throw new IOException("Trailing response data");
        return r;
    }
    private static DataInputStream input(byte[] bytes) throws IOException {
        if (bytes.length > MAX_BYTES) throw new IOException("Worker message too large");
        return new DataInputStream(new ByteArrayInputStream(bytes));
    }
    private static DataOutputStream output(OutputStream stream) {
        return new DataOutputStream(new LimitedOutput(stream, MAX_BYTES));
    }
    static final class LimitedOutput extends FilterOutputStream {
        private int remaining;
        LimitedOutput(OutputStream out, int limit) { super(out); remaining = limit; }
        @Override public void write(int b) throws IOException {
            if (remaining == 0) throw new IOException("Worker message too large"); remaining--; out.write(b);
        }
        @Override public void write(byte[] b, int offset, int len) throws IOException {
            if (len > remaining) throw new IOException("Worker message too large"); remaining -= len; out.write(b, offset, len);
        }
    }
    static void string(DataOutputStream out, String value) throws IOException {
        if (value == null) { out.writeInt(-1); return; }
        if (value.length() > MAX_STRING) throw new IOException("Worker string too large");
        byte[] bytes = value.getBytes("UTF-8");
        if (bytes.length > MAX_STRING) throw new IOException("Worker string too large");
        out.writeInt(bytes.length); out.write(bytes);
    }
    static String string(DataInputStream in) throws IOException {
        int length = in.readInt(); if (length == -1) return null;
        if (length < 0 || length > MAX_STRING || length > in.available()) throw new IOException("Invalid worker string length");
        byte[] bytes = new byte[length]; in.readFully(bytes); return new String(bytes, "UTF-8");
    }
    private static void count(DataOutputStream out, int count) throws IOException {
        if (count < 0 || count > 4096) throw new IOException("Worker item limit"); out.writeInt(count);
    }
    private static int count(DataInputStream in) throws IOException {
        int n = in.readInt(); if (n < 0 || n > 4096) throw new IOException("Worker item limit"); return n;
    }
    private static void strings(DataOutputStream out, Collection<String> list) throws IOException {
        count(out, list.size()); for (String value : list) string(out, value);
    }
    private static void strings(DataInputStream in, Collection<String> list) throws IOException {
        int n = count(in); for (int i = 0; i < n; i++) list.add(string(in));
    }
    private static void values(DataOutputStream out, Map<String, String> map) throws IOException {
        count(out, map.size()); for (Map.Entry<String, String> e : map.entrySet()) { string(out, e.getKey()); string(out, e.getValue()); }
    }
    private static void values(DataInputStream in, Map<String, String> map) throws IOException {
        int n = count(in); for (int i = 0; i < n; i++) map.put(string(in), string(in));
    }
    private static void flags(DataOutputStream out, Map<String, Boolean> map) throws IOException {
        count(out, map.size()); for (Map.Entry<String, Boolean> e : map.entrySet()) { string(out, e.getKey()); out.writeBoolean(e.getValue()); }
    }
    private static void flags(DataInputStream in, Map<String, Boolean> map) throws IOException {
        int n = count(in); for (int i = 0; i < n; i++) map.put(string(in), in.readBoolean());
    }
    private static void result(DataOutputStream out, ScanRunner.Result result) throws IOException {
        count(out, result.reports.size()); for (ScanReport report : result.reports) report(out, report);
        rows(out, result.rows, result.reports); rows(out, result.aboutRows, result.reports);
        out.writeInt(result.unscanned); values(out, result.actioned); string(out, result.commandOutcome);
        string(out, result.discoveryProblem); strings(out, result.fileHitLines);
    }
    private static ScanRunner.Result result(DataInputStream in) throws IOException {
        ScanRunner.Result result = new ScanRunner.Result(); int n = count(in);
        for (int i = 0; i < n; i++) result.reports.add(report(in));
        rows(in, result.rows, result.reports); rows(in, result.aboutRows, result.reports);
        result.unscanned = in.readInt(); values(in, result.actioned); result.commandOutcome = string(in);
        result.discoveryProblem = string(in); strings(in, result.fileHitLines); return result;
    }
    private static void rows(DataOutputStream out, List<ScanRunner.Row> rows, List<ScanReport> reports) throws IOException {
        count(out, rows.size()); for (ScanRunner.Row row : rows) {
            out.writeBoolean(row.header); out.writeBoolean(row.toggle); string(out, row.key);
            string(out, row.title); string(out, row.summary); out.writeInt(reports.indexOf(row.report));
        }
    }
    private static void rows(DataInputStream in, List<ScanRunner.Row> rows, List<ScanReport> reports) throws IOException {
        int n = count(in); for (int i = 0; i < n; i++) {
            boolean header = in.readBoolean(), toggle = in.readBoolean(); String key = string(in);
            String title = string(in), summary = string(in); int idx = in.readInt();
            if (idx < -1 || idx >= reports.size()) throw new IOException("Invalid report reference");
            rows.add(header ? ScanRunner.Row.header(title) : toggle
                    ? ScanRunner.Row.toggle(title, summary, key, idx < 0 ? null : reports.get(idx))
                    : ScanRunner.Row.text(title, summary));
        }
    }
    private static void report(DataOutputStream out, ScanReport report) throws IOException {
        string(out, report.label); string(out, report.path); out.writeBoolean(report.archive); out.writeBoolean(report.installed);
        PluginManifest m = report.manifest;
        out.writeBoolean(m.present); out.writeBoolean(m.unreadable); string(out, m.parseError);
        // Display and action fields only. Raw manifest JSON never crosses to the host parser.
        string(out, m.pluginId); string(out, m.displayName());
        string(out, report.contentHash); string(out, report.verdict().name()); string(out, report.verdictReason());
        out.writeInt(report.score()); out.writeBoolean(report.truncated()); out.writeInt(report.filesScanned()); out.writeLong(report.elapsedMs());
        out.writeBoolean(report.destructiveActionIdentityComplete()); string(out, report.actionIdentityPath());
        ledger(out, report.ledger);
        strings(out, report.errors); strings(out, report.traits); count(out, report.signals.size());
        for (Signal signal : report.signals) {
            string(out, signal.ruleId); string(out, signal.category.name()); string(out, signal.severity.name());
            string(out, signal.title); string(out, signal.detail); count(out, signal.evidence().size());
            for (Signal.Evidence evidence : signal.evidence()) { string(out, evidence.where); string(out, evidence.snippet); }
        }
    }
    private static ScanReport report(DataInputStream in) throws IOException {
        String label = string(in), path = string(in); boolean archive = in.readBoolean(), installed = in.readBoolean();
        boolean present = in.readBoolean(), unreadable = in.readBoolean(); String parseError = string(in);
        String pluginId = string(in), displayName = string(in);
        PluginManifest m = unreadable ? (present ? PluginManifest.unreadable(parseError) : PluginManifest.presenceUnknown(parseError))
                : !present ? PluginManifest.missing() : parseError != null ? PluginManifest.broken(parseError)
                : PluginManifest.parse(("{\"pluginID\":" + Json.quote(pluginId) + ",\"name\":" + Json.quote(displayName) + "}").getBytes("UTF-8"));
        // Lenient manifests have parseError but remain usable; preserve identity for verified actions.
        if (pluginId != null && pluginId.length() > 0 && !pluginId.equals(m.pluginId)) {
            m = PluginManifest.parse(("{\"pluginID\":" + Json.quote(pluginId) + ",\"name\":" + Json.quote(displayName) + "}").getBytes("UTF-8"));
        }
        m.setResolvedName(displayName);
        ScanReport r = new ScanReport(label, path, archive, installed, m, string(in));
        try {
            r.setVerdict(Verdict.valueOf(string(in)), string(in)); r.setScore(in.readInt()); r.setTruncated(in.readBoolean());
            r.setFilesScanned(in.readInt()); r.setElapsedMs(in.readLong()); r.setDestructiveActionIdentity(in.readBoolean(), string(in));
            ledger(in, r.ledger);
            strings(in, r.errors); strings(in, r.traits); int n = count(in);
            for (int i = 0; i < n; i++) {
                Signal s = new Signal(string(in), Category.valueOf(string(in)), Severity.valueOf(string(in)), string(in), string(in));
                int evidence = count(in); if (evidence > 12) throw new IOException("Worker evidence limit");
                for (int j = 0; j < evidence; j++) s.withEvidence(string(in), string(in)); r.add(s);
            }
        } catch (IllegalArgumentException e) { throw new IOException("Invalid worker enum", e); }
        return r;
    }
    private static void ledger(DataOutputStream out, CoverageLedger ledger) throws IOException {
        out.writeBoolean(ledger.active());
        if (!ledger.active()) return;
        out.writeInt(ledger.droppedMembers());
        for (CoverageLedger.PackageAnalyzer a : CoverageLedger.PackageAnalyzer.values()) check(out, ledger.get(a));
        out.writeInt(ledger.members().size());
        for (CoverageLedger.Member member : ledger.members()) {
            out.writeInt(member.id); string(out, member.label); string(out, member.nameHash);
            for (CoverageLedger.Analyzer a : CoverageLedger.Analyzer.values()) check(out, member.get(a));
        }
    }
    private static void ledger(DataInputStream in, CoverageLedger ledger) throws IOException {
        if (!in.readBoolean()) return;
        ledger.start(); ledger.restoreDropped(in.readInt());
        for (CoverageLedger.PackageAnalyzer a : CoverageLedger.PackageAnalyzer.values()) {
            CoverageLedger.Check check = check(in); ledger.set(a, check.status, check.reason);
        }
        int n = in.readInt();
        if (n < 0 || n > CoverageLedger.MAX_MEMBERS) throw new IOException("Worker ledger item limit");
        for (int i = 0; i < n; i++) {
            CoverageLedger.Member member = ledger.restoreMember(in.readInt(), string(in), string(in));
            for (CoverageLedger.Analyzer a : CoverageLedger.Analyzer.values()) {
                CoverageLedger.Check check = check(in); member.set(a, check.status, check.reason, check.bytes);
            }
        }
    }
    private static void check(DataOutputStream out, CoverageLedger.Check check) throws IOException {
        out.writeByte(check.status.ordinal()); out.writeByte(check.reason.ordinal()); out.writeLong(check.bytes);
    }
    private static CoverageLedger.Check check(DataInputStream in) throws IOException {
        int status = in.readUnsignedByte(), reason = in.readUnsignedByte(); long bytes = in.readLong();
        if (status >= CoverageLedger.Status.values().length || reason >= CoverageLedger.Reason.values().length || bytes < 0) {
            throw new IOException("Invalid worker coverage status");
        }
        return new CoverageLedger.Check(CoverageLedger.Status.values()[status], CoverageLedger.Reason.values()[reason], bytes);
    }
    public static byte[] readMessage(InputStream stream) throws IOException {
        DataInputStream in = new DataInputStream(stream); int n = in.readInt();
        if (n < 0 || n > MAX_BYTES) throw new IOException("Worker message limit");
        byte[] bytes = new byte[n]; in.readFully(bytes); return bytes;
    }
    public static void writeMessage(OutputStream stream, byte[] bytes) throws IOException {
        if (bytes.length > MAX_BYTES) throw new IOException("Worker message limit");
        DataOutputStream out = new DataOutputStream(stream); out.writeInt(bytes.length); out.write(bytes); out.flush();
    }
}
