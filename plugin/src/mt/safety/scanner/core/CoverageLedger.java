package mt.safety.scanner.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/** Bounded audit of every admitted member and every applicable analyzer, including skipped work. */
public final class CoverageLedger {
    public static final int MAX_MEMBERS = 12000;
    public enum Analyzer { READ, BUILTIN_RULES, USER_PATTERNS, SIGNATURES, NESTED_ARCHIVE }
    public enum PackageAnalyzer { MANIFEST, STRUCTURE, CONTENT_HASH, IOC_DEFINITIONS,
        SIGNATURE_DEFINITIONS, CODE_VISIBILITY }
    public enum Status { COMPLETE, PARTIAL, SKIPPED, FAILED, NOT_APPLICABLE }
    public enum Reason { OK, EMPTY, DIRECTORY, MANIFEST_METADATA, BUDGET_EXHAUSTED, MEMBER_LIMIT,
        READ_FAILED, UNSUPPORTED, DEPTH_LIMIT, ENTRY_LIMIT, DEFINITIONS_INCOMPLETE,
        NO_DEFINITIONS, NO_USER_PATTERNS, NON_ARCHIVE, NOT_ATTEMPTED, HASH_UNAVAILABLE,
        PARSE_FAILED, LEDGER_LIMIT, NOT_VISIBLE, MANIFEST_MISSING, MATCH_LIMIT }

    public static final class Check {
        public final Status status;
        public final Reason reason;
        public final long bytes;
        public Check(Status status, Reason reason, long bytes) {
            if (status == null || reason == null || bytes < 0) throw new IllegalArgumentException("Invalid coverage check");
            this.status = status; this.reason = reason; this.bytes = bytes;
        }
    }
    private static final Check PENDING = new Check(Status.SKIPPED, Reason.NOT_ATTEMPTED, 0);
    public static final class Member {
        public final int id;
        /** Bounded display only; nameHash identifies the complete relative path. IDs retain duplicates. */
        public final String label, nameHash;
        private final Check[] checks = new Check[Analyzer.values().length];
        private Member(int id, String label, String nameHash) {
            this.id = id; this.label = label; this.nameHash = nameHash;
            java.util.Arrays.fill(checks, PENDING);
        }
        public void set(Analyzer analyzer, Status status, Reason reason, long bytes) {
            checks[analyzer.ordinal()] = new Check(status, reason, bytes);
        }
        public Check get(Analyzer analyzer) { return checks[analyzer.ordinal()]; }
        public void notApplicable(Reason reason) {
            for (Analyzer a : Analyzer.values()) set(a, Status.NOT_APPLICABLE, reason, 0);
        }
    }

    private final List<Member> members = new ArrayList<Member>();
    private final Map<PluginPackage.Entry, Member> identities = new IdentityHashMap<PluginPackage.Entry, Member>();
    private final Map<PackageAnalyzer, Check> packageChecks = new EnumMap<PackageAnalyzer, Check>(PackageAnalyzer.class);
    private final Member overflow = new Member(0, "(ledger limit)", "");
    private int dropped;
    private boolean active;

    public void start() {
        active = true;
        for (PackageAnalyzer a : PackageAnalyzer.values()) if (!packageChecks.containsKey(a)) packageChecks.put(a, PENDING);
    }
    public boolean active() { return active; }
    public int droppedMembers() { return dropped; }
    public List<Member> members() { return Collections.unmodifiableList(members); }
    public void set(PackageAnalyzer analyzer, Status status, Reason reason) {
        packageChecks.put(analyzer, new Check(status, reason, 0));
    }
    public Check get(PackageAnalyzer analyzer) { return packageChecks.containsKey(analyzer) ? packageChecks.get(analyzer) : PENDING; }
    public Member member(PluginPackage.Entry entry) {
        Member member = identities.get(entry);
        if (member == null) {
            member = addMember(entry.name);
            if (member.id != 0) identities.put(entry, member);
        }
        return member;
    }
    public Member addMember(String path) {
        if (members.size() >= MAX_MEMBERS) {
            if (dropped < Integer.MAX_VALUE) dropped++;
            return overflow;
        }
        String name = path == null ? "" : path;
        Member member = new Member(members.size() + 1, ReportText.bounded(name, 32),
                Bytes.sha256(name.getBytes(StandardCharsets.UTF_8)));
        members.add(member);
        return member;
    }
    /** Validated IPC restoration, with no input-supplied class names or arbitrary maps. */
    public Member restoreMember(int id, String label, String nameHash) {
        if (id != members.size() + 1 || id > MAX_MEMBERS || label == null || label.length() > 40
                || nameHash == null || !nameHash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid coverage identity");
        }
        Member member = new Member(id, label, nameHash); members.add(member); return member;
    }
    public void restoreDropped(int dropped) {
        if (dropped < 0) throw new IllegalArgumentException("Invalid coverage count");
        this.dropped = dropped;
    }
    public void finishPending(Reason reason) {
        for (Member member : members) {
            for (Analyzer a : Analyzer.values()) {
                if (member.get(a).reason == Reason.NOT_ATTEMPTED) member.set(a, Status.SKIPPED, reason, 0);
            }
        }
    }
    public boolean incomplete() {
        if (!active) return false;
        if (dropped > 0) return true;
        for (PackageAnalyzer a : PackageAnalyzer.values()) if (incomplete(get(a))) return true;
        for (Member member : members) for (Analyzer a : Analyzer.values()) if (incomplete(member.get(a))) return true;
        return false;
    }
    private static boolean incomplete(Check check) {
        return check.status != Status.COMPLETE && check.status != Status.NOT_APPLICABLE;
    }
    public int incompleteChecks() {
        int n = dropped > 0 ? 1 : 0;
        if (!active) return n;
        for (PackageAnalyzer a : PackageAnalyzer.values()) if (incomplete(get(a))) n++;
        for (Member member : members) for (Analyzer a : Analyzer.values()) if (incomplete(member.get(a))) n++;
        return n;
    }
}
