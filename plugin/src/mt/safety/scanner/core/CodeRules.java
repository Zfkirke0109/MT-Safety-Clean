package mt.safety.scanner.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import mt.safety.scanner.core.Indicator.Scope;
import mt.safety.scanner.core.CoverageLedger.Analyzer;
import mt.safety.scanner.core.CoverageLedger.Status;
import mt.safety.scanner.core.CoverageLedger.Reason;

/**
 * Applies the indicator catalogue to every readable member of a package.
 *
 * <p>Findings are collapsed per rule rather than per match, so a plugin that mentions {@code Runtime}
 * in twelve files produces one finding with twelve pieces of evidence. On a phone screen that is the
 * difference between a report and a wall of text.
 */
public final class CodeRules {

    /**
     * How a plugin declares itself a translation engine, which excuses ordinary network use.
     *
     * <p>Deliberately narrow: only a class declaration that extends or implements the engine type
     * counts, and only in a file the manifest names as an entry point. Matching the bare word anywhere
     * would let a plugin switch off its own network scoring with a comment.
     */
    private static final Pattern TRANSLATION_ENGINE = Pattern.compile(
            "(extends|implements)\\s+(Base)?TranslationEngine\\b");

    /** Long unbroken Base64 runs, the usual shape of an embedded payload. */
    private static final Pattern BASE64_BLOB = Pattern.compile("[A-Za-z0-9+/]{512,}={0,2}");

    /** How much of a single member is read, by kind. */
    private static final int SOURCE_LIMIT = 1024 * 1024;
    private static final int BINARY_LIMIT = 4 * 1024 * 1024;

    /** Bounds on looking inside an archived member such as a jar under libs/. */
    private static final int NESTED_MEMBER_LIMIT = 512 * 1024;
    private static final int MAX_NESTED_ENTRIES = 400;
    private static final int MAX_NESTED_DEPTH = 2;

    /** Logical offsets in this fixed memory stream include inflater pushback after member EOF. */
    private static final class NestedZipStream extends ZipInputStream {
        private final int length;

        NestedZipStream(byte[] data) {
            super(new ByteArrayInputStream(data));
            length = data.length;
        }

        long nextHeaderOffset() throws IOException {
            // ZipInputStream.available() is only 0/1. Its inherited input is instead a
            // PushbackInputStream over our ByteArrayInputStream; both report exact remaining bytes.
            // Call only initially or after the preceding member has reached EOF/readEnd().
            return length - in.available();
        }
    }

    private static final Set<String> SOURCE_EXTENSIONS = new HashSet<String>();
    private static final Set<String> TEXT_EXTENSIONS = new HashSet<String>();

    static {
        SOURCE_EXTENSIONS.add("java");
        SOURCE_EXTENSIONS.add("kt");

        TEXT_EXTENSIONS.add("json");
        TEXT_EXTENSIONS.add("txt");
        TEXT_EXTENSIONS.add("xml");
        TEXT_EXTENSIONS.add("properties");
        TEXT_EXTENSIONS.add("lang");
        TEXT_EXTENSIONS.add("md");
        TEXT_EXTENSIONS.add("cfg");
        TEXT_EXTENSIONS.add("ini");
        TEXT_EXTENSIONS.add("csv");
        TEXT_EXTENSIONS.add("js");
        TEXT_EXTENSIONS.add("html");
        TEXT_EXTENSIONS.add("sh");
        TEXT_EXTENSIONS.add("py");
        TEXT_EXTENSIONS.add("yaml");
        TEXT_EXTENSIONS.add("yml");
    }

    private CodeRules() {
    }

    /**
     * Scans members and records findings; returns the number of members actually read.
     *
     * <p>No member is exempt on the strength of its name or its first few bytes. An earlier version
     * skipped anything with a media extension whose magic bytes matched, which sounds safe and is not:
     * image decoders tolerate trailing junk, so a genuine PNG header followed by an appended payload
     * satisfied the check and then bypassed every indicator, user pattern and encoded-payload rule.
     * Reading an ordinary icon costs a fraction of the byte allowance; letting one carry a payload
     * costs the whole point of the scan. Binary members are searched for printable runs rather than
     * decoded whole, so real image data contributes nothing to match against.
     *
     * <p>The cost is real for a package that ships large media: those members now draw on the same
     * byte allowance as everything else, and a package big enough to exhaust it is reported as
     * truncated. That is the intended degradation. A scan that admits it did not finish is useful; one
     * that reports Clean because it agreed not to look is not.
     */
    public static int apply(ScanReport report, PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget, IocDatabase database) {
        return apply(report, pkg, entries, budget, database, null);
    }

    /**
     * As {@link #apply(ScanReport, PluginPackage, List, ScanBudget, IocDatabase)}, also checking each
     * member against a signature database when one is loaded.
     */
    public static int apply(ScanReport report, PluginPackage pkg, List<PluginPackage.Entry> entries,
            ScanBudget budget, IocDatabase database, SignatureDatabase signatures) {
        Map<String, Signal> byRule = new HashMap<String, Signal>();
        int scanned = 0;
        for (PluginPackage.Entry entry : entries) { report.ledger.member(entry); }

        for (PluginPackage.Entry entry : entries) {
            CoverageLedger.Member coverage = report.ledger.member(entry);
            if (entry.directory) {
                coverage.notApplicable(Reason.DIRECTORY);
                continue;
            }
            // The manifest is metadata, judged by ManifestRules on what it declares. Searching its
            // text for indicators reported a plugin for naming its own classes under bin.mt.plugin
            // and for the dexMode flag every v3 package carries.
            if (entry.name.equals("manifest.json")) {
                coverage.notApplicable(Reason.MANIFEST_METADATA);
                continue;
            }
            if (budget.exhausted()) {
                skipped(coverage, Reason.BUDGET_EXHAUSTED);
                budget.markTruncated();
                break;
            }
            String ext = entry.extension();
            Scope scope = classify(ext);
            int limit = scope == Scope.SOURCE ? SOURCE_LIMIT : BINARY_LIMIT;

            byte[] data;
            try {
                data = pkg.read(entry, limit, budget);
            } catch (IOException e) {
                report.addError("could not read " + entry.name + ": " + e.getMessage());
                failedRead(coverage, e);
                // A member that cannot be read is content that was not inspected.
                budget.markTruncated();
                continue;
            }
            boolean completeRead = data.length == entry.size && entry.size <= limit;
            recordRead(coverage, completeRead, data.length, entry.size > limit
                    ? Reason.MEMBER_LIMIT : Reason.BUDGET_EXHAUSTED);
            if (entry.size > limit) {
                // Only the first part of this member was read, so a finding could be sitting past the
                // cap. The report says the scan was incomplete rather than implying full coverage.
                budget.markTruncated();
            }
            if (data.length > 0) { scanned++; }

            // Known-malware signatures see the member's bytes as they are, before any text is
            // extracted from them. A whole-file hash only means something for a complete read.
            boolean signaturesComplete = SignatureRules.match(report, byRule, entry, data, completeRead, signatures);

            // A jar's members are deflated, so searching the container's raw bytes finds nothing at
            // all. libs/ is the documented home for third-party jars, which makes it the obvious
            // place to hide a payload: it has to be opened, not just skimmed.
            if (Bytes.looksLikeZip(data)) {
                scanNestedArchive(report, byRule, entry.name, data, budget, database, signatures, 1, coverage);
            } else {
                coverage.set(Analyzer.NESTED_ARCHIVE, Status.NOT_APPLICABLE, Reason.NON_ARCHIVE, 0);
            }

            String text = scope == Scope.BINARY ? Bytes.extractedText(data, 6) : Bytes.text(data);
            if (scope == Scope.SOURCE && isDeclaredEntryPoint(entry.name, report)
                    && TRANSLATION_ENGINE.matcher(text).find()) {
                report.traits.add("translation-engine");
            }
            matchIndicators(report, byRule, entry, scope, text);
            matchUserPatterns(report, byRule, entry, text, database);
            matchPairs(report, byRule, entry, scope, text);
            if (scope == Scope.SOURCE) {
                checkSourceShape(report, byRule, entry, text);
            }
            checkEncodedPayloads(report, byRule, entry, text);
            recordAnalysis(coverage, completeRead, data.length, database, signatures);
            recordSignatureCutoff(coverage, signaturesComplete, data.length, budget);
        }
        return scanned;
    }

    /**
     * Applies the extra patterns the user added to their indicator file.
     *
     * <p>This is the escape hatch that keeps the scanner useful between releases: an endpoint or string
     * from an advisory can be added locally and is treated as a high-severity match.
     */
    private static void matchUserPatterns(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry entry, String text, IocDatabase database) {
        if (database == null) {
            return;
        }
        List<Pattern> userPatterns = database.patterns();
        for (int i = 0; i < userPatterns.size(); i++) {
            Matcher matcher = userPatterns.get(i).matcher(text);
            if (!matcher.find()) {
                continue;
            }
            Signal signal = signalFor(report, byRule, "USR001", Category.PROVENANCE, Severity.HIGH,
                    "Matches a pattern from your own indicator list",
                    "One of the patterns in your indicator file was found in this package.");
            signal.withEvidence(location(entry, text, matcher.start()),
                    database.patternSources().get(i) + " -> " + snippet(text, matcher.start(), matcher.end()));
        }
    }

    /**
     * Opens an archived member and applies the same rules to what is inside it.
     *
     * <p>Nested entry count, nesting depth, decompressed output per member, and logical scan-budget
     * reservations are bounded. The enclosing member is already held in a bounded byte array. A
     * reservation accounts for bytes returned to this scanner, including the one-byte EOF probe; it
     * does not meter compressed input that {@link ZipInputStream}'s inflater may buffer internally.
     * The deadline is checked between operations and cannot preempt inflater CPU work or bound its
     * per-byte cost. A capped or failed member stops traversal before advancing the stream, which
     * would otherwise inflate the unread remainder.
     *
     * <p>Evidence keeps the path that leads to it, {@code libs/helper.jar!evil/Evil.class}, so a
     * finding can be traced back to the file it actually came from.
     */
    /** Uses raw admitted member slices for XZ/mixed-codec archives; preserves bounded legacy salvage. */
    private static void scanNestedArchive(ScanReport report, Map<String, Signal> byRule, String parentName,
            byte[] data, ScanBudget budget, IocDatabase database, SignatureDatabase signatures, int depth,
            CoverageLedger.Member container) {
        long errorsBefore = report.errorEvents();
        int membersBefore = report.ledger.members().size();
        int droppedBefore = report.ledger.droppedMembers();
        scanNestedArchiveBody(report, byRule, parentName, data, budget, database, signatures, depth);
        boolean complete = depth <= MAX_NESTED_DEPTH && report.errorEvents() == errorsBefore && !budget.stopped()
                && droppedBefore == report.ledger.droppedMembers();
        Reason reason = depth > MAX_NESTED_DEPTH ? Reason.DEPTH_LIMIT : Reason.READ_FAILED;
        for (int i = membersBefore; i < report.ledger.members().size(); i++) {
            CoverageLedger.Member member = report.ledger.members().get(i);
            for (Analyzer analyzer : Analyzer.values()) {
                CoverageLedger.Check check = member.get(analyzer);
                if (check.status != Status.COMPLETE && check.status != Status.NOT_APPLICABLE) {
                    complete = false;
                    reason = check.reason;
                }
            }
        }
        if (complete) { reason = Reason.OK; }
        else if (budget.exhausted()) { reason = Reason.BUDGET_EXHAUSTED; }
        container.set(Analyzer.NESTED_ARCHIVE, complete ? Status.COMPLETE : Status.PARTIAL,
                reason, data.length);
    }

    private static void scanNestedArchiveBody(ScanReport report, Map<String, Signal> byRule, String parentName,
            byte[] data, ScanBudget budget, IocDatabase database, SignatureDatabase signatures, int depth) {
        ArchiveIndex.View view;
        try {
            view = ArchiveIndex.open(data);
        } catch (IOException e) {
            // The established legacy salvage reads only a bounded prefix and always records the
            // missing index. This retains previously readable evidence from malformed input.
            scanNestedArchiveLegacy(report, byRule, parentName, data, budget, database, signatures, depth);
            return;
        }
        if (view.legacyMethodsOnly()) {
            PluginPackage.closeQuietly(view);
            scanNestedArchiveLegacy(report, byRule, parentName, data, budget, database, signatures, depth);
            return;
        }
        try {
            if (depth > MAX_NESTED_DEPTH) {
                report.addError(parentName + ": nested archive deeper than " + MAX_NESTED_DEPTH
                        + " levels was not inspected");
                budget.markTruncated();
                return;
            }
            if (!view.problems.isEmpty()) {
                report.addError(parentName + ": " + view.problems.get(0));
                budget.markTruncated();
            }
            Map<ArchiveIndex.Member, CoverageLedger.Member> records =
                    new java.util.IdentityHashMap<ArchiveIndex.Member, CoverageLedger.Member>();
            for (ArchiveIndex.Member member : view.localOrder) {
                records.put(member, report.ledger.addMember(parentName + "!" + member.name));
            }
            int count = 0;
            for (ArchiveIndex.Member member : view.localOrder) {
                CoverageLedger.Member coverage = records.get(member);
                if (count++ >= MAX_NESTED_ENTRIES || budget.exhausted()) {
                    report.addError(parentName + ": nested entry or scan budget limit reached");
                    Reason reason = count > MAX_NESTED_ENTRIES ? Reason.ENTRY_LIMIT : Reason.BUDGET_EXHAUSTED;
                    for (CoverageLedger.Member record : records.values()) {
                        if (record.get(Analyzer.READ).reason == Reason.NOT_ATTEMPTED) { skipped(record, reason); }
                    }
                    budget.markTruncated();
                    break;
                }
                String childName = parentName + "!" + member.name;
                byte[] child;
                try {
                    child = BoundedZipDecoder.read(view.stream(member), member.method, member.flags,
                            member.compressedSize, member.size, member.crc,
                            member.name.endsWith("/") ? 1 : NESTED_MEMBER_LIMIT, budget);
                } catch (IOException e) {
                    report.addError("could not read " + childName + ": " + e.getMessage());
                    failedRead(coverage, e);
                    budget.markTruncated();
                    continue;
                }
                if (member.name.endsWith("/")) {
                    coverage.notApplicable(Reason.DIRECTORY);
                    if (child.length != 0) {
                        report.addError(childName + ": directory entry contains unread data");
                        coverage.set(Analyzer.READ, Status.PARTIAL, Reason.MEMBER_LIMIT, child.length);
                        budget.markTruncated();
                    }
                    continue;
                }
                boolean complete = child.length == member.size;
                recordRead(coverage, complete, child.length, member.size > NESTED_MEMBER_LIMIT
                        ? Reason.MEMBER_LIMIT : Reason.BUDGET_EXHAUSTED);
                PluginPackage.Entry synthetic = new PluginPackage.Entry(childName, member.size,
                        member.compressedSize, false);
                analyzeNestedChild(report, byRule, synthetic, child, complete, budget,
                        database, signatures, depth, coverage);
                if (!complete) {
                    for (CoverageLedger.Member record : records.values()) {
                        if (record.get(Analyzer.READ).reason == Reason.NOT_ATTEMPTED) {
                            skipped(record, member.size > NESTED_MEMBER_LIMIT
                                    ? Reason.MEMBER_LIMIT : Reason.BUDGET_EXHAUSTED);
                        }
                    }
                    budget.markTruncated();
                    break; // Keep the established nested prefix limit and skip later entries.
                }
            }
        } finally {
            PluginPackage.closeQuietly(view);
        }
    }

    private static void analyzeNestedChild(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry synthetic, byte[] child, boolean complete, ScanBudget budget,
            IocDatabase database, SignatureDatabase signatures, int depth,
            CoverageLedger.Member coverage) {
        String kind = Bytes.detectKind(child);
        if ("dex".equals(kind) || "elf".equals(kind)) {
            signalFor(report, byRule, "ARC009", Category.PERSISTENCE, Severity.HIGH,
                    "An archived library contains executable code",
                    "A jar under libs/ is expected to hold Java classes. Dalvik bytecode or a"
                            + " native binary inside one is a payload travelling in a wrapper.")
                    .withEvidence(synthetic.name, kind + ", " + Bytes.humanSize(child.length));
        }
        Scope scope = classify(synthetic.extension());
        String text = scope == Scope.BINARY ? Bytes.extractedText(child, 6) : Bytes.text(child);
        boolean signaturesComplete = SignatureRules.match(report, byRule, synthetic, child, complete, signatures);
        matchIndicators(report, byRule, synthetic, scope, text);
        matchPairs(report, byRule, synthetic, scope, text);
        matchUserPatterns(report, byRule, synthetic, text, database);
        checkEncodedPayloads(report, byRule, synthetic, text);
        recordAnalysis(coverage, complete, child.length, database, signatures);
        recordSignatureCutoff(coverage, signaturesComplete, child.length, budget);
        if (complete && Bytes.looksLikeZip(child)) {
            scanNestedArchive(report, byRule, synthetic.name, child, budget, database, signatures, depth + 1, coverage);
        } else if (Bytes.looksLikeZip(child)) {
            coverage.set(Analyzer.NESTED_ARCHIVE, Status.SKIPPED, Reason.MEMBER_LIMIT, 0);
        } else {
            coverage.set(Analyzer.NESTED_ARCHIVE, Status.NOT_APPLICABLE, Reason.NON_ARCHIVE, 0);
        }
    }

    private static void scanNestedArchiveLegacy(ScanReport report, Map<String, Signal> byRule, String parentName,
            byte[] data, ScanBudget budget, IocDatabase database, SignatureDatabase signatures, int depth) {
        if (depth > MAX_NESTED_DEPTH) {
            // The depth cap is a safety bound, not a verdict: what sits below it was never inspected.
            report.addError(parentName + ": nested archive deeper than " + MAX_NESTED_DEPTH
                    + " levels was not inspected");
            budget.markTruncated();
            return;
        }
        Signal executableInside = null;
        Map<Long, ArchiveIndex.Member> indexedEntries = null;
        Map<Long, CoverageLedger.Member> records = new HashMap<Long, CoverageLedger.Member>();
        try {
            indexedEntries = ArchiveIndex.nestedEntries(data);
            Set<String> nestedNames = new HashSet<String>();
            for (Map.Entry<Long, ArchiveIndex.Member> indexed : indexedEntries.entrySet()) {
                if (!nestedNames.add(indexed.getValue().name)) {
                    report.addError(parentName + ": duplicate nested member: " + indexed.getValue().name);
                    budget.markTruncated();
                }
                records.put(indexed.getKey(), report.ledger.addMember(parentName + "!" + indexed.getValue().name));
            }
        } catch (IOException e) {
            // ZipInputStream treats some truncated local headers as ordinary EOF. Missing/invalid
            // index metadata must revoke completeness even when that stream never throws. Still
            // inspect its bounded readable prefix so prior malicious evidence is not discarded.
            report.addError(parentName + ": " + e.getMessage());
            budget.markTruncated();
        }
        NestedZipStream zin = new NestedZipStream(data);
        try {
            ZipEntry ze;
            int count = 0;
            while (true) {
                long localOffset = zin.nextHeaderOffset();
                ze = zin.getNextEntry();
                if (ze == null) {
                    if (indexedEntries != null && count != indexedEntries.size()) {
                        report.addError(parentName + ": nested local and indexed member counts disagree");
                        budget.markTruncated();
                    }
                    break;
                }
                if (count++ >= MAX_NESTED_ENTRIES || budget.exhausted()) {
                    Reason reason = count > MAX_NESTED_ENTRIES ? Reason.ENTRY_LIMIT : Reason.BUDGET_EXHAUSTED;
                    for (CoverageLedger.Member record : records.values()) {
                        if (record.get(Analyzer.READ).reason == Reason.NOT_ATTEMPTED) { skipped(record, reason); }
                    }
                    budget.markTruncated();
                    break;
                }
                CoverageLedger.Member coverage = records.get(localOffset);
                if (coverage == null) { coverage = report.ledger.addMember(parentName + "!" + ze.getName()); }
                ArchiveIndex.Member indexed = indexedEntries == null ? null : indexedEntries.get(localOffset);
                if (indexedEntries != null && (indexed == null || !ze.getName().equals(indexed.name))) {
                    report.addError(parentName + ": nested local member is not bound to its index: "
                            + ze.getName());
                    budget.markTruncated();
                }
                if (ze.isDirectory()) {
                    coverage.notApplicable(Reason.DIRECTORY);
                    if (budget.reserve(1) == 0) {
                        coverage.set(Analyzer.READ, Status.SKIPPED, Reason.BUDGET_EXHAUSTED, 0);
                        budget.markTruncated();
                        break;
                    }
                    try {
                        if (zin.read() >= 0) {
                            report.addError(parentName + "!" + ze.getName()
                                    + ": directory entry contains unread data; nested traversal stopped");
                            coverage.set(Analyzer.READ, Status.PARTIAL, Reason.MEMBER_LIMIT, 1);
                            budget.markTruncated();
                            break;
                        }
                        if (!verifyNestedMetadata(report, budget, parentName, indexed, ze)) {
                            coverage.set(Analyzer.READ, Status.FAILED, Reason.READ_FAILED, 0);
                        }
                    } catch (IOException e) {
                        report.addError(parentName + "!" + ze.getName()
                                + ": could not verify empty directory entry: " + e.getMessage());
                        failedRead(coverage, e);
                        budget.markTruncated();
                        break;
                    }
                    continue;
                }
                // One extra output byte is reserved for the end-of-member probe so it is charged too.
                // This bounds bytes returned by ZipInputStream, not inflater-internal CPU or input reads.
                int reserved = budget.reserve(NESTED_MEMBER_LIMIT + 1);
                if (reserved <= 1) {
                    // No room for data plus the probe: stop without reading or advancing.
                    skipped(coverage, Reason.BUDGET_EXHAUSTED);
                    budget.markTruncated();
                    break;
                }
                int granted = reserved - 1;
                byte[] child;
                try {
                    child = Bytes.readAtMost(zin, granted);
                } catch (IOException e) {
                    report.addError("could not read " + parentName + "!" + ze.getName() + ": "
                            + e.getMessage());
                    failedRead(coverage, e);
                    budget.markTruncated();
                    // Do not ask ZipInputStream for another entry: it would first drain the
                    // unread remainder of this potentially enormous or corrupt member.
                    break;
                }
                // ZIP streams do not expose a reliable entry size before inflation. Probe at most
                // the one reserved byte when the allowance is exactly filled; an additional byte
                // proves truncation.
                // This accounts for bytes delivered by the nested stream. The inflater may buffer
                // compressed input internally, and the scan deadline cannot preempt its CPU work.
                // Importantly, getNextEntry() implicitly inflates the rest of the *current* entry.
                boolean completeChild = child.length < granted;
                boolean memberCutShort = false;
                if (!completeChild) {
                    try {
                        if (zin.read() >= 0) {
                            memberCutShort = true;
                            budget.markTruncated();
                        } else {
                            completeChild = true;
                        }
                    } catch (IOException e) {
                        memberCutShort = true;
                        budget.markTruncated();
                        report.addError("could not verify end of " + parentName + "!" + ze.getName()
                                + ": " + e.getMessage());
                    }
                }
                if (completeChild && !verifyNestedMetadata(report, budget, parentName, indexed, ze)) {
                    completeChild = false;
                }

                recordRead(coverage, completeChild, child.length,
                        granted >= NESTED_MEMBER_LIMIT ? Reason.MEMBER_LIMIT : Reason.BUDGET_EXHAUSTED);
                String childName = parentName + "!" + ze.getName();
                PluginPackage.Entry synthetic =
                        new PluginPackage.Entry(childName, child.length, child.length, false);

                // Dalvik bytecode or a native library inside a library archive is not a library.
                String kind = Bytes.detectKind(child);
                if ("dex".equals(kind) || "elf".equals(kind)) {
                    if (executableInside == null) {
                        executableInside = signalFor(report, byRule, "ARC009", Category.PERSISTENCE,
                                Severity.HIGH,
                                "An archived library contains executable code",
                                "A jar under libs/ is expected to hold Java classes. Dalvik bytecode or a"
                                        + " native binary inside one is a payload travelling in a wrapper.");
                    }
                    executableInside.withEvidence(childName, kind + ", " + Bytes.humanSize(child.length));
                }

                Scope childScope = classify(synthetic.extension());
                String childText = childScope == Scope.BINARY
                        ? Bytes.extractedText(child, 6) : Bytes.text(child);
                // Only compare whole-file hashes when the member really reached EOF.
                // Pattern matching on the bounded prefix remains useful for partial members.
                boolean signaturesComplete = SignatureRules.match(report, byRule, synthetic, child, completeChild, signatures);
                matchIndicators(report, byRule, synthetic, childScope, childText);
                matchPairs(report, byRule, synthetic, childScope, childText);
                matchUserPatterns(report, byRule, synthetic, childText, database);
                checkEncodedPayloads(report, byRule, synthetic, childText);

                recordAnalysis(coverage, completeChild, child.length, database, signatures);
                recordSignatureCutoff(coverage, signaturesComplete, child.length, budget);
                if (!memberCutShort && Bytes.looksLikeZip(child)) {
                    scanNestedArchive(report, byRule, childName, child, budget, database, signatures,
                            depth + 1, coverage);
                } else if (Bytes.looksLikeZip(child)) {
                    coverage.set(Analyzer.NESTED_ARCHIVE, Status.SKIPPED, Reason.MEMBER_LIMIT, 0);
                } else {
                    coverage.set(Analyzer.NESTED_ARCHIVE, Status.NOT_APPLICABLE, Reason.NON_ARCHIVE, 0);
                }
                if (memberCutShort) {
                    for (CoverageLedger.Member record : records.values()) {
                        if (record.get(Analyzer.READ).reason == Reason.NOT_ATTEMPTED) {
                            skipped(record, granted >= NESTED_MEMBER_LIMIT
                                    ? Reason.MEMBER_LIMIT : Reason.BUDGET_EXHAUSTED);
                        }
                    }
                    // Preserve findings in the inspected prefix, but never call getNextEntry()
                    // after a bounded read stopped short: it would inflate the skipped tail.
                    break;
                }
            }
        } catch (IOException e) {
            report.addError("could not open " + parentName + ": " + e.getMessage());
            budget.markTruncated();
        } catch (RuntimeException e) {
            // A malformed archive must not take the scan down with it.
            report.addError("could not read inside " + parentName + ": " + e);
            budget.markTruncated();
        } finally {
            PluginPackage.closeQuietly(zin);
            for (CoverageLedger.Member record : records.values()) {
                if (record.get(Analyzer.READ).reason == Reason.NOT_ATTEMPTED) {
                    skipped(record, budget.exhausted() ? Reason.BUDGET_EXHAUSTED : Reason.READ_FAILED);
                }
            }
        }
    }

    private static void skipped(CoverageLedger.Member member, Reason reason) {
        for (Analyzer analyzer : Analyzer.values()) { member.set(analyzer, Status.SKIPPED, reason, 0); }
    }

    private static void failedRead(CoverageLedger.Member member, IOException failure) {
        Reason reason = String.valueOf(failure.getMessage()).contains("unsupported")
                ? Reason.UNSUPPORTED : Reason.READ_FAILED;
        skipped(member, reason);
        member.set(Analyzer.READ, Status.FAILED, reason, 0);
    }

    private static void recordSignatureCutoff(CoverageLedger.Member member, boolean complete,
            int bytes, ScanBudget budget) {
        if (!complete) {
            member.set(Analyzer.SIGNATURES, Status.PARTIAL, Reason.MATCH_LIMIT, bytes);
            budget.markTruncated();
        }
    }

    private static void recordRead(CoverageLedger.Member member, boolean complete, int bytes, Reason reason) {
        member.set(Analyzer.READ, complete ? Status.COMPLETE : Status.PARTIAL,
                complete ? bytes == 0 ? Reason.EMPTY : Reason.OK : reason, bytes);
    }

    private static void recordAnalysis(CoverageLedger.Member member, boolean complete, int bytes,
            IocDatabase database, SignatureDatabase signatures) {
        Status status = complete ? Status.COMPLETE : Status.PARTIAL;
        Reason reason = complete ? bytes == 0 ? Reason.EMPTY : Reason.OK
                : member.get(Analyzer.READ).reason;
        member.set(Analyzer.BUILTIN_RULES, status, reason, bytes);
        if (database != null && !database.loadErrors().isEmpty()) {
            member.set(Analyzer.USER_PATTERNS, Status.PARTIAL, Reason.DEFINITIONS_INCOMPLETE, bytes);
        } else if (database == null || database.patterns().isEmpty()) {
            member.set(Analyzer.USER_PATTERNS, Status.NOT_APPLICABLE, Reason.NO_USER_PATTERNS, 0);
        } else {
            member.set(Analyzer.USER_PATTERNS, status, reason, bytes);
        }
        boolean unavailable = signatures != null && (!signatures.problems().isEmpty()
                || signatures.unsupportedCount() > 0 || signatures.cappedCount() > 0);
        if (unavailable) {
            member.set(Analyzer.SIGNATURES, Status.PARTIAL, Reason.DEFINITIONS_INCOMPLETE, bytes);
        } else if (signatures == null || signatures.isEmpty()) {
            member.set(Analyzer.SIGNATURES, Status.NOT_APPLICABLE, Reason.NO_DEFINITIONS, 0);
        } else {
            member.set(Analyzer.SIGNATURES, status, reason, bytes);
        }
    }

    private static boolean verifyNestedMetadata(ScanReport report, ScanBudget budget, String parentName,
            ArchiveIndex.Member indexed, ZipEntry local) {
        if (indexed != null && indexed.matches(local)) {
            return true;
        }
        report.addError(parentName + "!" + local.getName()
                + ": nested local and indexed metadata could not be verified");
        budget.markTruncated();
        return false;
    }

    /** True when the manifest names this source file as an interface or the settings screen. */
    private static boolean isDeclaredEntryPoint(String memberName, ScanReport report) {
        java.util.List<String> declared = report.manifest.declaredClasses();
        for (int i = 0; i < declared.size(); i++) {
            String className = declared.get(i);
            if (className == null || className.length() == 0) {
                continue;
            }
            String asPath = className.replace('.', '/') + ".java";
            if (memberName.endsWith(asPath)) {
                return true;
            }
            int lastDot = className.lastIndexOf('.');
            String simple = lastDot >= 0 ? className.substring(lastDot + 1) : className;
            if (memberName.endsWith("/" + simple + ".java") || memberName.equals(simple + ".java")) {
                return true;
            }
        }
        return false;
    }

    private static Scope classify(String extension) {
        if (SOURCE_EXTENSIONS.contains(extension)) {
            return Scope.SOURCE;
        }
        if (TEXT_EXTENSIONS.contains(extension)) {
            return Scope.TEXT;
        }
        // Unknown and compiled members are searched for printable runs, which is safe either way.
        return Scope.BINARY;
    }

    private static void matchIndicators(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry entry, Scope scope, String text) {
        List<Indicator> indicators = CodePatterns.indicators();
        for (int i = 0; i < indicators.size(); i++) {
            Indicator indicator = indicators.get(i);
            if (!indicator.appliesTo(scope)) {
                continue;
            }
            Matcher matcher = indicator.pattern.matcher(text);
            boolean found = false;
            while (matcher.find()) {
                if (!indicator.excludedAt(text, matcher.start())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                continue;
            }
            Signal signal = signalFor(report, byRule, indicator.ruleId, indicator.category,
                    indicator.severity, indicator.title, indicator.detail);
            signal.withEvidence(location(entry, text, matcher.start()), snippet(text, matcher.start(), matcher.end()));
        }
    }

    private static void matchPairs(ScanReport report, Map<String, Signal> byRule, PluginPackage.Entry entry,
            Scope scope, String text) {
        List<PairIndicator> pairs = CodePatterns.pairs();
        for (int i = 0; i < pairs.size(); i++) {
            PairIndicator pair = pairs.get(i);
            if (!pair.appliesTo(scope)) {
                continue;
            }
            Matcher firstMatch = pair.first.matcher(text);
            if (!firstMatch.find()) {
                continue;
            }
            Matcher secondMatch = pair.second.matcher(text);
            if (!secondMatch.find()) {
                continue;
            }
            Signal signal = signalFor(report, byRule, pair.ruleId, pair.category, pair.severity,
                    pair.title, pair.detail);
            signal.withEvidence(location(entry, text, firstMatch.start()),
                    snippet(text, firstMatch.start(), firstMatch.end()) + "  +  "
                            + snippet(text, secondMatch.start(), secondMatch.end()));
        }
    }

    /**
     * Heuristics on the shape of Java source rather than its contents.
     *
     * <p>A v2 plugin ships source precisely so it can be read. Source that has been mechanically
     * shortened or squeezed onto single lines has had that property removed on purpose.
     */
    private static void checkSourceShape(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry entry, String text) {
        int longestLine = 0;
        int lineStart = 0;
        for (int i = 0; i <= text.length(); i++) {
            if (i == text.length() || text.charAt(i) == '\n') {
                longestLine = Math.max(longestLine, i - lineStart);
                lineStart = i + 1;
            }
        }
        if (longestLine > 2000) {
            Signal signal = signalFor(report, byRule, "OBF007", Category.OBFUSCATION, Severity.MEDIUM,
                    "Source has been squeezed onto very long lines",
                    "MT plugins ship source so it can be read. Source formatted this way is not meant to be.");
            signal.withEvidence(entry.name, "longest line is " + longestLine + " characters");
        }

        // Only type declarations count. An earlier version also matched `int i`, which made every
        // ordinary for-loop look like obfuscation; obfuscators rename types, so that is what to look at.
        int singleLetterDeclarations = countMatches(text,
                Pattern.compile("\\b(class|interface|enum)\\s+[a-zA-Z]\\b"));
        if (singleLetterDeclarations >= 5) {
            Signal signal = signalFor(report, byRule, "OBF008", Category.OBFUSCATION, Severity.MEDIUM,
                    "Identifiers look machine-shortened",
                    "Many one-character class, method and field names, which is what an obfuscator leaves"
                            + " behind. Unusual in source a plugin ships for review.");
            signal.withEvidence(entry.name, singleLetterDeclarations + " single-letter declarations");
        }
    }

    /**
     * Decodes long embedded Base64 and looks at what comes out.
     *
     * <p>This is where an "empty-looking" plugin gives itself away: the source reads harmlessly and the
     * payload sits in a string constant. Decoding one level is enough to see an archive header, Dalvik
     * bytecode, or a drop endpoint.
     */
    private static void checkEncodedPayloads(ScanReport report, Map<String, Signal> byRule,
            PluginPackage.Entry entry, String text) {
        Matcher matcher = BASE64_BLOB.matcher(text);
        int examined = 0;
        while (matcher.find() && examined < 4) {
            examined++;
            byte[] decoded = Bytes.base64Decode(matcher.group());
            if (decoded == null || decoded.length < 64) {
                continue;
            }
            String kind = null;
            if (Bytes.looksLikeZip(decoded)) {
                kind = "a zip, apk or mtp archive";
            } else if (Bytes.looksLikeDex(decoded)) {
                kind = "Dalvik bytecode";
            } else if (Bytes.looksLikeElf(decoded)) {
                kind = "a native executable";
            } else if (decoded.length > 4 && decoded[0] == (byte) 0xCA && decoded[1] == (byte) 0xFE) {
                kind = "a Java class file";
            }
            if (kind != null) {
                Signal signal = signalFor(report, byRule, "OBF005", Category.OBFUSCATION, Severity.CRITICAL,
                        "An encoded blob in the source decodes to executable code",
                        "The package hides code inside a text constant. This is how a plugin passes review"
                                + " looking harmless and then runs something else.");
                signal.withEvidence(location(entry, text, matcher.start()),
                        Bytes.humanSize(decoded.length) + " of " + kind);
                continue;
            }

            // Not code, but the decoded text may still name where data is being sent.
            String decodedText = Bytes.text(decoded);
            List<Indicator> indicators = CodePatterns.indicators();
            for (int i = 0; i < indicators.size(); i++) {
                Indicator indicator = indicators.get(i);
                if (!indicator.severity.atLeast(Severity.MEDIUM)) {
                    continue;
                }
                Matcher inner = indicator.pattern.matcher(decodedText);
                if (inner.find()) {
                    Signal signal = signalFor(report, byRule, "OBF006", Category.OBFUSCATION, Severity.HIGH,
                            "An encoded blob hides a risky reference",
                            "Something the plugin would rather a reader did not see is stored encoded"
                                    + " instead of in plain text.");
                    signal.withEvidence(location(entry, text, matcher.start()),
                            indicator.ruleId + " inside decoded data: "
                                    + snippet(decodedText, inner.start(), inner.end()));
                    break;
                }
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Returns the existing finding for a rule, or registers a new one. */
    static Signal signalFor(ScanReport report, Map<String, Signal> byRule, String ruleId,
            Category category, Severity severity, String title, String detail) {
        Signal existing = byRule.get(ruleId);
        if (existing != null) {
            return existing;
        }
        Signal created = new Signal(ruleId, category, severity, title, detail);
        byRule.put(ruleId, created);
        report.add(created);
        return created;
    }

    /** "src/Foo.java:42" for source, plain member name otherwise. */
    private static String location(PluginPackage.Entry entry, String text, int offset) {
        String ext = entry.extension();
        if (!SOURCE_EXTENSIONS.contains(ext) && !TEXT_EXTENSIONS.contains(ext)) {
            return entry.name;
        }
        int line = 1;
        int limit = Math.min(offset, text.length());
        for (int i = 0; i < limit; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return entry.name + ":" + line;
    }

    /** A short, single-line excerpt centred on the match. */
    private static String snippet(String text, int start, int end) {
        int from = Math.max(0, start - 24);
        int to = Math.min(text.length(), Math.max(end + 32, start + 48));
        String raw = text.substring(from, to);
        return raw.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim();
    }

    private static int countMatches(String text, Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find() && count < 1000) {
            count++;
        }
        return count;
    }
}
