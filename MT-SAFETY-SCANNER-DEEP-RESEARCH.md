# MT Safety Scanner — independently corrected technical research and architecture

**Revision:** 2026-10-09 PDT. See `FINAL-ADVERSARIAL-FACT-CHECK.md` for verification labels and original-claim triage. This report is design guidance, not tested implementation. Current source HEAD `90de1e15ef4ce9ad20e272a64daa52b4ed56a189`; all references below are to its unchanged source.

## 1. Actual data flow and trust boundaries

```text
MT Manager (host app / SDK v3 / own UID, plugin classes.dex)
  | plugin manager + PluginPreference settings onBuild()/onClick()
  v
plugin/ui-v3/mt/safety/scanner/ui/ScannerPreference.java
  -> plugin/src/mt/safety/scanner/ScanRunner.java
  -> core/Discovery.java + core/PluginPackage.java [untrusted .mtp/archive/installed sidecars]
  -> core/ManifestRules.java + core/ArchiveRules.java
  -> core/CodeRules.java + core/SignatureRules.java + core/SignatureDatabase.java
  -> core/RiskScorer.java -> core/ScanReport.java/ReportFormatter.java
  -> host preference rows / user report; separately confirmed explicit user actions -> Quarantine.java
```

Trust boundary 1: local plugin archive, nested script/dex/native members, unsupported and encrypted data, irregular paths, duplicate entries. Treat metadata and decompressed bytes as attacker-controlled. Trust boundary 2: imported signature rules, trust/deny lists and cache stamps; a hostile signature file must not cause allocation blowup, catastrophic regex, parser loop, or fake detections. Trust boundary 3: host API and private files; plugin should not request more privileges or execute inspected code. Trust boundary 4: reports and operator actions, including secrets and output paths; never display raw passwords, bearer tokens, complete sensitive excerpts or arbitrary private filesystem paths. Trust boundary 5: toolchain/dependency downloads during CI, releases and off-host optional analyzers; external services must be opt-in.

The installed-plugin approach in `PluginPackage.java:550-590` attempts to collect MT-extracted sidecar files (including dex) next to archives. Whether a protected sidecar is accessible depends on the **host's permitted UID and SDK**; root/Shizuku is not required and must not be silently used. Full completeness is impossible for encrypted, deleted, missing or inaccessible content; measured coverage is the product feature.

## 2. Architecture alternatives (ADR-001 decision)

| Design | Security value | Mobile cost | SDK v3 risk | Implementation effort | Verdict |
|---|---|---|---|---|---|
| A. Enhance monolithic in-process Java scanner | Fast incremental fixes; low dependency cost | Low initially, rising with parser load | Lowest immediate, highest long-term coupling | Small | **Use only as incremental staging** for coverage bug fix |
| B. Modular analyzer interface within current plugin and budgets | Reliable member accounting, evidence, reproducibility, pluggable parsers | Controllable per analyzer | Medium and testable with existing D8 chain | Medium | **Recommended core**, but phase safely |
| C. Thin MT UI with optional external heavy analysis service/Termux | Best for JADX, decompilers, large graph algorithms, YARA-X | Low host / high external | Host IPC/auth/privacy issues; external app not universally present | High | **Optional later**, explicit user opt-in and shared export protocol only |

Decision **B**, progressively. PR1 may be a minimal backwards-compatible extension to existing classes, not an immediate wholesale refactor. Do not introduce an Android app, WorkManager, JNI engine, root service, Gradle or `androidx` dependency unless MT v3 compatibility is directly proved.

## 3. Proposed types (not existing classes)

```java
// Illustrative Java 8 interface proposal; NOT compiled or integrated yet.
public interface MemberAnalyzer {
    String id();
    void inspect(MemberView member, ScanContext context) throws java.io.IOException;
}
public interface MemberView {
    String logicalPath();
    long declaredSize();
    java.io.InputStream openBounded() throws java.io.IOException;
}
public enum CoverageState { COMPLETE, PARTIAL, UNSUPPORTED, INACCESSIBLE, ERROR }
```

`ScanContext` (proposed) owns shared deadline, byte budget, depth, counters, cancellation and evidence writer; `MemberView` must not return an unbounded stream in real implementation. `Result` must preserve existing `Verdict` and legacy JSON fields while adding `coverage`, `summary`, `entryFindings`, and `schemaVersion`. **Disposition** and **severity** are not the same as completeness. Invalid or inaccessible entry is neither clean nor malicious. No percentage without trustworthy denominator. `member key` = normalized path plus archive index (not filename alone; duplicates exist). Hash entire package from bounded source only, not parsed content that silently omitted a method.

Suggested per-entry statuses: `DISCOVERED`, `DECODED_COMPLETE`, `SCANNED_PARTIAL`, `UNSUPPORTED_COMPRESSION`, `ENCRYPTED`, `INACCESSIBLE`, `CORRUPT`, `LIMIT_EXCEEDED`, `SKIPPED_POLICY`. Aggregate `COMPLETE` only if every in-scope member has acceptable complete status and all required analyzers processed the bytes. Keep unknown denominator explicit. Existing `SCN001` continues as informational warning; if `coverage != COMPLETE`, suppress a confident CLEAN UI badge and explain `no findings in inspected content`.

## 4. ZIP/ZIP64 and XZ engineering

**Existing** `PluginPackage.ArchivePackage` uses stock `ZipFile`, and `structuralAnomalies` a `ZipInputStream`; nested ZIP reading `CodeRules` uses stock streaming. Stock API can't decode method95. Commons Compress 1.28.0 Java8 supports ZIP structural metadata and `getRawInputStream`; **its ZIP method95 enum is not decoder support**. `getInputStream` returns decompressed supported entries, NOT raw method95. For an XZ candidate, XZ for Java 1.12 has a bounded `SingleXZInputStream(..., memoryLimitKiB, verifyCheck=true)` and supports Java8. Actual ZIP95 framing, size, flags, data descriptor, possible extra metadata and CRC32 require the real method95 fixture to confirm. No working code should be merged before this proof.

ZIP95 spike acceptance: fixture created by independent archive tool actually emitting `method=95` in **local and central headers**; SHA256 of expected *decoded* content from another decoder; verified central index offsets, bit flags, ZIP64 values, XZ header/footers and checksum, expected uncompressed count, ZIP CRC32. Test wrong ZIP95 flags, missing XZ header, truncation, wrong size/CRC, encrypted bit, central/local disagreement, data descriptor, duplicate path. `zip.canReadEntryData` should not be overridden to mean arbitrary raw-stream decoder success. Prefer central directory random access for duplicates; avoid `ZipArchiveInputStream` under malformed data descriptors where it can misread content. If no authenticated method95 specimen, leave unsupported and count it truthfully. https://commons.apache.org/proper/commons-compress/zip ; https://tukaani.org/xz/java.html ; https://support.pkware.com/pkzip/appnote .

**Caps to preserve initially:** UI interactive 4s/24MiB, deep 20s/256MiB, file scan 6s/64MiB and deep files 90s/1GiB; `CodeRules` nested count 400/depth2; `ScanRunner` total 6/30 seconds per run with per-plugin 16MiB; structural inflation via `walkInflationCap`. These caps overlap and do not prove CPU preemption. Proposed additional caps under review: max per decoder memory e.g. 16MiB KiB budget (explicit KiB conversion), 256KiB header parse, >=0 archive offsets and overflow guards, max entries 4k, max depth 2, max single member 8MiB interactive, 64MiB deep; **these are design candidate values**, not measured or verified defaults. Enforce **post-decompression** bytes/time/ratio globally and per member and count skipped bytes, never trust declared size alone. Distinguish `limit-hit` from malformed. Don't raise defaults to 50 nested levels or GB-scale inflation. No uncontrolled on-disk extraction or symlink-following.

## 5. Static analysis: prioritize proof over complexity

Stage 1 maintain existing byte/string/regex detection (with provenance) and add DEX magic/header checksum sanity and instruction-level invoke recognition, Smali `invoke-*`/`const-string` tokenizer with comment awareness. Prefer Google-maintained `com.android.tools.smali:smali-dexlib2` candidate (BSD-3-Clause), or minimal own bounded reader for a small API inventory if full dependency exceeds D8 size; test both alternatives. Check `invoke-static`, `invoke-virtual`, `invoke-interface`, method references, field access, encoded values, jumbo strings, multiple dex, malformed counts and map boundaries. Do **not** run code.

Stage 2 JavaScript lexical parser: distinguish comments/string-only false positives, parse with a reviewed *no-evaluation* parser if compatible or conservative token scanner; never call `eval`, Rhino `Context.evaluateString` or VM. Flag `eval`, dynamic constructor, remote loader, fetch/XHR/WebSocket, process APIs only as capabilities with confidence grounded in AST location. Stage 2 ELF: bounds-checked `e_ident`, class32/64, endian, program/section headers, `.dynsym`, DT_NEEDED, imports, JNI exports; sectionless and stripped ELF must report partial semantic coverage, not corruption. Optional external JADX, jadx-cli, readelf, YARA-X and full taint are **outside MT plugin**, with user opt-in and no private upload.

Stage 3 bounded source→sink graph: sources (private files/clipboard/contact/etc) → reaching definitions → actual outgoing sink call arguments, accounting for `move`, `move-result`, register reuse, constants, control-flow joins, callee summary and path feasibility. A method containing both `getDeviceId()` and `HttpURLConnection.getOutputStream()` is only co-occurrence until a data-flow edge is proven; HIGH confidence refers to evidence *for that specific rule*, not calibrated probability. Multi-method/data-obfuscation analysis is optional external. Runtime command execution, Shizuku access and reflection are expected capabilities of legitimate MT extensions; never claim malicious solely because they appear.

## 6. Signature intelligence and safety

Current `SignatureDatabase.java` handles selected ClamAV `.hdb`, `.hsb`, `.ndb`, `.fp`, `.sfp`, `.ign2` with bounded count/size/line limits and skips unsupported; `HexSignature.java` handles a subset of syntax. Do not promise ClamAV parity. Implement explicit `supported/skipped/malformed/duplicate/capped` counters by file and syntax; normalize duplicate signatures; refuse giant wildcard patterns and unsupported offset target combos. Preserve correct MD5/SHA1/SHA256 length and **exact whole-file size** semantics, optional `*` size according to format; test named target types, EOF, negation/FLEVEL, anchoring, short files, overlapping hits. Cross-check behavior with clamscan in an **offline reference environment** only for syntax ClamAV actually supports, never execute payloads. YARA-X and native ClamAV would add package size, ABI/JNI/host fragility and are not justified for SDK v3 in-process; offer isolated offline optional backend later.

Definition updates should default to local import only. Opt-in updater: allowlist HTTPS endpoints, independent pinned pubkey or signed manifest with replay/version controls, staged bounded parser validation, atomic same-filesystem replacement and recovery, rollback last good set, observe counts and source freshness. ClamAV official format docs: https://docs.clamav.net/manual/Signatures.html ; https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html . A large signature count is not proof of accuracy, and downloaded third-party signatures may yield false positives.

## 7. Provenance and build hardening

Native `.mtp` is a plugin ZIP, not an Android `.apk` with APK Signing Scheme guarantees. A recognized MT plugin ID or SHA-256 alone does not authenticate publisher. A plugin distribution layer can independently verify detached Ed25519-signed manifest with pinned key and revocation/rotation plan; release attestations and Sigstore are candidates but require upstream publishing and trust roots, not assertions. Nested APKs may optionally receive APK signature verification, separate from `.mtp` provenance. Generate evidence-based SBOM candidates from JAR/POM metadata but never claim version or vulnerability definitively based solely on embedded strings. OSV matches require ecosystem, package identity, version, advisory, and exploitability caveats. Signature definitions and build tool downloads need their own trusted provenance.

**Exact current toolchain** `tools/build.sh`: Java desktop `javac --release 8`, plugin `javac -source 8 -target 8 -bootclasspath android.jar` (Android API30), MT API AAR `3.0.0` compile-only, R8 tool with D8 `8.9.35`, `--min-api 24`. `plugin/manifest.json` minAndroidVersion24, SDK3, dexMode true, `mainPreference` unchanged. No Gradle files in repo. Keep bundled libs separated from provided MT API and profile dex method count, transitive dependencies, license NOTICE and host classloader conflicts. `.mtp` package `dist/mt-safety-scanner.mtp` is ZIP with manifest+classes.dex+assets. CI currently excludes dex hash in CONTENTS; therefore do not say provenance verified.

## 8. Risk scores, evidence schema, defaults

```json
{
  "schemaVersion": 2,
  "pluginId": "example.plugin",
  "packageSha256": "...",
  "coverage": {"status": "PARTIAL", "membersTotal": 3,
    "membersComplete": 2, "membersUnsupported": 1, "reasons": ["ZIP_METHOD_95"]},
  "disposition": "NO_THREAT_DETECTED_IN_INSPECTED_CONTENT",
  "findings": [{"id": "FINDING-001", "ruleId": "DEX_DYNAMIC_LOAD",
    "category": "DYNAMIC_CODE", "severity": "MEDIUM", "confidence": "HIGH",
    "evidenceKind": "DEX_INVOKE", "member": "classes.dex",
    "class": "Lexample/Loader;", "method": "run()V", "offset": 24,
    "observations": ["invoke-virtual of a class loader"],
    "explanation": "Dynamic load capability detected, malicious use not established",
    "legitimateInterpretation": "Module loading in a developer plugin",
    "suggestedVerification": "Inspect origin and target of loaded bytes",
    "remediation": "Review loader provenance and permissions"}]
}
```

**Illustrative JSON**, not tested output. Severity = impact if misused; confidence = quality of inference; coverage = inspected fraction/support; disposition = threat conclusion. `CONFIRMED_MALICIOUS` should require strong trusted signature/provenance corroboration and human triage; third-party hashes are fallible. Deterministic finding IDs should hash rule+member path+byte offset+normalized evidence and stable rule version; de-duplicate by evidence, not by category alone. Confidentiality: redact likely keys, tokens, personal data and file excerpts; no remote submission by default. Exports may include SARIF later but JSON/backwards compatibility first.

## 9. Ranked improvements and decision triggers

| Rank | Task | Security value | Complexity | Device cost | FP direction | Hard gate |
|---|---|---|---|---|---|---|
| P0 | Baseline and known failure fixtures | Critical | Low | Zero | lower | PR0 review |
| P0 | Coverage and false-clean prevention | Critical | Medium | Low | lower | legacy tests and UI semantics |
| P1 | ZIP95 feasibility spike | High | Medium | Medium | neutral | genuine method95 fixture + independent decode |
| P1 | Bounded member-reading abstraction | High | High | Low/Medium | lower | fuzz and D8 |
| P1 | Source-grounded evidence/confidence | High | Medium | Low | much lower | benign controls |
| P2 | DEX invoke analysis | High | Medium/High | Medium | lower | dependency/build/license gate |
| P2 | ClamAV format conformance | High | Medium | Medium | lower | deterministic cross-engine tests |
| P2 | Signature and build provenance | High | Medium | Low | lower | pinned trust roots |
| P2 | JS lexical / ELF imports | Medium | Medium | Low | lower | parser memory cap |
| P3 | Taint-like correlation | Medium/High | High | High | lower if proven | source→sink witness |
| P3 | Cache/thread scheduling | Medium | High | Lower when correct | neutral | host callback proof and thermal measurements |
| P4 | External heavyweight backend | Potentially high | Very high | Optional | depends | explicit privacy and consent design |

**Stop conditions:** no authentic ZIP95 sample; any new dependencies unresolved; Java8/D8 incompatibility; important baseline regression; scanner reports a partial scan as clean; PII exposure; unbounded processing; MT host plugin fails to load; UI lifecycle cannot safely support async; automatic destructive actions; high benign false positives. Failing a stop condition means rollback the experimental PR, NOT remove protections.
