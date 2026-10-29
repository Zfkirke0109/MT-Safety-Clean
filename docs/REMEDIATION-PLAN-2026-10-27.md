# MT Scanner remaining-issue remediation

Base: `66f9860f1291672a9e685f4230b1a16d4a9de821`.
User authorization: fix all remaining issues using the previously selected plugins, then place the
verified `.mtp` in the connected phone's Downloads and notify the user. This supersedes earlier
phase-only restrictions for source changes, necessary reviewed build inputs and the requested final
download/notification. It does not authorize installing the plugin, merging, publishing a release,
executing inspected payloads, privilege escalation, or destructive changes on the user's phone.

## Global constraints

- Preserve SDK3, Java8, `pluginID=mt.safety.scanner`, `.mtp`, min API24 and compile-only MT host API.
- Never present unsupported/failed/partial work as fully clean. Never infer proven exfiltration from
  independent capabilities. Preserve true signature/denylist/destructive evidence and confirmations.
- Inputs remain static data. Only scanner-owned code and trusted OS tools may execute.
- Bounded reads, counts, memory accounting and monotonic deadlines; cancellation must not block UI.
- Keep work in isolated task worktrees; tests/build outputs use task-specific TMPDIRs. Parent alone
  integrates, updates GitHub, accesses the device, downloads the final package and notifies.
- Tests must demonstrate regressions before their fixes. Do not weaken assertions to manufacture green.
- Unsupported encryption without a key and arbitrary-secret recognition are inherent limits, not
  proof of safety. Provide explicit coverage and content-free sharing paths instead of false claims.

## Task 1 — Signature definition memory and freshness

Own SignatureDatabase and focused new tests. Bound aggregate input bytes and all retained entry
classes (including clean/ignored names) with conservative retained-memory accounting. Stream parse
instead of reading entire 64 MiB files into multiple copies. Content-hash the bounded definition set
for cache freshness, detect mutation across loading, and expose incomplete diagnostics. Parent will
integrate any small ScanRunner cache-call changes; do not edit ScanRunner or ScannerTest.

## Task 2 — Capability calibration

Own RiskScorer, relevant rule documentation/generator and focused scoring tests. Keep CMB IDs stable;
mere sensitive-data/network, loader/network, shell/network or capture/network co-occurrence is
potential capability evidence, not observed exfiltration/remote control. Use conservative MEDIUM
combination signals without silently de-escalating valid known-malware signatures, explicit denylist,
direct destructive evidence or strong direct indicators. Prove before/after benign disconnected and
malicious controls; update contradictory documentation. Latest user authorization includes issue #9.

## Task 3 — Android responsiveness and isolated scan boundary

Own ScannerPreference and new scanner-owned execution helpers. Move expensive scan/file/action work
off Android UI callbacks, retain responsive status and safe lifecycle handling. Investigate a bounded
own-code subprocess boundary for untrusted scan operations with wall deadline and heap limit, public
API24-compatible mechanisms only. Coordinate needed Host/ScanRunner hooks with parent before edits.
No installation or device changes; parent performs own-code ART harness validation. Preserve SDK3 UI.

## Task 4 — Legacy Android bounded directory traversal

Own DirectoryListing and focused tests. Provide a bounded, non-eager API24/25 implementation using
public APIs or a vetted fixed system-tool argv if necessary, without shell interpretation, privilege
escalation, user-content execution or unbounded File.listFiles fallback. Verify compatibility from
primary Android sources and close/cancel child resources; fail closed if capability is unavailable.
Parent performs actual Android probes.

## Task 5 — Build integrity and dedicated static checks

Own tools/build.sh, CI workflow(s), new build verification scripts and provenance docs/tests. Enforce
expected SHA256 for every downloaded/cached toolchain input, pin Actions, compare actual DEX against
fresh build in artifact checks, produce deterministic member manifest and SBOM/provenance receipts.
Add and actually run dedicated security/secret checks where supported (CodeQL and/or Semgrep plus
secret scan); report unavailable engines honestly. Do not touch dist/package or deploy. Review any
developer-only download with exact source, version, hash, license. Coordinate any archive runtime
library build requirements with parent. Preserve JDK/D8 API24 pipeline; no Gradle/APK rewrite.

## Task 6 — Archive decoder feasibility and support

Own archive-support research and, after communicating design, isolated adapter/new tests. Determine
genuine ZIP95 fixtures and bounded XZ decoding using primary upstream specifications/implementations.
No fake method-95 header specimen may be called decoder proof. A new library requires exact vetted
version/hash/license/transitives, Java8/D8 compatibility and fixed decoder-memory allowance. Preserve
metadata admission, CRC/size/flags checks, duplicate identities, nested limits and truthful coverage.
Encrypted or unsupported formats remain explicit and cannot become clean. Do not modify build script
or shared PluginPackage/ArchiveIndex/CodeRules without coordinating file ownership with parent.

## Parent integration — Coverage, action policy, privacy and delivery

Implement bounded member/analyzer outcomes with stable reason codes, additive JSON and truthful
coverage. Integrate signature freshness, UI isolation and archive hooks. Resolve action safety without
claiming an atomic boundary against arbitrary same-UID code; use the safest reviewable policy for
unavoidable non-atomic mutations. Provide content-free share/export mode for arbitrary secrets and
keep useful local evidence separate. Run full baseline/new tests, independent standards/spec reviews,
package/CI/DEX verification, and own-code Android harness without installation. Obtain/read formal
review where available; do not claim quota-blocked review approval. Finally download only the verified
new artifact to `/sdcard/Download` using a unique filename, verify its phone hash, and notify the user.

## Preflight rulings

| Task/interface overlap | Ruling |
| --- | --- |
| Definitions ↔ ScanRunner cache | Definition agent owns parser/stamp; parent applies cache integration. |
| UI ↔ Host/ScanRunner | UI agent proposes hooks first; parent owns shared orchestration edits. |
| Legacy listing ↔ definitions/archive/actions | Preserve DirectoryListing public visitor API. |
| Archive support ↔ build | Archive agent supplies vetted dependency/adapter requirements; build agent coordinates through parent. |
| Archive adapter ↔ coverage ledger | Parent owns shared package/scanner/coverage integration. |
| Action safety ↔ existing mutation feature | Do not silently trade data safety for apparent atomicity; record product-policy decision before edits. |
| All task builds ↔ temporary outputs | Separate worktrees and TMPDIRs; no shared `/tmp/mt-safety-build` compilation. |

Each task has independent owned files and tests. Integration and two-axis reviews occur before final
packaging/delivery. Missing proof remains missing proof; no successful build is an MT host install test.
