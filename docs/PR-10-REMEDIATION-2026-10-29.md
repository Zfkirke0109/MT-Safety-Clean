# PR10 remediation and verification

Baseline: `66f9860f1291672a9e685f4230b1a16d4a9de821`. The user's authorization covers fixing
remaining issues, necessary reviewed builds, and delivery of a verified uniquely named MTP to the
S26 Ultra Downloads. Installation, merging, release publication and privilege escalation remain
outside this delivery. The source commit and final artifact identity are recorded separately in
`docs/DELIVERY-STATUS.json`; GitHub checks must be read from the actual current PR head.

## Corrected findings

| Area | Result and verification |
| --- | --- |
| Definition memory/freshness | Streamed bounded loading, aggregate source/retained-entry accounting, content-based cache stamps and change-during-load refusal. Signature database regressions retain independent valid sources after failures. |
| Signature semantics | Multi-byte alternatives retain whole branches; unsupported syntax refuses instead of clamping. Shared bounded work/hit cutoffs retain prior valid evidence and report incomplete analysis. 21 focused checks include EOF offsets against true logical length, unknown-length prefixes and valid offsets within prefixes. |
| Capability calibration / issue9 | Mere co-occurrence remains suspicious capability evidence, not inferred exfiltration, remote control or known malware. Direct critical indicators, exact malware signatures and denylist evidence retain their effect. |
| Android responsiveness | Single-flight asynchronous dispatch, bounded snapshots, own-code worker IPC and independent supervision. Fixed trusted ART paths, explicit 96MiB heap and runtime enforcement; no scanned code is loaded. |
| Legacy enumeration | Fixed system toybox argv with NUL records, bounded records/bytes/deadline and cancellation. No eager fallback. Special filenames and forced legacy backend pass on the S26. |
| First-run and scanner-owned writes | Unique staging for replacement; exclusive no-follow descriptor creation on Android for initial indicators. Existing files and dangling links survive; 6 seed and 27 atomic-file checks plus live Android controls. |
| Other-plugin action races | Scanner mutation/uninstall/quarantine paths are disabled/delegated to MT Manager. This avoids claiming atomic authority over arbitrary same-UID paths. Legacy actions refuse without changing target data; viewing existing receipts remains supported. |
| ZIP95 and archive identity | Genuine independent upstream ZIP95 fixture, bounded XZ1.12 decoding and exact raw indexed identities. Checked offsets, headers, descriptors, CRC, sizes, flags, duplicates and nested limits. Encryption/unsupported codecs remain explicit. |
| Selected-file archive salvage | One unreadable/corrupt/encrypted member no longer hides later verified peers. Zero-size and directory records also undergo bounded codec validation; directory payloads mark incomplete. 59 ZIP95/container checks cover these cases. |
| Coverage accounting | Bounded member/analyzer ledger with stable reasons; dropped work cannot become complete. Oversized manifest prefixes refuse full parsing. Uncapped error-event accounting prevents a saturated display list from hiding nested cutoffs. |
| Immediate file results | Incomplete definitions, prefix reads and matcher limits qualify the immediate UI result. No unqualified no-hit claim after partial work. 12 runner/export checks. |
| Privacy | Content-free share export excludes arbitrary paths, names, findings content and imported secrets. Useful local evidence remains separate. 122 share-formatter checks. Recognized-secret redaction does not claim universal recognition. |
| Supply chain/package | Every pinned original/extracted/flattened input reverified. Sorted Java/JAR/MTP members, fixed ZIP metadata, all DEX hashes, provenance/SBOM and actual rebuilt-member comparisons. SDK3 identity, Java8, minAPI24 and compile-only host API retained. |
| Dedicated checks | Actual Gitleaks8.28.0 and Semgrep1.138.0 core scans, with positive controls; 49 production Java files, five local AST rules. Only two reviewed fixed OS-process launch locations remain. CodeQL was not configured or run. |

The final specification pass reproduced three additional defects before correction: false EOF
prefix matches, lost supported peers, and zero-size validation bypass. Independent probes now
show no false EOF hit, retained later peer hits and explicit partial results for both genuine
method95 size corruption and unsupported method94. The tests were not weakened to pass.

## Executed verification

`bash tools/build.sh all` passed **610 main checks, 0 failed, 0 skipped**, all focused regression
mains and **15 Python integrity tests**. Focused mains include 89 decoder, 59 ZIP95/container,
21 signature, 4 IOC loading, 6 indicator seed, 27 atomic-file, 12 budget, 19 ledger, 5 ledger
completion, 122 share formatter, 13 single-flight, 30 worker boundary, 8 UI-policy and 12
runner/export checks. Legacy directory regression controls passed too. Counts are per suite,
not a claim of disjoint coverage. Real Android/MT SDK compilation with warnings as errors and
D8 minAPI24 passed. The actual SDK-backed preference snapshot test passed 8 assertions with
5,000 irrelevant legacy flags and a bounded request.

`python3 tools/security_checks.py --output <report-directory>` passed Gitleaks and both positive
controls. Semgrep scanned all 49 Java sources without engine/parser errors. Its two review-only
process findings are `DirectoryListing`'s fixed toybox command and `AndroidWorkerLaunch`'s fixed
trusted ART command. Neither selects an executable from inspected content. Exact reviewed
checksum-only Gitleaks exceptions do not disable general hex strings or paths.

The scanner-owned app-UID ART harness passed **16 checks** on Zachary's S26 Ultra SM-S948U,
API37, UID10271. It verified first creation/no overwrite/dangling links, special filenames,
legacy enumeration, actual worker launch, **100663296-byte heap**, inert signature IPC, normal
exit, wall timeout and cancellation with confirmed child exit. See the content-free JSON receipt
and reproducible source in `tools/android/`. Earlier app_process and hard-link implementations
failed the live tests and were replaced; they are not presented as successful device validation.

## Independent review results

### Standards

No remaining material hard-standard violation or refactor finding. The independent standards
review compiled Java8/Werror and ran six focused mains (84 checks), then inspected the final
EOF/member-salvage/zero-size corrections. It did not independently repeat final packaging or
device work.

### Specification

No remaining material finding in the scoped final tree. The independent specification reviewer
ran the full test target, then recompiled final changed sources and independently passed the
21 signature checks, 59 ZIP95 checks and all three original adversarial probes.

Both axes covered the baseline diff, working-tree corrections and relevant new production/tests.
These are independent assistant review sessions, not formal GitHub Copilot approval. Historical
Copilot attempts were quota-blocked; its earlier comments remain auditable. All reproduced
material findings have source changes and regression evidence.

## Limits and delivery gates

- **MT host installation/UI/lifecycle/performance: NOT_RUN.** The user has authorized downloading
  the plugin, not installing it. The ART harness does not establish MT host compatibility.
- **Physical API24/25 test: NOT_RUN.** Java8/SDK/D8 checks and forced legacy testing on API37 do
  not substitute for an older-device runtime test. Denied/unavailable runtime capabilities fail
  closed with incomplete inspection.
- The worker is bounded own-code execution under the host app UID, not a same-UID security
  boundary or a sandbox for running unknown plugins. Heap cap is not an exact total-RSS cap.
- Finite byte/count/time/depth limits can leave content uninspected. Encryption without a key,
  unsupported formats and parser failures remain explicit partial/unreadable outcomes, not clean.
- Static capability evidence is not observed runtime data flow. Signature matches depend on the
  imported definitions and can require human assessment.
- Provenance is an unsigned receipt. Same-toolchain package reproducibility and complete member
  comparison are verified; reproducibility across arbitrary JDKs/OS versions is not promised.
- CodeQL, formal fresh Copilot approval and an installed MT host test are not claimed.

Only a current-head `READY_FOR_USER_INSTALL` manifest with artifact SHA256/size/source commit,
zero remaining material findings and passing current-head CI permits delivery. Download uses
the manifest's unique name without replacing a different file, then verifies phone SHA256 and
size. No install, merge or release follows automatically. Rollback is a reviewed revert of the
remediation commits on this PR branch; earlier defects and removed unsafe action behavior would
return. Preserve main and unrelated/stacked PR work.
