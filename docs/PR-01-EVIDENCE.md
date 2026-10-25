# PR #10 recovery and security handoff — 2026-10-24

**Decision: NOT_READY.** The scoped corrections pass local validation. An unbounded archive-metadata
allocation path remains open, Android runtime validation has not been performed, and final-commit CI
and formal Copilot review must be checked in the PR conversation. This document records the source
and local evidence included in this recovery commit; the PR description/conversation records its exact
commit SHA, subsequent workflow URLs, downloaded-artifact hashes and formal review outcome.

## A. Recovered context and authorization

- Repository: `Zfkirke0109/MT-Safety-Clean`; default branch `main`.
- Starting PR #10 branch: `copilot/report-incomplete-scan-coverage`.
- Starting HEAD: `5d3711dd7d12677827a24fe4a6678faf46575b94`, matching the supplied historical handoff.
- Current main: `0d7ec2b9262e96fb8989de2b3aba54ce3eb7e6ee`; merge base:
  `d8cceb62fb4ad143808bdc89bf8ae41814837d22`.
- The checkout was newly cloned and clean before modifications. No preexisting uncommitted work was
  discarded. All 17 existing PR commits are preserved; no rebase, force push or main merge was used.
- PR #11 remains an open, unmerged stacked draft at `5efba1a47d97fc64527b0ab07d77907624a66e06`.
  No PR #11 changes were made. PR #13 remains merged; main contains its updated Copilot instructions.
  The four main-only commits change only `.github/copilot-instructions.md`; updating the PR branch was
  unnecessary. The unchanged branch copy will not overwrite main's independently changed copy at merge.
- Open issues #8 and #9 were read. Issue #9's CMB101 calibration is explicitly a later phase and was
  left unchanged. The old instruction to create a fresh implementation branch is superseded by the
  user's explicit instruction to continue this existing PR. Stale PR0-only and uncommitted-handoff
  wording is superseded by the current user's authorization and the recorded PR1 owner authorization.
- Read `AGENTS.md`, README, manifest, build script and workflow in the required order; then all three
  required master/research documents, all three ADRs, the PR1 phase prompt, both instruction versions,
  acceptance criteria and validation matrix. Every specifically required handoff path exists.
- Read all formal PR #10 reviews, all 10 inline threads including resolved threads and replies, all
  13 conversation comments, commit history, issues, checks and workflow records using the connected
  GitHub integration and authenticated `gh`. GitHub is the authoritative history here.
- No accessible ChatGPT-history interface or connected browser-control tool was available. No claim
  is made to have read personal chat history, inaccessible task conversations, historical PDFs or
  attachments. The supplied handoff and committed research were used where those sources were absent.

Previous agents implemented coverage/disposition and additive JSON, partial-read propagation,
nested ZIP depth/EOF/cutoff handling, LOW/INFO reporting, unknown manifest enumeration, sibling identity
restrictions, streaming directory introduction and guarded quarantine changes across commits
`7438300` through `5d3711d`. Their final replies were claims to verify, not independent proof.
The PR body still named `ea66ff9` and 351 checks when recovery began. Actual starting push run
[38050676886](https://github.com/Zfkirke0109/MT-Safety-Clean/actions/runs/38050676886) and PR run
[38050680487](https://github.com/Zfkirke0109/MT-Safety-Clean/actions/runs/38050680487) are successful
attempt 2 runs for `5d3711d`; push job logs independently show 358/0 and SDK3/D8 packaging.

## Architecture and changes in this takeover

`ScannerPreference -> ScanRunner -> Discovery/MtEnvironment -> PluginPackage` discovers loose archives,
unpacked installations and archive-backed installations. PluginScanner reads manifest/name, captures
hash/canonical action identity, applies ManifestRules, ArchiveRules, CodeRules and signatures under
ScanBudget, then scores and reports separate coverage/disposition. ReportFormatter and ScanRunner
render/export those results. Installed siblings remain inspected but cannot authorize whole-directory
actions from an archive-only hash. User-confirmed actions revalidate identity through ScanRunner;
Quarantine moves, restore and purge operate separately on filesystem state.

This takeover:

1. Removed the `File`-subclass `listFiles()` allocation fallback. Streaming provider injection is
   package-private and instance-scoped; production always uses reflective streaming.
2. Charged rejected directory entries against existing 8000/400 limits. Iterator, close and entry
   failures preserve earlier entries/findings and revoke complete coverage and action identity.
3. Migrated discovery, ordinary file traversal and signature-folder enumeration to bounded streaming.
   Discovery reports incomplete searches, enforces its 200-result cap and retains overlapping-root
   behavior. Signature-folder enumeration counts ignored entries, caps at 4096, sorts bounded results,
   and invalidates caches after incomplete listings. Signature matching semantics were not changed.
4. Required a guard for every public quarantine move; the legacy overload remains callable but
   refuses without a scan-bound guard. Self-protection remains. Java caller interfaces are trusted
   host-UID APIs; they are not an unforgeable authorization boundary against arbitrary code in that UID.
5. Removed copy-and-delete quarantine/restore fallback. Failed rename preserves source data; failed
   restore retains its metadata for retry. `MoveGuard.allowCopyTarget()` defaults false for source
   compatibility, but there is no copy/delete move path left to authorize.
6. Refused source `quarantine-info.json` collisions, including observable dangling entries, bounded
   quarantine listing and safety/purge traversal, and added finite action identity rehash allowance.
   Rehash uses 4 seconds and 256 KiB of logical hash charge; existing hash cost is declared length/64,
   roughly 16 MiB of file data with rounding. This is not strict physical-I/O or CPU preemption.
7. Reported unavailable symlink fixtures as SKIPPED. Repaired a previously absent fixture parent and
   required successful link purge, link disappearance and target survival. Rebuilt the tracked `.mtp`
   from these sources; manifest identity, scoring, CMB101, ZIP95 capability and UI confirmations remain.

## B. Findings and dispositions

`FIXED_VERIFIED` below means source, regressions and independent agent inspection support the fix.
It does not mean a GitHub thread was resolved or a formal reviewer approved this commit.

| Finding | Severity / impact | Disposition | Evidence and remaining limit |
| --- | --- | --- | --- |
| [ZIP EOF probe](https://github.com/Zfkirke0109/MT-Safety-Clean/pull/10#discussion_r4236950405) | HIGH, hostile archive availability/coverage | FIXED_VERIFIED | Existing reservation includes probe; near-exhausted/cutoff/prefix-retention regressions pass. No advance after cutoff. Inflater compressed buffering and CPU remain unmetered. |
| [Directory allocation](https://github.com/Zfkirke0109/MT-Safety-Clean/pull/10#discussion_r4237496332) | HIGH, attacker-controlled directory memory exhaustion | FIXED_VERIFIED | Removed subclass allocation and remaining production array listings; bounded rejection/stream-failure and wide/count tests pass. OS calls remain nonpreemptive. |
| [Uninspected siblings](https://github.com/Zfkirke0109/MT-Safety-Clean/pull/10#discussion_r4237496347) | MEDIUM, false coverage/action eligibility | FIXED_VERIFIED | Escaping, failed canonicalization, incomplete listing and entry failures force PARTIAL and no action identity; prior findings retained. |
| [Symlink portability](https://github.com/Zfkirke0109/MT-Safety-Clean/pull/10#discussion_r4237496364) | MEDIUM, misleading test evidence | FIXED_VERIFIED | Normal run has zero skips. Missing-ln run reports 9 SKIPPED; those are not counted PASS. Previously vacuous purge-link fixture repaired. |
| [Unguarded quarantine](https://github.com/Zfkirke0109/MT-Safety-Clean/pull/10#discussion_r4237527560) | HIGH, accidental unverified move | FIXED_VERIFIED | Both public signatures reject null guard for all layouts; actual pre-fix synthetic move reproduced. Trusted callers still supply user authorization. |
| [Copy target verification](https://github.com/Zfkirke0109/MT-Safety-Clean/pull/10#discussion_r4237527580) | HIGH, loss of approved source bytes | FIXED_VERIFIED | Pre-fix default guard corruption/source-deletion reproduced. Copy/delete fallback removed; failed-rename/source-survival and restore-retry tests pass. Cross-volume operations now refuse. |
| [MFT012 documentation](https://github.com/Zfkirke0109/MT-Safety-Clean/pull/10#discussion_r4237527591) | LOW, misleading rule documentation | FIXED_VERIFIED | Runtime, generator and generated reference describe unknown presence; docs generation produces no diff. |
| Resolved coverage-only signal / unreadable wording / unsupported-output tests | MEDIUM/LOW, false report statements | FIXED_VERIFIED | Re-read underlying three resolved threads. SCN001/MFT012 excluded from threat predicate; unsupported has no inspected-content claim; JSON/text/overview tests pass. |
| Historical partial LOW/INFO, directory truncation and permission-dependent fixtures | MEDIUM, false-clean/vacuous tests | FIXED_VERIFIED | Real finding preserved at CLEAN score; incomplete directory hash withheld; deterministic unreadable fixtures retained. |
| Rejected entries evade directory caps; unchecked iteration/close failures | HIGH/MEDIUM, excess work/lost findings | FIXED_VERIFIED | Before: 9000 and 1000 rejected entries processed. After: exact 8000/400 validation caps, bounded emission, close-once, PARTIAL and retained EXE001 tests. |
| Discovery result cap and overlapping-root regression | MEDIUM, excess work/missed packages | FIXED_VERIFIED | Before 250 loose results exceeded 200. Independent review caught newly introduced root dedup issue; baseline 1 -> bad patch 0 -> corrected 1 reproduced and gated. |
| Quarantine metadata collision and unbounded retained listing | HIGH, evidence loss / availability | FIXED_VERIFIED | Reserved filename refuses before move; listing over 8000 refuses whole list; purge over-limit preflight leaves all source entries intact. |
| Unlimited action rehash | MEDIUM, host UI availability | FIXED_VERIFIED | Finite deadline/hash charge; large input refuses. Remaining bounded 512 KiB manifest read uses unlimited logical budget, not unlimited returned bytes. |
| Archive central-directory/index and entry-list allocation | HIGH, hostile archive memory exhaustion | CONFIRMED_OPEN | `PluginPackage.ArchivePackage.zip()` creates ZipFile before budgets; `entries()` materializes every entry without cap. A controlled 1,137,918-byte ZIP materialized 10,001 entries. This demonstrates missing admission cap, not a reproduced device OOM. A list cap alone would not bound ZipFile's internal index. |
| Aggregate signature definitions / same-size-mtime freshness | MEDIUM, memory pressure/stale definitions | DOCUMENTED_RESIDUAL_RISK | Directory enumeration is bounded; aggregate parser storage, ignored/clean definitions and external timestamp-preserving replacement are not fully addressed by this correction. No full ClamAV parity claim. |
| Filesystem substitution between checks and rename/delete | HIGH potential impact, same-UID concurrent mutation | DOCUMENTED_RESIDUAL_RISK | Static link checks and identity checks are separate from filesystem operations. Rename-only removes copy/delete races, not every source/ancestor/store/destination race. Purge may partially succeed on later failure. No atomic-safety or lossless-restoration guarantee. |
| API24–25 directory capability | Compatibility limitation | DOCUMENTED_RESIDUAL_RISK | No reflective NIO streaming; directory/discovery/file/signature-folder/quarantine paths refuse with diagnostics. Loose archive inspection does not require NIO listing. Actual ART behavior NOT_VERIFIED. |
| CMB101 co-occurrence wording/calibration | MEDIUM, false-positive risk | DOCUMENTED_RESIDUAL_RISK | Separate issue #9 remains open. No calibration changes; capability co-occurrence is not observed exfiltration. |
| Toolchain pinning / compiled-artifact provenance | MEDIUM, build supply chain | DOCUMENTED_RESIDUAL_RISK | Exact versions and observed hashes recorded below. Existing build script lacks expected-hash enforcement; CONTENTS excludes DEX hash. Local actual DEX/source-build equality was checked; no general reproducibility claim. |

## C. Independent reviews

Three actual read-only reviewer sessions used the same configured model; no distinct provider/model
or higher reasoning setting is asserted. Security, Android and test reviewers did not modify source or
GitHub. Three separate implementer sessions made disjoint corrections; they are not counted as reviews.

| Reviewer session | Actual access/evidence | Conclusion |
| --- | --- | --- |
| `security_adversary` | GitHub exact-HEAD sources, local full diff, synthetic scratch source/copy guard demonstrations; final source review | Scoped bypasses corrected; archive metadata allocation remains HIGH/open; NOT_READY overall. Initial interrupted review turn was resumed, not counted as a separate review. |
| `android_compatibility` | Instructions, source/reflection, dependency POMs/licenses/OSV evidence, actual build logs, class/DEX/package inspection | 99 plugin classes major 52; 99 scanner-only DEX classes; no direct NIO/OkHttp type links or bundled host/test classes. No correction-specific build blocker; Android runtime NOT_RUN. |
| `regression_review` | Full harness/diff, baseline/focused/full logs and independent overlap-root probes | No weakened assertions; found/corrected overlap regression and vacuous symlink fixture. Final local run 390/0/0. Exact-commit CI/formal review remain distinct. |

## D. Validation matrix

Environment: isolated Linux workspace, non-root uid 1000; verified Temurin JDK 17.0.21+9. Original
runtime lacked javac; downloaded JDK archive SHA-256 matched official Adoptium metadata
`8b9b611d917e3dfd8419d3566b5949226f69b052fed7e109c1368add1dfe8711`.

| Check | Status | Actual evidence |
| --- | --- | --- |
| Starting exact commit `bash tools/build.sh test` | PASS | Isolated git archive of 5d3711d: 358 passed, 0 failed, exit 0. |
| Final source `bash tools/build.sh test` | PASS | 390 passed, 0 failed, 0 skipped, exit 0; `javac --release 8 -Xlint:all,-options -Werror`. |
| Missing `ln` portability run | PASS / SKIPPED | Same compiled suite, PATH restricted to JDK: 379 passed, 0 failed, 9 explicitly skipped, exit 0. Conditional assertions differ by capability. |
| Focused red/green evidence | PASS | Directory, stream-failure, quarantine, traversal baseline failures captured; focused corrections pass. Supplemental quarantine cap fixtures were added after implementation and separately checked against immutable baseline; no false red-first claim. |
| `git diff --check` | PASS | Exit 0. |
| `bash tools/build.sh docs` and generated-doc diff | PASS | Exit 0; no DETECTION-RULES diff. |
| `bash tools/build.sh package` | PASS | Exit 0; core + SDK3 UI Java8 compile, Android30 bootclasspath, compile-only MT API3, D8 8.9.35 `--min-api 24`. |
| Local package/source consistency | PASS | Manifest/assets equal sources; packaged DEX equals fresh D8 output; CONTENTS unchanged. CI CONTENTS alone does not prove DEX consistency. |
| Artifact static inspection | PASS | `.mtp` contains manifest, DEX, assets, icon only; 99 scanner DEX classes, no foreign/host/test/OkHttp definitions. |
| Dependency review | PASS with limits | No new runtime libraries. Existing input receipts reviewed; OSV result below; bundled R8 dependency versions not exhaustively inventoried. |
| Changed-file secret-pattern heuristic | PASS with limits | No token/private-key patterns in changed files; limited heuristic, not a complete secret audit. |
| CodeQL / Semgrep / dedicated secret scanner | NOT_RUN | Engines unavailable; repository code-scanning API returns HTTP403. Prior agent's zero-alert claim not reused as new-head evidence. |
| New exact-HEAD push/PR Actions and pre-commit.ci | NOT_RUN at commit preparation | Must be independently checked after push; live links/outcomes go in PR conversation. |
| Fresh formal Copilot review | NOT_RUN at commit preparation | Request after push; a request event is not a completed review. |
| Android ART API24/25/26+, MT host lifecycle/performance | NOT_RUN | No device interaction or installation authorized/performed. |
| ZIP95 decoding / taint proof / exhaustive fuzzing | NOT_RUN | Outside this phase; unsupported marker tests prove refusal only. |

Local `.mtp`: **116,757 bytes**, SHA-256
`5281d2d07e47bb6c2d775fc2a62dfa25885370921f98a92d6bfda67f8406e0e7`.
DEX: **243,880 bytes**, SHA-256
`4ebabeb7ba7571ae1a25a31ff2daf781cd6a5cb6b03e6e351494bf2cba77dffb`.

### Existing dependency receipts

| Input | SHA-256 / review |
| --- | --- |
| R8 8.9.35, 18,012,736 bytes | `204b2fc2b0f4e888dc0ef748b58090def1bf4185068d36abbb94841dbc7107a8`; official Google Maven POM lists bundled licenses, no resolved Maven dependencies. Jar bundles third-party components; full transitive/advisory inventory NOT_VERIFIED. |
| Android platform30 r03 ZIP, 52,328,361 bytes | `f3f5b75744dbf6ee6ed3e8174a71e513bfee502d0bc3463ea97e517bff68d84e`; official SDK metadata SHA1 `e7c6280901dcfa511af098d67dd88c4dfcbc6ea2` and size match; Android SDK license. |
| Extracted android.jar | `96ccfdc84d15fad4e22d76cbb8ef38b150a4b56327957067875ca7e18113a424`; compile-only. |
| MT API3.0.0 AAR, 120,363 bytes | `a51c800eb904e41834ded615376e8c60a33788b073bbb967777ac61d6c88f82d`; POM Apache2; declared okhttp3.12.13 and annotation1.3.0 dependencies are neither resolved nor shipped by existing pipeline. |
| Extracted MT API jar | `6e90db4fd75342d717c22469a3a2407bbcce0b43f7790f99088983c42115b84a`; 150 Java8 classes, compile-only. |

OSV query for exact Maven coordinates returned no indexed advisories for R8/API/annotation and a
positive [GHSA-3cqm-mf7h-prrj](https://osv.dev/vulnerability/GHSA-3cqm-mf7h-prrj) for declared OkHttp
3.12.13. It is not silently treated as safe: scanner sources/artifact contain no OkHttp code or network
calls and that dependency is not shipped. This says nothing about MT Manager's own implementation.
No indexed advisory result proves absence of vulnerabilities or publisher authenticity.

## E–G. GitHub evidence, blockers and merge decision

The final PR description and handoff comment must identify the exact recovery commit, new push and
synthetic-merge PR runs separately, test counts, packaged `.mtp`/DEX/artifact-ZIP hashes, individual
review replies, formal Copilot submission (or actual failure/pending state), and unresolved threads.
Do not resolve existing threads solely from implementer replies or these local results.

**NOT_READY** until the confirmed archive metadata allocation defect is addressed under an appropriate
reviewed design, final-head push/PR CI is green, and the formal independent review has completed and
its findings are assessed. API24–25 refusal, filesystem races, unmeasured Android runtime and existing
signature/provenance limitations require explicit reviewer assessment; none is described as accepted
by the owner. No merge/release/device approval has been granted by this work.

## H. Rollback

Before merge, revert only the recovery commit on this PR branch with `git revert <recovery-SHA>` and
normal push. This restores the preceding 5d3711d sources and tracked package without rewriting history;
that earlier commit contains the reproduced defects, so rollback does not establish safety. If PR #10
is later merged after separate approval, revert its merge (`git revert -m 1 <merge-SHA>`) or squash commit
as appropriate. Preserve merged PR0 (#5/#6), PR #13 and all unrelated work. Do not reset main or alter
PR #11. No device rollback is needed because no device changes were performed.
