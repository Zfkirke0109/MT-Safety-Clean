# Copilot scoped task PR 01 — Coverage ledger and false-clean regression

**Authorization:** NOT GRANTED by this document. Start only after human reviewer explicitly approves PR 01 following PR0. One independently reviewable PR; no automatic merge, release, phone install or destructive changes. If source HEAD moved, re-audit before editing.

## Goal
Coverage ledger and false-clean regression. Read `AGENTS.md`, `.github/copilot-instructions.md`, master and ADRs first.

## Existing files to inspect (validate they still exist)
`plugin/src/mt/safety/scanner/core/` as applicable: PluginScanner.java, RiskScorer.java, ScanBudget.java, ScanReport.java, ReportFormatter.java, Verdict.java, Signal.java. For UI files inspect `plugin/ui-v3/mt/safety/scanner/ui/ScannerPreference.java`, `plugin/src/mt/safety/scanner/ScanRunner.java` where relevant. Actual paths are ground truth; no invented classes.

## New files / functions (PROPOSALS, not existing APIs)
CoverageState.java, CoverageLedger.java where justified; targeted tests under tools/test/mtsafety/test/. Define interfaces and Java8-compatible signatures only after reading surrounding types; keep classes minimal, no alternate scanner pipeline. Exposed analyzer methods should accept bounded `InputStream` and explicit shared context; precise signatures chosen by Copilot only after current code mapping.

## Work plan
1. Verify `git status --short`, commit SHA, actual file names and baseline tests. Locate exact call chain and document source lines.
2. Write **failing deterministic tests** for current defect or an externally derived testable contract. Document pre-change failure rather than delete/relax a test.
3. Implementation instructions: Instrument each member and error/timeout/budget exit; keep legacy fields; user-visible incomplete status must dominate unqualified clean; preserve current SCN001 severity as INFO.
4. Use smallest change behind a feature flag if ABI/schema/host behavior uncertain. Preserve Java8 `javac`, D8 `--min-api 24`, pluginSdkVersion3, dexMode=true, pluginID `mt.safety.scanner` and compile-only MT API. Keep existing scanner/quarantine confirmation.
5. Add negative and benign false-positive tests, check unsupported/partial coverage and secrets redaction, run full test suite, review diff and write PR evidence.

## Dependencies and compatibility
Do not add any dependency until pinned version, license, transitive jars, security advisories, Java8 target class version, Android API24/D8 compatibility, output dex size and MT host runtime have been individually validated. If only stock Java is required, state `no new dependencies`. Do not add Gradle or create an APK; use existing `tools/build.sh`. Any network fetch requires separate authorization and pinned expected hash.

## Exact commands to verify (not pre-executed by this package)
```bash
git status --short
git rev-parse HEAD
bash tools/build.sh test
# only with approved upstream/toolchain downloads; review generated diff first:
bash tools/build.sh package
unzip -l dist/mt-safety-scanner.mtp
unzip -p dist/mt-safety-scanner.mtp manifest.json
sha256sum dist/mt-safety-scanner.mtp
```
For rules reference changes only: `bash tools/build.sh docs; git diff -- docs/DETECTION-RULES.md`. Capture exit codes and artifact hashes; never invent results.

## Tests / acceptance
Target identifiers: **COV001,COV002,COV003,JSON001,ARC011; no trusted or clean display if incomplete; deterministic snapshots**. No unbounded malware/zip bomb payload; no untrusted code execution; retain prior fixtures and behavior. Record exact actual PASS/FAIL/NOT_RUN, runtime, memory, artifact SHA256, reported coverage, false positive controls. Reject any unqualified CLEAN on unsupported or truncated bytes.

## Expected PR artifacts
Scoped code+tests (if approved), source-line evidence, `docs/PR-01-EVIDENCE.md` with command outputs and dependency receipts, regenerated documented rule references if needed, `.mtp` built in approved dev host (not committed or deployed unless approved), a rollback/revert plan and a **human reviewer approval request** before proceeding.

## Stop conditions
Production changes limited to coverage/reporting; no new ZIP library or risk weight change. Any failing baseline, data loss, unsafe input execution, default automatic quarantine, privacy breach, root/Knox modification, dependency verification failure, or source contract mismatch requires **stop and human escalation**.

## Rollback
Revert the PR as a unit (`git revert <approved-commit-SHA>`), leave prior `.mtp` and definitions unchanged, disable any feature flag, compare pre/post JSON and baseline tests; device rollback follows `INSTALL-AND-ROLLBACK.md` **only when authorized**. Do not modify user's phone as part of this phase unless separately approved.
