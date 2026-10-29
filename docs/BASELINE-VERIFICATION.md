# PR0 baseline verification

## Scope and environment

PR #6 remains stacked on `audit/pr0-copilot-handoff`; this work updates that existing PR branch.
Reviewed source baseline: `90de1e15ef4ce9ad20e272a64daa52b4ed56a189`. The changes since it add onboarding,
research-handoff, test and baseline-documentation files only; no scanner, UI, manifest, build, CI, package
or dependency behavior was changed.

The supplied handoff ZIP was 721,012 bytes with SHA-256
`2cc688504e005e1145ac1ffb6e6d81eaf3684cf5eac8db1f5d9e57ccc13ba93b`. `unzip -t` passed, the extracted
files matched `SHA256SUMS.txt` using `VERIFY-SHA256.py`, and extraction audit found no path traversal
members or symlinks. Only the required research Markdown was added; `historical/`, PDFs and the ZIP were
not added.

The project is an MT Manager SDK v3 `.mtp` plugin (`pluginID=mt.safety.scanner`, min Android 24,
`dexMode=true`), not an APK/Gradle build. The core uses Java 8 compatibility (`javac --release 8`);
CI specifies Temurin 17. Local baseline environment: OpenJDK/Temurin 17.0.20.1 and `javac 17.0.20.1`.
The build/test target needs no external downloads. Neither `tools/build.sh package` nor device/MT Manager
testing was run.

## Baseline command and output

Before adding PR0 tests, the exact command was:

```text
bash tools/build.sh test
```

Output ended with `278 checks passed, 0 failed` and `All good.`; exit status **0**. The full 284-line
console output is preserved in [`BASELINE-TEST-OUTPUT.txt`](BASELINE-TEST-OUTPUT.txt). GitHub Actions
run `38031137362` on the parent branch also passed all workflow steps at `eff2c6d`; its test log reports
the same 278 checks. This is the unchanged existing suite, not PR0 test coverage.

## PR0 test results

After the test-only additions, `bash tools/build.sh test` passed **282 checks, 0 failed**, exit status
**0**. The tests include a fixed-timestamp JDK DEFLATE ZIP, a duplicate-name ZIP with conflicting benign contents,
an inert method-95 header marker, malformed/unsupported signature definition checks, and disconnected
sensitive-data/network API co-occurrence. The generated archives are small: the DEFLATE fixture was 489
bytes, the duplicate fixture 653 bytes, and the method-95 marker fixture 647 bytes.
Hashes from this local run were respectively `2f7268125798d5e1500c8bacf99711cc8357d0343a4a711205b02136321381ac`,
`bbab7e70192eea29e75d76489e56e9f40bcbbef711cb92d0d8ae1ef6457d3788`, and
`21d9b90cd67db16f178dadff2f130804d8ee8715a5bdd9d1c7bb8f60ac40e1a1`.

The method-95 fixture sets method 95 in both local and central headers but carries deliberately opaque,
non-XZ bytes. It verifies refusal, not decompression or ZIP95 compatibility; no authentic method-95/XZ
fixture was produced or tested. On this JDK the scanner returns `UNREADABLE` with an explicit method-95
message.

The benign-backup fixture lists shared Documents in one source and makes a separate status URL call in
another, with no source-to-sink connection. The current scanner reports `SEN006`, `NET001`, and `CMB101`,
and `LIKELY_MALICIOUS`. This is recorded as capability co-occurrence, not proof of exfiltration; whether
the fixture's modeled behavior is benign is a test assumption, and the false-positive risk needs human review.

### Expected-red incomplete-scan regression

Run separately from the default suite:

```text
java -cp /tmp/mt-safety-build/classes mtsafety.test.IncompleteScanCleanRegression
```

This test intentionally asserts that an incomplete package must not be labeled `CLEAN` or `TRUSTED`.
It currently fails as expected (exit status **1**):

```text
java.lang.AssertionError: incomplete package is presented as an unqualified all-clear: Clean
```

The same fixture has `truncated=true` and `SCN001=true`. `PluginScanner` attaches `SCN001` and then calls
`RiskScorer.score` (`PluginScanner.java:77-89`); `RiskScorer.decide` has no truncation/coverage guard and
can return `CLEAN` (`RiskScorer.java:186-220`). `ReportFormatter.summaryLine` renders that verdict as
`Clean` without its reason (`ReportFormatter.java:19-25`); the detailed text output does append
`(incomplete)` (`ReportFormatter.java:80-84`), and the MT settings rows separately show an incomplete
warning (`ScanRunner.java:852-853, 886-888`). Thus a misleading clean verdict is confirmed, while the
warning remains visible in those detailed views. No production behavior was changed in PR0. Approval is
needed before fixing the verdict/display in PR1.

## Other existing coverage and limits

- `ScannerTest.java:287-326` covers a complete DEFLATE ZIP, conflicting duplicate names (`ARC005`), and an unsupported
  method-95 marker; `ScannerTest.java:502-505` checks budget exhaustion and `SCN001`.
- `SignatureTest.java:150-162` checks malformed hash lines, unsupported pattern syntax and parser counts.
- The duplicate fixture uses two benign but different source bodies for the same member name. ZIP64,
  encrypted-member semantics, and authentic ZIP95 payload decoding remain unverified.
- Baseline source evidence: `PluginScanner.java:77-89`, `RiskScorer.java:186-220`,
  `ReportFormatter.java:19-25,80-84`, `ScanBudget.java:61-94`, and `ScanRunner.java:82-85,852-853,886-888`.
  Test entry point: `tools/build.sh:71-86`.

## Compatibility, artifacts and rollback

No production/plugin/API files changed, and the `plugin/manifest.json` identity and `dist/` artifacts were
not rebuilt. Static compatibility risk is limited to test/fixture changes and documentation; actual
Android/D8/API24 and MT Manager loading compatibility were **not tested**. The committed
`dist/mt-safety-scanner.mtp` SHA-256 is
`a12ef911c5e59987e2537f953c47aa8f4faf928da97437223757a89c2d01eccd`; `dist/CONTENTS.txt` SHA-256 is
`4a0f242b231fe6bd8c9b03584b8cc835f5c1ea7b77e0fd41b2bfbdc84bf52324`.

To roll back this PR0 work, revert its commits in reverse chronological order. Do not revert the
pre-existing onboarding commits unless that is separately intended.

**Reviewer decisions requested:** approve the authoritative handoff staging and PR0 evidence; decide
whether to prioritize the incomplete-scan verdict fix and benign co-occurrence calibration in PR1. No
PR1+ work should begin before explicit approval.


## Current capability calibration (2026-10-28)

The preceding PR0 observations remain historical baseline evidence. Current behavior changes
CMB101/102/103/105 and same-file CMB002/003 to Medium capability findings and explicitly states that
API co-occurrence does not establish a source-to-sink connection. The unchanged disconnected-backup
fixture retains SEN006, NET001 and CMB101, and now returns REVIEW (score 16). Separate private-data,
loader and shell controls return SUSPICIOUS (38); a location/status control returns REVIEW (23).
Strong signature, denylist and direct destructive controls retain their high-risk verdicts.
CMB104/106/107 retain High severity with wording that asks for review rather than claiming deliberate
concealment, observed transfer or malicious intent. These are static heuristic findings, not runtime
observations or a general source-to-sink analysis.
