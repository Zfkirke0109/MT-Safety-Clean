# Independent PR #10 review and corrections — 2026-10-27

Reviewed repository: `Zfkirke0109/MT-Safety-Clean`, PR #10, branch
`copilot/report-incomplete-scan-coverage`. Starting head:
`6b6ea2ff0f69300d66ae30a683409d6661208753`; fixed merge base:
`d8cceb62fb4ad143808bdc89bf8ae41814837d22`. All 30 changed files, relevant callers,
tests, build configuration, package contract and existing review threads were examined.
`origin/main` additionally contains PR #13 documentation changes, with no production-code change
since that merge base. PR #11 remains untouched.

This review fixes independently reproduced defects. It does not authorize a merge, release,
installation, destructive device action, ZIP95 decoder or risk-weight/CMB101 change.

## Findings and corrections

| Severity | Finding and trigger | Correction and verification |
| --- | --- | --- |
| HIGH | Root ZIP index allocation happens before scan limits; 8,001 entries or a small entry count with multi-megabyte comments materializes an excessive index. | New `ArchiveIndex` admits at most 8,000 actual records and 2 MiB of central metadata before `ZipFile`. Uses bounded tail/fixed-header reads, checked offsets and classic/optional-ZIP64 agreement. Entry-list caps remain defense in depth. Oversized, understated-count and ZIP64 cases are gating. |
| HIGH | A nested ZIP containing only `PK\x03\x04`, missing its index, or having fenced/contradictory local records can return CLEAN/COMPLETE. A same-name/same-offset STORED-vs-DEFLATED disagreement hides a different decoded payload. | Validate bounded nested index metadata; bind local offsets and names independent of CEN order; compare method, CRC and sizes after member EOF. Invalid encoding, encrypted index entries and local/CEN disagreement revoke completeness. Continue bounded prefix inspection and preserve existing findings. |
| MEDIUM | Definition loading/parsing/unsupported/cap failures do not qualify a clean package. | Retain IOC/signature diagnostics, mark aggregate coverage partial, preserve legacy verdict/scoring, and serialize additive `errors`. SCN001 now describes incomplete content or definition checks. |
| MEDIUM | CLI drops discovery failures and partial-file/package outcomes, and forgets file signature hits when packages follow. Explicit missing roots can report success. | Keep discovery scope separate from each package; add `discoveryComplete`/`discoveryProblems`; preserve exit 2 for any actionable result, otherwise exit 1 for incomplete/error outcomes. Explicit unavailable roots are diagnostic; optional guessed Android roots retain their behavior. |
| MEDIUM | Root `/` becomes boundary `//`, excluding ordinary descendant paths. | Normalize the directory boundary in discovery/file scanning. Tests exercise that canonical-root case against an isolated fixture, without reading the machine's actual root. |
| MEDIUM | File/member prefix and archive-member count cutoffs are absent from file-scan coverage. | Record bounded incomplete-coverage diagnostics while retaining hits and continuing eligible work. Existing file-count/match assertions remain; the former false “not truncated” assertion is split into traversal counts and explicit prefix limitation checks. |
| HIGH impact, existing acceptance gap | Evidence and exported errors can contain recognized credentials. | Redact recognizable bot URLs, bearer/basic values, common assignments and selected key/token formats before display/export. Keep original detection/action data. Bound evidence locations/snippets and error text; no universal secret-recognition claim. |

Independent follow-up review caught five parser/redaction weaknesses before publication: encrypted
CEN flags, lossy UTF-8 replacement, quadratic whitespace/JWT matching, and quoted-password suffix leakage.
All received regression tests and corrections. Credential assignment detection now uses possessive,
non-overlapping whitespace and a linear quoted/unquoted value scan with escape handling. A legal
65,000-space input timed out at 5 seconds before the correction; the same standalone probe completed
in 27 ms afterward on this host. That measurement is not an Android performance result.
The child-JVM regression also timed out before the repeated-`eyJ-` JWT-boundary correction and passes
afterward; URL-safe token characters can no longer introduce internal candidate starts.

## Standards review

An independent read-only reviewer compared the pinned original diff against `AGENTS.md`, Copilot
instructions, the implementation master, ADRs and acceptance criteria. Its two actionable findings
were definition-failure completeness and the filesystem-root boundary; both are corrected. The
optional unused copy-target guard API was retained to avoid an unrelated public-API removal.

The reviewer inspected the corrective worktree and independently identified the encryption/encoding
and sanitizer defects above. No existing malicious/benign match, identity, confirmation or quarantine
assertion was removed. Java 8, SDK3, API24 packaging, compile-only host API and no new runtime libraries
remain the contract. Actual Android behavior is a separate validation gate.

## Specification review

A second independent read-only reviewer checked reporting, CLI, nested archives and tests against
the PR1 prompt and ADR-003. It reproduced the truncated nested all-clear, discarded discovery scope,
and incorrect CLI outcome aggregation. Those are corrected. It also noted that the proposed complete
member/analyzer ledger remains only partially implemented: aggregate coverage and bounded member/error
diagnostics exist, but there is no success/failure record for every member/analyzer. This remains an
explicit design limitation, not a claim of full ledger conformance.

The reviewer independently ran ten tiny probes against corrective classes, verifying partial
coverage/error exits for original nested adversaries, complete benign output, discovery diagnostics,
combined hit precedence, unavailable roots and capped file prefixes. Subsequent final sanitizer
re-review additionally passed eight final probes, including complete quoted-value redaction and a
32,000-space input in 0.145 seconds including JVM startup. The standards reviewer confirmed the
subsequent JWT-boundary correction in source and reported no remaining scoped findings.

Axis totals at the original head: Standards **2 actionable + 1 optional**, worst MEDIUM false
completeness; Spec **3 reproduced findings + 1 partial requirement**, worst HIGH nested false all-clear.
These axes remain distinct from the root-index defect already documented in the earlier recovery.

## Validation evidence

Environment: Linux container, uid 0, installed OpenJDK 17.0.20. The runtime has `jdk.compiler` and
`jdk.jartool` modules but no `javac`/`jar` launchers. Temporary PATH shims invoke
`java com.sun.tools.javac.Main` and `java sun.tools.jar.Main`; no compiler/toolchain download or
repository build-script change was needed for local tests.

| Check | Result |
| --- | --- |
| Unchanged `6b6ea2f`: `bash tools/build.sh test` | PASS: 390 passed, 0 failed, 0 skipped. |
| New tests against original implementation | 396 passed, 14 failed, 0 skipped; original failures independently reproduced. |
| Subsequent adversarial red/green rounds | Two fenced local/index failures; one method disagreement; seven encoding/encryption/file-cap/explicit-root failures; three credential leakage failures; two sanitizer edge failures. Each was observed before its correction. The old large-file assertion also exposed a prior false completeness expectation and was strengthened as described above. |
| Corrective `bash tools/build.sh test` | PASS: 428 passed, 0 failed, 0 skipped. Java8 release compilation, warnings as errors. |
| Missing-`ln` portability | PASS: 417 passed, 0 failed, 9 explicitly SKIPPED. These unavailable symlink assertions are not counted PASS. |
| `bash tools/build.sh docs`, `git diff --check` | PASS locally; rule-reference change is SCN001 definition/content coverage wording. |
| Independent review | Actual separate standards/spec reviewer sessions, same configured model; not formal GitHub Copilot approval and no distinct-provider claim. |
| SDK3/D8 package and final-head Actions | Pending at source-commit preparation; exact results/artifact hashes are appended after the existing CI workflow completes. |
| CodeQL / dedicated security or secret scanner | NOT_RUN; no claim of exhaustive static-analysis or secret coverage. |
| ART/MT Manager runtime, lifecycle, device performance | NOT_RUN. DroidBridge read-only identity/logcat/screen checks succeeded on S26 Ultra / Android17 API37; no scanner install, launch or device mutation. |

## Compatibility, remaining risks and readiness

- Root admission deliberately refuses unsupported/ambiguous metadata rather than claiming all-clear.
  It does not add a decoder. Small ordinary single-disk ZIP64 is tested; unusual digital-signature,
  encrypted-index, padding, split and nested ZIP64-offset forms can refuse or remain partial.
- Directory streaming on API24–25 remains unavailable and fails closed. No eager array fallback,
  min-API increase, Gradle conversion or APK substitution was introduced.
- File identity/link checks, preflight/open and rename/delete remain non-atomic against concurrent
  same-UID source/ancestor/store substitution. Existing rename-only action safeguards are retained.
- Inflater CPU/internal buffering, aggregate signature-parser memory and cache freshness, expected
  toolchain hash enforcement, per-member ledger completeness and host lifecycle performance remain
  documented limits. Detection co-occurrence is not proof of exfiltration; CMB101 calibration remains
  separate issue #9, with scoring unchanged here.
- Redaction recognizes listed credential forms; arbitrary secrets and all private metadata cannot
  be guaranteed absent. Report sharing still requires judgment.
- Historical formal Copilot threads are not automatically resolved. These independent reviews and
  passing tests do not impersonate a quota-blocked formal review or authorize release.

The reproduced source defects are corrected; merge/release readiness still requires assessment of
the explicit compatibility/design limits and authorized MT host validation. No automatic merge.

## Rollback

Revert the corrective source and artifact/evidence commits on this PR branch, preserving all earlier
PR commits, PR0, main/PR #13 and stacked PR #11. Use normal pushes, without rewriting history.
Reverting restores earlier defects; it is not a claim that the older scanner is safer. No device
rollback is needed because no device state was changed.
