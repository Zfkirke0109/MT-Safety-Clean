# ADR-003: Scan result is a matrix, not a single severity label

**Status:** proposed PR1. Existing `Verdict` values remain for backwards compatibility. New `coverage` is an independent enum (`COMPLETE|PARTIAL|UNSUPPORTED|INACCESSIBLE|ERROR`), with reason codes per member and analyzer. `disposition` states evidence-based threat assessment separately (`KNOWN_MALWARE_MATCH`, `SUSPICIOUS_CAPABILITY`, `NO_THREAT_DETECTED_IN_INSPECTED_CONTENT`, `UNDETERMINED`). `confidence` speaks to a specific finding, never silently overrides coverage. `severity` expresses potential impact, not certainty.

**Invariant:** COVERAGE!=COMPLETE => user interface and JSON must never claim an unqualified `CLEAN`/`TRUSTED` result even if legacy `Verdict` remains `CLEAN` for compatibility; prefer a distinct display status `INCOMPLETE`. Every error path (opened-but-unreadable member, nested decoder, scanner budget, invalid signature, archive corruption, missing sidecar, JSON exception) must update ledger. Snapshot tests keep old JSON fields. Missing denominator must display `unknown` (not 100%).

**Security:** Sanitization before serialization; token-like strings redacted. Stable finding ID includes rule version, member index/path and offset. No dangerous code execution. Quarantine/delete flows retain user confirmation.

## PR1 implementation note: JSON and API consumers

`ScanReport.coverage()` (`COMPLETE`, `PARTIAL`, `UNSUPPORTED_OR_UNREADABLE`) is reported separately from the
legacy verdict. JSON keeps `verdict` and `truncated` unchanged for compatibility and adds `coverage` and
`disposition`. **Consumers must read `coverage` together with `verdict`: `"verdict":"CLEAN"` with
`"coverage":"PARTIAL"` is not an all-clear; `disposition` is the unambiguous effective result.** Any read
failure of a package member, nested archive member or the manifest marks coverage `PARTIAL` (with the error
recorded); an entirely inaccessible package stays `UNREADABLE`.
