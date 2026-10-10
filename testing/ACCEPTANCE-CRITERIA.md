# Release blocker and per-PR acceptance criteria

**Baseline:** Git HEAD, actual `plugin/manifest.json`, JDK, `tools/build.sh` commands, CI and current suite all recorded. `NOT_RUN` must not be labeled `PASS`.

**Required across every PR:** CI core tests PASS, no new known false-clean, manifest identity preserved, budget caps preserved, no new automatic destructive actions, no untrusted payload execution/network submission, no plaintext secrets in exported reports; each new dependency has version/licensing/transitive+advisory report and Android classpath test; feature flag/default off until runtime proof; hand-tested host UX before release.

**PR0 gate:** 100% audit assertions mapped to source/evidence/unknown, baseline command outputs captured, six categories of fixture identified, one focused failing behavior demonstrated/test or explicitly impossible, no production edits. Reviewer approves PR1 scope.

**PR1 gate:** every error and supported/unsupported member path has ledger record; coverage independent of verdict; zero unqualified clean for truncation, encrypted member, missing sidecar or unsupported method; old JSON keys remain; UI text snapshot check; no resource cap regression.

**PR2 gate:** authentic ZIP95 fixture origin, local+central method 95 verified, independent expected SHA256+CRC, decoder bound KiB memory, D8 built and host ran; if absent, status remains UNSUPPORTED and PR2 documents blocker rather than shipping implementation.

**PR3 gate:** malformed/archive corpus deterministic and runnable within existing budgets; no path extraction; duplicate and nested identities stable; no uncaught errors; no incorrect clean result; compatibility file scan intact.

**PR4–9 gate:** each added analyzer emits precise source + confidence and passes benign controls; no blanket 'exfiltration' from co-occurrence; ClamAV subset formal documented with skip counters; no silent client/server traffic; no unsupported parser loaded by default.

**PR10/release gate:** run actual MT Manager supported v3 install in test after explicit user permission; no crashes; measured UI p95 and memory relative baseline; user-approved revert path and prior plugin backup; signed or verified release artifacts; humans sign off critical FP/FN regressions. No unverified green claims.
