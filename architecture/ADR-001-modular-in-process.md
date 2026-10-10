# ADR-001: Bounded modular MT Manager Plugin SDK v3 analyzer

**Status:** proposed, decision requires PR0 human approval. **Date:** 2026-10-09. **Constraints:** no root; preserve `mt.safety.scanner`, SDK3, `dexMode`, `mainPreference`, Java8/D8, host compile-only API, existing UI/interaction and safety confirmations.

**Options:** A. Monolithic Java patch: lowest initial risk but poor typed coverage and parser isolation. B. Modular in-process `MemberAnalyzer` behind existing PluginScanner and ScanBudget: bounded costs, testable adapters and evidence. C. Thin UI with Termux/optional service backend: strongest heavyweight analysis but optional integration, IPC/permissions/privacy costs and nonuniversal deployment.

**Decision:** B, staged from A without architecture rewrite. PR1 adds coverage tracking and targeted tests; ZIP95 is a separate isolated feasibility spike; remaining analyzers add functionality incrementally only after D8/APK-free `.mtp` smoke tests. Optional C deferred, offline-first.

**Core seams:** `PluginPackage` discovery/member reader; `ScanBudget` shared deadline/byte/expand limits; `MemberAnalyzer` typed results; `CoverageLedger` entry status; `Signal`/`ScanReport` legacy-compatible evidence/disposition; `RiskScorer` does not promote unsupported content to CLEAN; `ReportFormatter` JSON v2 additive. New interfaces are proposals, not current names. MT host classloader and lifecycle behavior must be observed, not inferred.

**Consequences:** no full taint analysis in host; some encrypted/private plugin files remain uninspectable; coverage ledger makes uncertainty visible. Future rollback retains older scanner data through additive JSON and versioned feature flags. Every feature phase includes a human review gate and isolated PR; do not commit an unproven decoder or unverified dependency.
