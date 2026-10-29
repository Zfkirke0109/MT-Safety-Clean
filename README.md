# MT Manager Plugin Safety Scanner

An MT Manager plugin that statically inspects other plugins and reports capabilities, known-signature
matches and inspection limits. Use MT Manager's own controls to disable, uninstall, move, restore or
delete other plugins. This scanner does not perform those file actions.

The command line scanner also checks an `.mtp` before installation. Scanned Java, DEX, scripts and
native files remain data: the scanner never executes code from packages under inspection.

## Scan in MT Manager

The `.mtp` uses plugin SDK v3, `dexMode: true`, `pluginID=mt.safety.scanner`, and Android API24 as its
minimum. Install through an MT Manager version supporting SDK v3, such as 2.26.3 or newer, then open
**Plugin Safety Scanner** in plugin management. Installation may require MT Manager VIP under the
host's plugin rules.

Opening the settings screen starts a background operation. It shows progress and **Cancel operation**;
completed findings appear when available. **Scan again / run command** starts another operation. The
deep-scan switch permits more work within bounded budgets. **Scan files for known malware** confirms
the requested file scan before starting it.

Scanning, definition loading and report exports run outside UI callbacks in a bounded worker process
containing only scanner-owned code. A fixed trusted ART runtime is launched with a **96 MiB** heap
limit, and the worker refuses if that limit is not enforced. One operation runs at a time; repeated requests are rejected while
busy rather than queued. The supervisor uses monotonic timeouts, bounded messages and a process
termination check. Cancellation requests termination without waiting on the UI thread. Worker launch,
execution, communication or termination failures produce an unavailable/incomplete result. There is no
fallback to scanning on the UI thread; unconfirmed worker termination blocks new worker starts.

This worker does not provide a sandbox for running unknown plugins: unknown code is never loaded.
The S26 Ultra app-UID harness verifies worker launch, heap, IPC, timeout and cancellation.
Actual MT Manager preference-screen integration and lifecycle/performance remain untested.

### Read findings together with coverage

Reports include verdict, numeric score, findings and independent coverage. Local evidence may include
file/line locations or compiled-code observations. A capability describes what the scanner observed;
it does not establish intent or prove that information was sent.

| Marker | Meaning |
| --- | --- |
| `[ ok]` | Complete inspection with no findings, or explicitly trusted identity. Read coverage too. |
| `[.  ]` | Low-severity evidence or findings below the verdict threshold. |
| `[!  ]` | Review capabilities and whether the plugin needs them. |
| `[!! ]` | Suspicious findings requiring review. |
| `[!!!]` | Strong findings, a known-malware signature or explicit denylist match. |
| `[ ? ]` | Unreadable, unsupported or incomplete inspection; no all-clear. |

Partial results can retain strong findings. A legacy `CLEAN` verdict with partial coverage is an
incomplete inspection; a trusted hash does not make unread content inspected. A package found during
an incomplete search does not establish that the rest of the search was checked.

### Other-plugin management and historical quarantine

All other-plugin file management belongs in MT Manager. This scanner has no selection, quarantine or
delete controls. Old `quarantine`, `remove`, `restore`, `purge`, bulk-action and `confirm` commands return
management guidance without changing other plugins or historical quarantine files.

The **Historical quarantine** notice and `quarantined` command provide read-only information about
entries left by earlier versions. Review and recover those files manually in MT Manager; this version
does not restore or purge them. Keep a copy when manual recovery is needed.

### Commands

Enter a command in **Command**, then use **Scan again / run command**. Commands may change this scanner's
preferences, local definitions and reports; they do not manage other plugins' files.

| Command | Result |
| --- | --- |
| `deep` / `fast` | Select a thorough or quick bounded scan. |
| `export` | Save useful local text/JSON reports, which may contain arbitrary private data. |
| `export-shareable` | Save explicitly marked content-free text/JSON reports. |
| `definitions` / `defs` | Show catalogue and loaded-definition information. |
| `import PATH` | Import supported local indicators or signature definitions. |
| `trust HASH` / `untrust HASH` | Add or undo trust for an exact package hash. |
| `deny HASH_OR_ID` | Add a local denylist indicator. |
| `root PATH` | Add a permitted search folder; `root` clears it. This grants no privilege. |
| `files [PATH]` | Check permitted files against loaded signatures. |
| `quarantined` | Describe historical quarantine entries without changing them. |
| `cancel` | Clear an old pending action plan. Use **Cancel operation** for active work. |
| `help` | Show command guidance. |

## Local reports and content-free sharing

`export` saves `scan-report.txt` and `scan-report.json` in this scanner's own folder. Local reports
retain useful evidence, names, paths and diagnostics. Recognizable credential formats are redacted,
but arbitrary secrets cannot be recognized reliably. Treat local reports, file scan reports and UI
evidence as private; inspect them before sharing.

Use **Export share-safe report** or `export-shareable` for explicit sharing mode. It saves
`scan-report-share-safe.txt` and `scan-report-share-safe.json`, marked `SHARE-SAFE` / `SHARE_SAFE`.
The export permits scanner-authored constants, enumerated verdict/coverage/severity/category and
allowlisted rule IDs, numeric counts/scores and opaque SHA-256 IDs. Names, plugin IDs, paths, excerpts,
signature names, arbitrary descriptions and error text are omitted. Unknown rule IDs become a fixed
fallback. Public hash fields are hashed as inputs, never copied as trusted export strings.

IDs use a fresh unexported salt per formatter invocation and the report ordinal. They correlate
locations within a report; separate exports and text/JSON calls get different IDs. They are unsuitable
for package actions. Counts and capability combinations still disclose scan results; content-free
does not promise anonymity. Discovery completeness and unscanned-candidate counts remain visible
without free-form discovery errors. File scan evidence is excluded. See the
[sharing contract](docs/SHARE-SAFE-REPORTS.md).

## Detection and coverage

The [rule catalogue](docs/DETECTION-RULES.md) covers shell/root execution, external code loading,
network access, sensitive data, device identity, capture APIs, cross-plugin access, destructive
operations, obfuscation, provenance and package structure. It is compiled into the scanner, with
version/date reported locally. Updating it requires a new scanner build.

Network and sensitive-data, code-loading, command-execution or capture findings may be independent,
even within one file. CMB101/102/103/105 and same-file CMB002/003 are Medium capability combinations,
not proof of exfiltration, remote control or surveillance. Strong direct findings, known-malware
signatures, explicit denylists and destructive indicators retain their severity. Purpose-aware context
can excuse an ordinary capability, such as networking in a translation plugin, unless conflicting
findings revoke that context.

Local JSON includes a bounded coverage ledger for up to **12,000 admitted members**. Each member has
separate read, built-in-rule, user-pattern, signature and nested-archive checks. Package-level checks
cover manifest, structure, content hash, indicator/signature definitions and code visibility. Checks
have `COMPLETE`, `PARTIAL`, `SKIPPED`, `FAILED` or `NOT_APPLICABLE` status and enumerated reason codes,
such as exhausted budget, unsupported content, failed reads or incomplete definitions.

Member labels are bounded to 32 characters for display; a SHA-256 of the full relative path accompanies
the label, and separate IDs preserve duplicate members. These local path hashes differ from salted
sharing IDs. Reaching the ledger limit records dropped members and makes coverage partial. Admission,
read, analyzer, nesting and definition limits remain explicit limitations; omitted work is not fully
clean. The ledger covers admitted/visible work, not undiscovered inaccessible or encrypted content.

### ZIP and nested archives

ZIP methods **0 (stored), 8 (deflate) and 95 (XZ)** use a bounded decoder after metadata admission.
Index and local headers must agree on identity, flags, method, sizes and CRC; descriptor checks,
exact decoded length, ZIP CRC32 and codec completion distinguish complete reads from prefixes.
Compressed input is capped at 8 MiB, output at the caller's limit and the 4 MiB member cap, and XZ
memory at **8192 KiB (8 MiB)**. Prefix reads, unsupported methods and encrypted members leave coverage
incomplete. No password recovery or decryption is attempted.

Archive admission caps the central directory at 8,000 entries and 2 MiB metadata. Split archives,
encrypted indexes, ambiguous/unsupported record layouts and invalid offsets refuse as unreadable.
Supported single-disk ZIP/ZIP64 layouts and nested archives retain time, byte and count limits; nested
inspection stops at depth 2 and 400 entries. Failures preserve findings already obtained and prevent
an all-clear. See the [XZ dependency/decoder review](docs/archive-support/XZ-DEPENDENCY-REVIEW.md).

## Local indicators and ClamAV-format signatures

`assets/indicators.json` seeds an empty local indicator file on first run. It holds trusted hashes,
denied hashes/plugin IDs, optional custom patterns and provenance fields. Importing indicators merges
them while preserving existing trust decisions. There is no automatic definition feed, private upload
or telemetry feature.

Supported signature files implement subsets of ClamAV's text formats:

| Files | Supported purpose |
| --- | --- |
| `.hdb`, `.hdu` | Whole-file MD5 hashes with size constraints. |
| `.hsb`, `.hsu` | Whole-file SHA-1/SHA-256 hashes with size constraints. |
| `.ndb`, `.ndu` | Supported byte-pattern, target and offset syntax. |
| `.fp`, `.sfp` | Known-clean hashes. |
| `.ign2` | Signature names to ignore. |

Use `import PATH` or the signature folder shown under About. Unsupported, malformed, capped or
unreadable definitions are counted/reported; this is not ClamAV engine parity. Explicit gaps and
offset shifts greater than 4096, leading/trailing/adjacent gaps and patterns over 64 blocks are
refused rather than silently changed. Open gaps search admitted bytes within a shared 8,388,608-step
matching allowance. Work/hit cutoffs preserve matches and mark package ledgers, file reports and the
immediate file-scan summary incomplete. Multi-byte alternatives preserve complete branches. Review definition
sources deliberately. A hash/pattern match may make a plugin `KNOWN_BAD`; `PUA.*` matches are High
unwanted-software findings. Signature names and matching locations remain in local evidence only.

Loading has aggregate limits across selected inputs: **16 MiB input**, **32 MiB retained-data
accounting**, **100,000 retained entries** including clean hashes and ignore names, **16,000 patterns**,
and **256 definition files**. Patterns and other retained data share the entry/memory limits; these
allowances cannot be added together. Content-based freshness fingerprints include complete bounded
definition contents and source metadata: same-size rewrites with preserved timestamps invalidate the
cache. Changes during loading fail closed with incomplete definition coverage. Retained accounting
is a budget, not a measured total JVM heap guarantee.

The file scan checks permitted files and archive members against loaded signatures. It reports
bounded progress, hits and problems and saves a useful private `files-report.txt`. It never deletes or
moves files. An absence of signature hits does not establish safety, especially with limited or
incomplete definitions.

## Command line

```sh
tools/mtsafety suspicious.mtp
tools/mtsafety --scan-dir /sdcard/Download
tools/mtsafety --json plugin-dir/
tools/mtsafety --signatures android.ndb x.mtp
tools/mtsafety --signatures sigs/ --files ~/Downloads
```

The CLI needs a JDK supporting `javac --release 8` (9 or newer) and the same pinned XZ runtime, without
an Android SDK or MT host for core scans. Its first build may fetch the locked runtime. CLI text/JSON
are useful local reports, subject to the same arbitrary-secret sharing limitation.

Exit status is `0` for a complete result needing no action, `2` for an actionable package/signature
hit, and `1` for usage/read errors or incomplete package, file, definition or requested discovery
coverage. Actionable results retain exit `2` when file/package scans are combined. JSON includes
discovery completeness/problems separately from each package's verdict, coverage and disposition.

## Build and test

```sh
bash tools/build.sh test       # compile and test the Java core
bash tools/build.sh docs       # regenerate the rule reference
bash tools/build.sh package    # build the SDK3 .mtp
```

The build preserves Java 8 source/bytecode, SDK v3 packaging and D8 `--min-api 24`; this is not a
Gradle/APK project. Core tests run on a desktop JDK. Python 3 and standard build utilities are needed
for toolchain verification and package checks. Test output supplies actual counts; desktop success
implies no device-validation or performance result.

The pure Java core bundles one runtime dependency: reviewed **XZ for Java 1.12**, licensed **0BSD**,
with license text at `plugin/assets/licenses/xz-1.12.txt`. Build/test/CLI paths use verified Java 8 base
classes rather than multi-release Java 9 variants. Runtime/build inputs are versioned and SHA-256
pinned in `tools/toolchain-lock.json`; caches are checked before use. Initial fetches need access to
pinned artifact sources. See [build integrity](docs/BUILD-INTEGRITY.md).

Packaging also uses the pinned Android platform, R8/D8 and MT API 3.0.0. Android/MT APIs are
compile-only, never bundled. The `.mtp` contains the manifest, scanner code DEX, scanner-owned worker
DEX asset and plugin assets. Integrity checks compare every actual archive member including DEX.
Checksums verify consistency, not publisher authentication.

```text
plugin/src/mt/safety/scanner/core/       static inspection, budgets, ledger and formatters
plugin/src/mt/safety/scanner/execution/  bounded worker protocol and supervision
plugin/ui-v3/                          SDK3 UI and Android worker adapter
plugin/assets/                         indicators and runtime license
tools/src/                             desktop CLI and catalogue tooling
tools/test/                            JVM and build-integrity regressions
```

## Remaining limits

- Inspection is static. Obfuscation, generated behavior, encryption, unsupported formats and
  inaccessible storage can hide capabilities. Coverage states limits without claiming proven safety
  or proven exfiltration.
- Directory streaming uses public NIO on API26+ and a fixed bounded system-toybox fallback on
  API24–25. The fallback was exercised on the S26; actual API24–25 hardware remains untested.
  Unavailable OS capabilities fail closed with diagnostics.
- Worker isolation grants no permissions, bypasses no storage restrictions and requires no
  root/Shizuku. Host/OS launch restrictions may make scans unavailable. The app-UID S26 harness
  validates the worker boundary; it does not establish MT host UI integration or API24 compatibility.
- Plugin locations vary by host and Android version. Discovery uses permitted roots/package contents
  and excludes this scanner. Inaccessible scope remains incomplete.
- Limits constrain admitted input and retained accounting; they do not make concurrent mutation atomic
  or prove exact total memory/CPU consumption. Bounded worker supervision remains necessary.
- Local reports may contain arbitrary private content. Only explicit content-free sharing omits
  free-form inputs, and its counts/findings still disclose scan results.
