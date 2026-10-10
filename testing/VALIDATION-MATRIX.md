# Deterministic validation matrix — no malicious payload execution

Status for this handoff: **SPECIFIED, NOT EXECUTED**. Test commands are repository-documented; future test IDs are proposals. Every test must record original fixture hash, fixture generator, scanner stdout/stderr and `PASS/FAIL/NOT_RUN`, Java/D8/API24 build variant, peak memory and the invariant it demonstrates.

| Test ID | Input / fixture | Expected safe behavior | Gate |
|---|---|---|---|
| ARC001 | Valid .mtp DEFLATE entry, SDK v3 manifest | complete read, report old fields unchanged | PR0 |
| ARC002 | Valid .mtp STORED entry, nested 1 level | nested contents accounted once | PR0/3 |
| ARC003 | Authentic ZIP95/XZ independently generated | method 95 local+central, hash+CRC+length agree; decoded or explicit UNSUPPORTED | PR2/3 |
| ARC004 | Header says 95 but body invalid XZ | error/partial, no phantom clean | PR2 |
| ARC005 | Damaged central directory, truncated data | explicit ERROR, no process crash | PR0/3 |
| ARC006 | Duplicate path incl slash/Unicode normalization collisions | track archive index; flag ambiguity, no silent override | PR3 |
| ARC007 | ZIP64 offsets/sizes and oversized declarations | overflow safe, consistent statuses | PR3 |
| ARC008 | Symlink ZIP Unix metadata, absolute path, `../`, NUL | no extraction/path traversal, finding + coverage | PR0/3 |
| ARC009 | Extreme compression ratio via 1–4MiB compressed-safe mock or synthetic stream | capped expansion, no huge fixture allocation | PR3 |
| ARC010 | Deep nested ZIP/JAR/APK >2 levels, >400 members | bounded skip + per-member reason, no hang | PR3 |
| ARC011 | encrypted/unsupported member | `UNSUPPORTED`/`ENCRYPTED`, no clean promotion | PR1/3 |
| ARC012 | corrupt CRC / data descriptor conflict | invalid member, coverage partial, independent CRC | PR3 |
| COV001 | clean but budget-truncated fake plugin | SCN001; UI explicitly incomplete, NEVER unqualified clean | PR1 |
| COV002 | partial failed member with serious finding in other member | preserve genuine finding and partial coverage simultaneously | PR1 |
| COV003 | expired time window, cancelled scan, missing plugin | deadline, cancelled/inaccessible statuses, no leaked handles | PR1/10 |
| DEX001 | minimal benign DEX with known invoke | precise class, descriptor, method, opcode and offset | PR5 |
| DEX002 | malformed offsets/huge count, multidex | reject safely, no OOM or integer overflow | PR5 |
| DEX003 | smali invoke in comment/string vs actual invoke | true positive only where code indicates | PR5 |
| DEX004 | runtime shell from legitimate build tool and DEX class-loader in benign plugin | capability only, not auto malware/exfil | PR5/9 |
| JS001 | suspicious API spelled inside JS comment/string | suppress false code claim; evidence kind STRING_ONLY | PR7 |
| JS002 | obfuscated literal reconstruction and eval call in valid JS | AST/lexer evidence; never execute | PR7 |
| ELF001 | ELF32/64 both byte orders, missing sections, stripped imports | parse bounded, distinguish unknown from corruption | PR7 |
| ELF002 | ELF bad segment size/address overlap, malicious count | reject bounded, no JNI load or execution | PR7 |
| FLOW001 | sensitive read and network in same DEX class but unconnected | potential capability only, no confirmed exfil | PR9 |
| FLOW002 | same DEX register reused, source overwritten before sink | no false positive source→sink | PR9 |
| FLOW003 | traceable source through move/call into sink argument | report witness with method and bytecode offsets | PR9 |
| SIG001 | MD5 `.hdb`, SHA1/SHA256 `.hsb` positives with exact sizes | matching correct, nonmatching omitted | PR0/6 |
| SIG002 | Valid `.ndb` target/offset/EOF/wildcard/negation FLEVEL | match exactly documented supported subset | PR6 |
| SIG003 | corrupt regex pattern, unsupported .ldb, invalid offsets | skip and count, no matched malware claim | PR6 |
| SIG004 | duplicate definitions, oversized file/line, missing DB | no parser hang; counters/coverage warnings | PR6 |
| SIG005 | trusted allowlist and dangerous matched hash | preserve existing semantics and confidence distinction | PR6 |
| PROV001 | known hash but unsigned publisher metadata | fingerprint not treated as authenticated publisher | PR8 |
| PROV002 | valid/invalid/expired signed manifest, key rotation | cryptographic verification and safe failure | PR8 |
| CACHE001 | same name/size/mtime with different signature bytes | invalidate or display unverified freshness; no stale false clean | PR10 |
| JSON001 | old snapshot JSON/text plus new fields, redacted strings | stable old fields, no plaintext token or private path | PR4 |
| UI001 | onBuild/onClick flow, confirmations, repeated scan, screen resume | MT host remains responsive, no implicit actions | PR10 |
| PERF001 | 1/10/50MB benign plugin cold/warm 10 runs | report measured p50/p95, heap, battery proxy; no invented SLA | PR10 |
| REL001 | Java8 core tests, Android30 bootclasspath, D8 min24 `.mtp` | no linkage or classloader errors; signed artifact provenance distinct | all post-PR0 |

**CI requirements:** `bash tools/build.sh test`; `bash tools/build.sh docs` + inspect generated diff; `bash tools/build.sh package` only after network/toolchain approval; parse `dist/mt-safety-scanner.mtp` manifest; compare exported `classes.dex` hash; native fuzz harness only on host with strict CPU/RAM/time caps. Test against reference clamscan for supported patterns on safe fixtures. For Zip95, a fixture 'patched' by editing ZIP method bits but leaving DEFLATE data **does not prove** XZ decoding. On missing fixture, report `NOT_RUN` and ship support status only.
