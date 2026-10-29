# Build integrity and dedicated developer checks

`bash tools/build.sh test` runs the Java regression suite and behavioral Python integrity tests.
The first run also fetches the approved pinned XZ runtime; subsequent runs reverify its cache.
`bash tools/build.sh package` retains Java 8 source/target, SDK3, D8 min API24 and the compile-only
MT host API. There is no Gradle project, APK conversion or new scanner runtime network access.

## Reviewed input lock and cache behavior

`tools/toolchain-lock.json` fixes URLs, versions and SHA256 values. Every archive **and** every
extracted cached JAR is verified on every invocation. A corrupt cache fails closed; remove the
identified cache entry only after investigating it. Downloads use HTTPS-only redirects and a
unique temporary file; the expected SHA256 must match before atomic publication into the cache.
Only one fixed reviewed ZIP member is extracted, with a 100 MiB bound, without interpreting paths.

Independent retrieval on 2026-10-28 confirmed the Google inputs below. The MT entries retain
the existing reviewed receipts pending successful original-host retrieval (see the limitation below):

| Input | Original source | SHA256 | License/scope |
| --- | --- | --- | --- |
| R8/D8 8.9.35 | [Google Maven JAR](https://maven.google.com/com/android/tools/r8/8.9.35/r8-8.9.35.jar) | `204b2fc2b0f4e888dc0ef748b58090def1bf4185068d36abbb94841dbc7107a8` | BSD-3-Clause for R8 code; bundled third-party licenses are in the JAR's `LICENSE`. Build only. |
| Android platform30 r03 | [Google SDK ZIP](https://dl.google.com/android/repository/platform-30_r03.zip) | `f3f5b75744dbf6ee6ed3e8174a71e513bfee502d0bc3463ea97e517bff68d84e` | Android SDK license, compile only. |
| android.jar | `android-11/android.jar` in that verified ZIP | `96ccfdc84d15fad4e22d76cbb8ef38b150a4b56327957067875ca7e18113a424` | Compile only; never dexed. |
| MT API3.0.0 AAR | [MT Maven AAR](https://maven.mt2.cn/bin/mt/plugin/api/3.0.0/api-3.0.0.aar) | `a51c800eb904e41834ded615376e8c60a33788b073bbb967777ac61d6c88f82d` | License not asserted; compile only. |
| MT classes.jar | `classes.jar` in that AAR | `6e90db4fd75342d717c22469a3a2407bbcce0b43f7790f99088983c42115b84a` | Compile only; never dexed. |

The Google Maven POM identifies R8 8.9.35 and has no external dependencies; its binary bundles
third-party components and notices. The SDK ZIP's `source.properties` confirms API30 revision3.
The MT Maven service returned HTTP503 during task5's initial independent retrieval attempts;
MT hashes are pinned from the existing reviewed receipt and must also match the actual available
artifact before a package build can proceed. That availability/provenance limitation is explicit,
not a successful independent re-download claim. No MT API license is inferred from availability.

## XZ runtime integration

The approved XZ1.12 runtime JAR comes from [Maven Central](https://repo.maven.apache.org/maven2/org/tukaani/xz/1.12/xz-1.12.jar),
SHA256 `3e158a87bd73d8afb4b6e8239c013b7d049c48563f45860ce99cd2e448cf4a6b`, 168792 bytes,
0BSD license, no POM dependencies. Its independent official-host download and official `.sha256`
sidecar matched the reviewed receipt. The package build uses only base `.class` members, excludes
`META-INF/versions/**` and `module-info.class`, and rejects base classes newer than Java8 (major52).
The deterministic flattened JAR SHA256 is
`91574957aacdfafaa3c14c5c5f16076d0c3150754ebdec79c2ae60e43ad98c87` (123 base classes).
Both original and cached flattened JAR hashes are enforced before use. XZ is on desktop compile/test/CLI
and plugin compile classpaths, and is a D8 **program** input. MT API and Android remain compile-only.
The archive task owns the adapter, authentic method95 fixtures and the bundled XZ license notice.
The build runs its dedicated `BoundedZipDecoderRegression` main when that test class is integrated.

## Deterministic packaging and receipts

The intermediate class JAR and final MTP use sorted members, fixed `1980-01-01T00:00:00Z` timestamps,
fixed Unix regular-file permissions, and stored ZIP entries. Stored entries avoid zlib-version
variance. `manifest.json` is first; remaining names are lexically sorted. Java source lists are
sorted. Every actual package member, including `classes.dex` and any worker DEX asset, is SHA256
hashed in `CONTENTS.txt` and `PROVENANCE.json`. No DEX exemption remains.

The output directory contains:

- `mt-safety-scanner.mtp`, `CONTENTS.txt` and `SHA256SUMS`.
- `PROVENANCE.json`: package/member hashes, Git source revision, actual source/resource/build-file
  hashes (including uncommitted input bytes), locked toolchain inputs and compatibility settings.
- `SBOM.cdx.json`: CycloneDX1.5 component inventory with explicit build/compile-only scopes. Build/compile-only
  components are excluded; the approved XZ dependency is marked required in the runtime artifact.

Provenance is an unsigned local receipt, not a signed supply-chain attestation. The JDK and OS are
provided by the developer/runner; cross-JDK byte reproducibility is not promised. CI repeats the
build on the same runner and compares complete MTP bytes. It separately compares **actual** committed
and rebuilt archive-member bytes, so stale DEX fails even if a hand-edited `CONTENTS.txt` agrees.

```sh
TMPDIR=/tmp/mt-build MT_OUTPUT_DIR=/tmp/mt-fresh bash tools/build.sh package
bash tools/build.sh verify-package dist/mt-safety-scanner.mtp /tmp/mt-fresh/mt-safety-scanner.mtp
```

`MT_OUTPUT_DIR` allows a review build without replacing checked-in artifacts. CI uses a separate
output directory and always uploads a successfully built package and receipts even if the stale
committed-package gate fails. The gate should be resolved by reviewing and synchronizing the fresh
artifact, never by excluding DEX or weakening comparison.

## Dedicated developer-only checks

`TMPDIR=/tmp/mt-security python3 tools/security_checks.py --output /tmp/mt-security-report`
runs standalone Linux x86_64 Gitleaks and Semgrep OSS core. Both archives are pinned in
`tools/security/scanners-lock.json`, downloaded and SHA256 verified by the same fail-closed cache
logic. Exactly one known executable member is copied from each verified archive. No package install,
remote rule registry, account, metrics upload or Python dependency installation is needed. Neither
engine is packaged into the plugin. Other platforms report unsupported/not run explicitly.

| Engine | Official receipt | Archive SHA256 | License |
| --- | --- | --- | --- |
| Gitleaks8.28.0 | [Official release API](https://api.github.com/repos/gitleaks/gitleaks/releases/tags/v8.28.0), Linux x64 asset digest | `a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb` | MIT |
| Semgrep1.138.0 core | [PyPI version metadata](https://pypi.org/pypi/semgrep/1.138.0/json), published Linux x86_64 wheel digest | `7a10d1e33191b5314a6375051151e30e4315ffca362d54a18955b7ce1fbdd5f4` | LGPL-2.1-or-later according to release metadata |

Both downloaded archive hashes were independently matched against those official metadata records.
Only the self-contained Semgrep core binary is executed; wheel Python packages and their transitives
are not installed. Gitleaks default rules scan the working tree and fully redact secret reports;
this does not claim full Git-history coverage. Semgrep applies five local AST rule groups to all
plugin Java sources: unsafe native deserialization, disabled hostname verification, obsolete TLS
selection, dynamic loading, and process launch. Engine errors/timeouts/parser omissions fail the
check. Positive controls test that the real engines/rules detect synthetic input. No control
contains a live credential. Command-launch findings are review-only; legitimate scanner-owned OS
helpers still require a human assessment. Other error findings and any secret findings fail CI.
Reports retain only rule/file/line for Semgrep, and fully redacted Gitleaks details. Empty focused
results are not a claim that the scanner has no vulnerabilities. CodeQL is not configured or run.

OSV version queries on 2026-10-28 returned no records for Maven `com.android.tools:r8`8.9.35,
PyPI `semgrep`1.138.0 and Go `github.com/gitleaks/gitleaks/v8`v8.28.0. This is a point-in-time registry
check, not an audit of every bundled third-party component; no comprehensive advisory clearance is
claimed for Android SDK or the MT API.

## GitHub Actions pins

The official GitHub `git/ref/tags` API was queried for each original repository and the returned
commit objects matched these immutable workflow pins (no fork or mirror was used):

| Action tag | Commit |
| --- | --- |
| actions/checkout v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| actions/setup-java v4.7.1 | `c5195efecf7bdfc987ee8bae7a71cb8b11521c00` |
| actions/cache v4.2.3 | `5a3ec84eff668545956fd18022155c47e93e2684` |
| actions/upload-artifact v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |

Workflow permissions are `contents: read`; checkout does not persist credentials. Action pinning
retains the existing major versions, rather than silently changing the runner environment.


## Scanner-owned worker and historical API cache receipts

Packaging separately compiles `plugin/src` plus only
`plugin/ui-v3/mt/safety/scanner/ui/AndroidWorkerMain.java` against Android and XZ, with no MT API or
other UI classes as program/classpath inputs. D8 minAPI24 produces `assets/scanner-worker.dex`; the freshly
compiled bytes overwrite any source asset at that path. Its entry class is
`mt.safety.scanner.ui.AndroidWorkerMain`. The main plugin may also contain that entry class.
`bash tools/build.sh worker` builds only this worker, without fetching MT API. The package receipt
records the worker source recipe, and the ordinary member hashes/actual archive comparison cover it.

During MT upstream unavailability CI explicitly restores the original cache key
`mt-toolchain-r8-8.9.35-platform30` at its original `/tmp/mt-safety-build/toolchain` path; GitHub cache
versions include cache paths, so a new-path restore key alone would not retrieve the old entry.
`tools/cached_api_receipts.py` verifies every available old/current MT AAR and JAR against the same
lock before copying any bytes. Only verified available `mt-api.aar` and `mt-plugin-api.jar` are
staged into the current cache and uploaded as the `build-input-receipt` artifact, including when a
subsequent package gate fails. Empty caches produce no receipt; corrupt caches fail and publish none.
This fallback does not change the approved original source URL, hashes or host-API compile-only scope.

On 2026-10-29 the exact pinned MT AAR and JAR were recovered from this repository's verified
`build-input-receipt` artifact in [run40633296587](https://github.com/Zfkirke0109/MT-Safety-Clean/actions/runs/40633296587),
artifact12880946492. The downloaded ZIP SHA256 was
`fb1e464426f13d078f4998b7ada39750c4eeac4064d3db8b8e82ee7dffb2ce90`.
Both members matched the lockfile before use. The final SDK3/worker builds therefore used the
real reviewed MT API bytes, not substitutes; the original Maven service's availability remains
separate from this verified cache-receipt recovery.
