# Sources, URLs, tool use and citations ledger

## First-party repository / live source inspected

- Repository https://github.com/Zfkirke0109/MT-Safety-Clean (HEAD `90de1e15ef4ce9ad20e272a64daa52b4ed56a189`, retrieved through GitHub API/phone read-only curl on 2026-10-09 PDT)
- Tree endpoint https://api.github.com/repos/Zfkirke0109/MT-Safety-Clean/git/trees/main?recursive=1
- Current source pin https://github.com/Zfkirke0109/MT-Safety-Clean/tree/90de1e15ef4ce9ad20e272a64daa52b4ed56a189
- `plugin/manifest.json`: 2–11; `tools/build.sh`: 24–32, 71–106, 111–148, 163–169; `.github/workflows/ci.yml`: 12–51.
- `plugin/src/mt/safety/scanner/core/PluginPackage.java`: 14–16, 177–249, 266–339, 550–590; `PluginScanner.java`: 54–111; `RiskScorer.java`: 107–126, 186–220; `ScanBudget.java`: 6–9,19–26,36–37,61–89,98–124; `CodeRules.java`: 40–46,203–243; `SignatureDatabase.java`: 283–455; `ScanRunner.java`: 29–40,72–85.
- The following files were *enumerated in the tree*, not fully line-by-line audited here: `FileScanner.java`, `HexSignature.java`, `ReportFormatter.java`, `Discovery.java`, `Quarantine.java`, `ScannerPreference.java`, `tools/test/mtsafety/test/{ScannerTest,SignatureTest,ActionsTest,Fixtures}.java`. Copilot must inspect them in PR0. Do NOT claim all repository files were executed or complete runtime behavior proved.

## Official technical references (checked via web)

1. MT Manager Plugin SDK v3 getting started, preference API and official demo (official demo **uses Gradle**, current repo does **not**): https://mt.cc/guide/plugin-v3/getting-started.html . Main preference must implement PluginPreference; official developer steps show `.mtp` distribution.
2. Commons Compress ZIP supported methods and limitations: https://commons.apache.org/proper/commons-compress/zip and https://commons.apache.org/proper/commons-compress/limitations.html
3. Commons Compress 1.28 `ZipFile` raw stream and canReadEntryData: https://commons.apache.org/proper/commons-compress/apidocs/org/apache/commons/compress/archivers/zip/ZipFile.html
4. ZipMethod XZ=95: https://commons.apache.org/proper/commons-compress/apidocs/org/apache/commons/compress/archivers/zip/ZipMethod.html
5. Apache release notes/Java requirement: https://commons.apache.org/proper/commons-compress/changes.html ; security advisories: https://commons.apache.org/proper/commons-compress/security.html ; license: https://www.apache.org/licenses/LICENSE-2.0
6. XZ for Java project/version/Java8/license: https://tukaani.org/xz/java.html ; stream constructor and KiB limit: https://tukaani.org/xz/xz-javadoc/org/tukaani/xz/SingleXZInputStream.html
7. PKWARE ZIP APPNOTE: https://support.pkware.com/pkzip/appnote ; Common ZIP (supplementary independent spec): https://commonzip.org/spec/
8. ClamAV format: https://docs.clamav.net/manual/Signatures.html ; .ndb grammar: https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html ; byte pattern: https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html
9. Maintained smali fork and coordinates: https://github.com/google/smali ; Google Maven `com.android.tools.smali:smali-dexlib2`; BSD-3-Clause from upstream build metadata.
10. OSV project and API: https://osv.dev/docs/ ; Android ART/dex: https://source.android.com/docs/core/runtime ; CWE-409: https://cwe.mitre.org/data/definitions/409.html

**Source boundaries:** Web source checks confirm technical APIs, not working integration with MT Manager. In particular, no published library's availability can validate ZIP95 payload framing, real Java8/D8 success or UI behavior. Dependency advisories and sizes require version-specific refresh on each implementation PR; do not overstate the absence of CVEs.

## Skills actually read from installed catalog

- `skills://plugins/android-engineering-suite/testing-setup`
- `skills://plugins/android-engineering-suite/android-permissions-security`
- `skills://plugins/engineering-suite/doubt-driven-development`
- `skills://plugins/agent-skills/source-driven-development`
- `skills://plugins/agent-skills/security-and-hardening` (general threat modeling portions apply; web-specific examples do not govern this Java MT plugin)
- `skills://plugins/mattpocock-skills/research` (primary-source research principles; no background agent supported or launched)
- `skills://plugins/codex-dev-workflows/create-agent-instructions`
- `skills://plugins/codex-dev-workflows/code-review`

Other @mentioned plugins were discovered through their skill catalog, but none of their other workflows was executed. Research performed with DroidBridge Unified **read-only context/shell `getprop` and `curl`**; website source lookup, offline ZIP/PDF text extraction and checksum comparison. No device state change, compiler invocation on the actual repository, security exploit, Gemini session, GitHub write or Copilot run occurred.
