# Content-free sharing

`ShareReportFormatter.text(List<ScanReport>)` and `ShareReportFormatter.json(List<ScanReport>)`
produce an explicitly marked `SHARE-SAFE` / `SHARE_SAFE` export. These APIs return strings; they do
not write files, upload data, modify scores, or perform package actions. The command and UI must select
this mode explicitly. Keep `ReportFormatter` for useful private local reports.

The export permits scanner-authored constants, compiled enum values, an exact scanner-owned rule ID
allowlist, numeric scores/counts and opaque SHA-256 identifiers. Unrecognized rule IDs become the fixed
`UNRECOGNIZED_RULE` value, even when they look like valid rule IDs. New scanner rules must be added to
the allowlist to retain their IDs. No regular expression can establish that arbitrary text is safe.

Names, plugin IDs, manifest values, versions, paths, excerpts, titles, explanations, verdict reasons,
traits, action identities, error messages and signature names are omitted. Error and evidence counts
remain visible. Counts and rule/severity/category combinations still reveal scan results; this mode
does not promise anonymity or conceal which capabilities were detected.

Public `contentHash` and evidence-location fields are hash inputs, never trusted export strings. Each
formatter call creates a fresh 256-bit random salt that is not exported. Full SHA-256 output includes
that salt, the report ordinal and a separate report/location domain. A location can correlate findings
within a report; it is the entire evidence location, possibly including a line, rather than a normalized
archive-member identity. Duplicate reports receive distinct IDs. Separate formatter calls, including
text and JSON calls over the same input, produce different IDs. IDs are unsuitable for package actions
or comparing exports. They do not replace the original content hash used locally.

Legacy verdict, independent coverage, numeric score and finding severity remain available. A partial
clean result has disposition `INCOMPLETE` and a question marker. A partial trusted result is
`TRUSTED_INCOMPLETE`. Other partial findings use `FINDINGS_INCOMPLETE`; their verdict and severity
markers remain visible. Complete clean results with findings use `FINDINGS_BELOW_THRESHOLD`.

This formatter covers package scan reports only. File scan reports, discovery diagnostics and loaded
definition metadata are not accepted by this API and must not be appended to share-safe output. The
local formatter's recognizable-credential redaction remains a separate safeguard; arbitrary secrets
cannot be recognized reliably.

Run the focused regression after `bash tools/build.sh test`:

```sh
java -cp "$TMPDIR/mt-safety-build/classes:$TMPDIR/mt-safety-build/toolchain/xz-java8.jar" \
  mt.safety.scanner.core.ShareReportFormatterRegression
```

The regression injects arbitrary phrases into every free-form report surface, malicious unknown rule
IDs and a digest-shaped public hash. It checks both export modes, strict JSON parsing and permitted
JSON scalars/keys, full-length opaque IDs, within-report location correlation, fresh export IDs,
qualified partial dispositions, unchanged scores and the separate useful local report.
