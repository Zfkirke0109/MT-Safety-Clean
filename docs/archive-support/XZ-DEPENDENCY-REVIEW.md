# Bounded ZIP95 decoder dependency review

Reviewed on 2026-10-28. Runtime candidate: `org.tukaani:xz:1.12`, a pure Java XZ
implementation. Maven POM contains no dependencies. The upstream home page states
the base code is Java 8 compatible and version 1.12 fixes a significant bug in
1.10/1.11. The official security section reported no known security issues on the
review date; this is a point-in-time upstream statement, not a guarantee.

WinZip's official method-95 support article identifies this method as XZ and dates
its support to WinZip 18; it is distinct from ZIP method 14 (LZMA).

Primary sources:

- https://kb.winzip.com/en/130426

- https://tukaani.org/xz/java.html
- https://github.com/tukaani-project/xz-java/blob/master/SHA256SUMS
- https://github.com/tukaani-project/xz-java/blob/v1.12/COPYING
- https://github.com/tukaani-project/xz-java/blob/v1.12/NEWS.md
- https://repo.maven.apache.org/maven2/org/tukaani/xz/1.12/xz-1.12.pom

| Artifact | SHA256 |
|---|---|
| xz-1.12.jar (168792 bytes) | 3e158a87bd73d8afb4b6e8239c013b7d049c48563f45860ce99cd2e448cf4a6b |
| xz-1.12.pom | 937b44d869c059c39f07ae194d8cd6219f5aebf2200ef9707f0b50b7837da281 |
| xz-1.12-sources.jar | c35c682fa8b617c1f6f21270df14bad4e11df2fe46962dfe45e765b7aec0181b |

Downloaded artifact hashes were compared to the official project's SHA256SUMS.
No OpenPGP signature verification is claimed. Sources and POM are review inputs;
only the vetted Java 8 runtime classes are required in the plugin. License is
0BSD, reproduced in `plugin/assets/licenses/xz-1.12.txt`.

The published jar is multi-release. Build integration must exclude
`META-INF/versions/**` and module-info classes before D8 input; it must also use
this flattened jar in JVM regressions so tests exercise the Android base classes,
not optimized Java 9 variants. All 123 base class files were inspected and use
class-file version <=52. Java 8 source compilation has been tested. D8/API24
package validation belongs to the parent integration build; this adapter review
alone does not claim Android device execution or performance measurements.

## Decoder contract and bounds

`BoundedZipDecoder.read(raw, method, flags, compressedSize, size, crc, limit, budget)`
accepts a raw compressed slice only after archive metadata admission. The caller
must bind index identity to the exact local-header position, validate local and
central name/method/flags/size/CRC (including descriptors), and refuse overlapping
or ambiguous layouts. The adapter never extracts files, evaluates fixture data,
loads inspected dex/native code, or requests a password.

- Methods 0 (stored), 8 (raw deflate), and 95 (XZ) are supported.
- Encrypted flags and unsupported methods/reserved flags fail explicitly.
- Compressed bytes are capped at 8 MiB and exact raw consumption is checked.
- Output is capped by the caller and `PluginPackage.MAX_MEMBER_BYTES` (4 MiB).
- XZ uses `SingleXZInputStream` with `memoryLimit=8192` KiB,
  `verifyCheck=true`, and the dummy array cache (no retained decoder buffers).
- Decompression reads use 8 KiB chunks with budget/deadline/cancellation polling.
- A complete read requires exact decoded count, ZIP CRC32, codec end/footer checks,
  and no unused compressed bytes. Concatenated XZ streams, XZ stream padding and
  any trailing compressed data deliberately refuse rather than silently truncate.
- Prefix reads return only authorized bytes and mark the budget truncated; their
  unconsumed remainder and CRC/footer have not been verified.
- The method always closes its source, including unsupported or oversized input.

This is an intentionally narrower decoder than a general archive extractor.
Large dictionaries, arbitrary compression methods, split/encrypted archives and
unsupported container layouts remain incomplete coverage. Existing 8000-entry,
2 MiB central-directory metadata preflight and nested depth/member/count limits
must remain enforced by the parent container layer.

## Independent proof

See `tools/test-fixtures/zip95/README.md`. The libarchive upstream archive contains
three real method-95 XZ streams, validated against upstream CRC32 oracles and
independently calculated liblzma output hashes. No claimed proof relies on a
method-field-only mutation. The original creating archiver is not documented, so
there is no claim of WinZip-specific compatibility or an exhaustive ZIP95 corpus.
