# Genuine ZIP method 95 fixture

`libarchive-xz-multi.zipx` is the unmodified binary obtained by uu-decoding
`libarchive/test/test_read_format_zip_xz_multi.zipx.uu` in upstream libarchive v3.8.2.
It was introduced upstream in commit `121035c83e18b70d3128e9ac966109ebedb7e516`
(2018-12-18), with the XZ ZIP reader and independent expected CRC32 values.
The creating archiver/version is not recorded in that commit; this file must not be
advertised as a verified WinZip-produced fixture. It is an authentic independent
upstream ZIP95 test archive, not a ZIP created by changing method fields in this project.

Sources:

- https://github.com/libarchive/libarchive/blob/v3.8.2/libarchive/test/test_read_format_zip_xz_multi.zipx.uu
- https://github.com/libarchive/libarchive/blob/v3.8.2/libarchive/test/test_read_format_zip.c
- https://github.com/libarchive/libarchive/commit/121035c83e18b70d3128e9ac966109ebedb7e516

Archive: 5476 bytes, SHA256
`d4ba4b1fa117e8170ffb4e0ded734c5da9006064daf35c9056671c66da21bb74`.
The three local headers and central records specify method 95, flags 0, no encryption.
The central directory starts at byte 5179. There are exactly three central records,
followed by the EOCD, with no trailing data. Payload bytes begin with actual XZ
stream magic; each independently decompresses with Python's liblzma implementation.
The fixture contents are read solely as static test data and are never executed.

| Member | Compressed offset | Compressed bytes | Decoded bytes | Upstream CRC32 | Decoded SHA256 independently measured with Python/liblzma |
|---|---:|---:|---:|---|---|
| bash.bashrc | 41 | 1216 | 2245 | f751b8c9 | 4995deb0c6a2b5482ba62759f1f5bcdd19186528d99d263dc8bc61d42878798e |
| pacman.conf | 1298 | 1344 | 2566 | b20b7f88 | 6024bbf50cc92236b7b437430cb9e4180da91925cdc19a5a7910fe172931cfb6 |
| profile | 2679 | 2500 | 6601 | 2329f054 | 4973827f59fed69911bc0b3e4ad7f9ee6aac0ee120b38ded0a46a7302044dd36 |

`LIBARCHIVE-COPYING` preserves the upstream distribution license. The companion C
test credits Tim Kientzle (2003-2007) and Michihiro NAKAJIMA (2011), under the same
BSD redistribution/disclaimer terms. No libarchive code is shipped in the plugin.

The separately embedded XZ CRC32 regression stream is synthetic scanner-owned test
data compressed with Python/liblzma; it is only an integrity-check test, and is not
used as the proof of independent ZIP95 support.
