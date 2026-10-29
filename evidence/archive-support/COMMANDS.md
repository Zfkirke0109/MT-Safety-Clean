# Adapter verification commands

Environment: Linux, OpenJDK 17.0.20 (2026-07-21), source compatibility `--release 8`.
`PATH=/tmp/mt-review-bin:$PATH`; `TMPDIR=/tmp/mt-task-archive`.

The first `bash tools/build.sh test` with the new regression and no adapter
failed compilation (`red-compile.log`). A scanner-owned minimal main opening the
unaltered upstream archive with `new ZipFile(file)` failed with method-95 refusal
(`red-platform.log`). The ZipFile failure is the behavioral baseline, not proof of
a fake-header fixture. The tested archive's provenance and actual XZ content are
documented alongside the binary.

Because build.sh is owned by the build-integrity task, its dependency wiring is
not changed in this worktree. The green commands used the inspected/flattened
runtime jar directly:

```sh
find plugin/src tools/src tools/test -name '*.java' > /tmp/mt-task-archive/sources.txt
javac --release 8 -encoding UTF-8 -Xlint:all,-options -Werror \
  -cp /tmp/mt-task-archive/xz-1.12-java8.jar \
  -d /tmp/mt-task-archive/classes @/tmp/mt-task-archive/sources.txt
java -Xmx48m \
  -cp /tmp/mt-task-archive/classes:/tmp/mt-task-archive/xz-1.12-java8.jar \
  mt.safety.scanner.core.BoundedZipDecoderRegression
java -cp /tmp/mt-task-archive/classes:/tmp/mt-task-archive/xz-1.12-java8.jar \
  mtsafety.test.ScannerTest
```

Results: compilation PASS; decoder 87 checks PASS under 48 MiB heap; existing
suite 428 passed, 0 failed, 0 skipped. The enormous-dictionary case requests
128 MiB in its valid XZ block header and fails via the configured decoder memory
limit before such an allocation (the JVM heap is only 48 MiB). The fixture's XZ
streams themselves have low dictionary requirements; this test does not claim
all WinZip settings fit the configured cap.

A single compressed stream is parsed only as data. No fixture scripts are
executed and no inspected native or dex code is loaded. D8 and Android device
execution are NOT_RUN by this isolated task. Parent integration must run the
canonical build/tests/package and register the focused test, including complete
root/nested archive cases and truthful per-entry coverage.
