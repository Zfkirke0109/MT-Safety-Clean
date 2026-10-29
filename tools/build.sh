#!/usr/bin/env bash
#
# Builds, checks and packages the plugin.
#
#   tools/build.sh          compile, test, then package
#   tools/build.sh test     compile the pure-Java core and run the test suite
#   tools/build.sh package  build the MT plugin SDK v3 (.mtp) package
#   tools/build.sh docs     regenerate docs/DETECTION-RULES.md from the rule catalogue
#
# The `test` target uses a JDK and the pinned Java8 XZ runtime; no Android or MT types are needed.
# The runtime input is verified on every run (downloaded on first use). The `package` target builds
# a v3 plugin, whose code
# ships as a compiled classes.dex, so it additionally fetches an Android platform jar, the d8 dexer
# and MT Manager's published plugin API. Those downloads are cached under the build directory.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

build_dir="${TMPDIR:-/tmp}/mt-safety-build"
toolchain="$build_dir/toolchain"
out_dir="${MT_OUTPUT_DIR:-$root/dist}"
runtime_jar="$toolchain/xz-java8.jar"

# Versions, sources, archive and extracted-input SHA256 values are reviewed in the lockfile.
MIN_API=24

fetch_toolchain() {
  echo "==> verifying v3 toolchain (cached under $toolchain)"
  python3 tools/toolchain.py "$toolchain"
}

fetch_runtime() {
  python3 tools/toolchain.py "$toolchain" runtime
}

compile_core() {
  # The core plus the desktop CLI and tests. No MT or Android types are involved, so this is the
  # build a contributor runs, and the one the tests need.
  fetch_runtime
  echo "==> compiling core"
  rm -rf "$build_dir/classes"
  mkdir -p "$build_dir/classes"
  find plugin/src tools/src tools/test -name '*.java' | LC_ALL=C sort > "$build_dir/core-sources.txt"
  javac --release 8 -encoding UTF-8 -Xlint:all,-options -Werror \
    -classpath "$runtime_jar" -d "$build_dir/classes" @"$build_dir/core-sources.txt"
  echo "    ok"
}

run_tests() {
  echo "==> running tests"
  java -cp "$build_dir/classes:$runtime_jar" mtsafety.test.ScannerTest
  for regression in \
    mt.safety.scanner.core.BoundedZipDecoderRegression \
    mt.safety.scanner.core.Zip95ContainerRegression \
    mt.safety.scanner.core.SignatureMatchingRegression \
    mt.safety.scanner.core.IndicatorLoadingRegression \
    mt.safety.scanner.core.IndicatorSeedRegression \
    mt.safety.scanner.core.LegacyDirectoryListingRegression \
    mt.safety.scanner.core.AtomicFilesRegression \
    mt.safety.scanner.core.ScanBudgetRegression \
    mt.safety.scanner.core.CoverageLedgerRegression \
    mt.safety.scanner.core.CoverageCompletionRegression \
    mt.safety.scanner.core.ShareReportFormatterRegression \
    mt.safety.scanner.execution.SingleFlightRegression \
    mt.safety.scanner.execution.WorkerBoundaryRegression \
    mt.safety.scanner.execution.UiPolicyRegression \
    mtsafety.test.RunnerExportRegression; do
    java -cp "$build_dir/classes:$runtime_jar" "$regression"
  done
}

compile_plugin() { # variant_dir  -> compiles core + that UI against the MT/Android toolchain to .dex
  local ui_dir="$1"
  fetch_toolchain
  local android_jar="$toolchain/android.jar"
  local api_jar="$toolchain/mt-plugin-api.jar"
  echo "==> compiling plugin (core + $ui_dir) against the Android/MT toolchain"
  rm -rf "$build_dir/plugin-classes" "$build_dir/dex"
  mkdir -p "$build_dir/plugin-classes" "$build_dir/dex"
  find plugin/src "$ui_dir" -name '*.java' | LC_ALL=C sort > "$build_dir/plugin-sources.txt"
  # Android bytecode: Java 8 source and target, resolved against the Android platform rather than the
  # desktop JDK, with MT's plugin API on the classpath as a compile-only dependency (MT provides it
  # at runtime, so it is never dexed or shipped).
  javac -source 8 -target 8 -encoding UTF-8 -bootclasspath "$android_jar" -classpath "$api_jar:$runtime_jar" \
    -Xlint:all,-options -Werror -d "$build_dir/plugin-classes" @"$build_dir/plugin-sources.txt"
  java -cp "$build_dir/classes:$build_dir/plugin-classes:$android_jar:$api_jar:$runtime_jar" \
    mt.safety.scanner.execution.LegacyPreferenceSnapshotRegression
  python3 tools/package_integrity.py jar "$build_dir/plugin-classes" "$build_dir/plugin.jar"
  echo "==> dexing"
  java -cp "$toolchain/r8.jar" com.android.tools.r8.D8 \
    --min-api "$MIN_API" --lib "$android_jar" --classpath "$api_jar" \
    --output "$build_dir/dex" "$build_dir/plugin.jar" "$runtime_jar"
  [ -s "$build_dir/dex/classes.dex" ] || { echo "d8 produced no classes.dex" >&2; exit 1; }
  echo "    classes.dex $(wc -c < "$build_dir/dex/classes.dex") bytes"
}


compile_worker() {
  local worker_main="plugin/ui-v3/mt/safety/scanner/ui/AndroidWorkerMain.java"
  [ -f "$worker_main" ] || { echo "missing scanner-owned Android worker entry: $worker_main" >&2; exit 1; }
  # This worker deliberately has no MT host API or other UI classes on its classpath/program inputs.
  python3 tools/toolchain.py "$toolchain" worker
  echo "==> compiling isolated scanner worker"
  rm -rf "$build_dir/worker-classes" "$build_dir/worker-dex"
  mkdir -p "$build_dir/worker-classes" "$build_dir/worker-dex"
  find plugin/src -name '*.java' | LC_ALL=C sort > "$build_dir/worker-sources.txt"
  printf '%s\n' "$worker_main" >> "$build_dir/worker-sources.txt"
  javac -source 8 -target 8 -encoding UTF-8 -bootclasspath "$toolchain/android.jar" \
    -classpath "$runtime_jar" -Xlint:all,-options -Werror -d "$build_dir/worker-classes" @"$build_dir/worker-sources.txt"
  python3 tools/package_integrity.py jar "$build_dir/worker-classes" "$build_dir/worker.jar"
  java -cp "$toolchain/r8.jar" com.android.tools.r8.D8 \
    --min-api "$MIN_API" --lib "$toolchain/android.jar" \
    --output "$build_dir/worker-dex" "$build_dir/worker.jar" "$runtime_jar"
  [ -s "$build_dir/worker-dex/classes.dex" ] || { echo "d8 produced no worker DEX" >&2; exit 1; }
}

package() {
  echo "==> packaging (MT plugin SDK v3)"
  for required in plugin/manifest.json plugin/assets; do
    [ -e "$required" ] || { echo "missing $required" >&2; exit 1; }
  done
  python3 -c "import json,sys; m=json.load(open('plugin/manifest.json')); sys.exit(0 if m.get('pluginSdkVersion')==3 and m.get('dexMode') is True else 1)" \
    || { echo "plugin/manifest.json must be a v3 manifest with dexMode true" >&2; exit 1; }

  compile_plugin "plugin/ui-v3"
  compile_worker

  local stage="$build_dir/stage"
  rm -rf "$stage"; mkdir -p "$stage"
  cp plugin/manifest.json "$stage/manifest.json"
  cp "$build_dir/dex/classes.dex" "$stage/classes.dex"
  cp -r plugin/assets "$stage/assets"
  cp "$build_dir/worker-dex/classes.dex" "$stage/assets/scanner-worker.dex"
  [ -f plugin/icon.webp ] && cp plugin/icon.webp "$stage/icon.webp"
  [ -f plugin/icon.png ] && cp plugin/icon.png "$stage/icon.png"

  python3 tools/package_integrity.py package "$stage" "$out_dir" "$root"

}

generate_docs() {
  echo "==> regenerating the rule reference"
  python3 tools/render_rules_doc.py "$build_dir/classes"
  echo "    docs/DETECTION-RULES.md"
}

case "${1:-all}" in
  test) compile_core; run_tests; python3 -m unittest discover -s tools/test -p 'test_*integrity.py' ;;
  verify-toolchain) fetch_toolchain ;;
  verify-package) python3 tools/package_integrity.py compare "${2:-$root/dist/mt-safety-scanner.mtp}" "${3:?fresh .mtp path required}" ;;
  worker) compile_worker ;;
  package) compile_core; package ;;
  docs) compile_core; generate_docs ;;
  all) compile_core; run_tests; python3 -m unittest discover -s tools/test -p 'test_*integrity.py'; package ;;
  *) echo "usage: tools/build.sh [test|package|worker|docs|verify-toolchain|verify-package|all]" >&2; exit 1 ;;
esac
