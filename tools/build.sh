#!/usr/bin/env bash
#
# Builds, checks and packages the plugin.
#
#   tools/build.sh          compile, test, then package
#   tools/build.sh test     compile the pure-Java core and run the test suite
#   tools/build.sh package  build the MT plugin SDK v3 (.mtp) package
#   tools/build.sh docs     regenerate docs/DETECTION-RULES.md from the rule catalogue
#
# The `test` target needs only a JDK: the detection core is plain Java with no Android or MT types,
# so it compiles and runs on a desktop JVM. The `package` target builds a v3 plugin, whose code
# ships as a compiled classes.dex, so it additionally fetches an Android platform jar, the d8 dexer
# and MT Manager's published plugin API. Those downloads are cached under the build directory.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

build_dir="${TMPDIR:-/tmp}/mt-safety-build"
toolchain="$build_dir/toolchain"
out_dir="$root/dist"
mtp="$out_dir/mt-safety-scanner.mtp"

# Pinned toolchain. These URLs are stable; a build is reproducible in what it produces (the dex),
# even though a zip's stored timestamps make the archive itself non-reproducible byte-for-byte.
# d8 ships inside r8. The dev build in build-tools r34 crashes on JDK-21-compiled anonymous classes
# (a trivial anonymous Comparator is enough), so the toolchain pins a stable r8 from Google Maven.
R8_VERSION="8.9.35"
R8_URL="https://maven.google.com/com/android/tools/r8/${R8_VERSION}/r8-${R8_VERSION}.jar"
PLATFORM_URL="https://dl.google.com/android/repository/platform-30_r03.zip"
MT_API_URL="https://maven.mt2.cn/bin/mt/plugin/api/3.0.0/api-3.0.0.aar"
MIN_API=24

fetch() { # url dest
  local url="$1" dest="$2" i
  [ -s "$dest" ] && return 0
  mkdir -p "$(dirname "$dest")"
  for i in 1 2 3 4; do
    if curl -fsSL --max-time 300 -o "$dest" "$url"; then
      [ -s "$dest" ] && return 0
    fi
    echo "    retry $i for $url" >&2
    sleep $((i * 2))
  done
  echo "could not download $url" >&2
  return 1
}

fetch_toolchain() {
  echo "==> fetching v3 toolchain (cached under $toolchain)"
  local android_jar="$toolchain/android.jar"
  local d8_jar="$toolchain/r8.jar"
  local api_jar="$toolchain/mt-plugin-api.jar"

  if [ ! -s "$android_jar" ]; then
    fetch "$PLATFORM_URL" "$toolchain/platform.zip"
    ( cd "$toolchain" && unzip -q -o platform.zip 'android-11/android.jar' )
    cp "$toolchain/android-11/android.jar" "$android_jar"
  fi
  if [ ! -s "$d8_jar" ]; then
    fetch "$R8_URL" "$d8_jar"
  fi
  if [ ! -s "$api_jar" ]; then
    fetch "$MT_API_URL" "$toolchain/mt-api.aar"
    ( cd "$toolchain" && rm -rf aar && mkdir aar && cd aar && unzip -q -o ../mt-api.aar classes.jar )
    cp "$toolchain/aar/classes.jar" "$api_jar"
  fi
  echo "    android.jar $(wc -c < "$android_jar") | r8.jar $(wc -c < "$d8_jar") | mt-api $(wc -c < "$api_jar")"
}

compile_core() {
  # The core plus the desktop CLI and tests. No MT or Android types are involved, so this is the
  # build a contributor runs, and the one the tests need.
  echo "==> compiling core"
  rm -rf "$build_dir/classes"
  mkdir -p "$build_dir/classes"
  find plugin/src tools/src tools/test -name '*.java' > "$build_dir/core-sources.txt"
  javac --release 8 -encoding UTF-8 -Xlint:all,-options -Werror \
    -d "$build_dir/classes" @"$build_dir/core-sources.txt"
  echo "    ok"
}

run_tests() {
  echo "==> running tests"
  java -cp "$build_dir/classes" mtsafety.test.ScannerTest
}

compile_plugin() { # variant_dir  -> compiles core + that UI against the MT/Android toolchain to .dex
  local ui_dir="$1"
  fetch_toolchain
  local android_jar="$toolchain/android.jar"
  local api_jar="$toolchain/mt-plugin-api.jar"
  echo "==> compiling plugin (core + $ui_dir) against the Android/MT toolchain"
  rm -rf "$build_dir/plugin-classes" "$build_dir/dex"
  mkdir -p "$build_dir/plugin-classes" "$build_dir/dex"
  find plugin/src "$ui_dir" -name '*.java' > "$build_dir/plugin-sources.txt"
  # Android bytecode: Java 8 source and target, resolved against the Android platform rather than the
  # desktop JDK, with MT's plugin API on the classpath as a compile-only dependency (MT provides it
  # at runtime, so it is never dexed or shipped).
  javac -source 8 -target 8 -encoding UTF-8 -bootclasspath "$android_jar" -classpath "$api_jar" \
    -Xlint:all,-options -d "$build_dir/plugin-classes" @"$build_dir/plugin-sources.txt"
  ( cd "$build_dir/plugin-classes" && jar cf "$build_dir/plugin.jar" . )
  echo "==> dexing"
  java -cp "$toolchain/r8.jar" com.android.tools.r8.D8 \
    --min-api "$MIN_API" --lib "$android_jar" --classpath "$api_jar" \
    --output "$build_dir/dex" "$build_dir/plugin.jar"
  [ -s "$build_dir/dex/classes.dex" ] || { echo "d8 produced no classes.dex" >&2; exit 1; }
  echo "    classes.dex $(wc -c < "$build_dir/dex/classes.dex") bytes"
}

package() {
  echo "==> packaging (MT plugin SDK v3)"
  for required in plugin/manifest.json plugin/assets; do
    [ -e "$required" ] || { echo "missing $required" >&2; exit 1; }
  done
  python3 -c "import json,sys; m=json.load(open('plugin/manifest.json')); sys.exit(0 if m.get('pluginSdkVersion')==3 and m.get('dexMode') is True else 1)" \
    || { echo "plugin/manifest.json must be a v3 manifest with dexMode true" >&2; exit 1; }

  compile_plugin "plugin/ui-v3"

  local stage="$build_dir/stage"
  rm -rf "$stage"; mkdir -p "$stage"
  cp plugin/manifest.json "$stage/manifest.json"
  cp "$build_dir/dex/classes.dex" "$stage/classes.dex"
  cp -r plugin/assets "$stage/assets"
  [ -f plugin/icon.webp ] && cp plugin/icon.webp "$stage/icon.webp"
  [ -f plugin/icon.png ] && cp plugin/icon.png "$stage/icon.png"

  mkdir -p "$out_dir"
  rm -f "$mtp"
  # manifest.json first so it sits at the top of the archive, where MT expects it.
  ( cd "$stage" && zip -q -r -X "$mtp" manifest.json classes.dex assets \
      $( [ -f icon.webp ] && echo icon.webp ) $( [ -f icon.png ] && echo icon.png ) )

  # Recorded so CI can tell whether the committed .mtp still matches the sources. The archive is not
  # byte-reproducible (a zip stores timestamps), so each member's name is recorded with a hash of its
  # contents: a member list alone catches a file added or removed, not one whose contents changed.
  # classes.dex is excluded from the hash because d8's output embeds build metadata that varies run to
  # run; its presence is recorded instead, and the sources that produce it are what the tests cover.
  : > "$out_dir/CONTENTS.txt"
  while IFS= read -r member; do
    case "$member" in
      */) printf '%s  (directory)\n' "$member" >> "$out_dir/CONTENTS.txt" ;;
      classes.dex) printf '%s  (compiled; not hashed)\n' "$member" >> "$out_dir/CONTENTS.txt" ;;
      *)  printf '%s  %s\n' "$member" \
            "$(unzip -p "$mtp" "$member" | sha256sum | cut -d' ' -f1)" >> "$out_dir/CONTENTS.txt" ;;
    esac
  done < <(unzip -Z1 "$mtp" | LC_ALL=C sort)

  echo "    $mtp"
  echo "    size    $(wc -c < "$mtp") bytes"
  echo "    sha256  $(sha256sum "$mtp" | cut -d' ' -f1)"
  echo "==> archive contents"
  sed 's/^/    /' "$out_dir/CONTENTS.txt"
}

generate_docs() {
  echo "==> regenerating the rule reference"
  python3 tools/render_rules_doc.py "$build_dir/classes"
  echo "    docs/DETECTION-RULES.md"
}

case "${1:-all}" in
  test) compile_core; run_tests ;;
  package) compile_core; package ;;
  docs) compile_core; generate_docs ;;
  all) compile_core; run_tests; package ;;
  *) echo "usage: tools/build.sh [test|package|docs|all]" >&2; exit 1 ;;
esac
