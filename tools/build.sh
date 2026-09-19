#!/usr/bin/env bash
#
# Builds, checks and packages the plugin.
#
#   tools/build.sh          compile, test, then package
#   tools/build.sh test     compile and test only
#   tools/build.sh package  package only
#   tools/build.sh docs     regenerate docs/DETECTION-RULES.md from the rule catalogue
#
# Needs nothing but a JDK and zip. There is no Android SDK step because an MT plugin SDK v2 package
# is a zip of Java sources that MT Manager compiles on the device; the javac run here exists to catch
# errors before the phone does.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

build_dir="${TMPDIR:-/tmp}/mt-safety-build"
out_dir="$root/dist"
mtp="$out_dir/mt-safety-scanner.mtp"

compile() {
  echo "==> compiling"
  rm -rf "$build_dir"
  mkdir -p "$build_dir"
  # tools/stubs stands in for classes MT Manager and Android provide at runtime; it is never shipped.
  find plugin/src tools/stubs tools/src tools/test -name '*.java' > "$build_dir/sources.txt"
  javac --release 8 -encoding UTF-8 -Xlint:all,-options -Werror \
    -d "$build_dir/classes" @"$build_dir/sources.txt"
  echo "    ok"
}

run_tests() {
  echo "==> running tests"
  java -cp "$build_dir/classes" mtsafety.test.ScannerTest
}

package() {
  echo "==> packaging"
  for required in plugin/manifest.json plugin/src plugin/assets; do
    [ -e "$required" ] || { echo "missing $required" >&2; exit 1; }
  done
  python3 -c "import json,sys; json.load(open('plugin/manifest.json'))" \
    || { echo "plugin/manifest.json is not valid JSON" >&2; exit 1; }

  mkdir -p "$out_dir"
  rm -f "$mtp"
  # Zipped from inside plugin/ so manifest.json sits at the top of the archive, where MT expects it.
  ( cd plugin && zip -q -r -X "$mtp" manifest.json src assets $( [ -f icon.png ] && echo icon.png ) )

  # Recorded so CI can tell whether the committed .mtp still matches the sources. The archive itself is
  # not byte-reproducible, because a zip stores modification times, so each member's name is recorded
  # with a hash of its contents. A member list alone catches a file added or removed but not one whose
  # contents changed, which is exactly how a stale artefact would slip through.
  : > "$out_dir/CONTENTS.txt"
  while IFS= read -r member; do
    case "$member" in
      */) printf '%s  (directory)\n' "$member" >> "$out_dir/CONTENTS.txt" ;;
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
  test) compile; run_tests ;;
  package) package ;;
  docs) compile; generate_docs ;;
  all) compile; run_tests; package ;;
  *) echo "usage: tools/build.sh [test|package|docs|all]" >&2; exit 1 ;;
esac
