#!/usr/bin/env bash
# Build only scanner-owned device fixtures; this never installs or runs anything on a phone.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="${TMPDIR:-/tmp}/mt-safety-build"
cd "$root"
bash tools/build.sh worker
classes="$build_dir/device-classes"
dex="$build_dir/device-dex"
mkdir -p "$classes" "$dex"
javac -source 8 -target 8 -encoding UTF-8 -Xlint:all,-options -Werror \
  -bootclasspath "$build_dir/toolchain/android.jar" \
  -classpath "$build_dir/worker-classes" -d "$classes" \
  tools/android/mt/safety/scanner/device/DeviceRegression.java
python3 tools/package_integrity.py jar "$classes" "$build_dir/device.jar"
java -cp "$build_dir/toolchain/r8.jar" com.android.tools.r8.D8 \
  --min-api 24 --lib "$build_dir/toolchain/android.jar" \
  --classpath "$build_dir/worker.jar" --output "$dex" "$build_dir/device.jar"
echo "Harness: $dex/classes.dex"
echo "Worker: $build_dir/worker-dex/classes.dex"
