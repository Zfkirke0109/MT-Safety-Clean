# Scanner-owned Android regression harness

Build with the same reviewed Java8/Android/D8 inputs as the worker:

```sh
bash tools/android/build-harness.sh
```

The script prints paths to the harness and worker DEX. It never connects to, installs on, or changes
a phone. Transfer these two scanner-owned files to a fresh private scratch directory belonging to
the test app, verify their SHA256 values, and mark them read-only before ART loads them. Create an
empty run directory beneath that scratch directory, then use the trusted ART runtime available on
the test device:

```sh
CLASSPATH=/private/scratch/harness.dex:/private/scratch/worker.dex \
  /apex/com.android.art/bin/dalvikvm -Xmx96m \
  -cp /private/scratch/harness.dex:/private/scratch/worker.dex \
  mt.safety.scanner.device.DeviceRegression \
  /private/scratch/worker.dex /private/scratch/fresh-run
```

Those paths are placeholders; discover the app identity, private directory and trusted runtime on
the actual device. Older Android releases may use another fixed path from `AndroidWorkerLaunch`.
Run as an ordinary app UID, with an outer command deadline. The harness writes only new inert
fixtures beneath its supplied run directory, starts only scanner-owned code and tests termination
of its own children. It never executes archive members or installs the plugin.

The standalone ART harness uses public `android.system.Os` calls for its fixture process IDs and
signals. Framework `android.os.Process` native methods are not all registered in standalone ART.
The MT UI adapter runs in the Android application framework; this harness does not validate that
host adapter, UI lifecycle or plugin installation.

The S26 Ultra/API37 receipt is in `evidence/remediation-2026-10-29/android-worker.json`: 16 checks,
ordinary app UID, 100663296-byte maximum heap, successful IPC, timeout and cancellation. Forcing
the legacy directory backend on API37 tests that backend on this phone; API24/25 hardware remains
untested. A successful harness run is not an MT host integration test.
