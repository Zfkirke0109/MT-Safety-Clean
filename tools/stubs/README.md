# Compile-only stubs

These files exist so the plugin's MT-facing class can be type-checked on a desktop JVM and in CI.
They are **never** shipped inside the `.mtp`: at runtime MT Manager supplies the real
`bin.mt.plugin.api` classes, and Android supplies `android.content.SharedPreferences`.

The signatures mirror MT Manager's published plugin SDK v2 documentation
(<https://mt.cc/guide/plugin/api-list.html> and the pages it links). If MT Manager's API differs from
what is declared here, the mismatch shows up as a compile error when MT Manager compiles the plugin's
`src/` on device, and the fix belongs in `plugin/src/mt/safety/scanner/ui/ScannerPreference.java` —
the only source file that references these types.
