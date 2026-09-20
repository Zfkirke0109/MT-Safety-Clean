# MT Manager Plugin Safety Scanner

An MT Manager plugin that scans the **other** MT Manager plugins installed on your device, reports what
each one is actually able to do, and helps you get rid of the ones that have no business doing it.

It also ships a command line scanner, so you can check an `.mtp` **before** you install it — which is
the moment at which checking is most useful.

```
1 plugin scanned: 1 to remove, 0 suspicious, 0 worth a look, 0 clean

=== Translate Pro (Official) ===
Verdict : Likely malicious  (risk score 171)
Advice  : Remove this now, then change any password or key you opened on this device.

[!!!] CRITICAL  CMB101  Reads private data and has a way to send it out
[!! ] HIGH      NET003  Sends data to an anonymous drop or bot endpoint
      - src/pro/Engine.java:18  |  new URL("https://api.telegram.org/bot99:AAF/sendDocument")
[!! ] HIGH      SEN001  Reads app-private storage paths
      - src/pro/Engine.java:17  |  new File("/data/data/com.whatsapp/databases").listFiles()
[!  ] MEDIUM    MFT008  Claims to be official or verified
```

## Why a plugin can be dangerous at all

MT Manager's documentation says plugins "only affect MT Manager, not the system or other applications".
That is a fair statement of intent, but it is not a sandbox: a plugin's Java code runs **inside MT
Manager's own process**, so ordinary `java.io.File` and `java.net` calls work, backed by MT Manager's
storage and network access. A plugin can read what MT Manager can read.

That is the gap this tool looks into. It does not trust the format to protect you; it reads what each
package can actually do and tells you.

## What it looks for

Roughly 50 rules across shell and root commands, loading code from outside the package, network
endpoints built for anonymous collection, access to private app data and key material, clipboard and
screen capture, reaching into MT Manager's own files, destructive and ransomware behaviour, hidden and
encoded payloads, and package-structure attacks such as a member that unpacks outside its own folder.

**Combinations decide the verdict, not individual hits.** Network access is ordinary. Reading another
app's private data is odd. A package doing both is exfiltration, and gets called that even when the two
halves sit in different files.

**A capability the plugin's purpose requires is not held against it.** A translation engine has to reach
the network. If it only does that, the network finding is recorded as context and not counted — but if
the same package also reads private data, the excuse is withdrawn and its network use counts in full.
The example above is exactly that case: it declares itself a translation engine, and is still condemned.

Full reference, generated from the rules themselves: **[docs/DETECTION-RULES.md](docs/DETECTION-RULES.md)**.

## Install the plugin

1. Download `dist/mt-safety-scanner.mtp` from this repository (or build it with `tools/build.sh`).
2. Open it with MT Manager, or use MT Manager's plugin management screen to install it.
3. Open **plugin management**, tap **Plugin Safety Scanner**.

Opening the plugin's settings screen **is** the scan — MT Manager gives a plugin one screen, built once,
with no buttons, so the screen is the report. Reopen it to scan again.

> Installing plugins requires MT Manager VIP, per MT Manager's own plugin documentation. That is MT
> Manager's restriction, not this tool's.

### Reading the result

Each plugin gets a verdict and its findings, worst first, with the file and line the evidence came from.

| Marker | Meaning |
| --- | --- |
| `[ ok]` | Clean, or a version you marked trusted. |
| `[!  ]` | Worth a look. It can do more than it may need. |
| `[!! ]` | Suspicious. Remove it unless you know why it needs this. |
| `[!!!]` | Likely malicious, or on your denylist. Remove it. |
| `[ ? ]` | Could not be read. Judge it by hand. |

### Removing a flagged plugin

**One at a time:** an installed plugin the scan flagged gets a **Quarantine this plugin** switch under
it. Turn it on and reopen the screen. The plugin is moved aside and `restore` puts it back. Nothing
happens while the screen is open, so a switch touched by accident can simply be turned off again.

The switch is deliberately absent in three cases, and each is a refusal rather than an oversight: a
`.mtp` file sitting in a downloads folder is not installed, so there is nothing to move aside; a package
the scan could not hash has no identity to bind the switch to, and the screen will not arm an action it
cannot confirm is still pointing at the same files when it runs; and the scanner will not quarantine
itself. Those are listed with `[ ? ]` or without a switch, and the advice line says to judge them by
hand.

**All of them at once:** type `quarantine malicious` (or `quarantine suspicious` for the wider net).
Nothing is moved yet — the screen comes back listing exactly which plugins it would touch and a short
code:

```
This will quarantine 2 plugin(s): Handy Tools, Theme Pack.
Type "confirm 4f9a" to go ahead, or "cancel" to drop it.
```

Type `confirm 4f9a` and reopen. The code is tied to that exact set of plugins: if anything changed in
between, it is refused rather than applied to a different list than the one you read.

`remove malicious` / `remove suspicious` do the same thing but delete permanently, leaving no
quarantined copy to restore from.

### Actions

There are no buttons available to a plugin, so actions are typed into the **Command** field and run the
next time you open the screen. A half-typed command therefore cannot do anything.

| Command | What it does |
| --- | --- |
| `quarantine malicious` / `quarantine suspicious` | Move every flagged plugin aside, reversibly. Lists them and waits for a confirmation code. |
| `remove malicious` / `remove suspicious` | The same, but permanent. |
| `confirm CODE` / `cancel` | Carry out, or drop, the listed action. |
| `deep` / `fast` | Thorough or quick scanning. Thorough reads more and opens more slowly. |
| `export` | Writes the full text and JSON reports into this plugin's folder. |
| `trust HASH` | Accept a package by its SHA-256. Shown at the bottom of each report. |
| `untrust HASH` / `deny HASH_OR_ID` | Undo a trust decision, or mark something as known bad. |
| `quarantine ID` | Move one installed plugin aside, reversibly. |
| `restore ID` / `purge ID` / `quarantined` | Manage what has been moved. |
| `root PATH` | Also search a folder you name. |

Bulk actions only ever touch **installed** plugins, never an `.mtp` sitting in a downloads folder, and
never this scanner itself.

## Removing a malicious plugin

**Use MT Manager's own plugin management screen to uninstall it.** That is the clean route: MT Manager
keeps its own record of installed plugins, and deleting files from underneath it can leave that record
inconsistent. A plugin cannot call that uninstaller — there is no API for it — so what this one offers
instead is moving a plugin's files out of the way, or deleting them.

`quarantine` exists for what that route does not cover — a plugin that misbehaves on load, or one you
want preserved as evidence before it goes. It moves the plugin's directory into this plugin's own
storage, records where it came from, and can put it back with `restore`. Nothing is deleted until you
run `purge`.

If a plugin was reading private data, treat anything you opened on that device as exposed: change the
passwords and keys involved. Removing the plugin does not undo what it already sent.

## Check an `.mtp` before installing it

```sh
tools/mtsafety suspicious.mtp                 # a package you downloaded
tools/mtsafety --scan-dir /sdcard/Download    # everything in a folder
tools/mtsafety --json plugin-dir/             # machine-readable
```

Exit status is `0` when nothing needs action, `2` when something does, `1` on a usage or read error, so
it drops into a script. It needs only a JDK (9 or newer) — no Android SDK, no device — and runs under
Termux on the phone itself.

## Your own indicator lists

`assets/indicators.json` is copied into the plugin's folder on first run. It holds your trusted hashes,
your denied hashes and plugin ids, and any extra regular expressions you want treated as high severity.

It ships **empty on purpose**. A list of allegedly malicious plugin hashes invented by this tool's
author would be worthless, and one fetched from a server would put a network dependency in the middle of
a security decision. Fill it from sources you trust; share it as a plain file.

## Build and test

```sh
tools/build.sh          # compile, run the tests, package dist/mt-safety-scanner.mtp
tools/build.sh test     # compile and test only
tools/build.sh docs     # regenerate the rule reference from the rule catalogue
```

Requirements: **JDK 9 or newer** and `zip`. (The scripts pass `javac --release 8`, which produces
Java 8 bytecode for MT Manager's on-device compiler but is itself a JDK 9+ flag.) **No Android SDK is needed** — a plugin SDK v2 `.mtp` is a zip of Java
sources that MT Manager compiles on the device. The `javac` run exists to catch errors before the phone
does, using the stubs in `tools/stubs/` to stand in for classes MT Manager provides at runtime. Those
stubs are never shipped inside the `.mtp`.

The test suite uses no test framework, so it builds and runs with nothing but a JDK. It checks both
directions: hostile fixtures must be caught, and benign ones must come back clean. A scanner that flags
everything is as useless as one that flags nothing. `tools/build.sh test` prints the current count.

A block of those checks are regressions: every defect found in review is kept as a test rather than
merely fixed. A scanner that quietly stops catching something is worse than one that never caught it,
because the report still looks reassuring.

## Layout

```
plugin/                     what goes into the .mtp
  manifest.json             MT plugin metadata (pluginSdkVersion 2)
  assets/indicators.json    your trust lists, seeded on first run
  src/mt/safety/scanner/
    core/                   the detection engine: no Android, no MT, no dependencies
    ui/ScannerPreference    the only file that touches an MT Manager type
    ScanRunner, Host        logic and the seam between the two
tools/
  build.sh, mtsafety        build and run
  src/                      command line scanner and the doc generator
  test/                     fixtures and the test suite
  stubs/                    compile-only API stubs, never shipped
docs/DETECTION-RULES.md     generated rule reference
```

The detection engine has no Android and no MT Manager imports. That is what lets the same code run on a
phone and under test on a desktop JVM, and it is why the tests can be this thorough.

## Honest limits

- **Findings are capabilities, not intent.** A flagged plugin can be perfectly honest, and code hidden
  carefully enough can stay quiet. Read the evidence before deleting anything.
- **This targets plugin SDK v2** (`pluginSdkVersion: 2`), the generation whose packages carry Java
  source. MT Manager also has a v3 SDK, built with Gradle, which ships compiled code; the rules still
  run there against recovered strings, but without line numbers.
- **It has not been run on a device by its author.** The engine is covered by the test suite and the
  package layout is verified, but the `bin.mt.plugin.api` signatures come from MT Manager's published
  documentation plus a real third-party plugin's source, not from an install on a phone. If MT Manager
  rejects it, the likely cause is an API difference, and the fix is confined to
  `plugin/src/mt/safety/scanner/ui/ScannerPreference.java` — the only file that mentions an MT type.
  To port to the v3 SDK, change its import and `onBuild` parameter from `MTPluginContext` to
  `PluginContext`; nothing else in the scanner refers to either.
- **Where plugins live on disk is not documented**, and it differs between MT Manager versions and
  between rooted and unrooted devices. Discovery works by content — a folder holding a `manifest.json`,
  or an `.mtp` file — starting from the directory MT Manager hands the plugin itself, which is correct
  whatever the layout. Unreadable locations are skipped. Add one with `root PATH`.
- **The scanner excludes itself.** Its rule catalogue contains every string it searches for, so scanning
  itself would produce a page of findings about the tool doing its job.
- **No signatures.** MT plugin packages are not signed, so there is no publisher to verify. Identity
  rests on the content hash and your own trusted list.
