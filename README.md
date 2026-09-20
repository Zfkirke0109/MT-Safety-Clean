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

1. Download `dist/mt-safety-scanner.mtp` from this repository (or build it with `tools/build.sh`). It
   is a plugin SDK v3 package: install it in MT Manager 2.26.3 or newer.
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

**Pick and uninstall:** every plugin the scan flagged — "worth a look" included — gets a **Select for
removal** switch under it. Turning one on does nothing by itself; it only marks the plugin. The
**Uninstall selected, quarantined and malicious (N)** button at the top then deletes, in one go,
everything you selected, everything the scan called malicious, and anything already sitting in
quarantine. It confirms in a dialog listing exactly what it will delete, and before it touches
anything it re-reads each package and refuses if it changed since the scan.

Deleting is permanent. **Quarantine all flagged (N)** is the reversible version: it moves the same set
aside so `restore` can put it back.

The switch is deliberately absent in three cases, and each is a refusal rather than an oversight: a
`.mtp` file sitting in a downloads folder is not installed, so there is nothing to move aside; a package
the scan could not hash has no identity to bind the action to, so the screen will not act on something
it cannot confirm is still the package it examined; and the scanner will not quarantine itself. Those
are listed with `[ ? ]` or without a switch, and the advice line says to judge them by hand.

**By typed command (the same actions, without the dialogs):** type `quarantine-all` to sweep
everything flagged, or `quarantine malicious` / `quarantine suspicious` for the narrower sets.
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

## Where the detection comes from

There is no threat-intelligence feed behind this, and no vendor database. Detection is two things,
and they are deliberately kept apart because they age and update differently.

**1. The rule catalogue** — 47 rules, written and reviewed in
[`CodePatterns.java`](plugin/src/mt/safety/scanner/core/CodePatterns.java). Each one is a regular
expression, a severity, a title and a paragraph explaining why it is there, in a plain text file you
can read in a browser. They are **capability rules, not malware signatures**: they answer "what is
this plugin able to do", which is why the scanner works on a plugin nobody has ever seen before and
why it can point at a file, a line and the matched snippet as evidence. Nothing is hashed, hidden or
compiled into an opaque blob, and [`docs/DETECTION-RULES.md`](docs/DETECTION-RULES.md) is generated
*from* the catalogue by the build, so the published reference cannot drift from what actually runs.

The catalogue carries a version and a date. Both are shown under **About** on the scanner screen, at
the top of every exported report, and in the JSON export, so a report can always be read against the
rules that produced it. Type `definitions` to see them with the age in days. The catalogue is compiled
into the plugin, so it updates when you install a new build — there is no separate definition
download.

**2. Your indicator file** — `assets/indicators.json`, copied into the plugin's folder on first run.
It holds your trusted hashes, your denied hashes and plugin ids, and any extra regular expressions you
want treated as high severity, plus `version`, `updated` and `source` describing where the list came
from. The scanner shows those and how many days old the file is.

It ships **empty on purpose**. A list of allegedly malicious plugin hashes invented by this tool's
author would be worthless, and one fetched from a server would put a network dependency in the middle
of a security decision — in a tool whose whole job is reporting other plugins for having exactly that
capability. So updating it is deliberate: obtain a list from a source you trust and fold it in with

```
import /sdcard/Download/plugin-iocs.json
```

which merges rather than replaces (your own trust decisions survive), adopts the newer list's version
and date, and tells you how many entries were added. Re-importing the same list adds nothing.

**This scanner makes no network connections at all** — not for definitions, not for telemetry, not for
anything. You can verify that: `grep -rn "java.net\|URLConnection\|Socket" plugin/src/` returns only
the rule catalogue's own search strings.

## Build and test

```sh
tools/build.sh          # compile, run the tests, package dist/mt-safety-scanner.mtp
tools/build.sh test     # compile and test only
tools/build.sh docs     # regenerate the rule reference from the rule catalogue
```

Requirements for `test`: **JDK 9 or newer** and `zip`, nothing else. The detection core is plain Java
with no Android or MT types, so it compiles and runs on a desktop JVM; `tools/build.sh test` is the
build a contributor runs.

`package` builds a plugin SDK **v3** `.mtp`, whose code ships as a compiled `classes.dex`. That step
additionally downloads, and caches under the build directory, an Android platform jar, a stable
`r8`/`d8` dexer (Google Maven `com.android.tools:r8`, pinned; the dexer bundled with build-tools r34
crashes on JDK-21-compiled classes) and MT Manager's published plugin API (`bin.mt.plugin:api`, used
compile-only and never shipped). It compiles the core plus the one UI file against those, dexes the
result, and zips `manifest.json` + `classes.dex` + `assets/` + `icon.png`.

The test suite uses no test framework, so it builds and runs with nothing but a JDK. It checks both
directions: hostile fixtures must be caught, and benign ones must come back clean. A scanner that flags
everything is as useless as one that flags nothing. `tools/build.sh test` prints the current count.

A block of those checks are regressions: every defect found in review is kept as a test rather than
merely fixed. A scanner that quietly stops catching something is worse than one that never caught it,
because the report still looks reassuring.

## Layout

```
plugin/                     what goes into the .mtp
  manifest.json             MT plugin metadata (pluginSdkVersion 3, dexMode)
  assets/indicators.json    your trust lists, seeded on first run
  icon.png                  the plugin's icon
  src/mt/safety/scanner/
    core/                   the detection engine: no Android, no MT, no dependencies
    ScanRunner, Host        logic and the seam to the UI
  ui-v3/...ScannerPreference the v3 UI (buttons + dialogs); the only file that touches an MT type
tools/
  build.sh, mtsafety        build and run
  src/                      command line scanner and the doc generator
  test/                     fixtures and the test suite
docs/DETECTION-RULES.md     generated rule reference
```

The detection engine has no Android and no MT Manager imports. That is what lets the same code run on a
phone and under test on a desktop JVM, and it is why the tests can be this thorough.

## Honest limits

- **Findings are capabilities, not intent.** A flagged plugin can be perfectly honest, and code hidden
  carefully enough can stay quiet. Read the evidence before deleting anything.
- **This ships as plugin SDK v3** (`pluginSdkVersion: 3`, `dexMode: true`), whose package carries a
  compiled `classes.dex` and needs MT Manager 2.26.3 or newer. It still *scans* both generations: a v2
  package's Java sources and a v3 package's dex are read the same way, and for a v3 package the class a
  manifest declares is confirmed exactly against the dex string table rather than guessed from file
  names.
- **It has not been run on a device by its author.** The engine is covered by the test suite and the
  package layout is verified, but the `bin.mt.plugin.api` signatures come from MT Manager's published
  API (`bin.mt.plugin:api:3.0.0`, downloaded from MT Manager's own Maven) and a real third-party
  plugin's source, not from an install on a phone. If MT Manager rejects it, the likely cause is an API
  difference, and the fix is confined to `plugin/ui-v3/mt/safety/scanner/ui/ScannerPreference.java` —
  the only file that mentions an MT type. The entire detection core underneath it is plain Java,
  shared with the command-line scanner and covered by the desktop test suite.
- **Where plugins live on disk is not documented**, and it differs between MT Manager versions and
  between rooted and unrooted devices. Discovery works by content — a folder holding a `manifest.json`,
  or an `.mtp` file — starting from the directory MT Manager hands the plugin itself, which is correct
  whatever the layout. Unreadable locations are skipped. Add one with `root PATH`.
- **The scanner excludes itself.** Its rule catalogue contains every string it searches for, so scanning
  itself would produce a page of findings about the tool doing its job.
- **No signatures.** MT plugin packages are not signed, so there is no publisher to verify. Identity
  rests on the content hash and your own trusted list.
