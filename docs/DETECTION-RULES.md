# Detection rules

Every rule answers one question: **what is this plugin able to do?** That is not the same as what it
intends to do, and the difference matters when you are deciding whether to delete something. A finding
is evidence for you to read, not a conviction.

Two facts about MT plugins set the shape of all of this:

1. A plugin's code runs **inside MT Manager's own process**. MT Manager's documentation says plugins
   "only affect MT Manager, not the system or other applications", and that is a fair statement of
   intent, but nothing in the runtime enforces it: ordinary `java.io.File` and `java.net` calls work,
   with MT Manager's own storage and network access behind them. So a plugin reading `/data/data` or
   opening a socket is worth telling you about.
2. A plugin SDK v2 package ships its **Java source** in `src/`. Most detection therefore reads source
   rather than bytecode, which is why the evidence in a report can point at a file and a line number.
   A v3 package ships compiled code instead, and there the same rules run against strings recovered
   from the compiled members, which is weaker but still useful.

## Severity and score

| Severity | Weight | Meaning |
| --- | --- | --- |
| Info | 0 | Context for you; never affects the verdict. |
| Low | 3 | Normal for some plugins. Only interesting in combination. |
| Medium | 10 | A capability a plugin rarely needs. |
| High | 25 | Hard to justify in a file-manager plugin. |
| Critical | 60 | No benign reading. Enough on its own. |

Verdicts follow from the total, with any Critical finding forcing the worst outcome:

| Verdict | When |
| --- | --- |
| Trusted | The content hash is in your trusted list, and nothing critical was found. |
| Clean | Score under 10. |
| Worth a look | Score 10-24. |
| Suspicious | Score 25-59. |
| Likely malicious | Score 60+, or any critical finding. |
| Known bad | The hash or plugin id is in your denylist. |
| Could not scan | The package could not be read. Judge it by hand. |

## Combinations

Single indicators are weak; combinations are strong. Network access is ordinary, reading another app's
private data is odd, and doing both is exfiltration. These fire across the whole package, because
collection and upload are usually in different files.

| Rule | Severity | What it means |
| --- | --- | --- |
| `CMB101` | Critical | Reads private data **and** has a way to send it out. |
| `CMB102` | Critical | Network access **and** a class loader: it can run code chosen after you installed it. |
| `CMB103` | Critical | Process execution **and** network access: remote control. |
| `CMB104` | High | Destructive behaviour that has been deliberately hidden. |
| `CMB105` | Critical | Clipboard, screen, camera or location capture **and** network access: surveillance. |
| `CMB106` | High | Reaches into MT Manager's own files **and** can reach the network. |
| `CMB107` | High | Capabilities across four or more unrelated areas. |

## When a capability is excused

A translation engine cannot work without reaching the network, so charging it for that would produce a
frightening report about a plugin doing its job, and a scanner that cries wolf gets ignored. When a
package registers a translation interface, ordinary low-severity network findings are recorded as
context (`CTX001`) instead of counted.

The excuse is withdrawn the moment the package does something the trait cannot explain: if it also
reads private data, runs commands or loads code, its network use counts in full. The worked example in
the README is exactly this case.

## Package structure

| Rule | Severity | What it means |
| --- | --- | --- |
| `ARC001` | Critical | A member is named so that it unpacks **outside** the plugin folder (`../`, or an absolute path). Extraction could overwrite MT Manager's own files. |
| `ARC002` | Medium | Members outside the documented layout of `manifest.json`, `icon.*`, `src/`, `assets/`, `libs/`. |
| `ARC003` | High | Carries an installable or executable file: apk, mtp, dex, native library or shell script. Judged by magic bytes against the declared type, so renaming a payload to `.dat` or `.png` does not hide it. No extension is exempt from this check. |
| `ARC004` | High | A member that expands enormously when unpacked. |
| `ARC005` | High | The archive index disagrees with its contents, for example the same member twice. The file a reviewer reads need not be the file that installs. |
| `ARC006` | Low | Hidden or oddly named members. |
| `ARC007` | Medium | A large member whose contents look encrypted or packed rather than like data. |
| `ARC008` | Low | Plugin contents sit inside a wrapping folder, which usually means the package was unpacked and rezipped. |

## Package metadata

| Rule | Severity | What it means |
| --- | --- | --- |
| `MFT001` | High | No `manifest.json`. Not a plugin, or repacked. |
| `MFT002` | High | `manifest.json` is not valid JSON. MT Manager may still accept a manifest your tools cannot read. |
| `MFT003` | Medium | No `pluginID`. |
| `MFT004` | Medium | `pluginID` uses characters outside the documented letters, numbers, underscores and dots. |
| `MFT005` | Low | Unrecognised `pluginSdkVersion`. May simply be newer than this scanner. |
| `MFT006` | Medium | A declared entry point is not present in the package. |
| `MFT007` | Medium | Ships code but declares no entry point. Undeclared code is code nobody reviews. |
| `MFT008` | Medium | Claims to be "official" or "verified". MT Manager does not certify plugins. |
| `MFT009` | High | Zero-width or direction-changing characters in the name or id, so the name you see is not the real one. |
| `MFT010` | Low | Unusually long description, which can push meaningful text out of view. |
| `MFT011` | High | Near-identical to another installed plugin, after folding case, separators and lookalike characters. One may be impersonating the other. Two packages claiming exactly the same identity count too: that is the strongest form of it, not a reason to stay quiet. |
| `MFT012` | Low | `manifest.json` is present but was not read, through an I/O error or an exhausted budget. Nothing in the report rests on what the plugin declares. This is a limit of the scan, not a finding against the package, and is kept separate from `MFT002` for that reason. |

`MFT011` compares the plugins **you actually have** rather than checking against a shipped list of
known-good names. A built-in list would go stale, and a wrong entry would be worse than none.

## Provenance and your own lists

| Rule | Severity | What it means |
| --- | --- | --- |
| `PRV001` | Critical | Matches an entry in your denylist. |
| `USR001` | High | Matches a regular expression from your own indicator file. |
| `CTX001` | Info | A capability was excused because the plugin's declared purpose requires it. |
| `SCN001` | Info | The scan did not read the whole package, so absence of findings proves less than usual. |

No hashes ship with this tool. A list of allegedly malicious plugin hashes invented by its author would
be worthless, and one fetched from a server would put a network dependency in the middle of a security
decision. `assets/indicators.json` is an empty, documented template you fill from sources you trust.

## Code and content patterns

These run against Java sources, plain-text members, and strings recovered from compiled members. Each
regular expression matches both the source spelling (`Runtime.getRuntime`) and the form that survives
in a compiled constant pool (`Ljava/lang/Runtime;`).

No member is exempt on the strength of its name or its first few bytes, media included. Image decoders
tolerate trailing junk, so a genuine PNG header followed by an appended payload would satisfy any
magic-byte check and then bypass every rule below it. Binary members are searched for printable runs
rather than decoded whole, so real image data contributes nothing to match against; a package that
ships enough media to exhaust the byte allowance is reported as truncated rather than as clean.

| Rule | Severity | Category | What it means |
| --- | --- | --- | --- |
| `EXE001` | High | Shell and root commands | **Runs operating system commands.** The plugin starts external processes. A plugin that only extends MT Manager's own features has no reason to shell out. |
| `EXE002` | High | Shell and root commands | **Asks for root privileges.** References the su binary or a root manager. With root, anything the plugin does is unrestricted by Android's app sandbox. |
| `EXE003` | High | Shell and root commands | **Drives the Android package manager.** Installs, removes or re-permissions apps from the command line. |
| `EXE004` | Medium | Shell and root commands | **Changes file permissions or mounts.** Alters permissions or remounts filesystems, usually to make a protected area writable. |
| `EXE005` | Medium | Shell and root commands | **Reads or sets system properties.** Uses setprop/getprop or service controls, which are system administration, not plugin work. |
| `DYN001` | High | Loading code from outside the package | **Loads code that is not in this package.** Uses a class loader to run code from a file or download. Anything reviewed here can be replaced at runtime by code nobody has seen. |
| `DYN002` | High | Loading code from outside the package | **Loads a native library.** MT plugins are Java only. Loading a .so means native code the scanner cannot read. |
| `DYN003` | Medium | Loading code from outside the package | **Uses reflection.** Reflection is common in plugins, but it is also how code reaches APIs it was not given. |
| `DYN004` | High | Loading code from outside the package | **Reaches for MT Manager's application context.** The plugin API deliberately hands out no Android Context. Obtaining one gives the plugin MT Manager's full app identity and permissions. |
| `DYN005` | High | Loading code from outside the package | **Compiles or evaluates code on the fly.** Ships a compiler or script engine, so its real behaviour is decided at runtime. |
| `NET001` | Low | Network access | **Makes network requests.** Expected for a translation engine or an update check; listed so you know it talks to the network at all. |
| `NET002` | Medium | Network access | **Contacts a hardcoded IP address.** Real services are reached by hostname. A bare address, whether in a URL or handed straight to a socket, is typical of a private collection server. |
| `NET003` | High | Network access | **Sends data to an anonymous drop or bot endpoint.** These endpoints exist to receive data without an identifiable owner. They are how stolen data usually leaves a device. |
| `NET004` | Medium | Network access | **Uses a tunnel, dynamic DNS or shortened address.** Hides where the traffic actually goes, and lets the operator move the server at will. |
| `NET005` | Low | Network access | **Transfers over plain HTTP.** Unencrypted transport, so anything sent is readable on the network path. |
| `NET006` | Medium | Network access | **Uploads file bodies.** Builds multipart or raw file uploads, which is how bulk data is shipped off a device. |
| `SEN001` | High | Access to private or credential data | **Reads app-private storage paths.** Paths under /data/data or /data/user hold other apps' private files, including MT Manager's own. A plugin has no business there. |
| `SEN002` | High | Access to private or credential data | **Looks for key, wallet or seed material.** Searches for the exact artefacts used to take over accounts and crypto wallets. |
| `SEN003` | Medium | Access to private or credential data | **Handles stored credentials or session tokens.** A plugin needing its own API key is normal; reaching for saved passwords, cookies or session tokens is not. |
| `SEN004` | High | Access to private or credential data | **Reads other applications' data folders.** Targets messaging and social app storage, which holds private conversations and media. |
| `SEN005` | Medium | Access to private or credential data | **Reads contacts, messages or call history.** Personal data with no connection to editing files or translating text. |
| `SEN006` | Low | Access to private or credential data | **Walks shared media folders.** Ordinary for a file tool, worth noting only if the plugin also sends data out. |
| `IDN001` | Medium | Device and user identifiers | **Collects device identifiers.** Builds a durable fingerprint of the device or SIM, used to track a victim across installs. |
| `IDN002` | Low | Device and user identifiers | **Enumerates installed applications.** Inventories what else is on the device. |
| `XPL001` | High | Reaching into MT Manager or other plugins | **Reads or writes MT Manager's own files.** Hardcodes a path into MT Manager's private storage. That reaches MT's settings, licence state and every other installed plugin. (A class merely named under bin.mt.plugin is not this: that is the namespace plugin authors use.) |
| `XPL002` | High | Reaching into MT Manager or other plugins | **Escapes its own plugin directory.** Walks up out of the directory MT Manager gave it, which is where other plugins live. |
| `DES001` | High | Deleting or encrypting user files | **Deletes files in bulk.** Recursive deletion. In a plugin you did not ask to clean anything, this is a wiper. |
| `DES002` | Critical | Deleting or encrypting user files | **Contains extortion text.** Ransom wording. There is no benign reason for this in a file-manager plugin. |
| `DES003` | Medium | Deleting or encrypting user files | **Overwrites file contents in place.** Rewrites or truncates existing files rather than creating new ones. |
| `OBF001` | Medium | Hidden or encoded payloads | **Decrypts or unscrambles strings at runtime.** Hides what the code actually references. Legitimate plugins rarely need to. |
| `OBF002` | Medium | Hidden or encoded payloads | **Embeds a long encoded blob.** A large Base64 or hex blob in source is usually a payload rather than data. |
| `OBF003` | High | Hidden or encoded payloads | **Uses bidirectional or invisible Unicode in source.** Characters that make the code a reviewer reads differ from the code that runs (a Trojan Source trick). |
| `OBF004` | Low | Hidden or encoded payloads | **Decodes Base64 at runtime.** Common and usually harmless; only interesting next to a large embedded blob. |
| `EVA001` | Medium | Anti-analysis behaviour | **Checks whether it is being analysed.** Looks for an emulator, debugger or root, typically to behave differently while watched. |
| `EVA002` | Medium | Anti-analysis behaviour | **Defers its work on a long timer.** Long sleeps and schedulers delay behaviour past the moment you would be watching. |
| `PER001` | Medium | Writing installable or executable files | **Names installable or executable files.** Mentions apk, dex, mtp or so files. Meaningful when the plugin also writes files. |
| `PER002` | High | Writing installable or executable files | **Triggers an application install.** Hands Android a package to install, which is how a plugin becomes a permanent app. |
| `REC001` | High | Screen, clipboard and accessibility capture | **Reads the clipboard.** The clipboard is where passwords, recovery phrases and one-time codes pass through. |
| `REC002` | High | Screen, clipboard and accessibility capture | **Captures the screen.** Screen capture records whatever you are looking at, including other apps. |
| `REC003` | High | Screen, clipboard and accessibility capture | **Uses accessibility automation.** Accessibility APIs can read and tap any screen. This is the standard route for Android banking fraud. |
| `REC004` | Medium | Screen, clipboard and accessibility capture | **Uses the microphone or camera.** Audio or image capture from a plugin that should only touch files. |
| `REC005` | Medium | Screen, clipboard and accessibility capture | **Reads device location.** Location has no role in editing files. |

### Same-file combinations

| Rule | Severity | Category | What it means |
| --- | --- | --- | --- |
| `CMB001` | High | Writing installable or executable files | **Writes an installable or executable file.** The same file both opens an output stream and names an apk, dex, mtp or so file: it drops a payload onto storage. |
| `CMB002` | Critical | Loading code from outside the package | **Downloads code and loads it.** Network access and a class loader in one file. Whatever this plugin does today, its operator can change tomorrow. |
| `CMB003` | Critical | Shell and root commands | **Runs shell commands on instructions from the network.** Process execution and network access in one file, the shape of a remote control channel. |
| `CMB004` | Critical | Deleting or encrypting user files | **Encrypts files and then deletes the originals.** Encryption together with bulk deletion in one file is the ransomware pattern. |
| `CMB005` | High | Hidden or encoded payloads | **Decodes a hidden blob and runs or loads it.** Decoding feeding straight into execution or class loading hides the real payload from review. |

## Encoded payloads

Long Base64 runs are decoded and examined, one level deep:

- Decoding to a zip, apk, mtp, dex, native binary or Java class file is `OBF005`, **critical**. This
  is how a plugin passes a read-through looking harmless and then runs something else.
- Decoding to text that itself trips a medium-or-worse rule is `OBF006`, **high**: something the
  plugin would rather you did not read is stored encoded.

## Acting on what is found

Findings are only useful if something can be done with them, and the settings screen has no buttons, so
acting happens through real controls. Every plugin the scan flagged, "worth a look" included, gets a
"Select for removal" switch, which only marks it. An "Uninstall selected, quarantined and malicious"
button then deletes everything selected, everything malicious and anything already in quarantine, after
confirming in a dialog that lists exactly what it will delete; a "Quarantine all flagged" button is the
reversible version of the same sweep. Before it moves anything the scanner re-reads each package and
refuses if it changed since the scan. The same actions are available as typed commands
(`quarantine-all`, `quarantine malicious`, `remove suspicious`, ...) for anyone who prefers them.

A control appears only where it can be honoured: not for a `.mtp` file in a downloads folder, which is
not installed; not for a package the scan could not hash, because the action is bound to the contents it
was confirmed against and there is nothing to bind it to; and not for the scanner itself. Those findings
are reported without a control and have to be judged by hand.

A bulk action never runs when it is typed. It lists the plugins it would touch and issues a short code
derived from that exact set; only `confirm CODE` carries it out, and only while the set is unchanged. A
code that no longer matches the installed plugins is refused rather than applied to a different list
than the one that was read. Bulk actions cover installed plugins only, never a package file sitting in a
downloads folder, and never the scanner itself.

Quarantine moves a plugin into the scanner's own storage and records where it came from, so `restore`
puts it back; `remove` deletes it outright. MT Manager's own plugin management screen remains the clean
way to uninstall, since it keeps the record of what is installed, and no plugin can call that
uninstaller.

## Known limits

- **Heuristics, not proof.** Rules describe capability. A flagged plugin can be entirely honest, and
  sufficiently careful code can stay quiet. Read the evidence.
- **Obfuscation beyond one layer.** Decoding goes one level deep. A payload encrypted with a key
  computed at runtime will show up as `OBF001`/`ARC007`, without the scanner knowing what it contains.
- **Compiled packages read less well.** A v3 package ships compiled code, so findings there rest on
  recovered strings and carry no line numbers.
- **No signature checking.** MT plugin packages are not signed, so there is no publisher to verify.
  Identity rests on the content hash and on your own trusted list.
- **The scanner skips itself.** Its catalogue contains every string it searches for, so scanning itself
  would produce a page of findings about the tool doing its job. Use `--include-self` on the command
  line to override this.
