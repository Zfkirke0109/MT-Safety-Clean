# MT Safety Scanner — Copilot research handoff staging

This branch contains **onboarding instructions only**, not the complete security review and not the implementation of PR 0. It does not modify Java, scanner behavior, Android configuration, or release artifacts.

## Attach and stage the full package

1. Attach `MT-Safety-Scanner-Final-Copilot-Handoff.zip` to the draft PR conversation from GitHub in Android Chrome (use Desktop site if needed).
2. **Do not assume Copilot can inspect ZIP attachments.** Extract the archive on your device or computer. Copy its current `COPILOT-IMPLEMENTATION-MASTER.md`, `FINAL-ADVERSARIAL-FACT-CHECK.md`, `MT-SAFETY-SCANNER-DEEP-RESEARCH.md`, `architecture/`, `evidence/`, `prompts/`, `testing/`, and `ISSUES-PR-ROADMAP.md` into the Copilot-accessible branch or workspace, preserving paths. Check for collisions before copying `AGENTS.md` and `.github/copilot-instructions.md`; the onboarding branch already provides compatible guardrails.
3. Do not commit duplicate historical PDFs or prior packages unless specifically desired; `historical/` files can stay in the ZIP as a separate archive reference.
4. If using a PR comment, paste the contents of `COPILOT-KICKOFF-PROMPT.md` with an explicit `@copilot` mention where GitHub Copilot Coding Agent is enabled. **Only start after the required extracted Markdown files are accessible in Copilot's checkout.** If Copilot can only work from an issue, create a scoped issue for PR 0 and assign it to Copilot.
5. Open a **new implementation PR 0** based on the accepted instructions; the onboarding PR does not itself count as the baseline-test PR.
6. Await human review of PR 0 before implementing later changes.

Repository source facts at handoff: SDK v3 `.mtp`, Java 8 `tools/build.sh`, D8, minimum Android API 24, rootless operation. Baseline reference: `90de1e15ef4ce9ad20e272a64daa52b4ed56a189`. Reverify against current `main`.

The ZIP's `SHA256SUMS.txt` verifies its extracted contents; it is not a publisher-authenticity proof. **Build, tests, CI, device validation, installation, and release are NOT performed by this onboarding PR.**
