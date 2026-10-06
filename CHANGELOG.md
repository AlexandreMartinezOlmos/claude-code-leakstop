# Changelog

All notable changes to LeakStop. It follows [semantic versioning](https://semver.org); see "Stability and versioning" in the README for what is part of the public interface.

## 1.1.0 - 2026-10-06

LeakStop now also keeps secrets out of what tools return and out of your own messages. Requires Claude Code 2.1.287 or later, as before.

- **Masks secrets in what tools return.** A secret printed by a command, found in a file Claude reads or returned by an MCP tool now reaches neither Claude nor the session's transcript: LeakStop replaces it with its masked form and tells Claude. That includes the copy of a large command output that Claude Code saves to disk. Real secrets are masked in `standard` mode, weaker signals too in `strict`; `monitor` only reports.
- **Masks secrets pasted into your messages**, the same way. Claude Code's prompt history keeps what you typed.
- **Holds sensitive files printed from git history or through `find`:** `git show HEAD:.env`, `git cat-file -p`, `git log -p -- .env`, `git blame`, and `find … -exec cat` or `| xargs cat` on a sensitive file.
- **Asks before an MCP tool that names `.leakstop.json` runs**, as it already did for the file and shell tools.
- **New `statusLine` option** (off by default): a line under the prompt says LeakStop is on, or paused. When it is missing, nothing is protecting the session.
- **A `Write` that would put a masked value over the real one is denied.** After a masked read Claude only has the masked form; writing the file back from it would lose the real value.
- The tests moved out of the plugin folder, so they are no longer installed with it; `node scripts/test.ts` runs them.
- The icon has rounded corners.

## 1.0.2 - 2026-10-04

Documentation only. No change to what LeakStop detects or how it decides.

- The plugin folder now has its own `README.md`, so the installed plugin ships a description of what it does, its protection levels and its privacy, and Anthropic's directory can read it.
- The plugin README now says what the mod runs (`git` and `find`, read-only), that it sends nothing anywhere, which hooks it uses and the one case in which it rewrites a command (**Show names only**), as the directory asks. It also explains that the test files and the detector only contain fake credentials and patterns to look for, which the directory's scan reads as a credential going to a server.
- `userConfig.mode` no longer lists its `options` in the manifest, because Anthropic's directory does not accept that key yet. Nothing changes in behaviour: any value other than `monitor` or `strict` already meant `standard`, and the description names the three values.
- Added the plugin icon (`.claude-plugin/icon.png`).
- A test no longer spells out a command that downloads and runs something, which the directory flags as an install-time risk.
- `scripts/check-release.ts` checks that this README exists, has enough text and states the same minimum Claude Code version.

## 1.0.1 - 2026-10-04

Documentation only. No change to what LeakStop detects or how it decides.

- The README now opens with a recording of a real Claude Code session: LeakStop holds a read of `.env`, the choice is Cancel, and `/leakstop` lists the finding.
- Added an icon (`assets/icon.svg` and a 512 pixel PNG) and a 1280x640 social preview image in `assets/`.

## 1.0.0 - 2026-10-04

First stable release. Requires Claude Code 2.1.287 or later.

- The public interface is now stable within 1.x: the `/leakstop` subcommands, the `mode` option, the fields of `.leakstop.json` and the install id `leakstop@leakstop` will not change in a breaking way. The README says exactly what is covered.
- A new README: installation inside Claude Code, from the terminal, for a team (project scope) and for an organisation; updating and uninstalling; a one-minute way to see it work; the list of sensitive files; troubleshooting.
- `/leakstop list` is documented as the other name of `/leakstop allowed`.
- Added `SECURITY.md` (how to report a vulnerability and what counts as one), `PRIVACY.md` (what LeakStop keeps and where), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue forms and a pull request template.
- Every change is now checked by CI: the plugin validation with `--strict`, the marketplace validation and the test suite, on Linux and macOS, with Claude Code 2.1.287 (the oldest supported) and the newest; plus a check that the version, the changelog, the licence and the descriptions agree and that no secret is in the repository.
- The manifest now carries the metadata that Anthropic's directory reads (display name, keywords, documentation, support and privacy links), and the installed plugin ships its own copy of the licence.
- `scripts/calibrate.ts` accepts `--check`, which makes it exit with an error when it flags anything.

No change to what LeakStop detects or how it decides.

## 0.2.0 - 2026-10-04

- Outbound tools are watched. A secret in what `WebFetch`, `WebSearch`, `Agent`, `SendMessage`, `SendFile`, `Artifact`, `ArtifactData`, `ArtifactComments`, `PushNotification`, `SendFeedback`, `RemoteTrigger` or any MCP tool is about to send away is held (a weaker finding warns, and `strict` holds it), with a question that says where it would go and a message to Claude that says what to do instead. `SendFile` and `Artifact` also send local files: those are read and scanned, and a sensitive file (`.env`, keys, credentials) is held outright. In `monitor` mode it only warns, and an internal failure denies in `standard` and `strict`.
- `/leakstop allowed` lists what is allowed (this session, for good, `.leakstop.json`) with the fingerprint and, when known, the type and place of each; `/leakstop forget <number or sha256:…>` and `/leakstop forget all` take back what you allowed; `/leakstop reload` reads `.leakstop.json` again without restarting. `forget` and `reload` only work when you type them.
- In the VS Code chat panel the hold question reads as one line with dashes between its parts, because that panel runs line breaks together into one paragraph. The terminal and the desktop app keep the multi-line question.
- The warning banner now stays until you send your next message. Before, a background agent finishing (or a peer session, a schedule or another plugin) cleared it, so a warning raised by an `Agent` call vanished in seconds.
- A command name written with quotes or a backslash (`\grep`, `"grep"`) is no longer assumed to be Claude Code's `.gitignore`-aware `grep`, so a recursive search written that way is held when it would reach a sensitive file.

## 0.1.1 - 2026-10-04

- A recursive `grep` or `rg` over a folder that holds sensitive files (`.env`, keys, credentials) is now held when the search would really reach them. Claude Code's own `grep` and `rg` honour `.gitignore`, so a plain `grep -r KEY .` no longer asks because of an ignored `.env`; `command grep`, `/usr/bin/grep`, `egrep`, `rg --no-ignore` and `rg -uu` still do. Excluding those files (`--exclude`, `-g '!…'`), limiting the search (`--include`) or listing only names (`-l`, `-c`) keeps it quiet.
- The message Claude reads after a denial now says what you did: Cancel ("do not retry"), Use environment variable or Add to .gitignore ("do it now"), or your own words when you type an answer. Before, all of them read the same and Claude asked you again.
- Denying a read of `.env` now tells Claude it can append a variable with `echo 'NAME=value' >> .env`.
- `sed -i` and `tee … > /dev/null` that write a secret into a file git ignores (such as `.env`) now pass, like `echo >> .env` already did.
- `/leakstop` no longer leaves a stray empty line in the transcript when it opens the panel, and in the VS Code chat panel (where nothing can be drawn) it now prints the history as text instead of nothing.
- A weaker finding that only warns is now labelled `warned` in the panel and the banner, not `allowed`.
- Text inside a quoted heredoc (`<<'EOF'`), such as a note that mentions `$(…)` or backticks, is no longer read as a command substitution; an unquoted heredoc, which the shell does expand, still is.
- `printf "$KEY" > file` (and `echo`) no longer counts as printing the variable: its output goes to the file. Reading that file back in the same command still does.

## 0.1.0 - 2026-10-02

First release. Requires Claude Code 2.1.287 or later.

- Holds or blocks secrets before Claude writes them: private keys, provider tokens (AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, Google, npm, Hugging Face), credentials in URLs, JWTs and hard-coded passwords, in `Write`, `Edit` and `NotebookEdit`.
- Watches shell commands: literal secrets in a command, printing sensitive files or the environment (with a names-only alternative), `git add` of sensitive files, and `git commit` / `git push` that would publish a secret.
- Holds reads of sensitive files (blocked in `strict` mode).
- Warning banner above the prompt, history panel and the `/leakstop` command (`pause`, `resume`, `allow`).
- Three protection levels: `monitor`, `standard`, `strict`.
- Per-project `.leakstop.json` with `ignorePaths`, `allowFingerprints` and `customRules`; treated as untrusted and bounded in cost.
- No network, no model calls and no environment reads.

Not in this release: redacting secrets pasted into the prompt, and redacting the result of a read.

[Unreleased]: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/compare/v1.1.0...develop
[1.1.0]: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/releases/tag/v0.1.0
