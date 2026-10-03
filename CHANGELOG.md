# Changelog

## Unreleased

- Outbound tools are watched. A secret in what `WebFetch`, `WebSearch`, `Agent`, `SendMessage`, `SendFile`, `Artifact`, `ArtifactData`, `ArtifactComments`, `PushNotification`, `SendFeedback`, `RemoteTrigger` or any MCP tool is about to send away is held (a weaker finding warns, and `strict` holds it), with a question that says where it would go and a message to Claude that says what to do instead. `SendFile` and `Artifact` also send local files: those are read and scanned, and a sensitive file (`.env`, keys, credentials) is held outright. In `monitor` mode it only warns, and an internal failure denies in `standard` and `strict`.

- `/leakstop allowed` lists what is allowed (this session, for good, `.leakstop.json`) with the fingerprint and, when known, the type and place of each; `/leakstop forget <number or sha256:…>` and `/leakstop forget all` take back what you allowed; `/leakstop reload` reads `.leakstop.json` again without restarting. `forget` and `reload` only work when you type them.
- A command name written with quotes or a backslash (`\grep`, `"grep"`) is no longer assumed to be Claude Code's `.gitignore`-aware `grep`, so a recursive search written that way is held when it would reach a sensitive file.

## 0.1.1

- A recursive `grep` or `rg` over a folder that holds sensitive files (`.env`, keys, credentials) is now held when the search would really reach them. Claude Code's own `grep` and `rg` honour `.gitignore`, so a plain `grep -r KEY .` no longer asks because of an ignored `.env`; `command grep`, `/usr/bin/grep`, `egrep`, `rg --no-ignore` and `rg -uu` still do. Excluding those files (`--exclude`, `-g '!…'`), limiting the search (`--include`) or listing only names (`-l`, `-c`) keeps it quiet.
- The message Claude reads after a denial now says what you did: Cancel ("do not retry"), Use environment variable or Add to .gitignore ("do it now"), or your own words when you type an answer. Before, all of them read the same and Claude asked you again.
- Denying a read of `.env` now tells Claude it can append a variable with `echo 'NAME=value' >> .env`.
- `sed -i` and `tee … > /dev/null` that write a secret into a file git ignores (such as `.env`) now pass, like `echo >> .env` already did.
- `/leakstop` no longer leaves a stray empty line in the transcript when it opens the panel, and in the VS Code chat panel (where nothing can be drawn) it now prints the history as text instead of nothing.
- A weaker finding that only warns is now labelled `warned` in the panel and the banner, not `allowed`.
- Text inside a quoted heredoc (`<<'EOF'`), such as a note that mentions `$(…)` or backticks, is no longer read as a command substitution; an unquoted heredoc, which the shell does expand, still is.
- `printf "$KEY" > file` (and `echo`) no longer counts as printing the variable: its output goes to the file. Reading that file back in the same command still does.

## 0.1.0

First release. Requires Claude Code 2.1.287 or later.

- Holds or blocks secrets before Claude writes them: private keys, provider tokens (AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, Google, npm, Hugging Face), credentials in URLs, JWTs and hard-coded passwords, in `Write`, `Edit` and `NotebookEdit`.
- Watches shell commands: literal secrets in a command, printing sensitive files or the environment (with a names-only alternative), `git add` of sensitive files, and `git commit` / `git push` that would publish a secret.
- Holds reads of sensitive files (blocked in `strict` mode).
- Warning banner above the prompt, history panel and the `/leakstop` command (`pause`, `resume`, `allow`).
- Three protection levels: `monitor`, `standard`, `strict`.
- Per-project `.leakstop.json` with `ignorePaths`, `allowFingerprints` and `customRules`; treated as untrusted and bounded in cost.
- No network, no model calls and no environment reads.

Not in this release: redacting secrets pasted into the prompt, and redacting the result of a read.
