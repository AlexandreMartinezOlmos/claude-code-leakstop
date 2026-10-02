# Changelog

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
