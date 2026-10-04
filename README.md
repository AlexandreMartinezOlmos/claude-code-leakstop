# LeakStop

[![CI](https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AlexandreMartinezOlmos/claude-code-leakstop)](https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Stops Claude Code from leaking secrets before it does.**

When an AI agent works in your terminal it can, without meaning to, copy an API key from `.env` into your code, print your whole environment into the conversation, or `git add .` a private key. LeakStop watches what Claude is *about to do* and steps in **before** it happens: it asks you, or blocks the action, and tells Claude how to do it safely (for example, "read the key from an environment variable instead").

It runs entirely on your machine. No network, no AI model, no accounts. It never reads your environment variables, and it never shows or stores a full secret: only a short prefix and the last three characters.

![A recording of Claude Code asked to show .env: LeakStop holds the read, the user chooses Cancel, Claude explains it did not read the file, and /leakstop lists the finding.](assets/demo.gif)

That is a real session: Claude is asked to show a `.env` file, LeakStop holds the read, and the choice is **Cancel**. A write that would put a secret into your code looks like this:

```
LeakStop · CRITICAL
Anthropic API key in Write → src/config.ts:12
  sk-ant-••••••3fA
This file is not ignored by git, so the secret would end up in the repository.

How do you want to handle it?

  1. Use environment variable
  2. Allow once
  3. Cancel
```

- [Install](#install)
- [Try it in one minute](#try-it-in-one-minute)
- [Using it](#using-it)
- [Protection level](#protection-level)
- [Per-project settings](#per-project-settings-optional)
- [How you can trust it](#how-you-can-trust-it)
- [Stability and versioning](#stability-and-versioning)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

## Install

You need **Claude Code 2.1.287 or later** (check with `claude --version`). LeakStop is a Claude Code *mod*, a kind of plugin that is on by default from that version. Every change is tested against the oldest supported version and the newest one.

### Inside Claude Code

Run these three commands:

```
/plugin marketplace add AlexandreMartinezOlmos/claude-code-leakstop
/plugin install leakstop@leakstop
/reload-plugins
```

### From your terminal

```
claude plugin marketplace add AlexandreMartinezOlmos/claude-code-leakstop
claude plugin install leakstop@leakstop
```

Then start Claude Code (or run `/reload-plugins` in a session that is already open).

### Check that it is on

Open `/plugin`: LeakStop should be listed as active. Then run `/leakstop`: it opens a panel with this session's findings (empty at first). If LeakStop is ever missing from `/plugin`, nothing is protecting you (see [Limitations](#limitations)).

After installing you may see a note that "1 userConfig option is not yet set". That is fine: until you choose a [protection level](#protection-level), LeakStop runs in `standard` mode.

### Update

Third-party marketplaces do not update on their own by default. To get a new version:

```
claude plugin marketplace update leakstop
claude plugin update leakstop@leakstop
```

and restart Claude Code. To make it automatic, open `/plugin`, go to **Marketplaces**, select `leakstop` and choose **Enable auto-update**. The [changelog](CHANGELOG.md) lists what each version changes.

### Uninstall

```
claude plugin uninstall leakstop@leakstop
```

The marketplace stays registered until you run `claude plugin marketplace remove leakstop`.

### For a team

To give everyone who works in one repository the same protection, run this once inside it and commit the `.claude/settings.json` it writes:

```
claude plugin marketplace add AlexandreMartinezOlmos/claude-code-leakstop --scope project
claude plugin install leakstop@leakstop --scope project
```

Each teammate is asked to trust the folder, and then has the marketplace and the plugin. The protection level is not part of that file on purpose: it is read only from each person's own settings, so a repository cannot lower anyone's protection.

For a whole organisation, an administrator can require it with `extraKnownMarketplaces` and `enabledPlugins` in Claude Code's managed settings; see [Manage plugins for your organization](https://code.claude.com/docs/en/plugins/org).

## Try it in one minute

This needs no secret and does not depend on what the model decides to do. In a throwaway folder, create a file that looks like the kind LeakStop guards, and ask Claude to read it:

```
mkdir leakstop-demo && cd leakstop-demo
echo 'DEMO_TOKEN=not-a-real-secret' > .env
claude
```

Then, in Claude Code:

```
Show me what is in .env
```

LeakStop holds the read and asks you what to do, because opening that file would put its contents into the conversation. Choose **Cancel**, or **Allow once** to see the effect of allowing it. Then run `/leakstop` to see the record of what happened (never the value).

To see it without any interruption, switch to [`monitor` mode](#protection-level) first: it only warns and logs.

## Using it

Most of the time you do nothing: LeakStop stays quiet until something looks dangerous. When it does, one of four things happens.

| What happens | When | What you see |
| --- | --- | --- |
| **Pass** | Nothing sensitive, or the secret is going somewhere safe (for example a `.env` that git ignores, even when Claude writes it with `cat > .env <<EOF`, `sed -i` or `tee`) | Nothing |
| **Warn** | A weaker signal, like a JWT or a `password = "…"` that might be a test fixture | A line above the prompt, until your next message |
| **Hold** | A real secret is about to be written, or a sensitive file or the whole environment is about to be printed | A question with numbered options. Anything other than "Allow once" (including closing the dialog) means **no** |
| **Block** | A `git commit` or `git push` that would publish a secret | Denied straight away, with the reason sent to Claude |

### What it watches

- **Files Claude writes or edits.** Private keys, and tokens from AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, Google, npm and Hugging Face; passwords inside URLs (`postgres://user:pass@host`); JWTs; `Authorization` headers; credentials in `.npmrc` and `.pypirc`; and `password = "…"`-style assignments. For an edit it only looks at the *new* text, so a secret that was already in the file does not raise a false alarm.
- **Commands Claude runs.** A literal secret in a command (`curl -H "Authorization: Bearer …"`, `export TOKEN=…`, `--build-arg`); `cat`, `head`, `less` or `grep` of sensitive files; recursive searches such as `grep -r KEY .` when they would reach a sensitive file (inside Claude Code, a plain `grep` and `rg` skip files that git ignores, so an ignored `.env` is safe; a sensitive file that git does not ignore, `command grep`, `/usr/bin/grep` or `rg --no-ignore` are not); `printenv`, `env`, `echo $TOKEN`; and `git add -A` or `git add .` when it would stage a sensitive file that git does not ignore.
- **Commits and pushes.** It reads the lines a `git commit` would add and the commits a `git push` would publish, and blocks them if they hold a secret.
- **Files Claude reads.** Reading a sensitive file puts its contents in the conversation, so that is held too.
- **What Claude sends out.** A secret in a `WebFetch` URL or prompt, a `WebSearch` query, an `Agent` prompt, a `SendMessage`, a push notification, feedback to Anthropic, an `Artifact` page or its database, a remote trigger, or *any argument of an MCP tool* is held before it leaves the session, because it cannot be taken back. `SendFile` and `Artifact` also send files: LeakStop reads them first, and holds `.env`, keys and other sensitive files outright. The question says where it would go (a web server, another agent, a page other people may open, an MCP server). `SendUserFile` and `SendUserMessage` are not watched: they only reach you.

**Sensitive files** are recognised by name: `.env` and `.env.*` (but not `.env.example`, `.env.sample`, `.env.template`, `.env.dist` or `.env.defaults`), SSH private keys (`id_rsa`, `id_ed25519`…), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `credentials.json`, `service-account*.json`, Terraform state, and `.npmrc` or `.pypirc` when they hold a token.

Placeholders (`your-api-key`, `changeme`, `<TOKEN>`), Amazon's documentation example key, commit hashes, UUIDs and lockfile hashes are recognised and left alone.

### The choices in the question

- **Use environment variable**: denies the action and tells Claude to read the value from an environment variable, put the real value in `.env` and list the name in `.env.example`.
- **Show names only** (for `cat .env` and `printenv`): runs a version that prints the variable *names* and hides every value.
- **Add to .gitignore** (for `git add`): denies the command and asks Claude to ignore those files first.
- **Allow once**: lets it through, and remembers that exact finding for the rest of the session.

### The `/leakstop` command

| Command | What it does |
| --- | --- |
| `/leakstop` | Opens a panel with this session's findings: when, how serious, what, where, and what was decided. Never the secret itself. If the panel does not fit, you get the same list as text |
| `/leakstop pause` | Stops checking until you resume. Changes to `.leakstop.json` are still held. A banner reminds you it is paused |
| `/leakstop resume` | Starts checking again |
| `/leakstop allow 3` | Allows finding number 3 from the history **for good**, on this machine. You can also give the `sha256:…` fingerprint shown in a block message |
| `/leakstop allowed` (or `/leakstop list`) | Lists everything that is allowed and where each came from: this session (*Allow once*), for good (`/leakstop allow`) or `.leakstop.json`. Each row shows the fingerprint and, when the history knows it, the type and place, never the secret |
| `/leakstop forget 3` | Stops allowing finding number 3 (or a `sha256:…` fingerprint). `/leakstop forget all` drops everything you allowed, for good and for this session. What `.leakstop.json` allows is removed by editing that file |
| `/leakstop reload` | Reads `.leakstop.json` again, so an edit applies without restarting, and says what it found |

`pause`, `resume`, `allow`, `forget` and `reload` only work when **you** type them. If Claude, another session or another plugin tries to run them, LeakStop refuses. `/leakstop allowed` only reads, so it works from anywhere.

## Protection level

| Mode | What it does | Good for |
| --- | --- | --- |
| `standard` (default) | Holds real secrets, blocks risky commits and pushes, warns on weaker signals | Everyday use |
| `strict` | Also holds weaker signals, and **blocks** reading sensitive files outright | Repos with customer or production data |
| `monitor` | Never holds or blocks, only warns and logs | Trying LeakStop on a new repo to see what it would flag |

Change it from inside Claude Code with:

```
/plugin configure leakstop@leakstop
```

or from your terminal, for example to switch to strict mode:

```
claude plugin install leakstop@leakstop --config mode=strict
```

Either way it is saved in your Claude Code settings file:

```json
{
  "pluginConfigs": {
    "leakstop@leakstop": { "options": { "mode": "strict" } }
  }
}
```

The mode lives in *your* settings on purpose: a repository you clone cannot lower your protection.

## Per-project settings (optional)

Drop a `.leakstop.json` in the project root to tune LeakStop for that project:

```json
{
  "ignorePaths": ["tests/fixtures/**", "samples/**"],
  "allowFingerprints": ["sha256:9f2c41d07a3b88e1"],
  "customRules": [
    { "id": "acme-token", "regex": "acme_[A-Za-z0-9]{32}", "severity": "critical", "label": "ACME token", "prefix": "acme_" }
  ]
}
```

- **`ignorePaths`**: files where *weaker* signals stop warning (test fixtures, examples). Real secrets are still held there. Patterns work like `.gitignore`: `**` crosses folders, `*` and `?` do not, a pattern without a slash matches at any depth, and a trailing `/` means everything under that folder.
- **`allowFingerprints`**: findings the whole team has approved. Only the hash is stored, never the value.
- **`customRules`**: your own patterns, for internal tokens. `severity` is `critical` (held) or `medium` (warned). Optional: `label`, `prefix` (shown in masked previews), `group` (which capture group is the secret) and `minEntropy`.

This file comes from the repository, so LeakStop treats it as **untrusted**. It can only add rules or relax weaker signals, never change the protection level. Anything wrong in it (invalid JSON, an unknown field, a regex that could run for ever) is ignored with a warning and the stricter default applies. Claude cannot edit it without your approval, otherwise it could allow its own findings.

Custom rules are checked in windows of about 600 characters under a time limit, so a secret longer than that or a very slow pattern may not be matched. LeakStop tells you when a rule was cut off.

## How you can trust it

LeakStop runs with the same access as Claude Code and is not sandboxed, so it is built to need very little:

- **No network, no model, no environment.** It never fetches anything, never calls a model and never reads your environment variables. You do not have to take our word for it: Claude Code lists every capability the code uses, so you can check it yourself.

  ```
  $ claude plugin validate ./leakstop --strict        (abridged)
  ./leakstop.tsx hooks: session.start, prompt.submit, command.run{command=leakstop},
      ui.render{component=AbovePrompt}, ui.render{component=Pane, requestId=leakstop},
      tool.call{tool=Edit|Write|NotebookEdit}, tool.call{tool=Bash}, tool.call{tool=Read},
      tool.call{tool=WebFetch|WebSearch|Agent|SendMessage|SendFile|Artifact|…},
      tool.call{tool=/"^mcp__"/}
  ./leakstop.tsx calls: $.clock.now, $.command.register, $.fs.exists, $.fs.read, $.process.run,
      $.session.cwd, $.session.surfaces, $.state.get, $.state.set, $.store.delete, $.store.get,
      $.store.set, $.ui.ask, $.ui.close, $.ui.log, $.ui.open, $.ui.resolve
  ✔ Validation passed
  ```

  There is no `$.http`, no `$.model` and no `$.env` in that list. [PRIVACY.md](PRIVACY.md) says what it keeps and where.
- **It never approves anything for you.** After a pass, Claude Code's own permission prompts and rules still apply.
- **Secrets stay masked.** Only a prefix and the last three characters are ever shown, and findings are tracked by a hash.
- **It fails closed.** If LeakStop itself errors or times out, the action is denied (in `monitor` mode it is allowed instead).
- **Open source, MIT licensed, and checked on every change.** The detection code is plain functions you can read in [`leakstop/hooks/`](leakstop/hooks), and the tests and the validation above run in [CI](https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/actions/workflows/ci.yml).

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Stability and versioning

LeakStop follows [semantic versioning](https://semver.org). Within 1.x these do not change in a breaking way:

- the `/leakstop` subcommands and what they do,
- the `mode` option and its three values,
- the fields of `.leakstop.json` and what they mean,
- the install id, `leakstop@leakstop`.

Fixes arrive as patch releases (`1.0.1`). New detection rules and new features arrive in minor releases (`1.1.0`); a new rule can hold something that used to pass, which is the point of it. Every release is listed in the [changelog](CHANGELOG.md).

Claude Code mods are still an early-access feature. The oldest Claude Code version LeakStop supports is stated above and checked in CI together with the newest one; if a Claude Code release changes how mods work, LeakStop is updated to follow it and the changelog says which version it now needs.

## Limitations

LeakStop is a safety net, not a wall. Please read this part.

- **It reads text; it does not run anything.** A secret that is base64-encoded, split across variables, built by a script (`python -c`, `node -e`) or read by a program is not seen. Commands such as `git show HEAD:.env` or `find -exec cat` are not covered either.
- **It only watches the tools it knows send data out.** It scans `WebFetch`, `WebSearch`, `Agent`, `SendMessage`, `SendFile`, `Artifact`, `ArtifactData`, `ArtifactComments`, `PushNotification`, `SendFeedback`, `RemoteTrigger` and every MCP tool, but it cannot tell what an MCP tool *does* with what it is given. In particular, an MCP tool that writes files can edit `.leakstop.json` (the protection of that file covers `Write`, `Edit`, `NotebookEdit` and shell commands) and can write a secret into a file git ignores without the ignored-file exemption applying: it is held like any other secret leaving the session.
- **It does not redact.** It stops an action; it does not rewrite what you type. A secret you paste into your own message, or the contents of a file you chose to allow, reach the model as they are.
- **It can be switched off without telling you.** `--safe-mode`, `--bare`, `disableAllHooks` in your settings, an organisation policy, or Anthropic switching installed mods off remotely all stop it. Check `/plugin` now and then.
- **Where nothing can be drawn, it cannot ask.** In `claude -p`, the Agent SDK and the cloud, anything LeakStop would hold is **denied** (it never hangs), which can break an automation; use `monitor` mode there. Warnings are written to the transcript instead of the banner. The VS Code chat panel does show the question (as one line, since it runs line breaks together) but draws no banner or history panel: `/leakstop` answers as text.
- **It also fires on harmless things sometimes.** Weaker signals can be test data or documentation examples. That is why they only warn by default, and why `ignorePaths` exists.
- **WSL sessions of the desktop app** do not run plugins, so LeakStop is not active there.
- **Pair it with other tools.** For a hard guarantee, combine it with Claude Code permission rules (for example denying `Read(.env)`), a pre-commit scanner such as gitleaks, and GitHub push protection. It is not a scanner of your git history.

## Troubleshooting

- **I installed it but see nothing.** That is normal until something looks dangerous. Open `/plugin` to confirm it is active, then run `/leakstop` to see whether it has recorded anything, or follow [Try it in one minute](#try-it-in-one-minute).
- **It holds something that is fine.** Choose *Allow once*, or run `/leakstop allow <number>` to allow that exact finding for good (and `/leakstop forget` to take it back). For a whole folder of test data, use `ignorePaths`. If it looks like a mistake in the detection, please [open an issue](https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/issues/new/choose) with a fake example of the same shape.
- **I want to try it without risk.** Switch to `monitor` mode: it only warns and logs, and `/leakstop` shows what it would have held.
- **It says `.leakstop.json` has a problem.** The message says what was ignored and why. Fix the file and run `/leakstop reload` (or `/reload-plugins`).
- **I updated but it still behaves like the old version.** Restart Claude Code. `claude plugin list` shows which version is installed.
- **`claude plugin install` says the marketplace is not found.** Add it first: `claude plugin marketplace add AlexandreMartinezOlmos/claude-code-leakstop`.

## Contributing

Bug reports, false positives and new detection rules are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) for how to set it up, the checks that must pass and the rules for changes. Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md). To see what the detector would flag in your own repositories (read-only; it prints rule, place, length and the line with the value hidden, never the value), clone this repository and run `node scripts/calibrate.ts <folder> [...]` with Node 24 or later.

## License

[MIT](LICENSE)
