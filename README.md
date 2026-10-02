# LeakStop

**Stops Claude Code from leaking secrets before it does.**

When an AI agent works in your terminal it can, without meaning to, copy an API key from `.env` into your code, print your whole environment into the conversation, or `git add .` a private key. LeakStop watches what Claude is *about to do* and steps in **before** it happens: it asks you, or blocks the action, and tells Claude how to do it safely (for example, "read the key from an environment variable instead").

It runs entirely on your machine. No network, no AI model, no accounts. It never reads your environment variables, and it never shows or stores a full secret: only a short prefix and the last three characters.

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

## Install

You need **Claude Code 2.1.287 or later** (check with `claude --version`). LeakStop is a Claude Code *mod*, a kind of plugin that is on by default from that version.

Inside Claude Code, run these three commands:

```
/plugin marketplace add AlexandreMartinezOlmos/claude-code-leakstop
/plugin install leakstop@leakstop
/reload-plugins
```

**Check that it is on.** Open `/plugin`: LeakStop should be listed as active. If you ever see it missing, nothing is protecting you (see [Limitations](#limitations)).

To update, reinstall from `/plugin` when a new version is published. To remove it, uninstall it from the same `/plugin` screen.

## Using it

Most of the time you do nothing: LeakStop stays quiet until something looks dangerous. When it does, one of four things happens.

| What happens | When | What you see |
| --- | --- | --- |
| **Pass** | Nothing sensitive, or the secret is going somewhere safe (for example a `.env` that git ignores, even when Claude writes it with `cat > .env <<EOF`) | Nothing |
| **Warn** | A weaker signal, like a JWT or a `password = "…"` that might be a test fixture | A line above the prompt, until your next message |
| **Hold** | A real secret is about to be written, or a sensitive file or the whole environment is about to be printed | A question with numbered options. Anything other than "Allow once" (including closing the dialog) means **no** |
| **Block** | A `git commit` or `git push` that would publish a secret | Denied straight away, with the reason sent to Claude |

### What it watches

- **Files Claude writes or edits.** Private keys, and tokens from AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, Google, npm and Hugging Face; passwords inside URLs (`postgres://user:pass@host`); JWTs; and `password = "…"`-style assignments. For an edit it only looks at the *new* text, so a secret that was already in the file does not raise a false alarm.
- **Commands Claude runs.** A literal secret in a command (`curl -H "Authorization: Bearer …"`, `export TOKEN=…`, `--build-arg`); `cat`, `head`, `less` or `grep` of `.env`, `*.pem`, `id_rsa` and similar files; recursive searches such as `grep -r KEY .` when a sensitive file is inside the folder being searched (`grep` ignores `.gitignore`, so it would print the values); `printenv`, `env`, `echo $TOKEN`; and `git add -A` or `git add .` when it would stage a sensitive file that git does not ignore.
- **Commits and pushes.** It reads the lines a `git commit` would add and the commits a `git push` would publish, and blocks them if they hold a secret.
- **Files Claude reads.** Reading a sensitive file puts its contents in the conversation, so that is held too.

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

`pause`, `resume` and `allow` only work when **you** type them. If Claude, another session or another plugin tries to run them, LeakStop refuses.

### Protection level

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

After installing you may see a note that "1 userConfig option is not yet set". That is fine: until you choose, LeakStop runs in `standard` mode.

The mode lives in *your* settings on purpose: a repository you clone cannot lower your protection.

## Per-project settings (optional)

Drop a `.leakstop.json` in the project root to tune LeakStop for that project:

```json
{
  "ignorePaths": ["tests/fixtures/**", "docs/**"],
  "allowFingerprints": ["sha256:9f2c41d07a3b88e1"],
  "customRules": [
    { "id": "acme-token", "regex": "acme_[A-Za-z0-9]{32}", "severity": "critical", "label": "ACME token", "prefix": "acme_" }
  ]
}
```

- **`ignorePaths`**: files where *weaker* signals stop warning (test fixtures, docs). Real secrets are still held there. Patterns work like `.gitignore`: `**` crosses folders, `*` and `?` do not, a pattern without a slash matches at any depth, and a trailing `/` means everything under that folder.
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
      tool.call{tool=Edit|Write|NotebookEdit}, tool.call{tool=Bash}, tool.call{tool=Read}
  ./leakstop.tsx calls: $.clock.now, $.command.register, $.fs.exists, $.fs.read, $.process.run,
      $.session.cwd, $.session.surfaces, $.state.get, $.state.set, $.store.get, $.store.set,
      $.ui.ask, $.ui.close, $.ui.log, $.ui.open, $.ui.resolve
  ✔ Validation passed
  ```

  There is no `$.http`, no `$.model` and no `$.env` in that list.
- **It never approves anything for you.** After a pass, Claude Code's own permission prompts and rules still apply.
- **Secrets stay masked.** Only a prefix and the last three characters are ever shown, and findings are tracked by a hash.
- **It fails closed.** If LeakStop itself errors or times out, the action is denied (in `monitor` mode it is allowed instead).
- **Open source, MIT licensed.** The detection code is plain functions you can read in [`leakstop/hooks/`](leakstop/hooks).

## Limitations

LeakStop is a safety net, not a wall. Please read this part.

- **It reads text; it does not run anything.** A secret that is base64-encoded, split across variables, built by a script (`python -c`, `node -e`) or read by a program is not seen. Commands such as `git show HEAD:.env` or `find -exec cat` are not covered either.
- **It does not look at tools that send data out yet.** LeakStop covers the tools that read or write local files and the shell. It does not scan what goes into web requests, messages to other agents or sessions, sent files or other MCP tools.
- **It can be switched off without telling you.** `--safe-mode`, `--bare`, `disableAllHooks` in your settings, an organisation policy, or Anthropic switching installed mods off remotely all stop it. Check `/plugin` now and then.
- **Where nothing can be drawn, it cannot ask.** In `claude -p`, the Agent SDK, the cloud and the VS Code chat panel, anything LeakStop would hold is **denied** (it never hangs), which can break an automation; use `monitor` mode there. Warnings are written to the transcript instead of the banner.
- **It also fires on harmless things sometimes.** Weaker signals can be test data or documentation examples. That is why they only warn by default, and why `ignorePaths` exists.
- **WSL sessions of the desktop app** do not run plugins, so LeakStop is not active there.
- **Pair it with other tools.** For a hard guarantee, combine it with Claude Code permission rules (for example denying `Read(.env)`), a pre-commit scanner such as gitleaks, and GitHub push protection. It is not a scanner of your git history.

Claude Code mods are still an early-access feature and their interface can change between versions, so LeakStop states the minimum version it was tested with (2.1.287) and is re-tested on new releases.

## Troubleshooting

- **I installed it but see nothing.** That is normal until something looks dangerous. Open `/plugin` to confirm it is active, then run `/leakstop` to see whether it has recorded anything.
- **It holds something that is fine.** Choose *Allow once*, or run `/leakstop allow <number>` to allow that exact finding for good. For a whole folder of test data, use `ignorePaths`.
- **I want to try it without risk.** Switch to `monitor` mode: it only warns and logs, and `/leakstop` shows what it would have held.
- **It says `.leakstop.json` has a problem.** The message says what was ignored and why. Fix the file and run `/reload-plugins`.

## Development

```
git clone https://github.com/AlexandreMartinezOlmos/claude-code-leakstop
cd claude-code-leakstop
claude --plugin-dir ./leakstop      # loads the mod and reloads it when you save
(cd leakstop && claude plugin test) # unit and interface tests
claude plugin validate ./leakstop --strict
```

While developing, use `monitor` mode so LeakStop does not hold its own test files, and test in a throwaway project. Test secrets are generated at run time; no real-looking secret is ever committed to this repository.

To see what the detector would flag in your own repositories (read-only; it prints rule, place, length and the line with the value hidden, never the value), run `node scripts/calibrate.ts <folder> [...]` with Node 24 or later.

## License

[MIT](LICENSE)
