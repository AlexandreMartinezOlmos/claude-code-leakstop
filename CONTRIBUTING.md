# Contributing to LeakStop

Thanks for helping. Bug reports, false positives and new detection rules are all welcome.

## Before you start

- **A vulnerability?** Do not open an issue: follow [SECURITY.md](SECURITY.md).
- **A false positive or a missed secret?** Open an issue with the form for it. Describe the *shape* of the value (`ghp_` plus 36 letters and digits), never paste a real one.
- **A bigger change?** Open an issue first so we can agree on it before you spend time on code.

## Setting up

You need [Claude Code](https://code.claude.com) 2.1.287 or later and Node 24 or later.

```
git clone https://github.com/AlexandreMartinezOlmos/claude-code-leakstop
cd claude-code-leakstop
claude --plugin-dir ./leakstop      # loads the mod and reloads it when you save
```

A mod loaded with `--plugin-dir` is not *installed*, so `/plugin configure` does not apply to it. Pass the mode for that session instead. While you develop, use `monitor` so LeakStop does not hold its own test files, and try things in a throwaway project:

```
claude --plugin-dir ./leakstop --settings '{"pluginConfigs":{"leakstop":{"options":{"mode":"monitor"}}}}'
```

## Checks that must pass

CI runs these on every pull request, with the oldest supported Claude Code and the newest one. Run them before you push:

```
claude plugin validate ./leakstop --strict
claude plugin validate .
(cd leakstop && claude plugin test)
node scripts/check-release.ts
node scripts/calibrate.ts --check .
```

`claude plugin validate --strict` also lists every capability the code uses. If your change adds one that touches the network, a model or the environment, it will not be accepted: [PRIVACY.md](PRIVACY.md) promises none.

## How the code is laid out

Everything lives in [`leakstop/hooks/`](leakstop/hooks):

| File | What it does |
| --- | --- |
| `leakstop.tsx` | The only file that talks to Claude Code (`$`): registers the hooks and the `/leakstop` command |
| `rules.ts` | The catalog of patterns. Data only |
| `detect.ts` | Scans text, classifies sensitive paths, masks and fingerprints |
| `commands.ts` | Reads a shell command as text and says what it is about to do |
| `outbound.ts` | Collects what a tool call sends out of the session |
| `policy.ts` | Turns a finding and a mode into pass, warn, hold or block |
| `messages.ts`, `ui.ts` | What the user and Claude read |
| `config.ts` | Validates `.leakstop.json` as untrusted input |
| `diff.ts`, `mask.ts` | Only the new text of an edit; masking |

Only `leakstop.tsx` receives `$`. Everything else is pure functions, so it can be tested without Claude Code.

## Rules for changes

- **Regular expressions must be linear.** A hook that runs out of time is skipped by Claude Code and the action goes ahead, so a slow pattern is a security bug. Bound every quantifier.
- **Never show or store a full secret.** Only a short prefix and the last three characters.
- **Err on the side of looking.** A false positive is a question; a false negative is a leak. But a rule that fires on ordinary code gets switched off by its users, so add a test for the harmless case too.
- **Fail closed.** An internal error denies the action (in `monitor` mode it allows).
- **Test secrets are generated at run time.** Use the helpers in `leakstop/tests/secrets.ts`. Never write a complete token in the repository: scanners flag it, and so does LeakStop's own check in CI.
- **English everywhere**: code, comments, commit messages, documentation and the text users read.
- **Every change comes with tests**, and `claude plugin test` must stay green.

## Pull requests

- Branch from `develop` (`feature/<name>` or `fix/<name>`) and open the pull request against `develop`. `main` only holds releases.
- Commit messages start with `feat:`, `fix:`, `docs:` or `chore:`.
- Update `CHANGELOG.md` under an `Unreleased` heading for anything a user would notice.

## Releasing (maintainer)

1. Branch `release/vX.Y.Z` from `develop`. Set `version` in `leakstop/.claude-plugin/plugin.json` and rename `Unreleased` in `CHANGELOG.md` to the version, with its date and its link at the bottom. `node scripts/check-release.ts` checks that they agree.
2. Run the checks above. Merge into `main` with `--no-ff`, tag `vX.Y.Z` and publish a GitHub release whose notes are the changelog entry plus the minimum Claude Code version.
3. Merge `main` back into `develop`.

The version in `plugin.json` is what makes installed copies update, so it must change with every release.

## Versioning

LeakStop follows [semantic versioning](https://semver.org). The public surface is documented in the README: the `/leakstop` subcommands, the `mode` option, and the fields of `.leakstop.json`. Those do not change in a 1.x release except to add to them. New detection rules may arrive in a minor release; a fix for a missed secret or a false positive is a patch.
