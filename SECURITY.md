# Security policy

LeakStop exists to protect secrets, so a flaw in it matters. Thank you for reporting one responsibly.

## Supported versions

Only the latest 1.x release gets security fixes. Update with `claude plugin marketplace update leakstop` and then `claude plugin update leakstop@leakstop`.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Use GitHub's private reporting instead:

1. Go to the [Security tab](https://github.com/AlexandreMartinezOlmos/claude-code-leakstop/security) of this repository.
2. Choose **Report a vulnerability**.
3. Describe what you found and how to reproduce it.

Please **never include a real secret** in a report. A fake one with the same shape (for example `ghp_` followed by random characters) shows the problem just as well.

You can expect an answer within about a week. If the report is confirmed, the fix is released as a patch version and the advisory credits you, unless you prefer to stay anonymous.

## What counts as a vulnerability

- LeakStop **shows, logs or stores a full secret** anywhere (the banner, the history panel, messages to Claude, the store files, error messages). Only a short prefix and the last three characters may appear.
- A **bypass of something the README says LeakStop catches**: a documented kind of secret, tool or command that goes through unchecked.
- A repository's `.leakstop.json` **lowers your protection** (changes the protection level, switches rules off, or allows its own findings) instead of being treated as untrusted.
- LeakStop **fails open**: an error, a time-out or a crafted input lets the action through in `standard` or `strict` mode.
- A pattern or input that makes LeakStop **hang or burn CPU** (a regular-expression denial of service).
- LeakStop **reaches the network, runs a model or reads your environment variables**. It is built never to.

## What does not count

These are written down in the [Limitations](README.md#limitations) section and are not vulnerabilities, although a report that improves them is welcome as a normal issue:

- Secrets that are encoded, split across variables, built by a script or read by a program.
- An MCP tool that does something LeakStop cannot see.
- LeakStop being switched off by `--safe-mode`, `--bare`, `disableAllHooks`, an organisation policy or Anthropic.
- Surfaces that cannot run mods or cannot draw a question.
- False positives, which are ordinary bugs.
