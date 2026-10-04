# Privacy

LeakStop collects nothing and sends nothing.

- **No network.** It never opens a connection. It has no telemetry, no analytics and no update check.
- **No model.** It never calls an AI model. Detection is made of plain patterns you can read in [`leakstop/hooks/`](leakstop/hooks).
- **No environment.** It never reads your environment variables.
- **No full secrets.** When it finds one it keeps a short prefix, the last three characters and a 64-bit hash of the value, to recognise the same finding again.

What it keeps on your machine:

| What | Where | Holds |
| --- | --- | --- |
| The findings of the current session | Claude Code's session state | Type, place, severity, decision and hash, never the secret |
| What you allowed for good with `/leakstop allow` | A file in `~/.claude/plugins/store/`, written through Claude Code | Hashes only. Empty it with `/leakstop forget all`, or delete the file |
| Your protection level | Your Claude Code settings | `monitor`, `standard` or `strict` |

Claude Code itself is covered by [Anthropic's own terms and privacy policy](https://www.anthropic.com/legal/privacy). LeakStop adds nothing to what Claude Code sends, except the reason it gives Claude when it denies an action, which only ever shows a masked value.

To check any of this yourself, run `claude plugin validate ./leakstop --strict`: it lists every capability the code uses, and there is no network, model or environment access in the list.
