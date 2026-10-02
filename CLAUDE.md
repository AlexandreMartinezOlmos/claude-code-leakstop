# LeakStop

A Claude Code mod (plugin) that stops secrets from leaking before they are written, printed or committed to git.

- The full specification is in `docs/REQUIREMENTS.md`. Read all of it before touching any code.
- The types that Claude Code generates in `leakstop/.claude-plugin/types/` win over that document if they disagree.
- Every milestone ends with `claude plugin validate ./leakstop --strict` and `claude plugin test` passing. Do not commit if they fail.
- Test secrets are generated at runtime; never write literal secrets in the repository.
- While developing, use LeakStop's `monitor` mode.
- Everything is in English: code, comments, commit messages, README and user-facing strings.
