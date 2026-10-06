## What and why

<!-- What changes, and what it fixes or adds. Link the issue if there is one. -->

## Checklist

- [ ] Opened against `develop`
- [ ] `claude plugin validate ./leakstop --strict`, `claude plugin validate .` and `node scripts/test.ts` pass
- [ ] New or changed behaviour has tests, including the harmless case for a new rule
- [ ] No complete token in the repository: test secrets are generated at run time
- [ ] `CHANGELOG.md` has an `Unreleased` entry for anything a user would notice
- [ ] README updated if a command, option or limitation changed
