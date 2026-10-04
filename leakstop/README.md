# LeakStop

**Stops Claude Code from leaking secrets before it does.**

When an AI agent works in your terminal it can, without meaning to, copy an API key from `.env` into your code, print your whole environment into the conversation, or `git add .` a private key. LeakStop is a Claude Code mod that watches what Claude is *about to do* and steps in **before** it happens: it asks you, or blocks the action, and tells Claude how to do it safely (for example, "read the key from an environment variable instead").

It runs entirely on your machine. No network, no AI model, no accounts. It never reads your environment variables, and it never shows or stores a full secret: only a short prefix and the last three characters.

## Requirements

Claude Code 2.1.287 or later. LeakStop is a Claude Code *mod*, a kind of plugin that is on by default from that version.

## What it watches

- **Files Claude writes or edits:** private keys, and tokens from AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, Google, npm and Hugging Face; passwords inside URLs; JWTs; `Authorization` headers; and `password = "…"`-style assignments.
- **Commands Claude runs:** a literal secret in a command, `cat` or `grep` of sensitive files such as `.env` and private keys, `printenv`, and `git add .` when it would stage a sensitive file that git does not ignore.
- **Commits and pushes:** a `git commit` or `git push` that would publish a secret is blocked.
- **Files Claude reads:** reading a sensitive file puts its contents in the conversation, so that is held too.
- **What Claude sends out:** a secret in a web request, a search, a message to another agent or any argument of an MCP tool is held before it leaves the session.

## What you see

Most of the time, nothing: LeakStop stays quiet until something looks dangerous. A weaker signal shows a warning line above the prompt. A real secret opens a question with numbered options (anything other than "Allow once" means no). A risky commit or push is denied straight away.

Run `/leakstop` to see a record of what it found this session, never the secret itself. It also has `pause`, `resume`, `allow`, `allowed`, `forget` and `reload` subcommands.

## Protection level

Set the `mode` option with `/plugin configure leakstop@leakstop`:

- `standard` (default) holds real secrets, blocks risky commits and pushes, and warns on weaker signals.
- `strict` also holds weaker signals and blocks reading sensitive files outright.
- `monitor` never holds or blocks, it only warns and logs. It is the safest way to try LeakStop on a new repository.

## Privacy and trust

LeakStop collects nothing and sends nothing. It has no network, model or environment access, and `claude plugin validate --strict` lists every capability its code uses so you can check that yourself. It is open source under the MIT licence, and everything it needs is readable plain code in the `hooks` folder of this plugin.

## More

The full documentation, a demo recording, the changelog and the privacy and security policies are in the repository: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop

LeakStop is a safety net, not a wall. The repository README lists what it cannot see.
