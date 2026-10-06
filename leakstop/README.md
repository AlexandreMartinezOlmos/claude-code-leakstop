# LeakStop

**Stops Claude Code from leaking secrets before it does.**

When an AI agent works in your terminal it can, without meaning to, copy an API key from `.env` into your code, print your whole environment into the conversation, or `git add .` a private key. LeakStop is a Claude Code mod that watches what Claude is *about to do* and steps in **before** it happens: it asks you, or blocks the action, and tells Claude how to do it safely (for example, "read the key from an environment variable instead").

It runs entirely on your machine. No network, no AI model, no accounts. It never reads your environment variables, and it never shows or stores a full secret: only a short prefix and the last three characters.

## Requirements

Claude Code 2.1.287 or later. LeakStop is a Claude Code *mod*, a kind of plugin that is on by default from that version.

## What it watches

- **Files Claude writes or edits:** private keys, and tokens from AWS, GitHub, GitLab, Anthropic, OpenAI, Stripe, Slack, Google, npm and Hugging Face; passwords inside URLs; JWTs; `Authorization` headers; and `password = "…"`-style assignments.
- **Commands Claude runs:** a literal secret in a command, `cat` or `grep` of sensitive files such as `.env` and private keys (also from git history, `git show HEAD:.env`, or through `find -exec`), `printenv`, and `git add .` when it would stage a sensitive file that git does not ignore.
- **Commits and pushes:** a `git commit` or `git push` that would publish a secret is blocked.
- **Files Claude reads:** reading a sensitive file puts its contents in the conversation, so that is held too.
- **What tools return:** a real secret in what a command, a file read or an MCP tool returns is masked before Claude sees it.
- **Your messages:** a real secret you paste into the prompt is masked before it is sent.
- **What Claude sends out:** a secret in a web request, a search, a message to another agent or any argument of an MCP tool is held before it leaves the session.

## What you see

Most of the time, nothing: LeakStop stays quiet until something looks dangerous. A weaker signal shows a warning line above the prompt. A real secret opens a question with numbered options (anything other than "Allow once" means no). A risky commit or push is denied straight away.

Run `/leakstop` to see a record of what it found this session, never the secret itself. It also has `pause`, `resume`, `allow`, `allowed`, `forget` and `reload` subcommands.

## Protection level

Set the `mode` option with `/plugin configure leakstop@leakstop`:

- `standard` (default) holds real secrets, blocks risky commits and pushes, masks real secrets in what tools return and in your messages, and warns on weaker signals.
- `strict` also holds and masks weaker signals and blocks reading sensitive files outright.
- `monitor` never holds, blocks or masks, it only warns and logs.

Turn on the `statusLine` option (off by default) to keep a line under the prompt that says LeakStop is on; when it is missing, nothing is protecting the session. It is the safest way to try LeakStop on a new repository.

## How it works

LeakStop is a hooks module. Each hook looks at what is about to happen, or at what a tool returned, and passes it on unchanged unless it finds a problem.

- `session.start` registers the `/leakstop` command and reads `.leakstop.json` from the project folder, if there is one.
- `prompt.submit` clears the warning line when you send your own message, and masks a real secret pasted into it.
- `command.run`, for `/leakstop` only, answers the subcommands (`pause`, `resume`, `allow`, `allowed`, `forget`, `reload`).
- `ui.render` draws the warning line above the prompt and the findings panel.
- `tool.call` runs before `Write`, `Edit`, `NotebookEdit`, `Bash`, `Read`, the tools that send data out (`WebFetch`, `WebSearch`, `Agent`, `SendMessage`, `SendFile`, `Artifact` and similar) and every MCP tool. It scans the input for secrets and sensitive files and either lets the call go on, asks you, or denies it. For `Bash`, `Read` and every MCP tool it then scans what the tool returned and masks real secrets in it.

## What it changes

It does not edit a tool's input, with one exception, described below. It does change three things on their way to Claude, and only to replace a secret by its masked form (a short prefix and the last three characters): what `Bash`, `Read` and MCP tools return, the text you send, and, for a large `Bash` output, the copy of it that Claude Code saves under its own folder in your home directory, which LeakStop reads and rewrites with the value masked.

The exception for inputs: When a `Bash` command is a single plain view of an environment file (such as `cat .env`) or of the whole environment (`env` or `printenv`), the question offers **Show names only**. If you choose it, the command is replaced by a `sed` filter that prints the variable names and hides every value. In every other case the call is either passed on exactly as it came, or denied.

## What it runs

LeakStop starts two programs, both read-only and local, with a time limit:

- `git`, in the project folder, with fixed arguments: `check-ignore` (is this file ignored?), `ls-files --others --exclude-standard` and `diff --name-only` (what would `git add .` stage?), `diff` and `diff --cached` (what would `git commit` add?), and `log -p` over the commits that are not on a remote yet (what would `git push` publish?). None of these writes anything or uses the network. The path or folder is the only variable part.
- `find`, up to eight levels deep, to see whether a recursive `grep` or `rg` would reach a sensitive file such as `.env` or a private key.

It also reads the files that a tool call is about to write, send or open, `.leakstop.json`, and the saved copy of a large command output, only to scan them. It keeps hashes of what you allow for good (`/leakstop allow`) in Claude Code's plugin store, and the findings of the session in Claude Code's session state.

## What it sends and where

Nothing. LeakStop has no network access, does not call a model and sends no data anywhere. The only things it produces are the question it shows you, the warning line, the findings panel, and the short reason it gives Claude when it denies an action, which only ever shows a masked value.

It never reads your environment variables or any credential from your machine. The names of environment variables appear only inside the advice it gives Claude ("read the value from an environment variable instead").

## Detection patterns

The detector contains text that looks like a credential sent to a server, and it is not one:

- `hooks/commands.ts` and `hooks/detect.ts` recognise commands such as `python -c` and `node -e`, and names such as `TOKEN` or `.npmrc`, as patterns to look for in the text of a command. They only read the text. LeakStop never runs that code, never reads the value of an environment variable and never sends anything out.

## Privacy and trust

LeakStop collects nothing and sends nothing. It has no network, model or environment access, and `claude plugin validate --strict` lists every capability its code uses so you can check that yourself. It is open source under the MIT licence, and everything it needs is readable plain code in the `hooks` folder of this plugin.

## More

The full documentation, a demo recording, the changelog and the privacy and security policies are in the repository: https://github.com/AlexandreMartinezOlmos/claude-code-leakstop

LeakStop is a safety net, not a wall. The repository README lists what it cannot see.
