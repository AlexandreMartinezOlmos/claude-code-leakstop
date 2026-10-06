// What LeakStop says: the hold question and the denial message. Pure: no `$`.
//
// Everything here is built from a MaskedFinding, so no complete secret can
// reach the interface or the model. The most that appears is the rule's
// identifying prefix and the last three characters.

import { classifyPath } from './detect.ts'
import type { MaskedFinding } from './mask.ts'
import { destinationOf, toolLabel } from './outbound.ts'

/** The labels of the options in the dialogs. */
export const USE_ENV = 'Use environment variable'
export const ALLOW_ONCE = 'Allow once'
export const CANCEL = 'Cancel'
export const SHOW_NAMES = 'Show names only'
export const ADD_GITIGNORE = 'Add to .gitignore'

const MAX_FREE_TEXT = 200

/**
 * What the model reads before a denial: who decided, so it neither retries after a cancel nor asks the user
 * again after a choice that already told it what to do. `answer` is `undefined` when nobody could answer.
 */
export function answerNote(answer: string | undefined): string {
  switch (answer) {
    case undefined:
      return 'LeakStop could not ask the user, so the action was denied.'
    case CANCEL:
      return 'The user chose Cancel: do not retry this action or work around it. Ask them how they want to proceed.'
    case USE_ENV:
      return 'The user chose "Use environment variable": do that now instead of writing the value.'
    case ADD_GITIGNORE:
      return 'The user chose "Add to .gitignore": add those files to .gitignore now, then retry.'
    default: {
      const text = answer.replace(/\s+/g, ' ').trim()
      const shown = text.length > MAX_FREE_TEXT ? `${text.slice(0, MAX_FREE_TEXT)}…` : text
      return `The user picked no option and answered: "${shown}". That is not an approval of the original action; follow what they said, and ask them if it is unclear.`
    }
  }
}

/**
 * The question as one line, for a surface that does not keep line breaks (the VS Code panel runs them
 * together into one paragraph): the lines read in order, set apart by dashes.
 */
export function flatten(question: string): string {
  return question
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '')
    .join(' — ')
}

/** The tools whose write is checked. */
export type WriteTool = 'Write' | 'Edit' | 'NotebookEdit'

const VERB: Record<WriteTool, string> = { Write: 'write', Edit: 'edit', NotebookEdit: 'notebook edit' }

/** The variable a secret of each kind belongs in. */
const ENV_VARS: Record<string, string> = {
  'aws-access-key': 'AWS_ACCESS_KEY_ID',
  'github-token': 'GITHUB_TOKEN',
  'github-fine-grained-token': 'GITHUB_TOKEN',
  'gitlab-token': 'GITLAB_TOKEN',
  'anthropic-key': 'ANTHROPIC_API_KEY',
  'openai-key': 'OPENAI_API_KEY',
  'stripe-live-key': 'STRIPE_SECRET_KEY',
  'stripe-test-key': 'STRIPE_SECRET_KEY',
  'slack-token': 'SLACK_BOT_TOKEN',
  'google-api-key': 'GOOGLE_API_KEY',
  'npm-token': 'NPM_TOKEN',
  'npmrc-auth-token': 'NPM_TOKEN',
  'huggingface-token': 'HF_TOKEN',
  'pypirc-password': 'PYPI_TOKEN',
  'url-credentials': 'DATABASE_URL',
  'jwt': 'AUTH_TOKEN',
}

/** `src/config.ts` for `/work/app/src/config.ts` when the session runs in `/work/app`. */
export function displayPath(path: string, cwd?: string): string {
  if (cwd === undefined || cwd === '') return path
  const root = cwd.endsWith('/') ? cwd : `${cwd}/`
  return path.startsWith(root) ? path.slice(root.length) : path
}

const article = (label: string): string => (/^(?:[aeiou]|npm|AWS|SSH)/i.test(label) ? 'an' : 'a')

const typeOf = (finding: MaskedFinding): string => `${article(finding.label)} ${finding.label}`

/** `sk-ant-…`, or nothing when the rule has no public prefix. */
const hint = (finding: MaskedFinding): string => (finding.prefix === undefined ? '' : ` (${finding.prefix}…)`)

function advice(path: string, findings: readonly MaskedFinding[]): string {
  if (classifyPath(path)?.kind === 'env') {
    return 'This file is not ignored by git: add it to .gitignore first, then write the secret there.'
  }
  const first = findings[0]
  if (first?.ruleId === 'private-key') {
    return 'Keep the key out of the repository: store it outside the project or in a secret manager, and read its path from an environment variable.'
  }
  const name = first === undefined ? undefined : ENV_VARS[first.ruleId]
  if (name === undefined) {
    return 'Read the value from an environment variable instead, add it to .env (ignored by git) and declare the variable without a value in .env.example.'
  }
  return `Read the value from the environment variable ${name} instead (for example process.env.${name}), add it to .env (ignored by git) and declare the variable without a value in .env.example.`
}

/** The message Claude reads when a write is denied: type, location and alternative, never the value. */
export function denyMessage(tool: WriteTool, path: string, findings: readonly MaskedFinding[]): string {
  const shown = findings.slice(0, 5)
  const what = shown.map((f) => `${path}:${f.line} contains ${typeOf(f)}${hint(f)}`).join('; ')
  const more = findings.length > shown.length ? ` (and ${findings.length - shown.length} more)` : ''
  return `LeakStop blocked this ${VERB[tool]}: ${what}${more}. ${advice(path, findings)}`
}

/** The hold question: plain text, because the dialog supports no colors. */
export function holdQuestion(tool: WriteTool, path: string, findings: readonly MaskedFinding[]): string {
  const severity = findings.some((f) => f.severity === 'critical') ? 'CRITICAL' : 'MEDIUM'
  const shown = findings.slice(0, 3)
  const lines = [`LeakStop · ${severity}`]
  for (const finding of shown) {
    lines.push(`${finding.label} in ${tool} → ${path}:${finding.line}`, `  ${finding.masked}`)
  }
  if (findings.length > shown.length) lines.push(`  …and ${findings.length - shown.length} more`)
  lines.push(
    classifyPath(path)?.kind === 'env'
      ? 'This file is not ignored by git and would end up in the repository.'
      : 'This file is not ignored by git, so the secret would end up in the repository.',
    '',
    'How do you want to handle it?',
  )
  return lines.join('\n')
}

/** The question for an edit of LeakStop's own configuration. */
export function configQuestion(path: string): string {
  return [
    'LeakStop · CONFIGURATION',
    `Claude wants to change ${path}`,
    "This file can relax LeakStop's rules, so only you should approve it.",
    '',
    'Allow this change?',
  ].join('\n')
}

export function configDenyMessage(path: string): string {
  return `LeakStop blocked this change: ${path} controls LeakStop's own rules and can only be changed with the user's approval. Ask the user to edit it.`
}

/** One transcript line for a finding that warns instead of holding. */
export function warnLine(path: string, finding: MaskedFinding, wouldHold: boolean): string {
  const tail = wouldHold ? ' · monitor mode: this would have been held' : ''
  return `LeakStop · ${finding.severity.toUpperCase()} · ${finding.label} in ${path}:${finding.line}${tail}`
}

// --- Bash and Read ------------------------------------------------------------

const list = (items: readonly string[], max = 5): string => {
  const shown = items.slice(0, max).join(', ')
  return items.length > max ? `${shown} and ${items.length - max} more` : shown
}

/** What the model reads when a command with a literal secret is denied. */
export function commandSecretDeny(findings: readonly MaskedFinding[]): string {
  const what = findings.slice(0, 5).map((f) => `${typeOf(f)}${hint(f)}`).join(', ')
  const name = findings[0] === undefined ? undefined : ENV_VARS[findings[0].ruleId]
  const variable = name === undefined ? 'an environment variable' : `an environment variable (for example ${name})`
  const use = name === undefined ? 'a variable' : `$${name}`
  return `LeakStop blocked this command: it contains ${what}. Keep the value in ${variable}, defined in .env (ignored by git), and refer to it as ${use} instead of writing it out.`
}

export function commandSecretQuestion(findings: readonly MaskedFinding[]): string {
  const severity = findings.some((f) => f.severity === 'critical') ? 'CRITICAL' : 'MEDIUM'
  const lines = [`LeakStop · ${severity}`]
  for (const finding of findings.slice(0, 3)) lines.push(`${finding.label} in the Bash command`, `  ${finding.masked}`)
  if (findings.length > 3) lines.push(`  …and ${findings.length - 3} more`)
  lines.push('Written out in a command, the secret stays in the session history.', '', 'How do you want to handle it?')
  return lines.join('\n')
}

/** Printing sensitive files or the environment: the values would enter the conversation. */
export function dumpQuestion(subject: string, items: readonly string[]): string {
  return [
    'LeakStop · CRITICAL',
    subject,
    `  ${list(items)}`,
    "The values would enter the model's context and the session history.",
    '',
    'How do you want to handle it?',
  ].join('\n')
}

export function fileReadDeny(files: readonly string[]): string {
  return `LeakStop blocked this command: it would print ${list(files)} into the conversation, where the values would stay in the model's context and the session history. Do not read the file. To see which variables exist, read .env.example or ask the user. To add a variable without reading the file, append it: echo 'NAME=value' >> .env`
}

export const ENV_DUMP_DENY =
  'LeakStop blocked this command: printing the whole environment would put secret values into the conversation. Ask for the specific variable you need, or list names only with: env | cut -d= -f1'

export function secretVarDeny(names: readonly string[]): string {
  return `LeakStop blocked this command: it would print the value of ${list(names)} into the conversation. Use the variable without printing it (for example by passing it to the program that needs it), or ask the user.`
}

export function gitAddQuestion(files: readonly string[]): string {
  return [
    'LeakStop · CRITICAL',
    'git add would stage files that hold secrets and are not ignored by git',
    `  ${list(files)}`,
    'They would end up in the next commit.',
    '',
    'How do you want to handle it?',
  ].join('\n')
}

export function gitAddDeny(files: readonly string[]): string {
  return `LeakStop blocked git add: ${list(files)} hold secrets and are not ignored by git. Add them to .gitignore (and run git rm --cached on any that are already tracked), then retry. Stage specific files instead of -A or . while sensitive files are not ignored.`
}

/** A commit or push that would publish a secret. The fingerprint lets the user allow that one finding. */
export function gitBlockMessage(operation: 'commit' | 'push', findings: readonly (MaskedFinding & { path: string })[]): string {
  const what = findings.slice(0, 5).map((f) => `${typeOf(f)}${hint(f)} at ${f.path}:${f.line}`).join('; ')
  const more = findings.length > 5 ? ` (and ${findings.length - 5} more)` : ''
  const subject = operation === 'commit' ? 'the staged changes add' : 'the commits to be pushed add'
  const fix =
    operation === 'commit'
      ? 'Unstage the file (git restore --staged <file>), read the value from an environment variable instead and commit again.'
      : 'Remove the secret from those commits before pushing, read it from an environment variable instead, and rotate it if it was ever shared.'
  const allow = findings.slice(0, 3).map((f) => f.fingerprint).join(' ')
  return `LeakStop blocked this git ${operation}: ${subject} ${what}${more}. ${fix} If the user wants it anyway, they can run /leakstop allow ${allow}`
}

export function readQuestion(path: string): string {
  return ['LeakStop · CRITICAL', 'Read of a sensitive file', `  ${path}`, "Its contents would enter the model's context and the session history.", '', 'How do you want to handle it?'].join('\n')
}

export function readDeny(path: string, isStrict: boolean): string {
  const never = isStrict ? ' Strict mode never allows reading sensitive files.' : ''
  return `LeakStop blocked reading ${path}: it holds secrets that would enter the conversation.${never} Do not read it; read .env.example for variable names or ask the user. To add a variable without reading the file, append it: echo 'NAME=value' >> .env`
}

/** The transcript line for something that warns instead of holding. */
export function noticeLine(what: string, isMonitor: boolean): string {
  return `LeakStop · ${what}${isMonitor ? ' · monitor mode: this would have been held' : ''}`
}

/** A recursive search that would print lines of sensitive files nobody named. */
export function searchQuestion(files: readonly string[]): string {
  return dumpQuestion('This search would print lines from files that hold secrets', files)
}

export function searchDeny(files: readonly string[]): string {
  return `LeakStop blocked this search: it would print lines from ${list(files)}, which hold secrets, into the conversation. Search specific folders such as src/ instead, or exclude those files (for example grep -r --exclude='.env*' …, or rg -g '!.env*'). To list only the files that match, use grep -rl or rg -l.`
}

// --- Outbound tools ------------------------------------------------------------

type Located = MaskedFinding & { path: string }

/** What the model reads when a call that sends something away is denied: where the secret is and what to do instead. */
export function outboundDeny(tool: string, findings: readonly Located[]): string {
  const what = findings.slice(0, 5).map((f) => `${f.path} contains ${typeOf(f)}${hint(f)}`).join('; ')
  const more = findings.length > 5 ? ` (and ${findings.length - 5} more)` : ''
  return `LeakStop blocked this ${toolLabel(tool)} call: ${what}${more}. It would be sent ${destinationOf(tool)}, and a credential that leaves the session cannot be taken back. Leave the value out: describe what is needed, or name the environment variable that holds it, and send that instead.`
}

export function outboundQuestion(tool: string, findings: readonly Located[]): string {
  const severity = findings.some((f) => f.severity === 'critical') ? 'CRITICAL' : 'MEDIUM'
  const lines = [`LeakStop · ${severity}`]
  // The tool is already named: "in Agent → prompt", not "in Agent → Agent › prompt".
  const own = `${toolLabel(tool)} › `
  for (const finding of findings.slice(0, 3)) lines.push(`${finding.label} in ${toolLabel(tool)} → ${finding.path.startsWith(own) ? finding.path.slice(own.length) : finding.path}`, `  ${finding.masked}`)
  if (findings.length > 3) lines.push(`  …and ${findings.length - 3} more`)
  lines.push(`This call would send it ${destinationOf(tool)}.`, '', 'How do you want to handle it?')
  return lines.join('\n')
}

/** A file that holds secrets named in a call that sends it away. */
export function outboundFileQuestion(tool: string, files: readonly string[]): string {
  return ['LeakStop · CRITICAL', `${toolLabel(tool)} would send files that hold secrets`, `  ${list(files)}`, `Their contents would go ${destinationOf(tool)}.`, '', 'How do you want to handle it?'].join('\n')
}

export function outboundFileDeny(tool: string, files: readonly string[]): string {
  return `LeakStop blocked this ${toolLabel(tool)} call: ${list(files)} hold secrets and would be sent ${destinationOf(tool)}. Do not send them. Send a copy without the secrets (for example .env.example with the values removed), or ask the user.`
}

// --- Tool output -----------------------------------------------------------------

/** What the model reads after an output in which LeakStop masked secrets. */
export function maskedContext(tool: string, findings: readonly MaskedFinding[]): string {
  const what = findings.slice(0, 5).map(typeOf).join(', ')
  const more = findings.length > 5 ? ` (and ${findings.length - 5} more)` : ''
  return `LeakStop masked ${what}${more} in the output of this ${tool} call: the value never reached you and is not in the transcript. Do not try to print or read it another way; if the task needs it, use it from an environment variable or ask the user.`
}

/** The line above the prompt when an output carried a secret. */
export function maskedLine(tool: string, finding: MaskedFinding, isMonitor: boolean): string {
  return `LeakStop · ${finding.severity.toUpperCase()} · ${finding.label} in the output of ${tool}${isMonitor ? ' · monitor mode: this would have been masked' : ' · masked'}`
}

/** Instead of an output LeakStop could not check after the tool ran. */
export const OUTPUT_FAILURE = 'LeakStop could not check the output of this call, so it was withheld. The call did run; do not run it again just to see its output.'

/** What the model reads after a message in which LeakStop masked a pasted secret. */
export function promptMaskedContext(findings: readonly MaskedFinding[]): string {
  const what = findings.slice(0, 5).map(typeOf).join(', ')
  return `LeakStop masked ${what} that the user pasted into this message: the value never reached you. If the task needs it, ask the user to put it in an environment variable or a git-ignored file instead of the chat.`
}
