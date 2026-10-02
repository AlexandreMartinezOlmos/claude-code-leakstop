// What LeakStop says: the hold question and the denial message. Pure: no `$`.
//
// Everything here is built from a MaskedFinding, so no complete secret can
// reach the interface or the model. The most that appears is the rule's
// identifying prefix and the last three characters.

import { classifyPath } from './detect.ts'
import type { MaskedFinding } from './mask.ts'

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
  return `LeakStop blocked this command: it would print ${list(files)} into the conversation, where the values would stay in the model's context and the session history. Do not read the file. To see which variables exist, read .env.example or ask the user.`
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
  return `LeakStop blocked reading ${path}: it holds secrets that would enter the conversation.${never} Do not read it; read .env.example for variable names or ask the user.`
}

/** The transcript line for something that warns instead of holding. */
export function noticeLine(what: string, isMonitor: boolean): string {
  return `LeakStop · ${what}${isMonitor ? ' · monitor mode: this would have been held' : ''}`
}
