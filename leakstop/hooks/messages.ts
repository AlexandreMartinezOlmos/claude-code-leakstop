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
