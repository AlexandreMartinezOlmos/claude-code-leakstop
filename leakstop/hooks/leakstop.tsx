// LeakStop: the hooks module. Every use of `$` lives in this file; detection,
// masking, policy, command analysis and messages are pure modules that never
// receive it.
//
// Rules this file keeps:
// - Every `$` call is spelled in full, and event names are string literals.
// - A hook that can deny has a `.catch` that denies (monitor mode: lets it go).
// - Nothing that holds a secret is stored, logged or shown: findings are turned
//   into MaskedFindings first, and only those cross into `$`.
// - It never approves a call on its own: `next(e)` after a pass leaves the
//   user's permissions and rules in force.

import type { EngineInterface, Register, ToolCallInput } from 'claude-code'

import type { Decision, StoredConfig, StoredFinding } from '../types'
import { analyzeCommand } from './commands.ts'
import { EMPTY_CONFIG, matchesAny, parseConfig, toRule } from './config.ts'
import type { CommandFacts, GitOp } from './commands.ts'
import { classifyPath, scanEdit, scanText, scanWrite } from './detect.ts'
import type { Finding, Rule, ScanResult } from './detect.ts'
import { scanDiff } from './diff.ts'
import type { DiffFinding } from './diff.ts'
import { describe, fingerprint } from './mask.ts'
import type { MaskedFinding } from './mask.ts'
import * as say from './messages.ts'
import type { WriteTool } from './messages.ts'
import { collect, toolLabel } from './outbound.ts'
import { decide, decideAll } from './policy.ts'
import type { Action, Destination, Mode } from './policy.ts'
import { USAGE, allowedText, bannerLine, fit, historyRows, mergeAllowed, parseArgs, resolveIds, summaryText } from './ui.ts'

const { USE_ENV, ALLOW_ONCE, CANCEL, SHOW_NAMES, ADD_GITIGNORE } = say

const MAX_FINDINGS = 100
const MAX_ALLOW_ONCE = 500
const MAX_UNTRACKED_READ = 200
const GIT_TIMEOUT_MS = 20000

const findingsRef = { plugin: 'leakstop', key: 'findings' } as const
const allowOnceRef = { plugin: 'leakstop', key: 'allowOnce' } as const
const pausedRef = { plugin: 'leakstop', key: 'paused' } as const
const bannerRef = { plugin: 'leakstop', key: 'banner' } as const
const configRef = { plugin: 'leakstop', key: 'config' } as const

const PANE = 'leakstop'
const MAX_BANNER = 5
const MAX_ALLOWED_FOREVER = 1000

/** What is kept about a finding or a sensitive operation: never a value. */
type Note = Pick<MaskedFinding, 'fingerprint' | 'ruleId' | 'label' | 'severity' | 'line'> & { path?: string }

/** The outcome of a check: nothing to say, a denial, or a rewritten command. */
type Verdict = { deny: string } | { command: string } | undefined

// --- Helpers that take `$` (top-level functions of this file) ---------------

/** True when git ignores `path`. Anything unexpected (not a repo, no git) reads as "not ignored". */
async function isIgnored($: EngineInterface, path: string): Promise<boolean> {
  try {
    const result = await $.process.run(['git', 'check-ignore', '-q', '--', path], { timeoutMs: 5000 })
    return result.exitCode === 0
  } catch {
    return false
  }
}

async function sessionCwd($: EngineInterface): Promise<string | undefined> {
  try {
    return await $.session.cwd()
  } catch {
    return undefined
  }
}

/** Line of `oldString` in the file on disk, so an Edit's findings point at real lines. 0 when unknown. */
async function lineOffset($: EngineInterface, path: string, oldString: string): Promise<number> {
  if (oldString === '') return 0
  try {
    const content = await $.fs.read(path)
    if (typeof content !== 'string') return 0
    const index = content.indexOf(oldString)
    if (index < 0) return 0
    let lines = 0
    for (let i = 0; i < index; i++) if (content.charCodeAt(i) === 10) lines++
    return lines
  } catch {
    return 0
  }
}

async function record($: EngineInterface, tool: string, path: string, notes: readonly Note[], decision: Decision): Promise<void> {
  const at = await $.clock.now()
  const entries: StoredFinding[] = notes.map((n) => ({
    fingerprint: n.fingerprint,
    ruleId: n.ruleId,
    label: n.label,
    severity: n.severity,
    path: n.path ?? path,
    line: n.line,
    tool,
    decision,
    at,
  }))
  const { value = [] } = await $.state.get(findingsRef)
  await $.state.set(findingsRef, [...value, ...entries].slice(-MAX_FINDINGS))
  if (decision === 'warned') {
    const { value: banner = [] } = await $.state.get(bannerRef)
    await $.state.set(bannerRef, [...banner, ...entries].slice(-MAX_BANNER))
  }
}

/** True where a banner can be drawn: the terminal and the desktop app. The VS Code panel and `claude -p` draw nothing. */
async function drawsBanner($: EngineInterface): Promise<boolean> {
  try {
    const surfaces = await $.session.surfaces()
    return surfaces.some((surface) => surface === 'terminal' || surface === 'desktop')
  } catch {
    return false
  }
}

async function clearBanner($: EngineInterface): Promise<void> {
  const { value = [] } = await $.state.get(bannerRef)
  if (value.length > 0) await $.state.set(bannerRef, [])
}

async function setPaused($: EngineInterface, paused: boolean): Promise<void> {
  await $.state.set(pausedRef, paused)
}

/** Allows findings for good: the store is shared by every session on the machine. */
async function allowForever($: EngineInterface, fingerprints: readonly string[]): Promise<void> {
  const stored = await $.store.get('allowFingerprints')
  const current = Array.isArray(stored) ? stored.filter((x): x is string => typeof x === 'string') : []
  await $.store.set('allowFingerprints', [...new Set([...current, ...fingerprints])].slice(-MAX_ALLOWED_FOREVER))
}

async function rememberAllowOnce($: EngineInterface, fingerprints: readonly string[]): Promise<void> {
  const { value = [] } = await $.state.get(allowOnceRef)
  await $.state.set(allowOnceRef, [...new Set([...value, ...fingerprints])].slice(-MAX_ALLOW_ONCE))
}

/** Reads the project's `.leakstop.json` (at session start and on `/leakstop reload`). A missing file is not a problem; a bad one is reported and the defaults apply. */
async function loadConfig($: EngineInterface): Promise<StoredConfig> {
  let config: StoredConfig = EMPTY_CONFIG
  let exists = false
  try {
    exists = await $.fs.exists('.leakstop.json')
  } catch {
    exists = false
  }
  if (exists) {
    try {
      const content = await $.fs.read('.leakstop.json')
      config = typeof content === 'string' ? parseConfig(content) : { ...EMPTY_CONFIG, warnings: ['.leakstop.json could not be read as text, so the defaults apply'] }
    } catch {
      config = { ...EMPTY_CONFIG, warnings: ['.leakstop.json could not be read (is it over 4 MiB?), so the defaults apply'] }
    }
  }
  await $.state.set(configRef, config)
  return config
}

async function getConfig($: EngineInterface): Promise<StoredConfig> {
  const { value } = await $.state.get(configRef)
  return value ?? EMPTY_CONFIG
}

/** The project's custom rules, compiled. */
const customRules = (config: StoredConfig): Rule[] => config.customRules.map(toRule).filter((rule): rule is Rule => rule !== undefined)

/** Medium findings in a path the project told us to ignore are dropped; critical ones never are. */
const isRelaxed = (config: StoredConfig, severity: string, path: string): boolean => severity === 'medium' && matchesAny(path, config.ignorePaths)

/** What is allowed, by where it came from: this session, the user for good (the machine-wide store) and the project. */
async function allowedSources($: EngineInterface, config: StoredConfig): Promise<{ session: string[]; forever: string[]; project: string[] }> {
  const { value: session = [] } = await $.state.get(allowOnceRef)
  let stored: unknown
  try {
    stored = await $.store.get('allowFingerprints')
  } catch {
    stored = undefined
  }
  const forever = Array.isArray(stored) ? stored.filter((x): x is string => typeof x === 'string') : []
  return { session, forever, project: config.allowFingerprints }
}

/** Fingerprints allowed for this session, the ones the user allowed for good and the ones the project allows. */
async function allowedFingerprints($: EngineInterface, config: StoredConfig): Promise<Set<string>> {
  const { session, forever, project } = await allowedSources($, config)
  return new Set([...session, ...forever, ...project])
}

/** Stops allowing `fingerprints` (every one of the user's when `undefined`); the project's own list is not touched. Returns what was removed. */
async function forgetAllowed($: EngineInterface, fingerprints: readonly string[] | undefined): Promise<{ session: string[]; forever: string[] }> {
  const { session, forever } = await allowedSources($, EMPTY_CONFIG)
  const drop = (list: readonly string[]): string[] => (fingerprints === undefined ? [...list] : list.filter((f) => fingerprints.includes(f)))
  const removed = { session: drop(session), forever: drop(forever) }
  if (removed.session.length > 0) await $.state.set(allowOnceRef, session.filter((f) => !removed.session.includes(f)))
  if (removed.forever.length > 0) {
    const kept = forever.filter((f) => !removed.forever.includes(f))
    if (kept.length > 0) await $.store.set('allowFingerprints', kept)
    else await $.store.delete('allowFingerprints')
  }
  return removed
}

/** The user's answer, or `undefined` when nobody could answer (dismissed, `claude -p`, no interface). */
async function askUser($: EngineInterface, question: string, options: readonly string[]): Promise<string | undefined> {
  try {
    return await $.ui.ask(question, { options, header: 'LeakStop' })
  } catch {
    return undefined
  }
}

type Spec = {
  action: Action
  tool: string
  path: string
  notes: readonly Note[]
  question: string
  options: readonly string[]
  deny: string
  /** Transcript lines for a warning. */
  warn: readonly string[]
  /** The command to run instead when the user picks "Show names only". */
  rewrite?: string
}

/** Carries out the policy's action: pass, warn, hold (ask) or block. `undefined` means the call may go on. */
async function settle($: EngineInterface, spec: Spec): Promise<Verdict> {
  switch (spec.action) {
    case 'pass':
      await record($, spec.tool, spec.path, spec.notes, 'passed')
      return undefined
    case 'warn':
      // Where a banner is drawn it says it; where nothing is drawn, the transcript does.
      if (!(await drawsBanner($))) for (const line of spec.warn) $.ui.log(line)
      await record($, spec.tool, spec.path, spec.notes, 'warned')
      return undefined
    case 'hold': {
      const answer = await askUser($, spec.question, spec.options)
      if (answer === ALLOW_ONCE) {
        await rememberAllowOnce($, spec.notes.map((n) => n.fingerprint))
        await record($, spec.tool, spec.path, spec.notes, 'allowed')
        return undefined
      }
      if (answer === SHOW_NAMES && spec.rewrite !== undefined) {
        await record($, spec.tool, spec.path, spec.notes, 'allowed')
        return { command: spec.rewrite }
      }
      await record($, spec.tool, spec.path, spec.notes, 'denied')
      return { deny: `${say.answerNote(answer)} ${spec.deny}` }
    }
    case 'block':
      await record($, spec.tool, spec.path, spec.notes, 'denied')
      return { deny: spec.deny }
  }
}

/** A sensitive operation (no secret value to fingerprint) as a Note, identified by what it is about. */
async function operation(ruleId: string, label: string, about: string): Promise<Note> {
  return { fingerprint: await fingerprint(about), ruleId, label, severity: 'critical', line: 0 }
}

/** Editing LeakStop's own configuration is always held: otherwise Claude could allowlist its own findings. */
async function checkConfig($: EngineInterface, tool: string, shownPath: string, mode: Mode): Promise<Verdict> {
  if (decide('config-edit', 'critical', mode) !== 'hold') {
    $.ui.log(say.noticeLine(`the change to ${shownPath} would have been held`, false))
    return undefined
  }
  const answer = await askUser($, say.configQuestion(shownPath), [ALLOW_ONCE, CANCEL])
  if (answer === ALLOW_ONCE) return undefined
  await record($, tool, shownPath, [await operation('config-edit', 'LeakStop configuration change', `config:${shownPath}`)], 'denied')
  return { deny: `${say.answerNote(answer)} ${say.configDenyMessage(shownPath)}` }
}

/** True when the file is sensitive by path and, for `.npmrc` and `.pypirc`, holds a token. */
async function isSensitiveFile($: EngineInterface, path: string, dir?: string): Promise<boolean> {
  const kind = classifyPath(path)
  if (kind === undefined) return false
  if (!kind.requiresToken) return true
  try {
    const content = await $.fs.read(dir === undefined || path.startsWith('/') ? path : `${dir}/${path}`)
    return typeof content === 'string' && scanText(content, { path }).findings.length > 0
  } catch {
    return false
  }
}

async function git($: EngineInterface, args: readonly string[], dir?: string): Promise<{ isOk: boolean; stdout: string; isTruncated: boolean }> {
  const init = dir === undefined ? { timeoutMs: GIT_TIMEOUT_MS } : { cwd: dir, timeoutMs: GIT_TIMEOUT_MS }
  const result = await $.process.run(['git', ...args], init)
  return { isOk: result.exitCode === 0, stdout: result.stdout, isTruncated: result.isStdoutTruncated }
}

const names = (output: string): string[] => output.split('\0').filter((name) => name !== '')

const normalize = (path: string): string => path.replace(/^\.\//, '').replace(/\/+$/, '')

const isInScope = (file: string, paths: readonly string[]): boolean => paths.some((p) => file === normalize(p) || file.startsWith(`${normalize(p)}/`))

// --- Bash checks -------------------------------------------------------------

/** A literal secret inside the command: a `curl` header, an `export`, a `--build-arg`, a heredoc. */
async function checkSecrets($: EngineInterface, command: string, mode: Mode, allowed: ReadonlySet<string>, config: StoredConfig, writeTargets?: readonly string[]): Promise<Verdict> {
  const scan = scanText(command, { extraRules: customRules(config) })
  if (scan.isPartial) $.ui.log('LeakStop: the custom rules were too slow and did not cover the whole command')
  const found = scan.findings
  if (found.length === 0) return undefined
  const masked = (await Promise.all(found.map(describe))).filter((f) => !allowed.has(f.fingerprint))
  if (masked.length === 0) return undefined
  // `cat > .env <<EOF … EOF` or `echo KEY=… >> .env` into files git ignores is where a secret belongs.
  let destination: Destination = 'command'
  if (writeTargets !== undefined) {
    const ignored = await Promise.all(writeTargets.map((target) => isIgnored($, target)))
    if (ignored.every(Boolean)) destination = 'ignored-file'
  }
  const action = decideAll(destination, masked.map((f) => f.severity), mode)
  return settle($, {
    action,
    tool: 'Bash',
    path: '',
    notes: masked,
    question: say.commandSecretQuestion(masked),
    options: [USE_ENV, ALLOW_ONCE, CANCEL],
    deny: say.commandSecretDeny(masked),
    warn: masked.map((f) => say.noticeLine(`${f.severity.toUpperCase()} · ${f.label} in a command`, mode === 'monitor')),
  })
}

/** Printing sensitive files, the whole environment or a secret variable into the conversation. */
async function checkSensitive($: EngineInterface, facts: CommandFacts, mode: Mode, allowed: ReadonlySet<string>): Promise<Verdict> {
  const action = decide('sensitive-dump', 'critical', mode)
  let command: string | undefined

  const files: string[] = []
  for (const file of facts.readFiles) if (await isSensitiveFile($, file)) files.push(file)
  const fileNotes = await Promise.all(files.map((file) => operation('sensitive-file-read', 'Sensitive file printed', `path:${file}`)))
  const pendingFiles = files.filter((_, i) => !allowed.has((fileNotes[i] as Note).fingerprint))
  if (pendingFiles.length > 0) {
    const notes = fileNotes.filter((n) => !allowed.has(n.fingerprint))
    const verdict = await settle($, {
      action,
      tool: 'Bash',
      path: pendingFiles.join(', '),
      notes,
      question: say.dumpQuestion('This command would print files that hold secrets', pendingFiles),
      options: facts.namesOnly === undefined ? [ALLOW_ONCE, CANCEL] : [SHOW_NAMES, ALLOW_ONCE, CANCEL],
      deny: say.fileReadDeny(pendingFiles),
      warn: [say.noticeLine(`${pendingFiles.join(', ')} would be printed`, mode === 'monitor')],
      rewrite: facts.namesOnly,
    })
    if (verdict !== undefined && 'deny' in verdict) return verdict
    if (verdict !== undefined) command = verdict.command
  }

  if (facts.isEnvDump) {
    const note = await operation('environment-dump', 'Environment printed', 'env-dump')
    if (!allowed.has(note.fingerprint)) {
      const verdict = await settle($, {
        action,
        tool: 'Bash',
        path: 'environment',
        notes: [note],
        question: say.dumpQuestion('This command would print the whole environment', ['printenv / env']),
        options: facts.namesOnly === undefined ? [ALLOW_ONCE, CANCEL] : [SHOW_NAMES, ALLOW_ONCE, CANCEL],
        deny: say.ENV_DUMP_DENY,
        warn: [say.noticeLine('the whole environment would be printed', mode === 'monitor')],
        rewrite: facts.namesOnly,
      })
      if (verdict !== undefined && 'deny' in verdict) return verdict
      if (verdict !== undefined) command = verdict.command
    }
  }

  if (facts.secretVars.length > 0) {
    const notes = await Promise.all(facts.secretVars.map((name) => operation('secret-variable-print', 'Secret variable printed', `env-var:${name}`)))
    const pending = facts.secretVars.filter((_, i) => !allowed.has((notes[i] as Note).fingerprint))
    if (pending.length > 0) {
      const verdict = await settle($, {
        action,
        tool: 'Bash',
        path: pending.join(', '),
        notes: notes.filter((n) => !allowed.has(n.fingerprint)),
        question: say.dumpQuestion('This command would print secret variables', pending),
        options: [ALLOW_ONCE, CANCEL],
        deny: say.secretVarDeny(pending),
        warn: [say.noticeLine(`${pending.join(', ')} would be printed`, mode === 'monitor')],
      })
      if (verdict !== undefined && 'deny' in verdict) return verdict
    }
  }

  return command === undefined ? undefined : { command }
}

/** Sensitive files a recursive search could reach, found by looking in the folders it was given. */
const FIND_SENSITIVE: readonly string[] = [
  '(',
  ...['.env', '.env.*', '*.env', '*.pem', '*.key', '*.p12', '*.pfx', 'id_rsa*', 'id_dsa*', 'id_ecdsa*', 'id_ed25519*', 'credentials.json', 'service-account*.json', '*.tfstate', '*.tfstate.backup'].flatMap((name, i) => (i === 0 ? ['-name', name] : ['-o', '-name', name])),
  ')',
  '-type',
  'f',
  '-not',
  '-path',
  '*/node_modules/*',
  '-not',
  '-path',
  '*/.git/*',
]

/** `grep -r KEY .` reads `.env` too: grep ignores .gitignore and hidden-file rules. Hold when a sensitive file is within reach. */
async function checkSearch($: EngineInterface, search: Search, mode: Mode, allowed: ReadonlySet<string>): Promise<Verdict> {
  const found: string[] = []
  for (const dir of search.dirs.slice(0, 5)) {
    try {
      const result = await $.process.run(['find', dir, '-maxdepth', '8', ...FIND_SENSITIVE], { timeoutMs: 5000 })
      for (const file of names(result.stdout.replace(/\n/g, '\0'))) found.push(file.replace(/^\.\//, ''))
    } catch {
      // A folder that cannot be listed (or takes too long) is not a reason to block the search.
    }
  }
  const candidates = [...new Set(found)]
    .filter((file) => classifyPath(file) !== undefined && classifyPath(file)?.requiresToken === false)
    .filter((file) => !matchesAny(file, search.excludes))
    .filter((file) => search.includes.length === 0 || matchesAny(file, search.includes))
    .slice(0, 20)
  // A search that honours .gitignore never opens the files git ignores (a plain .env).
  const reach: string[] = []
  for (const file of candidates) if (!(search.respectsIgnore && (await isIgnored($, file)))) reach.push(file)
  if (reach.length === 0) return undefined

  const note = await operation('sensitive-search', 'Search through sensitive files', `search:${[...reach].sort().join('\n')}`)
  if (allowed.has(note.fingerprint)) return undefined
  return settle($, {
    action: decide('sensitive-dump', 'critical', mode),
    tool: 'Bash',
    path: reach.join(', '),
    notes: [note],
    question: say.searchQuestion(reach),
    options: [ALLOW_ONCE, CANCEL],
    deny: say.searchDeny(reach),
    warn: [say.noticeLine(`a search would print lines from ${reach.join(', ')}`, mode === 'monitor')],
  })
}

/** `git add -A` or `.` (or a named path) that would stage sensitive files git does not ignore. */
async function checkGitAdd($: EngineInterface, op: Extract<GitOp, { kind: 'add' }>, mode: Mode, allowed: ReadonlySet<string>): Promise<Verdict> {
  const untracked = await git($, ['ls-files', '--others', '--exclude-standard', '-z'], op.dir)
  const modified = await git($, ['diff', '--name-only', '-z'], op.dir)
  if (!untracked.isOk && !modified.isOk) return undefined
  const candidates = [...new Set([...names(untracked.stdout), ...names(modified.stdout)])].filter((file) => op.isAll || isInScope(file, op.paths))

  const sensitive: string[] = []
  for (const file of candidates.slice(0, 1000)) if (await isSensitiveFile($, file, op.dir)) sensitive.push(file)
  if (sensitive.length === 0) return undefined

  const note = await operation('git-add-sensitive', 'Sensitive files staged', `git-add:${[...sensitive].sort().join('\n')}`)
  if (allowed.has(note.fingerprint)) return undefined
  return settle($, {
    action: decide('git-add', 'critical', mode),
    tool: 'Bash',
    path: sensitive.join(', '),
    notes: [note],
    question: say.gitAddQuestion(sensitive),
    options: [ADD_GITIGNORE, ALLOW_ONCE, CANCEL],
    deny: say.gitAddDeny(sensitive),
    warn: [say.noticeLine(`git add would stage ${sensitive.join(', ')}`, mode === 'monitor')],
  })
}

type Pending = { findings: DiffFinding[]; isTruncated: boolean }

/** What a commit is about to contain: the staged diff and, when the command stages first, the rest. */
async function pendingForCommit($: EngineInterface, op: Extract<GitOp, { kind: 'commit' }>, config: StoredConfig): Promise<Pending> {
  const cached = await git($, ['diff', '--cached', '--no-color', '-U0'], op.dir)
  if (!cached.isOk) return { findings: [], isTruncated: false }
  const diffs = [cached.stdout]
  let isTruncated = cached.isTruncated

  const stagesAll = op.staging.some((s) => s.isAll)
  const stagedPaths = op.staging.flatMap((s) => (s.isAll ? [] : s.paths))
  // `-a`, or a `git add` earlier in the same command, stages tracked changes that are not staged yet.
  if (op.isAll || stagesAll) {
    const unstaged = await git($, ['diff', '--no-color', '-U0'], op.dir)
    if (unstaged.isOk) diffs.push(unstaged.stdout)
    isTruncated ||= unstaged.isTruncated
  } else if (stagedPaths.length > 0) {
    const unstaged = await git($, ['diff', '--no-color', '-U0', '--', ...stagedPaths], op.dir)
    if (unstaged.isOk) diffs.push(unstaged.stdout)
    isTruncated ||= unstaged.isTruncated
  }

  const extraRules = customRules(config)
  const findings = scanDiff(diffs.join('\n'), extraRules).findings

  // New files that an earlier `git add` in the same command would stage.
  if (stagesAll || stagedPaths.length > 0) {
    const untracked = await git($, ['ls-files', '--others', '--exclude-standard', '-z'], op.dir)
    const files = names(untracked.stdout).filter((file) => stagesAll || isInScope(file, stagedPaths))
    for (const file of files.slice(0, MAX_UNTRACKED_READ)) {
      try {
        const content = await $.fs.read(op.dir === undefined ? file : `${op.dir}/${file}`)
        if (typeof content === 'string') for (const finding of scanText(content, { path: file, extraRules }).findings) findings.push({ ...finding, path: file })
      } catch {
        // Unreadable or over 4 MiB: skipped, as the spec says.
      }
    }
  }
  return { findings, isTruncated }
}

/** What a push is about to publish: the added lines of every commit no remote has. */
async function pendingForPush($: EngineInterface, op: Extract<GitOp, { kind: 'push' }>, config: StoredConfig): Promise<Pending> {
  const log = await git($, ['log', '-p', '--no-color', '--format=', 'HEAD', '--not', '--remotes'], op.dir)
  if (!log.isOk) return { findings: [], isTruncated: false }
  return { findings: scanDiff(log.stdout, customRules(config)).findings, isTruncated: log.isTruncated }
}

/** Secrets in what is about to be committed or pushed: blocked without asking. */
async function checkPublish($: EngineInterface, kind: 'commit' | 'push', pending: Pending, mode: Mode, allowed: ReadonlySet<string>, config: StoredConfig): Promise<Verdict> {
  if (pending.isTruncated) $.ui.log('LeakStop: the diff is larger than 4 MiB, so only the first 4 MiB was scanned')
  if (pending.findings.length === 0) return undefined
  const described = await Promise.all(pending.findings.map(async (f) => ({ ...(await describe(f)), path: f.path })))
  const masked = described.filter((f) => !allowed.has(f.fingerprint) && !isRelaxed(config, f.severity, f.path))
  if (masked.length === 0) return undefined
  const destination: Destination = kind === 'commit' ? 'git-commit' : 'git-push'
  return settle($, {
    action: decideAll(destination, masked.map((f) => f.severity), mode),
    tool: 'Bash',
    path: '',
    notes: masked,
    question: '',
    options: [],
    deny: say.gitBlockMessage(kind, masked),
    warn: masked.map((f) => say.noticeLine(`${f.severity.toUpperCase()} · ${f.label} in ${f.path}:${f.line} (git ${kind})`, mode === 'monitor')),
  })
}

async function checkGit($: EngineInterface, op: GitOp, mode: Mode, allowed: ReadonlySet<string>, config: StoredConfig): Promise<Verdict> {
  if (op.kind === 'add') return checkGitAdd($, op, mode, allowed)
  if (op.kind === 'commit') return checkPublish($, 'commit', await pendingForCommit($, op, config), mode, allowed, config)
  return checkPublish($, 'push', await pendingForPush($, op, config), mode, allowed, config)
}

// --- Outbound tools ------------------------------------------------------------

/** Secrets in what a tool sends away: the web, another agent or session, a published page, an MCP server. */
async function guardOutbound($: EngineInterface, e: ToolCallInput, mode: Mode): Promise<Verdict> {
  const { value: paused = false } = await $.state.get(pausedRef)
  if (paused) return undefined

  const tool = e.tool
  const label = toolLabel(tool)
  const config = await getConfig($)
  const allowed = await allowedFingerprints($, config)
  const rules = customRules(config)
  const out = collect(e as unknown as Record<string, unknown>)
  if (out.isTruncated) $.ui.log(`LeakStop: ${label} carries more than LeakStop reads, so only part of it was scanned`)

  const found: (Finding & { path: string })[] = []
  for (const part of out.texts) {
    const scan = scanText(part.text, { extraRules: rules })
    if (scan.isSkipped) $.ui.log(`LeakStop: ${label} ${part.field} is larger than 4 MiB and was not scanned`)
    if (scan.isPartial) $.ui.log(`LeakStop: the custom rules were too slow and did not cover ${label} ${part.field}`)
    // The place is the argument, not a line: it is not a file.
    for (const finding of scan.findings) found.push({ ...finding, line: 0, path: `${label} › ${part.field}` })
  }

  // Files the call sends: sensitive ones are held as they are, the rest are read and scanned.
  const sensitive: string[] = []
  for (const file of out.files) {
    if (await isSensitiveFile($, file)) {
      sensitive.push(file)
      continue
    }
    try {
      const content = await $.fs.read(file)
      if (typeof content !== 'string') continue
      const scan = scanText(content, { path: file, extraRules: rules })
      if (scan.isSkipped) $.ui.log(`LeakStop: ${file} is larger than 4 MiB and was not scanned`)
      for (const finding of scan.findings) found.push({ ...finding, path: file })
    } catch {
      // Unreadable or over 4 MiB: it cannot be checked, and the tool will say if it cannot read it either.
    }
  }

  const fileNotes = await Promise.all(sensitive.map((file) => operation('sensitive-file-send', 'Sensitive file sent', `path:${file}`)))
  const pendingFiles = sensitive.filter((_, i) => !allowed.has((fileNotes[i] as Note).fingerprint))
  if (pendingFiles.length > 0) {
    const verdict = await settle($, {
      action: decide('sensitive-dump', 'critical', mode),
      tool,
      path: pendingFiles.join(', '),
      notes: fileNotes.filter((n) => !allowed.has(n.fingerprint)),
      question: say.outboundFileQuestion(tool, pendingFiles),
      options: [ALLOW_ONCE, CANCEL],
      deny: say.outboundFileDeny(tool, pendingFiles),
      warn: [say.noticeLine(`${label} would send ${pendingFiles.join(', ')}`, mode === 'monitor')],
    })
    if (verdict !== undefined && 'deny' in verdict) return verdict
  }

  if (found.length === 0) return undefined
  const described = await Promise.all(found.map(async (f) => ({ ...(await describe(f)), path: f.path })))
  const masked = described.filter((f) => !allowed.has(f.fingerprint) && !isRelaxed(config, f.severity, f.path))
  if (masked.length === 0) return undefined
  return settle($, {
    action: decideAll('outbound', masked.map((f) => f.severity), mode),
    tool,
    path: '',
    notes: masked,
    question: say.outboundQuestion(tool, masked),
    options: [ALLOW_ONCE, CANCEL],
    deny: say.outboundDeny(tool, masked),
    warn: masked.map((f) => say.noticeLine(`${f.severity.toUpperCase()} · ${f.label} in ${f.path}`, mode === 'monitor')),
  })
}

// --- Pure helpers of this file (no `$`) -------------------------------------

type Call = { tool: WriteTool; path: string; result: ScanResult; oldString?: string }

/** What the write is about to put on disk, scanned. `undefined`: nothing is written. */
function scanCall(e: ToolCallInput, extraRules: readonly Rule[]): Call | undefined {
  switch (e.tool) {
    case 'Write':
      return { tool: 'Write', path: e.file_path, result: scanWrite(e.file_path, e.content, { extraRules }) }
    case 'Edit':
      return { tool: 'Edit', path: e.file_path, result: scanEdit(e.file_path, e.old_string, e.new_string, { extraRules }), oldString: e.old_string }
    case 'NotebookEdit':
      return typeof e.new_source === 'string'
        ? { tool: 'NotebookEdit', path: e.notebook_path, result: scanText(e.new_source, { path: e.notebook_path, extraRules }) }
        : undefined
    default:
      return undefined
  }
}

const isConfigPath = (path: string): boolean => (path.split(/[\\/]/).pop() ?? '') === '.leakstop.json'

type Failure = { called: boolean; error: { kind: string } }

/** Fail closed: a hook that throws or runs out of time is skipped and the call would go on. Monitor mode never blocks. */
function onFailure(mode: Mode, next: Failure): { deny: string } | undefined {
  if (mode === 'monitor' || next.called) return undefined
  return { deny: `LeakStop could not check this call (${next.error.kind}), so it was blocked. Try again, or ask the user to review it.` }
}

// --- The module -------------------------------------------------------------

export const register: Register = (on, options) => {
  const mode: Mode = options.mode === 'monitor' || options.mode === 'strict' ? options.mode : 'standard'

  on('session.start', async ($, e, next) => {
    await $.command.register({ name: 'leakstop', description: 'Show LeakStop findings, pause or resume protection, or allow a finding' })
    const config = await loadConfig($)
    for (const warning of config.warnings.slice(0, 5)) $.ui.log(`LeakStop: .leakstop.json: ${warning}`)
    return next(e)
  })

  // A warning stays above the prompt until the user's next message. A background agent finishing, a peer
  // session or a schedule also submit prompts: they are not the user reading the warning.
  on('prompt.submit', async ($, e, next) => {
    if (e.origin?.kind === 'composer' || e.origin?.kind === 'bridge') await clearBanner($)
    return next(e)
  })

  on('command.run', { command: 'leakstop' }, async ($, e) => {
    const args = parseArgs(e.args)
    const { value: findings = [] } = await $.state.get(findingsRef)
    const { value: paused = false } = await $.state.get(pausedRef)
    const config = await getConfig($)

    if (args.kind === 'open') {
      await clearBanner($)
      let isPlaced = false
      try {
        isPlaced = (await $.ui.open({ id: PANE, title: 'LeakStop', focus: true })).isPlaced
      } catch {
        isPlaced = false
      }
      // Where nothing is drawn (the VS Code panel) a "placed" panel is invisible: say it in text.
      const isShown = isPlaced && (await drawsBanner($))
      return isShown ? {} : { text: summaryText(findings, paused, config.warnings) }
    }
    if (args.kind === 'usage') return { text: USAGE }
    if (args.kind === 'allowed') {
      const { session, forever, project } = await allowedSources($, config)
      return { text: allowedText(mergeAllowed(session, forever, project), findings) }
    }

    // Changing what LeakStop checks is the user's call. A command that did not
    // come from the person (a task, a peer session, another plugin) is refused.
    if (e.origin?.kind !== 'composer' && e.origin?.kind !== 'bridge') {
      return { text: `LeakStop: /leakstop ${args.kind} only works when you type it yourself.` }
    }
    if (args.kind === 'pause') {
      await setPaused($, true)
      return { text: 'LeakStop paused: nothing is checked until you run /leakstop resume. Changes to .leakstop.json are still held.' }
    }
    if (args.kind === 'resume') {
      await setPaused($, false)
      return { text: 'LeakStop resumed.' }
    }
    if (args.kind === 'reload') {
      const reloaded = await loadConfig($)
      const parts = [`${reloaded.customRules.length} custom rule${reloaded.customRules.length === 1 ? '' : 's'}`, `${reloaded.ignorePaths.length} ignored path${reloaded.ignorePaths.length === 1 ? '' : 's'}`, `${reloaded.allowFingerprints.length} allowed fingerprint${reloaded.allowFingerprints.length === 1 ? '' : 's'}`]
      const notes = reloaded.warnings.slice(0, 5).map((warning) => `.leakstop.json: ${warning}`)
      return { text: [`LeakStop reloaded .leakstop.json: ${parts.join(', ')}.`, ...notes].join('\n') }
    }
    if (args.kind === 'forget') {
      const isAll = args.ids.length === 1 && args.ids[0]?.toLowerCase() === 'all'
      const { fingerprints, unknown } = isAll ? { fingerprints: undefined, unknown: [] as string[] } : resolveIds(args.ids, findings)
      const removed = await forgetAllowed($, fingerprints)
      const count = new Set([...removed.session, ...removed.forever]).size
      const kept = (fingerprints ?? config.allowFingerprints).filter((f) => config.allowFingerprints.includes(f))
      const done = count > 0 ? `Stopped allowing ${count} finding${count === 1 ? '' : 's'}: ${[...new Set([...removed.session, ...removed.forever])].join(' ')}.` : 'Nothing of yours was allowed, so nothing changed.'
      const notes = [
        ...(kept.length > 0 ? [`Still allowed by .leakstop.json (edit that file to remove): ${kept.join(' ')}.`] : []),
        ...(unknown.length > 0 ? [`Not recognised: ${unknown.join(', ')}.`] : []),
      ]
      return { text: [done, ...notes, ...(unknown.length > 0 ? [USAGE] : [])].join('\n') }
    }
    const { fingerprints, unknown } = resolveIds(args.ids, findings)
    if (fingerprints.length > 0) await allowForever($, fingerprints)
    const done = fingerprints.length > 0 ? `Allowed for good: ${fingerprints.join(' ')}.` : 'Nothing was allowed.'
    return { text: unknown.length > 0 ? `${done} Not recognised: ${unknown.join(', ')}.\n${USAGE}` : done }
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    const { value: banner = [] } = await $.state.get(bannerRef)
    const { value: paused = false } = await $.state.get(pausedRef)
    if (!paused && banner.length === 0) return next(e)

    const { Box, Text } = $.ui.resolve(e)
    return (
      <Box>
        <Text color={paused ? 'red' : 'yellow'}>{bannerLine(banner, paused, e.props.bodyColumns)}</Text>
      </Box>
    )
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Button, Text } = $.ui.resolve(e)
    const { value: findings = [] } = await $.state.get(findingsRef)
    const { value: paused = false } = await $.state.get(pausedRef)
    const width = e.props.bodyColumns
    const room = Math.max(1, Math.floor(((e.viewport?.rows ?? 24) - 4) / 2))
    const rows = historyRows(findings, width).slice(0, room)

    return (
      <Box flexDirection="column">
        {paused && <Text color="red">{fit('PAUSED · nothing is being checked', width)}</Text>}
        {rows.length === 0 && <Text dimColor>No findings this session.</Text>}
        {rows.map((row) => (
          <Box flexDirection="column">
            <Text>{row.head}</Text>
            <Text dimColor>{row.detail}</Text>
          </Box>
        ))}
        <Box gap={2}>
          <Button key="pause" hotkey="1" label={paused ? 'Resume' : 'Pause'} onPress={() => setPaused($, !paused)} />
          <Button key="close" hotkey="2" label="Close" onPress={() => $.ui.close({ id: PANE })} />
        </Box>
      </Box>
    )
  })

  on('tool.call', { tool: ['Edit', 'Write', 'NotebookEdit'] }, async ($, e, next) => {
    const config = await getConfig($)
    const call = scanCall(e, customRules(config))
    if (call === undefined) return next(e)
    const cwd = await sessionCwd($)
    const shownPath = displayPathOf(call.path, cwd)

    // Self-protection comes first and holds even when LeakStop is paused.
    if (isConfigPath(call.path)) {
      const verdict = await checkConfig($, call.tool, shownPath, mode)
      return verdict === undefined ? next(e) : { deny: (verdict as { deny: string }).deny }
    }

    const { value: paused = false } = await $.state.get(pausedRef)
    if (paused) return next(e)

    if (call.result.isSkipped) {
      $.ui.log(`LeakStop: ${shownPath} is larger than 4 MiB and was not scanned`)
      return next(e)
    }
    if (call.result.isPartial) $.ui.log(`LeakStop: the custom rules were too slow and did not cover all of ${shownPath}`)
    if (call.result.findings.length === 0) return next(e)

    const offset = call.oldString === undefined ? 0 : await lineOffset($, call.path, call.oldString)
    const described = await Promise.all(call.result.findings.map(describe))
    const masked = described.map((f) => ({ ...f, line: f.line + offset })).filter((f) => !isRelaxed(config, f.severity, shownPath))
    if (masked.length === 0) return next(e)

    const allowed = await allowedFingerprints($, config)
    const pending = masked.filter((f) => !allowed.has(f.fingerprint))
    if (pending.length === 0) {
      await record($, call.tool, shownPath, masked, 'allowed')
      return next(e)
    }

    const destination: Destination = (await isIgnored($, call.path)) ? 'ignored-file' : 'file'
    const severities = pending.map((f) => f.severity)
    const wouldHold = mode === 'monitor' && decideAll(destination, severities, 'standard') === 'hold'
    const verdict = await settle($, {
      action: decideAll(destination, severities, mode),
      tool: call.tool,
      path: shownPath,
      notes: pending,
      question: say.holdQuestion(call.tool, shownPath, pending),
      options: [USE_ENV, ALLOW_ONCE, CANCEL],
      deny: say.denyMessage(call.tool, shownPath, pending),
      warn: pending.map((f) => say.warnLine(shownPath, f, wouldHold)),
    })
    return verdict === undefined ? next(e) : { deny: (verdict as { deny: string }).deny }
  }).catch(($, e, next) => onFailure(mode, next) ?? next(e))

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const facts = analyzeCommand(e.command)

    if (facts.touchesConfig) {
      const verdict = await checkConfig($, 'Bash', '.leakstop.json', mode)
      if (verdict !== undefined) return { deny: (verdict as { deny: string }).deny }
    }

    const { value: paused = false } = await $.state.get(pausedRef)
    if (paused) return next(e)

    const config = await getConfig($)
    const allowed = await allowedFingerprints($, config)
    let command = e.command

    const secrets = await checkSecrets($, e.command, mode, allowed, config, facts.writeTargets)
    if (secrets !== undefined && 'deny' in secrets) return secrets

    const sensitive = await checkSensitive($, facts, mode, allowed)
    if (sensitive !== undefined) {
      if ('deny' in sensitive) return sensitive
      command = sensitive.command
    }

    for (const search of facts.searches) {
      const verdict = await checkSearch($, search, mode, allowed)
      if (verdict !== undefined && 'deny' in verdict) return verdict
    }

    for (const op of facts.git) {
      const verdict = await checkGit($, op, mode, allowed, config)
      if (verdict !== undefined && 'deny' in verdict) return verdict
    }

    return command === e.command ? next(e) : next({ ...e, command })
  }).catch(($, e, next) => onFailure(mode, next) ?? next(e))

  on('tool.call', { tool: 'Read' }, async ($, e, next) => {
    if (!(await isSensitiveFile($, e.file_path))) return next(e)

    const { value: paused = false } = await $.state.get(pausedRef)
    if (paused) return next(e)

    const note = await operation('sensitive-file-read', 'Sensitive file read', `path:${e.file_path}`)
    const allowed = await allowedFingerprints($, await getConfig($))
    if (allowed.has(note.fingerprint)) return next(e)

    const cwd = await sessionCwd($)
    const shownPath = displayPathOf(e.file_path, cwd)
    const verdict = await settle($, {
      action: decide('read', 'critical', mode),
      tool: 'Read',
      path: shownPath,
      notes: [note],
      question: say.readQuestion(shownPath),
      options: [ALLOW_ONCE, CANCEL],
      deny: say.readDeny(shownPath, mode === 'strict'),
      warn: [say.noticeLine(`${shownPath} is a sensitive file`, mode === 'monitor')],
    })
    return verdict === undefined ? next(e) : { deny: (verdict as { deny: string }).deny }
  }).catch(($, e, next) => onFailure(mode, next) ?? next(e))

  // What leaves the session through a tool: a secret there cannot be taken back.
  on('tool.call', { tool: ['WebFetch', 'WebSearch', 'Agent', 'SendMessage', 'SendFile', 'Artifact', 'ArtifactData', 'ArtifactComments', 'PushNotification', 'SendFeedback', 'RemoteTrigger'] }, async ($, e, next) => {
    const verdict = await guardOutbound($, e, mode)
    return verdict === undefined ? next(e) : { deny: (verdict as { deny: string }).deny }
  }).catch(($, e, next) => onFailure(mode, next) ?? next(e))

  on('tool.call', { tool: /^mcp__/ }, async ($, e, next) => {
    const verdict = await guardOutbound($, e, mode)
    return verdict === undefined ? next(e) : { deny: (verdict as { deny: string }).deny }
  }).catch(($, e, next) => onFailure(mode, next) ?? next(e))
}

const displayPathOf = say.displayPath
