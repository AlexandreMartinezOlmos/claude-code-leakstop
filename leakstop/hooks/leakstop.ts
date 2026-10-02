// LeakStop: the hooks module. Every use of `$` lives in this file; detection,
// masking, policy and messages are pure modules that never receive it.
//
// Rules this file keeps:
// - Every `$` call is spelled in full, and event names are string literals.
// - A hook that can deny has a `.catch` that denies (monitor mode: lets it go).
// - Nothing that holds a secret is stored, logged or shown: findings are turned
//   into MaskedFindings first, and only those cross into `$`.
// - It never approves a call on its own: `next(e)` after a pass leaves the
//   user's permissions and rules in force.

import type { EngineInterface, Register, ToolCallInput } from 'claude-code'

import type { Decision, StoredFinding } from '../types'
import { scanEdit, scanText, scanWrite } from './detect.ts'
import type { ScanResult } from './detect.ts'
import { describe } from './mask.ts'
import type { MaskedFinding } from './mask.ts'
import { configDenyMessage, configQuestion, denyMessage, displayPath, holdQuestion, warnLine } from './messages.ts'
import type { WriteTool } from './messages.ts'
import { decide, decideAll } from './policy.ts'
import type { Destination, Mode } from './policy.ts'

const USE_ENV = 'Use environment variable'
const ALLOW_ONCE = 'Allow once'
const CANCEL = 'Cancel'

const MAX_FINDINGS = 100
const MAX_ALLOW_ONCE = 500

const findingsRef = { plugin: 'leakstop', key: 'findings' } as const
const allowOnceRef = { plugin: 'leakstop', key: 'allowOnce' } as const
const pausedRef = { plugin: 'leakstop', key: 'paused' } as const

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

async function record($: EngineInterface, tool: string, path: string, findings: readonly MaskedFinding[], decision: Decision): Promise<void> {
  const at = await $.clock.now()
  const entries: StoredFinding[] = findings.map((f) => ({
    fingerprint: f.fingerprint,
    ruleId: f.ruleId,
    label: f.label,
    severity: f.severity,
    path,
    line: f.line,
    tool,
    decision,
    at,
  }))
  const { value = [] } = await $.state.get(findingsRef)
  await $.state.set(findingsRef, [...value, ...entries].slice(-MAX_FINDINGS))
}

async function rememberAllowOnce($: EngineInterface, fingerprints: readonly string[]): Promise<void> {
  const { value = [] } = await $.state.get(allowOnceRef)
  await $.state.set(allowOnceRef, [...new Set([...value, ...fingerprints])].slice(-MAX_ALLOW_ONCE))
}

/** The user's answer, or `undefined` when nobody could answer (dismissed, `claude -p`, no interface). */
async function askUser($: EngineInterface, question: string, options: readonly string[]): Promise<string | undefined> {
  try {
    return await $.ui.ask(question, { options, header: 'LeakStop' })
  } catch {
    return undefined
  }
}

// --- Pure helpers of this file (no `$`) -------------------------------------

type Call = { tool: WriteTool; path: string; result: ScanResult; oldString?: string }

/** What the write is about to put on disk, scanned. `undefined`: nothing is written. */
function scanCall(e: ToolCallInput): Call | undefined {
  switch (e.tool) {
    case 'Write':
      return { tool: 'Write', path: e.file_path, result: scanWrite(e.file_path, e.content) }
    case 'Edit':
      return { tool: 'Edit', path: e.file_path, result: scanEdit(e.file_path, e.old_string, e.new_string), oldString: e.old_string }
    case 'NotebookEdit':
      return typeof e.new_source === 'string'
        ? { tool: 'NotebookEdit', path: e.notebook_path, result: scanText(e.new_source, { path: e.notebook_path }) }
        : undefined
    default:
      return undefined
  }
}

const isConfigPath = (path: string): boolean => (path.split(/[\\/]/).pop() ?? '') === '.leakstop.json'

// --- The module -------------------------------------------------------------

export const register: Register = (on, options) => {
  const mode: Mode = options.mode === 'monitor' || options.mode === 'strict' ? options.mode : 'standard'

  on('tool.call', { tool: ['Edit', 'Write', 'NotebookEdit'] }, async ($, e, next) => {
    const call = scanCall(e)
    if (call === undefined) return next(e)
    const cwd = await sessionCwd($)
    const shownPath = displayPath(call.path, cwd)

    // Self-protection comes first and holds even when LeakStop is paused:
    // without it Claude could allowlist its own findings.
    if (isConfigPath(call.path)) {
      if (decide('config-edit', 'critical', mode) !== 'hold') {
        $.ui.log(`LeakStop · monitor mode: the change to ${shownPath} would have been held`)
        return next(e)
      }
      const answer = await askUser($, configQuestion(shownPath), [ALLOW_ONCE, CANCEL])
      return answer === ALLOW_ONCE ? next(e) : { deny: configDenyMessage(shownPath) }
    }

    const { value: paused = false } = await $.state.get(pausedRef)
    if (paused) return next(e)

    if (call.result.isSkipped) {
      $.ui.log(`LeakStop: ${shownPath} is larger than 4 MiB and was not scanned`)
      return next(e)
    }
    if (call.result.findings.length === 0) return next(e)

    const offset = call.oldString === undefined ? 0 : await lineOffset($, call.path, call.oldString)
    const described = await Promise.all(call.result.findings.map(describe))
    const masked = described.map((f) => ({ ...f, line: f.line + offset }))

    const { value: allowed = [] } = await $.state.get(allowOnceRef)
    const pending = masked.filter((f) => !allowed.includes(f.fingerprint))
    if (pending.length === 0) {
      await record($, call.tool, shownPath, masked, 'allowed')
      return next(e)
    }

    const destination: Destination = (await isIgnored($, call.path)) ? 'ignored-file' : 'file'
    const action = decideAll(destination, pending.map((f) => f.severity), mode)

    if (action === 'pass') {
      await record($, call.tool, shownPath, pending, 'passed')
      return next(e)
    }

    if (action === 'warn') {
      const wouldHold = mode === 'monitor' && decideAll(destination, pending.map((f) => f.severity), 'standard') === 'hold'
      for (const finding of pending) $.ui.log(warnLine(shownPath, finding, wouldHold))
      await record($, call.tool, shownPath, pending, 'warned')
      return next(e)
    }

    // Hold (the only other action a write can get; a block would deny the same way).
    if (action === 'hold') {
      const question = holdQuestion(call.tool, shownPath, pending)
      const answer = await askUser($, question, [USE_ENV, ALLOW_ONCE, CANCEL])
      if (answer === ALLOW_ONCE) {
        await rememberAllowOnce($, pending.map((f) => f.fingerprint))
        await record($, call.tool, shownPath, pending, 'allowed')
        return next(e)
      }
    }
    await record($, call.tool, shownPath, pending, 'denied')
    return { deny: denyMessage(call.tool, shownPath, pending) }
  }).catch(($, e, next) => {
    // Fail closed: a hook that throws or runs out of time is skipped and the
    // call would go on. Monitor mode never blocks.
    if (mode === 'monitor' || next.called) return next(e)
    return { deny: `LeakStop could not check this call (${next.error.kind}), so it was blocked. Try again, or ask the user to review it.` }
  })
}
