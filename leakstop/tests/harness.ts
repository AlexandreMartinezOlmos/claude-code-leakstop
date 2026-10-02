// Helpers that stand in for Claude Code beneath the plugin in a test.
//
// `$.ui.ask` is not an event: the engine raises it as a `tool.call` of
// `AskUserQuestion`, so a test answers it there. `$.process.run` and
// `$.fs.read` are events of their own.

export const REJECT = Symbol('reject')

type Answer = string | typeof REJECT

/** Answers every ask with `answer` (or rejects it, as `claude -p` does) and records the questions. */
export function answerWith(on: any, answer: Answer): { questions: string[]; headers: string[]; options: string[][] } {
  const seen = { questions: [] as string[], headers: [] as string[], options: [] as string[][] }
  on('tool.call', { tool: 'AskUserQuestion' }, (_$: any, e: any) => {
    const q = e.questions[0]
    seen.questions.push(q.question)
    seen.headers.push(q.header)
    seen.options.push(q.options.map((o: any) => o.label))
    if (answer === REJECT) return { deny: 'no interface' }
    return { result: { questions: e.questions, answers: { [q.question]: answer } } }
  })
  return seen
}

/** What `git check-ignore` says about every path. */
export function gitSays(on: any, state: 'ignored' | 'tracked' | 'not-a-repo'): void {
  const exitCode = state === 'ignored' ? 0 : state === 'tracked' ? 1 : 128
  on('process.run', () => ({ value: { exitCode, stdout: '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }))
}

/** The file Edit reads from disk to find real line numbers. */
export function fileOnDisk(on: any, content: string): void {
  on('fs.read', () => ({ value: content }))
}

export const CWD = '/work/app'

export type Watch = {
  /** The findings LeakStop last wrote to `$.state`. */
  findings: () => any[]
  /** The fingerprints LeakStop last wrote as allowed for the session. */
  allowOnce: () => string[]
  /** Lines LeakStop sent to the transcript with `$.ui.log`. */
  logs: string[]
}

/**
 * The engine and the tools beneath the plugin: the clock, the session's
 * directory, the transcript log and the tools themselves (which run when
 * LeakStop lets a call through). Returns a view of what LeakStop wrote to its
 * state, since a test's `$` has no `state` noun: the writes are watched on their way.
 */
export function toolsRun(on: any): Watch {
  const written: Record<string, any> = {}
  const logs: string[] = []
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('session.cwd', () => ({ value: CWD }))
  on('ui.log', (_$: any, e: any) => {
    logs.push(e.text)
    return { value: undefined }
  })
  on('state.set', { plugin: 'leakstop' }, (_$: any, e: any, next: any) => {
    written[e.key] = e.value
    return next(e)
  })
  on('tool.call', { tool: ['Write', 'Edit', 'NotebookEdit'] }, () => ({ result: 'ok' }))
  return { findings: () => written.findings ?? [], allowOnce: () => written.allowOnce ?? [], logs }
}

export const isDenied = (r: any): boolean => typeof r?.deny === 'string'
export const ran = (r: any): boolean => r?.result === 'ok'
