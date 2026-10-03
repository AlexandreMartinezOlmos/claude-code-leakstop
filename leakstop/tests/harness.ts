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
  /** The Bash commands that actually ran, after any rewrite. */
  commands: string[]
}

/**
 * The engine and the tools beneath the plugin: the clock, the session's
 * directory, the transcript log and the tools themselves (which run when
 * LeakStop lets a call through). Returns a view of what LeakStop wrote to its
 * state, since a test's `$` has no `state` noun: the writes are watched on their way.
 */
export function toolsRun(on: any, options: { surfaces?: string[] } = {}): Watch {
  const written: Record<string, any> = {}
  const logs: string[] = []
  const commands: string[] = []
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('session.cwd', () => ({ value: CWD }))
  on('session.surfaces', () => ({ value: options.surfaces ?? [] }))
  on('ui.log', (_$: any, e: any) => {
    logs.push(e.text)
    return { value: undefined }
  })
  on('state.set', { plugin: 'leakstop' }, (_$: any, e: any, next: any) => {
    written[e.key] = e.value
    return next(e)
  })
  on('tool.call', { tool: ['Write', 'Edit', 'NotebookEdit', 'Bash', 'Read'] }, (_$: any, e: any) => {
    if (e.tool === 'Bash') commands.push(e.command)
    return { result: 'ok' }
  })
  return { findings: () => written.findings ?? [], allowOnce: () => written.allowOnce ?? [], logs, commands }
}

export const isDenied = (r: any): boolean => typeof r?.deny === 'string'
export const ran = (r: any): boolean => r?.result === 'ok'

export type GitReply = string | { exitCode?: number; stdout?: string; isTruncated?: boolean } | undefined

export type GitScript = {
  /** The arguments (after `git`) of every call, and the options each was run with. */
  calls: string[][]
  inits: any[]
  /** Replaces the script: hooks cannot be registered once a test has called `$`. */
  use: (reply: (argv: string[], init?: any) => GitReply) => void
}

/**
 * Stands in for every program the plugin runs (`git`, and `find` for recursive searches). `reply` gets the arguments after
 * `git` and answers with stdout (or an exit code); unscripted calls succeed with
 * no output.
 */
export function gitScript(on: any, first: (argv: string[], init?: any) => GitReply): GitScript {
  let reply = first
  const script: GitScript = { calls: [], inits: [], use: (next) => void (reply = next) }
  on('process.run', (_$: any, e: any) => {
    // `git` calls get the arguments after `git`; any other program gets its whole argv.
    const argv = (e.argv[0] === 'git' ? e.argv.slice(1) : e.argv) as string[]
    script.calls.push(argv)
    script.inits.push(e.init)
    const r = reply(argv, e.init)
    const out = typeof r === 'string' ? { stdout: r } : (r ?? {})
    return { value: { exitCode: out.exitCode ?? 0, stdout: out.stdout ?? '', stderr: '', isStdoutTruncated: out.isTruncated ?? false, isStderrTruncated: false } }
  })
  return script
}

/**
 * Files on disk, by path relative to the working directory (the engine resolves
 * paths before the event); any other path cannot be read.
 */
export function disk(on: any, files: Record<string, string>): void {
  on('fs.exists', (_$: any, e: any) => ({ value: Object.keys(files).some((k) => e.path === k || e.path.endsWith(`/${k}`)) }))
  on('fs.read', (_$: any, e: any) => {
    const key = Object.keys(files)
      .filter((k) => e.path === k || e.path.endsWith(`/${k}`))
      .sort((a, b) => b.length - a.length)[0]
    if (key === undefined) throw new Error('ENOENT')
    return { value: files[key] }
  })
}

/** Fingerprints the user allowed for good, as `/leakstop allow` will store them. */
export function storeAllows(on: any, fingerprints: string[]): void {
  on('store.get', (_$: any, e: any) => ({ value: e.key === 'allowFingerprints' ? fingerprints : undefined }))
}

/** A unified diff that adds `lines` to `path`, the first at line `from`. */
export function diffAdding(path: string, from: number, lines: string[]): string {
  return [`diff --git a/${path} b/${path}`, `--- a/${path}`, `+++ b/${path}`, `@@ -0,0 +${from},${lines.length} @@`, ...lines.map((l) => `+${l}`)].join('\n') + '\n'
}

export type UiCalls = {
  /** What `$.ui.open` was asked, and what `$.command.register` registered. */
  opened: any[]
  closed: any[]
  registered: any[]
}

/** The UI the engine would provide: panes (placed or not) and command registration. */
export function uiEngine(on: any, options: { isPlaced?: boolean } = {}): UiCalls {
  const calls: UiCalls = { opened: [], closed: [], registered: [] }
  on('ui.open', (_$: any, e: any) => {
    calls.opened.push(e)
    return { value: options.isPlaced === false ? { isPlaced: false, reason: 'the terminal is too narrow' } : { isPlaced: true } }
  })
  on('ui.close', (_$: any, e: any) => {
    calls.closed.push(e)
    return { value: undefined }
  })
  on('command.register', (_$: any, e: any) => {
    calls.registered.push(e)
    return { value: { command: e.name } }
  })
  return calls
}

/** The machine-wide store, in memory. Returns the data, to assert on what was kept. */
export function storeKV(on: any, initial: Record<string, unknown> = {}): Record<string, unknown> {
  const data: Record<string, unknown> = { ...initial }
  on('store.get', (_$: any, e: any) => ({ value: data[e.key] }))
  on('store.set', (_$: any, e: any) => {
    data[e.key] = e.value
    return { value: undefined }
  })
  on('store.delete', (_$: any, e: any) => {
    delete data[e.key]
    return { value: undefined }
  })
  return data
}

export const USER = { kind: 'composer' } as const

export const BAND_PROPS = { hasSurvey: false, isWorking: false, maxRows: 10, bodyColumns: 80, scroll: { bodyRows: 10 } as any, view: {} as any }
export const PANE_PROPS = { title: 'LeakStop', isFocused: true, bodyColumns: 60, placement: 'dock' as const, scroll: { bodyRows: 20 } as any, view: {} as any }
