// Reads a Bash command as text and says what it is about to do that matters to
// LeakStop. Pure: no `$`, no I/O.
//
// It reads, it does not execute. A command built from variables, a script run
// with `python -c` or an encoded payload is not understood; the README says so.
// Everything here errs on the side of looking: a false positive is a question,
// a false negative is a leak.

import { classifyPath } from './detect.ts'

export type Segment = {
  /** Words with quotes and escapes resolved. Redirections are words of their own (`>`, `<`). */
  words: string[]
  /** Segments joined by `|` share a pipeline id. */
  pipeline: number
}

/** Splits on `&&`, `||`, `;`, `&`, `|`, newlines and parentheses; skips heredoc bodies. */
export function parseCommand(command: string): Segment[] {
  const segments: Segment[] = []
  let words: string[] = []
  let word = ''
  let hasWord = false
  let pipeline = 0
  let heredocs: { delimiter: string; isIndented: boolean }[] = []

  const endWord = (): void => {
    if (hasWord) words.push(word)
    word = ''
    hasWord = false
  }
  const endSegment = (isPipe: boolean): void => {
    endWord()
    if (words.length > 0) segments.push({ words, pipeline })
    words = []
    if (!isPipe) pipeline++
  }

  let i = 0
  while (i < command.length) {
    const char = command[i] as string
    const next = command[i + 1]

    if (char === '\\') {
      if (next !== undefined && next !== '\n') {
        word += next
        hasWord = true
      }
      i += 2
      continue
    }
    if (char === "'") {
      const close = command.indexOf("'", i + 1)
      const end = close < 0 ? command.length : close
      word += command.slice(i + 1, end)
      hasWord = true
      i = end + 1
      continue
    }
    if (char === '"') {
      i++
      hasWord = true
      while (i < command.length && command[i] !== '"') {
        if (command[i] === '\\' && i + 1 < command.length) i++
        word += command[i]
        i++
      }
      i++
      continue
    }
    if (char === ' ' || char === '\t') {
      endWord()
      i++
      continue
    }
    if (char === '\n') {
      endSegment(false)
      i++
      // Skip the bodies of heredocs opened on the line that just ended.
      for (const heredoc of heredocs) {
        while (i < command.length) {
          const lineEnd = command.indexOf('\n', i)
          const line = command.slice(i, lineEnd < 0 ? command.length : lineEnd)
          i = lineEnd < 0 ? command.length : lineEnd + 1
          if ((heredoc.isIndented ? line.trim() : line) === heredoc.delimiter) break
        }
      }
      heredocs = []
      continue
    }
    if (char === '&' && word.endsWith('>')) {
      // `2>&1`: a file-descriptor duplication, not a control operator.
      word += char
      i++
      continue
    }
    if (char === '&' && next === '&') {
      endSegment(false)
      i += 2
      continue
    }
    if (char === '|' && next === '|') {
      endSegment(false)
      i += 2
      continue
    }
    if (char === '|') {
      endSegment(true)
      i++
      continue
    }
    if (char === ';' || char === '&' || char === '(' || char === ')' || char === '\x60') {
      endSegment(false)
      i++
      continue
    }
    if (char === '<' && next === '<' && command[i + 2] !== '<') {
      // Heredoc: `<<EOF`, `<<-EOF`, `<<'EOF'`. The body is skipped at the next newline.
      let j = i + 2
      const isIndented = command[j] === '-'
      if (isIndented) j++
      while (command[j] === ' ') j++
      const quote = command[j] === "'" || command[j] === '"' ? command[j] : undefined
      if (quote !== undefined) j++
      let delimiter = ''
      while (j < command.length && !/[\s;&|()<>'"]/.test(command[j] as string)) delimiter += command[j++]
      if (quote !== undefined && command[j] === quote) j++
      endWord()
      words.push('<<')
      if (delimiter !== '') heredocs.push({ delimiter, isIndented })
      i = j
      continue
    }
    if (char === '<' || (char === '>' && !/^\d+$/.test(word))) {
      endWord()
      let op = char
      i++
      while (command[i] === char || (char === '>' && command[i] === '|')) op += command[i++]
      if (char === '>' && command[i] === '&') {
        // `>&2`: duplicate a descriptor.
        op += command[i++]
        while (/[0-9-]/.test(command[i] ?? '')) op += command[i++]
      }
      words.push(op)
      continue
    }
    word += char
    hasWord = true
    i++
  }
  endSegment(false)
  return segments
}

// --- Programs --------------------------------------------------------------

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/
const WRAPPERS = new Set(['sudo', 'command', 'time', 'nohup', 'exec', 'builtin', 'nice', 'env'])

type Program = { name: string; args: string[]; isBareEnv: boolean }

/** The program a segment runs, past assignments and wrappers (`sudo`, `env FOO=1`, `time`). */
function programOf(words: readonly string[]): Program {
  let i = 0
  let isEnv = false
  for (;;) {
    const word = words[i]
    if (word === undefined) break
    if (ASSIGNMENT.test(word)) {
      i++
    } else if (WRAPPERS.has(word)) {
      if (word === 'env') isEnv = true
      i++
      while (words[i]?.startsWith('-') === true) i++
    } else {
      break
    }
  }
  const first = words[i]
  if (first === undefined) return { name: '', args: [], isBareEnv: isEnv }
  return { name: first.split('/').pop() ?? first, args: words.slice(i + 1), isBareEnv: false }
}

const isFlag = (word: string): boolean => word.startsWith('-') && word.length > 1

/** Words that are operands: not flags and not the target of a redirection. */
function operands(args: readonly string[]): string[] {
  const out: string[] = []
  for (let i = 0; i < args.length; i++) {
    const word = args[i] as string
    if (/^>>?\|?$/.test(word)) {
      i++ // the target of an output redirection is written, not read
      continue
    }
    if (word === '<') continue // the next word is read: keep it
    if (word === '<<' || isFlag(word)) continue
    out.push(word)
  }
  return out
}

// --- Facts -----------------------------------------------------------------

/** Programs that print a file's contents, values included. `sed`, `awk` and `cut` are left out: they are how names are listed. */
const VIEWERS = new Set(['cat', 'head', 'tail', 'less', 'more', 'bat', 'nl', 'tac', 'strings', 'xxd', 'od', 'hexdump', 'grep', 'egrep', 'fgrep', 'rg', 'ag'])
/** The viewers whose output is the file itself, so listing names only is a faithful replacement. */
const PLAIN_VIEWERS = new Set(['cat', 'head', 'tail', 'less', 'more', 'bat', 'nl', 'tac'])

const SECRET_NAME = /(?:^|_)(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIALS?|AUTH|PRIVATE)(?:_|$)|APIKEY/i

export const isSecretName = (name: string): boolean => SECRET_NAME.test(name)

/**
 * Sensitive by path, or a glob that would match a sensitive path (`.env*`,
 * `*.pem`): the shell expands it, so the pattern itself is what the command shows.
 */
function isSensitiveOperand(operand: string): boolean {
  if (classifyPath(operand) !== undefined) return true
  if (!/[*?[]/.test(operand)) return false
  return [operand.replace(/[*?]/g, ''), operand.replace(/[*?]/g, 'x'), operand.replace(/\*/g, '.x')].some((guess) => classifyPath(guess) !== undefined)
}

export type GitOp =
  | { kind: 'add'; isAll: boolean; paths: string[]; dir?: string }
  | { kind: 'commit'; isAll: boolean; dir?: string; staging: { isAll: boolean; paths: string[] }[] }
  | { kind: 'push'; dir?: string }

export type CommandFacts = {
  /** Files a viewer would print that are sensitive by path (content check pending for `requiresToken` ones). */
  readFiles: string[]
  /** `printenv`, `env`, `export -p`, `set` or the environ file under /proc: the whole environment. */
  isEnvDump: boolean
  /** Secret-looking variables printed one by one: `printenv API_KEY`, `echo $TOKEN`. */
  secretVars: string[]
  git: GitOp[]
  /** The command changes `.leakstop.json`. */
  touchesConfig: boolean
  /** The command that prints names only instead, when the command is simple enough to rewrite. */
  namesOnly?: string
  /**
   * Where the command writes, when it does nothing but write: one `echo`, `printf` or `cat`
   * redirected to files, with no pipe, no `&&` and no command substitution. A secret in
   * such a command goes to those files and nowhere else.
   */
  writeTargets?: string[]
}

/**
 * Prints `NAME=<hidden>` for each assignment and nothing else, so no value and no
 * continuation line escapes. A name must be a plausible variable name (all upper
 * or all lower case, 48 characters at most): a base64 line that happens to end in
 * `=` inside a multi-line value is not one, and printing it would leak key material.
 */
const NAMES_ONLY_SED = String.raw`sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Z_][A-Z0-9_]{0,47}|[a-z_][a-z0-9_]{0,47})=.*/\2=<hidden>/p'`

export const shellQuote = (text: string): string => "'" + text.split("'").join("'\\''") + "'"

const READ_ONLY = new Set(['cat', 'less', 'more', 'head', 'tail', 'grep', 'egrep', 'rg', 'ls', 'stat', 'wc', 'file', 'diff', 'jq', 'test', '['])

function touchesConfig(segments: readonly Segment[]): boolean {
  return segments.some((segment) => {
    if (!segment.words.some((word) => word.includes('.leakstop.json'))) return false
    const program = programOf(segment.words)
    const isWrite = segment.words.some((word) => /^\d*>>?\|?$/.test(word))
    const isReadOnlyGit = program.name === 'git' && /^(?:diff|log|show|status|check-ignore|blame|ls-files)$/.test(program.args.find((a) => !isFlag(a)) ?? '')
    return isWrite || !(READ_ONLY.has(program.name) || isReadOnlyGit)
  })
}

const BACKTICKS = new RegExp('\\x60([^\\x60]*)\\x60', 'g')

/** Text of command substitutions (dollar-parenthesis and backticks), which can hide a command inside quotes. */
function substitutions(command: string): string[] {
  const out: string[] = []
  for (const match of command.matchAll(/\$\(([^()]*)\)/g)) if (match[1] !== undefined) out.push(match[1])
  for (const match of command.matchAll(BACKTICKS)) if (match[1] !== undefined) out.push(match[1])
  return out
}

function gitOps(segments: readonly Segment[]): GitOp[] {
  const ops: GitOp[] = []
  const staging: { isAll: boolean; paths: string[] }[] = []
  let dir: string | undefined
  for (const segment of segments) {
    const program = programOf(segment.words)
    if (program.name === 'cd') {
      const target = program.args.find((a) => !isFlag(a))
      if (target !== undefined && !/^[~$-]/.test(target)) dir = dir === undefined || target.startsWith('/') ? target : `${dir}/${target}`
      continue
    }
    if (program.name !== 'git') continue
    // Global options before the subcommand: -C <dir>, -c k=v, --no-pager, ...
    let gitDir = dir
    const args = program.args
    let i = 0
    while (i < args.length && isFlag(args[i] as string)) {
      const flag = args[i] as string
      if (flag === '-C' && args[i + 1] !== undefined) {
        const target = args[i + 1] as string
        gitDir = gitDir === undefined || target.startsWith('/') ? target : `${gitDir}/${target}`
        i += 2
      } else if (flag === '-c' || flag === '--git-dir' || flag === '--work-tree') {
        i += 2
      } else {
        i++
      }
    }
    const sub = args[i]
    const rest = args.slice(i + 1)
    const withDir = <T extends GitOp>(op: T): T => (gitDir === undefined ? op : { ...op, dir: gitDir })
    if (sub === 'add') {
      const paths = operands(rest)
      const isAll = rest.some((a) => a === '-A' || a === '--all' || a === '-u' || a === '--update') || paths.some((p) => p === '.' || p === ':/' || p === '*' || p === './')
      staging.push({ isAll, paths })
      ops.push(withDir({ kind: 'add', isAll, paths }))
    } else if (sub === 'commit') {
      const isAll = rest.some((a) => a === '--all' || /^-[A-Za-z]*a[A-Za-z]*$/.test(a))
      ops.push(withDir({ kind: 'commit', isAll, staging: [...staging] }))
    } else if (sub === 'push') {
      ops.push(withDir({ kind: 'push' }))
    }
  }
  return ops
}

function analyzeSegments(command: string, segments: readonly Segment[], depth: number): CommandFacts {
  const readFiles: string[] = []
  const secretVars: string[] = []
  let isEnvDump = false

  for (const segment of segments) {
    const { name, args, isBareEnv } = programOf(segment.words)
    const isFiltered = segments.some(
      (other) => other !== segment && other.pipeline === segment.pipeline && ['cut', 'wc'].includes(programOf(other.words).name),
    )

    if (isBareEnv || (name === 'printenv' && operands(args).length === 0)) {
      if (!isFiltered) isEnvDump = true
    } else if (name === 'printenv') {
      for (const variable of operands(args)) if (isSecretName(variable)) secretVars.push(variable)
    } else if ((name === 'export' || name === 'declare' || name === 'typeset') && args.some((a) => /^-[a-z]*[px][a-z]*$/.test(a)) && operands(args).length === 0) {
      if (!isFiltered) isEnvDump = true
    } else if (name === 'set' && args.length === 0) {
      if (!isFiltered) isEnvDump = true
    } else if (name === 'echo' || name === 'printf') {
      for (const match of segment.words.join(' ').matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)) {
        if (match[1] !== undefined && isSecretName(match[1])) secretVars.push(match[1])
      }
    } else if (VIEWERS.has(name)) {
      for (const file of operands(args)) {
        if (/^\/proc\/[^/]+\/environ$/.test(file)) isEnvDump = true
        else if (isSensitiveOperand(file)) readFiles.push(file)
      }
    }
  }

  let git = gitOps(segments)
  let touches = touchesConfig(segments)

  if (depth < 2) {
    for (const inner of substitutions(command)) {
      const facts = analyzeSegments(inner, parseCommand(inner), depth + 1)
      readFiles.push(...facts.readFiles)
      secretVars.push(...facts.secretVars)
      isEnvDump ||= facts.isEnvDump
      git = [...git, ...facts.git]
      touches ||= facts.touchesConfig
    }
  }

  return { readFiles: [...new Set(readFiles)], isEnvDump, secretVars: [...new Set(secretVars)], git, touchesConfig: touches, namesOnly: namesOnlyFor(segments, readFiles, isEnvDump) }
}

/** The replacement that lists names only, for a command that is one plain view of env files or the bare environment. */
function namesOnlyFor(segments: readonly Segment[], readFiles: readonly string[], isEnvDump: boolean): string | undefined {
  if (segments.length !== 1) return undefined
  const { name, args, isBareEnv } = programOf((segments[0] as Segment).words)
  if (isEnvDump && (isBareEnv || name === 'printenv') && operands(args).length === 0) return `env | ${NAMES_ONLY_SED}`
  if (readFiles.length > 0 && PLAIN_VIEWERS.has(name)) {
    const others = operands(args).filter((word) => !/^\d+$/.test(word))
    if (others.length === readFiles.length && readFiles.every((file) => classifyPath(file)?.kind === 'env')) {
      return `${NAMES_ONLY_SED} ${readFiles.map((file) => shellQuote(file.startsWith('-') ? `./${file}` : file)).join(' ')}`
    }
  }
  return undefined
}

const WRITERS = new Set(['echo', 'printf', 'cat'])

/** The files a command only writes to, or `undefined` when it does anything else as well. */
function writeTargetsOf(command: string, segments: readonly Segment[]): string[] | undefined {
  if (segments.length !== 1 || substitutions(command).length > 0) return undefined
  const { name, args } = programOf((segments[0] as Segment).words)
  if (!WRITERS.has(name)) return undefined
  const targets: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (/^>>?\|?$/.test(args[i] as string) && args[i + 1] !== undefined) targets.push(args[++i] as string)
  }
  return targets.length > 0 ? targets : undefined
}

export function analyzeCommand(command: string): CommandFacts {
  const segments = parseCommand(command)
  const facts = analyzeSegments(command, segments, 0)
  const writeTargets = writeTargetsOf(command, segments)
  return writeTargets === undefined ? facts : { ...facts, writeTargets }
}
