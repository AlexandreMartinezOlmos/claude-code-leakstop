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

type Program = { name: string; args: string[]; isBareEnv: boolean; /** Invoked by its bare name, with no wrapper before it. */ isPlain: boolean }

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
  if (first === undefined) return { name: '', args: [], isBareEnv: isEnv, isPlain: false }
  return { name: first.split('/').pop() ?? first, args: words.slice(i + 1), isBareEnv: false, isPlain: i === 0 && !first.includes('/') }
}

/** The files a segment sends its standard output to with `>` or `>>`. */
function outputTargets(args: readonly string[]): string[] {
  const targets: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (/^>>?\|?$/.test(args[i] as string) && args[i + 1] !== undefined) targets.push(args[++i] as string)
  }
  return targets
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

/** A recursive `grep` or `rg` that prints lines (not just file names or counts). */
export type Search = {
  /** Where it looks: the folders it was given, or `.` when it was given none. */
  dirs: string[]
  /** Patterns of files it is told to skip (`--exclude`, `--exclude-dir`, `-g '!…'`). */
  excludes: string[]
  /** Patterns of files it is limited to (`--include`, `-g`); empty when it looks at everything. */
  includes: string[]
  /**
   * Files that git ignores are not searched. True for `rg` and `ag` unless told otherwise, and for the
   * plain `grep` command, which Claude Code's shell replaces with a search that honours `.gitignore`.
   */
  respectsIgnore: boolean
}

const SEARCHERS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'ag'])
/** Flags whose value is the next word. */
const VALUE_FLAGS = new Set(['-e', '-f', '-m', '-A', '-B', '-C', '-d', '-D', '-g', '-t', '-T', '-j', '-M', '-E', '--include', '--exclude', '--exclude-dir', '--exclude-from', '--file', '--regexp', '--max-count', '--glob', '--iglob', '--type', '--type-not', '--threads', '--max-depth', '--context', '--before-context', '--after-context', '--directories', '--devices'])
/** `rg` and `ag` skip hidden and ignored files unless told otherwise. */
/** Flags that stop a search from honouring `.gitignore`. */
const NO_IGNORE = /^(?:--no-ignore(?:-[a-z-]+)?|--unrestricted|-u+|-U)$/
const REACHES_HIDDEN = /^(?:--hidden|-\.|--no-ignore(?:-[a-z-]+)?|--unrestricted|-u+|-U)$/
/** Flags that make the output file names or counts, never lines. */
const LIST_ONLY_LONG = /^--(?:files-with-matches|files-without-match|count|count-matches|quiet|silent|files)$/

type SearchParse = {
  /** The patterns and paths, with every flag and flag value removed. */
  paths: string[]
  /** File names or counts only: nothing here can print a line of a file. */
  isListOnly: boolean
  /** Set when the search is recursive and can reach files nobody named. */
  search?: Search
}

function parseSearch(name: string, args: readonly string[], isPlain: boolean): SearchParse {
  const isGrep = name === 'grep' || name === 'egrep' || name === 'fgrep'
  let isRecursive = !isGrep // rg and ag always are
  let reachesHidden = isGrep // grep reads dotfiles and ignored files
  let isIgnoreOff = false
  let isPatternGiven = false
  let isListOnly = false
  const words: string[] = []
  const excludes: string[] = []
  const includes: string[] = []

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string
    if (/^>>?\|?$/.test(arg)) {
      i++ // the target of an output redirection
      continue
    }
    if (arg === '<' || arg === '<<') continue
    if (!isFlag(arg)) {
      words.push(arg)
      continue
    }
    const [flag, inline] = arg.startsWith('--') && arg.includes('=') ? [arg.slice(0, arg.indexOf('=')), arg.slice(arg.indexOf('=') + 1)] : [arg, undefined]
    const value = inline ?? (VALUE_FLAGS.has(flag) ? args[++i] : undefined)

    if (LIST_ONLY_LONG.test(flag)) isListOnly = true
    if (/^-[A-Za-z]*[lLcq][A-Za-z]*$/.test(flag) && !flag.startsWith('--') && !VALUE_FLAGS.has(flag)) isListOnly = true
    if (flag === '--recursive' || flag === '--dereference-recursive') isRecursive = true
    else if (isGrep && !flag.startsWith('--') && /^-[A-Za-z]*[rR][A-Za-z]*$/.test(flag) && !VALUE_FLAGS.has(flag)) isRecursive = true
    if (isGrep && (flag === '-d' || flag === '--directories') && value === 'recurse') isRecursive = true
    if (!isGrep && REACHES_HIDDEN.test(flag)) reachesHidden = true
    if (NO_IGNORE.test(flag)) isIgnoreOff = true
    if (flag === '-e' || flag === '-f' || flag === '--regexp' || flag === '--file') isPatternGiven = true

    if (value !== undefined) {
      if (flag === '--exclude' || flag === '--exclude-from') excludes.push(value)
      else if (flag === '--exclude-dir') excludes.push(`**/${value}/**`)
      else if (flag === '--include') includes.push(value)
      else if (flag === '-g' || flag === '--glob' || flag === '--iglob') (value.startsWith('!') ? excludes : includes).push(value.replace(/^!/, ''))
    }
  }
  const paths = isPatternGiven ? words : words.slice(1)
  if (isListOnly || !isRecursive || !reachesHidden) return { paths, isListOnly }
  const respectsIgnore = !isIgnoreOff && (isGrep ? name === 'grep' && isPlain : true)
  return { paths, isListOnly, search: { dirs: paths.length > 0 ? paths : ['.'], excludes, includes, respectsIgnore } }
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
  /** Recursive searches that print matching lines and may reach files nobody named. */
  searches: Search[]
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

const dedupe = <T>(items: readonly T[]): T[] => {
  const seen = new Set<string>()
  return items.filter((item) => {
    const key = JSON.stringify(item)
    return seen.has(key) ? false : (seen.add(key), true)
  })
}

function analyzeSegments(command: string, segments: readonly Segment[], depth: number): CommandFacts {
  const readFiles: string[] = []
  const secretVars: string[] = []
  let isEnvDump = false
  const searches: Search[] = []
  /** Files this command fills with the value of a secret variable, and which variables. */
  const written = new Map<string, string[]>()

  for (const segment of segments) {
    const { name, args, isBareEnv, isPlain } = programOf(segment.words)
    if (written.size > 0 && (VIEWERS.has(name) || name === 'sed' || name === 'awk')) {
      for (const file of operands(args)) secretVars.push(...(written.get(file) ?? []))
    }
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
      const printed: string[] = []
      for (const match of segment.words.join(' ').matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)) {
        if (match[1] !== undefined && isSecretName(match[1])) printed.push(match[1])
      }
      // Redirected to a file, the value is not printed; reading that file back in the same command is.
      const targets = outputTargets(args)
      if (targets.length === 0) secretVars.push(...printed)
      else if (printed.length > 0) for (const target of targets) written.set(target, printed)
    } else if (SEARCHERS.has(name)) {
      const parsed = parseSearch(name, args, isPlain)
      if (parsed.search !== undefined) searches.push(parsed.search)
      // A search that names a sensitive file is a plain read of it, unless it only lists names or counts.
      if (!parsed.isListOnly) {
        for (const file of parsed.paths) {
          if (/^\/proc\/[^/]+\/environ$/.test(file)) isEnvDump = true
          else if (isSensitiveOperand(file)) readFiles.push(file)
        }
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
      searches.push(...facts.searches)
      git = [...git, ...facts.git]
      touches ||= facts.touchesConfig
    }
  }

  return { readFiles: [...new Set(readFiles)], isEnvDump, secretVars: [...new Set(secretVars)], searches: dedupe(searches), git, touchesConfig: touches, namesOnly: namesOnlyFor(segments, readFiles, isEnvDump) }
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

/** `sed` options that edit the file in place: `-i`, `-i.bak`, `-Ei`, `--in-place`. */
const isInPlace = (word: string): boolean => /^-[EnrsuzS]*i/.test(word) || word === '--in-place' || word.startsWith('--in-place=')

/** The files `sed -i` rewrites, or `undefined` when it is not an in-place edit of named files. */
function inPlaceTargets(args: readonly string[]): string[] | undefined {
  if (!args.some(isInPlace)) return undefined
  const words: string[] = []
  for (let i = 0; i < args.length; i++) {
    const word = args[i] as string
    if (word === '-i' && args[i + 1] === '') i++ // macOS: the backup suffix is its own, empty, word
    else if (word === '-e' || word === '-f') {
      words.push('-e')
      i++
    } else if (!isFlag(word) || word === '-') words.push(word)
  }
  const script = words.includes('-e') ? 0 : 1
  const targets = words.filter((w) => w !== '-e').slice(script)
  return targets.length > 0 ? targets : undefined
}

/** True when a `tee` segment sends its standard output to /dev/null, so it writes the files and prints nothing. */
const isQuietTee = (args: readonly string[]): boolean => {
  for (let i = 0; i < args.length; i++) {
    if (/^>>?$/.test(args[i] as string) && args[i + 1] === '/dev/null') return true
  }
  return false
}

/** The files a command only writes to, or `undefined` when it does anything else as well. */
function writeTargetsOf(command: string, segments: readonly Segment[]): string[] | undefined {
  if (substitutions(command).length > 0) return undefined
  if (segments.length === 1) {
    const { name, args } = programOf((segments[0] as Segment).words)
    if (name === 'sed') return inPlaceTargets(args)
    if (!WRITERS.has(name)) return undefined
    const targets = outputTargets(args)
    return targets.length > 0 ? targets : undefined
  }
  // `echo … | tee -a file > /dev/null`: tee prints what it writes, so only the quiet form is a plain write.
  if (segments.length === 2 && (segments[0] as Segment).pipeline === (segments[1] as Segment).pipeline) {
    const writer = programOf((segments[0] as Segment).words)
    const tee = programOf((segments[1] as Segment).words)
    if (!['echo', 'printf'].includes(writer.name) || outputTargets(writer.args).length > 0) return undefined
    if (tee.name !== 'tee' || !isQuietTee(tee.args)) return undefined
    const targets = operands(tee.args).filter((word) => word !== '/dev/null')
    return targets.length > 0 ? targets : undefined
  }
  return undefined
}

export function analyzeCommand(command: string): CommandFacts {
  const segments = parseCommand(command)
  const facts = analyzeSegments(command, segments, 0)
  const writeTargets = writeTargetsOf(command, segments)
  return writeTargets === undefined ? facts : { ...facts, writeTargets }
}
