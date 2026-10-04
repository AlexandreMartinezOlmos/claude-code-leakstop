// `.leakstop.json`: parsing and validation. Pure: no `$`, no I/O.
//
// The file comes from the repository, so it is untrusted: a cloned project must
// not be able to lower the protection or slow the scanner down. Whatever is
// wrong with it is ignored with a warning, and ignoring a setting always means
// the stricter default. The file can only add rules or relax medium findings;
// the protection level itself (`mode`) lives in the user's own settings.

import type { StoredConfig, StoredRule } from '../types'
import type { Rule, Severity } from './rules.ts'

/** A config file larger than this is ignored. */
export const MAX_CONFIG_CHARS = 256 * 1024

const MAX_IGNORE_PATHS = 200
const MAX_ALLOW_FINGERPRINTS = 500
const MAX_CUSTOM_RULES = 50
const MAX_PATTERN_CHARS = 200
const MAX_REGEX_CHARS = 200
const KNOWN_KEYS = new Set(['ignorePaths', 'allowFingerprints', 'customRules'])
const KNOWN_RULE_KEYS = new Set(['id', 'regex', 'severity', 'label', 'prefix', 'group', 'minEntropy'])

export const EMPTY_CONFIG: StoredConfig = { ignorePaths: [], allowFingerprints: [], customRules: [], warnings: [] }

// --- Globs for ignorePaths -------------------------------------------------

/**
 * `tests/fixtures/**`, `*.json`, `examples/`. A pattern with no slash matches at any
 * depth, as in .gitignore; `**` crosses folders, `*` and `?` do not.
 */
export function globToRegExp(glob: string): RegExp | undefined {
  const pattern = glob.replace(/\\/g, '/').replace(/^\.\//, '')
  if (pattern === '' || pattern.length > MAX_PATTERN_CHARS) return undefined
  if ((pattern.match(/\*\*/g) ?? []).length > 3) return undefined

  let source = ''
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i] as string
    if (char === '*' && pattern[i + 1] === '*') {
      const isFolder = pattern[i + 2] === '/'
      source += isFolder ? '(?:.*/)?' : '.*'
      i += isFolder ? 2 : 1
    } else if (char === '*') {
      source += '[^/]*'
    } else if (char === '?') {
      source += '[^/]'
    } else {
      source += char.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    }
  }
  if (pattern.endsWith('/')) source += '.*'
  const anywhere = pattern.includes('/') ? '' : '(?:.*/)?'
  return new RegExp(`^${anywhere}${source}$`)
}

/** A longer path never matches: globs come from the repository and can be slow on a very long path, and ignoring a path only ever relaxes. */
const MAX_PATH_CHARS = 512

/** True when `path` matches any pattern. Patterns that do not compile match nothing. */
export function matchesAny(path: string, patterns: readonly string[]): boolean {
  if (path.length > MAX_PATH_CHARS) return false
  const normalized = path.replace(/\\/g, '/').replace(/^\.\//, '')
  return patterns.some((pattern) => globToRegExp(pattern)?.test(normalized) === true)
}

// --- Custom rules ------------------------------------------------------------

/** Walks a regex source and says whether a group holding an unbounded repeat is itself repeated without bound. */
function hasNestedQuantifier(source: string): boolean {
  const stack: boolean[] = []
  let unbounded = 0
  let i = 0
  const isUnboundedAt = (index: number): boolean => {
    const char = source[index]
    if (char === '*' || char === '+') return true
    if (char === '{') return /^\{\d+,\}/.test(source.slice(index))
    return false
  }
  while (i < source.length) {
    const char = source[i] as string
    if (char === '\\') {
      i += 2
      continue
    }
    if (char === '[') {
      i++
      while (i < source.length && source[i] !== ']') i += source[i] === '\\' ? 2 : 1
      i++ // the quantifier after the class, if any, is counted on the next turn
      continue
    }
    if (char === '(') {
      stack.push(false)
    } else if (char === ')') {
      const held = stack.pop() ?? false
      if (held && isUnboundedAt(i + 1)) return true
      if (held && stack.length > 0) stack[stack.length - 1] = true
    } else if (isUnboundedAt(i) && i > 0) {
      unbounded++
      if (stack.length > 0) stack[stack.length - 1] = true
    }
    i++
  }
  // `.*.*.*` and friends are slow without being nested.
  return unbounded > 4
}

const HOSTILE_INPUTS: readonly string[] = [
  'a'.repeat(4000),
  'ab'.repeat(2000),
  ' '.repeat(4000),
  '0123456789abcdef'.repeat(250),
  `${'a'.repeat(22)}!`,
  `${'a '.repeat(11)}!`,
  `${'ab'.repeat(11)}!`,
]
const BUDGET_MS = 40

/**
 * Why a custom regex cannot be used, or `undefined` when it can. It must be
 * short, free of backreferences and lookarounds, free of nested unbounded
 * repeats, and quick on hostile inputs: a rule that makes the scanner run out of
 * its 10 seconds would make Claude Code skip the hook and let the call through.
 */
export function regexProblem(source: string): string | undefined {
  if (source.length === 0 || source.length > MAX_REGEX_CHARS) return `must be 1 to ${MAX_REGEX_CHARS} characters`
  if (/\\[1-9k]/.test(source)) return 'backreferences are not allowed'
  if (/\(\?<?[=!]/.test(source)) return 'lookaheads and lookbehinds are not allowed'
  let regex: RegExp
  try {
    regex = new RegExp(source, 'g')
  } catch {
    return 'is not a valid regular expression'
  }
  if (regex.test('')) return 'matches the empty string'
  if (hasNestedQuantifier(source)) return 'repeats a repeat (for example (a+)+), which can run for ever'
  for (const input of HOSTILE_INPUTS) {
    const startedAt = performance.now()
    input.match(regex)
    if (performance.now() - startedAt > BUDGET_MS) return 'is too slow on long input'
  }
  return undefined
}

function parseRule(raw: unknown, index: number, seen: Set<string>): { rule?: StoredRule; warning?: string } {
  const at = `customRules[${index}]`
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { warning: `${at} is not an object, so it was ignored` }
  const entry = raw as Record<string, unknown>
  const unknown = Object.keys(entry).filter((key) => !KNOWN_RULE_KEYS.has(key))
  if (unknown.length > 0) return { warning: `${at} has unknown fields (${unknown.join(', ')}), so it was ignored` }

  const { id, regex, severity, label, prefix, group, minEntropy } = entry
  if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,39}$/.test(id)) return { warning: `${at}.id must be lowercase letters, digits and dashes (40 at most), so the rule was ignored` }
  if (seen.has(id)) return { warning: `${at}.id "${id}" is used twice, so the second rule was ignored` }
  if (typeof regex !== 'string') return { warning: `${at}.regex must be a string, so the rule was ignored` }
  if (severity !== 'critical' && severity !== 'medium') return { warning: `${at}.severity must be "critical" or "medium", so the rule was ignored` }
  const problem = regexProblem(regex)
  if (problem !== undefined) return { warning: `${at}.regex ${problem}, so the rule was ignored` }

  const rule: StoredRule = { id: `custom:${id}`, label: typeof label === 'string' && label.length > 0 ? label.slice(0, 60) : `Custom rule ${id}`, severity, source: regex }
  if (typeof prefix === 'string' && prefix.length > 0 && prefix.length <= 20) rule.prefix = prefix
  if (typeof group === 'number' && Number.isInteger(group) && group >= 1 && group <= 9) rule.groups = [group]
  if (typeof minEntropy === 'number' && minEntropy >= 0 && minEntropy <= 6) rule.minEntropy = minEntropy
  seen.add(id)
  return { rule }
}

/** A stored rule as the scanner takes it. `undefined` when it no longer compiles. */
export function toRule(stored: StoredRule): Rule | undefined {
  try {
    const rule: Rule = { id: stored.id, label: stored.label, severity: stored.severity as Severity, regex: new RegExp(stored.source, 'g') }
    if (stored.prefix !== undefined) rule.prefix = stored.prefix
    if (stored.groups !== undefined) rule.groups = stored.groups
    if (stored.minEntropy !== undefined) rule.minEntropy = stored.minEntropy
    return rule
  } catch {
    return undefined
  }
}

// --- The file ----------------------------------------------------------------

const FINGERPRINT = /^sha256:[0-9a-f]{16}$/

function stringList(value: unknown, field: string, max: number, warnings: string[], accept: (item: string) => boolean, why: string): string[] {
  if (!Array.isArray(value)) {
    warnings.push(`${field} must be a list of strings, so it was ignored`)
    return []
  }
  const kept: string[] = []
  let dropped = 0
  for (const item of value.slice(0, max)) {
    if (typeof item === 'string' && accept(item)) kept.push(item)
    else dropped++
  }
  if (value.length > max) warnings.push(`${field} has more than ${max} entries; the rest were ignored`)
  if (dropped > 0) warnings.push(`${field}: ${dropped} entr${dropped === 1 ? 'y' : 'ies'} ignored (${why})`)
  return [...new Set(kept)]
}

/**
 * Reads the text of `.leakstop.json`. Never throws: a malformed file gives the
 * defaults and a warning, an unknown or malformed field is ignored with a
 * warning, and the valid fields are kept.
 */
export function parseConfig(text: string): StoredConfig {
  if (text.length > MAX_CONFIG_CHARS) return { ...EMPTY_CONFIG, warnings: ['.leakstop.json is larger than 256 KiB, so it was ignored'] }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return { ...EMPTY_CONFIG, warnings: ['.leakstop.json is not valid JSON, so the defaults apply'] }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ...EMPTY_CONFIG, warnings: ['.leakstop.json must hold a JSON object, so the defaults apply'] }
  }

  const root = parsed as Record<string, unknown>
  const warnings: string[] = []
  const unknown = Object.keys(root).filter((key) => !KNOWN_KEYS.has(key))
  if (unknown.length > 0) warnings.push(`unknown field${unknown.length === 1 ? '' : 's'} ignored: ${unknown.join(', ')}`)

  const ignorePaths =
    root.ignorePaths === undefined
      ? []
      : stringList(root.ignorePaths, 'ignorePaths', MAX_IGNORE_PATHS, warnings, (item) => globToRegExp(item) !== undefined, 'empty, too long or too many **')
  const allowFingerprints =
    root.allowFingerprints === undefined
      ? []
      : stringList(root.allowFingerprints, 'allowFingerprints', MAX_ALLOW_FINGERPRINTS, warnings, (item) => FINGERPRINT.test(item), 'not a sha256: fingerprint')

  const customRules: StoredRule[] = []
  if (root.customRules !== undefined) {
    if (!Array.isArray(root.customRules)) {
      warnings.push('customRules must be a list, so it was ignored')
    } else {
      if (root.customRules.length > MAX_CUSTOM_RULES) warnings.push(`customRules has more than ${MAX_CUSTOM_RULES} rules; the rest were ignored`)
      const seen = new Set<string>()
      root.customRules.slice(0, MAX_CUSTOM_RULES).forEach((raw, index) => {
        const { rule, warning } = parseRule(raw, index, seen)
        if (rule !== undefined) customRules.push(rule)
        if (warning !== undefined) warnings.push(warning)
      })
    }
  }

  return { ignorePaths, allowFingerprints, customRules, warnings }
}
