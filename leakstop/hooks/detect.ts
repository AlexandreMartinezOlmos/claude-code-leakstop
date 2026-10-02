// Detection: path rules, regexes, entropy, allowlist and false-positive
// exclusions. Pure functions: no `$`, no I/O, no state.
//
// A Finding carries the secret's `value` so the caller can fingerprint and mask
// it. It must never be stored, logged or sent anywhere: turn it into a
// MaskedFinding with `describe` (mask.ts) and drop it.

import { NPMRC_RULES, PYPIRC_RULES, RULES } from './rules.ts'
import type { Rule, Severity } from './rules.ts'

export type { Rule, Severity } from './rules.ts'

/** `$.fs.read` accepts 4 MiB; anything larger is skipped, not scanned. */
export const MAX_SCAN_CHARS = 4 * 1024 * 1024

export type Finding = {
  ruleId: string
  label: string
  severity: Severity
  /** 1-based, relative to the scanned text. */
  line: number
  start: number
  end: number
  /** The secret itself. In memory only. */
  value: string
  prefix?: string
  isGeneric: boolean
}

export type ScanResult = {
  findings: Finding[]
  /** True when the text was over MAX_SCAN_CHARS and nothing was scanned. */
  isSkipped: boolean
  /** True when the custom rules ran out of their time budget and did not cover all the text. */
  isPartial: boolean
}

export type ScanOptions = {
  /** Path of the file the text is going to, when there is one. */
  path?: string
  /** Extra rules, already validated by the caller. */
  extraRules?: readonly Rule[]
}

// --- Entropy ---------------------------------------------------------------

/** Shannon entropy of `text`, in bits per character. */
export function entropy(text: string): number {
  if (text.length === 0) return 0
  const counts = new Map<string, number>()
  for (const char of text) counts.set(char, (counts.get(char) ?? 0) + 1)
  let bits = 0
  for (const count of counts.values()) {
    const p = count / text.length
    bits -= p * Math.log2(p)
  }
  return bits
}

// --- Paths -----------------------------------------------------------------

export type PathKind = 'env' | 'private-key' | 'credentials' | 'terraform-state' | 'package-auth'

export type PathClass = {
  kind: PathKind
  label: string
  /** The file is only sensitive when it holds a token (.npmrc, .pypirc). */
  requiresToken: boolean
}

const baseName = (path: string): string => path.split(/[\\/]/).pop()?.toLowerCase() ?? ''

const ENV_SAFE_SUFFIX = /\.(?:example|sample|template|dist|defaults)$/

/** The sensitive-file rules, by path alone. `undefined`: not sensitive. */
export function classifyPath(path: string): PathClass | undefined {
  const name = baseName(path)
  if (name === '') return undefined
  if (/^\.env(?:\..+)?$/.test(name) || /\.env$/.test(name)) {
    return ENV_SAFE_SUFFIX.test(name) ? undefined : { kind: 'env', label: 'Environment file', requiresToken: false }
  }
  if (/^id_(?:rsa|dsa|ecdsa|ed25519)(?:\..*)?$/.test(name)) {
    return name.endsWith('.pub') ? undefined : { kind: 'private-key', label: 'SSH private key', requiresToken: false }
  }
  if (/\.(?:pem|key|p12|pfx|jks|keystore)$/.test(name)) {
    return { kind: 'private-key', label: 'Key or certificate file', requiresToken: false }
  }
  if (name === 'credentials.json' || /^service-account.*\.json$/.test(name)) {
    return { kind: 'credentials', label: 'Credentials file', requiresToken: false }
  }
  if (/\.tfstate(?:\.backup)?$/.test(name)) {
    return { kind: 'terraform-state', label: 'Terraform state', requiresToken: false }
  }
  if (name === '.npmrc' || name === '.pypirc') {
    return { kind: 'package-auth', label: 'Package registry config', requiresToken: true }
  }
  return undefined
}

/** Firebase's client config files: the Google API key in them identifies the app and is committed by design, so it only warns. */
const FIREBASE_CLIENT_FILES = new Set(['googleservice-info.plist', 'google-services.json'])

const LOCKFILES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
  'cargo.lock',
  'poetry.lock',
  'pipfile.lock',
  'composer.lock',
  'gemfile.lock',
  'go.sum',
])

// --- Allowlist and false-positive exclusions -------------------------------

/** Long words and shapes that a real credential never contains by chance. */
const STRONG_PLACEHOLDER = /example|placeholder|changeme|change[-_ ]?me|dummy|sample|redacted|insert|replace|(?:^|[-_])your[-_]|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|^\$[A-Za-z_]|^%\(/i
/** Short fragments that a random key can contain by chance (`-my_`, `xxxx`): they only count in a low-entropy value. */
const WEAK_PLACEHOLDER = /(?:^|[-_])my[-_]|todo|fixme|x{4,}|\*{4,}|•{3,}|\.{3,}|0{8,}|#{4,}/i
/** A random 20+ character key is above this; `your-key-here` and `xxxxxxxx` are well below. */
const RANDOM_ENTROPY = 4.2
const WEAK_PASSWORDS = new Set(['password', 'passwd', 'pass', 'pwd', 'secret', 'admin', 'root', 'test', 'user', 'guest', 'postgres', 'mysql', 'redis'])

/**
 * Placeholders and documentation examples: `your-api-key`, `changeme`,
 * `<TOKEN>`, `xxxx…`, AWS's `…EXAMPLE` keys and anything that is a reference
 * to a variable instead of a value. A high-entropy value is never called a
 * placeholder because of a short fragment: that would let a real key through.
 */
export function isPlaceholder(value: string): boolean {
  if (STRONG_PLACEHOLDER.test(value)) return true
  if (WEAK_PLACEHOLDER.test(value) && entropy(value) < RANDOM_ENTROPY) return true
  if (WEAK_PASSWORDS.has(value.toLowerCase())) return true
  // One repeated character, with or without a known prefix.
  return /^(.)\1+$/.test(value.replace(/^[A-Za-z]{1,6}[-_]/, ''))
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const GIT_SHA = /^[0-9a-f]{40}$/i
const INTEGRITY = /^sha(?:1|256|384|512)-[A-Za-z0-9+/=]+$/
const DATA_URI = /^data:[a-z]+\/[a-z0-9.+-]+;base64,/i
const DOTTED_PATH = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$/
const CONSTANT_NAME = /^[A-Z][A-Z0-9_]+$/
const WORD_LIST = /^[A-Za-z]+(?:[-_][A-Za-z]+)+$/

/** Typical false positives of the generic heuristic: hashes, ids, code, URLs and paths. */
export function isFalsePositive(value: string): boolean {
  return (
    UUID.test(value) ||
    GIT_SHA.test(value) ||
    INTEGRITY.test(value) ||
    DATA_URI.test(value) ||
    DOTTED_PATH.test(value) || // process.env.API_KEY, os.environ.get
    CONSTANT_NAME.test(value) || // the name of an environment variable
    WORD_LIST.test(value) || // some-config-value
    value.includes('://') ||
    value.startsWith('/') ||
    value.startsWith('./') ||
    value.startsWith('../')
  )
}

// --- Scanning --------------------------------------------------------------

/**
 * Custom rules come from the repository, so they run under a cost bound whatever
 * they are: over windows of this many characters, overlapping by the difference
 * with STRIDE, and within a total time budget. A slow pattern can then cost at
 * most a window's worth per window, and never the hook's 10 seconds.
 */
const WINDOW = 600
const STRIDE = 400
const CUSTOM_BUDGET_MS = 500

type Budget = { deadline: number; isPartial: boolean }

function* windowedMatches(regex: RegExp, text: string, budget: Budget): Generator<RegExpMatchArray> {
  const seen = new Set<number>()
  for (let from = 0; from < text.length; from += STRIDE) {
    if (performance.now() > budget.deadline) {
      budget.isPartial = true
      return
    }
    for (const match of text.slice(from, from + WINDOW).matchAll(regex)) {
      const start = from + (match.index ?? 0)
      if (seen.has(start)) continue
      seen.add(start)
      match.index = start
      yield match
    }
    if (from + WINDOW >= text.length) return
  }
}

/** 1-based line of each offset, from a table of line starts built once. */
function lineIndex(text: string): (offset: number) => number {
  const starts = [0]
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1)
  return (offset) => {
    let low = 0
    let high = starts.length - 1
    while (low < high) {
      const mid = (low + high + 1) >> 1
      if ((starts[mid] ?? 0) <= offset) low = mid
      else high = mid - 1
    }
    return low + 1
  }
}

const overlaps = (a: Finding, b: Finding): boolean => a.start < b.end && b.start < a.end

/** Scans `text` for secrets. Findings come back in order of position. */
export function scanText(text: string, options: ScanOptions = {}): ScanResult {
  if (text.length > MAX_SCAN_CHARS) return { findings: [], isSkipped: true, isPartial: false }

  const name = options.path === undefined ? '' : baseName(options.path)
  const rules: Rule[] = [...RULES, ...(options.extraRules ?? [])]
  if (name === '.npmrc') rules.push(...NPMRC_RULES)
  if (name === '.pypirc') rules.push(...PYPIRC_RULES)
  // Lockfiles are full of integrity hashes; only precise provider rules apply.
  const isLockfile = LOCKFILES.has(name)

  const lineOf = lineIndex(text)
  const found: Finding[] = []
  const budget: Budget = { deadline: performance.now() + CUSTOM_BUDGET_MS, isPartial: false }

  for (const rule of rules) {
    if (isLockfile && rule.isGeneric) continue
    const matches = rule.id.startsWith('custom:') ? windowedMatches(rule.regex, text, budget) : text.matchAll(rule.regex)
    for (const match of matches) {
      const groupValue = rule.groups?.map((g) => match[g]).find((v) => v !== undefined)
      const value = rule.groups === undefined ? match[0] : groupValue
      if (value === undefined || value === '') continue
      if (isPlaceholder(value)) continue
      if (rule.accept !== undefined && !rule.accept(value, match)) continue
      if (rule.minEntropy !== undefined && entropy(value) < rule.minEntropy) continue
      if (rule.isGeneric === true && isFalsePositive(value)) continue
      const start = match.index ?? 0
      found.push({
        ruleId: rule.id,
        label: rule.label,
        severity: rule.id === 'google-api-key' && FIREBASE_CLIENT_FILES.has(name) ? 'medium' : rule.severity,
        line: lineOf(start),
        start,
        end: start + match[0].length,
        value,
        prefix: rule.prefix,
        isGeneric: rule.isGeneric === true,
      })
    }
  }

  // A precise finding wins over a heuristic one on the same text.
  const precise = found.filter((f) => !f.isGeneric)
  const findings = [...precise, ...found.filter((f) => f.isGeneric && !precise.some((p) => overlaps(f, p)))]
  findings.sort((a, b) => a.start - b.start)
  return { findings, isSkipped: false, isPartial: budget.isPartial }
}

/** Write: the whole content and the path. */
export function scanWrite(path: string, content: string, options: Omit<ScanOptions, 'path'> = {}): ScanResult {
  return scanText(content, { ...options, path })
}

/**
 * Edit: only the new text, so secrets that were already in the file do not
 * warn. A secret that is also in the replaced text was there before.
 */
export function scanEdit(path: string, oldString: string, newString: string, options: Omit<ScanOptions, 'path'> = {}): ScanResult {
  const result = scanText(newString, { ...options, path })
  return { ...result, findings: result.findings.filter((f) => !oldString.includes(f.value)) }
}
