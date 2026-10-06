import { expect, test } from 'claude-code/testing'
import { MAX_CONFIG_CHARS, globToRegExp, matchesAny, parseConfig, regexProblem, toRule } from '../hooks/config.ts'
import { scanText } from '../hooks/detect.ts'
import { random } from './secrets.ts'

const FP = 'sha256:0123456789abcdef'

test('an empty object is a valid config with nothing set', () => {
  expect(parseConfig('{}')).toEqual({ ignorePaths: [], allowFingerprints: [], customRules: [], warnings: [] })
})

test('invalid JSON, a non-object or an oversized file gives the defaults and a warning', () => {
  for (const text of ['{ nope', '', '[]', '"text"', 'null', '42']) {
    const config = parseConfig(text)
    expect(config.ignorePaths).toEqual([])
    expect(config.allowFingerprints).toEqual([])
    expect(config.customRules).toEqual([])
    expect(config.warnings.length).toBe(1)
  }
  expect(parseConfig('x'.repeat(MAX_CONFIG_CHARS + 1)).warnings[0]?.includes('256 KiB')).toBe(true)
})

test('unknown fields are ignored with a warning, the valid ones are kept', () => {
  const config = parseConfig(JSON.stringify({ ignorePaths: ['docs/**'], ignorePath: ['everything'], mode: 'monitor' }))
  expect(config.ignorePaths).toEqual(['docs/**'])
  expect(config.warnings).toEqual(['unknown fields ignored: ignorePath, mode'])
})

test('a field of the wrong type is ignored, which means the strict default', () => {
  const config = parseConfig(JSON.stringify({ ignorePaths: 'docs/**', allowFingerprints: { a: 1 }, customRules: 'x' }))
  expect(config.ignorePaths).toEqual([])
  expect(config.allowFingerprints).toEqual([])
  expect(config.customRules).toEqual([])
  expect(config.warnings.length).toBe(3)
})

test('allowFingerprints only keeps well-formed fingerprints', () => {
  const config = parseConfig(JSON.stringify({ allowFingerprints: [FP, FP, 'sha256:xyz', 'whatever', 7, 'sha256:0123456789ABCDEF'] }))
  expect(config.allowFingerprints).toEqual([FP])
  expect(config.warnings).toEqual(['allowFingerprints: 4 entries ignored (not a sha256: fingerprint)'])
})

test('lists are bounded', () => {
  const many = Array.from({ length: 300 }, (_, i) => `dir${i}/**`)
  const config = parseConfig(JSON.stringify({ ignorePaths: many }))
  expect(config.ignorePaths.length).toBe(200)
  expect(config.warnings.some((w) => w.includes('more than 200'))).toBe(true)
})

test('ignorePaths globs: ** crosses folders, * and ? do not, no slash means any depth, a trailing slash means everything under it', () => {
  const m = (glob: string, path: string): boolean => matchesAny(path, [glob])
  expect(m('tests/fixtures/**', 'tests/fixtures/user.json')).toBe(true)
  expect(m('tests/fixtures/**', 'tests/fixtures/deep/er/user.json')).toBe(true)
  expect(m('tests/fixtures/**', 'tests/other/user.json')).toBe(false)
  expect(m('tests/*/user.json', 'tests/fixtures/user.json')).toBe(true)
  expect(m('tests/*/user.json', 'tests/a/b/user.json')).toBe(false)
  expect(m('**/fixtures/*.json', 'a/b/fixtures/x.json')).toBe(true)
  expect(m('**/fixtures/*.json', 'fixtures/x.json')).toBe(true)
  expect(m('*.snap', 'src/deep/a.snap')).toBe(true)
  expect(m('*.snap', 'a.snapshot')).toBe(false)
  expect(m('docs/', 'docs/guide/a.md')).toBe(true)
  expect(m('docs/', 'src/docs/a.md')).toBe(false)
  expect(m('a?.txt', 'ab.txt')).toBe(true)
  expect(m('a?.txt', 'a/b.txt')).toBe(false)
  expect(m('./tests/**', 'tests/a.ts')).toBe(true)
  expect(m('tests/**', './tests/a.ts')).toBe(true)
  expect(m('tests/**', 'tests\\win\\a.ts')).toBe(true)
  // Regex characters in a pattern are literal.
  expect(m('a+b(1).txt', 'a+b(1).txt')).toBe(true)
  expect(m('a.b', 'axb')).toBe(false)
  expect(matchesAny('anything', [])).toBe(false)
})

test('absurd globs are rejected', () => {
  expect(globToRegExp('')).toBe(undefined)
  expect(globToRegExp('x'.repeat(201))).toBe(undefined)
  expect(globToRegExp('**/**/**/**/x')).toBe(undefined)
  const config = parseConfig(JSON.stringify({ ignorePaths: ['', '**/**/**/**/x', 'ok/**'] }))
  expect(config.ignorePaths).toEqual(['ok/**'])
})

test('hostile globs stay fast, and a very long path is never ignored', () => {
  const hostile = ['**/**/**/x', '*/*/*/*/*/*/y', '**/a/**/a/**/zzz']
  const longest = `${'a/'.repeat(250)}file.json` // just under the limit
  let startedAt = performance.now()
  expect(matchesAny(longest, hostile)).toBe(false)
  expect(performance.now() - startedAt).toBeLessThan(500)

  const absurd = `${'a/'.repeat(1500)}file.json`
  startedAt = performance.now()
  expect(matchesAny(absurd, ['**'])).toBe(false) // even a pattern that would match everything
  expect(performance.now() - startedAt).toBeLessThan(50)
})

// --- Custom rules ------------------------------------------------------------

test('a custom rule is validated, prefixed and usable by the scanner', () => {
  const config = parseConfig(JSON.stringify({ customRules: [{ id: 'acme-token', regex: 'acme_[A-Za-z0-9]{32}', severity: 'critical', label: 'ACME token', prefix: 'acme_' }] }))
  expect(config.warnings).toEqual([])
  expect(config.customRules.length).toBe(1)
  expect(config.customRules[0]?.id).toBe('custom:acme-token')

  const rule = toRule(config.customRules[0] as any)
  const secret = `acme_${random(32)}`
  const found = scanText(`const t = "${secret}"`, { extraRules: rule === undefined ? [] : [rule] }).findings
  expect(found.length).toBe(1)
  expect(found[0]?.ruleId).toBe('custom:acme-token')
  expect(found[0]?.label).toBe('ACME token')
  expect(found[0]?.severity).toBe('critical')
  expect(found[0]?.prefix).toBe('acme_')
})

test('a custom rule can capture the secret in a group and ask for entropy', () => {
  const config = parseConfig(JSON.stringify({ customRules: [{ id: 'internal', regex: 'corp-key=([A-Za-z0-9]{20,})', severity: 'medium', group: 1, minEntropy: 3.5 }] }))
  const rule = toRule(config.customRules[0] as any)
  const extraRules = rule === undefined ? [] : [rule]
  const secret = random(24)
  expect(scanText(`corp-key=${secret}`, { extraRules }).findings[0]?.value).toBe(secret)
  expect(scanText(`corp-key=${'a'.repeat(24)}`, { extraRules }).findings).toEqual([])
})

test('bad custom rules are ignored one by one, with a reason', () => {
  const config = parseConfig(
    JSON.stringify({
      customRules: [
        { id: 'good', regex: 'good_[0-9]{10}', severity: 'critical' },
        { id: 'Bad Id', regex: 'x_[0-9]{10}', severity: 'critical' },
        { id: 'good', regex: 'dup_[0-9]{10}', severity: 'critical' },
        { id: 'no-severity', regex: 'y_[0-9]{10}' },
        { id: 'broken', regex: '([', severity: 'critical' },
        { id: 'extra', regex: 'z_[0-9]{10}', severity: 'critical', allow: true },
        'not an object',
      ],
    }),
  )
  expect(config.customRules.map((r) => r.id)).toEqual(['custom:good'])
  expect(config.warnings.length).toBe(6)
})

test('catastrophic and unsafe regexes are rejected', () => {
  for (const regex of ['(a+)+$', '(a*)*b', '(.*)*x', '(\\w+\\s?)+$', '([a-z]+)*end', '(a{1,}){1,}', '(x+x+)+y', '^(\\d+)*$', '.*.*.*.*.*=.*', '(a)\\1', '(?=x)y', '(?<!a)b', 'a*', '']) {
    expect(regexProblem(regex) !== undefined).toBe(true)
  }
  expect(regexProblem('x'.repeat(201))).toBe('must be 1 to 200 characters')
})

test('ordinary rules are accepted', () => {
  for (const regex of ['acme_[A-Za-z0-9]{32}', 'AKIA[0-9A-Z]{16}', '(?:foo|bar)_[a-z0-9]{12,40}', 'tok-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}', 'secret\\(([^)]{6,30})\\)', '\\bcorp_[A-Za-z0-9_-]{20,64}']) {
    expect(regexProblem(regex)).toBe(undefined)
  }
})

test('a custom regex cannot slow the scanner down, whatever it is', () => {
  // `[a-z]+_[0-9]+_[a-z]+` is accepted but quadratic on a long run of letters: the scan cost is bounded anyway.
  const rules = ['[a-z]+_[0-9]+_[a-z]+', 'acme_[A-Za-z0-9]{32}', '(?:foo|bar)_[a-z0-9]{12,40}'].map((source) => toRule({ id: 'custom:t', label: 't', severity: 'critical', source }))
  for (const rule of rules) {
    for (const text of ['a'.repeat(300_000), 'ab_'.repeat(100_000), `${'a_1_'.repeat(50_000)}!`]) {
      const startedAt = performance.now()
      scanText(text, { extraRules: rule === undefined ? [] : [rule] })
      expect(performance.now() - startedAt).toBeLessThan(1500)
    }
  }
})

test('a quadratic custom rule reports that it did not cover everything', () => {
  const rule = toRule({ id: 'custom:q', label: 'q', severity: 'critical', source: '[a-z]+_[0-9]+_[a-z]+' })
  const result = scanText('a'.repeat(3_000_000), { extraRules: rule === undefined ? [] : [rule] })
  expect(result.isSkipped).toBe(false)
  expect(result.isPartial).toBe(true)
  // Ordinary text is fully covered.
  expect(scanText('const a = 1', { extraRules: rule === undefined ? [] : [rule] }).isPartial).toBe(false)
})

test('custom rules still find a secret anywhere in a large file, across window edges', () => {
  const rule = toRule({ id: 'custom:acme', label: 'ACME', severity: 'critical', source: 'acme_[A-Za-z0-9]{32}' })
  const secret = `acme_${random(32)}`
  for (const offset of [0, 399, 400, 401, 590, 599, 600, 601, 1234, 20_000]) {
    const text = `${'x'.repeat(offset)} ${secret} ${'y'.repeat(2000)}`
    const found = scanText(text, { extraRules: rule === undefined ? [] : [rule] }).findings
    expect(found.length).toBe(1)
    expect(found[0]?.value).toBe(secret)
  }
  // The same secret twice is two findings, not four.
  const twice = scanText(`${secret} ${'z'.repeat(450)} ${secret}`, { extraRules: rule === undefined ? [] : [rule] }).findings
  expect(twice.length).toBe(2)
})

test('a stored rule that no longer compiles is dropped, not thrown', () => {
  expect(toRule({ id: 'custom:x', label: 'x', severity: 'critical', source: '([' })).toBe(undefined)
})
