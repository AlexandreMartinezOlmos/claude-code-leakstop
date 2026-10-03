import { expect, test } from 'claude-code/testing'
import type { StoredFinding } from '../types'
import { USAGE, allowedText, bannerLine, fit, formatTime, historyRows, mergeAllowed, parseArgs, resolveIds, summaryText, where } from '../hooks/ui.ts'

const finding = (over: Partial<StoredFinding> = {}): StoredFinding => ({
  fingerprint: 'sha256:0123456789abcdef',
  ruleId: 'jwt',
  label: 'JSON Web Token',
  severity: 'medium',
  path: 'tests/fixtures/user.json',
  line: 8,
  tool: 'Write',
  decision: 'warned',
  at: 1_700_000_000_000,
  ...over,
})

test('fit cuts with an ellipsis and never exceeds the width', () => {
  expect(fit('hello', 10)).toBe('hello')
  expect(fit('hello world', 6)).toBe('hello…')
  expect(fit('hello', 0)).toBe('')
  for (let width = 1; width < 20; width++) expect(fit('x'.repeat(30), width).length).toBeLessThanOrEqual(width)
})

test('formats the time as HH:MM', () => {
  expect(formatTime(1_700_000_000_000)).toMatch(/^\d{2}:\d{2}$/)
})

test('says where it happened', () => {
  expect(where(finding())).toBe('tests/fixtures/user.json:8')
  expect(where(finding({ path: '', tool: 'Bash', line: 0 }))).toBe('Bash command')
  expect(where(finding({ path: '.env', line: 0 }))).toBe('.env')
})

test('the banner names severity, type, place and the command, in the spec’s shape', () => {
  expect(bannerLine([finding()], false, 100)).toBe('△ LeakStop · MEDIUM · JSON Web Token in tests/fixtures/user.json:8 · warned · /leakstop')
  expect(bannerLine([finding({ severity: 'critical' })], false, 100).includes('CRITICAL')).toBe(true)
  expect(bannerLine([finding(), finding()], false, 120).includes('(+1 more)')).toBe(true)
  expect(bannerLine([], false, 100)).toBe('')
})

test('the banner leaves two cells free on the first row and keeps the command hint', () => {
  for (const width of [30, 40, 60, 80, 120]) {
    const line = bannerLine([finding({ path: 'packages/some/very/deep/folder/with/a/long/name/config.json' })], false, width)
    expect(line.length).toBeLessThanOrEqual(width - 2)
    if (width >= 40) expect(line.endsWith('/leakstop')).toBe(true)
  }
  expect(bannerLine([finding()], false, 5).length).toBeLessThanOrEqual(3)
})

test('a paused session says so, whatever else is waiting', () => {
  const line = bannerLine([finding()], true, 100)
  expect(line.includes('PAUSED')).toBe(true)
  expect(line.endsWith('/leakstop resume')).toBe(true)
})

test('the history is numbered, newest first, and fitted', () => {
  const findings = [finding({ label: 'first' }), finding({ label: 'second', decision: 'denied', severity: 'critical' }), finding({ label: 'third', decision: 'passed' })]
  const rows = historyRows(findings, 60)
  expect(rows.map((r) => r.head.slice(0, 2))).toEqual(['#3', '#2', '#1'])
  expect(rows[1]?.head.includes('CRITICAL')).toBe(true)
  expect(rows[1]?.detail.includes('denied')).toBe(true)
  expect(rows[0]?.detail.includes('git ignores')).toBe(true)
  for (const row of rows) {
    expect(row.head.length).toBeLessThanOrEqual(60)
    expect(row.detail.length).toBeLessThanOrEqual(60)
  }
})

test('the text summary lists findings without values and says how to allow one', () => {
  expect(summaryText([], false)).toBe('LeakStop · no findings this session')
  expect(summaryText([], true).includes('PAUSED')).toBe(true)
  const many = Array.from({ length: 20 }, (_, i) => finding({ label: `type ${i}` }))
  const text = summaryText(many, false)
  expect(text.split('\n').length).toBe(1 + 15 + 1 + 1)
  expect(text.includes('…and 5 older')).toBe(true)
  expect(text.includes('/leakstop allow')).toBe(true)
  expect(summaryText([finding()], false).startsWith('LeakStop · 1 finding this session')).toBe(true)
})

test('parses the subcommands', () => {
  expect(parseArgs('')).toEqual({ kind: 'open' })
  expect(parseArgs('  ')).toEqual({ kind: 'open' })
  expect(parseArgs('pause')).toEqual({ kind: 'pause' })
  expect(parseArgs('resume')).toEqual({ kind: 'resume' })
  expect(parseArgs('allow 1 sha256:0123456789abcdef')).toEqual({ kind: 'allow', ids: ['1', 'sha256:0123456789abcdef'] })
  for (const bad of ['allow', 'pause now', 'help', 'allowall 1']) expect(parseArgs(bad)).toEqual({ kind: 'usage' })
  expect(USAGE.includes('/leakstop allow')).toBe(true)
})

test('resolves numbers and fingerprints, and reports what it does not know', () => {
  const findings = [finding({ fingerprint: 'sha256:aaaaaaaaaaaaaaaa' }), finding({ fingerprint: 'sha256:bbbbbbbbbbbbbbbb' })]
  expect(resolveIds(['1', '#2', 'SHA256:CCCCCCCCCCCCCCCC', 'dddddddddddddddd'], findings)).toEqual({
    fingerprints: ['sha256:aaaaaaaaaaaaaaaa', 'sha256:bbbbbbbbbbbbbbbb', 'sha256:cccccccccccccccc', 'sha256:dddddddddddddddd'],
    unknown: [],
  })
  expect(resolveIds(['9', 'nonsense', '1', '1'], findings)).toEqual({ fingerprints: ['sha256:aaaaaaaaaaaaaaaa'], unknown: ['9', 'nonsense'] })
})

test('parses allowed, forget and reload', () => {
  expect(parseArgs('allowed')).toEqual({ kind: 'allowed' })
  expect(parseArgs('list')).toEqual({ kind: 'allowed' })
  expect(parseArgs('forget 2 sha256:0123456789abcdef')).toEqual({ kind: 'forget', ids: ['2', 'sha256:0123456789abcdef'] })
  expect(parseArgs('forget all')).toEqual({ kind: 'forget', ids: ['all'] })
  expect(parseArgs('reload')).toEqual({ kind: 'reload' })
  for (const bad of ['forget', 'allowed 1', 'reload now', 'list all']) expect(parseArgs(bad)).toEqual({ kind: 'usage' })
  for (const word of ['allowed', 'forget', 'reload']) expect(USAGE.includes(`/leakstop ${word}`)).toBe(true)
})

test('merges where each allowed fingerprint came from, and says what the history knows about it', () => {
  const a = 'sha256:aaaaaaaaaaaaaaaa'
  const b = 'sha256:bbbbbbbbbbbbbbbb'
  const c = 'sha256:cccccccccccccccc'
  expect(mergeAllowed([a], [a, b], [c])).toEqual([
    { fingerprint: a, sources: ['forever', 'session'] },
    { fingerprint: b, sources: ['forever'] },
    { fingerprint: c, sources: ['project'] },
  ])
  const text = allowedText(mergeAllowed([a], [b], [c]), [finding({ fingerprint: a, label: 'GitHub token', path: 'src/a.ts', line: 3 })])
  expect(text.startsWith('LeakStop · 3 allowed')).toBe(true)
  expect(text.includes(`${a} · this session · GitHub token · src/a.ts:3`)).toBe(true)
  expect(text.includes(`${b} · for good\n`)).toBe(true)
  expect(text.includes(`${c} · .leakstop.json`)).toBe(true)
  expect(text.includes('Fingerprints from .leakstop.json are removed by editing that file.')).toBe(true)
  expect(allowedText([], [])).toBe('LeakStop · nothing is allowed: every finding is checked')
})

test('a long list of allowed fingerprints is cut', () => {
  const many = Array.from({ length: 40 }, (_, i) => `sha256:${String(i).padStart(16, '0')}`)
  const text = allowedText(mergeAllowed([], many, []), [])
  expect(text.includes('…and 15 more')).toBe(true)
  expect(text.split('\n').length).toBe(1 + 25 + 1 + 1)
})
