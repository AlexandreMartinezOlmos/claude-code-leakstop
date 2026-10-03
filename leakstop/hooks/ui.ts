// What the banner, the history panel and the `/leakstop` command say. Pure: no `$`.
//
// Strings are fitted to the width the surface gives (`bodyColumns`), so nothing
// here depends on the terminal's own size.

import type { StoredFinding } from '../types'
import { toolLabel } from './outbound.ts'

/** `…` when a line is cut. */
export function fit(text: string, width: number): string {
  if (width <= 0) return ''
  return text.length <= width ? text : `${text.slice(0, Math.max(0, width - 1))}…`
}

/** `HH:MM` in the user's time zone. */
export function formatTime(at: number): string {
  const date = new Date(at)
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
}

const SEVERITY = { critical: 'CRITICAL', medium: 'MEDIUM' } as const

/** Where it happened: a file and line, or the command. */
export function where(finding: StoredFinding): string {
  if (finding.path === '') return finding.tool === 'Bash' ? 'Bash command' : `${toolLabel(finding.tool)} call`
  return finding.line > 0 ? `${finding.path}:${finding.line}` : finding.path
}

/** What happened to it, in words. */
export function outcome(finding: StoredFinding): string {
  switch (finding.decision) {
    case 'allowed':
      return 'allowed'
    case 'denied':
      return 'denied'
    case 'warned':
      return finding.severity === 'critical' ? 'logged, not enforced' : 'warned'
    case 'passed':
      return 'passed (git ignores this file)'
  }
}

/**
 * The one line above the prompt. `width` is the room the band has: the first
 * row is two cells shorter, because the terminal draws the pane's closing mark over it.
 */
export function bannerLine(banner: readonly StoredFinding[], paused: boolean, width: number): string {
  const room = Math.max(0, width - 2)
  if (paused) return fit('△ LeakStop · PAUSED · nothing is being checked · /leakstop resume', room)
  const latest = banner[banner.length - 1]
  if (latest === undefined) return ''
  const more = banner.length > 1 ? ` (+${banner.length - 1} more)` : ''
  const head = `△ LeakStop · ${SEVERITY[latest.severity]} · ${latest.label} in ${where(latest)}${more}`
  const tail = ` · ${latest.severity === 'critical' ? 'logged' : 'warned'} · /leakstop`
  return room < tail.length + 12 ? fit(`${head}${tail}`, room) : `${fit(head, room - tail.length)}${tail}`
}

export type HistoryRow = { head: string; detail: string }

/** The history, newest first, numbered as `/leakstop allow <number>` counts them. */
export function historyRows(findings: readonly StoredFinding[], width: number): HistoryRow[] {
  return findings
    .map((finding, index): HistoryRow => ({
      head: fit(`#${index + 1} ${formatTime(finding.at)} ${SEVERITY[finding.severity].padEnd(8)} ${finding.label} · ${where(finding)}`, width),
      detail: fit(`   → ${outcome(finding)}`, width),
    }))
    .reverse()
}

const MAX_TEXT_ROWS = 15

/** The same history as plain text, for where no panel can be drawn. */
export function summaryText(findings: readonly StoredFinding[], paused: boolean, warnings: readonly string[] = []): string {
  const state = paused ? ' · PAUSED (nothing is being checked)' : ''
  const notes = warnings.slice(0, 5).map((warning) => `.leakstop.json: ${warning}`)
  if (findings.length === 0) return [`LeakStop · no findings this session${state}`, ...notes].join('\n')
  const rows = historyRows(findings, 200).slice(0, MAX_TEXT_ROWS)
  const lines = rows.map((row) => `${row.head} ${row.detail.trim()}`)
  const hidden = findings.length - rows.length
  return [
    `LeakStop · ${findings.length} finding${findings.length === 1 ? '' : 's'} this session${state}`,
    ...lines,
    ...(hidden > 0 ? [`…and ${hidden} older`] : []),
    ...notes,
    'Allow one for good with /leakstop allow <number or sha256:…>',
  ].join('\n')
}

/** Where a fingerprint was allowed. */
export type AllowSource = 'session' | 'forever' | 'project'

const SOURCE_TEXT: Record<AllowSource, string> = { session: 'this session', forever: 'for good', project: '.leakstop.json' }

export type Allowed = { fingerprint: string; sources: AllowSource[] }

/** Every fingerprint that is allowed, with where each came from, in a stable order. */
export function mergeAllowed(session: readonly string[], forever: readonly string[], project: readonly string[]): Allowed[] {
  const merged = new Map<string, Set<AllowSource>>()
  const add = (source: AllowSource, fingerprints: readonly string[]): void => {
    for (const fingerprint of fingerprints) merged.set(fingerprint, (merged.get(fingerprint) ?? new Set()).add(source))
  }
  add('forever', forever)
  add('session', session)
  add('project', project)
  return [...merged].map(([fingerprint, sources]) => ({ fingerprint, sources: [...sources] }))
}

const MAX_ALLOWED_ROWS = 25

/** What is allowed, with what the history knows about each finding (a type and a place, never a value). */
export function allowedText(allowed: readonly Allowed[], findings: readonly StoredFinding[]): string {
  if (allowed.length === 0) return 'LeakStop · nothing is allowed: every finding is checked'
  const known = new Map<string, StoredFinding>()
  for (const finding of findings) known.set(finding.fingerprint, finding)
  const rows = allowed.slice(0, MAX_ALLOWED_ROWS).map(({ fingerprint, sources }) => {
    const finding = known.get(fingerprint)
    const what = finding === undefined ? '' : ` · ${finding.label} · ${where(finding)}`
    return `  ${fingerprint} · ${sources.map((source) => SOURCE_TEXT[source]).join(' + ')}${what}`
  })
  const hidden = allowed.length - rows.length
  return [
    `LeakStop · ${allowed.length} allowed`,
    ...rows,
    ...(hidden > 0 ? [`…and ${hidden} more`] : []),
    'Stop allowing one with /leakstop forget <fingerprint>, or everything of yours with /leakstop forget all.',
    ...(allowed.some((a) => a.sources.includes('project')) ? ['Fingerprints from .leakstop.json are removed by editing that file.'] : []),
  ].join('\n')
}

export type CommandArgs =
  | { kind: 'open' }
  | { kind: 'pause' }
  | { kind: 'resume' }
  | { kind: 'allow'; ids: string[] }
  | { kind: 'allowed' }
  | { kind: 'forget'; ids: string[] }
  | { kind: 'reload' }
  | { kind: 'usage' }

export function parseArgs(args: string): CommandArgs {
  const words = args.trim().split(/\s+/).filter((word) => word !== '')
  const [first, ...rest] = words
  if (first === undefined) return { kind: 'open' }
  if (first === 'pause' && rest.length === 0) return { kind: 'pause' }
  if (first === 'resume' && rest.length === 0) return { kind: 'resume' }
  if (first === 'allow' && rest.length > 0) return { kind: 'allow', ids: rest }
  if ((first === 'allowed' || first === 'list') && rest.length === 0) return { kind: 'allowed' }
  if (first === 'forget' && rest.length > 0) return { kind: 'forget', ids: rest }
  if (first === 'reload' && rest.length === 0) return { kind: 'reload' }
  return { kind: 'usage' }
}

export const USAGE = [
  'Usage:',
  '  /leakstop                 show this session’s findings',
  '  /leakstop pause           stop checking until you resume',
  '  /leakstop resume          start checking again',
  '  /leakstop allow <id>...   allow findings for good: a number from the history or a sha256:… fingerprint',
  '  /leakstop allowed         list what is allowed: for this session, for good, and by .leakstop.json',
  '  /leakstop forget <id>...  stop allowing findings: a history number or a sha256:… fingerprint',
  '  /leakstop forget all      stop allowing everything you allowed (what .leakstop.json allows stays)',
  '  /leakstop reload          read .leakstop.json again',
].join('\n')

const FINGERPRINT = /^(?:sha256:)?([0-9a-f]{16})$/

/** Turns what the user typed into fingerprints; `unknown` lists what matched nothing. */
export function resolveIds(ids: readonly string[], findings: readonly StoredFinding[]): { fingerprints: string[]; unknown: string[] } {
  const fingerprints: string[] = []
  const unknown: string[] = []
  for (const id of ids) {
    const number = /^#?(\d+)$/.exec(id)
    const hex = FINGERPRINT.exec(id.toLowerCase())
    const byNumber = number === null ? undefined : findings[Number(number[1]) - 1]
    if (byNumber !== undefined) fingerprints.push(byNumber.fingerprint)
    else if (hex !== null) fingerprints.push(`sha256:${hex[1]}`)
    else unknown.push(id)
  }
  return { fingerprints: [...new Set(fingerprints)], unknown }
}
