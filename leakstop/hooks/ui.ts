// What the banner, the history panel and the `/leakstop` command say. Pure: no `$`.
//
// Strings are fitted to the width the surface gives (`bodyColumns`), so nothing
// here depends on the terminal's own size.

import type { StoredFinding } from '../types'

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
  if (finding.path === '') return `${finding.tool} command`
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

export type CommandArgs =
  | { kind: 'open' }
  | { kind: 'pause' }
  | { kind: 'resume' }
  | { kind: 'allow'; ids: string[] }
  | { kind: 'usage' }

export function parseArgs(args: string): CommandArgs {
  const words = args.trim().split(/\s+/).filter((word) => word !== '')
  const [first, ...rest] = words
  if (first === undefined) return { kind: 'open' }
  if (first === 'pause' && rest.length === 0) return { kind: 'pause' }
  if (first === 'resume' && rest.length === 0) return { kind: 'resume' }
  if (first === 'allow' && rest.length > 0) return { kind: 'allow', ids: rest }
  return { kind: 'usage' }
}

export const USAGE = [
  'Usage:',
  '  /leakstop                 show this session’s findings',
  '  /leakstop pause           stop checking until you resume',
  '  /leakstop resume          start checking again',
  '  /leakstop allow <id>...   allow findings for good: a number from the history or a sha256:… fingerprint',
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
