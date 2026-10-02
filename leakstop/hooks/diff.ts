// Scans the lines a diff adds. Pure: no `$`, no I/O.
//
// `git diff --cached` says what a commit would contain and `git log -p` what a
// push would publish. Only added lines matter: a secret that is being removed
// is not being leaked.

import { scanText } from './detect.ts'
import type { Finding, Rule } from './detect.ts'

export type AddedFile = {
  path: string
  /** The added lines, in order. */
  lines: string[]
  /** The line of each added line in the new file. */
  numbers: number[]
}

export type DiffFinding = Finding & { path: string }

const unquote = (path: string): string => (path.startsWith('"') && path.endsWith('"') ? path.slice(1, -1) : path)

/** The added lines of a unified diff, grouped by file. */
export function addedLines(diff: string): AddedFile[] {
  const files = new Map<string, AddedFile>()
  let current: AddedFile | undefined
  let line = 0
  let isInHunk = false

  for (const row of diff.split('\n')) {
    if (row.startsWith('diff --git ')) {
      current = undefined
      isInHunk = false
      continue
    }
    if (!isInHunk && row.startsWith('+++ ')) {
      const target = unquote(row.slice(4).replace(/\t.*$/, ''))
      if (target === '/dev/null') {
        current = undefined
      } else {
        const path = target.startsWith('b/') ? target.slice(2) : target
        current = files.get(path) ?? { path, lines: [], numbers: [] }
        files.set(path, current)
      }
      continue
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(row)
    if (hunk !== null) {
      line = Number(hunk[1])
      isInHunk = true
      continue
    }
    if (!isInHunk || current === undefined) continue
    if (row.startsWith('+')) {
      current.lines.push(row.slice(1))
      current.numbers.push(line++)
    } else if (row.startsWith(' ')) {
      line++
    }
  }
  return [...files.values()]
}

export type DiffScan = {
  findings: DiffFinding[]
  /** A file's added text was over 4 MiB and was not scanned. */
  isSkipped: boolean
}

/** Scans each file's added lines; a finding points at the real line in the file. */
export function scanDiff(diff: string, extraRules: readonly Rule[] = []): DiffScan {
  const findings: DiffFinding[] = []
  let isSkipped = false
  for (const file of addedLines(diff)) {
    if (file.lines.length === 0) continue
    const result = scanText(file.lines.join('\n'), { path: file.path, extraRules })
    if (result.isSkipped) {
      isSkipped = true
      continue
    }
    for (const finding of result.findings) {
      findings.push({ ...finding, line: file.numbers[finding.line - 1] ?? finding.line, path: file.path })
    }
  }
  return { findings, isSkipped }
}
