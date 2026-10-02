// Runs LeakStop's detector over the files git tracks in one or more repositories
// and reports what it would flag, so the thresholds can be tuned before a release.
// Read-only. Never prints a secret: only the rule, the place, the value's length
// and entropy, and the line of code with the value replaced.
//
//   node scripts/calibrate.ts <repo or folder> [...]
//
// A git repository is read through `git ls-files`; any other folder is walked.

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

import { entropy, scanText } from '../leakstop/hooks/detect.ts'

const SKIP = /\.(?:png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|woff2?|ttf|otf|eot|mp[34]|mov|lock|map|svg|wasm|bin|class|jar|xcf|psd)$/i
const MAX_FILE_BYTES = 1024 * 1024

function walk(dir: string, prefix = ''): string[] {
  const out: string[] = []
  for (const entry of readdirSync(join(dir, prefix), { withFileTypes: true })) {
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`
    if (entry.isDirectory()) out.push(...walk(dir, relative))
    else if (entry.isFile()) out.push(relative)
  }
  return out
}

const rows: string[] = []
const byRule = new Map<string, number>()
let files = 0
let bytes = 0
let elapsed = 0

for (const repo of process.argv.slice(2)) {
  const listed = existsSync(join(repo, '.git'))
    ? execFileSync('git', ['-C', repo, 'ls-files', '-z'], { maxBuffer: 256 * 1024 * 1024 }).toString().split('\0').filter(Boolean)
    : walk(repo)
  const name = repo.split('/').filter(Boolean).pop() ?? repo
  for (const path of listed) {
    if (SKIP.test(path)) continue
    const full = join(repo, path)
    let size = 0
    try {
      size = statSync(full).size
    } catch {
      continue
    }
    if (size > MAX_FILE_BYTES || size === 0) continue
    let text: string
    try {
      text = readFileSync(full, 'utf8')
    } catch {
      continue
    }
    if (text.includes('\u0000')) continue
    files++
    bytes += size
    const startedAt = performance.now()
    const { findings } = scanText(text, { path })
    elapsed += performance.now() - startedAt
    const lines = text.split('\n')
    for (const finding of findings) {
      byRule.set(finding.ruleId, (byRule.get(finding.ruleId) ?? 0) + 1)
      const line = (lines[finding.line - 1] ?? '').replace(finding.value, `⟨${finding.value.length} chars⟩`).trim().slice(0, 110)
      rows.push(`${name}\t${finding.severity}\t${finding.ruleId}\t${path}:${finding.line}\tlen=${finding.value.length} H=${entropy(finding.value).toFixed(2)}\t${line}`)
    }
  }
}

console.log(`scanned ${files} files, ${(bytes / 1024 / 1024).toFixed(1)} MiB, in ${elapsed.toFixed(0)} ms`)
console.log('findings by rule:', Object.fromEntries([...byRule].sort((a, b) => b[1] - a[1])))
for (const row of rows) console.log(row)
