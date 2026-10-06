import { expect, test } from 'claude-code/testing'
import { addedLines, scanDiff } from '../hooks/diff.ts'
import { PROVIDER_TOKENS } from './secrets.ts'

const token = (rule: string): string => PROVIDER_TOKENS[rule]?.() ?? ''

const diff = (secret: string, other = ''): string =>
  [
    'diff --git a/src/config.ts b/src/config.ts',
    'index 111..222 100644',
    '--- a/src/config.ts',
    '+++ b/src/config.ts',
    '@@ -1,3 +1,4 @@',
    ' import x from "x"',
    '-const old = 1',
    `+const key = "${secret}"`,
    ' export default x',
    '@@ -20,0 +22,2 @@ function f() {',
    '+// added',
    `+const other = "${other}"`,
    'diff --git a/gone.ts b/gone.ts',
    'deleted file mode 100644',
    '--- a/gone.ts',
    '+++ /dev/null',
    '@@ -1 +0,0 @@',
    `-const removed = "${secret}"`,
  ].join('\n')

test('collects the added lines with their real line numbers', () => {
  const files = addedLines(diff('abc'))
  expect(files.map((f) => f.path)).toEqual(['src/config.ts'])
  expect(files[0]?.numbers).toEqual([2, 22, 23])
  expect(files[0]?.lines[0]).toBe('const key = "abc"')
})

test('a secret that is added is found at its real line, one that is removed is not', () => {
  const secret = token('anthropic-key')
  const { findings, isSkipped } = scanDiff(diff(secret))
  expect(isSkipped).toBe(false)
  expect(findings.length).toBe(1)
  expect(findings[0]?.path).toBe('src/config.ts')
  expect(findings[0]?.line).toBe(2)
  expect(findings[0]?.ruleId).toBe('anthropic-key')
})

test('finds secrets in several files and hunks', () => {
  const a = token('github-token')
  const b = token('npm-token')
  const text = `${diff(a, b)}\ndiff --git a/.env b/.env\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+X=${token('huggingface-token')}\n`
  const found = scanDiff(text).findings.map((f) => `${f.path}:${f.line}:${f.ruleId}`)
  expect(found).toEqual(['src/config.ts:2:github-token', 'src/config.ts:23:npm-token', '.env:1:huggingface-token'])
})

test('a diff with no added lines or no secrets finds nothing', () => {
  expect(scanDiff('').findings).toEqual([])
  expect(scanDiff(diff('not-a-secret')).findings).toEqual([])
})

test('handles paths with spaces and quoted names', () => {
  const secret = token('github-token')
  const text = `diff --git "a/my file.ts" "b/my file.ts"\n--- "a/my file.ts"\n+++ "b/my file.ts"\n@@ -0,0 +1 @@\n+k = "${secret}"\n`
  expect(scanDiff(text).findings[0]?.path).toBe('my file.ts')
})
