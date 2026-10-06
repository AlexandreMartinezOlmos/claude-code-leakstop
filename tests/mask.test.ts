import { expect, test } from 'claude-code/testing'
import { scanText } from '../hooks/detect.ts'
import { describe, fingerprint, mask } from '../hooks/mask.ts'
import { PROVIDER_TOKENS, random } from './secrets.ts'

test('masks the prefix and the last three characters only', () => {
  const token = `sk-ant-api03-${random(40)}`
  const masked = mask(token, 'sk-ant-')
  expect(masked).toBe(`sk-ant-••••••${token.slice(-3)}`)
  expect(masked.includes(token.slice(7, 30))).toBe(false)
})

test('shows nothing but the type when there is no prefix or the value is short', () => {
  expect(mask(random(30))).toBe('••••••')
  expect(mask(`ghp_${random(8)}`, 'ghp_')).toBe('ghp_••••••')
  expect(mask(`other_${random(30)}`, 'ghp_')).toBe('••••••')
})

test('the fingerprint is stable, distinguishes values and has the documented shape', async () => {
  const a = random(32)
  const b = random(32)
  expect(await fingerprint(a)).toBe(await fingerprint(a))
  expect(await fingerprint(a)).not.toBe(await fingerprint(b))
  expect(await fingerprint(a)).toMatch(/^sha256:[0-9a-f]{16}$/)
  // SHA-256 of "abc".
  expect(await fingerprint('abc')).toBe('sha256:ba7816bf8f01cfea')
})

test('a described finding holds no trace of the value', async () => {
  const token = PROVIDER_TOKENS['github-token']?.() ?? ''
  const finding = scanText(`token = "${token}"`).findings[0]
  if (finding === undefined) throw new Error('expected a finding')
  const described = await describe(finding)
  expect('value' in described).toBe(false)
  const json = JSON.stringify(described)
  expect(json.includes(token)).toBe(false)
  expect(json.includes(token.slice(8, 30))).toBe(false)
  expect(described.masked).toBe(`ghp_••••••${token.slice(-3)}`)
  expect(described.ruleId).toBe('github-token')
  expect(described.line).toBe(1)
})
