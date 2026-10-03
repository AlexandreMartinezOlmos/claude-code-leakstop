import { expect, test } from 'claude-code/testing'
import { decide, decideAll, maxAction } from '../hooks/policy.ts'
import type { Action, Destination, Mode } from '../hooks/policy.ts'
import type { Severity } from '../hooks/rules.ts'

// destination: [standard critical, standard medium, strict critical, strict medium]
const TABLE: Record<Destination, [Action, Action, Action, Action]> = {
  'file': ['hold', 'warn', 'hold', 'hold'],
  'ignored-file': ['pass', 'pass', 'pass', 'pass'],
  'command': ['hold', 'warn', 'hold', 'hold'],
  'outbound': ['hold', 'warn', 'hold', 'hold'],
  'sensitive-dump': ['hold', 'hold', 'hold', 'hold'],
  'git-add': ['hold', 'hold', 'hold', 'hold'],
  'git-commit': ['block', 'warn', 'block', 'block'],
  'git-push': ['block', 'warn', 'block', 'block'],
  'read': ['hold', 'hold', 'block', 'block'],
  'config-edit': ['hold', 'hold', 'hold', 'hold'],
  'prompt': ['warn', 'warn', 'warn', 'warn'],
}

for (const [destination, expected] of Object.entries(TABLE) as [Destination, [Action, Action, Action, Action]][]) {
  test(`policy for ${destination}`, () => {
    expect(decide(destination, 'critical', 'standard')).toBe(expected[0])
    expect(decide(destination, 'medium', 'standard')).toBe(expected[1])
    expect(decide(destination, 'critical', 'strict')).toBe(expected[2])
    expect(decide(destination, 'medium', 'strict')).toBe(expected[3])
  })
}

test('monitor never holds or blocks', () => {
  const destinations = Object.keys(TABLE) as Destination[]
  const severities: Severity[] = ['critical', 'medium']
  for (const destination of destinations) {
    for (const severity of severities) {
      const action = decide(destination, severity, 'monitor')
      expect(action === 'pass' || action === 'warn').toBe(true)
      expect(action).toBe(destination === 'ignored-file' ? 'pass' : 'warn')
    }
  }
})

test('the strongest action wins over several findings', () => {
  const mode: Mode = 'standard'
  expect(decideAll('file', [], mode)).toBe('pass')
  expect(decideAll('file', ['medium', 'medium'], mode)).toBe('warn')
  expect(decideAll('file', ['medium', 'critical'], mode)).toBe('hold')
  expect(decideAll('git-commit', ['medium', 'critical'], mode)).toBe('block')
  expect(maxAction('hold', 'warn')).toBe('hold')
  expect(maxAction('warn', 'block')).toBe('block')
  expect(maxAction('pass', 'pass')).toBe('pass')
})
