import { expect, test } from 'claude-code/testing'

test('the module loads and session.start passes through', async ($, on) => {
  // Answer session.start in Claude Code's place, beneath the mod
  on('session.start', () => ({ cwd: '/tmp/leakstop-test' }))
  const result = await $.session.start({ cwd: '/tmp/leakstop-test' })
  expect(result.cwd).toBe("/tmp/leakstop-test")
})
