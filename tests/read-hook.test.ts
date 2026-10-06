import { expect, test } from 'claude-code/testing'
import { REJECT, answerWith, disk, isDenied, ran, toolsRun } from './harness.ts'
import { random } from './secrets.ts'

const read = ($: any, file_path: string) => $.tool.call({ tool: 'Read', file_path })

const ALLOW_ONCE = 'Allow once'
const CANCEL = 'Cancel'

test('reading a sensitive file is held: Cancel denies, Allow once reads', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const r = await read($, '/work/app/.env')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('LeakStop blocked reading .env')).toBe(true)
  expect(asked.options[0]).toEqual([ALLOW_ONCE, CANCEL])
  expect(asked.questions[0]?.includes('  .env')).toBe(true)

})

test('Allow once reads the file and is remembered', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  expect(ran(await read($, '.env'))).toBe(true)
  expect(ran(await read($, '.env'))).toBe(true)
  expect(asked.questions.length).toBe(1)
})

test('no interface denies', async ($, on) => {
  toolsRun(on)
  answerWith(on, REJECT)
  expect(isDenied(await read($, 'certs/server.pem'))).toBe(true)
})

test('strict mode blocks without asking and without an allow option', { options: { mode: 'strict' } }, async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  const r = await read($, '.env.production')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('Strict mode')).toBe(true)
  expect(asked.questions.length).toBe(0)
})

test('monitor mode warns and reads', { options: { mode: 'monitor' } }, async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  expect(ran(await read($, '.env'))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.logs.length).toBe(1)
})

test('example files and ordinary files are read freely', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  for (const path of ['.env.example', 'src/index.ts', 'README.md', 'id_rsa.pub']) expect(ran(await read($, path))).toBe(true)
  expect(asked.questions.length).toBe(0)
})

test('a .npmrc is sensitive only when it holds a token', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  disk(on, { '.npmrc': 'registry=https://registry.npmjs.org/\n', 'sub/.npmrc': `//registry.npmjs.org/:_authToken=${random(30)}\n` })
  expect(ran(await read($, '.npmrc'))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(isDenied(await read($, 'sub/.npmrc'))).toBe(true)
  expect(asked.questions.length).toBe(1)
})

test('an unreadable .npmrc is not treated as sensitive', async ($, on) => {
  toolsRun(on)
  disk(on, {})
  expect(ran(await read($, '.npmrc'))).toBe(true)
})
