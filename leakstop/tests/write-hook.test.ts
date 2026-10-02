import { expect, test } from 'claude-code/testing'
import { CWD, REJECT, answerWith, fileOnDisk, gitSays, isDenied, ran, toolsRun } from './harness.ts'
import { PROVIDER_TOKENS, fakeJwt, random } from './secrets.ts'

const token = (): string => PROVIDER_TOKENS['anthropic-key']?.() ?? ''
const write = ($: any, path: string, content: string) => $.tool.call({ tool: 'Write', file_path: path, content })
const config = (secret: string): string => `export const apiKey = "${secret}"\n`

const USE_ENV = 'Use environment variable'
const ALLOW_ONCE = 'Allow once'
const CANCEL = 'Cancel'

// --- A critical secret in a versioned file: hold ---------------------------

test('key in code: Cancel denies and the message holds no value', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  const r = await write($, 'src/config.ts', config(secret))

  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop blocked this write: src/config.ts:1 contains an Anthropic API key (sk-ant-…).')).toBe(true)
  expect(r.deny.includes(secret)).toBe(false)
  expect(r.deny.includes(secret.slice(14))).toBe(false)
  expect(asked.questions.length).toBe(1)
  expect(asked.headers[0]).toBe('LeakStop')
  expect(asked.options[0]).toEqual([USE_ENV, ALLOW_ONCE, CANCEL])
  // The question shows the masked value and never the full one.
  expect(asked.questions[0]?.includes(`sk-ant-••••••${secret.slice(-3)}`)).toBe(true)
  expect(asked.questions[0]?.includes(secret.slice(14))).toBe(false)
})

test('key in code: "Use environment variable" denies with instructions to read the variable', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  answerWith(on, USE_ENV)
  const r = await write($, 'src/config.ts', config(token()))
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('process.env.ANTHROPIC_API_KEY')).toBe(true)
  expect(r.deny.includes('.env.example')).toBe(true)
})

test('key in code: "Allow once" passes and is remembered for the session only', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, ALLOW_ONCE)

  expect(ran(await write($, 'src/config.ts', config(secret)))).toBe(true)
  expect((env.allowOnce()).length).toBe(1)
  // The same finding does not ask again; a different one does.
  expect(ran(await write($, 'src/other.ts', config(secret)))).toBe(true)
  expect(asked.questions.length).toBe(1)
  expect(ran(await write($, 'src/other.ts', config(token())))).toBe(true)
  expect(asked.questions.length).toBe(2)
})

test('paths are shown relative to the session directory', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  const r = await write($, `${CWD}/src/config.ts`, config(token()))
  expect(r.deny.startsWith('LeakStop blocked this write: src/config.ts:1')).toBe(true)
  expect(asked.questions[0]?.includes('→ src/config.ts:1')).toBe(true)
  expect(JSON.stringify(env.findings()).includes(CWD)).toBe(false)
})

test('a free-text answer denies', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  answerWith(on, 'sure, go ahead and write it')
  expect(isDenied(await write($, 'src/config.ts', config(token())))).toBe(true)
})

test('"Allow once" typed as part of a longer sentence is not an allow', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  answerWith(on, 'Allow once please')
  expect(isDenied(await write($, 'src/config.ts', config(token())))).toBe(true)
})

test('no interface: a rejected ask denies', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  answerWith(on, REJECT)
  const r = await write($, 'src/config.ts', config(token()))
  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop blocked this write')).toBe(true)
})

// --- Ignored files, placeholders and edits ---------------------------------

test('a key in a git-ignored .env passes and is logged', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  gitSays(on, 'ignored')
  const asked = answerWith(on, CANCEL)
  expect(ran(await write($, '.env', `ANTHROPIC_API_KEY=${secret}\n`))).toBe(true)
  expect(asked.questions.length).toBe(0)
  const stored = env.findings()
  expect(stored.length).toBe(1)
  expect(stored[0].decision).toBe('passed')
  expect(stored[0].path).toBe('.env')
})

test('a key in a .env that git does not ignore is held, and the advice is to ignore it', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  answerWith(on, CANCEL)
  const r = await write($, '.env', `ANTHROPIC_API_KEY=${token()}\n`)
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('.gitignore')).toBe(true)
})

test('an Edit that leaves a secret untouched passes with no question', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  const before = `const a = 1\nconst key = "${secret}"\nconst b = 2\n`
  const r = await $.tool.call({ tool: 'Edit', file_path: 'src/config.ts', old_string: before, new_string: before.replace('const b = 2', 'const b = 3') })
  expect(ran(r)).toBe(true)
  expect(asked.questions.length).toBe(0)
})

test('an Edit that adds a secret is held, with the real line number', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  fileOnDisk(on, 'one\ntwo\nthree\nfour\nconst b = 2\nsix\n')
  answerWith(on, CANCEL)
  const r = await $.tool.call({ tool: 'Edit', file_path: 'src/config.ts', old_string: 'const b = 2', new_string: `const key = "${token()}"` })
  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop blocked this edit: src/config.ts:5 contains')).toBe(true)
})

test('a NotebookEdit that adds a secret is held', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  answerWith(on, CANCEL)
  const r = await $.tool.call({ tool: 'NotebookEdit', notebook_path: 'analysis.ipynb', new_source: `key = "${token()}"` })
  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop blocked this notebook edit: analysis.ipynb:1')).toBe(true)
})

test('placeholders and ordinary code pass with no question', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  for (const content of [
    'API_KEY="your-api-key"\n',
    'const key = process.env.ANTHROPIC_API_KEY\n',
    `// commit ${random(40, '0123456789abcdef')}\n`,
    'export const add = (a: number, b: number) => a + b\n',
  ]) {
    expect(ran(await write($, 'src/index.ts', content))).toBe(true)
  }
  expect(asked.questions.length).toBe(0)
})

// --- Medium findings and the modes ------------------------------------------

test('a medium finding warns and passes in standard mode', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  expect(ran(await write($, 'tests/fixtures/user.json', `{"token": "${fakeJwt()}"}`))).toBe(true)
  expect(asked.questions.length).toBe(0)
  const stored = env.findings()
  expect(stored.map((f: any) => f.decision)).toEqual(['warned'])
  expect(stored[0].severity).toBe('medium')
})

test('a medium finding is held in strict mode', { options: { mode: 'strict' } }, async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  expect(isDenied(await write($, 'tests/fixtures/user.json', `{"token": "${fakeJwt()}"}`))).toBe(true)
  expect(asked.questions.length).toBe(1)
})

test('monitor mode never holds: it passes and records the finding', { options: { mode: 'monitor' } }, async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  expect(ran(await write($, 'src/config.ts', config(token())))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect((env.findings()).map((f: any) => f.decision)).toEqual(['warned'])
})

test('an unknown mode falls back to standard', { options: { mode: 'paranoid' } }, async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  answerWith(on, CANCEL)
  expect(isDenied(await write($, 'src/config.ts', config(token())))).toBe(true)
})

test('outside a git repository a write is still held', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'not-a-repo')
  answerWith(on, CANCEL)
  expect(isDenied(await write($, 'src/config.ts', config(token())))).toBe(true)
})

// --- Self-protection ---------------------------------------------------------

test('Claude editing .leakstop.json is always held', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  const r = await write($, '.leakstop.json', '{"ignorePaths": ["**"]}')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('.leakstop.json')).toBe(true)
  expect(asked.options[0]).toEqual([ALLOW_ONCE, CANCEL])
  const edit = await $.tool.call({ tool: 'Edit', file_path: 'sub/.leakstop.json', old_string: '[]', new_string: '["**"]' })
  expect(isDenied(edit)).toBe(true)
})

test('.leakstop.json can be changed when the user allows it', async ($, on) => {
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  answerWith(on, ALLOW_ONCE)
  expect(ran(await write($, '.leakstop.json', '{}'))).toBe(true)
})

test('.leakstop.json with no interface is denied', async ($, on) => {
  const env = toolsRun(on)
  answerWith(on, REJECT)
  expect(isDenied(await write($, '.leakstop.json', '{}'))).toBe(true)
})

// --- Fail closed -------------------------------------------------------------

test('an internal failure is denied by the .catch in standard mode', async ($, on) => {
  const env = toolsRun(on)
  const r = await write($, 'src/config.ts', 123 as unknown as string)
  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop could not check this call')).toBe(true)
})

test('an internal failure is denied by the .catch in strict mode', { options: { mode: 'strict' } }, async ($, on) => {
  const env = toolsRun(on)
  expect(isDenied(await write($, 'src/config.ts', 123 as unknown as string))).toBe(true)
})

test('an internal failure lets the call through in monitor mode', { options: { mode: 'monitor' } }, async ($, on) => {
  const env = toolsRun(on)
  expect(ran(await write($, 'src/config.ts', 123 as unknown as string))).toBe(true)
})

// --- Privacy -----------------------------------------------------------------

test('no value ever reaches the state, the question or the denial', async ($, on) => {
  const secrets = [token(), PROVIDER_TOKENS['github-token']?.() ?? '']
  const env = toolsRun(on)
  gitSays(on, 'tracked')
  const asked = answerWith(on, CANCEL)
  const r = await write($, 'src/config.ts', secrets.map(config).join(''))
  expect(isDenied(r)).toBe(true)
  const everything = JSON.stringify([r, asked.questions, env.findings(), env.allowOnce()])
  for (const secret of secrets) {
    expect(everything.includes(secret)).toBe(false)
    expect(everything.includes(secret.slice(10, 30))).toBe(false)
  }
  expect(everything.includes('2 more')).toBe(false)
  expect(r.deny.includes('src/config.ts:1')).toBe(true)
  expect(r.deny.includes('src/config.ts:2')).toBe(true)
})

test('other tools are not touched', async ($, on) => {
  toolsRun(on)
  const r = await $.tool.call({ tool: 'Read', file_path: 'src/index.ts' })
  expect(ran(r)).toBe(true)
})
