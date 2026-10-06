import { expect, test } from 'claude-code/testing'
import { isDenied, storeAllows } from './harness.ts'
import { fingerprint } from '../hooks/mask.ts'
import { PROVIDER_TOKENS, fakeJwt } from './secrets.ts'

const token = (rule = 'anthropic-key'): string => PROVIDER_TOKENS[rule]?.() ?? ''
const SAVED = '/home/dev/.claude/projects/app/session/tool-results/out.txt'

/** An engine whose tools answer with results shaped like the real ones. */
function engine(on: any, results: { bash?: any; read?: any; mcp?: any }, options: { disk?: Record<string, string>; noClock?: boolean } = {}) {
  const written: Record<string, any> = {}
  const logs: string[] = []
  const runs: string[] = []
  const disk = { ...(options.disk ?? {}) }
  if (options.noClock !== true) on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('session.cwd', () => ({ value: '/work/app' }))
  on('session.surfaces', () => ({ value: [] }))
  on('ui.log', (_$: any, e: any) => {
    logs.push(e.text)
    return { value: undefined }
  })
  on('state.set', { plugin: 'leakstop' }, (_$: any, e: any, next: any) => {
    written[e.key] = e.value
    return next(e)
  })
  on('fs.read', (_$: any, e: any) => {
    if (!(e.path in disk)) throw new Error('ENOENT')
    return { value: disk[e.path] }
  })
  on('fs.write', (_$: any, e: any) => {
    disk[e.path] = e.text
    return { value: undefined }
  })
  on('tool.call', { tool: 'Bash' }, (_$: any, e: any) => (runs.push(e.command), { result: results.bash }))
  on('tool.call', { tool: 'Read' }, () => ({ result: results.read }))
  on('tool.call', { tool: /^mcp__/ }, () => ({ result: results.mcp }))
  return { findings: () => written.findings ?? [], logs, runs, disk }
}

const bashResult = (stdout: string, extra: Record<string, unknown> = {}) => ({ stdout, stderr: '', interrupted: false, ...extra })

test('a secret printed by a command is masked before the model gets it, and recorded without its value', async ($, on) => {
  const secret = token()
  const env = engine(on, { bash: bashResult(`ANTHROPIC_API_KEY=${secret}\nPATH=/usr/bin\n`) })
  const r = await $.tool.call({ tool: 'Bash', command: 'bash deploy.sh' })

  expect(r.result.stdout.includes(secret)).toBe(false)
  expect(r.result.stdout).toBe(`ANTHROPIC_API_KEY=sk-ant-••••••${secret.slice(-3)}\nPATH=/usr/bin\n`)
  expect(r.context.some((c: string) => c.startsWith('LeakStop masked an Anthropic API key in the output of this Bash call'))).toBe(true)
  expect(env.findings()).toHaveLength(1)
  expect(env.findings()[0]).toMatchObject({ tool: 'Bash', decision: 'masked', severity: 'critical', fingerprint: await fingerprint(secret) })
  expect(JSON.stringify([r, env.findings(), env.logs]).includes(secret)).toBe(false)
  expect(env.runs).toEqual(['bash deploy.sh'])
})

test('stderr is masked too, and an output with no secret is returned untouched', async ($, on) => {
  const secret = token('github-token')
  engine(on, { bash: { stdout: 'ok\n', stderr: `fatal: bad token ${secret}`, interrupted: false } })
  const r = await $.tool.call({ tool: 'Bash', command: 'bash release.sh' })
  expect(r.result.stdout).toBe('ok\n')
  expect(r.result.stderr.includes(secret)).toBe(false)
})

test('an output with nothing to mask comes back as the engine gave it', async ($, on) => {
  const env = engine(on, { bash: bashResult('total 0\n') })
  const r = await $.tool.call({ tool: 'Bash', command: 'ls' })
  expect(r.result.stdout).toBe('total 0\n')
  expect(r.context).toBeUndefined()
  expect(env.findings()).toEqual([])
})

test('the file a large output is saved to is masked as well', async ($, on) => {
  const secret = token('aws-access-key')
  const saved = `${'x'.repeat(100)}\naws_access_key_id = ${secret}\n`
  const env = engine(on, { bash: bashResult('x'.repeat(100), { persistedOutputPath: SAVED }) }, { disk: { [SAVED]: saved } })
  await $.tool.call({ tool: 'Bash', command: 'make logs' })
  expect(env.disk[SAVED]?.includes(secret)).toBe(false)
  expect(env.disk[SAVED]?.includes('aws_access_key_id = AKIA')).toBe(true)
  expect(env.findings()).toHaveLength(1)
})

test('a file read with the Read tool is masked, and the history names the file', async ($, on) => {
  const secret = token('stripe-live-key')
  const env = engine(on, { read: { type: 'text', file: { filePath: '/work/app/src/pay.ts', content: `const key = "${secret}"\n`, numLines: 2, startLine: 1, totalLines: 2 } } })
  const r = await $.tool.call({ tool: 'Read', file_path: '/work/app/src/pay.ts' })
  expect(r.result.file.content.includes(secret)).toBe(false)
  expect(r.result.file.numLines).toBe(2)
  expect(env.findings()[0]).toMatchObject({ tool: 'Read', path: 'src/pay.ts', decision: 'masked' })
})

test('every text of an MCP result is masked, binary data is left alone', async ($, on) => {
  const secret = token('openai-key')
  const image = 'iVBORw0KGgo' + 'A'.repeat(200)
  engine(on, { mcp: [{ type: 'text', text: `config: ${secret}` }, { type: 'image', data: image, mimeType: 'image/png' }] })
  const r = await $.tool.call({ tool: 'mcp__vault__get_config' })
  expect(r.result[0].text.includes(secret)).toBe(false)
  expect(r.result[1].data).toBe(image)
})

test('medium findings pass in standard mode', async ($, on) => {
  const jwt = fakeJwt()
  engine(on, { bash: bashResult(`session=${jwt}\n`) })
  const r = await $.tool.call({ tool: 'Bash', command: 'cat session.log' })
  expect(r.result.stdout.includes(jwt)).toBe(true)
})

test('strict mode masks medium findings', { options: { mode: 'strict' } }, async ($, on) => {
  const jwt = fakeJwt()
  engine(on, { bash: bashResult(`session=${jwt}\n`) })
  const r = await $.tool.call({ tool: 'Bash', command: 'cat session.log' })
  expect(r.result.stdout.includes(jwt)).toBe(false)
})

test('monitor mode leaves the output as it was and only reports', { options: { mode: 'monitor' } }, async ($, on) => {
  const secret = token()
  const env = engine(on, { bash: bashResult(`key ${secret}\n`) })
  const r = await $.tool.call({ tool: 'Bash', command: 'bash show.sh' })
  expect(r.result.stdout.includes(secret)).toBe(true)
  expect(env.findings()[0]).toMatchObject({ decision: 'warned' })
})

test('a value the user allowed for good is not masked', async ($, on) => {
  const secret = token()
  storeAllows(on, [await fingerprint(secret)])
  engine(on, { bash: bashResult(`key ${secret}\n`) })
  const r = await $.tool.call({ tool: 'Bash', command: 'bash show.sh' })
  expect(r.result.stdout.includes(secret)).toBe(true)
})

test('a failure after the tool ran withholds the output and does not run the tool again', async ($, on) => {
  const secret = token()
  const env = engine(on, { bash: bashResult(`key ${secret}\n`) }, { noClock: true })
  const r = await $.tool.call({ tool: 'Bash', command: 'bash show.sh' })
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('do not run it again')).toBe(true)
  expect(env.runs).toEqual(['bash show.sh'])
})

// --- Secrets pasted into a message ------------------------------------------------

/** The engine beneath: answers prompt.submit with what reached it. */
function promptEngine(on: any) {
  const written: Record<string, any> = {}
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('session.surfaces', () => ({ value: [] }))
  on('state.set', { plugin: 'leakstop' }, (_$: any, e: any, next: any) => {
    written[e.key] = e.value
    return next(e)
  })
  on('prompt.submit', (_$: any, e: any) => ({ text: e.text, context: e.context }))
  return { findings: () => written.findings ?? [], banner: () => written.banner ?? [] }
}

test('a secret pasted into a message is masked before the model gets it, and the model is told', async ($, on) => {
  const secret = token()
  const env = promptEngine(on)
  const r = await $.prompt.submit({ text: `here is my key ${secret}, set up the client`, origin: { kind: 'user' } })
  expect(r.text).toBe(`here is my key sk-ant-••••••${secret.slice(-3)}, set up the client`)
  expect(r.context.some((c: string) => c.includes('the user pasted into this message'))).toBe(true)
  expect(env.findings()[0]).toMatchObject({ tool: 'prompt', path: 'your message', decision: 'masked' })
  expect(env.banner()).toHaveLength(1)
  expect(JSON.stringify([r, env.findings()]).includes(secret)).toBe(false)
})

test('a message with no secret goes through as typed', async ($, on) => {
  promptEngine(on)
  const r = await $.prompt.submit({ text: 'refactor the parser', origin: { kind: 'user' } })
  expect(r.text).toBe('refactor the parser')
  expect(r.context).toBeUndefined()
})

test('monitor mode reports a pasted secret and sends the message as typed', { options: { mode: 'monitor' } }, async ($, on) => {
  const secret = token()
  const env = promptEngine(on)
  const r = await $.prompt.submit({ text: `key ${secret}`, origin: { kind: 'user' } })
  expect(r.text).toBe(`key ${secret}`)
  expect(env.findings()[0]).toMatchObject({ decision: 'warned' })
})

// --- Writing back what was masked ---------------------------------------------------

test('a Write that would put the masked form over the real value on disk is denied', async ($, on) => {
  const secret = token('github-token')
  const onDisk = `export const token = "${secret}"\nexport const retries = 3\n`
  const env = engine(on, {}, { disk: { '/work/app/config.ts': onDisk } })
  on('tool.call', { tool: 'Write' }, () => ({ result: 'ok' }))
  const masked = `ghp_••••••${secret.slice(-3)}`
  const r = await $.tool.call({ tool: 'Write', file_path: '/work/app/config.ts', content: `// config\nexport const token = "${masked}"\nexport const retries = 5\n` })
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('the real value would be lost')).toBe(true)
  expect(r.deny.includes(secret)).toBe(false)
  expect(env.disk['/work/app/config.ts']).toBe(onDisk)
})

test('a Write with masked-looking text over a file that holds no such secret goes on', async ($, on) => {
  engine(on, {}, { disk: { '/work/app/notes.md': 'nothing here\n' } })
  on('tool.call', { tool: 'Write' }, () => ({ result: 'ok' }))
  const r = await $.tool.call({ tool: 'Write', file_path: '/work/app/notes.md', content: 'LeakStop shows keys as ghp_••••••abc\n' })
  expect(r.result).toBe('ok')
})
