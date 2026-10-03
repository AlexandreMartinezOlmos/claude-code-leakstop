import { expect, test } from 'claude-code/testing'
import { REJECT, USER, answerWith, disk, isDenied, ran, storeAllows, toolsRun } from './harness.ts'
import { scanText } from '../hooks/detect.ts'
import { fingerprint } from '../hooks/mask.ts'
import { PROVIDER_TOKENS, fakeJwt, random } from './secrets.ts'

const ALLOW_ONCE = 'Allow once'
const CANCEL = 'Cancel'
const token = (): string => PROVIDER_TOKENS['anthropic-key']?.() ?? ''
const call = ($: any, input: Record<string, unknown>) => $.tool.call(input)

/** One call per outbound tool, with `text` where the tool carries free text. */
const CALLS: Record<string, (text: string) => Record<string, unknown>> = {
  WebFetch: (text) => ({ tool: 'WebFetch', url: 'https://example.com/docs', prompt: `Summarise this. Use ${text}` }),
  WebSearch: (text) => ({ tool: 'WebSearch', query: `error ${text}` }),
  Agent: (text) => ({ tool: 'Agent', description: 'check the API', prompt: `Call the API with ${text}` }),
  SendMessage: (text) => ({ tool: 'SendMessage', to: 'worker', message: `the key is ${text}` }),
  SendFile: (text) => ({ tool: 'SendFile', to: 'peer', files: [], message: `see ${text}` }),
  PushNotification: (text) => ({ tool: 'PushNotification', status: 'proactive', message: `done: ${text}` }),
  SendFeedback: (text) => ({ tool: 'SendFeedback', type: 'bug', title: 'a bug', details: `**What happened:** ${text}` }),
  ArtifactComments: (text) => ({ tool: 'ArtifactComments', action: 'reply', url: 'https://claude.ai/artifact/x', thread_id: 't', text }),
  ArtifactData: (text) => ({ tool: 'ArtifactData', action: 'set', url: 'https://claude.ai/artifact/x', collection: 'c', doc_id: 'd', data: { html: `<p>${text}</p>` } }),
  RemoteTrigger: (text) => ({ tool: 'RemoteTrigger', action: 'create', body: { prompt: `use ${text}` } }),
  Artifact: (text) => ({ tool: 'Artifact', action: 'publish', description: `a page using ${text}` }),
  mcp: (text) => ({ tool: 'mcp__github__create_issue', title: 'Bug', body: { text: `token ${text}` } }),
}

for (const [name, build] of Object.entries(CALLS)) {
  test(`${name}: a secret is held, Cancel denies it and the tool does not run`, async ($, on) => {
    const env = toolsRun(on)
    const asked = answerWith(on, CANCEL)
    const secret = token()
    const r = await call($, build(secret))
    expect(isDenied(r)).toBe(true)
    expect(r.deny.startsWith('The user chose Cancel')).toBe(true)
    expect(r.deny.includes('It would be sent')).toBe(true)
    expect(r.deny.includes('Anthropic API key (sk-ant-…)')).toBe(true)
    expect(asked.options[0]).toEqual([ALLOW_ONCE, CANCEL])
    expect(asked.questions[0]?.includes('This call would send it')).toBe(true)
    expect(env.sent).toEqual([])
    const everything = JSON.stringify([r, asked.questions, env.findings()])
    expect(everything.includes(secret)).toBe(false)
    expect(everything.includes(secret.slice(14, 34))).toBe(false)
  })
}

test('a clean call goes through without a question', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  for (const build of Object.values(CALLS)) expect(ran(await call($, build('nothing secret here')))).toBe(true)
  expect(asked.questions).toEqual([])
  expect(env.sent.length).toBe(Object.keys(CALLS).length)
})

test('the question and the history say where the secret is, with no line number for an argument', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  await call($, { tool: 'mcp__docs__batch', batch: [{ op: 'set', payload: `key ${token()}` }] })
  expect(asked.questions[0]?.includes('Anthropic API key in MCP docs/batch → batch[0].payload\n')).toBe(true)
  expect(asked.questions[0]?.includes('to the MCP server docs')).toBe(true)
  const [finding] = env.findings()
  expect(finding).toMatchObject({ tool: 'mcp__docs__batch', path: 'MCP docs/batch › batch[0].payload', line: 0, decision: 'denied', severity: 'critical' })
})

test('Allow once sends it and remembers that exact secret for the session', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  const secret = token()
  expect(ran(await call($, CALLS.WebFetch?.(secret) ?? {}))).toBe(true)
  expect(ran(await call($, CALLS.Agent?.(secret) ?? {}))).toBe(true)
  expect(asked.questions.length).toBe(1)
  expect(env.sent.length).toBe(2)
  expect(env.allowOnce().length).toBe(1)
  // Another secret is asked about.
  expect(ran(await call($, CALLS.Agent?.(token()) ?? {}))).toBe(true)
  expect(asked.questions.length).toBe(2)
})

test('a fingerprint the user allowed for good passes', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const secret = token()
  const found = scanText(secret).findings[0]
  storeAllows(on, [await fingerprint(found?.value ?? '')])
  expect(ran(await call($, CALLS.SendMessage?.(secret) ?? {}))).toBe(true)
  expect(asked.questions).toEqual([])
})

test('no interface and a free-text answer both deny', async ($, on) => {
  toolsRun(on)
  answerWith(on, REJECT)
  const r = await call($, CALLS.WebSearch?.(token()) ?? {})
  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop could not ask the user')).toBe(true)
})

test('free text is no approval', { }, async ($, on) => {
  const env = toolsRun(on)
  answerWith(on, 'go ahead')
  expect(isDenied(await call($, CALLS.WebSearch?.(token()) ?? {}))).toBe(true)
  expect(env.sent).toEqual([])
})

test('placeholders and example keys are not secrets', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const example = `AKIA${'IOSFODNN7'}${'EXAMPLE'}`
  expect(ran(await call($, { tool: 'Agent', description: 'x', prompt: `export API_KEY="your-api-key" and ${example}` }))).toBe(true)
  expect(asked.questions).toEqual([])
})

test('monitor mode sends it and says it would have been held', { options: { mode: 'monitor' } }, async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  expect(ran(await call($, CALLS.WebFetch?.(token()) ?? {}))).toBe(true)
  expect(asked.questions).toEqual([])
  expect(env.logs.length).toBe(1)
  expect(env.logs[0]?.includes('Anthropic API key in WebFetch › prompt')).toBe(true)
  expect(env.logs[0]?.includes('monitor mode: this would have been held')).toBe(true)
  expect(env.findings()[0]?.decision).toBe('warned')
})

test('a weaker finding warns in standard mode and is held in strict mode', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  expect(ran(await call($, { tool: 'SendMessage', to: 'w', message: `{"token": "${fakeJwt()}"}` }))).toBe(true)
  expect(asked.questions).toEqual([])
  expect(env.findings()[0]?.decision).toBe('warned')
})

test('strict mode holds a weaker finding too', { options: { mode: 'strict' } }, async ($, on) => {
  const env = toolsRun(on)
  answerWith(on, CANCEL)
  expect(isDenied(await call($, { tool: 'SendMessage', to: 'w', message: `{"token": "${fakeJwt()}"}` }))).toBe(true)
  expect(env.sent).toEqual([])
})

test('paused LeakStop checks nothing', async ($, on) => {
  const env = toolsRun(on)
  answerWith(on, CANCEL)
  on('command.register', (_$: any, e: any) => ({ value: { command: e.name } }))
  await $.command.run({ command: 'leakstop', args: 'pause', origin: USER })
  expect(ran(await call($, CALLS.Agent?.(token()) ?? {}))).toBe(true)
  expect(env.sent.length).toBe(1)
})

// --- Files that travel with the call ----------------------------------------------------

test('SendFile of a sensitive file is held, and the message offers a copy without secrets', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const r = await call($, { tool: 'SendFile', to: 'peer', files: ['.env', 'notes.md'] })
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('SendFile call: .env hold secrets')).toBe(true)
  expect(r.deny.includes('.env.example')).toBe(true)
  expect(asked.questions[0]?.includes('SendFile would send files that hold secrets\n  .env\n')).toBe(true)
  expect(asked.questions[0]?.includes('notes.md')).toBe(false)
  expect(env.sent).toEqual([])
})

test('SendFile of a file that holds a secret in its text is held, with the real line', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const secret = token()
  disk(on, { 'src/config.ts': `// config\nexport const apiKey = "${secret}"\n` })
  const r = await call($, { tool: 'SendFile', to: 'peer', files: ['src/config.ts'] })
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('src/config.ts contains an Anthropic API key')).toBe(true)
  expect(asked.questions[0]?.includes('→ src/config.ts\n')).toBe(true)
  expect(env.findings()[0]).toMatchObject({ path: 'src/config.ts', line: 2 })
  expect(JSON.stringify([r, asked.questions]).includes(secret.slice(14, 34))).toBe(false)
})

test('SendFile of a clean file goes through', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  disk(on, { 'notes.md': `# Notes\n${random(40)}\n` })
  expect(ran(await call($, { tool: 'SendFile', to: 'peer', files: ['notes.md'] }))).toBe(true)
  expect(asked.questions).toEqual([])
  expect(env.sent.length).toBe(1)
})

test('a file that cannot be read does not stop the call', async ($, on) => {
  toolsRun(on)
  answerWith(on, CANCEL)
  disk(on, {})
  expect(ran(await call($, { tool: 'SendFile', to: 'peer', files: ['missing.txt'] }))).toBe(true)
})

test('Artifact: the page and its supporting files are read before they are published', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const secret = PROVIDER_TOKENS['github-token']?.() ?? ''
  disk(on, { 'page.html': '<h1>hi</h1>', 'data.js': `const t = "${secret}"` })
  const r = await call($, { tool: 'Artifact', action: 'publish', file_path: 'page.html', files: { 'data.js': 'data.js' } })
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('data.js contains a GitHub token')).toBe(true)
  expect(r.deny.includes('claude.ai that other people may open')).toBe(true)
  expect(env.sent).toEqual([])

  const clean = await call($, { tool: 'Artifact', action: 'publish', file_path: 'page.html' })
  expect(ran(clean)).toBe(true)
  expect(asked.questions.length).toBe(1)
})

test('ArtifactData: a JSON file of documents is read too', async ($, on) => {
  toolsRun(on)
  answerWith(on, CANCEL)
  disk(on, { 'doc.json': `{"apiKey": "${token()}"}` })
  expect(isDenied(await call($, { tool: 'ArtifactData', action: 'set', url: 'u', collection: 'c', doc_id: 'd', file_path: 'doc.json' }))).toBe(true)
})

test('a secret in the text and a sensitive file in one call are both dealt with', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  expect(ran(await call($, { tool: 'SendFile', to: 'peer', files: ['.env'], message: `key ${token()}` }))).toBe(true)
  expect(asked.questions.length).toBe(2)
  expect(env.sent.length).toBe(1)
})

// --- Fail closed ------------------------------------------------------------------------

// Recording a finding needs the clock: with none, the check throws.

test('an internal failure is denied by the .catch in standard mode', async ($, on) => {
  toolsRun(on, { noClock: true })
  answerWith(on, CANCEL)
  const r = await call($, CALLS.Agent?.(token()) ?? {})
  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop could not check this call')).toBe(true)
})

test('an internal failure on an MCP call is denied too', { options: { mode: 'strict' } }, async ($, on) => {
  const env = toolsRun(on, { noClock: true })
  answerWith(on, CANCEL)
  const r = await call($, CALLS.mcp?.(token()) ?? {})
  expect(r.deny.startsWith('LeakStop could not check this call')).toBe(true)
  expect(env.sent).toEqual([])
})

test('an internal failure lets the call through in monitor mode', { options: { mode: 'monitor' } }, async ($, on) => {
  toolsRun(on, { noClock: true })
  answerWith(on, CANCEL)
  expect(ran(await call($, CALLS.Agent?.(token()) ?? {}))).toBe(true)
})
