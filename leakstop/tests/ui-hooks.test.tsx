import { expect, test } from 'claude-code/testing'
import { BAND_PROPS, PANE_PROPS, USER, answerWith, gitScript, isDenied, ran, storeKV, toolsRun, uiEngine } from './harness.ts'
import { PROVIDER_TOKENS, fakeJwt } from './secrets.ts'

const SURFACES = ['terminal', 'desktop'] as const
const CANCEL = 'Cancel'
const token = (): string => PROVIDER_TOKENS['anthropic-key']?.() ?? ''
const write = ($: any, path: string, content: string) => $.tool.call({ tool: 'Write', file_path: path, content })
const slash = ($: any, args: string, origin: any = USER) => $.command.run({ command: 'leakstop', args, ...(origin === null ? {} : { origin }) })

/** Everything beneath the plugin that a UI test needs; hooks must be registered before the first `$` call. */
function setup(on: any, options: { surfaces?: string[]; isPlaced?: boolean; answer?: string } = {}) {
  const env = toolsRun(on, { surfaces: options.surfaces ?? ['terminal'] })
  const ui = uiEngine(on, { isPlaced: options.isPlaced })
  const store = storeKV(on)
  // git ignores nothing here: findings are in versioned files.
  gitScript(on, (argv) => (argv[0] === 'check-ignore' ? { exitCode: 1 } : undefined))
  answerWith(on, options.answer ?? CANCEL)
  on('session.start', (_$: any, e: any) => ({ cwd: e.cwd }))
  on('prompt.submit', (_$: any, e: any) => ({ text: e.text }))
  // What the engine draws when LeakStop has nothing to say.
  on('ui.render', { component: 'AbovePrompt' }, ($: any, e: any) => {
    const { Text } = $.ui.resolve(e)
    return <Text>engine default band</Text>
  })
  return { env, ui, store }
}

const band = ($: any, surface: string, props: any = BAND_PROPS) => $.ui.mount({ plugin: 'leakstop', surface, component: 'AbovePrompt', props })
const pane = ($: any, surface: string, props: any = PANE_PROPS) => $.ui.mount({ plugin: 'leakstop', surface, component: 'Pane', props, requestId: 'leakstop' })

const MEDIUM = (): string => `{"token": "${fakeJwt()}"}`

// --- Registration and the command ------------------------------------------------

test('session.start registers /leakstop', async ($, on) => {
  const { ui } = setup(on)
  await $.session.start({ cwd: '/work/app' })
  expect(ui.registered.map((r) => r.name)).toEqual(['leakstop'])
  expect(typeof ui.registered[0].description).toBe('string')
})

test('/leakstop opens the history pane, focused, and prints nothing', async ($, on) => {
  const { ui } = setup(on)
  const result = await slash($, '')
  expect(result.text).toBe('')
  expect(ui.opened).toEqual([{ id: 'leakstop', title: 'LeakStop', focus: true }])
})

test('/leakstop falls back to the same summary as text when the pane cannot be placed', async ($, on) => {
  const secret = token()
  setup(on, { isPlaced: false })
  await write($, 'src/config.ts', `export const apiKey = "${secret}"\n`)
  const result = await slash($, '')
  expect(result.text.startsWith('LeakStop · 1 finding this session')).toBe(true)
  expect(result.text.includes('Anthropic API key · src/config.ts:1')).toBe(true)
  expect(result.text.includes('denied')).toBe(true)
  expect(result.text.includes(secret.slice(14))).toBe(false)
})

test('an unknown subcommand prints the usage', async ($, on) => {
  setup(on)
  expect((await slash($, 'frobnicate')).text.startsWith('Usage:')).toBe(true)
  expect((await slash($, 'allow')).text.startsWith('Usage:')).toBe(true)
})

// --- Pause and resume ----------------------------------------------------------------

test('pause stops the checks, resume brings them back', async ($, on) => {
  const { env } = setup(on)
  const secret = token()
  const content = `export const apiKey = "${secret}"\n`
  expect(isDenied(await write($, 'src/config.ts', content))).toBe(true)

  expect((await slash($, 'pause')).text.startsWith('LeakStop paused')).toBe(true)
  expect(ran(await write($, 'src/config.ts', content))).toBe(true)
  expect(ran(await $.tool.call({ tool: 'Bash', command: `export GITHUB_TOKEN=${PROVIDER_TOKENS['github-token']?.()}` }))).toBe(true)

  expect((await slash($, 'resume')).text).toBe('LeakStop resumed.')
  expect(isDenied(await write($, 'src/config.ts', content))).toBe(true)
  expect(env.commands.length).toBe(1)
})

test('pausing does not unprotect LeakStop’s own configuration', async ($, on) => {
  setup(on)
  await slash($, 'pause')
  expect(isDenied(await write($, '.leakstop.json', '{}'))).toBe(true)
})

test('only the person can pause, resume or allow', async ($, on) => {
  const { store } = setup(on)
  await write($, 'src/config.ts', `export const apiKey = "${token()}"\n`)
  for (const origin of [{ kind: 'sdk' }, { kind: 'task-notification' }, { kind: 'peer' }, { kind: 'plugin', name: 'other' }, null]) {
    for (const args of ['pause', 'resume', 'allow 1']) {
      const result = await slash($, args, origin)
      expect(result.text.includes('only works when you type it yourself')).toBe(true)
    }
  }
  expect(store.allowFingerprints).toBe(undefined)
  // Still protected.
  expect(isDenied(await write($, 'src/config.ts', `export const apiKey = "${token()}"\n`))).toBe(true)
  // The bridge is the person too.
  expect((await slash($, 'pause', { kind: 'bridge' })).text.startsWith('LeakStop paused')).toBe(true)
})

// --- /leakstop allow -------------------------------------------------------------------

test('allow by history number keeps the fingerprint in the store and lets that finding through', async ($, on) => {
  const { store } = setup(on)
  const content = `export const apiKey = "${token()}"\n`
  expect(isDenied(await write($, 'src/config.ts', content))).toBe(true)

  const result = await slash($, 'allow 1')
  expect(result.text.startsWith('Allowed for good: sha256:')).toBe(true)
  expect((store.allowFingerprints as string[]).length).toBe(1)
  expect(ran(await write($, 'src/config.ts', content))).toBe(true)
  // Another secret is still held.
  expect(isDenied(await write($, 'src/config.ts', `export const apiKey = "${token()}"\n`))).toBe(true)
})

test('allow by the fingerprint the block message shows', async ($, on) => {
  const { store } = setup(on)
  const secret = PROVIDER_TOKENS['github-token']?.() ?? ''
  const command = `export GITHUB_TOKEN=${secret}`
  const denied = await $.tool.call({ tool: 'Bash', command })
  expect(isDenied(denied)).toBe(true)
  await write($, 'src/a.ts', `const t = "${secret}"\n`)
  const [first] = (await slash($, 'allow sha256:ffffffffffffffff 99')).text.split('\n')
  expect(first?.startsWith('Allowed for good: sha256:ffffffffffffffff.')).toBe(true)
  expect(first?.includes('Not recognised: 99')).toBe(true)
  expect(store.allowFingerprints).toEqual(['sha256:ffffffffffffffff'])
})

// --- The banner --------------------------------------------------------------------------

for (const surface of SURFACES) {
  test(`${surface}: a medium warning shows in the banner until the next prompt`, async ($, on) => {
    const { env } = setup(on)
    expect(ran(await write($, 'tests/fixtures/user.json', MEDIUM()))).toBe(true)
    expect(env.logs).toEqual([]) // a banner is drawn here, so the transcript says nothing

    const mounted = await band($, surface, { ...BAND_PROPS, bodyColumns: 100 })
    const line = await mounted.find({ type: 'Text', text: /LeakStop · MEDIUM/ })
    expect(line?.text).toBe('△ LeakStop · MEDIUM · JSON Web Token in tests/fixtures/user.json:1 · allowed · /leakstop')
    expect(await mounted.find({ text: 'engine default band' })).toBe(undefined)

    await $.prompt.submit({ text: 'next message', origin: USER })
    await mounted.redraw()
    expect(await mounted.find({ text: /LeakStop · MEDIUM/ })).toBe(undefined)
    expect((await mounted.find({ text: 'engine default band' }))?.text).toBe('engine default band')
  })

  test(`${surface}: the banner yields to a survey and shows nothing when there is nothing to say`, async ($, on) => {
    setup(on)
    await write($, 'tests/fixtures/user.json', MEDIUM())

    const withSurvey = await band($, surface, { ...BAND_PROPS, hasSurvey: true })
    expect(await withSurvey.find({ text: /LeakStop/ })).toBe(undefined)
    expect((await withSurvey.find({ text: 'engine default band' }))?.text).toBe('engine default band')

    await slash($, '') // opening the history reads the warning: the banner clears
    const quiet = await band($, surface)
    expect(await quiet.find({ text: /LeakStop · MEDIUM/ })).toBe(undefined)
  })

  test(`${surface}: the banner fits the width it is given`, async ($, on) => {
    setup(on)
    await write($, 'packages/a/very/deep/folder/with/a/long/name/fixtures/user.json', MEDIUM())
    for (const bodyColumns of [36, 60, 100]) {
      const mounted = await band($, surface, { ...BAND_PROPS, bodyColumns })
      const line = await mounted.find({ text: /LeakStop/ })
      expect((line?.text ?? '').length).toBeLessThanOrEqual(bodyColumns - 2)
      expect((line?.text ?? '').length).toBeGreaterThan(10)
    }
  })

  test(`${surface}: a paused session says so above the prompt`, async ($, on) => {
    setup(on)
    await slash($, 'pause')
    const mounted = await band($, surface)
    expect((await mounted.find({ type: 'Text', text: /PAUSED/ }))?.text).toBe('△ LeakStop · PAUSED · nothing is being checked · /leakstop resume')
    await slash($, 'resume')
    await mounted.redraw()
    expect(await mounted.find({ type: 'Text', text: /PAUSED/ })).toBe(undefined)
  })
}

test('where nothing is drawn, warnings go to the transcript instead of the banner', async ($, on) => {
  const { env } = setup(on, { surfaces: [] })
  expect(ran(await write($, 'tests/fixtures/user.json', MEDIUM()))).toBe(true)
  expect(env.logs.length).toBe(1)
  expect(env.logs[0]?.startsWith('LeakStop · MEDIUM')).toBe(true)
})

test('the VS Code panel and headless runs draw no banner either', async ($, on) => {
  const { env } = setup(on, { surfaces: ['vscode'] })
  expect(ran(await write($, 'tests/fixtures/user.json', MEDIUM()))).toBe(true)
  expect(env.logs.length).toBe(1)
})

// --- The history pane ---------------------------------------------------------------------

for (const surface of SURFACES) {
  test(`${surface}: the pane lists the findings, never a value, with working buttons`, async ($, on) => {
    const { ui } = setup(on)
    const secret = token()
    await write($, 'src/config.ts', `export const apiKey = "${secret}"\n`)
    await write($, 'tests/fixtures/user.json', MEDIUM())

    const mounted = await pane($, surface)
    const rows = await mounted.findAll({ type: 'Text' })
    const texts = rows.map((r) => r.text)
    expect(texts.some((t) => t.startsWith('#2') && t.includes('JSON Web Token'))).toBe(true)
    expect(texts.some((t) => t.startsWith('#1') && t.includes('CRITICAL') && t.includes('Anthropic API key · src/config.ts:1'))).toBe(true)
    expect(texts.some((t) => t.includes('→ denied'))).toBe(true)
    expect(texts.some((t) => t.includes('→ allowed'))).toBe(true)
    expect(JSON.stringify(await mounted.drawn()).includes(secret.slice(14))).toBe(false)

    expect((await mounted.find({ type: 'Button', key: 'pause' }))?.props.label).toBe('Pause')
    expect((await mounted.find({ type: 'Button', key: 'close' }))?.props.label).toBe('Close')
    expect((await mounted.find({ type: 'Button', key: 'pause' }))?.props.hotkey).toBe('1')

    await mounted.press({ key: 'pause' })
    await mounted.redraw()
    expect((await mounted.find({ type: 'Button', key: 'pause' }))?.props.label).toBe('Resume')
    expect((await mounted.find({ type: 'Text', text: /PAUSED/ }))?.text).toBe('PAUSED · nothing is being checked')
    expect(ran(await write($, 'src/config.ts', `export const apiKey = "${secret}"\n`))).toBe(true)

    await mounted.press({ key: 'pause' })
    await mounted.redraw()
    expect((await mounted.find({ type: 'Button', key: 'pause' }))?.props.label).toBe('Pause')

    await mounted.press({ key: 'close' })
    expect(ui.closed.map((c) => c.id)).toEqual(['leakstop'])
  })

  test(`${surface}: the pane says so when there is nothing to show`, async ($, on) => {
    setup(on)
    const mounted = await pane($, surface)
    expect((await mounted.find({ type: 'Text', text: /No findings/ }))?.text).toBe('No findings this session.')
  })

  test(`${surface}: the pane fits its width and its height`, async ($, on) => {
    setup(on)
    for (let i = 0; i < 12; i++) await write($, `packages/service-${i}/some/deep/path/fixtures/user.json`, MEDIUM())
    const mounted = await pane($, surface, { ...PANE_PROPS, bodyColumns: 30 })
    for (const text of (await mounted.findAll({ type: 'Text' })).map((t) => t.text)) expect(text.length).toBeLessThanOrEqual(30)
    // Newest first, as many rows as the height allows.
    const heads = (await mounted.findAll({ type: 'Text' })).map((t) => t.text).filter((t) => t.startsWith('#'))
    expect(heads[0]?.startsWith('#12')).toBe(true)
  })
}

// --- State survives a reload ---------------------------------------------------------------

test('findings, the pause and the warnings live in $.state, so a reload keeps them', async ($, on) => {
  setup(on)
  await write($, 'tests/fixtures/user.json', MEDIUM())
  await slash($, 'pause')
  // A hot reload runs register() again and fires session.start again; module variables start over, `$.state` does not.
  await $.session.start({ cwd: '/work/app' })
  await $.session.start({ cwd: '/work/app' })

  const mounted = await pane($, 'terminal')
  expect((await mounted.find({ type: 'Text', text: /JSON Web Token/ }))?.text.startsWith('#1')).toBe(true)
  expect(await mounted.find({ type: 'Text', text: /PAUSED/ })).toBeDefined()
  const bar = await band($, 'terminal')
  expect(await bar.find({ type: 'Text', text: /PAUSED/ })).toBeDefined()
})
