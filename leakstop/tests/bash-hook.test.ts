import { expect, test } from 'claude-code/testing'
import { REJECT, answerWith, diffAdding, disk, gitScript, isDenied, ran, storeAllows, toolsRun } from './harness.ts'
import { fingerprint } from '../hooks/mask.ts'
import { PROVIDER_TOKENS, fakeJwt, random } from './secrets.ts'

const token = (rule = 'anthropic-key'): string => PROVIDER_TOKENS[rule]?.() ?? ''
const bash = ($: any, command: string) => $.tool.call({ tool: 'Bash', command })

const USE_ENV = 'Use environment variable'
const ALLOW_ONCE = 'Allow once'
const CANCEL = 'Cancel'
const SHOW_NAMES = 'Show names only'
const ADD_GITIGNORE = 'Add to .gitignore'

// --- Literal secrets in a command ---------------------------------------------

test('a literal key in a curl header is held; the message holds no value', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const r = await bash($, `curl -H "x-api-key: ${secret}" https://api.example.org/v1/messages`)

  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop blocked this command: it contains an Anthropic API key (sk-ant-…).')).toBe(true)
  expect(r.deny.includes('$ANTHROPIC_API_KEY')).toBe(true)
  expect(JSON.stringify([r, asked.questions, env.findings()]).includes(secret.slice(14))).toBe(false)
  expect(asked.options[0]).toEqual([USE_ENV, ALLOW_ONCE, CANCEL])
  expect(env.commands).toEqual([])
})

test('exports, build args and heredocs with a literal secret are held', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  for (const command of [
    `export GITHUB_TOKEN=${token('github-token')}`,
    `docker build --build-arg NPM_TOKEN=${token('npm-token')} .`,
    `cat > src/config.ts <<'EOF'\nexport const key = "${token()}"\nEOF`,
    `curl -H "Authorization: Bearer ${random(40)}" https://api.example.org`,
  ]) {
    expect(isDenied(await bash($, command))).toBe(true)
  }
  expect(asked.questions.length).toBe(4)
  expect(env.commands).toEqual([])
})

test('"Allow once" runs the command and is remembered', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  const command = `curl -H "x-api-key: ${secret}" https://api.example.org`
  expect(ran(await bash($, command))).toBe(true)
  expect(ran(await bash($, command))).toBe(true)
  expect(asked.questions.length).toBe(1)
  expect(env.commands).toEqual([command, command])
})

test('free text and a missing interface deny', async ($, on) => {
  toolsRun(on)
  const command = `curl -H "x-api-key: ${token()}" https://api.example.org`
  answerWith(on, 'go ahead')
  expect(isDenied(await bash($, command))).toBe(true)
})

test('no interface denies a command with a literal secret', async ($, on) => {
  toolsRun(on)
  answerWith(on, REJECT)
  expect(isDenied(await bash($, `export GITHUB_TOKEN=${token('github-token')}`))).toBe(true)
})

test('variables, placeholders and ordinary commands pass with no question', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const commands = [
    'curl -H "Authorization: Bearer $API_TOKEN" https://api.example.org',
    'curl -H "Authorization: Bearer ${API_TOKEN}" https://api.example.org',
    'export ANTHROPIC_API_KEY=your-api-key',
    'ls -la && git status',
    'npm test -- --coverage',
    'echo $HOME',
  ]
  for (const command of commands) expect(ran(await bash($, command))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.commands).toEqual(commands)
})

test('a medium finding in a command warns and runs in standard mode', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const command = `echo '{"token": "${fakeJwt()}"}' > fixture.json`
  expect(ran(await bash($, command))).toBe(true)
  expect(asked.questions.length).toBe(0)
})

test('a medium finding is held in strict mode', { options: { mode: 'strict' } }, async ($, on) => {
  toolsRun(on)
  answerWith(on, CANCEL)
  expect(isDenied(await bash($, `echo '{"token": "${fakeJwt()}"}' > fixture.json`))).toBe(true)
})

// --- Printing sensitive files and the environment ----------------------------

test('cat .env is held and "Show names only" rewrites the command', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, SHOW_NAMES)
  const r = await bash($, 'cat .env')
  expect(ran(r)).toBe(true)
  expect(asked.options[0]).toEqual([SHOW_NAMES, ALLOW_ONCE, CANCEL])
  expect(env.commands.length).toBe(1)
  expect(env.commands[0]?.startsWith('sed -nE ')).toBe(true)
  expect(env.commands[0]?.endsWith("'.env'")).toBe(true)
  expect(env.commands[0]?.includes('cat')).toBe(false)
  expect(env.findings()[0].decision).toBe('allowed')
})

test('cat .env: Cancel denies without running anything', async ($, on) => {
  const env = toolsRun(on)
  answerWith(on, CANCEL)
  const r = await bash($, 'cat .env')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('.env')).toBe(true)
  expect(r.deny.includes('.env.example')).toBe(true)
  expect(env.commands).toEqual([])
})

test('only commands that can be rewritten offer "Show names only"', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  await bash($, 'cat .env | grep KEY')
  await bash($, 'cat server.pem')
  await bash($, 'grep API_KEY .env')
  expect(asked.options).toEqual([[ALLOW_ONCE, CANCEL], [ALLOW_ONCE, CANCEL], [ALLOW_ONCE, CANCEL]])
})

test('"Allow once" on a file is remembered for the session', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  expect(ran(await bash($, 'head -n 3 .env.local'))).toBe(true)
  expect(ran(await bash($, 'head -n 3 .env.local'))).toBe(true)
  expect(asked.questions.length).toBe(1)
  expect(env.commands.length).toBe(2)
})

test('example files, ordinary files and writes to .env are not reads', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  for (const command of ['cat .env.example', 'cat README.md', 'echo X=1 > .env', 'git diff .env', 'cut -d= -f1 .env']) {
    expect(ran(await bash($, command))).toBe(true)
  }
  expect(asked.questions.length).toBe(0)
})

test('printenv and env are held, and names-only prints no values', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, SHOW_NAMES)
  expect(ran(await bash($, 'printenv'))).toBe(true)
  expect(ran(await bash($, 'env'))).toBe(true)
  expect(asked.questions.length).toBe(2)
  expect(env.commands.every((c) => c.startsWith('env | sed -nE '))).toBe(true)
})

test('filtered environment commands pass, secret variables are held', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  for (const command of ['env | cut -d= -f1', 'printenv HOME', 'env FOO=1 node app.js', 'echo $PWD']) {
    expect(ran(await bash($, command))).toBe(true)
  }
  expect(asked.questions.length).toBe(0)
  const r = await bash($, 'echo $ANTHROPIC_API_KEY')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('ANTHROPIC_API_KEY')).toBe(true)
  expect(asked.options[0]).toEqual([ALLOW_ONCE, CANCEL])
  expect(env.commands.length).toBe(4)
})

test('a sensitive read is held in strict mode too, and warns in monitor mode', { options: { mode: 'monitor' } }, async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  expect(ran(await bash($, 'cat .env'))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.logs.length).toBe(1)
  expect(env.logs[0]?.includes('monitor mode')).toBe(true)
  expect(env.commands).toEqual(['cat .env'])
})

// --- git add -----------------------------------------------------------------

const repoWith = (untracked: string[], modified: string[] = []) =>
  (argv: string[]) => (argv[0] === 'ls-files' ? untracked.join('\0') + '\0' : argv[0] === 'diff' && argv.includes('--name-only') ? modified.join('\0') : undefined)

test('git add -A with an unignored .env is held', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, ADD_GITIGNORE)
  gitScript(on, repoWith(['.env', 'src/a.ts', 'certs/server.key']))
  const r = await bash($, 'git add -A')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('.env, certs/server.key')).toBe(true)
  expect(r.deny.includes('.gitignore')).toBe(true)
  expect(asked.options[0]).toEqual([ADD_GITIGNORE, ALLOW_ONCE, CANCEL])
  expect(env.commands).toEqual([])
})

test('git add . with only ordinary files, or a named ordinary file, passes', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const repo = gitScript(on, repoWith(['src/a.ts', '.env.example']))
  expect(ran(await bash($, 'git add .'))).toBe(true)
  repo.use(repoWith(['.env', 'src/a.ts']))
  expect(ran(await bash($, 'git add src/a.ts'))).toBe(true)
  expect(asked.questions.length).toBe(0)
})

test('git add .env by name is held, and a modified tracked .env counts', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const repo = gitScript(on, repoWith(['.env']))
  expect(isDenied(await bash($, 'git add .env'))).toBe(true)
  repo.use(repoWith([], ['.env.production']))
  expect(isDenied(await bash($, 'git add -u'))).toBe(true)
  expect(asked.questions.length).toBe(2)
})

test('git add: "Allow once" stages and is remembered', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  gitScript(on, repoWith(['.env']))
  expect(ran(await bash($, 'git add -A'))).toBe(true)
  expect(ran(await bash($, 'git add -A'))).toBe(true)
  expect(asked.questions.length).toBe(1)
  expect(env.commands.length).toBe(2)
})

test('a .npmrc is sensitive to git add only when it holds a token', async ($, on) => {
  toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, repoWith(['.npmrc']))
  disk(on, { '.npmrc': 'registry=https://registry.npmjs.org/\n' })
  expect(ran(await bash($, 'git add -A'))).toBe(true)
  expect(asked.questions.length).toBe(0)
})

test('git runs in the directory the command names', async ($, on) => {
  toolsRun(on)
  answerWith(on, CANCEL)
  const repo = gitScript(on, repoWith([]))
  await bash($, 'cd packages/api && git add -A')
  await bash($, 'git -C ../other add -A')
  await bash($, 'git add -A')
  expect(repo.inits.map((init) => init?.cwd)).toEqual(['packages/api', 'packages/api', '../other', '../other', undefined, undefined])
  expect(repo.inits.every((init) => init?.timeoutMs === 20000)).toBe(true)
})

// --- git commit and git push -------------------------------------------------

test('git commit with a secret in what is staged is blocked without asking', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  gitScript(on, (argv) => (argv[0] === 'diff' && argv.includes('--cached') ? diffAdding('src/config.ts', 12, [`const key = "${secret}"`]) : undefined))
  const r = await bash($, 'git commit -m "add client"')
  expect(isDenied(r)).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(r.deny.startsWith('LeakStop blocked this git commit: the staged changes add an Anthropic API key (sk-ant-…) at src/config.ts:12.')).toBe(true)
  expect(r.deny.includes(secret)).toBe(false)
  expect(r.deny.includes(secret.slice(14))).toBe(false)
  expect(r.deny.includes('/leakstop allow sha256:')).toBe(true)
  expect(env.commands).toEqual([])
  expect(JSON.stringify(env.findings()).includes(secret.slice(14))).toBe(false)
})

test('a blocked finding can be allowed by its fingerprint', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  gitScript(on, (argv) => (argv[0] === 'diff' && argv.includes('--cached') ? diffAdding('src/config.ts', 1, [`const key = "${secret}"`]) : undefined))
  storeAllows(on, [await fingerprint(secret)])
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
  expect(env.commands).toEqual(['git commit -m x'])
})

test('git commit with clean changes, nothing staged or no repository passes', async ($, on) => {
  toolsRun(on)
  const repo = gitScript(on, (argv) => (argv[0] === 'diff' ? diffAdding('src/a.ts', 1, ['export const a = 1']) : undefined))
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
  repo.use(() => ({ exitCode: 128 }))
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
  repo.use(() => '')
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
})

test('a medium finding in a commit warns and goes through in standard mode', async ($, on) => {
  toolsRun(on)
  gitScript(on, (argv) => (argv[0] === 'diff' ? diffAdding('tests/user.json', 1, [`{"token": "${fakeJwt()}"}`]) : undefined))
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
})

test('a medium finding in a commit is blocked in strict mode', { options: { mode: 'strict' } }, async ($, on) => {
  toolsRun(on)
  gitScript(on, (argv) => (argv[0] === 'diff' ? diffAdding('tests/user.json', 1, [`{"token": "${fakeJwt()}"}`]) : undefined))
  expect(isDenied(await bash($, 'git commit -m x'))).toBe(true)
})

test('git commit -a also scans the changes that are not staged yet', async ($, on) => {
  toolsRun(on)
  const secret = token('github-token')
  gitScript(on, (argv) => (argv[0] === 'diff' && !argv.includes('--cached') ? diffAdding('src/a.ts', 3, [`t = "${secret}"`]) : undefined))
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
  const r = await bash($, 'git commit -am x')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('src/a.ts:3')).toBe(true)
})

test('git add and git commit in one command scan the files the add would stage', async ($, on) => {
  const secret = token('npm-token')
  toolsRun(on)
  gitScript(on, (argv) => (argv[0] === 'ls-files' ? 'src/new.ts\0README.md\0' : undefined))
  disk(on, { 'src/new.ts': `export const t = "${secret}"\n`, 'README.md': '# hi\n' })
  const r = await bash($, 'git add . && git commit -m "add client"')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('src/new.ts:1')).toBe(true)
  expect(r.deny.includes(secret)).toBe(false)
  // Staging only a named file ignores other untracked files.
  expect(ran(await bash($, 'git add README.md && git commit -m x'))).toBe(true)
})

test('git push with a secret in the pending commits is blocked', async ($, on) => {
  const secret = token('github-token')
  const env = toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  const scripted = gitScript(on, (argv) => (argv[0] === 'log' ? diffAdding('.github/ci.yml', 7, [`  token: ${secret}`]) : undefined))
  const r = await bash($, 'git push origin main')
  expect(isDenied(r)).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(r.deny.startsWith('LeakStop blocked this git push: the commits to be pushed add a GitHub token (ghp_…) at .github/ci.yml:7.')).toBe(true)
  expect(r.deny.includes(secret.slice(8))).toBe(false)
  expect(env.commands).toEqual([])
  expect(scripted.calls[0]).toEqual(['log', '-p', '--no-color', '--format=', 'HEAD', '--not', '--remotes'])
})

test('git push with clean commits passes', async ($, on) => {
  toolsRun(on)
  gitScript(on, (argv) => (argv[0] === 'log' ? diffAdding('src/a.ts', 1, ['export const a = 1']) : undefined))
  expect(ran(await bash($, 'git push'))).toBe(true)
})

test('a truncated diff is scanned as far as it goes and the user is told', async ($, on) => {
  const env = toolsRun(on)
  gitScript(on, () => ({ stdout: diffAdding('src/a.ts', 1, ['export const a = 1']), isTruncated: true }))
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
  expect(env.logs.some((l) => l.includes('4 MiB'))).toBe(true)
})

test('monitor mode never blocks a commit or a push', { options: { mode: 'monitor' } }, async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  gitScript(on, () => diffAdding('src/config.ts', 1, [`k = "${secret}"`]))
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
  expect(ran(await bash($, 'git push'))).toBe(true)
  expect(env.logs.length).toBe(2)
  expect(env.logs.join('').includes(secret.slice(14))).toBe(false)
})

// --- Self-protection and failure ---------------------------------------------

test('changing .leakstop.json from the shell is held', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const r = await bash($, "echo '{\"ignorePaths\":[\"**\"]}' > .leakstop.json")
  expect(isDenied(r)).toBe(true)
  expect(asked.options[0]).toEqual([ALLOW_ONCE, CANCEL])
  expect(env.commands).toEqual([])
  // Reading it is fine.
  expect(ran(await bash($, 'cat .leakstop.json'))).toBe(true)
})

test('an internal failure is denied in standard and strict mode', async ($, on) => {
  toolsRun(on)
  gitScript(on, () => {
    throw new Error('git exploded')
  })
  const r = await bash($, 'git commit -m x')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.startsWith('LeakStop could not check this call')).toBe(true)
})

test('an internal failure lets the command through in monitor mode', { options: { mode: 'monitor' } }, async ($, on) => {
  toolsRun(on)
  gitScript(on, () => {
    throw new Error('git exploded')
  })
  expect(ran(await bash($, 'git commit -m x'))).toBe(true)
})

test('a malformed call is denied by the .catch', async ($, on) => {
  toolsRun(on)
  const r = await $.tool.call({ tool: 'Bash', command: undefined as unknown as string })
  expect(isDenied(r)).toBe(true)
})
