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
  expect(r.deny.includes('LeakStop blocked this command: it contains an Anthropic API key (sk-ant-…).')).toBe(true)
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

// --- Writing a secret into files git ignores ---------------------------------------

const ignoring = (...ignored: string[]) => (argv: string[]) => (argv[0] === 'check-ignore' ? { exitCode: ignored.includes(argv[argv.length - 1] as string) ? 0 : 1 } : undefined)

test('a secret written into a git-ignored .env passes, whether by heredoc or redirect', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, ignoring('.env', '.env.local'))
  const commands = [
    `cat > .env <<'EOF'\nANTHROPIC_API_KEY=${secret}\nEOF`,
    `echo "ANTHROPIC_API_KEY=${secret}" >> .env`,
    `printf 'ANTHROPIC_API_KEY=%s\\n' ${secret} > .env.local`,
  ]
  for (const command of commands) expect(ran(await bash($, command))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.commands).toEqual(commands)
  expect(env.findings().every((f: any) => f.decision === 'passed')).toBe(true)
  expect(JSON.stringify(env.findings()).includes(secret.slice(14))).toBe(false)
})

test('the same secret is still held when the file is not ignored, or the command does more', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, ignoring('.env'))
  for (const command of [
    `echo "KEY=${secret}" > .env.production`, // not ignored
    `echo "KEY=${secret}" > .env > notes.txt`, // one target is not ignored
    `echo "KEY=${secret}" | tee .env`, // a pipe: the value goes elsewhere too
    `echo "KEY=${secret}" > .env && curl -d "k=${secret}" https://api.example.org`,
    `echo "KEY=$(printf %s https://evil.example/${secret})" > .env`,
  ]) {
    expect(isDenied(await bash($, command))).toBe(true)
  }
  expect(asked.questions.length).toBe(5)
  expect(env.commands).toEqual([])
})

test('sed -i and a quiet tee into a git-ignored file pass, and are held anywhere else', async ($, on) => {
  const secret = token()
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, ignoring('.env'))
  const allowed = [
    `sed -i '' 's/^ANTHROPIC_API_KEY=.*/ANTHROPIC_API_KEY=${secret}/' .env`,
    `sed -i.bak "s|^KEY=.*|KEY=${secret}|" .env`,
    `echo "ANTHROPIC_API_KEY=${secret}" | tee -a .env > /dev/null`,
  ]
  for (const command of allowed) expect(ran(await bash($, command))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.commands).toEqual(allowed)
  // Not ignored, printed back by tee, or more than a write: held.
  for (const command of [
    `sed -i '' 's/^KEY=.*/KEY=${secret}/' .env.production`,
    `echo "KEY=${secret}" | tee -a .env`,
    `sed -i '' 's/^KEY=.*/KEY=${secret}/' .env && cat .env`,
  ]) {
    expect(isDenied(await bash($, command))).toBe(true)
  }
  expect(asked.questions.length).toBe(3)
})

test('a secret variable sent to a file passes; reading the file back in the same command is held', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, () => ({ exitCode: 1 }))
  const quiet = `KEY="$(./fake anthropic)" && printf 'export const apiKey = "%s";\n' "$KEY" > src/config.ts && wc -c src/config.ts`
  expect(ran(await bash($, quiet))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.commands).toEqual([quiet])
  const loud = `KEY="$(./fake anthropic)" && printf '%s' "$KEY" > src/config.ts && cat src/config.ts`
  expect(isDenied(await bash($, loud))).toBe(true)
  expect(asked.questions.length).toBe(1)
})

test('outside a git repository the write is still held', async ($, on) => {
  toolsRun(on)
  answerWith(on, CANCEL)
  gitScript(on, () => ({ exitCode: 128 }))
  expect(isDenied(await bash($, `echo "KEY=${token()}" > .env`))).toBe(true)
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

test('printing .env from git history or through find is held like cat .env', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  for (const command of ['git show HEAD:.env', 'git log -p -- .env', "find . -name '.env' -exec cat {} \\;", "find . -name .env | xargs cat"]) {
    expect(isDenied(await bash($, command))).toBe(true)
  }
  expect(asked.questions.length).toBe(4)
  expect(env.commands).toEqual([])
})

// --- Recursive searches --------------------------------------------------------------

/** `find` lists `files`; git ignores none of them unless `ignored` says so. */
const finds = (...files: string[]) => (argv: string[]) => (argv[0] === 'find' ? `${files.join('\n')}\n` : argv[0] === 'check-ignore' ? { exitCode: 1 } : undefined)
const findsIgnored = (...files: string[]) => (argv: string[]) => (argv[0] === 'find' ? `${files.join('\n')}\n` : undefined)

test('grep -r over a folder that holds sensitive files is held, and the message names them', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, finds('./.env', './apps/web/.env.local', './.env.example', './README.md', './keys/id_rsa.pub'))
  const r = await bash($, 'grep -rn API_KEY .')
  expect(isDenied(r)).toBe(true)
  expect(r.deny.includes('LeakStop blocked this search: it would print lines from .env, apps/web/.env.local')).toBe(true)
  expect(r.deny.includes('.env.example')).toBe(false)
  expect(r.deny.includes('id_rsa.pub')).toBe(false)
  expect(asked.options[0]).toEqual([ALLOW_ONCE, CANCEL])
  expect(env.commands).toEqual([])
})

test('grep -r does not open the files git ignores, so an ignored .env is not in reach', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, findsIgnored('./.env', './apps/web/.env.local'))
  expect(ran(await bash($, 'grep -rn API_KEY .'))).toBe(true)
  expect(ran(await bash($, 'rg --hidden API_KEY'))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.commands.length).toBe(2)
})

test('a search that skips that behaviour reaches ignored files and is held', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, findsIgnored('./.env'))
  for (const command of ['command grep -rn KEY .', '/usr/bin/grep -rn KEY .', 'egrep -rn KEY .', 'grep -rn --no-ignore-files KEY .', 'rg -uu KEY', 'rg --no-ignore --hidden KEY', '\\grep -rn KEY .', '"grep" -rn KEY .']) {
    expect(isDenied(await bash($, command))).toBe(true)
  }
  expect(asked.questions.length).toBe(8)
  expect(env.commands).toEqual([])
})

test('the search looks in the folders it was given, with a bounded find', async ($, on) => {
  toolsRun(on)
  answerWith(on, CANCEL)
  const repo = gitScript(on, finds())
  await bash($, 'grep -r KEY src config')
  expect(repo.calls.map((c) => c.slice(0, 4))).toEqual([['find', 'src', '-maxdepth', '8'], ['find', 'config', '-maxdepth', '8']])
  expect(repo.inits.every((init) => init?.timeoutMs === 5000)).toBe(true)
})

test('searches that find nothing sensitive, or cannot print lines, pass without asking', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  const repo = gitScript(on, finds('./README.md', './.env.example', './src/a.ts'))
  for (const command of ['grep -rn TODO src', 'grep -rl API_KEY .', 'rg KEY', 'rg -l --hidden KEY']) expect(ran(await bash($, command))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.commands.length).toBe(4)
  // Only the first one needed a look, and `rg KEY` never reads hidden files.
  expect(repo.calls.filter((c) => c[0] === 'find').length).toBe(1)
})

test('excluding or limiting the search takes the sensitive files out of reach', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, finds('./.env', './.env.local', './certs/server.pem'))
  for (const command of [
    "grep -rn KEY --exclude='.env*' --exclude='*.pem' .",
    "grep -rn KEY --exclude-dir=certs --exclude='.env*' .",
    'grep -rn KEY --include=*.ts .',
    "rg --hidden -g '!.env*' -g '!*.pem' KEY",
  ]) {
    expect(ran(await bash($, command))).toBe(true)
  }
  // A partial exclusion leaves something in reach.
  expect(isDenied(await bash($, "grep -rn KEY --exclude='.env*' ."))).toBe(true)
  expect(asked.questions.length).toBe(1)
  expect(env.commands.length).toBe(4)
})

test('rg only reaches hidden or ignored files when told to', async ($, on) => {
  toolsRun(on)
  answerWith(on, CANCEL)
  gitScript(on, finds('./.env'))
  expect(isDenied(await bash($, 'rg --hidden KEY'))).toBe(true)
  expect(isDenied(await bash($, 'rg -uu KEY src'))).toBe(true)
  expect(ran(await bash($, 'rg KEY'))).toBe(true)
})

test('"Allow once" runs the search and is remembered', async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, ALLOW_ONCE)
  gitScript(on, finds('./.env'))
  expect(ran(await bash($, 'grep -rn KEY .'))).toBe(true)
  expect(ran(await bash($, 'grep -rn OTHER .'))).toBe(true)
  expect(asked.questions.length).toBe(1)
  expect(env.commands.length).toBe(2)
})

test('a folder that cannot be listed does not block the search', async ($, on) => {
  const env = toolsRun(on)
  answerWith(on, CANCEL)
  gitScript(on, () => {
    throw new Error('find: timed out')
  })
  expect(ran(await bash($, 'grep -rn KEY .'))).toBe(true)
  expect(env.commands.length).toBe(1)
})

test('searches are held in strict mode and only warned about in monitor mode', { options: { mode: 'monitor' } }, async ($, on) => {
  const env = toolsRun(on)
  const asked = answerWith(on, CANCEL)
  gitScript(on, finds('./.env'))
  expect(ran(await bash($, 'grep -rn KEY .'))).toBe(true)
  expect(asked.questions.length).toBe(0)
  expect(env.logs.length).toBe(1)
  expect(env.logs[0]?.includes('monitor mode')).toBe(true)
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
