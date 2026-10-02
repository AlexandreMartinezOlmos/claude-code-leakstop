import { expect, test } from 'claude-code/testing'
import { MAX_SCAN_CHARS, classifyPath, entropy, scanEdit, scanText, scanWrite } from '../hooks/detect.ts'
import { BASE64, HEX, PROVIDER_TOKENS, URLSAFE, fakeJwt, fakePrivateKey, random } from './secrets.ts'

const ids = (text: string, path?: string): string[] => scanText(text, { path }).findings.map((f) => f.ruleId)

// --- Provider tokens -------------------------------------------------------

for (const [ruleId, make] of Object.entries(PROVIDER_TOKENS)) {
  test(`detects a ${ruleId}`, () => {
    const token = make()
    const { findings } = scanText(`const key = "${token}"\n`)
    expect(findings.length).toBe(1)
    expect(findings[0]?.ruleId).toBe(ruleId)
    expect(findings[0]?.severity).toBe('critical')
    expect(findings[0]?.value).toBe(token)
  })
}

test('detects a private key and requires a body', () => {
  const key = fakePrivateKey()
  const { findings } = scanText(`a\nb\n${key}\nc`)
  expect(findings.length).toBe(1)
  expect(findings[0]?.ruleId).toBe('private-key')
  expect(findings[0]?.line).toBe(3)
  // A header with no body is documentation, not a key.
  expect(ids(`-----BEGIN ${'RSA'} PRIVATE KEY-----\n...\n-----END ${'RSA'} PRIVATE KEY-----`)).toEqual([])
})

test('a Stripe test key is medium, a live key critical', () => {
  const { findings } = scanText(`sk_test_${random(24)}`)
  expect(findings[0]?.severity).toBe('medium')
})

test('detects credentials in a URL, but not placeholders or local defaults', () => {
  expect(ids(`DATABASE_URL=postgres://app:${random(20)}@db.internal:5432/app`)).toEqual(['url-credentials'])
  expect(ids(`mongodb+srv://admin:${random(16)}@cluster0.example.net/db`)).toEqual(['url-credentials'])
  expect(ids('redis://:' + random(18) + '@cache:6379')).toEqual(['url-credentials'])
  expect(ids('postgres://user:password@localhost/db')).toEqual([])
  expect(ids('postgres://postgres:postgres@localhost/db')).toEqual([])
  expect(ids('postgres://user:${DB_PASSWORD}@localhost/db')).toEqual([])
  expect(ids('https://github.com/org/repo')).toEqual([])
})

test('detects a JWT as medium', () => {
  const { findings } = scanText(`{"token": "${fakeJwt()}"}`)
  expect(findings.map((f) => f.ruleId)).toEqual(['jwt'])
  expect(findings[0]?.severity).toBe('medium')
})

// --- Generic heuristic -----------------------------------------------------

test('detects a hard-coded credential as medium, quoted or bare', () => {
  for (const text of [
    `password = "${random(24)}"`,
    `API_KEY: '${random(32)}'`,
    `{ "client_secret": "${random(40, URLSAFE)}" }`,
    `AUTH_TOKEN=${random(32)}`,
  ]) {
    const { findings } = scanText(text)
    expect(findings.length).toBe(1)
    expect(findings[0]?.ruleId).toBe('generic-assignment')
    expect(findings[0]?.severity).toBe('medium')
  }
})

test('a provider finding wins over the generic one on the same text', () => {
  const { findings } = scanText(`apiKey = "${PROVIDER_TOKENS['anthropic-key']?.()}"`)
  expect(findings.map((f) => f.ruleId)).toEqual(['anthropic-key'])
})

test('placeholders pass', () => {
  for (const text of [
    'API_KEY="your-api-key"',
    'API_KEY="your-api-key-goes-here-123"',
    'password = "changeme-changeme"',
    'token: "<TOKEN_FROM_VAULT_PLEASE>"',
    'SECRET="xxxxxxxxxxxxxxxxxxxxxxxx"',
    'api_key = "${ANTHROPIC_API_KEY_VALUE}"',
    `key = "sk-ant-${'x'.repeat(30)}"`,
    'access_token = "••••••••••••••••••••"',
  ]) {
    expect(ids(text)).toEqual([])
  }
})

test('the AWS documentation example key passes', () => {
  const example = `AKIA${'IOSFODNN7'}${'EXAMPLE'}`
  expect(ids(`aws_access_key_id = ${example}`)).toEqual([])
  expect(ids(`aws_access_key_id = AKIA${random(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}`)).toEqual(['aws-access-key'])
})

test('reading a value from the environment is not a hard-coded secret', () => {
  for (const text of [
    'const apiKey = process.env.ANTHROPIC_API_KEY_VALUE_FOR_TESTS',
    'api_key = os.environ.get_secret_value_for_tests',
    'password: SOME_ENVIRONMENT_VARIABLE_NAME',
    'secret = get_secret_from_somewhere_else',
    'token_url = "https://oauth.example.org/oauth2/token/endpoint"',
    'secret_path = "/var/run/secrets/kubernetes.io/token"',
  ]) {
    expect(ids(text)).toEqual([])
  }
})

test('low entropy values and short values pass', () => {
  expect(ids('password = "aaaaaaaaaaaaaaaaaaaaaaaa"')).toEqual([])
  expect(ids('password = "abababababababababababab"')).toEqual([])
  expect(ids('password = "short1"')).toEqual([])
  expect(entropy('aaaa')).toBe(0)
  expect(entropy('abcd')).toBe(2)
})

// --- Typical false positives -------------------------------------------------

test('commit hashes, UUIDs and lockfile integrity fields pass', () => {
  const sha = random(40, HEX)
  const uuid = `${random(8, HEX)}-${random(4, HEX)}-${random(4, HEX)}-${random(4, HEX)}-${random(12, HEX)}`
  const integrity = `sha512-${random(86, BASE64)}==`
  expect(ids(`token = "${sha}"`)).toEqual([])
  expect(ids(`{ "token": "${uuid}" }`)).toEqual([])
  expect(ids(`{ "token": "${integrity}" }`)).toEqual([])
  expect(ids(`commit ${sha}\nAuthor: someone`)).toEqual([])
  const lock = `{\n  "node_modules/left-pad": {\n    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",\n    "integrity": "${integrity}"\n  }\n}`
  expect(ids(lock, 'package-lock.json')).toEqual([])
  // Generic rules are off in lockfiles, provider rules are not.
  expect(ids(`"token": "${random(32)}"`, 'package-lock.json')).toEqual([])
  expect(ids(`"x": "${PROVIDER_TOKENS['github-token']?.()}"`, 'package-lock.json')).toEqual(['github-token'])
})

test('a base64 image passes', () => {
  expect(ids(`icon = "data:image/png;base64,${random(200, BASE64)}"`)).toEqual([])
})

// --- Write and Edit --------------------------------------------------------

test('Write scans the whole content, Edit only the new text', () => {
  const token = PROVIDER_TOKENS['anthropic-key']?.() ?? ''
  const other = PROVIDER_TOKENS['github-token']?.() ?? ''
  const before = `const a = 1\nconst key = "${token}"\nconst b = 2\n`

  expect(scanWrite('src/config.ts', before).findings.length).toBe(1)

  // Edit of another line, with the secret still inside the replaced block.
  expect(scanEdit('src/config.ts', before, before.replace('const b = 2', 'const b = 3')).findings).toEqual([])
  // Edit that adds a new secret.
  const edited = scanEdit('src/config.ts', 'const b = 2', `const b = "${other}"`)
  expect(edited.findings.map((f) => f.ruleId)).toEqual(['github-token'])
  // Lines are relative to the new text.
  expect(edited.findings[0]?.line).toBe(1)
})

test('reports the line of each finding', () => {
  const text = `a\n\nb = "${PROVIDER_TOKENS['npm-token']?.()}"\nc\nd = "${PROVIDER_TOKENS['huggingface-token']?.()}"`
  expect(scanText(text).findings.map((f) => f.line)).toEqual([3, 5])
})

test('.npmrc and .pypirc are only sensitive when they hold a token', () => {
  expect(ids(`//registry.npmjs.org/:_authToken=${random(30)}`, '.npmrc')).toEqual(['npmrc-auth-token'])
  expect(ids('//registry.npmjs.org/:_authToken=${NPM_TOKEN}', '.npmrc')).toEqual([])
  expect(ids('registry=https://registry.npmjs.org/', '.npmrc')).toEqual([])
  expect(ids(`[pypi]\nusername = __token__\npassword = pypi-${random(40)}`, '.pypirc')).toEqual(['pypirc-password'])
})

// --- Paths -----------------------------------------------------------------

test('classifies sensitive paths', () => {
  const sensitive = ['.env', '.env.local', 'apps/web/.env.production', 'prod.env', 'server.pem', 'tls/site.key', 'cert.p12', '/home/u/.ssh/id_rsa', 'id_ed25519', 'credentials.json', 'config/service-account-prod.json', 'terraform.tfstate', 'terraform.tfstate.backup', '.npmrc', '.pypirc', 'C:\\proj\\.env']
  for (const path of sensitive) expect(classifyPath(path)?.kind !== undefined).toBe(true)
  const ordinary = ['.env.example', '.env.sample', 'apps/.env.template', 'id_rsa.pub', 'src/env.ts', 'README.md', 'package.json', 'credentials.ts', 'environment.json', '']
  for (const path of ordinary) expect(classifyPath(path)).toBe(undefined)
  expect(classifyPath('.npmrc')?.requiresToken).toBe(true)
  expect(classifyPath('.env')?.requiresToken).toBe(false)
})

// --- Limits and speed ------------------------------------------------------

test('text over 4 MiB is skipped', () => {
  const result = scanText('a'.repeat(MAX_SCAN_CHARS + 1))
  expect(result.isSkipped).toBe(true)
  expect(result.findings).toEqual([])
  expect(scanText('a'.repeat(MAX_SCAN_CHARS)).isSkipped).toBe(false)
})

test('scans 1 MiB of code quickly and does not blow up on hostile input', () => {
  const line = 'export const handler = async (event, context) => { return { statusCode: 200, body: JSON.stringify({ ok: true, token_count: 12 }) } }\n'
  const code = line.repeat(Math.ceil((1024 * 1024) / line.length))
  const startedAt = performance.now()
  const clean = scanText(code)
  const elapsed = performance.now() - startedAt
  console.log(`scan of ${(code.length / 1024).toFixed(0)} KiB: ${elapsed.toFixed(1)} ms`)
  expect(clean.findings).toEqual([])
  expect(elapsed).toBeLessThan(250)

  // Long runs that nearly match several rules.
  const hostile = [
    `password${'_'.repeat(200000)}`,
    `-----BEGIN RSA PRIVATE KEY-----${'A'.repeat(200000)}`,
    `postgres://${'a'.repeat(100000)}`,
    `${'sk-ant-'.repeat(30000)}`,
    `${'eyJ'.repeat(60000)}`,
    `token = "${' '.repeat(100000)}`,
  ]
  for (const text of hostile) {
    const t0 = performance.now()
    scanText(text)
    expect(performance.now() - t0).toBeLessThan(500)
  }
})
