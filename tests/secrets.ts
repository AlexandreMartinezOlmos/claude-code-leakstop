// Fake secrets for tests, generated at runtime: a known prefix plus random
// characters. Nothing here is a real credential, and no complete token is ever
// written in the repository (GitHub push protection and public scanners would
// flag it).

export const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
export const URLSAFE = `${ALNUM}_-`
export const BASE64 = `${ALNUM}+/`
export const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const HEX = '0123456789abcdef'

export function random(length: number, alphabet: string = ALNUM): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length))
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join('')
}

const base64url = (text: string): string => btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

/** A fake token for each provider rule, keyed by rule id. */
export const PROVIDER_TOKENS: Record<string, () => string> = {
  'aws-access-key': () => `AKIA${random(16, BASE32)}`,
  'github-token': () => `ghp_${random(36)}`,
  'github-fine-grained-token': () => `github_pat_${random(60, `${ALNUM}_`)}`,
  'gitlab-token': () => `glpat-${random(24, URLSAFE)}`,
  'anthropic-key': () => `sk-ant-api03-${random(40, URLSAFE)}`,
  'openai-key': () => `sk-proj-${random(48, URLSAFE)}`,
  'stripe-live-key': () => `sk_live_${random(24)}`,
  'slack-token': () => `xoxb-${random(12, '0123456789')}-${random(24)}`,
  'google-api-key': () => `AIza${random(35, URLSAFE)}`,
  'npm-token': () => `npm_${random(36)}`,
  'huggingface-token': () => `hf_${random(34)}`,
}

export function fakeJwt(): string {
  return [base64url('{"alg":"HS256","typ":"JWT"}'), base64url(`{"sub":"${random(12)}"}`), random(43, URLSAFE)].join('.')
}

export function fakePrivateKey(): string {
  const body = Array.from({ length: 4 }, () => random(64, BASE64)).join('\n')
  return `-----BEGIN ${'RSA'} PRIVATE KEY-----\n${body}\n-----END ${'RSA'} PRIVATE KEY-----`
}
