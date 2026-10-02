// The pattern catalog: data only, no `$` and no side effects.
//
// Every regex here is linear: quantifiers are bounded or run over a character
// class that cannot also match the next token, so a hostile input cannot make
// a scan blow up. A hook that runs out of time is skipped by Claude Code and
// the call would go on, so a slow regex is a security bug.

export type Severity = 'critical' | 'medium'

export type Rule = {
  id: string
  /** What the user reads: "Anthropic API key". */
  label: string
  severity: Severity
  /** Global regex. */
  regex: RegExp
  /** The capture groups that can hold the secret; the first one that matched wins. Absent: the whole match. */
  groups?: readonly number[]
  /** Fixed identifying prefix, the only part of the value masking may show. */
  prefix?: string
  /** Shannon entropy (bits per character) the value must reach. */
  minEntropy?: number
  /** Heuristic rule: false-positive exclusions apply and a provider finding on the same text wins. */
  isGeneric?: boolean
  /** A last, rule-specific check on the value. */
  accept?: (value: string, match: RegExpMatchArray) => boolean
}

const base64Length = (text: string): number => text.replace(/[^A-Za-z0-9+/=]/g, '').length

/** A private key header with a real body; a header alone is documentation or a regex. */
const hasKeyBody = (value: string): boolean =>
  base64Length(value.replace(/-----(?:BEGIN|END)[^-]*-----/g, '')) >= 40

export const RULES: readonly Rule[] = [
  {
    id: 'private-key',
    label: 'Private key',
    severity: 'critical',
    regex: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,16384}?(?:-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----|$)/g,
    accept: hasKeyBody,
  },
  {
    id: 'aws-access-key',
    label: 'AWS access key ID',
    severity: 'critical',
    regex: /\b(?:AKIA|ASIA)[A-Z2-7]{16}\b/g,
    prefix: 'AKIA',
  },
  {
    id: 'github-token',
    label: 'GitHub token',
    severity: 'critical',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    prefix: 'ghp_',
  },
  {
    id: 'github-fine-grained-token',
    label: 'GitHub fine-grained token',
    severity: 'critical',
    regex: /\bgithub_pat_[A-Za-z0-9_]{36,255}\b/g,
    prefix: 'github_pat_',
  },
  {
    id: 'gitlab-token',
    label: 'GitLab token',
    severity: 'critical',
    regex: /\bglpat-[A-Za-z0-9_-]{20,}/g,
    prefix: 'glpat-',
  },
  {
    id: 'anthropic-key',
    label: 'Anthropic API key',
    severity: 'critical',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
    prefix: 'sk-ant-',
  },
  {
    id: 'openai-key',
    label: 'OpenAI API key',
    severity: 'critical',
    regex: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}/g,
    prefix: 'sk-proj-',
  },
  {
    id: 'stripe-live-key',
    label: 'Stripe live key',
    severity: 'critical',
    regex: /\b[sr]k_live_[A-Za-z0-9]{16,}/g,
    prefix: 'sk_live_',
  },
  {
    id: 'stripe-test-key',
    label: 'Stripe test key',
    severity: 'medium',
    regex: /\b[sr]k_test_[A-Za-z0-9]{16,}/g,
    prefix: 'sk_test_',
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    severity: 'critical',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
    prefix: 'xoxb-',
  },
  {
    id: 'google-api-key',
    label: 'Google API key',
    severity: 'critical',
    regex: /\bAIza[0-9A-Za-z_-]{35}/g,
    prefix: 'AIza',
  },
  {
    id: 'npm-token',
    label: 'npm token',
    severity: 'critical',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    prefix: 'npm_',
  },
  {
    id: 'huggingface-token',
    label: 'Hugging Face token',
    severity: 'critical',
    regex: /\bhf_[A-Za-z0-9]{34,}/g,
    prefix: 'hf_',
  },
  {
    // scheme://user:password@host. The secret is the password (group 2).
    id: 'url-credentials',
    label: 'Credentials in a URL',
    severity: 'critical',
    regex: /\b[a-z][a-z0-9+.-]{1,20}:\/\/([^\s:@/'"<>]{0,100}):([^\s@/'"<>]{3,200})@[^\s'"<>/]{1,255}/gi,
    groups: [2],
    // `postgres://postgres:postgres@localhost` is a local default, not a secret.
    accept: (_value, match) => (match[1] ?? '').toLowerCase() !== (match[2] ?? '').toLowerCase(),
  },
  {
    id: 'jwt',
    label: 'JSON Web Token',
    severity: 'medium',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    prefix: 'eyJ',
  },
  {
    // curl -H "Authorization: Bearer <literal>". A variable (`$TOKEN`) never matches.
    id: 'authorization-header',
    label: 'Authorization header credential',
    severity: 'critical',
    regex: /\bAuthorization["']?\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{20,})/gi,
    groups: [1],
    minEntropy: 3,
  },
  {
    // A suspicious key name, a separator and a high-entropy value. The value is
    // quoted (groups 1 and 2) or bare (group 3, which must also contain a digit
    // so identifiers such as `getApiKeyFromConfig` do not count).
    id: 'generic-assignment',
    label: 'Hard-coded credential',
    severity: 'medium',
    regex:
      /(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|token)[A-Za-z0-9_-]{0,20}["']?\s*[:=]>?\s*(?:"([^"\s]{16,200})"|'([^'\s]{16,200})'|([A-Za-z0-9_+/=.-]{20,200}))/gi,
    groups: [1, 2, 3],
    minEntropy: 3.5,
    isGeneric: true,
    accept: (value, match) => match[3] === undefined || /\d/.test(value),
  },
]

/** Rules that only make sense for one kind of file. */
export const NPMRC_RULES: readonly Rule[] = [
  {
    id: 'npmrc-auth-token',
    label: 'npm registry auth token',
    severity: 'critical',
    regex: /_authToken\s*=\s*([^\s$]{8,})/g,
    groups: [1],
  },
]

export const PYPIRC_RULES: readonly Rule[] = [
  {
    id: 'pypirc-password',
    label: 'PyPI password or token',
    severity: 'critical',
    regex: /^[ \t]*password[ \t]*[:=][ \t]*([^\s$]{6,})/gim,
    groups: [1],
  },
]
