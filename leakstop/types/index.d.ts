// The contract of LeakStop's `$.state` values. Values only ever hold what is
// safe to keep: types, locations and fingerprints, never a secret.

export type Decision = 'allowed' | 'denied' | 'warned' | 'passed'

export type StoredFinding = {
  /** `sha256:` and 16 hex characters. */
  fingerprint: string
  ruleId: string
  /** What the user reads, "Anthropic API key". */
  label: string
  severity: 'critical' | 'medium'
  path: string
  line: number
  tool: string
  decision: Decision
  /** Milliseconds since the epoch. */
  at: number
}

declare module 'claude-code' {
  interface PluginState {
    leakstop: {
      /** The session's findings, newest last, bounded. */
      findings: StoredFinding[]
      /** Fingerprints the user allowed for this session only. */
      allowOnce: string[]
      /** Set by `/leakstop pause`. */
      paused: boolean
      /** Warnings the user has not seen yet; cleared by the next prompt or by `/leakstop`. */
      banner: StoredFinding[]
    }
  }
}
