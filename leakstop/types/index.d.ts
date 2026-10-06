// The contract of LeakStop's `$.state` values. Values only ever hold what is
// safe to keep: types, locations and fingerprints, never a secret.

export type Decision = 'allowed' | 'denied' | 'warned' | 'passed' | 'masked'

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

/** A custom rule from `.leakstop.json`, validated and ready to compile. */
export type StoredRule = {
  /** `custom:` and the id the user gave it. */
  id: string
  label: string
  severity: 'critical' | 'medium'
  /** The regular expression source. */
  source: string
  prefix?: string
  groups?: number[]
  minEntropy?: number
}

/** `.leakstop.json` after validation. */
export type StoredConfig = {
  /** Globs where medium findings do not warn. Critical findings are still held. */
  ignorePaths: string[]
  /** `sha256:` fingerprints the project allows for the whole team. */
  allowFingerprints: string[]
  customRules: StoredRule[]
  /** What was wrong with the file, in words; empty when it is fine. */
  warnings: string[]
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
      /** The project's `.leakstop.json`, read at session start. */
      config: StoredConfig
    }
  }
}
