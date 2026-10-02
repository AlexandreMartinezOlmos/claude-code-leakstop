// Masking and fingerprints. Pure: no `$`.
//
// This is the only place a Finding's `value` is read. What leaves it is a
// MaskedFinding: the type, the location, a masked preview and a fingerprint.
// That is all `$.state`, `$.store`, the interface and the messages to Claude
// may ever hold.

import type { Finding } from './detect.ts'

export type MaskedFinding = Omit<Finding, 'value' | 'start' | 'end'> & {
  /** `sk-ant-••••••3fA`, or `••••••` when the value has no safe part to show. */
  masked: string
  /** `sha256:` and 16 hex characters of the value's SHA-256. */
  fingerprint: string
}

const DOTS = '••••••'
/** Below this many characters after the prefix, the tail would give too much away. */
const MIN_TAIL_BODY = 16

/**
 * Identifying prefix and the last three characters. A value with no known
 * prefix shows nothing: the type already says what it is.
 */
export function mask(value: string, prefix?: string): string {
  if (prefix === undefined || !value.startsWith(prefix)) return DOTS
  const body = value.length - prefix.length
  return body >= MIN_TAIL_BODY ? `${prefix}${DOTS}${value.slice(-3)}` : `${prefix}${DOTS}`
}

/** `sha256:` plus the first 8 bytes of the digest, in hex. */
export async function fingerprint(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  const hex = Array.from(new Uint8Array(digest).slice(0, 8), (byte) => byte.toString(16).padStart(2, '0')).join('')
  return `sha256:${hex}`
}

/** The finding without its value: the only form that may be kept or shown. */
export async function describe(finding: Finding): Promise<MaskedFinding> {
  const { value, start: _start, end: _end, ...rest } = finding
  return { ...rest, masked: mask(value, finding.prefix), fingerprint: await fingerprint(value) }
}
