// Policy: severity × destination × mode → action. Pure: no `$`.

import type { Severity } from './rules.ts'

export type Mode = 'monitor' | 'standard' | 'strict'

/** Pass: let it through. Warn: let it through and tell the user. Hold: ask. Block: deny without asking. */
export type Action = 'pass' | 'warn' | 'hold' | 'block'

/** Where the secret, or the sensitive thing, is about to go. */
export type Destination =
  | 'file' // Write/Edit to a path git does not ignore
  | 'ignored-file' // Write/Edit to a path git ignores, like a .env
  | 'command' // a literal secret inside a Bash command
  | 'sensitive-dump' // cat/head/less of a sensitive file, printenv, env
  | 'git-add' // git add -A or . with unignored sensitive files
  | 'git-commit' // secrets in what is staged
  | 'git-push' // secrets in the commits about to be pushed
  | 'read' // the Read tool on a sensitive file
  | 'config-edit' // Claude editing .leakstop.json
  | 'prompt' // a secret pasted by the user

const ORDER: readonly Action[] = ['pass', 'warn', 'hold', 'block']

/** The stronger of two actions. */
export function maxAction(a: Action, b: Action): Action {
  return ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b
}

/** The action for one finding, or one sensitive operation (pass `'critical'` for those). */
export function decide(destination: Destination, severity: Severity, mode: Mode): Action {
  if (destination === 'ignored-file') return 'pass'
  if (mode === 'monitor') return 'warn'
  if (destination === 'prompt') return 'warn'

  switch (destination) {
    case 'sensitive-dump':
    case 'git-add':
    case 'config-edit':
      return 'hold'
    case 'read':
      return mode === 'strict' ? 'block' : 'hold'
    case 'git-commit':
    case 'git-push':
      if (severity === 'critical') return 'block'
      return mode === 'strict' ? 'block' : 'warn'
    case 'file':
    case 'command':
      if (severity === 'critical') return 'hold'
      return mode === 'strict' ? 'hold' : 'warn'
  }
}

/** The strongest action over several findings; `pass` when there are none. */
export function decideAll(destination: Destination, severities: readonly Severity[], mode: Mode): Action {
  return severities.reduce<Action>((acc, severity) => maxAction(acc, decide(destination, severity, mode)), 'pass')
}
