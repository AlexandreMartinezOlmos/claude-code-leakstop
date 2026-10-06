// Runs the mod's tests. They live in tests/ at the root of the repository, outside the
// plugin folder, so that the people who install LeakStop do not get them; `claude plugin
// test` only looks inside a mod's folder, so they are run beside a temporary copy of it.
//
//   node scripts/test.ts

import { spawnSync } from 'node:child_process'
import { cpSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = join(import.meta.dirname, '..')
const dir = mkdtempSync(join(tmpdir(), 'leakstop-test-'))
try {
  const plugin = join(dir, 'leakstop')
  cpSync(join(root, 'leakstop'), plugin, { recursive: true })
  cpSync(join(root, 'tests'), join(plugin, 'tests'), { recursive: true })
  const run = spawnSync('claude', ['plugin', 'test'], { cwd: plugin, stdio: 'inherit' })
  process.exitCode = run.status ?? 1
} finally {
  rmSync(dir, { recursive: true, force: true })
}
