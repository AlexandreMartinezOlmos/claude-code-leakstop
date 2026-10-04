// Checks that the pieces of a release agree with each other, so a release cannot
// go out with a version in one place and another version somewhere else.
//
//   node scripts/check-release.ts
//
// Exit code 1 and one line per problem when something disagrees.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const read = (path: string): string => readFileSync(`${root}${path}`, 'utf8')

const plugin = JSON.parse(read('leakstop/.claude-plugin/plugin.json')) as { version: string; description: string; homepage: string; repository: string }
const marketplace = JSON.parse(read('.claude-plugin/marketplace.json')) as { plugins: { name: string; description: string }[] }
const changelog = read('CHANGELOG.md')

const problems: string[] = []

const latest = /^## (\d+\.\d+\.\d+)\b/m.exec(changelog)?.[1]
if (latest === undefined) problems.push('CHANGELOG.md has no "## x.y.z" heading')
else if (latest !== plugin.version) problems.push(`plugin.json is ${plugin.version} but the newest CHANGELOG.md heading is ${latest}`)

if (!new RegExp(`^\\[${plugin.version.replaceAll('.', '\\.')}\\]: `, 'm').test(changelog)) problems.push(`CHANGELOG.md has no link for ${plugin.version} at the bottom`)

const listed = marketplace.plugins.find((entry) => entry.name === 'leakstop')
if (listed === undefined) problems.push('marketplace.json does not list leakstop')
else if (listed.description !== plugin.description) problems.push('the marketplace description differs from the one in plugin.json')

if (read('LICENSE') !== read('leakstop/LICENSE')) problems.push('leakstop/LICENSE differs from LICENSE (the installed plugin ships its own copy)')

const readme = read('README.md')
const minimum = /Claude Code (\d+\.\d+\.\d+) or later/.exec(readme)?.[1]
if (minimum === undefined) problems.push('README.md does not state the minimum Claude Code version')
else if (!changelog.includes(`Requires Claude Code ${minimum} or later`)) problems.push(`CHANGELOG.md never says "Requires Claude Code ${minimum} or later" (the README minimum)`)

for (const line of problems) console.error(`✘ ${line}`)
if (problems.length > 0) process.exit(1)
console.log(`✔ release ${plugin.version} is consistent`)
