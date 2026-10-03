import { expect, test } from 'claude-code/testing'
import { collect, destinationOf, isLikelyBinary, isOutbound, toolLabel } from '../hooks/outbound.ts'

test('collects every string a call carries, beside the reserved keys', () => {
  const out = collect({ tool: 'Agent', tool_use_id: 'toolu_1', agentId: 'a1', description: 'do it', prompt: 'hello', run_in_background: true, n: 3 })
  expect(out.texts).toEqual([
    { field: 'description', text: 'do it' },
    { field: 'prompt', text: 'hello' },
  ])
  expect(out.files).toEqual([])
  expect(out.isTruncated).toBe(false)
})

test('reaches into nested arguments and names where each text is', () => {
  const out = collect({ tool: 'mcp__docs__batch', batch: [{ op: 'set', payload: { text: 'a' } }, 'b'], container: { id: 'c' }, empty: '' })
  expect(out.texts.map((t) => t.field)).toEqual(['batch[0].op', 'batch[0].payload.text', 'batch[1]', 'container.id'])
})

test('past the depth limit the subtree is scanned as serialized text, and nothing is lost', () => {
  const deep = { tool: 'mcp__a__b', x: { a: { b: { c: { d: { e: { f: { g: 'too deep' } } } } } } } }
  expect(collect(deep)).toEqual({ texts: [{ field: 'x.a.b.c.d.e.f', text: '{"g":"too deep"}' }], files: [], isTruncated: false })
})

test('past 200 texts the rest is folded into one block that is still scanned', () => {
  const wide = { tool: 'mcp__a__b', items: Array.from({ length: 250 }, (_, i) => `item ${i}`) }
  const out = collect(wide)
  expect(out.texts.length).toBe(201)
  expect(out.texts[200]?.field).toBe('(further arguments)')
  expect(out.texts[200]?.text.split('\n')).toEqual(Array.from({ length: 50 }, (_, i) => `item ${200 + i}`))
  expect(out.isTruncated).toBe(false)
})

test('only text beyond the overflow cap is dropped, and that is reported', () => {
  const big = 'x'.repeat(600 * 1024)
  const out = collect({ tool: 'mcp__a__b', items: [...Array.from({ length: 200 }, () => 'a'), big, big, big] })
  expect(out.texts.length).toBe(201)
  expect(out.isTruncated).toBe(true)
})

test('long argument names are scanned as text, short ones are not', () => {
  const out = collect({ tool: 'mcp__a__b', map: { short: 'v', 'a-rather-long-argument-name': 'w' } })
  expect(out.texts.map((t) => t.field)).toEqual(['map (names)', 'map.short', 'map.a-rather-long-argument-name'])
  expect(out.texts[0]?.text).toBe('a-rather-long-argument-name')
})

test('lists the files a call sends', () => {
  expect(collect({ tool: 'SendFile', to: 'peer', files: ['a.txt', 'b.txt', 'a.txt'] }).files).toEqual(['a.txt', 'b.txt'])
  expect(collect({ tool: 'Artifact', file_path: 'page.html', file_paths: ['x.png'], files: [{ path: 'app.js' }] }).files).toEqual(['page.html', 'x.png', 'app.js'])
  expect(collect({ tool: 'Artifact', files: { 'data.json': 'src/data.json', 'logo.png': { from: 'img/logo.png' }, 'gone.css': null } }).files).toEqual(['src/data.json', 'img/logo.png'])
  expect(collect({ tool: 'ArtifactData', action: 'batch', writes: [{ op: 'set', file_path: 'doc.json' }, { op: 'delete' }] }).files).toEqual(['doc.json'])
  // Only the tools that read a local file and send it have files.
  expect(collect({ tool: 'WebFetch', url: 'https://example.com', files: ['a'] }).files).toEqual([])
  const many = collect({ tool: 'SendFile', to: 'p', files: Array.from({ length: 300 }, (_, i) => `f${i}`) })
  expect(many.files.length).toBe(200)
  expect(many.isTruncated).toBe(true)
})

test('names tools and destinations', () => {
  expect(toolLabel('WebFetch')).toBe('WebFetch')
  expect(toolLabel('mcp__claude_ai_Claude_Docs__batch')).toBe('MCP claude_ai_Claude_Docs/batch')
  expect(toolLabel('mcp__srv__do__thing')).toBe('MCP srv/do__thing')
  expect(isOutbound('Agent')).toBe(true)
  expect(isOutbound('mcp__a__b')).toBe(true)
  for (const tool of ['Bash', 'Read', 'Write', 'SendUserFile', 'SendUserMessage']) expect(isOutbound(tool)).toBe(false)
  expect(destinationOf('WebFetch').includes('web server')).toBe(true)
  expect(destinationOf('mcp__github__create_issue')).toBe('to the MCP server github')
})

test('recognises files that cannot hold a readable secret', () => {
  for (const path of ['logo.PNG', 'fonts/a.woff2', 'doc.pdf', 'bundle.zip', 'a/b/c.wasm']) expect(isLikelyBinary(path)).toBe(true)
  for (const path of ['page.html', 'data.json', '.env', 'server.pem', 'notes.txt', 'png']) expect(isLikelyBinary(path)).toBe(false)
})
