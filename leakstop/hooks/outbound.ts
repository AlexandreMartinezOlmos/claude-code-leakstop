// What a tool call sends out of the session: to the web, to another agent or
// session, into a published page or to an MCP server. Pure: no `$`, no I/O.
//
// Everything a call carries as text is collected (the model chooses the field
// names of an MCP tool, so there is no list to keep), and the fields that name
// local files whose contents travel with the call are listed apart so the hook
// can read them.

/** The built-in tools that send what they are given to somewhere else. MCP tools are matched by their `mcp__` prefix. */
export const OUTBOUND_TOOLS = ['WebFetch', 'WebSearch', 'Agent', 'SendMessage', 'SendFile', 'Artifact', 'ArtifactData', 'ArtifactComments', 'PushNotification', 'SendFeedback', 'RemoteTrigger'] as const

/** Keys the engine puts beside a tool's own arguments. */
const RESERVED = new Set(['tool', 'tool_use_id', 'agentId'])

const MAX_PARTS = 200
const MAX_DEPTH = 6
const MAX_FILES = 20

/** A piece of text the call carries, and the argument it came from (`prompt`, `batch[0].payload`). */
export type Part = { field: string; text: string }

export type Outbound = {
  texts: Part[]
  /** Local files whose contents the call sends, as the paths it names. */
  files: string[]
  /** More text or more files than are looked at; the rest was not read. */
  isTruncated: boolean
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)

/** Arguments that name files the tool reads and sends. */
function filesNamed(input: Record<string, unknown>): string[] {
  const files: string[] = []
  const add = (value: unknown): void => {
    if (typeof value === 'string' && value !== '') files.push(value)
  }
  const addAll = (value: unknown): void => {
    if (Array.isArray(value)) value.forEach(add)
  }
  switch (input.tool) {
    case 'SendFile':
      addAll(input.files)
      break
    case 'Artifact': {
      add(input.file_path)
      addAll(input.file_paths)
      // `files` is a list of { path } or a map from published path to a source path or { from }.
      if (Array.isArray(input.files)) for (const item of input.files) add(isRecord(item) ? item.path : undefined)
      else if (isRecord(input.files)) for (const source of Object.values(input.files)) add(isRecord(source) ? source.from : source)
      break
    }
    case 'ArtifactData':
      add(input.file_path)
      if (Array.isArray(input.writes)) for (const write of input.writes) add(isRecord(write) ? write.file_path : undefined)
      break
  }
  return [...new Set(files)]
}

/** The text of a call and the files it sends. */
export function collect(input: Record<string, unknown>): Outbound {
  const texts: Part[] = []
  let isTruncated = false
  const walk = (value: unknown, field: string, depth: number): void => {
    if (typeof value === 'string') {
      if (value === '') return
      if (texts.length >= MAX_PARTS) isTruncated = true
      else texts.push({ field, text: value })
    } else if (depth >= MAX_DEPTH) {
      if (value !== null && typeof value === 'object') isTruncated = true
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => walk(item, `${field}[${index}]`, depth + 1))
    } else if (isRecord(value)) {
      for (const [key, item] of Object.entries(value)) walk(item, `${field}.${key}`, depth + 1)
    }
  }
  for (const [key, value] of Object.entries(input)) if (!RESERVED.has(key)) walk(value, key, 0)

  const named = filesNamed(input)
  return { texts, files: named.slice(0, MAX_FILES), isTruncated: isTruncated || named.length > MAX_FILES }
}

/** `mcp__srv__tool` as `MCP srv/tool`; a built-in tool is its own name. */
export function toolLabel(tool: string): string {
  const match = /^mcp__(.+?)__(.+)$/.exec(tool)
  return match === null ? tool : `MCP ${match[1]}/${match[2]}`
}

/** True for a tool whose arguments LeakStop reads as outbound. */
export const isOutbound = (tool: string): boolean => tool.startsWith('mcp__') || (OUTBOUND_TOOLS as readonly string[]).includes(tool)

/** Where what the call carries ends up, in words. */
export function destinationOf(tool: string): string {
  switch (tool) {
    case 'WebFetch':
      return 'to the web server it fetches, which can log it'
    case 'WebSearch':
      return 'to a search engine'
    case 'Agent':
      return "into another agent's context"
    case 'SendMessage':
      return 'to another agent or session'
    case 'SendFile':
      return 'to another session'
    case 'Artifact':
    case 'ArtifactData':
    case 'ArtifactComments':
      return 'into a page or database on claude.ai that other people may open'
    case 'PushNotification':
      return "to the user's phone through a push service"
    case 'SendFeedback':
      return 'to Anthropic'
    case 'RemoteTrigger':
      return 'to a remote trigger'
    default:
      return tool.startsWith('mcp__') ? `to the MCP server ${/^mcp__(.+?)__/.exec(tool)?.[1] ?? ''}` : 'outside the session'
  }
}
