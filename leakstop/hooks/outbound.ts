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
/** Text past MAX_PARTS is scanned as one block, up to this many characters. */
const MAX_OVERFLOW = 1024 * 1024
const MAX_DEPTH = 6
/** Files whose paths are checked; only the first MAX_READ of them are opened. */
const MAX_FILES = 200
export const MAX_READ = 20
/** Keys shorter than this cannot be a provider token by themselves. */
const MIN_KEY = 16

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

/** The text of a call and the files it sends. Nothing is dropped: past the limits the rest is folded into one block. */
export function collect(input: Record<string, unknown>): Outbound {
  const texts: Part[] = []
  let overflow = ''
  let isTruncated = false
  const add = (field: string, text: string): void => {
    if (texts.length < MAX_PARTS) {
      texts.push({ field, text })
    } else if (overflow.length + text.length + 1 <= MAX_OVERFLOW) {
      overflow += overflow === '' ? text : `\n${text}`
    } else {
      isTruncated = true
    }
  }
  const walk = (value: unknown, field: string, depth: number): void => {
    if (typeof value === 'string') {
      if (value !== '') add(field, value)
    } else if (value === null || typeof value !== 'object') {
      return
    } else if (depth >= MAX_DEPTH) {
      // Too deep to follow: its text is scanned as it is serialized.
      try {
        add(field, JSON.stringify(value))
      } catch {
        isTruncated = true
      }
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => walk(item, `${field}[${index}]`, depth + 1))
    } else {
      // A key can hold a secret too (a map keyed by token), so the long ones are scanned, as one block.
      const keys = Object.keys(value).filter((key) => key.length >= MIN_KEY)
      if (keys.length > 0) add(`${field} (names)`, keys.join('\n'))
      for (const [key, item] of Object.entries(value)) walk(item, `${field}.${key}`, depth + 1)
    }
  }
  for (const [key, value] of Object.entries(input)) if (!RESERVED.has(key)) walk(value, key, 0)
  if (overflow !== '') texts.push({ field: '(further arguments)', text: overflow })

  const named = filesNamed(input)
  return { texts, files: named.slice(0, MAX_FILES), isTruncated: isTruncated || named.length > MAX_FILES }
}

/** Files that cannot hold a readable secret: reading them as text only costs time. */
export const isLikelyBinary = (path: string): boolean => /\.(?:png|jpe?g|gif|webp|avif|ico|bmp|tiff?|pdf|woff2?|ttf|otf|eot|mp[34]|m4a|mov|webm|wav|ogg|zip|gz|tgz|bz2|xz|7z|rar|wasm|bin|exe|dylib|so|class|jar|sqlite3?)$/i.test(path)

const MCP_NAME = /^mcp__(.+?)__(.+)$/

/** `mcp__srv__tool` as `MCP srv/tool`; a built-in tool is its own name. */
export function toolLabel(tool: string): string {
  const match = MCP_NAME.exec(tool)
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
      return MCP_NAME.test(tool) ? `to the MCP server ${MCP_NAME.exec(tool)?.[1] ?? ''}` : 'outside the session'
  }
}
