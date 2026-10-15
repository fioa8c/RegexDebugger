export interface YaraOptions {
  i: boolean
  s: boolean
  nocase: boolean
  wide: boolean
  ascii: boolean
  fullword: boolean
}

export const DEFAULT_YARA_OPTIONS: YaraOptions = {
  i: false,
  s: false,
  nocase: false,
  wide: false,
  ascii: false,
  fullword: false,
}

export interface DiagLabel {
  text: string
  start: number | null
  end: number | null
}

export interface Diag {
  severity: 'error' | 'warning'
  code: string
  title: string
  labels: DiagLabel[]
  notes: string[]
}

export interface YaraMatch {
  offset: number
  length: number
}

export interface EngineResult {
  matches: YaraMatch[]
  errors: Diag[]
  warnings: Diag[]
}

interface ScanPattern {
  matches: YaraMatch[]
}

interface ScanResult {
  matches: { patterns: ScanPattern[] }[]
}

export interface YaraModule {
  Compiler: new () => {
    addSource(source: string): void
    build(): { scanner(): YaraScanner; free(): void }
    readonly warnings: string[]
    free(): void
  }
}

interface YaraScanner {
  setMaxMatchesPerPattern(n: number): void
  scan(payload: Uint8Array): ScanResult
  free(): void
}

export const RULE_PREFIX = 'rule t { strings: $a = /'
const GUTTER = 4
const MAX_MATCHES = 10_000

export function buildRuleSource(pattern: string, opts: YaraOptions): string {
  const suffix = (opts.i ? 'i' : '') + (opts.s ? 's' : '')
  const mods = (['nocase', 'wide', 'ascii', 'fullword'] as const)
    .filter((m) => opts[m])
    .map((m) => ' ' + m)
    .join('')
  return `${RULE_PREFIX}${pattern}/${suffix}${mods} condition: $a }`
}

const WIDE =
  /[\u1100-\u115F\u2E80-\u303E\u3041-\u33FF\u3400-\u4DBF\u4E00-\u9FFF\uA000-\uA4CF\uAC00-\uD7A3\uF900-\uFAFF\uFE30-\uFE4F\uFF00-\uFF60\uFFE0-\uFFE6\u{20000}-\u{3FFFD}]|\p{Emoji_Presentation}/u
const ZERO_WIDTH = /[\p{Mn}\p{Me}\p{Cf}]/u

function charWidth(ch: string): number {
  if (ZERO_WIDTH.test(ch)) return 0
  return WIDE.test(ch) ? 2 : 1
}

function columnIndex(line: string, col: number): number {
  let width = 0
  let index = 0
  for (const ch of line) {
    const w = charWidth(ch)
    if (width >= col && w > 0) break
    width += w
    index += ch.length
  }
  return index
}

function patternRange(
  line: string,
  col: number,
  len: number,
  patternLen: number,
): [number, number] | null {
  const start = Math.max(columnIndex(line, col) - RULE_PREFIX.length, 0)
  const end = Math.min(columnIndex(line, col + len) - RULE_PREFIX.length, patternLen)
  return start < end ? [start, end] : null
}

export function parseDiag(text: string, patternLen: number): Diag {
  const lines = text.split('\n')
  const head = /^(error|warning)\[([^\]]+)\]: (.*)$/.exec(lines[0])
  const diag: Diag = {
    severity: head?.[1] === 'warning' ? 'warning' : 'error',
    code: head?.[2] ?? '',
    title: head?.[3] ?? lines[0],
    labels: [],
    notes: [],
  }
  const src = lines.findIndex((l) => /^\d+ \| /.test(l))
  const runs: { col: number; len: number; text: string | null }[] = []
  if (src >= 0 && src + 1 < lines.length) {
    const marks = lines[src + 1].slice(GUTTER)
    const lead = /^[ ^-]*/.exec(marks)?.[0] ?? ''
    for (const m of lead.matchAll(/[\^-]+/g)) {
      runs.push({ col: m.index, len: m[0].length, text: null })
    }
    const after = marks.slice(lead.length).trim()
    if (runs.length && after) runs[runs.length - 1].text = after
    for (const line of lines.slice(src + 2)) {
      if (!line.startsWith('  |')) continue
      const body = line.slice(GUTTER)
      const col = body.search(/\S/)
      if (col < 0 || body[col] === '|') continue
      const text = body.slice(col).trim()
      const open = runs.find((r) => r.col === col && r.text === null)
      const taken = runs.findIndex((r) => r.col === col)
      if (open) open.text = text
      else if (taken >= 0) runs.splice(taken + 1, 0, { ...runs[taken], text })
    }
  }
  const source = src >= 0 ? lines[src].slice(GUTTER) : ''
  for (const r of runs) {
    const range = patternRange(source, r.col, r.len, patternLen)
    diag.labels.push({ text: r.text ?? '', start: range?.[0] ?? null, end: range?.[1] ?? null })
  }
  for (const line of lines) {
    const note = /^\s*= (?:note|help): (.*)$/.exec(line)
    if (note) diag.notes.push(note[1])
  }
  return diag
}

const LOCAL_CODES = new Set(['input', 'crash', 'unsupported'])

export function formatDiag(d: Diag): string {
  const head = LOCAL_CODES.has(d.code) ? d.title : `${d.code}: ${d.title}`
  const labels = d.labels.map((l) => l.text).filter(Boolean)
  const line = labels.length ? `${head} — ${labels.join('; ')}` : head
  return [line, ...d.notes.map((n) => `note: ${n}`)].join('\n')
}

export function hasUnescapedSlash(pattern: string): boolean {
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === '\\') i++
    else if (pattern[i] === '/') return true
  }
  return false
}

export function knownCrash(pattern: string): string | null {
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === '\\') {
      if (/^b\{(start|end)-half\}/.test(pattern.slice(i + 1))) return '`\\b{start-half}` and `\\b{end-half}`'
      i++
    } else if (pattern[i] === '[') {
      let k = i + 1
      if (pattern[k] === '^') k++
      if (pattern[k] === ']') k++
      while (k < pattern.length && pattern[k] !== ']') k += pattern[k] === '\\' ? 2 : 1
      i = k
    } else if (pattern.startsWith('(?', i)) {
      const flags = /^\(\?([a-zA-Z]*)/.exec(pattern.slice(i))?.[1] ?? ''
      if (flags.includes('u')) return 'Unicode mode `(?u)`'
    }
  }
  return null
}

const SLASH_NOTE = 'Yara-X ends the regex at an unescaped `/`; write it as `\\/`'

function crashed(e: unknown): EngineResult {
  const text = e instanceof Error ? e.message : String(e)
  return localError(
    'crash',
    `the Yara-X engine crashed on this pattern (${text}). ` +
      'Each crash leaks engine memory; reload the page if valid patterns start failing',
  )
}

function localError(code: string, title: string): EngineResult {
  return {
    matches: [],
    errors: [{ severity: 'error', code, title, labels: [], notes: [] }],
    warnings: [],
  }
}

export function runYara(
  mod: YaraModule,
  pattern: string,
  opts: YaraOptions,
  input: string,
): EngineResult {
  if (!pattern) return { matches: [], errors: [], warnings: [] }
  if (/[\r\n]/.test(pattern)) {
    return localError('input', 'a Yara-X regex must be on a single line')
  }
  if (hasUnescapedSlash(pattern)) return localError('input', SLASH_NOTE)
  const crasher = knownCrash(pattern)
  if (crasher) {
    return localError(
      'unsupported',
      `${crasher} crashes Yara-X 1.21.0, so this tester doesn't send it to the engine`,
    )
  }
  const compiler = new mod.Compiler()
  try {
    compiler.addSource(buildRuleSource(pattern, opts))
  } catch (e) {
    const text = e instanceof Error ? e.message : String(e)
    if (!/^error\[/.test(text)) return crashed(e)
    compiler.free()
    return { matches: [], errors: [parseDiag(text, pattern.length)], warnings: [] }
  }
  const owned: { free(): void }[] = [compiler]
  try {
    const warnings = compiler.warnings.map((w) => parseDiag(w, pattern.length))
    const rules = compiler.build()
    owned.push(rules)
    const scanner = rules.scanner()
    owned.push(scanner)
    scanner.setMaxMatchesPerPattern(MAX_MATCHES)
    const result = scanner.scan(new TextEncoder().encode(input))
    const matches = result.matches
      .flatMap((r) => r.patterns)
      .flatMap((p) => p.matches)
      .map(({ offset, length }) => ({ offset, length }))
      .sort((a, b) => a.offset - b.offset || a.length - b.length)
    return { matches, errors: [], warnings }
  } catch (e) {
    return crashed(e)
  } finally {
    for (const o of owned.reverse()) {
      try {
        o.free()
      } catch {
        // an object the crash left unusable can't be freed; skip it
      }
    }
  }
}

let loading: Promise<YaraModule> | null = null
let loaded: YaraModule | null = null

export function loadedEngine(): YaraModule | null {
  return loaded
}

export function loadEngine(): Promise<YaraModule> {
  if (!loading) {
    loading = import('@virustotal/yara-x').then(async (mod) => {
      await mod.default()
      loaded = mod as unknown as YaraModule
      return loaded
    })
    loading.catch(() => {
      loading = null
    })
  }
  return loading
}
