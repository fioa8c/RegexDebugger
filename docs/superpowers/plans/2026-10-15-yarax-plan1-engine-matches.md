# Yara-X Flavor — Plan 1: Engine and Matches

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Yara-X flavor that runs the real Yara-X engine in the browser. It shows matches as byte offset and length, and the engine's own errors and warnings. It also fixes the existing layout bug that hides the flag bar.

**Architecture:**
- **Flavor switch:** `App.tsx` gains a flavor switch plus separate Yara-X state (pattern, options, sample). The JavaScript UI is unchanged.
- **Engine:** `src/lib/yarax/engine.ts` lazily loads the official `@virustotal/yara-x` WebAssembly package. It wraps the pattern in a one-string rule, compiles, scans the UTF-8 bytes of the sample, and parses the engine's formatted diagnostics.
- **Byte mapping:** `src/lib/yarax/bytes.ts` maps byte offsets back to string indices for highlighting.
- **UI:** new components in `src/components/yarax/` render the Yara-X pattern bar, the input and the Matches tab.

**Tech Stack:** React 19, Vite 8, TypeScript 6, Vitest 5 (node environment), `@virustotal/yara-x` 1.21.0 (wasm-bindgen `--target web`).

**Spec:** `docs/superpowers/specs/2026-10-15-yarax-flavor-design.md`. The file is **local only**: the user's global git ignore excludes `docs/superpowers/specs`, so it is never committed. Every fact a task needs is copied into that task.

This is **Plan 1 of 3** for the spec:
- **Plan 2** adds `parse.ts`, syntax coloring and the Structure breakdown.
- **Plan 3** adds atoms, scan cost, the grade, suggestions and the Analysis tab.

Plans 2 and 3 will be written after this plan lands.

**Deliberate departures from the spec**, decided while writing this plan:
- **Engine behavior is pinned with direct tests against the real engine** instead of a recorded `engine.json` fixture. The package loads under Node with `initSync`, so the tests run the engine itself.
- **The "escape `/` as `\/`" hint is in `engine.ts`, not `parse.ts`.** An unescaped `/` makes the engine fail with `E001` and no position, so the hint is needed before the parser exists.
- **The grid layout fix is included (Task 1).** It's a bug that predates this work, but it hides the flag bar that Yara-X mode needs.

## Global Constraints

- **Dependency:** pin `@virustotal/yara-x` exactly: `npm i --save-exact @virustotal/yara-x@1.21.0`. No other new dependencies.
- **JavaScript flavor:** behavior is unchanged, and the existing 51 tests stay green and unmodified.
- **Loading the package:** only `loadEngine()` in `src/lib/yarax/engine.ts` imports it, through a dynamic `import()`. Tests may import it statically to call `initSync`. No other file imports it.
- **WebAssembly URL:** do not add Vite config or copy the `.wasm` by hand. Vite 8 already rewrites the package's `new URL('yara_x_js_bg.wasm', import.meta.url)`:
  - **dev:** to `/node_modules/@virustotal/yara-x/pkg/yara_x_js_bg.wasm`
  - **build:** to `<base>/assets/yara_x_js_bg-<hash>.wasm`

  Both were verified to serve `application/wasm` (5,962,317 bytes).
- **Rule source:** the pattern is wrapped with the exact prefix `rule t { strings: $a = /`. The suffix is `/<i><s>`, modifiers follow in the order `nocase wide ascii fullword`, then ` condition: $a }`. Engine diagnostic columns are 1-based positions on that single line, after a 4-character gutter (`1 | `).
- **Limits:** max matches per pattern is 10,000, the same as the JavaScript flavor. The engine debounce is 150 ms.
- **Compiler objects after a throw:**
  - If `addSource` throws text that does **not** start with `error[`, the engine panicked (for example `\b{start-half}` throws `unreachable`). Never touch that `Compiler` again, not even `.free()` or `.errors`, because it throws `recursive use of an object detected…`. A fresh `new Compiler()` works.
  - On a normal error, the thrown message equals `errors[0]`.
  - On success, read `compiler.warnings` only, since `rules.warnings` and the scan result's warnings are duplicates.
- **Lint:** no new lint warnings beyond the 2 existing `react(purity)` warnings in `src/App.tsx`. `performance.now()` may only run inside effects or callbacks.
- **Style:** no semicolons, single quotes, 2-space indent, trailing commas in multi-line literals.
- **Before each commit:** run `npx tsc -b`, then `npx oxlint`, then `npx vitest run`.
- **Commit messages:** end every one with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A pattern with an unescaped `/`** (`a/b`). The engine reports `E001 syntax error — unclosed regular expression` with no position in the pattern. The tester should add the note "Yara-X ends the regex at an unescaped `/`; write it as `\/`", and `a\/b` should match. Pinned in Task 2.
2. **Sample text with multibyte characters before or inside a match** (`é`, `€`, emoji). Engine offsets are UTF-8 bytes, so highlights must land on the right characters, and a match boundary inside a character must widen to the whole character. Pinned in Tasks 2 (`éx` → offset 2) and 3.
3. **A pattern that crashes the engine** (`\b{start-half}a`), followed by continued typing. Expect a "crashed on this pattern" error, and the next pattern should work normally. Pinned in Task 2.
4. **The `wide` modifier on pasted text.** Expect no matches plus a hint to also turn on `ascii`, and `ascii wide` should match the plain bytes. The engine behavior is pinned in Task 2; the hint is checked in Task 4's browser check.
5. **Switching between flavors.** Each flavor keeps its own pattern, options and sample, because the state lives in `App.tsx`, not in the unmounting `YaraWorkbench`. Check by reading Task 4's diff.

## Out of scope (later plans or later work)

- Syntax coloring in Yara-X mode. The pattern is shown uncolored, with only error and warning underlines. This is Plan 2.
- The Analysis tab: atoms, cost, grade, suggestions and Structure. This is Plan 3.
- Hex strings, whole rules, file upload, the `private` modifier and shareable links. These are out of the spec.

---

### Task 1: Fix the grid layout that hides the flag bar

**Why:** in `src/index.css`, `.app` uses `grid-template-rows: auto 1fr auto`. The Token Reference sidebar sits in the third, `auto`-sized row next to the results box, so that row grows to the full cheat-sheet height. That squeezes the editor row until the flag bar is hidden and the results box overlaps the editors. Yara-X mode relies on that flag bar for its suffix and modifier toggles.

**Files:**
- Modify: `src/index.css`, the `.app` rule

**Interfaces:**
- Consumes: nothing.
- Produces: the editor row (`.main`) gets its natural height (panes are at least 260 px tall), and the results box and sidebar share the remaining height and scroll inside themselves.

**Ruling for this task:** CSS can't be unit-tested in this repo, because Vitest runs in node. The check is a headless Chrome screenshot taken before and after the change.

- [ ] **Step 1: Capture the broken layout**

```bash
npx vite build --base=/RegexDebugger/ && (npx vite preview --base=/RegexDebugger/ --port 5197 --strictPort > /dev/null 2>&1 &)
sleep 2
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-first-run --user-data-dir=/tmp/rd-chrome --virtual-time-budget=4000 --window-size=1400,900 --screenshot=/tmp/rd-before.png http://localhost:5197/RegexDebugger/
```

Expected: in `/tmp/rd-before.png`, the results table overlaps the pattern and test-string panes, and the `g global / i ignore case / …` flag bar is not visible.

- [ ] **Step 2: Change the row template**

In `src/index.css`, replace

```css
.app { display: grid; grid-template-columns: 1fr 340px; grid-template-rows: auto 1fr auto; height: 100%; }
```

with

```css
.app { display: grid; grid-template-columns: 1fr 340px; grid-template-rows: auto auto minmax(0, 1fr); height: 100%; }
```

- [ ] **Step 3: Capture the fixed layout**

```bash
npx vite build --base=/RegexDebugger/
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-first-run --user-data-dir=/tmp/rd-chrome --virtual-time-budget=4000 --window-size=1400,900 --screenshot=/tmp/rd-after.png http://localhost:5197/RegexDebugger/
pkill -f "vite preview --base=/RegexDebugger/ --port 5197"
```

Expected: in `/tmp/rd-after.png`:
- the two editor panes are full height, with the flag bar (`g global`, `i ignore case`, `m multi-line`, `s dot matches all`, `u unicode`) visible under the pattern
- the Matches table sits fully below the editors
- the Token Reference sidebar starts beside the results box and scrolls

Open the screenshot with the Read tool and check it.

- [ ] **Step 4: Run the gate and commit**

Run: `npx tsc -b && npx oxlint && npx vitest run`

Expected: `tsc` exits 0, only the 2 existing warnings, 51/51 tests pass.

```bash
git add src/index.css
git commit -m "$(cat <<'EOF'
fix(layout): editor row keeps its height; results and sidebar share the rest

The sidebar sat in an auto-sized grid row, so the long cheat sheet
stretched that row and squeezed the editors until the flag bar was
hidden behind the results box.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Yara-X engine wrapper

**Files:**
- Modify: `package.json` and `package-lock.json` (through `npm i`)
- Create: `src/lib/yarax/engine.ts`
- Create: `src/lib/yarax/samples.ts`
- Test: `src/lib/yarax/__tests__/engine.test.ts`

**Interfaces:**
- Consumes: `@virustotal/yara-x` 1.21.0. Its `default` export is `init()`, and there are also `initSync({ module })` and `Compiler` (`addSource`, `build() → Rules`, `warnings: string[]`, `free()`). `Rules.scanner()` returns a `Scanner` (`setMaxMatchesPerPattern(n)`, `scan(bytes)`, `free()`). The scan result has the shape `{ matches: [{ patterns: [{ identifier: '$a', kind: 'regexp', matches: [{ offset, length }] }] }] }`, and `matches` is `[]` when the rule doesn't fire.
- Produces, all exported from `engine.ts`:
  - `interface YaraOptions { i; s; nocase; wide; ascii; fullword: boolean }` and `DEFAULT_YARA_OPTIONS` (all `false`)
  - `interface Diag { severity: 'error' | 'warning'; code: string; title: string; labels: DiagLabel[]; notes: string[] }`, where `DiagLabel = { text: string; start: number | null; end: number | null }` and positions are pattern offsets
  - `interface YaraMatch { offset: number; length: number }` (bytes) and `interface EngineResult { matches; errors; warnings }`
  - `interface YaraModule` (the structural type of the loaded package)
  - `buildRuleSource(pattern, opts): string`
  - `parseDiag(text, patternLen): Diag`
  - `formatDiag(d): string`
  - `hasUnescapedSlash(pattern): boolean`
  - `runYara(mod, pattern, opts, input): EngineResult`, which is synchronous
  - `loadEngine(): Promise<YaraModule>`, cached, and reset if loading fails
- `samples.ts` exports `YARA_DEFAULT_PATTERN` and `YARA_SAMPLE_INPUT`.

- [ ] **Step 1: Install the package**

```bash
npm i --save-exact --no-audit --no-fund @virustotal/yara-x@1.21.0
grep -n '"@virustotal/yara-x"' package.json
```

Expected: `"@virustotal/yara-x": "1.21.0",` under `dependencies`, with no `^`.

- [ ] **Step 2: Write the failing tests**

Create `src/lib/yarax/__tests__/engine.test.ts`. The diagnostic strings below are the engine's real output, captured from 1.21.0. The triple-slash reference provides Node types for `readFileSync`; `tsconfig.app.json` only lists `vite/client`.

```ts
/// <reference types="node" />
import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'
import * as yarax from '@virustotal/yara-x'
import {
  DEFAULT_YARA_OPTIONS,
  buildRuleSource,
  formatDiag,
  hasUnescapedSlash,
  parseDiag,
  runYara,
  type YaraModule,
  type YaraOptions,
} from '../engine'
import { YARA_DEFAULT_PATTERN, YARA_SAMPLE_INPUT } from '../samples'

const mod = yarax as unknown as YaraModule
const opts = (o: Partial<YaraOptions> = {}): YaraOptions => ({ ...DEFAULT_YARA_OPTIONS, ...o })

beforeAll(() => {
  yarax.initSync({ module: readFileSync('node_modules/@virustotal/yara-x/pkg/yara_x_js_bg.wasm') })
})

const E014 =
  'error[E014]: invalid regular expression\n' +
  ' --> line:1:28\n' +
  '  |\n' +
  '1 | rule t { strings: $a = /foo{/ condition: $a }\n' +
  '  |                            ^ unclosed counted repetition\n' +
  '  |\n' +
  '  = note: did you mean `\\{` instead of `{`?'

const REDUNDANT =
  'warning[redundant_modifier]: redundant case-insensitive modifier\n' +
  ' --> line:1:29\n' +
  '  |\n' +
  '1 | rule t { strings: $a = /abc/i nocase condition: $a }\n' +
  '  |                             - ------ the `nocase` modifier does the same\n' +
  '  |                             |\n' +
  '  |                             the `i` suffix indicates that the pattern is case-insensitive'

describe('buildRuleSource', () => {
  it('wraps the pattern with suffix and modifiers', () => {
    expect(buildRuleSource('ab\\/c', opts({ i: true, s: true, nocase: true, fullword: true }))).toBe(
      'rule t { strings: $a = /ab\\/c/is nocase fullword condition: $a }',
    )
    expect(buildRuleSource('x', opts())).toBe('rule t { strings: $a = /x/ condition: $a }')
  })
})

describe('parseDiag', () => {
  it('reads code, title, label position and note', () => {
    expect(parseDiag(E014, 4)).toEqual({
      severity: 'error',
      code: 'E014',
      title: 'invalid regular expression',
      labels: [{ text: 'unclosed counted repetition', start: 3, end: 4 }],
      notes: ['did you mean `\\{` instead of `{`?'],
    })
  })

  it('reads every label of a multi-label diagnostic', () => {
    const d = parseDiag(REDUNDANT, 3)
    expect(d.severity).toBe('warning')
    expect(d.code).toBe('redundant_modifier')
    expect(d.labels.map((l) => l.text)).toEqual([
      'the `i` suffix indicates that the pattern is case-insensitive',
      'the `nocase` modifier does the same',
    ])
    expect(d.labels.every((l) => l.start === null && l.end === null)).toBe(true)
  })
})

describe('hasUnescapedSlash', () => {
  it('finds a slash that is not escaped', () => {
    expect(hasUnescapedSlash('a/b')).toBe(true)
    expect(hasUnescapedSlash('a\\/b')).toBe(false)
    expect(hasUnescapedSlash('a\\\\/b')).toBe(true)
    expect(hasUnescapedSlash('abc')).toBe(false)
  })
})

describe('formatDiag', () => {
  it('joins code, title, labels and notes into banner text', () => {
    expect(formatDiag(parseDiag(E014, 4))).toBe(
      'E014: invalid regular expression — unclosed counted repetition\n' +
        'note: did you mean `\\{` instead of `{`?',
    )
    expect(formatDiag(parseDiag(REDUNDANT, 3))).toBe(
      'redundant_modifier: redundant case-insensitive modifier — ' +
        'the `i` suffix indicates that the pattern is case-insensitive; ' +
        'the `nocase` modifier does the same',
    )
  })

  it('shows only the title for errors raised by the tester itself', () => {
    expect(
      formatDiag({ severity: 'error', code: 'input', title: 'a Yara-X regex must be on a single line', labels: [], notes: [] }),
    ).toBe('a Yara-X regex must be on a single line')
  })
})

describe('runYara', () => {
  it('reports byte offsets and lengths of every match', () => {
    const r = runYara(
      mod,
      'eval\\s*\\(\\s*base64_decode\\s*\\(',
      opts(),
      "<?php eval(base64_decode('x')); eval ( base64_decode ( 'y' );",
    )
    expect(r.errors).toEqual([])
    expect(r.matches).toEqual([
      { offset: 6, length: 19 },
      { offset: 32, length: 22 },
    ])
  })

  it('reports overlapping matches and byte offsets after multibyte text', () => {
    expect(runYara(mod, 'aa', opts(), 'aaaa').matches).toEqual([
      { offset: 0, length: 2 },
      { offset: 1, length: 2 },
      { offset: 2, length: 2 },
    ])
    expect(runYara(mod, 'x', opts(), 'éx').matches).toEqual([{ offset: 2, length: 1 }])
  })

  it('returns engine errors with the label mapped into the pattern', () => {
    const r = runYara(mod, 'foo{', opts(), 'foo')
    expect(r.matches).toEqual([])
    expect(r.errors).toEqual([parseDiag(E014, 4)])
  })

  it('returns engine warnings alongside matches', () => {
    const r = runYara(mod, 'a', opts(), 'banana')
    expect(r.warnings.map((w) => [w.code, w.labels[0].start, w.labels[0].end])).toEqual([
      ['slow_pattern', 0, 1],
    ])
    expect(r.matches.map((m) => m.offset)).toEqual([1, 3, 5])
  })

  it('applies suffixes and modifiers', () => {
    expect(runYara(mod, 'abc', opts({ nocase: true }), 'xABC').matches).toEqual([
      { offset: 1, length: 3 },
    ])
    expect(runYara(mod, 'abcd', opts({ fullword: true }), 'xabcd abcd').matches).toEqual([
      { offset: 6, length: 4 },
    ])
    expect(runYara(mod, 'abc', opts({ i: true, nocase: true }), 'abc').warnings[0].code).toBe(
      'redundant_modifier',
    )
  })

  it('reports an engine crash and keeps working afterwards', () => {
    const r = runYara(mod, '\\b{start-half}a', opts(), 'a')
    expect(r.errors.map((e) => e.code)).toEqual(['crash'])
    expect(runYara(mod, 'abc', opts(), 'abc').matches).toEqual([{ offset: 0, length: 3 }])
  })

  it('explains an unescaped slash, which ends the regex early', () => {
    const r = runYara(mod, 'a/b', opts(), 'a/b')
    expect(r.errors.map((e) => [e.code, e.notes])).toEqual([
      ['E001', ['Yara-X ends the regex at an unescaped `/`; write it as `\\/`']],
    ])
    expect(runYara(mod, 'a\\/b', opts(), 'xa/b').matches).toEqual([{ offset: 1, length: 3 }])
  })

  it('finds nothing with wide alone in pasted text, and the plain bytes with ascii wide', () => {
    expect(runYara(mod, 'abc', opts({ wide: true }), 'abc').matches).toEqual([])
    expect(runYara(mod, 'abc', opts({ wide: true, ascii: true }), 'abc').matches).toEqual([
      { offset: 0, length: 3 },
    ])
  })

  it('stops at 10,000 matches', () => {
    expect(runYara(mod, 'aa', opts(), 'a'.repeat(20001)).matches).toHaveLength(10000)
  })

  it('rejects a pattern with a line break before calling the engine', () => {
    expect(runYara(mod, 'a\nb', opts(), 'ab').errors.map((e) => e.code)).toEqual(['input'])
  })

  it('returns nothing for an empty pattern', () => {
    expect(runYara(mod, '', opts(), 'abc')).toEqual({ matches: [], errors: [], warnings: [] })
  })
})

describe('Yara-X defaults', () => {
  it('match the sample twice and skip the near-miss', () => {
    const r = runYara(mod, YARA_DEFAULT_PATTERN, opts(), YARA_SAMPLE_INPUT)
    expect(r.errors).toEqual([])
    expect(r.warnings).toEqual([])
    const text = r.matches.map((m) =>
      new TextDecoder().decode(new TextEncoder().encode(YARA_SAMPLE_INPUT).slice(m.offset, m.offset + m.length)),
    )
    expect(text).toEqual(['eval(base64_decode(', 'eval ( base64_decode ('])
  })
})
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `npx vitest run src/lib/yarax/__tests__/engine.test.ts`

Expected: FAIL, with an error that `../engine` (or `../samples`) can't be resolved. No tests run.

- [ ] **Step 4: Implement**

Create `src/lib/yarax/samples.ts`:

```ts
export const YARA_DEFAULT_PATTERN = 'eval\\s*\\(\\s*base64_decode\\s*\\('

export const YARA_SAMPLE_INPUT =
  '<?php\n' +
  '// matches\n' +
  "eval(base64_decode('ZWNobyAnaGknOw=='));\n" +
  '// near-miss: evaluate / base64_encode\n' +
  'evaluate(base64_encode($x));\n' +
  '// extra spaces still match\n' +
  'eval ( base64_decode ( $payload ) );\n'
```

Create `src/lib/yarax/engine.ts`:

```ts
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

function patternRange(col: number, len: number, patternLen: number): [number, number] | null {
  const start = Math.max(col - RULE_PREFIX.length, 0)
  const end = Math.min(col + len - RULE_PREFIX.length, patternLen)
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
    for (const m of marks.matchAll(/[\^-]+/g)) {
      runs.push({ col: m.index, len: m[0].length, text: null })
    }
    const after = marks.slice((runs.at(-1)?.col ?? 0) + (runs.at(-1)?.len ?? 0)).trim()
    if (runs.length && after) runs[runs.length - 1].text = after
    for (const line of lines.slice(src + 2)) {
      if (!line.startsWith('  |')) continue
      const body = line.slice(GUTTER)
      const col = body.search(/\S/)
      const run = runs.find((r) => r.col === col && r.text === null)
      if (run && body[col] !== '|') run.text = body.slice(col).trim()
    }
  }
  for (const r of runs) {
    const range = patternRange(r.col, r.len, patternLen)
    diag.labels.push({ text: r.text ?? '', start: range?.[0] ?? null, end: range?.[1] ?? null })
  }
  for (const line of lines) {
    const note = /^\s*= (?:note|help): (.*)$/.exec(line)
    if (note) diag.notes.push(note[1])
  }
  return diag
}

const LOCAL_CODES = new Set(['input', 'crash'])

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

const SLASH_NOTE = 'Yara-X ends the regex at an unescaped `/`; write it as `\\/`'

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
  const compiler = new mod.Compiler()
  try {
    compiler.addSource(buildRuleSource(pattern, opts))
  } catch (e) {
    const text = e instanceof Error ? e.message : String(e)
    if (!/^error\[/.test(text)) {
      return localError('crash', `the Yara-X engine crashed on this pattern (${text})`)
    }
    compiler.free()
    const diag = parseDiag(text, pattern.length)
    if (hasUnescapedSlash(pattern)) diag.notes.push(SLASH_NOTE)
    return { matches: [], errors: [diag], warnings: [] }
  }
  let crashed = false
  try {
    const warnings = compiler.warnings.map((w) => parseDiag(w, pattern.length))
    const rules = compiler.build()
    const scanner = rules.scanner()
    scanner.setMaxMatchesPerPattern(MAX_MATCHES)
    const result = scanner.scan(new TextEncoder().encode(input))
    scanner.free()
    rules.free()
    const matches = result.matches
      .flatMap((r) => r.patterns)
      .flatMap((p) => p.matches)
      .map(({ offset, length }) => ({ offset, length }))
      .sort((a, b) => a.offset - b.offset || a.length - b.length)
    return { matches, errors: [], warnings }
  } catch (e) {
    crashed = true
    const text = e instanceof Error ? e.message : String(e)
    return localError('crash', `the Yara-X engine crashed on this pattern (${text})`)
  } finally {
    if (!crashed) compiler.free()
  }
}

let loading: Promise<YaraModule> | null = null

export function loadEngine(): Promise<YaraModule> {
  if (!loading) {
    loading = import('@virustotal/yara-x').then(async (mod) => {
      await mod.default()
      return mod as unknown as YaraModule
    })
    loading.catch(() => {
      loading = null
    })
  }
  return loading
}
```

**Notes for the implementer:**
- **Column mapping:** `parseDiag` maps a label's column to the pattern by subtracting `RULE_PREFIX.length` (24) from its 0-based column after the 4-character gutter. It clamps the result to the pattern. Labels entirely outside the pattern get `null` positions; for example, labels on the `i` suffix or the `nocase` modifier.
- **Multi-label diagnostics:** the label text of the rightmost marker follows it on the marker line. The other markers' texts come on later lines, starting at the marker's own column.
- **Errors raised by the tester itself:** `crash` and `input` are produced by the tester, not the engine. `formatDiag` shows them without a code prefix.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npx vitest run src/lib/yarax/__tests__/engine.test.ts`

Expected: PASS, 18/18.

- [ ] **Step 6: Run the gate and commit**

Run: `npx tsc -b && npx oxlint && npx vitest run`

Expected: `tsc` exits 0, only the 2 existing warnings, 69/69 tests pass.

```bash
git add package.json package-lock.json src/lib/yarax/engine.ts src/lib/yarax/samples.ts src/lib/yarax/__tests__/engine.test.ts
git commit -m "$(cat <<'EOF'
feat(yarax): wrap the Yara-X WebAssembly engine

Compiles one regex string as a rule, scans the UTF-8 bytes of the
input and returns byte offsets plus the engine's errors and warnings,
parsed from its formatted text with label positions mapped back into
the pattern. Recovers from engine panics and explains unescaped `/`.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Byte-offset helpers

**Files:**
- Create: `src/lib/yarax/bytes.ts`
- Test: `src/lib/yarax/__tests__/bytes.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `mapBytes(text: string): ByteMap`, where `ByteMap = { bytes: Uint8Array; charStart(byteOffset): number; charEnd(byteOffset): number }`. `bytes` is the UTF-8 encoding. `charStart` maps a byte offset to the index of the character that contains it. `charEnd` widens an offset that falls inside a character to the end of that character. Both clamp to `[0, bytes.length]`.
  - `showBytes(bytes: Uint8Array): string`. It shows valid UTF-8 as text, with `\n`, `\t` and `\r` escaped and other control characters shown as `\xHH`. Invalid UTF-8 is shown byte by byte: printable ASCII as is, everything else as `\xHH`.

- [ ] **Step 1: Write the failing tests**

Create `src/lib/yarax/__tests__/bytes.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { mapBytes, showBytes } from '../bytes'

describe('mapBytes', () => {
  it('maps byte offsets to string indices for ASCII', () => {
    const m = mapBytes('abc')
    expect([...m.bytes]).toEqual([0x61, 0x62, 0x63])
    expect([0, 1, 2, 3].map(m.charStart)).toEqual([0, 1, 2, 3])
  })

  it('maps offsets after 2-, 3- and 4-byte characters', () => {
    const m = mapBytes('éx€y😀z')
    expect(m.bytes.length).toBe(2 + 1 + 3 + 1 + 4 + 1)
    expect(m.charStart(2)).toBe(1)
    expect(m.charStart(6)).toBe(3)
    expect(m.charStart(11)).toBe(6)
    expect(m.charStart(12)).toBe(7)
  })

  it('widens a range that splits a character to the whole character', () => {
    const m = mapBytes('aéb')
    expect(m.charStart(2)).toBe(1)
    expect(m.charEnd(2)).toBe(2)
    expect(m.charEnd(3)).toBe(2)
    expect(m.charEnd(4)).toBe(3)
  })
})

describe('showBytes', () => {
  it('shows valid UTF-8 as text with control characters escaped', () => {
    expect(showBytes(new TextEncoder().encode('é\tx\n\u0001'))).toBe('é\\tx\\n\\x01')
  })

  it('shows invalid UTF-8 byte by byte', () => {
    expect(showBytes(new Uint8Array([0x61, 0xc3, 0x00]))).toBe('a\\xC3\\x00')
  })
})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/lib/yarax/__tests__/bytes.test.ts`

Expected: FAIL, because `../bytes` can't be resolved.

- [ ] **Step 3: Implement**

Create `src/lib/yarax/bytes.ts`:

```ts
export interface ByteMap {
  bytes: Uint8Array
  charStart: (byteOffset: number) => number
  charEnd: (byteOffset: number) => number
}

export function mapBytes(text: string): ByteMap {
  const bytes = new TextEncoder().encode(text)
  const owner = new Int32Array(bytes.length + 1)
  let b = 0
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i) ?? 0
    const units = cp > 0xffff ? 2 : 1
    const size = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4
    for (let k = 0; k < size; k++) owner[b + k] = i
    b += size
    i += units
  }
  owner[bytes.length] = text.length
  const charStart = (offset: number) => owner[Math.max(0, Math.min(offset, bytes.length))]
  const charEnd = (offset: number) => {
    const o = Math.max(0, Math.min(offset, bytes.length))
    if (o === 0 || o === bytes.length || owner[o] !== owner[o - 1]) return owner[o]
    let k = o
    while (k < bytes.length && owner[k] === owner[o - 1]) k++
    return owner[k]
  }
  return { bytes, charStart, charEnd }
}

function hex(v: number): string {
  return '\\x' + v.toString(16).toUpperCase().padStart(2, '0')
}

function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return null
  }
}

export function showBytes(bytes: Uint8Array): string {
  const text = decodeUtf8(bytes)
  if (text === null) {
    return [...bytes].map((v) => (v >= 0x20 && v < 0x7f ? String.fromCharCode(v) : hex(v))).join('')
  }
  let out = ''
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0
    if (ch === '\n') out += '\\n'
    else if (ch === '\t') out += '\\t'
    else if (ch === '\r') out += '\\r'
    else if (c < 0x20 || c === 0x7f) out += hex(c)
    else out += ch
  }
  return out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/lib/yarax/__tests__/bytes.test.ts`

Expected: PASS, 5/5.

- [ ] **Step 5: Run the gate and commit**

Run: `npx tsc -b && npx oxlint && npx vitest run`

Expected: `tsc` exits 0, only the 2 existing warnings, 74/74 tests pass.

```bash
git add src/lib/yarax/bytes.ts src/lib/yarax/__tests__/bytes.test.ts
git commit -m "$(cat <<'EOF'
feat(yarax): map UTF-8 byte offsets to string indices

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Yara-X flavor in the UI

**Files:**
- Create: `src/components/yarax/useYaraScan.ts`
- Create: `src/components/yarax/YaraPatternPane.tsx`
- Create: `src/components/yarax/YaraMatchList.tsx`
- Create: `src/components/yarax/YaraWorkbench.tsx`
- Modify: `src/App.tsx` (flavor switch, Yara-X state, render branch)
- Modify: `src/components/InputPane.tsx` (optional `sample` prop for Reset)
- Modify: `src/components/TokenReference.tsx` (`flavor` prop)
- Modify: `src/lib/tokens.ts` (`YARAX_REFERENCE`)
- Modify: `src/index.css` (selector, warning box, underlines, table columns)

**Interfaces:**
- Consumes:
  - from Task 2: `loadEngine`, `runYara`, `formatDiag`, `DEFAULT_YARA_OPTIONS`, and the types `Diag`, `EngineResult`, `YaraMatch`, `YaraModule`, `YaraOptions`, plus `YARA_DEFAULT_PATTERN` and `YARA_SAMPLE_INPUT`
  - from Task 3: `mapBytes` and `showBytes`
- Produces:
  - `useYaraScan(pattern, opts, input): ScanState`, where `ScanState` is `{ status: 'loading' } | { status: 'unavailable'; reason } | { status: 'ready'; result; ms }`
  - `<YaraWorkbench pattern opts input onPattern onOpts onInput />`, which renders a fragment of `.main` and `.results`, the same grid children as the JavaScript UI
  - `<TokenReference flavor />`
  - `<InputPane sample? />`

**Design notes:**
- **State placement:** `App.tsx` owns the Yara-X state, so switching flavors (which unmounts `YaraWorkbench`) keeps the pattern, options and sample. The loaded module is cached by `loadEngine()`, so remounting is instant after the first load.
- **No stale results:** `runYara` is synchronous inside the debounced timeout, so clearing the timeout on every change is enough to drop stale results. This is how the spec's "request counter" requirement is met.
- **Tabs:** Yara-X mode has a single Matches tab for now; Plan 3 adds Analysis.
- **Shared empty list:** `NO_MATCHES` is a module constant, so `useMemo` doesn't see a new `[]` on every render. A fresh `[]` triggers a `react-hooks(exhaustive-deps)` warning.

- [ ] **Step 1: Add the hook**

Create `src/components/yarax/useYaraScan.ts`:

```ts
import { useEffect, useState } from 'react'
import {
  loadEngine,
  runYara,
  type EngineResult,
  type YaraModule,
  type YaraOptions,
} from '../../lib/yarax/engine'

export type ScanState =
  | { status: 'loading' }
  | { status: 'unavailable'; reason: string }
  | { status: 'ready'; result: EngineResult; ms: number }

const DEBOUNCE_MS = 150

export function useYaraScan(pattern: string, opts: YaraOptions, input: string): ScanState {
  const [mod, setMod] = useState<YaraModule | null>(null)
  const [failure, setFailure] = useState('')
  const [scan, setScan] = useState<{ result: EngineResult; ms: number } | null>(null)

  useEffect(() => {
    let live = true
    loadEngine().then(
      (m) => live && setMod(m),
      (e: unknown) => live && setFailure(e instanceof Error ? e.message : String(e)),
    )
    return () => {
      live = false
    }
  }, [])

  useEffect(() => {
    if (!mod) return
    const timer = setTimeout(() => {
      const t0 = performance.now()
      const result = runYara(mod, pattern, opts, input)
      setScan({ result, ms: performance.now() - t0 })
    }, DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [mod, pattern, opts, input])

  if (failure) return { status: 'unavailable', reason: failure }
  if (!scan) return { status: 'loading' }
  return { status: 'ready', ...scan }
}
```

- [ ] **Step 2: Add the pattern pane**

Create `src/components/yarax/YaraPatternPane.tsx`:

```tsx
import { CodeArea } from '../CodeArea'
import type { Span } from '../Highlighter'
import { formatDiag, type Diag, type YaraOptions } from '../../lib/yarax/engine'

const SUFFIXES = [
  { key: 'i', name: 'ignore case' },
  { key: 's', name: 'dot matches all' },
] as const

const MODIFIERS = ['nocase', 'wide', 'ascii', 'fullword'] as const

function diagSpans(diags: Diag[]): Span[] {
  return diags.flatMap((d) =>
    d.labels
      .filter((l) => l.start !== null && l.end !== null)
      .map((l) => ({
        start: l.start ?? 0,
        end: l.end ?? 0,
        className: d.severity === 'error' ? 'hl-err' : 'hl-warn',
      })),
  )
}

export function YaraPatternPane({
  pattern,
  opts,
  errors,
  warnings,
  onPattern,
  onOpts,
}: {
  pattern: string
  opts: YaraOptions
  errors: Diag[]
  warnings: Diag[]
  onPattern: (v: string) => void
  onOpts: (o: YaraOptions) => void
}) {
  const error = errors.map(formatDiag).join('\n')
  const warning = warnings.map(formatDiag).join('\n')
  const flag = (key: keyof YaraOptions, label: string, name?: string) => (
    <label key={key} className={'flag' + (opts[key] ? ' flag-on' : '')}>
      <input
        type="checkbox"
        checked={opts[key]}
        onChange={(e) => onOpts({ ...opts, [key]: e.target.checked })}
      />
      <span className="flag-key">{label}</span>
      {name && <span className="flag-name">{name}</span>}
    </label>
  )
  return (
    <section className="pane">
      <header className="pane-header">
        <span className="pane-title">Regular Expression</span>
        <span className="pane-flavor">Yara-X</span>
      </header>
      <CodeArea
        ariaLabel="Yara-X regular expression"
        value={pattern}
        onChange={onPattern}
        spans={diagSpans([...errors, ...warnings])}
        error={error}
      />
      {error && <div className="errorbox">{error}</div>}
      {warning && <div className="warnbox">{warning}</div>}
      <footer className="flagbar">
        {SUFFIXES.map((s) => flag(s.key, s.key, s.name))}
        <span className="flag-sep" aria-hidden />
        {MODIFIERS.map((m) => flag(m, m))}
      </footer>
    </section>
  )
}
```

- [ ] **Step 3: Add the match list**

Create `src/components/yarax/YaraMatchList.tsx`:

```tsx
import type { YaraMatch } from '../../lib/yarax/engine'
import { showBytes } from '../../lib/yarax/bytes'

export function YaraMatchList({
  matches,
  bytes,
  wideHint,
}: {
  matches: YaraMatch[]
  bytes: Uint8Array
  wideHint: boolean
}) {
  if (matches.length === 0) {
    return (
      <div className="empty">
        No matches found.
        {wideHint && (
          <div className="hint">
            <code>wide</code> searches for UTF-16LE text (a 00 byte after each byte), which
            pasted text doesn't contain. Turn on <code>ascii</code> too to search both.
          </div>
        )}
      </div>
    )
  }
  return (
    <div className="matchlist">
      <table>
        <thead>
          <tr>
            <th className="ynum">Match</th>
            <th className="ynum">Offset</th>
            <th className="ynum">Length</th>
            <th>Text</th>
          </tr>
        </thead>
        <tbody>
          {matches.map((m, i) => {
            const text = showBytes(bytes.slice(m.offset, m.offset + m.length))
            return (
              <tr key={i}>
                <td className="ynum idx">#{i + 1}</td>
                <td className="ynum">{m.offset}</td>
                <td className="ynum">{m.length}</td>
                <td>
                  <div className="mtext" title={text}>{text}</div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
```

- [ ] **Step 4: Add the workbench**

Create `src/components/yarax/YaraWorkbench.tsx`:

```tsx
import { useMemo } from 'react'
import { InputPane } from '../InputPane'
import type { Span } from '../Highlighter'
import { YaraPatternPane } from './YaraPatternPane'
import { YaraMatchList } from './YaraMatchList'
import { useYaraScan } from './useYaraScan'
import { formatDiag, type YaraMatch, type YaraOptions } from '../../lib/yarax/engine'
import { mapBytes } from '../../lib/yarax/bytes'
import { YARA_SAMPLE_INPUT } from '../../lib/yarax/samples'

const NO_MATCHES: YaraMatch[] = []

export function YaraWorkbench({
  pattern,
  opts,
  input,
  onPattern,
  onOpts,
  onInput,
}: {
  pattern: string
  opts: YaraOptions
  input: string
  onPattern: (v: string) => void
  onOpts: (o: YaraOptions) => void
  onInput: (v: string) => void
}) {
  const scan = useYaraScan(pattern, opts, input)
  const map = useMemo(() => mapBytes(input), [input])
  const result = scan.status === 'ready' ? scan.result : null
  const errors = result?.errors ?? []
  const warnings = result?.warnings ?? []
  const matches = result?.matches ?? NO_MATCHES

  const inputSpans: Span[] = useMemo(
    () =>
      matches.map((m) => ({
        start: map.charStart(m.offset),
        end: map.charEnd(m.offset + m.length),
        className: 'hl-match',
      })),
    [matches, map],
  )

  const badge =
    scan.status === 'loading'
      ? '…'
      : scan.status === 'unavailable' || errors.length
        ? '!'
        : `${matches.length} in ${scan.ms.toFixed(2)} ms`

  return (
    <>
      <main className="main">
        <YaraPatternPane
          pattern={pattern}
          opts={opts}
          errors={errors}
          warnings={warnings}
          onPattern={onPattern}
          onOpts={onOpts}
        />
        <InputPane input={input} spans={inputSpans} onInput={onInput} sample={YARA_SAMPLE_INPUT} />
      </main>

      <section className="results">
        <div className="tabs">
          <button className="tab tab-on">
            Matches
            <span className="tab-badge">{badge}</span>
          </button>
        </div>
        <div className="results-body">
          {scan.status === 'loading' ? (
            <div className="empty">Loading the Yara-X engine…</div>
          ) : scan.status === 'unavailable' ? (
            <div className="empty error-empty">Yara-X engine unavailable: {scan.reason}</div>
          ) : errors.length ? (
            <div className="empty error-empty yerr">{errors.map(formatDiag).join('\n')}</div>
          ) : (
            <YaraMatchList
              matches={matches}
              bytes={map.bytes}
              wideHint={opts.wide && !opts.ascii}
            />
          )}
        </div>
      </section>
    </>
  )
}
```

- [ ] **Step 5: Give `InputPane` a configurable sample**

In `src/components/InputPane.tsx`:
- Add `sample = SAMPLE_INPUT,` to the destructured props, after `onInput,`.
- Add `sample?: string` to the props type, after `onInput: (v: string) => void`.
- Change the Reset button's handler from `onClick={() => onInput(SAMPLE_INPUT)}` to `onClick={() => onInput(sample)}`.

- [ ] **Step 6: Make the Token Reference flavor-aware**

Replace the top of `src/components/TokenReference.tsx`, down to the `return (` line, with:

```tsx
import { REFERENCE, YARAX_REFERENCE } from '../lib/tokens'

export function TokenReference({ flavor }: { flavor: 'javascript' | 'yarax' }) {
  const entries = flavor === 'yarax' ? YARAX_REFERENCE : REFERENCE
  return (
```

Then change `{REFERENCE.map((r, i) => (` to `{entries.map((r, i) => (`.

Append to `src/lib/tokens.ts`, after `REFERENCE`, separated by a blank line:

```ts
export const YARAX_REFERENCE: ReferenceEntry[] = [
  { pattern: '/.../i', description: 'case-insensitive (ASCII letters only)' },
  { pattern: '/.../s', description: '. also matches \\n (any byte)' },
  { pattern: '.', description: 'any byte except \\n' },
  { pattern: '\\xFF', description: 'the raw byte 0xFF' },
  { pattern: '\\x{E9}', description: 'a code point, matched as its UTF-8 bytes (C3 A9)' },
  { pattern: '\\d \\w \\s', description: 'ASCII digit, word character, whitespace' },
  { pattern: '[a-f0-9]', description: 'one byte from the set (ASCII only)' },
  { pattern: '^ $', description: 'start / end of the data (of a line with (?m))' },
  { pattern: '\\b \\B', description: 'ASCII word boundary / non-boundary' },
  { pattern: 'a{n,m} a{,m}', description: 'between n and m times / at most m times' },
  { pattern: '*? +? ??', description: "lazy; can't be mixed with greedy (E015)" },
  { pattern: '(...)', description: 'a group; Yara-X never returns captures' },
  { pattern: '(?i) (?s) (?m)', description: 'inline flags' },
  { pattern: '\\/', description: 'a slash (must be escaped)' },
  { pattern: 'nocase', description: 'case-insensitive (same as /i)' },
  { pattern: 'wide', description: 'UTF-16LE: a 00 byte after each byte' },
  { pattern: 'ascii wide', description: 'search both encodings' },
  { pattern: 'fullword', description: 'no ASCII letter or digit right before or after' },
  { pattern: 'unsupported', description: 'backreferences, lookaround, \\p{...}' },
]
```

- [ ] **Step 7: Wire the flavor switch into `App.tsx`**

Add these imports:
- below `import { TokenReference } from './components/TokenReference'`:

  ```tsx
  import { YaraWorkbench } from './components/yarax/YaraWorkbench'
  ```
- below `import type { Span } from './components/Highlighter'`:

  ```tsx
  import { DEFAULT_YARA_OPTIONS } from './lib/yarax/engine'
  import { YARA_DEFAULT_PATTERN, YARA_SAMPLE_INPUT } from './lib/yarax/samples'
  ```

Above `const DEFAULT_PATTERN = `, add:

```tsx
type Flavor = 'javascript' | 'yarax'

```

Below `const [tab, setTab] = useState<'matches' | 'explain'>('matches')`, add:

```tsx
  const [flavor, setFlavor] = useState<Flavor>('javascript')
  const [yPattern, setYPattern] = useState(YARA_DEFAULT_PATTERN)
  const [yOpts, setYOpts] = useState(DEFAULT_YARA_OPTIONS)
  const [yInput, setYInput] = useState(YARA_SAMPLE_INPUT)
```

Replace everything from the `  return (` line in `App` to the end of the file with the block below. The JavaScript `<main>` and `<section className="results">` markup is unchanged apart from moving into the `: (<> … </>)` branch with 4 more spaces of indentation.

```tsx
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">&lt;/&gt;</span>
          <span className="brand-name">regex101.clone</span>
        </div>
        <label className="flavor">
          Flavor
          <select value={flavor} onChange={(e) => setFlavor(e.target.value as Flavor)}>
            <option value="javascript">JavaScript</option>
            <option value="yarax">Yara-X</option>
          </select>
        </label>
      </header>

      {flavor === 'yarax' ? (
        <YaraWorkbench
          pattern={yPattern}
          opts={yOpts}
          input={yInput}
          onPattern={setYPattern}
          onOpts={setYOpts}
          onInput={setYInput}
        />
      ) : (
        <>
          <main className="main">
            <PatternPane
              pattern={pattern}
              flags={flags}
              spans={patternSpans}
              error={error}
              onPattern={setPattern}
              onFlag={onFlag}
            />
            <InputPane input={input} spans={inputSpans} onInput={setInput} />
          </main>

          <section className="results">
            <div className="tabs">
              <button
                className={'tab' + (tab === 'matches' ? ' tab-on' : '')}
                onClick={() => setTab('matches')}
              >
                Matches
                <span className="tab-badge">
                  {error ? '!' : `${matches.length} in ${ms.toFixed(2)} ms`}
                </span>
              </button>
              <button
                className={'tab' + (tab === 'explain' ? ' tab-on' : '')}
                onClick={() => setTab('explain')}
              >
                Explanation
              </button>
            </div>
            <div className="results-body">
              {tab === 'matches'
                ? error
                  ? <div className="empty error-empty">{error}</div>
                  : <MatchList matches={matches} groupLabels={groupLabels} />
                : <ExplanationPane tokens={tokens} flags={flags} />}
            </div>
          </section>
        </>
      )}

      <TokenReference flavor={flavor} />
    </div>
  )
}
```

- [ ] **Step 8: Add the styles**

In `src/index.css`:
- In `:root`, after `--error-bg: #37202a;`, add:

  ```css
    --warn-fg: #ffd166;
    --warn-bg: #2f2a1c;
  ```
- After the `.flavor { … }` rule, add:

  ```css
  .flavor select {
    margin-left: 6px; padding: 3px 6px; border-radius: 6px;
    background: var(--bg-code); color: var(--text-hi);
    border: 1px solid var(--border); font: inherit;
  }
  ```
- At the end of the file, append:

  ```css

  .warnbox {
    margin: 0; padding: 8px 12px;
    background: var(--warn-bg); color: var(--warn-fg);
    font: 12px/1.5 var(--mono);
    border-top: 1px solid #4a3d1f;
    white-space: pre-wrap;
  }
  .flag-sep { width: 1px; margin: 2px 4px; background: var(--border); }
  .hl-err { text-decoration: underline wavy var(--error-fg); text-underline-offset: 3px; }
  .hl-warn { text-decoration: underline wavy var(--warn-fg); text-underline-offset: 3px; }
  .ynum { width: 1%; white-space: nowrap; padding-right: 18px !important; }
  .yerr { white-space: pre-wrap; font-family: var(--mono); }
  .hint { margin-top: 6px; font-size: 12px; }
  ```

- [ ] **Step 9: Run the gate**

Run: `npx tsc -b && npx oxlint && npx vitest run`

Expected: `tsc` exits 0, only the 2 existing `react(purity)` warnings (no `exhaustive-deps` warning), 74/74 tests pass.

- [ ] **Step 10: Check it in a real browser**

This temporarily makes Yara-X the default flavor, so headless Chrome renders it without a click. **The change must be reverted in this same step.**

```bash
sed -i '' "s/useState<Flavor>('javascript')/useState<Flavor>('yarax')/" src/App.tsx
npx vite build --base=/RegexDebugger/ && ls dist/assets/*.wasm
(npx vite preview --base=/RegexDebugger/ --port 5197 --strictPort > /dev/null 2>&1 &)
sleep 2
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-first-run --user-data-dir=/tmp/rd-chrome --virtual-time-budget=8000 --dump-dom http://localhost:5197/RegexDebugger/ > /tmp/rd-yarax.html
grep -o '<td class="ynum">[0-9]*</td>\|<div class="mtext"[^>]*>[^<]*</div>\|tab-badge">[^<]*<' /tmp/rd-yarax.html
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-first-run --user-data-dir=/tmp/rd-chrome --virtual-time-budget=8000 --window-size=1400,900 --screenshot=/tmp/rd-yarax.png http://localhost:5197/RegexDebugger/
pkill -f "vite preview --base=/RegexDebugger/ --port 5197"
sed -i '' "s/useState<Flavor>('yarax')/useState<Flavor>('javascript')/" src/App.tsx
grep -c "useState<Flavor>('javascript')" src/App.tsx
```

Expected:
- `dist/assets/yara_x_js_bg-<hash>.wasm` exists.
- The grep prints `tab-badge">2 in …`, offsets `17` and `154` with lengths `19` and `22`, and the texts `eval(base64_decode(` and `eval ( base64_decode (`.
- `/tmp/rd-yarax.png` (open it with the Read tool) shows the flavor selector set to Yara-X, the suffix toggles (`i ignore case`, `s dot matches all`), the modifier chips (`nocase wide ascii fullword`), both matches highlighted in the sample, and the Yara-X cheat sheet.
- The final grep prints `1`, which confirms the revert.

Then confirm by hand in `npm run dev`:
- Select **Yara-X** from the flavor menu. Type `a/b` and check the red banner shows the slash note. Toggle `wide` and check the hint appears.
- Switch back to **JavaScript** and check its pattern and sample are as you left them.

- [ ] **Step 11: Commit**

```bash
git status --short
git add src/App.tsx src/components/InputPane.tsx src/components/TokenReference.tsx src/components/yarax src/lib/tokens.ts src/index.css
git commit -m "$(cat <<'EOF'
feat(yarax): Yara-X flavor with real-engine matches

A flavor selector switches to a Yara-X workbench: suffix and modifier
toggles, the engine's errors and warnings as banners with underlines,
byte offset/length match table, highlights mapped from UTF-8 bytes, and
a Yara-X cheat sheet. The engine loads lazily on first use.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

Expected: `git status --short` lists only the files in this task's `git add`, with no stray `dist/` or `/tmp` files (`dist` is ignored).

---

### Task 5: Documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: no code.

- [ ] **Step 1: Update `CLAUDE.md`**

Under `## Architecture`, after the paragraph that starts `All state lives in \`App.tsx\``, add:

```markdown
**Flavors:** `App.tsx` holds `flavor` (`'javascript' | 'yarax'`) and separate state for each flavor. The JavaScript UI is rendered inline. Yara-X renders `components/yarax/YaraWorkbench`, which receives its state from `App` so that switching flavors keeps it.

**Yara-X engine** (`lib/yarax/engine.ts`): `loadEngine()` dynamically imports the official `@virustotal/yara-x` WebAssembly package, pinned exactly to `1.21.0`, and caches it. That is the only non-test import of the package, so it stays out of the main bundle. Vite rewrites the package's own `new URL('yara_x_js_bg.wasm', import.meta.url)` for dev and for the base-path build, so no Vite config is needed.
- `runYara` wraps the pattern as `rule t { strings: $a = /…/<is> <modifiers> condition: $a }`, scans the UTF-8 bytes, and returns byte offsets.
- `parseDiag` turns the engine's formatted error and warning text into structured diagnostics. Label columns map back into the pattern by subtracting the rule prefix (24 characters) after the 4-character gutter.
- After a panic, the thrown `Compiler` is poisoned, so never touch it again; a new one works.
- `lib/yarax/bytes.ts` maps byte offsets to string indices for the highlighter.
- Tests load the engine with `initSync` and the `.wasm` from `node_modules`.
```

Under `## Commands not in AGENTS.md`, add:

```markdown
- Yara-X engine tests only: `npx vitest run src/lib/yarax`
```

- [ ] **Step 2: Update `README.md`**

Replace the line

```markdown
A regex101-style regular expression tester for the JavaScript regex flavor. Type a pattern and some test text, and you get:
```

with:

```markdown
A regex101-style regular expression tester with two flavors: JavaScript, and **Yara-X**, which uses the real Yara-X engine compiled to WebAssembly. Type a pattern and some test text, and you get:
```

Replace the line

```markdown
Everything runs in the browser with the native `RegExp` engine. There is no backend, so the production build is a static site you can host anywhere.
```

with:

```markdown
Everything runs in the browser. The JavaScript flavor uses the browser's native `RegExp`, and the Yara-X flavor uses the official `@virustotal/yara-x` WebAssembly build. There is no backend, so the production build is a static site you can host anywhere.
```

In the `## Deploy` section, after the paragraph that starts `` `npm run build` writes a self-contained static site``, add:

```markdown
The Yara-X engine is a separate, roughly 6 MB WebAssembly file (about 2 MB gzipped) in `assets/`. It's downloaded only when someone switches to the Yara-X flavor. Static hosts must serve `.wasm` as `application/wasm`; GitHub Pages, Netlify, Vercel and Cloudflare Pages already do.
```

- [ ] **Step 3: Run the gate and commit**

Run: `npx tsc -b && npx oxlint && npx vitest run`

Expected: `tsc` exits 0, only the 2 existing warnings, 74/74 tests pass.

```bash
git add CLAUDE.md README.md
git commit -m "$(cat <<'EOF'
docs: Yara-X flavor architecture and deploy notes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```
