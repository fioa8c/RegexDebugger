# Yara-X Analysis (atoms, scan cost, suggestions, structure) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the Yara-X **Analysis** tab (scan-cost grade with raw numbers, the atoms Yara-X picks, what it verifies around them, rewrite suggestions and a byte-level structure breakdown), and color the Yara-X pattern with its chosen atom underlined.

**Architecture:** A pure TypeScript port of how Yara-X 1.21.0 chooses atoms runs in the browser, synchronously, on every edit: `parse.ts` (syntax tree + coloring tokens) → `hir.ts` (regex-syntax 0.8.11's normalized form) → `literal.ts` + `quality.ts` (literal extraction and atom scoring) → `atoms.ts` (Yara-X's five atom paths) → `cost.ts` / `advice.ts` / `describe.ts`, bundled by `analyze.ts`. The WebAssembly engine stays the authority on matches and errors; its `slow_pattern` warning is merged into the grade when it arrives. This plan merges the earlier Plans 2 and 3.

**Tech Stack:** React 19, TypeScript 6, Vite 8, Vitest 5 (node; jsdom per file), `@virustotal/yara-x` 1.21.0 (already installed, exact pin).

**Spec:** `docs/superpowers/specs/2026-10-15-yarax-flavor-design.md` (local only: specs are git-ignored on this machine). Sections used: "New modules", "Analysis tab", "Grade", "Verification extent", "Suggestions catalog", "Structure", "Errors and cross-checks", "Appendix: Yara-X reference facts".

**How this plan was made:** every file below was written and run in a throwaway copy of the repo first. The atom port was checked against a real `yr` 1.21.0 built with `--features debug-cmd`: all 91 compiling cases of the committed fixture match exactly (atom bytes and the `slow_pattern` verdict). The full gate passed on that copy (`tsc -b`, oxlint with only the 2 known warnings, 251 tests). The code blocks are those files, verbatim.

## Global Constraints

- `@virustotal/yara-x` stays pinned exactly at `1.21.0`; the port follows Yara-X tag `v1.21.0` (commit `7b2637d`) and `regex-syntax` `0.8.11`. Upgrading means bumping both and regenerating the fixture (`scripts/yarax/gen-atoms.mjs`).
- No new dependencies. The app never runs `yr`; only the fixture generator does, and only when the pin changes.
- JavaScript-flavor behavior is unchanged. Only Yara-X files, `src/index.css` (appended rules) and docs change.
- The analysis never waits for the engine: it renders from the pattern alone; the engine's `slow_pattern` warning is merged in when the scan finishes.
- The engine is the authority on validity: if it reports an error, the Analysis tab shows only the errors and their fixes. If `parse.ts` can't handle a pattern, the tab says it can't analyze it; it never guesses.
- Grade: **Slow** = Yara-X's slow_pattern conditions (port) or the engine's `slow_pattern` warning, labeled "Yara-X's rule". **Fast** = not Slow, weakest atom ≥ `FAST_MIN_QUALITY` (60) and both extents ≤ `FAST_MAX_EXTENT` (256 B), exact atoms counting 0 B; **OK** otherwise; both labeled "this tester's heuristic". Unbounded extents are capped at `SCAN_LIMIT` (4,096 B). `wide` doubles extents.
- Atom list: printable atoms in quotes, others as hex bytes; more than 16 atoms → first 16 (weakest first) + "… N more" + count by length.
- Code style: no semicolons, single quotes, 2-space indent; `erasableSyntaxOnly` is on, so no constructor parameter properties.
- Gate before every commit: `npx tsc -b` → `npx oxlint` (only the 2 existing `react(purity)` warnings in `App.tsx`) → `npx vitest run`.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Specs are never committed.

## Review Focus

1. **Typing speed on heavy patterns.** The analysis runs synchronously on each keystroke. A person pasting `[\x80-\xff]{4}`, `\d{4}-\d{2}` or a long alternation expects no visible lag. Pinned by `atoms.test.ts` "stays fast on patterns with many atoms" (Task 4); a reviewer should also try a few pathological patterns by hand in the browser.
2. **Inline-flag scoping.** `(?i)` mid-pattern, `(?-i:…)` groups and `(?U)` change atoms and descriptions. A person expects them scoped exactly like the engine. Pinned by `hir.test.ts` "scopes inline flags…" (Task 2) and fixture cases `a(?i)bc`, `(?i:ab)cd` (Task 4).
3. **Non-BMP text in patterns.** An emoji is 2 UTF-16 units but 4 UTF-8 bytes; the atom underline must cover whole characters. Pinned by `parse.test.ts` "keeps UTF-16 spans…" (Task 1) and `atoms.test.ts` "uses source spans in UTF-16 units" (Task 4).
4. **Engine still loading or unavailable.** The grade must render without the engine and must not claim drift. Pinned by `cost.test.ts` (null diags, Task 6) and `YaraAnalysis.test.tsx` "grades without waiting for the engine" (Task 8).
5. **Parser and engine disagreeing.** A pattern the engine rejects must show only its errors and fixes; one the parser can't model must say so. Pinned by `YaraAnalysis.test.tsx` (Task 8) and `analyze.test.ts` (Task 6). A reviewer should try patterns near the edges (`\b{start}`, `[[:^alpha:]]`, `a{,3}`, `\x{1F600}`) in the browser.

## Decisions this plan makes (not spelled out in the spec)

- The engine fixture `engine.json` from the spec is not added: Plan 1 already tests the real engine under Node (`engine.test.ts`).
- Fixture entries with more than 32 atoms store the count and a SHA-256 of the sorted hex list instead of the list, keeping the fixture at ~14 KB.
- The Matches/Analysis tab choice is local state in `YaraWorkbench` (it resets to Matches when switching flavors).
- The Verification section shows the pattern text from the start of the atom on (forward verification re-reads the atom, so a repetition inside its span counts as forward) and before it; the byte numbers live in the Scan cost lines. *(Changed after the final review: it first showed only the text after the atom, which hid `\s*` in `foo\s*bar`.)*
- Atom counts and the atom list include `wide` variants, since the engine searches for those too. Weakest/average quality, minimum length and the `short-atom`/`common-bytes` suggestions score the pattern's own atoms (shown as "without wide's 00 bytes"), and the verification tier uses the searched atoms. *(Changed after the final review: scoring the interleaved 00s made Fast unreachable under `wide` and always fired two suggestions the pattern can't act on; Yara-X's own slow rule also uses the plain atoms.)*

## File Structure

| File | Responsibility |
|---|---|
| `src/lib/yarax/parse.ts` (new) | Yara-X regex syntax → tree with source spans, and flat coloring tokens. Rejects (with a reason) what the engine rejects or this port doesn't model. |
| `src/lib/yarax/hir.ts` (new) | Port of regex-syntax's translator (Unicode off) and `Hir` smart constructors, with per-byte source spans. |
| `src/lib/yarax/literal.ts` (new) | Port of regex-syntax's literal `Seq` and prefix `Extractor` with Yara-X's limits. |
| `src/lib/yarax/quality.ts` (new) | Port of Yara-X's atom quality, best window search (plain and masked) and atom-set ordering. |
| `src/lib/yarax/atoms.ts` (new) | Port of Yara-X's atom choice: chaining, literals, masked literals, FastVM, PikeVM (Thompson); `wide`/`nocase` variants; verification extents; slow_pattern rule. |
| `src/lib/yarax/describe.ts` (new) | Byte-worded structure lines from the tree. |
| `src/lib/yarax/cost.ts` (new) | Tier, extents, grade, drift. |
| `src/lib/yarax/advice.ts` (new) | Suggestion catalog. |
| `src/lib/yarax/layer.ts` (new) | Merge coloring tokens with underline marks into non-overlapping highlighter spans. |
| `src/lib/yarax/analyze.ts` (new) | One call from pattern + options to tokens, atoms and structure; `costOf` adds the engine verdict. |
| `src/lib/yarax/__fixtures__/atoms.json` (new) | Reference atoms from `yr debug atoms` 1.21.0. |
| `scripts/yarax/gen-atoms.mjs` (new) | Regenerates the fixture from a `yr` binary. |
| `src/components/yarax/YaraAnalysis.tsx` (new) | The Analysis tab. |
| `src/components/yarax/YaraPatternPane.tsx` | Coloring and atom underline. |
| `src/components/yarax/YaraWorkbench.tsx` | Matches/Analysis tabs, analysis memo, grade badge. |
| `src/index.css` | `hl-atom` underline, `ya-*` and `grade-*` rules. |
| `CLAUDE.md`, `README.md` | Document the analysis. |

Task order follows the data flow; Tasks 1-4 deliver the atom port, Tasks 5-7 the analysis on top of it, Task 8 the UI, Task 9 the docs and the browser check.

---

### Task 0: Branch

- [ ] **Step 1: Work on `feat/yarax-analysis`**

This plan is committed on `feat/yarax-analysis`, branched from `main` at `d0ca719` (PR #3 merged).

```bash
git checkout feat/yarax-analysis
git status --short
npx vitest run
```

Expected: clean working tree; the existing suite passes (`Tests  95 passed`).

---

### Task 1: Parser and coloring tokens (`parse.ts`)

**Files:**
- Create: `src/lib/yarax/parse.ts`
- Test: `src/lib/yarax/__tests__/parse.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `parseYaraRegex(src: string): ParseResult` where `ParseResult = { ok: true; ast: Node; tokens: Token[] } | { ok: false; error: { message: string; span: Span } }`; types `Span {start, end}` (UTF-16 indices), `Node`, `ClassItem`, `AssertKind`, `PerlKind`, `FlagChange {on, off}`, `Token {kind: TokenKind, start, end}`, `TokenKind = 'literal' | 'escape' | 'dot' | 'meta' | 'anchor' | 'class' | 'quant' | 'group' | 'non' | 'alt'`. Group nodes carry `index` (1-based capture number, 0 when not capturing). `\xHH` chars have `byte: true`; `\<` `\>` are literal chars.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest'
import { parseYaraRegex, type Node } from '../parse'

function ast(src: string): Node {
  const r = parseYaraRegex(src)
  if (!r.ok) throw new Error(r.error.message)
  return r.ast
}

function err(src: string) {
  const r = parseYaraRegex(src)
  if (r.ok) throw new Error('expected an error')
  return r.error
}

describe('parseYaraRegex', () => {
  it('parses a concatenation of characters, escapes and quantifiers with spans', () => {
    const n = ast('ab\\s*')
    expect(n.kind).toBe('concat')
    if (n.kind !== 'concat') return
    expect(n.items.map((i) => i.kind)).toEqual(['char', 'char', 'repeat'])
    const rep = n.items[2]
    expect(rep).toMatchObject({ kind: 'repeat', min: 0, max: null, greedy: true, span: { start: 2, end: 5 }, opSpan: { start: 4, end: 5 } })
  })

  it('reads counted repetitions, including {,n} and lazy forms', () => {
    const q = (src: string) => {
      const n = ast(src)
      return n.kind === 'repeat' ? [n.min, n.max, n.greedy] : null
    }
    expect(q('a{3}')).toEqual([3, 3, true])
    expect(q('a{3,}')).toEqual([3, null, true])
    expect(q('a{2,5}?')).toEqual([2, 5, false])
    expect(q('a{,4}')).toEqual([0, 4, true])
    expect(q('a+?')).toEqual([1, null, false])
  })

  it('treats \\xHH as a raw byte and \\x{..} as a code point', () => {
    expect(ast('\\xE9')).toMatchObject({ kind: 'char', cp: 0xe9, byte: true })
    expect(ast('\\x{E9}')).toMatchObject({ kind: 'char', cp: 0xe9, byte: false })
    expect(ast('é')).toMatchObject({ kind: 'char', cp: 0xe9, byte: false, escaped: false })
  })

  it('reads \\< and \\> as literal angle brackets', () => {
    expect(ast('\\<')).toMatchObject({ kind: 'char', cp: 0x3c, escaped: true })
    expect(ast('\\>')).toMatchObject({ kind: 'char', cp: 0x3e, escaped: true })
  })

  it('parses groups, named groups, flag groups and inline flags', () => {
    expect(ast('(a)')).toMatchObject({ kind: 'group', capture: true, index: 1, name: null })
    expect(ast('(?P<x>a)')).toMatchObject({ kind: 'group', capture: true, name: 'x' })
    expect(ast('(?<x>a)')).toMatchObject({ kind: 'group', capture: true, name: 'x' })
    expect(ast('(?:a)')).toMatchObject({ kind: 'group', capture: false, flags: null })
    expect(ast('(?i-s:a)')).toMatchObject({ kind: 'group', capture: false, flags: { on: 'i', off: 's' } })
    expect(ast('(?m)')).toMatchObject({ kind: 'flags', flags: { on: 'm', off: '' } })
  })

  it('parses classes with ranges, negation, perl and ASCII classes', () => {
    const n = ast('[^a-f\\d[:space:]]')
    expect(n).toMatchObject({ kind: 'class', negated: true })
    if (n.kind !== 'class') return
    expect(n.items.map((i) => i.kind)).toEqual(['range', 'perl', 'ascii'])
    expect(ast('[]a]')).toMatchObject({ kind: 'class', items: [{ kind: 'char', cp: 0x5d }, { kind: 'char', cp: 0x61 }] })
    expect(ast('[a-]')).toMatchObject({ kind: 'class', items: [{ kind: 'char' }, { kind: 'char', cp: 0x2d }] })
  })

  it('records alternation bars', () => {
    expect(ast('ab|c|d')).toMatchObject({ kind: 'alt', bars: [2, 4] })
  })

  it('keeps UTF-16 spans for characters outside the BMP', () => {
    const n = ast('😀a')
    expect(n).toMatchObject({ kind: 'concat', items: [{ span: { start: 0, end: 2 } }, { span: { start: 2, end: 3 } }] })
  })

  it('rejects what the engine rejects, or what this tester does not model', () => {
    expect(err('foo{').message).toBe('unclosed counted repetition')
    expect(err('(?=a)').message).toMatch(/look-around/)
    expect(err('\\1').message).toMatch(/backreferences/)
    expect(err('\\p{L}').message).toBe('Unicode not allowed here')
    expect(err('[é]').message).toBe('Unicode not allowed here')
    expect(err('[z-a]').message).toMatch(/invalid character class range/)
    expect(err('*a').message).toMatch(/missing expression/)
    expect(err('(?u)a').message).toMatch(/Unicode mode/)
    expect(err('(?x)a').message).toMatch(/not analyzed/)
    expect(err('[a&&b]').message).toMatch(/set operations/)
    expect(err('(a').message).toBe('unclosed group')
    expect(err('a)').message).toBe('unopened group')
    expect(err('\\q').message).toBe('unrecognized escape sequence')
  })

  it('produces coloring tokens', () => {
    const r = parseYaraRegex('(a|\\d)+.^')
    if (!r.ok) throw new Error()
    expect(r.tokens.map((t) => [t.kind, t.start, t.end])).toEqual([
      ['group', 0, 1],
      ['literal', 1, 2],
      ['alt', 2, 3],
      ['meta', 3, 5],
      ['group', 5, 6],
      ['quant', 6, 7],
      ['dot', 7, 8],
      ['anchor', 8, 9],
    ])
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/lib/yarax/__tests__/parse.test.ts`
Expected: FAIL — `Failed to resolve import "../parse"`.

- [ ] **Step 3: Write the implementation**

```ts
// Parser for the Yara-X regex syntax (regex-syntax 0.8 with Unicode off).
// Produces a tree with source spans plus flat tokens for syntax coloring.
// Anything it can't model faithfully is an error: the analysis then says it
// can't analyze the pattern instead of guessing. The engine stays the
// authority on validity.

export interface Span {
  start: number
  end: number
}

export type AssertKind =
  | 'start-line'
  | 'end-line'
  | 'start-text'
  | 'end-text'
  | 'word'
  | 'not-word'
  | 'word-start'
  | 'word-end'
  | 'word-start-half'
  | 'word-end-half'

export type PerlKind = 'd' | 's' | 'w'

export interface FlagChange {
  on: string
  off: string
}

export type ClassItem =
  | { kind: 'char'; span: Span; cp: number; byte: boolean }
  | { kind: 'range'; span: Span; lo: number; hi: number }
  | { kind: 'perl'; span: Span; which: PerlKind; negated: boolean }
  | { kind: 'ascii'; span: Span; name: string; negated: boolean }
  | { kind: 'bracket'; span: Span; negated: boolean; items: ClassItem[] }

export type Node =
  | { kind: 'empty'; span: Span }
  | { kind: 'char'; span: Span; cp: number; byte: boolean; escaped: boolean }
  | { kind: 'dot'; span: Span }
  | { kind: 'assert'; span: Span; which: AssertKind }
  | { kind: 'perl'; span: Span; which: PerlKind; negated: boolean }
  | { kind: 'class'; span: Span; negated: boolean; items: ClassItem[] }
  | { kind: 'repeat'; span: Span; opSpan: Span; min: number; max: number | null; greedy: boolean; sub: Node }
  | { kind: 'group'; span: Span; capture: boolean; index: number; name: string | null; flags: FlagChange | null; sub: Node }
  | { kind: 'flags'; span: Span; flags: FlagChange }
  | { kind: 'concat'; span: Span; items: Node[] }
  | { kind: 'alt'; span: Span; items: Node[]; bars: number[] }

export type TokenKind = 'literal' | 'escape' | 'dot' | 'meta' | 'anchor' | 'class' | 'quant' | 'group' | 'non' | 'alt'

export interface Token {
  kind: TokenKind
  start: number
  end: number
}

export interface ParseError {
  message: string
  span: Span
}

export type ParseResult =
  | { ok: true; ast: Node; tokens: Token[] }
  | { ok: false; error: ParseError }

const ASCII_CLASSES = new Set([
  'alnum', 'alpha', 'ascii', 'blank', 'cntrl', 'digit', 'graph',
  'lower', 'print', 'punct', 'space', 'upper', 'word', 'xdigit',
])

const SIMPLE_ESCAPES: Record<string, number> = { a: 7, f: 12, t: 9, n: 10, r: 13, v: 11 }

class Fail extends Error {
  readonly perr: ParseError

  constructor(perr: ParseError) {
    super(perr.message)
    this.perr = perr
  }
}

function isHex(c: string): boolean {
  return /^[0-9a-fA-F]$/.test(c)
}

// regex-syntax allows escaping any ASCII character that isn't a letter, a
// digit, `<` or `>` (those two are word-boundary escapes).
function isEscapablePunct(c: string): boolean {
  if (c.length !== 1 || c.charCodeAt(0) > 0x7f) return false
  return !/[0-9A-Za-z<>]/.test(c)
}

class Parser {
  pos = 0
  captures = 0
  readonly src: string

  constructor(src: string) {
    this.src = src
  }

  fail(message: string, start: number, end = start + 1): never {
    throw new Fail({ message, span: { start, end: Math.min(Math.max(end, start), this.src.length) } })
  }

  peek(offset = 0): string {
    const cp = this.src.codePointAt(this.pos + offset)
    return cp === undefined ? '' : String.fromCodePoint(cp)
  }

  eof(): boolean {
    return this.pos >= this.src.length
  }

  bump(): string {
    const c = this.peek()
    this.pos += c.length
    return c
  }

  parseAlt(): Node {
    const start = this.pos
    const items: Node[] = [this.parseConcat()]
    const bars: number[] = []
    while (this.peek() === '|') {
      bars.push(this.pos)
      this.bump()
      items.push(this.parseConcat())
    }
    if (items.length === 1) return items[0]
    return { kind: 'alt', span: { start, end: this.pos }, items, bars }
  }

  parseConcat(): Node {
    const start = this.pos
    const items: Node[] = []
    while (!this.eof()) {
      const c = this.peek()
      if (c === '|' || c === ')') break
      if (c === '*' || c === '+' || c === '?' || c === '{') {
        const prev = items.pop()
        if (!prev || prev.kind === 'flags' || prev.kind === 'empty') {
          this.fail('repetition operator missing expression', this.pos)
        }
        items.push(this.parseRepeat(prev))
        continue
      }
      items.push(this.parseAtom())
    }
    if (items.length === 0) return { kind: 'empty', span: { start, end: start } }
    if (items.length === 1) return items[0]
    return { kind: 'concat', span: { start, end: this.pos }, items }
  }

  parseRepeat(sub: Node): Node {
    const opStart = this.pos
    const c = this.bump()
    let min: number
    let max: number | null
    if (c === '*') [min, max] = [0, null]
    else if (c === '+') [min, max] = [1, null]
    else if (c === '?') [min, max] = [0, 1]
    else {
      const m = /^\{(\d*)(,(\d*))?\}/.exec(this.src.slice(opStart))
      if (!m || (m[1] === '' && m[2] === undefined) || (m[1] === '' && m[3] === '')) {
        this.fail('unclosed counted repetition', opStart, this.src.indexOf('}', opStart) + 1 || this.src.length)
      }
      min = m[1] === '' ? 0 : Number(m[1])
      max = m[2] === undefined ? min : m[3] === '' ? null : Number(m[3])
      if (max !== null && min > max) this.fail('invalid repetition count range, the start must be <= the end', opStart, opStart + m[0].length)
      this.pos = opStart + m[0].length
    }
    let greedy = true
    if (this.peek() === '?') {
      greedy = false
      this.bump()
    }
    const opSpan = { start: opStart, end: this.pos }
    return { kind: 'repeat', span: { start: sub.span.start, end: this.pos }, opSpan, min, max, greedy, sub }
  }

  parseAtom(): Node {
    const start = this.pos
    const c = this.peek()
    if (c === '(') return this.parseGroup()
    if (c === '[') return this.parseClass()
    if (c === '\\') return this.parseEscape(false)
    this.bump()
    const span = { start, end: this.pos }
    if (c === '.') return { kind: 'dot', span }
    if (c === '^') return { kind: 'assert', span, which: 'start-line' }
    if (c === '$') return { kind: 'assert', span, which: 'end-line' }
    return { kind: 'char', span, cp: c.codePointAt(0)!, byte: false, escaped: false }
  }

  parseFlags(): FlagChange {
    let on = ''
    let off = ''
    let neg = false
    while (!this.eof() && this.peek() !== ')' && this.peek() !== ':') {
      const at = this.pos
      const f = this.bump()
      if (f === '-') {
        if (neg) this.fail('duplicate negation flag', at)
        neg = true
        continue
      }
      if (f === 'u') this.fail('Unicode mode (?u) is not analyzed: it crashes the Yara-X engine', at)
      if (f === 'x' || f === 'R') this.fail(`the (?${f}) flag is not analyzed`, at)
      if (!'imsU'.includes(f)) this.fail('unrecognized flag', at)
      if (on.includes(f) || off.includes(f)) this.fail('duplicate flag', at)
      if (neg) off += f
      else on += f
    }
    if (this.eof()) this.fail('unclosed group', this.pos - 1)
    return { on, off }
  }

  parseGroup(): Node {
    const start = this.pos
    this.bump()
    let capture = true
    let name: string | null = null
    let flags: FlagChange | null = null
    if (this.peek() === '?') {
      this.bump()
      const rest = this.src.slice(this.pos)
      if (/^(=|!|<=|<!)/.test(rest)) this.fail('look-around, including look-ahead and look-behind, is not supported', start, this.pos + 2)
      const named = /^(P?<)([_0-9A-Za-z.[\]]+)>/.exec(rest)
      if (named) {
        if (!/^[_A-Za-z]/.test(named[2])) this.fail('invalid capture group name', this.pos + named[1].length)
        name = named[2]
        this.pos += named[0].length
      } else {
        capture = false
        flags = this.parseFlags()
        if (this.peek() === ')') {
          this.bump()
          return { kind: 'flags', span: { start, end: this.pos }, flags }
        }
        this.bump() // ':'
        if (flags.on === '' && flags.off === '') flags = null
      }
    }
    const index = capture ? ++this.captures : 0
    const sub = this.parseAlt()
    if (this.peek() !== ')') this.fail('unclosed group', start)
    this.bump()
    return { kind: 'group', span: { start, end: this.pos }, capture, index, name, flags, sub }
  }

  // Parses `\x..`, `\u..`, `\U..`; returns the code point and whether it is
  // the fixed two-digit `\xHH` form (the only form that is a raw byte).
  parseHex(start: number, letter: string): { cp: number; byte: boolean } {
    const digits = letter === 'x' ? 2 : letter === 'u' ? 4 : 8
    if (this.peek() === '{') {
      this.bump()
      const close = this.src.indexOf('}', this.pos)
      const hex = close < 0 ? '' : this.src.slice(this.pos, close)
      if (close < 0 || hex === '' || hex.length > 8 || ![...hex].every(isHex)) {
        this.fail('invalid hexadecimal escape', start, close < 0 ? this.src.length : close + 1)
      }
      this.pos = close + 1
      const cp = parseInt(hex, 16)
      if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) this.fail('invalid Unicode scalar value', start, this.pos)
      return { cp, byte: false }
    }
    const hex = this.src.slice(this.pos, this.pos + digits)
    if (hex.length !== digits || ![...hex].every(isHex)) this.fail('invalid hexadecimal escape', start, this.pos + digits)
    this.pos += digits
    const cp = parseInt(hex, 16)
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) this.fail('invalid Unicode scalar value', start, this.pos)
    return { cp, byte: letter === 'x' }
  }

  parseEscape(inClass: boolean): Node {
    const start = this.pos
    this.bump()
    if (this.eof()) this.fail('incomplete escape sequence', start)
    const c = this.bump()
    const span = () => ({ start, end: this.pos })
    if (c in SIMPLE_ESCAPES) return { kind: 'char', span: span(), cp: SIMPLE_ESCAPES[c], byte: false, escaped: true }
    if (c === 'x' || c === 'u' || c === 'U') {
      const { cp, byte } = this.parseHex(start, c)
      return { kind: 'char', span: span(), cp, byte, escaped: true }
    }
    if (c === 'd' || c === 's' || c === 'w') return { kind: 'perl', span: span(), which: c, negated: false }
    if (c === 'D' || c === 'S' || c === 'W') {
      return { kind: 'perl', span: span(), which: c.toLowerCase() as PerlKind, negated: true }
    }
    if (c === 'p' || c === 'P') this.fail('Unicode not allowed here', start, this.pos)
    if (/[0-9]/.test(c)) this.fail('backreferences are not supported', start, this.pos)
    if (!inClass) {
      if (c === '<' || c === '>') return { kind: 'char', span: span(), cp: c.codePointAt(0)!, byte: false, escaped: true }
      if (c === 'A') return { kind: 'assert', span: span(), which: 'start-text' }
      if (c === 'z') return { kind: 'assert', span: span(), which: 'end-text' }
      if (c === 'B') return { kind: 'assert', span: span(), which: 'not-word' }
      if (c === 'b') {
        const m = /^\{(start|end|start-half|end-half)\}/.exec(this.src.slice(this.pos))
        if (!m) return { kind: 'assert', span: span(), which: 'word' }
        this.pos += m[0].length
        const which: AssertKind =
          m[1] === 'start' ? 'word-start' : m[1] === 'end' ? 'word-end' : m[1] === 'start-half' ? 'word-start-half' : 'word-end-half'
        return { kind: 'assert', span: span(), which }
      }
    }
    if (isEscapablePunct(c)) return { kind: 'char', span: span(), cp: c.codePointAt(0)!, byte: false, escaped: true }
    return this.fail('unrecognized escape sequence', start, this.pos)
  }

  parseClass(): Node {
    const start = this.pos
    const { negated, items } = this.parseBracket()
    return { kind: 'class', span: { start, end: this.pos }, negated, items }
  }

  parseBracket(): { negated: boolean; items: ClassItem[] } {
    const open = this.pos
    this.bump() // '['
    let negated = false
    if (this.peek() === '^') {
      negated = true
      this.bump()
    }
    const items: ClassItem[] = []
    let first = true
    for (;;) {
      if (this.eof()) this.fail('unclosed character class', open)
      const c = this.peek()
      if (c === ']' && !first) {
        this.bump()
        break
      }
      if (!first && (this.src.startsWith('&&', this.pos) || this.src.startsWith('--', this.pos) || this.src.startsWith('~~', this.pos))) {
        this.fail('character class set operations are not analyzed', this.pos, this.pos + 2)
      }
      first = false
      if (c === '[') {
        const ascii = /^\[:(\^?)([a-z]+):\]/.exec(this.src.slice(this.pos))
        if (ascii) {
          if (!ASCII_CLASSES.has(ascii[2])) this.fail('invalid ASCII class name', this.pos, this.pos + ascii[0].length)
          items.push({ kind: 'ascii', span: { start: this.pos, end: this.pos + ascii[0].length }, name: ascii[2], negated: ascii[1] === '^' })
          this.pos += ascii[0].length
          continue
        }
        const nestedStart = this.pos
        const nested = this.parseBracket()
        items.push({ kind: 'bracket', span: { start: nestedStart, end: this.pos }, ...nested })
        continue
      }
      const lo = this.classAtom()
      if (lo.kind === 'char' && this.peek() === '-' && this.peek(1) !== ']' && this.peek(1) !== '') {
        this.bump()
        const hi = this.classAtom()
        if (hi.kind !== 'char') this.fail('invalid character class range', lo.span.start, hi.span.end)
        const loB = this.classByte(lo)
        const hiB = this.classByte(hi)
        if (loB > hiB) this.fail('invalid character class range, the start must be <= the end', lo.span.start, hi.span.end)
        items.push({ kind: 'range', span: { start: lo.span.start, end: hi.span.end }, lo: loB, hi: hiB })
        continue
      }
      if (lo.kind === 'char') this.classByte(lo)
      items.push(lo)
    }
    return { negated, items }
  }

  classAtom(): Extract<ClassItem, { kind: 'char' | 'perl' }> {
    const start = this.pos
    if (this.peek() === '\\') {
      const n = this.parseEscape(true)
      if (n.kind === 'perl') return { kind: 'perl', span: n.span, which: n.which, negated: n.negated }
      if (n.kind === 'char') return { kind: 'char', span: n.span, cp: n.cp, byte: n.byte }
      return this.fail('unrecognized escape sequence', start, this.pos)
    }
    const c = this.bump()
    return { kind: 'char', span: { start, end: this.pos }, cp: c.codePointAt(0)!, byte: false }
  }

  // With Unicode off a class item must be ASCII or a `\xHH` byte escape.
  classByte(item: { cp: number; byte: boolean; span: Span }): number {
    if (item.cp <= 0x7f || item.byte) return item.cp
    return this.fail('Unicode not allowed here', item.span.start, item.span.end)
  }
}

function collectTokens(node: Node, out: Token[]): void {
  const push = (kind: TokenKind, start: number, end: number) => {
    if (end > start) out.push({ kind, start, end })
  }
  switch (node.kind) {
    case 'empty':
      return
    case 'char':
      push(node.escaped ? 'escape' : 'literal', node.span.start, node.span.end)
      return
    case 'dot':
      push('dot', node.span.start, node.span.end)
      return
    case 'perl':
      push('meta', node.span.start, node.span.end)
      return
    case 'assert':
      push('anchor', node.span.start, node.span.end)
      return
    case 'class':
      push('class', node.span.start, node.span.end)
      return
    case 'flags':
      push('non', node.span.start, node.span.end)
      return
    case 'repeat':
      collectTokens(node.sub, out)
      push('quant', node.opSpan.start, node.opSpan.end)
      return
    case 'group': {
      const kind = node.capture ? 'group' : 'non'
      push(kind, node.span.start, node.sub.span.start)
      collectTokens(node.sub, out)
      push(kind, node.span.end - 1, node.span.end)
      return
    }
    case 'concat':
      for (const n of node.items) collectTokens(n, out)
      return
    case 'alt':
      node.items.forEach((n, i) => {
        collectTokens(n, out)
        if (i < node.bars.length) push('alt', node.bars[i], node.bars[i] + 1)
      })
      return
  }
}

export function parseYaraRegex(src: string): ParseResult {
  const p = new Parser(src)
  try {
    const ast = p.parseAlt()
    if (!p.eof()) p.fail('unopened group', p.pos)
    const tokens: Token[] = []
    collectTokens(ast, tokens)
    return { ok: true, ast, tokens }
  } catch (e) {
    if (e instanceof Fail) return { ok: false, error: e.perr }
    throw e
  }
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `npx vitest run src/lib/yarax/__tests__/parse.test.ts`
Expected: PASS, 10 tests.

- [ ] **Step 5: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add src/lib/yarax/parse.ts src/lib/yarax/__tests__/parse.test.ts
git commit -m "feat(yarax): parse Yara-X regexes into a spanned tree and coloring tokens

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Normalized byte-level form (`hir.ts`)

**Files:**
- Create: `src/lib/yarax/hir.ts`
- Test: `src/lib/yarax/__tests__/hir.test.ts`

**Interfaces:**
- Consumes: `Node`, `ClassItem`, `AssertKind`, `Span` from Task 1.
- Produces: `translate(ast: Node, flags: { i: boolean; s: boolean }): Hir`; type `Hir` (kinds `empty | lit | class | look | rep | cap | cat | alt`, each with `p: Props {minLen, maxLen, hasLook, literal, altLiteral}`; `lit` has `bytes: number[]` and per-byte `src: Span[]`; `class` has `unicode: boolean` and `ranges: [number, number][]`); constructors `concat`, `repetition`, `alternation`, `cls`, `literal`, `look`, `capture`, `empty`; helpers `hirSpan(h): Span | null`, `hirEqual`, `utf8(cp): number[]`, `canonical`, `negateBytes`, `classCount`. `i` here means "case-insensitive" (the `i` suffix or `nocase`).

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest'
import { parseYaraRegex } from '../parse'
import { translate, type Hir } from '../hir'

function hir(src: string, flags = { i: false, s: false }): Hir {
  const r = parseYaraRegex(src)
  if (!r.ok) throw new Error(r.error.message)
  return translate(r.ast, flags)
}

// A compact, span-free rendering of a HIR for assertions.
function show(h: Hir): string {
  const hex = (b: number) => b.toString(16).padStart(2, '0')
  switch (h.k) {
    case 'empty':
      return 'ε'
    case 'lit':
      return `"${h.bytes.map(hex).join(' ')}"`
    case 'class':
      return `${h.unicode ? 'U' : 'B'}[${h.ranges.map(([a, b]) => (a === b ? hex(a) : `${hex(a)}-${hex(b)}`)).join(',')}]`
    case 'look':
      return `look(${h.look})`
    case 'rep':
      return `rep{${h.min},${h.max ?? ''}${h.greedy ? '' : '?'}}(${show(h.sub)})`
    case 'cap':
      return `cap${h.index}(${show(h.sub)})`
    case 'cat':
      return `cat(${h.subs.map(show).join(' ')})`
    case 'alt':
      return `alt(${h.subs.map(show).join(' | ')})`
  }
}

describe('translate', () => {
  it('merges adjacent characters into one literal and encodes UTF-8', () => {
    expect(show(hir('ab\\x41é'))).toBe('"61 62 41 c3 a9"')
    expect(show(hir('\\xE9'))).toBe('"e9"')
  })

  it('keeps per-byte source spans on literals', () => {
    const h = hir('aé')
    expect(h.k === 'lit' && h.src).toEqual([
      { start: 0, end: 1 },
      { start: 1, end: 2 },
      { start: 1, end: 2 },
    ])
  })

  it('folds ASCII letters into two-byte classes when case-insensitive', () => {
    expect(show(hir('a1', { i: true, s: false }))).toBe('cat(B[41,61] "31")')
    expect(show(hir('a(?-i)b', { i: true, s: false }))).toBe('cat(B[41,61] "62")')
    expect(show(hir('[a-c]', { i: true, s: false }))).toBe('B[41-43,61-63]')
  })

  it('scopes inline flags to their group and swaps greed under (?U)', () => {
    expect(show(hir('(?i)a(?-i:b)c'))).toBe('cat(B[41,61] "62" B[43,63])')
    expect(show(hir('(?U)a*b+?'))).toBe('cat(rep{0,?}("61") rep{1,}("62"))')
  })

  it('maps . to any byte but \\n, or to any byte under s', () => {
    expect(show(hir('.'))).toBe('B[00-09,0b-ff]')
    expect(show(hir('.', { i: false, s: true }))).toBe('B[00-ff]')
  })

  it('maps ^ and $ to the data ends unless (?m)', () => {
    expect(show(hir('^a$'))).toBe('cat(look(start-text) "61" look(end-text))')
    expect(show(hir('(?m)^a'))).toBe('cat(look(start-line) "61")')
  })

  it('drops non-capturing groups and keeps captures', () => {
    expect(show(hir('(?:ab)(c)'))).toBe('cat("61 62" cap1("63"))')
  })

  it('folds alternations of single characters into classes', () => {
    expect(show(hir('a|b'))).toBe('U[61-62]')
    expect(show(hir('\\xFF|a'))).toBe('B[61,ff]')
    expect(show(hir('[ab]|[cd]'))).toBe('U[61-64]')
  })

  it('lifts a common prefix out of an alternation of concatenations', () => {
    expect(show(hir('ab[cx]|ab[dy]'))).toBe('cat("61 62" U[63-64,78-79])')
    // Plain literals are not concatenations, so nothing is lifted.
    expect(show(hir('abc|abd'))).toBe('alt("61 62 63" | "61 62 64")')
  })

  it('simplifies repetitions', () => {
    expect(show(hir('a{1}'))).toBe('"61"')
    expect(show(hir('a{0}b'))).toBe('"62"')
    expect(show(hir('a*?'))).toBe('rep{0,?}("61")')
  })

  it('computes minimum and maximum lengths', () => {
    expect(hir('ab{2,5}c').p).toMatchObject({ minLen: 4, maxLen: 7 })
    expect(hir('a+').p).toMatchObject({ minLen: 1, maxLen: null })
    expect(hir('a*').p.minLen).toBe(0)
    expect(hir('\\ba').p.hasLook).toBe(true)
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/lib/yarax/__tests__/hir.test.ts`
Expected: FAIL — `Failed to resolve import "../hir"`.

- [ ] **Step 3: Write the implementation**

```ts
// The normalized byte-level form Yara-X compiles: a port of regex-syntax
// 0.8.11's translator (Unicode off, UTF-8 off) and its `Hir` smart
// constructors, which merge literals, fold single-character alternations
// into classes and lift common prefixes. Atom extraction depends on that
// exact shape, so the port follows the Rust code closely.

import type { AssertKind, ClassItem, Node, Span } from './parse'

export type Range = [number, number]

export interface Props {
  minLen: number | null
  maxLen: number | null
  // True when the node contains an assertion (`^`, `$`, `\b`, ...).
  hasLook: boolean
  literal: boolean
  altLiteral: boolean
}

export type Hir =
  | { k: 'empty'; p: Props }
  | { k: 'lit'; bytes: number[]; src: Span[]; p: Props }
  | { k: 'class'; unicode: boolean; ranges: Range[]; span: Span | null; p: Props }
  | { k: 'look'; look: AssertKind; span: Span; p: Props }
  | { k: 'rep'; min: number; max: number | null; greedy: boolean; sub: Hir; span: Span | null; p: Props }
  | { k: 'cap'; index: number; name: string | null; sub: Hir; span: Span; p: Props }
  | { k: 'cat'; subs: Hir[]; p: Props }
  | { k: 'alt'; subs: Hir[]; p: Props }

export interface HirFlags {
  i: boolean
  m: boolean
  s: boolean
  U: boolean
}

// ---------------------------------------------------------------- bytes

export function utf8(cp: number): number[] {
  if (cp < 0x80) return [cp]
  if (cp < 0x800) return [0xc0 | (cp >> 6), 0x80 | (cp & 0x3f)]
  if (cp < 0x10000) return [0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f)]
  return [0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f)]
}

function utf8Len(cp: number): number {
  return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4
}

// Decodes bytes that hold exactly one UTF-8 scalar value, or returns null.
function decodeSingle(bytes: number[]): number | null {
  try {
    const s = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes))
    const cp = s.codePointAt(0)
    if (cp === undefined || String.fromCodePoint(cp).length !== s.length) return null
    return utf8Len(cp) === bytes.length ? cp : null
  } catch {
    return null
  }
}

// ---------------------------------------------------------------- classes

// Sorts and merges overlapping or adjacent ranges, like regex-syntax's
// `IntervalSet` canonical form.
export function canonical(ranges: Range[]): Range[] {
  const sorted = ranges.map((r): Range => [Math.min(r[0], r[1]), Math.max(r[0], r[1])]).sort((a, b) => a[0] - b[0] || a[1] - b[1])
  const out: Range[] = []
  for (const r of sorted) {
    const last = out[out.length - 1]
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1])
    else out.push([r[0], r[1]])
  }
  return out
}

export function negateBytes(ranges: Range[]): Range[] {
  const out: Range[] = []
  let next = 0
  for (const [lo, hi] of canonical(ranges)) {
    if (lo > next) out.push([next, lo - 1])
    next = hi + 1
  }
  if (next <= 0xff) out.push([next, 0xff])
  return out
}

function caseFoldBytes(ranges: Range[]): Range[] {
  const extra: Range[] = []
  for (const [lo, hi] of ranges) {
    for (let b = lo; b <= hi; b++) {
      if (b >= 0x41 && b <= 0x5a) extra.push([b + 32, b + 32])
      else if (b >= 0x61 && b <= 0x7a) extra.push([b - 32, b - 32])
    }
  }
  return canonical([...ranges, ...extra])
}

export function classCount(ranges: Range[]): number {
  return ranges.reduce((n, [lo, hi]) => n + hi - lo + 1, 0)
}

const PERL: Record<'d' | 's' | 'w', Range[]> = {
  d: [[0x30, 0x39]],
  s: [[0x09, 0x0d], [0x20, 0x20]],
  w: [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]],
}

const ASCII: Record<string, Range[]> = {
  alnum: [[0x30, 0x39], [0x41, 0x5a], [0x61, 0x7a]],
  alpha: [[0x41, 0x5a], [0x61, 0x7a]],
  ascii: [[0x00, 0x7f]],
  blank: [[0x09, 0x09], [0x20, 0x20]],
  cntrl: [[0x00, 0x1f], [0x7f, 0x7f]],
  digit: [[0x30, 0x39]],
  graph: [[0x21, 0x7e]],
  lower: [[0x61, 0x7a]],
  print: [[0x20, 0x7e]],
  punct: [[0x21, 0x2f], [0x3a, 0x40], [0x5b, 0x60], [0x7b, 0x7e]],
  space: [[0x09, 0x0d], [0x20, 0x20]],
  upper: [[0x41, 0x5a]],
  word: [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]],
  xdigit: [[0x30, 0x39], [0x41, 0x46], [0x61, 0x66]],
}

// ---------------------------------------------------------------- props

function props(minLen: number | null, maxLen: number | null, hasLook: boolean, literal = false, altLiteral = false): Props {
  return { minLen, maxLen, hasLook, literal, altLiteral }
}

function classProps(unicode: boolean, ranges: Range[]): Props {
  if (ranges.length === 0) return props(null, null, false)
  if (!unicode) return props(1, 1, false)
  return props(utf8Len(ranges[0][0]), utf8Len(ranges[ranges.length - 1][1]), false)
}

// ---------------------------------------------------------------- constructors

export function empty(): Hir {
  return { k: 'empty', p: props(0, 0, false) }
}

export function literal(bytes: number[], src: Span[]): Hir {
  if (bytes.length === 0) return empty()
  return { k: 'lit', bytes, src, p: props(bytes.length, bytes.length, false, true, true) }
}

export function cls(unicode: boolean, ranges: Range[], span: Span | null): Hir {
  const rs = canonical(ranges)
  if (rs.length === 0) return { k: 'class', unicode: false, ranges: [], span, p: classProps(false, []) }
  if (rs.length === 1 && rs[0][0] === rs[0][1]) {
    const bytes = unicode ? utf8(rs[0][0]) : [rs[0][0]]
    return literal(bytes, bytes.map(() => span ?? { start: 0, end: 0 }))
  }
  return { k: 'class', unicode, ranges: rs, span, p: classProps(unicode, rs) }
}

export function look(which: AssertKind, span: Span): Hir {
  return { k: 'look', look: which, span, p: props(0, 0, true) }
}

export function repetition(min: number, max: number | null, greedy: boolean, sub: Hir, span: Span | null): Hir {
  if (sub.p.maxLen === 0) {
    min = Math.min(min, 1)
    max = max === null ? 1 : Math.min(max, 1)
  }
  if (min === 0 && max === 0) return empty()
  if (min === 1 && max === 1) return sub
  const minLen = sub.p.minLen === null ? null : sub.p.minLen * min
  const maxLen = max === null || sub.p.maxLen === null ? null : sub.p.maxLen * max
  return { k: 'rep', min, max, greedy, sub, span, p: props(minLen, maxLen, sub.p.hasLook) }
}

export function capture(index: number, name: string | null, sub: Hir, span: Span): Hir {
  return { k: 'cap', index, name, sub, span, p: { ...sub.p, literal: false, altLiteral: false } }
}

export function concat(subs: Hir[]): Hir {
  const out: Hir[] = []
  let prior: { bytes: number[]; src: Span[] } | null = null
  const flush = () => {
    if (prior) out.push(literal(prior.bytes, prior.src))
    prior = null
  }
  const add = (h: Hir) => {
    if (h.k === 'lit') {
      if (prior) {
        prior.bytes.push(...h.bytes)
        prior.src.push(...h.src)
      } else prior = { bytes: [...h.bytes], src: [...h.src] }
    } else if (h.k !== 'empty') {
      flush()
      out.push(h)
    }
  }
  for (const s of subs) {
    if (s.k === 'cat') s.subs.forEach(add)
    else add(s)
  }
  flush()
  if (out.length === 0) return empty()
  if (out.length === 1) return out[0]
  let minLen: number | null = 0
  let maxLen: number | null = 0
  let hasLook = false
  let lit = true
  let altLit = true
  for (const h of out) {
    hasLook ||= h.p.hasLook
    lit &&= h.p.literal
    altLit &&= h.p.altLiteral
    minLen = minLen === null || h.p.minLen === null ? null : minLen + h.p.minLen
    maxLen = maxLen === null || h.p.maxLen === null ? null : maxLen + h.p.maxLen
  }
  return { k: 'cat', subs: out, p: props(minLen, maxLen, hasLook, lit, altLit) }
}

// Source span of a node: the union of everything it was built from.
export function hirSpan(h: Hir): Span | null {
  switch (h.k) {
    case 'empty':
      return null
    case 'lit':
      return { start: Math.min(...h.src.map((s) => s.start)), end: Math.max(...h.src.map((s) => s.end)) }
    case 'class':
    case 'look':
    case 'rep':
    case 'cap':
      return h.span
    case 'cat':
    case 'alt': {
      const spans = h.subs.map(hirSpan).filter((s): s is Span => s !== null)
      if (spans.length === 0) return null
      return { start: Math.min(...spans.map((s) => s.start)), end: Math.max(...spans.map((s) => s.end)) }
    }
  }
}

function joinSpans(hs: Hir[]): Span | null {
  const spans = hs.map(hirSpan).filter((s): s is Span => s !== null)
  if (spans.length === 0) return null
  return { start: Math.min(...spans.map((s) => s.start)), end: Math.max(...spans.map((s) => s.end)) }
}

// Structural equality, ignoring source positions (regex-syntax's `Hir: Eq`).
export function hirEqual(a: Hir, b: Hir): boolean {
  if (a.k !== b.k) return false
  switch (a.k) {
    case 'empty':
      return true
    case 'lit':
      return b.k === 'lit' && a.bytes.length === b.bytes.length && a.bytes.every((x, i) => x === b.bytes[i])
    case 'class':
      return (
        b.k === 'class' &&
        a.unicode === b.unicode &&
        a.ranges.length === b.ranges.length &&
        a.ranges.every((r, i) => r[0] === b.ranges[i][0] && r[1] === b.ranges[i][1])
      )
    case 'look':
      return b.k === 'look' && a.look === b.look
    case 'rep':
      return b.k === 'rep' && a.min === b.min && a.max === b.max && a.greedy === b.greedy && hirEqual(a.sub, b.sub)
    case 'cap':
      return b.k === 'cap' && a.index === b.index && a.name === b.name && hirEqual(a.sub, b.sub)
    case 'cat':
    case 'alt':
      return (b.k === 'cat' || b.k === 'alt') && a.subs.length === b.subs.length && a.subs.every((x, i) => hirEqual(x, b.subs[i]))
  }
}

export function alternation(subs: Hir[]): Hir {
  const flat: Hir[] = []
  for (const s of subs) {
    if (s.k === 'alt') flat.push(...s.subs)
    else flat.push(s)
  }
  if (flat.length === 0) return cls(false, [], null)
  if (flat.length === 1) return flat[0]
  const span = joinSpans(flat)
  if (flat.every((h) => h.k === 'lit')) {
    const chars = flat.map((h) => decodeSingle((h as { bytes: number[] }).bytes))
    if (chars.every((c) => c !== null)) return cls(true, chars.map((c): Range => [c!, c!]), span)
    if (flat.every((h) => (h as { bytes: number[] }).bytes.length === 1)) {
      return cls(false, flat.map((h): Range => [(h as { bytes: number[] }).bytes[0], (h as { bytes: number[] }).bytes[0]]), span)
    }
  }
  if (flat.every((h) => h.k === 'class')) {
    const classes = flat as Extract<Hir, { k: 'class' }>[]
    // class_chars: every byte class must be ASCII to become a Unicode class.
    if (classes.every((c) => c.unicode || c.ranges.every((r) => r[1] <= 0x7f))) {
      return cls(true, classes.flatMap((c) => c.ranges), span)
    }
    // class_bytes: every Unicode class must be ASCII to become a byte class.
    if (classes.every((c) => !c.unicode || c.ranges.every((r) => r[1] <= 0x7f))) {
      return cls(false, classes.flatMap((c) => c.ranges), span)
    }
  }
  const lifted = liftCommonPrefix(flat)
  if (lifted) return lifted
  let minLen: number | null = null
  let maxLen: number | null = null
  let minPoisoned = false
  let maxPoisoned = false
  let hasLook = false
  let altLit = true
  for (const h of flat) {
    hasLook ||= h.p.hasLook
    altLit &&= h.p.literal
    if (!minPoisoned) {
      if (h.p.minLen === null) {
        minLen = null
        minPoisoned = true
      } else if (minLen === null || h.p.minLen < minLen) minLen = h.p.minLen
    }
    if (!maxPoisoned) {
      if (h.p.maxLen === null) {
        maxLen = null
        maxPoisoned = true
      } else if (maxLen === null || h.p.maxLen > maxLen) maxLen = h.p.maxLen
    }
  }
  return { k: 'alt', subs: flat, p: props(minLen, maxLen, hasLook, false, altLit) }
}

function liftCommonPrefix(hirs: Hir[]): Hir | null {
  if (hirs.length <= 1 || hirs.some((h) => h.k !== 'cat')) return null
  const cats = hirs as Extract<Hir, { k: 'cat' }>[]
  let len = cats[0].subs.length
  for (const c of cats.slice(1)) {
    let n = 0
    while (n < len && n < c.subs.length && hirEqual(cats[0].subs[n], c.subs[n])) n++
    len = n
    if (len === 0) return null
  }
  const prefix = cats[0].subs.slice(0, len)
  const suffixes = cats.map((c) => concat(c.subs.slice(len)))
  return concat([...prefix, alternation(suffixes)])
}

// ---------------------------------------------------------------- translate

function applyFlags(st: HirFlags, on: string, off: string): void {
  for (const f of on) st[f as keyof HirFlags] = true
  for (const f of off) st[f as keyof HirFlags] = false
}

function classItemRanges(item: ClassItem, st: HirFlags): Range[] {
  switch (item.kind) {
    case 'char':
      return [[item.cp, item.cp]]
    case 'range':
      return [[item.lo, item.hi]]
    case 'perl':
      return item.negated ? negateBytes(PERL[item.which]) : PERL[item.which]
    case 'ascii':
      return item.negated ? negateBytes(ASCII[item.name]) : ASCII[item.name]
    case 'bracket':
      return foldAndNegate(item.items.flatMap((i) => classItemRanges(i, st)), item.negated, st)
  }
}

function foldAndNegate(ranges: Range[], negated: boolean, st: HirFlags): Range[] {
  let rs = canonical(ranges)
  if (st.i) rs = caseFoldBytes(rs)
  if (negated) rs = negateBytes(rs)
  return rs
}

function isAsciiLetter(cp: number): boolean {
  return (cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a)
}

function tr(node: Node, st: HirFlags): Hir {
  switch (node.kind) {
    case 'empty':
      return empty()
    case 'flags':
      applyFlags(st, node.flags.on, node.flags.off)
      return empty()
    case 'char': {
      if (node.byte && node.cp > 0x7f) return literal([node.cp], [node.span])
      if (st.i && isAsciiLetter(node.cp)) return cls(false, caseFoldBytes([[node.cp, node.cp]]), node.span)
      const bytes = utf8(node.cp)
      return literal(bytes, bytes.map(() => node.span))
    }
    case 'dot':
      return cls(false, st.s ? [[0, 0xff]] : [[0, 0x09], [0x0b, 0xff]], node.span)
    case 'assert': {
      let which = node.which
      if (which === 'start-line' && !st.m) which = 'start-text'
      if (which === 'end-line' && !st.m) which = 'end-text'
      return look(which, node.span)
    }
    case 'perl':
      return cls(false, node.negated ? negateBytes(PERL[node.which]) : PERL[node.which], node.span)
    case 'class':
      return cls(false, foldAndNegate(node.items.flatMap((i) => classItemRanges(i, st)), node.negated, st), node.span)
    case 'repeat': {
      const sub = tr(node.sub, st)
      const greedy = st.U ? !node.greedy : node.greedy
      return repetition(node.min, node.max, greedy, sub, node.span)
    }
    case 'group': {
      const saved = { ...st }
      if (node.flags) applyFlags(st, node.flags.on, node.flags.off)
      const sub = tr(node.sub, st)
      Object.assign(st, saved)
      return node.capture ? capture(node.index, node.name, sub, node.span) : sub
    }
    case 'concat':
      return concat(node.items.map((n) => tr(n, st)).filter((h) => h.k !== 'empty'))
    case 'alt':
      return alternation(node.items.map((n) => tr(n, st)))
  }
}

export function translate(ast: Node, flags: { i: boolean; s: boolean }): Hir {
  return tr(ast, { i: flags.i, s: flags.s, m: false, U: false })
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `npx vitest run src/lib/yarax/__tests__/hir.test.ts`
Expected: PASS, 11 tests.

- [ ] **Step 5: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add src/lib/yarax/hir.ts src/lib/yarax/__tests__/hir.test.ts
git commit -m "feat(yarax): port regex-syntax's normalized HIR with source spans

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Literal extraction and atom quality (`literal.ts`, `quality.ts`)

**Files:**
- Create: `src/lib/yarax/literal.ts`, `src/lib/yarax/quality.ts`
- Test: `src/lib/yarax/__tests__/quality.test.ts`

**Interfaces:**
- Consumes: `Hir`, `utf8` from Task 2; `parseYaraRegex` (test only).
- Produces: `literal.ts`: `Lit {bytes, exact}`, class `Seq` (`lits: Lit[] | null`, null = infinite; `push`, `len`, `isFinite`, `isInexact`, `makeInexact`, `makeInfinite`, `minLiteralLen`, `maxLiteralLen`, `maxCrossLen`, `keepFirstBytes`, `dedup`, `crossForward`, `union`, `clone`), `extract(hir): Seq`, `DESIRED_ATOM_SIZE = 4`, `MAX_ATOMS_PER_REGEXP = 16384`, `sameBytes`, `cmpBytes`. `quality.ts`: `atomQuality(bytes): number` (i32::MIN for empty), `bestRangeInBytes(bytes)`, `bestRangeInMaskedBytes(bytes, mask)` → `{ range: [start, end], quality }`, class `AtomsQuality` (`of(atoms)`, `min()`, `merge`, `cmp` > 0 when better).

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest'
import { AtomsQuality, atomQuality, bestRangeInBytes, bestRangeInMaskedBytes } from '../quality'
import { Seq, extract } from '../literal'
import { parseYaraRegex } from '../parse'
import { translate } from '../hir'

const bytes = (s: string) => [...s].map((c) => c.charCodeAt(0))

describe('atomQuality', () => {
  it('scores atoms like Yara-X 1.21.0', () => {
    expect(atomQuality(bytes('1234'))).toBe(88)
    expect(atomQuality(bytes('e64_'))).toBe(86)
    expect(atomQuality(bytes('(bas'))).toBe(82)
    expect(atomQuality(bytes('abcd'))).toBe(80)
    expect(atomQuality(bytes('eval'))).toBe(80)
    expect(atomQuality(bytes('aaaa'))).toBe(74)
    expect(atomQuality(bytes('    '))).toBe(43)
    expect(atomQuality(bytes('ab'))).toBe(40)
    expect(atomQuality(bytes('a'))).toBe(20)
    expect(atomQuality([0, 0, 0, 0])).toBe(19)
    expect(atomQuality([])).toBe(-2147483648)
  })
})

describe('best ranges', () => {
  it('picks the best 4-byte window of a literal', () => {
    expect(bestRangeInBytes(bytes('base64_decode'))).toEqual({ range: [3, 7], quality: 86 })
    expect(bestRangeInBytes(bytes('ab'))).toEqual({ range: [0, 2], quality: 40 })
  })

  it('scores masked bytes and keeps the first of equally good windows', () => {
    // [\x40-\x4f]b: 0x40 with mask 0xF0, then `b`.
    expect(bestRangeInMaskedBytes([0x40, 0x62], [0xf0, 0xff])).toEqual({ range: [0, 2], quality: 24 })
    // A fully masked byte costs 13, but `ab?c` (47) still beats `ab` (40).
    expect(bestRangeInMaskedBytes(bytes('ab\0cd'), [0xff, 0xff, 0, 0xff, 0xff])).toEqual({ range: [0, 4], quality: 47 })
  })
})

describe('AtomsQuality', () => {
  const q = (...atoms: string[]) => AtomsQuality.of(atoms.map((a) => ({ bytes: bytes(a), exact: false })))

  it('prefers a higher minimum quality, then longer atoms', () => {
    expect(q('abcd').cmp(q('ab'))).toBeGreaterThan(0)
    expect(q('ab', 'abcd').cmp(q('abc'))).toBeLessThan(0)
  })

  it('prefers 1 atom over 256 atoms that are only one byte longer', () => {
    const many = AtomsQuality.of(Array.from({ length: 256 }, (_, i) => ({ bytes: [0x61, 0x62, i], exact: false })))
    expect(q('ab').cmp(many)).toBeGreaterThan(0)
  })

  it('is better than the empty sentinel', () => {
    expect(q('a').cmp(AtomsQuality.min())).toBeGreaterThan(0)
  })
})

describe('extract (regex-syntax literal extraction)', () => {
  const seq = (src: string) => {
    const r = parseYaraRegex(src)
    if (!r.ok) throw new Error(r.error.message)
    const s = extract(translate(r.ast, { i: false, s: false }))
    return s.lits === null ? null : s.lits.map((l) => String.fromCharCode(...l.bytes) + (l.exact ? '' : '…'))
  }

  it('crosses concatenations and stops at 4 bytes', () => {
    expect(seq('ab[cd]')).toEqual(['abc', 'abd'])
    expect(seq('abcdef')).toEqual(['abcd…'])
  })

  it('handles optional and repeated parts', () => {
    expect(seq('ab*c')).toEqual(['ab…', 'ac'])
    expect(seq('a+')).toEqual(['a…'])
    expect(seq('(ab){2}')).toEqual(['abab'])
  })

  it('expands byte classes into one literal per byte', () => {
    expect(seq('[a-z]')).toHaveLength(26)
    expect(seq('.')).toHaveLength(255)
  })

  it('dedups consecutive literals, keeping inexactness', () => {
    const s = new Seq([
      { bytes: [1], exact: true },
      { bytes: [1], exact: false },
    ])
    s.dedup()
    expect(s.lits).toEqual([{ bytes: [1], exact: false }])
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/lib/yarax/__tests__/quality.test.ts`
Expected: FAIL — `Failed to resolve import "../quality"`.

- [ ] **Step 3: Write `literal.ts`**

```ts
// Port of regex-syntax 0.8.11's literal extraction (`hir::literal`): the
// `Seq` of `Literal`s and the prefix `Extractor`, configured with the limits
// Yara-X sets (class 256, total 16384, literal length 4, repeat 4).

import type { Hir } from './hir'
import { utf8 } from './hir'

export interface Lit {
  bytes: number[]
  exact: boolean
}

export const DESIRED_ATOM_SIZE = 4
export const MAX_ATOMS_PER_REGEXP = 16384
const LIMIT_CLASS = 256
const LIMIT_REPEAT = 4
const LIMIT_LITERAL_LEN = 4
const LIMIT_TOTAL = MAX_ATOMS_PER_REGEXP

export function sameBytes(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

export function cmpBytes(a: number[], b: number[]): number {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i]
  return a.length - b.length
}

// A finite list of literals, or infinite (`lits === null`): "could be
// anything", which stops extraction.
export class Seq {
  lits: Lit[] | null

  constructor(lits: Lit[] | null) {
    this.lits = lits
  }

  static empty(): Seq {
    return new Seq([])
  }
  static infinite(): Seq {
    return new Seq(null)
  }
  static singleton(lit: Lit): Seq {
    return new Seq([lit])
  }

  clone(): Seq {
    return new Seq(this.lits === null ? null : this.lits.map((l) => ({ bytes: [...l.bytes], exact: l.exact })))
  }

  push(lit: Lit): void {
    if (this.lits === null) return
    const last = this.lits[this.lits.length - 1]
    if (last && last.exact === lit.exact && sameBytes(last.bytes, lit.bytes)) return
    this.lits.push(lit)
  }

  len(): number | null {
    return this.lits === null ? null : this.lits.length
  }

  isFinite(): boolean {
    return this.lits !== null
  }

  isInexact(): boolean {
    return this.lits === null || this.lits.every((l) => !l.exact)
  }

  makeInexact(): void {
    this.lits?.forEach((l) => (l.exact = false))
  }

  makeInfinite(): void {
    this.lits = null
  }

  minLiteralLen(): number | null {
    if (this.lits === null || this.lits.length === 0) return null
    return Math.min(...this.lits.map((l) => l.bytes.length))
  }

  maxLiteralLen(): number | null {
    if (this.lits === null || this.lits.length === 0) return null
    return Math.max(...this.lits.map((l) => l.bytes.length))
  }

  maxCrossLen(other: Seq): number | null {
    const a = this.len()
    const b = other.len()
    return a === null || b === null ? null : a * b
  }

  maxUnionLen(other: Seq): number | null {
    const a = this.len()
    const b = other.len()
    return a === null || b === null ? null : a + b
  }

  keepFirstBytes(n: number): void {
    this.lits?.forEach((l) => {
      if (n < l.bytes.length) {
        l.exact = false
        l.bytes.length = n
      }
    })
  }

  // Removes consecutive duplicates; a duplicate pair that differs in
  // exactness becomes inexact.
  dedup(): void {
    if (this.lits === null) return
    const out: Lit[] = []
    for (const l of this.lits) {
      const prev = out[out.length - 1]
      if (prev && sameBytes(prev.bytes, l.bytes)) {
        if (prev.exact !== l.exact) prev.exact = false
        continue
      }
      out.push(l)
    }
    this.lits = out
  }

  crossForward(other: Seq): void {
    if (other.lits === null) {
      if (this.minLiteralLen() === 0) this.lits = null
      else this.makeInexact()
      return
    }
    if (this.lits === null) {
      other.lits = []
      return
    }
    const out: Lit[] = []
    for (const self of this.lits) {
      if (!self.exact) {
        out.push(self)
        continue
      }
      for (const o of other.lits) {
        out.push({ bytes: [...self.bytes, ...o.bytes], exact: o.exact })
      }
    }
    other.lits = []
    this.lits = out
    this.dedup()
  }

  union(other: Seq): void {
    if (other.lits === null) {
      this.makeInfinite()
      return
    }
    const drained = other.lits
    other.lits = []
    if (this.lits === null) return
    this.lits.push(...drained)
    this.dedup()
  }
}

function enforceLiteralLen(seq: Seq): void {
  seq.keepFirstBytes(LIMIT_LITERAL_LEN)
}

function cross(seq1: Seq, seq2: Seq): Seq {
  const n = seq1.maxCrossLen(seq2)
  if (n !== null && n > LIMIT_TOTAL) seq2.makeInfinite()
  seq1.crossForward(seq2)
  enforceLiteralLen(seq1)
  return seq1
}

function union(seq1: Seq, seq2: Seq): Seq {
  const n = seq1.maxUnionLen(seq2)
  if (n !== null && n > LIMIT_TOTAL) {
    seq1.keepFirstBytes(4)
    seq2.keepFirstBytes(4)
    seq1.dedup()
    seq2.dedup()
    const m = seq1.maxUnionLen(seq2)
    if (m !== null && m > LIMIT_TOTAL) seq2.makeInfinite()
  }
  seq1.union(seq2)
  return seq1
}

function classOverLimit(ranges: [number, number][]): boolean {
  let count = 0
  for (const [lo, hi] of ranges) {
    if (count > LIMIT_CLASS) return true
    count += hi - lo + 1
  }
  return count > LIMIT_CLASS
}

export function extract(hir: Hir): Seq {
  switch (hir.k) {
    case 'empty':
    case 'look':
      return Seq.singleton({ bytes: [], exact: true })
    case 'lit': {
      const seq = Seq.singleton({ bytes: [...hir.bytes], exact: true })
      enforceLiteralLen(seq)
      return seq
    }
    case 'class': {
      if (classOverLimit(hir.ranges)) return Seq.infinite()
      const seq = Seq.empty()
      for (const [lo, hi] of hir.ranges) {
        for (let c = lo; c <= hi; c++) seq.push({ bytes: hir.unicode ? utf8(c) : [c], exact: true })
      }
      enforceLiteralLen(seq)
      return seq
    }
    case 'rep':
      return extractRepetition(hir)
    case 'cap':
      return extract(hir.sub)
    case 'cat': {
      let seq = Seq.singleton({ bytes: [], exact: true })
      for (const h of hir.subs) {
        if (seq.isInexact()) break
        seq = cross(seq, extract(h))
      }
      return seq
    }
    case 'alt': {
      let seq = Seq.empty()
      for (const h of hir.subs) {
        if (!seq.isFinite()) break
        seq = union(seq, extract(h))
      }
      return seq
    }
  }
}

function extractRepetition(rep: Extract<Hir, { k: 'rep' }>): Seq {
  let subseq = extract(rep.sub)
  if (rep.min === 0) {
    if (rep.max !== 1) subseq.makeInexact()
    let emptySeq = Seq.singleton({ bytes: [], exact: true })
    if (!rep.greedy) [subseq, emptySeq] = [emptySeq, subseq]
    return union(subseq, emptySeq)
  }
  let seq = Seq.singleton({ bytes: [], exact: true })
  for (let i = 0; i < Math.min(rep.min, LIMIT_REPEAT); i++) {
    if (seq.isInexact()) break
    seq = cross(seq, subseq.clone())
  }
  if (rep.max === rep.min) {
    if (rep.min > LIMIT_REPEAT) seq.makeInexact()
  } else {
    seq.makeInexact()
  }
  return seq
}
```

- [ ] **Step 4: Write `quality.ts`**

```ts
// Port of Yara-X 1.21.0 `compiler/atoms/quality.rs`: the per-atom quality
// score, the best-window search over literal and masked bytes, and the
// ordering used to compare whole sets of atoms.

import { DESIRED_ATOM_SIZE } from './literal'

// Rust's i32/usize/i64 sentinels; empty atoms score i32::MIN, which keeps
// set comparisons finite the way the Rust code does.
const I32_MIN = -2147483648
const I32_MAX = 2147483647
const I64_MIN = -9223372036854775808
const MIN = I32_MIN

function popcount(b: number): number {
  let n = 0
  for (let x = b & 0xff; x; x >>= 1) n += x & 1
  return n
}

class BestAtomFinder {
  index = 0
  base = 0
  bestQuality = MIN
  bestRange: [number, number] | null = null
  queue: { index: number; byte: number; mask: number; q: number }[] = []
  readonly size: number

  constructor(size: number) {
    this.size = size
  }

  feed(byte: number, mask: number): void {
    if (this.queue.length === this.size) this.base -= this.queue.shift()!.q
    let q = 0
    if (mask !== 0xff) {
      const zeros = 8 - popcount(mask)
      const ones = popcount(mask)
      q += zeros === 8 ? -13 : 2 * ones - zeros
    } else if (byte === 0x20 || byte === 0x90 || byte === 0xcc || byte === 0xff) q += 12
    else if (byte === 0x00) q += 6
    else if ((byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a)) q += 18
    else q += 20
    this.queue.push({ index: this.index, byte, mask, q })
    this.base += q
    this.index++
    if (this.queue.length === this.size) {
      const quality = this.quality()
      if (quality > this.bestQuality) {
        this.bestQuality = quality
        this.bestRange = [this.queue[0].index, this.queue[this.queue.length - 1].index + 1]
      }
    }
  }

  finalize(): { range: [number, number] | null; quality: number } {
    if (this.bestQuality === MIN && this.queue.length > 0) {
      this.bestQuality = this.quality()
      this.bestRange = [0, this.queue.length]
    }
    return { range: this.bestRange, quality: this.bestQuality }
  }

  quality(): number {
    if (this.queue.length === 0) return MIN
    const seen = new Set<number>()
    for (const e of this.queue) if (e.mask === 0xff) seen.add(e.byte)
    let q = this.base
    if (seen.size === 1) {
      const front = this.queue[0].byte
      q += front === 0x00 || front === 0x20 || front === 0x90 || front === 0xcc || front === 0xff ? -5 : 2
    } else {
      q += 2 * seen.size
    }
    return q
  }
}

// Quality of an atom: its best window of up to 4 bytes; i32::MIN when empty.
export function atomQuality(bytes: number[]): number {
  const f = new BestAtomFinder(DESIRED_ATOM_SIZE)
  for (const b of bytes) f.feed(b, 0xff)
  return f.finalize().quality
}

export function bestRangeInBytes(bytes: number[]): { range: [number, number]; quality: number } {
  let quality = MIN
  let range: [number, number] = [0, 0]
  for (let i = 0; i <= Math.max(0, bytes.length - DESIRED_ATOM_SIZE); i++) {
    const r: [number, number] = [i, Math.min(bytes.length, i + DESIRED_ATOM_SIZE)]
    const q = atomQuality(bytes.slice(r[0], r[1]))
    if (q > quality) {
      quality = q
      range = r
    }
  }
  return { range, quality }
}

export function bestRangeInMaskedBytes(bytes: number[], mask: number[]): { range: [number, number]; quality: number } {
  const finders = [1, 2, 3, 4].map((n) => new BestAtomFinder(n))
  bytes.forEach((b, i) => finders.forEach((f) => f.feed(b, mask[i])))
  let best: { range: [number, number]; quality: number } = { range: [0, 0], quality: MIN }
  for (const f of finders) {
    const { range, quality } = f.finalize()
    if (!range) continue
    if (best.range[1] - best.range[0] === 0) {
      best = { range, quality }
      continue
    }
    const better = quality > best.quality || (quality === best.quality && range[1] - range[0] < best.range[1] - best.range[0])
    if (better) best = { range, quality }
  }
  return best
}

// Summary of a set of atoms, ordered the way Yara-X picks between
// candidate sets (`AtomsQuality: Ord`).
export class AtomsQuality {
  numExact: number
  numInexact: number
  minLen: number
  minQuality: number
  sumQuality: number

  constructor(numExact: number, numInexact: number, minLen: number, minQuality: number, sumQuality: number) {
    this.numExact = numExact
    this.numInexact = numInexact
    this.minLen = minLen
    this.minQuality = minQuality
    this.sumQuality = sumQuality
  }

  static min(): AtomsQuality {
    return new AtomsQuality(0, 0, 0, I32_MIN, I64_MIN)
  }

  static of(atoms: { bytes: number[]; exact: boolean }[]): AtomsQuality {
    let numExact = 0
    let numInexact = 0
    let sum = 0
    let minQ = I32_MAX
    let minLen = Number.MAX_SAFE_INTEGER
    for (const a of atoms) {
      if (a.exact) numExact++
      else numInexact++
      const q = atomQuality(a.bytes)
      sum = Math.max(I64_MIN, sum + q)
      minQ = Math.min(minQ, q)
      minLen = Math.min(minLen, a.bytes.length)
    }
    return new AtomsQuality(numExact, numInexact, minLen, minQ, sum)
  }

  numAtoms(): number {
    return this.numExact + this.numInexact
  }

  avg(): number {
    return this.sumQuality / this.numAtoms()
  }

  merge(o: AtomsQuality): void {
    this.numExact += o.numExact
    this.numInexact += o.numInexact
    this.sumQuality = Math.max(I64_MIN, this.sumQuality + o.sumQuality)
    this.minLen = Math.min(this.minLen, o.minLen)
    this.minQuality = Math.min(this.minQuality, o.minQuality)
  }

  // > 0 when `this` is better than `o`.
  cmp(o: AtomsQuality): number {
    if (Math.abs(this.minLen - o.minLen) === 1) {
      if (this.numAtoms() > 0 && this.numAtoms() * 256 === o.numAtoms() && this.avg() * 2 >= o.avg()) return 1
      if (o.numAtoms() > 0 && o.numAtoms() * 256 === this.numAtoms() && o.avg() * 2 >= this.avg()) return -1
    }
    if (this.minQuality !== o.minQuality) return this.minQuality > o.minQuality ? 1 : -1
    if (this.minLen !== o.minLen) return this.minLen > o.minLen ? 1 : -1
    const a = this.avg()
    const b = o.avg()
    if (Math.abs(a - b) > 15) return totalCmp(a, b)
    if (this.numInexact !== o.numInexact) return o.numInexact > this.numInexact ? 1 : -1
    if (this.numExact !== o.numExact) return o.numExact > this.numExact ? 1 : -1
    return 0
  }
}

// f64::total_cmp for the values that can occur here (NaN sorts above all).
function totalCmp(a: number, b: number): number {
  if (Number.isNaN(a)) return Number.isNaN(b) ? 0 : 1
  if (Number.isNaN(b)) return -1
  return a === b ? 0 : a > b ? 1 : -1
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `npx vitest run src/lib/yarax/__tests__/quality.test.ts`
Expected: PASS, 10 tests.

- [ ] **Step 6: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add src/lib/yarax/literal.ts src/lib/yarax/quality.ts src/lib/yarax/__tests__/quality.test.ts
git commit -m "feat(yarax): port literal extraction and atom quality scoring

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Atom choice, checked against `yr` (`atoms.ts`)

**Files:**
- Create: `src/lib/yarax/atoms.ts`, `src/lib/yarax/__fixtures__/atoms.json`, `scripts/yarax/gen-atoms.mjs`
- Test: `src/lib/yarax/__tests__/atoms.test.ts`

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: `extractAtoms(hir: Hir, opts: AtomOptions): AtomResult`; `AtomOptions {nocase, wide, ascii, fullword}`; `AtomResult {pieces: Piece[], gaps: Gap[], emptyMatch, slow, all: Atom[]}`; `Piece {path: 'literal' | 'masked' | 'fast' | 'pike', hir, atoms: Atom[] (plain), span: Span | null, extent: Extent, slow, pikeBecause?: Span | null, searched: SearchedAtom[]}`; `Atom {bytes, exact, backtrack}`; `SearchedAtom {atom, wide}`; `Extent {backward, forward}` (bytes, null = unbounded); `Gap {min, max, span}`; `makeWide`, `cmpAtom`, `anyByte`, class `TooManyAlternatives`.

The fixture is the output of `scripts/yarax/gen-atoms.mjs` run against `yr` 1.21.0 built with `--features debug-cmd`; it is committed so tests never need `yr`. Copy it exactly.

- [ ] **Step 1: Add the fixture generator**

```js
// Regenerates src/lib/yarax/__fixtures__/atoms.json from a real `yr` build.
//
// `yr debug atoms` only exists with the `debug-cmd` feature, so build the
// CLI at the same tag as the pinned @virustotal/yara-x package:
//
//   cargo install --git https://github.com/VirusTotal/yara-x --tag v1.21.0 \
//     yara-x-cli --features debug-cmd --root /some/dir
//   YR=/some/dir/bin/yr node scripts/yarax/gen-atoms.mjs
//
// Each case records the atoms `yr` prints (hex, sorted), the warning codes
// and, when the rule doesn't compile, the error code. Lists longer than
// MAX_LISTED keep only their count and the SHA-256 of the sorted list
// joined with commas, so the fixture stays small.

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const YR = process.env.YR
if (!YR) {
  console.error('Set YR to a yr binary built with --features debug-cmd')
  process.exit(1)
}

const MAX_LISTED = 32

// [pattern, suffix, modifiers]
const CASES = [
  // literals and alternations of literals
  ['abc', '', ''],
  ['abcd', '', ''],
  ['base64_decode', '', ''],
  ['eval', '', 'fullword'],
  ['a', '', ''],
  ['ab', '', ''],
  ['\\x00\\x00\\x00\\x00', '', ''],
  ['\\x90\\x90', '', ''],
  ['abc|def', '', ''],
  ['(abc|d)', '', ''],
  ['ab|c', '', ''],
  ['1234', '', 'nocase'],
  ['abcdef', '', 'wide'],
  ['abc', '', 'ascii wide'],
  ['caf\\x{E9}', '', ''],
  ['café', '', ''],
  ['\\xE9\\xFF\\x00\\x01', '', ''],
  // case-insensitive
  ['abc', 'i', ''],
  ['abc', '', 'nocase'],
  ['abcd', 'i', ''],
  ['aaaa1234', '', 'nocase'],
  ['(?i)abc', '', ''],
  ['a(?i)bc', '', ''],
  ['(?i:ab)cd', '', ''],
  // masked literals
  ['[\\x40-\\x4f]b', '', ''],
  ['a.{2}bcd', 's', ''],
  ['[aA]bcd', '', ''],
  ['x[ac]yz', '', ''],
  ['MZ.{2}\\x90\\x00', 's', ''],
  // FastVM
  ['foo.{0,10}bar', '', ''],
  ['foo.{0,10}bar', 's', ''],
  ['foo.*bar', '', ''],
  ['abcd.{3}efgh', '', ''],
  ['(foo|bar).{0,5}bazz', '', ''],
  ['x[ac]yz.{0,4}hello', '', ''],
  ['[0-9a-f]{2}', '', ''],
  // PikeVM
  ['eval\\s*\\(\\s*base64_decode\\s*\\(', '', ''],
  ['foo\\s*bar', '', ''],
  ['foo\\s*bar', '', 'wide'],
  ['foo\\s*bar', '', 'ascii wide'],
  ['(abc|def)ghi', '', ''],
  ['a(bcd|efg)h', '', ''],
  ['(a|b)cd', '', ''],
  ['x(a|c)yz', '', ''],
  ['Look(at|into)this', '', ''],
  ['x[0-9]y', '', ''],
  ['[A-Za-z]{2,}x', '', ''],
  ['[A-Za-z0-9+\\/]{64,512}\\x00', '', ''],
  ['[a-z]', '', ''],
  ['a|b', '', ''],
  ['\\beval\\b', '', ''],
  ['^MZ', '', ''],
  ['abc$', '', ''],
  ['(?m)^abc', '', ''],
  ['ab+c', '', ''],
  ['ab*c', '', ''],
  ['ab?cd', '', ''],
  ['(ab){2}c', '', ''],
  ['(abc){3,}', '', ''],
  ['a(bc)?d', '', ''],
  ['\\d{4}-\\d{2}', '', ''],
  ['[a-z0-9]{8}\\.php', '', ''],
  ['https?:\\/\\/[a-z]+', '', ''],
  ['(foo|bar|baz)\\d+', '', ''],
  ['(foo|)bar', '', ''],
  ['x(?:ab|cd|ef)+y', '', ''],
  ['\\w+@\\w+\\.com', '', ''],
  ['GET \\/[^ ]+ HTTP', '', ''],
  ['\\x00\\x00[\\x01-\\x05]', '', ''],
  ['abc[^a]def', '', ''],
  ['[\\x80-\\xff]{4}', '', ''],
  ['(a|é)bc', '', ''],
  ['é|a', '', ''],
  ['(\\xFF|a)bc', '', ''],
  ['ab.{2}cd', '', ''],
  ['abc\\b', '', 'nocase'],
  ['[ab]|[cd]', '', ''],
  ['(abc)', '', ''],
  ['(?P<n>abc)d', '', ''],
  ['a{,3}bcd', '', ''],
  ['abc.*?def', '', ''],
  ['abcd', '', 'wide fullword'],
  ['\\s*eval', '', ''],
  // chaining
  ['foo.{0,300}bar', 's', ''],
  ['a.{0,300}b', 's', ''],
  ['abc.{0,300}d', 's', ''],
  ['abcd.{0,300}efgh.{500,}ijkl', 's', ''],
  ['abcd.*efgh', 's', ''],
  ['abcd.{0,300}e\\s*fgh', 's', ''],
  ['abcd.{0,300}efgh', 's', 'wide'],
  // errors and warnings
  ['a*', '', ''],
  ['foo{', '', ''],
  ['a.*?b.*c', '', ''],
  ['.*foo', 's', ''],
  ['abc', 'i', 'nocase'],
]

const dir = mkdtempSync(join(tmpdir(), 'yarax-atoms-'))
const out = []
try {
  for (const [pattern, suffix, mods] of CASES) {
    const file = join(dir, 'p.yar')
    writeFileSync(file, `rule t { strings: $a = /${pattern}/${suffix} ${mods} condition: $a }\n`)
    const run = (args) => {
      try {
        return { ok: true, text: execFileSync(YR, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) }
      } catch (e) {
        return { ok: false, text: String(e.stdout ?? '') + String(e.stderr ?? '') }
      }
    }
    const check = run(['check', file])
    const warnings = [...check.text.matchAll(/warning\[([a-z_0-9]+)\]/g)].map((m) => m[1])
    const debug = run(['debug', 'atoms', '--json', file])
    const entry = { pattern, suffix, modifiers: mods, count: 0, atoms: null, sha256: null, warnings, error: null }
    if (debug.ok) {
      const atoms = [...JSON.parse(debug.text)[0].atoms].sort()
      entry.count = atoms.length
      if (atoms.length <= MAX_LISTED) entry.atoms = atoms
      else entry.sha256 = createHash('sha256').update(atoms.join(',')).digest('hex')
    } else {
      entry.error = (/error\[([A-Z0-9]+)\]/.exec(debug.text) ?? [null, 'unknown'])[1]
    }
    out.push(entry)
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}
const version = execFileSync(YR, ['--version'], { encoding: 'utf8' }).trim()
// One case per line keeps the file short and its diffs readable.
writeFileSync(
  new URL('../../src/lib/yarax/__fixtures__/atoms.json', import.meta.url),
  `{"generatedBy": ${JSON.stringify(version)}, "cases": [\n${out.map((c) => JSON.stringify(c)).join(',\n')}\n]}\n`,
)
console.log(`wrote ${out.length} cases (${version})`)
```

- [ ] **Step 2: Add the fixture** (`src/lib/yarax/__fixtures__/atoms.json`, exactly as generated)

```json
{"generatedBy": "yara-x-cli 1.21.0", "cases": [
{"pattern":"abc","suffix":"","modifiers":"","count":1,"atoms":["616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcd","suffix":"","modifiers":"","count":1,"atoms":["61626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"base64_decode","suffix":"","modifiers":"","count":1,"atoms":["6536345F"],"sha256":null,"warnings":[],"error":null},
{"pattern":"eval","suffix":"","modifiers":"fullword","count":1,"atoms":["6576616C"],"sha256":null,"warnings":[],"error":null},
{"pattern":"a","suffix":"","modifiers":"","count":1,"atoms":["61"],"sha256":null,"warnings":["slow_pattern"],"error":null},
{"pattern":"ab","suffix":"","modifiers":"","count":1,"atoms":["6162"],"sha256":null,"warnings":[],"error":null},
{"pattern":"\\x00\\x00\\x00\\x00","suffix":"","modifiers":"","count":1,"atoms":["00000000"],"sha256":null,"warnings":["slow_pattern"],"error":null},
{"pattern":"\\x90\\x90","suffix":"","modifiers":"","count":1,"atoms":["9090"],"sha256":null,"warnings":["slow_pattern"],"error":null},
{"pattern":"abc|def","suffix":"","modifiers":"","count":2,"atoms":["616263","646566"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(abc|d)","suffix":"","modifiers":"","count":2,"atoms":["616263","64"],"sha256":null,"warnings":[],"error":null},
{"pattern":"ab|c","suffix":"","modifiers":"","count":2,"atoms":["6162","63"],"sha256":null,"warnings":[],"error":null},
{"pattern":"1234","suffix":"","modifiers":"nocase","count":1,"atoms":["31323334"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcdef","suffix":"","modifiers":"wide","count":1,"atoms":["61006200"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abc","suffix":"","modifiers":"ascii wide","count":2,"atoms":["61006200","616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"caf\\x{E9}","suffix":"","modifiers":"","count":1,"atoms":["6166C3A9"],"sha256":null,"warnings":[],"error":null},
{"pattern":"café","suffix":"","modifiers":"","count":1,"atoms":["6166C3A9"],"sha256":null,"warnings":[],"error":null},
{"pattern":"\\xE9\\xFF\\x00\\x01","suffix":"","modifiers":"","count":1,"atoms":["E9FF0001"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abc","suffix":"i","modifiers":"","count":8,"atoms":["414243","414263","416243","416263","614243","614263","616243","616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abc","suffix":"","modifiers":"nocase","count":8,"atoms":["414243","414263","416243","416263","614243","614263","616243","616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcd","suffix":"i","modifiers":"","count":16,"atoms":["41424344","41424364","41426344","41426364","41624344","41624364","41626344","41626364","61424344","61424364","61426344","61426364","61624344","61624364","61626344","61626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"aaaa1234","suffix":"","modifiers":"nocase","count":1,"atoms":["31323334"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(?i)abc","suffix":"","modifiers":"","count":8,"atoms":["414243","414263","416243","416263","614243","614263","616243","616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"a(?i)bc","suffix":"","modifiers":"","count":4,"atoms":["614243","614263","616243","616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(?i:ab)cd","suffix":"","modifiers":"","count":4,"atoms":["41426364","41626364","61426364","61626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"[\\x40-\\x4f]b","suffix":"","modifiers":"","count":16,"atoms":["4062","4162","4262","4362","4462","4562","4662","4762","4862","4962","4A62","4B62","4C62","4D62","4E62","4F62"],"sha256":null,"warnings":[],"error":null},
{"pattern":"a.{2}bcd","suffix":"s","modifiers":"","count":1,"atoms":["626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"[aA]bcd","suffix":"","modifiers":"","count":2,"atoms":["41626364","61626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"x[ac]yz","suffix":"","modifiers":"","count":2,"atoms":["7861797A","7863797A"],"sha256":null,"warnings":[],"error":null},
{"pattern":"MZ.{2}\\x90\\x00","suffix":"s","modifiers":"","count":1,"atoms":["4D5A"],"sha256":null,"warnings":[],"error":null},
{"pattern":"foo.{0,10}bar","suffix":"","modifiers":"","count":1,"atoms":["626172"],"sha256":null,"warnings":[],"error":null},
{"pattern":"foo.{0,10}bar","suffix":"s","modifiers":"","count":1,"atoms":["626172"],"sha256":null,"warnings":[],"error":null},
{"pattern":"foo.*bar","suffix":"","modifiers":"","count":1,"atoms":["626172"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcd.{3}efgh","suffix":"","modifiers":"","count":1,"atoms":["61626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(foo|bar).{0,5}bazz","suffix":"","modifiers":"","count":1,"atoms":["62617A7A"],"sha256":null,"warnings":[],"error":null},
{"pattern":"x[ac]yz.{0,4}hello","suffix":"","modifiers":"","count":1,"atoms":["68656C6C"],"sha256":null,"warnings":[],"error":null},
{"pattern":"[0-9a-f]{2}","suffix":"","modifiers":"","count":256,"atoms":null,"sha256":"e7a9448ac6f43f0c0c57984eb81acbe8cbb473d44c9f4429cb0223e359cf4883","warnings":[],"error":null},
{"pattern":"eval\\s*\\(\\s*base64_decode\\s*\\(","suffix":"","modifiers":"","count":1,"atoms":["6536345F"],"sha256":null,"warnings":[],"error":null},
{"pattern":"foo\\s*bar","suffix":"","modifiers":"","count":7,"atoms":["666F6F09","666F6F0A","666F6F0B","666F6F0C","666F6F0D","666F6F20","666F6F62"],"sha256":null,"warnings":[],"error":null},
{"pattern":"foo\\s*bar","suffix":"","modifiers":"wide","count":7,"atoms":["66006F006F000900","66006F006F000A00","66006F006F000B00","66006F006F000C00","66006F006F000D00","66006F006F002000","66006F006F006200"],"sha256":null,"warnings":[],"error":null},
{"pattern":"foo\\s*bar","suffix":"","modifiers":"ascii wide","count":14,"atoms":["66006F006F000900","66006F006F000A00","66006F006F000B00","66006F006F000C00","66006F006F000D00","66006F006F002000","66006F006F006200","666F6F09","666F6F0A","666F6F0B","666F6F0C","666F6F0D","666F6F20","666F6F62"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(abc|def)ghi","suffix":"","modifiers":"","count":2,"atoms":["616263","646566"],"sha256":null,"warnings":[],"error":null},
{"pattern":"a(bcd|efg)h","suffix":"","modifiers":"","count":2,"atoms":["626364","656667"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(a|b)cd","suffix":"","modifiers":"","count":2,"atoms":["616364","626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"x(a|c)yz","suffix":"","modifiers":"","count":2,"atoms":["7861797A","7863797A"],"sha256":null,"warnings":[],"error":null},
{"pattern":"Look(at|into)this","suffix":"","modifiers":"","count":1,"atoms":["74686973"],"sha256":null,"warnings":[],"error":null},
{"pattern":"x[0-9]y","suffix":"","modifiers":"","count":10,"atoms":["783079","783179","783279","783379","783479","783579","783679","783779","783879","783979"],"sha256":null,"warnings":[],"error":null},
{"pattern":"[A-Za-z]{2,}x","suffix":"","modifiers":"","count":2704,"atoms":null,"sha256":"6576de8c2f0be652a7e90d5ef1552f18f194b3e4db7d911d6a26d888bdf6a427","warnings":["slow_pattern"],"error":null},
{"pattern":"[A-Za-z0-9+\\/]{64,512}\\x00","suffix":"","modifiers":"","count":4096,"atoms":null,"sha256":"972e21159115f25ef4208f8603693f68eb020decd48016d7e954d26c6118d4c6","warnings":["slow_pattern"],"error":null},
{"pattern":"[a-z]","suffix":"","modifiers":"","count":26,"atoms":["61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F","70","71","72","73","74","75","76","77","78","79","7A"],"sha256":null,"warnings":["slow_pattern"],"error":null},
{"pattern":"a|b","suffix":"","modifiers":"","count":2,"atoms":["61","62"],"sha256":null,"warnings":["slow_pattern"],"error":null},
{"pattern":"\\beval\\b","suffix":"","modifiers":"","count":1,"atoms":["6576616C"],"sha256":null,"warnings":[],"error":null},
{"pattern":"^MZ","suffix":"","modifiers":"","count":1,"atoms":["4D5A"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abc$","suffix":"","modifiers":"","count":1,"atoms":["616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(?m)^abc","suffix":"","modifiers":"","count":1,"atoms":["616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"ab+c","suffix":"","modifiers":"","count":1,"atoms":["6162"],"sha256":null,"warnings":[],"error":null},
{"pattern":"ab*c","suffix":"","modifiers":"","count":2,"atoms":["6162","6163"],"sha256":null,"warnings":[],"error":null},
{"pattern":"ab?cd","suffix":"","modifiers":"","count":2,"atoms":["61626364","616364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(ab){2}c","suffix":"","modifiers":"","count":1,"atoms":["61626162"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(abc){3,}","suffix":"","modifiers":"","count":1,"atoms":["61626361"],"sha256":null,"warnings":[],"error":null},
{"pattern":"a(bc)?d","suffix":"","modifiers":"","count":2,"atoms":["61626364","6164"],"sha256":null,"warnings":[],"error":null},
{"pattern":"\\d{4}-\\d{2}","suffix":"","modifiers":"","count":10000,"atoms":null,"sha256":"f6d2bfb2d545c0411c9cb96539e499ad82f44779ab6bf87f5ef5c63705b04852","warnings":[],"error":null},
{"pattern":"[a-z0-9]{8}\\.php","suffix":"","modifiers":"","count":1,"atoms":["2E706870"],"sha256":null,"warnings":[],"error":null},
{"pattern":"https?:\\/\\/[a-z]+","suffix":"","modifiers":"","count":26,"atoms":["3A2F2F61","3A2F2F62","3A2F2F63","3A2F2F64","3A2F2F65","3A2F2F66","3A2F2F67","3A2F2F68","3A2F2F69","3A2F2F6A","3A2F2F6B","3A2F2F6C","3A2F2F6D","3A2F2F6E","3A2F2F6F","3A2F2F70","3A2F2F71","3A2F2F72","3A2F2F73","3A2F2F74","3A2F2F75","3A2F2F76","3A2F2F77","3A2F2F78","3A2F2F79","3A2F2F7A"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(foo|bar|baz)\\d+","suffix":"","modifiers":"","count":30,"atoms":["62617230","62617231","62617232","62617233","62617234","62617235","62617236","62617237","62617238","62617239","62617A30","62617A31","62617A32","62617A33","62617A34","62617A35","62617A36","62617A37","62617A38","62617A39","666F6F30","666F6F31","666F6F32","666F6F33","666F6F34","666F6F35","666F6F36","666F6F37","666F6F38","666F6F39"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(foo|)bar","suffix":"","modifiers":"","count":1,"atoms":["626172"],"sha256":null,"warnings":[],"error":null},
{"pattern":"x(?:ab|cd|ef)+y","suffix":"","modifiers":"","count":3,"atoms":["786162","786364","786566"],"sha256":null,"warnings":[],"error":null},
{"pattern":"\\w+@\\w+\\.com","suffix":"","modifiers":"","count":1,"atoms":["2E636F6D"],"sha256":null,"warnings":[],"error":null},
{"pattern":"GET \\/[^ ]+ HTTP","suffix":"","modifiers":"","count":1,"atoms":["48545450"],"sha256":null,"warnings":[],"error":null},
{"pattern":"\\x00\\x00[\\x01-\\x05]","suffix":"","modifiers":"","count":5,"atoms":["000001","000002","000003","000004","000005"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abc[^a]def","suffix":"","modifiers":"","count":255,"atoms":null,"sha256":"2ee354f40465cf241e78c85c4fc7e857870fd1a72632ccff57827c1d00ba1480","warnings":[],"error":null},
{"pattern":"[\\x80-\\xff]{4}","suffix":"","modifiers":"","count":16384,"atoms":null,"sha256":"f3f21052a9c706efb5ec24cbc1d0aca6d7e826545332e8f8507d34ed8219e6cf","warnings":["slow_pattern"],"error":null},
{"pattern":"(a|é)bc","suffix":"","modifiers":"","count":2,"atoms":["616263","C3A96263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"é|a","suffix":"","modifiers":"","count":2,"atoms":["61","C3A9"],"sha256":null,"warnings":["slow_pattern"],"error":null},
{"pattern":"(\\xFF|a)bc","suffix":"","modifiers":"","count":1,"atoms":["6263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"ab.{2}cd","suffix":"","modifiers":"","count":1,"atoms":["6162"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abc\\b","suffix":"","modifiers":"nocase","count":8,"atoms":["414243","414263","416243","416263","614243","614263","616243","616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"[ab]|[cd]","suffix":"","modifiers":"","count":4,"atoms":["61","62","63","64"],"sha256":null,"warnings":["slow_pattern"],"error":null},
{"pattern":"(abc)","suffix":"","modifiers":"","count":1,"atoms":["616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"(?P<n>abc)d","suffix":"","modifiers":"","count":1,"atoms":["61626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"a{,3}bcd","suffix":"","modifiers":"","count":1,"atoms":["626364"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abc.*?def","suffix":"","modifiers":"","count":1,"atoms":["616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcd","suffix":"","modifiers":"wide fullword","count":1,"atoms":["61006200"],"sha256":null,"warnings":[],"error":null},
{"pattern":"\\s*eval","suffix":"","modifiers":"","count":1,"atoms":["6576616C"],"sha256":null,"warnings":[],"error":null},
{"pattern":"foo.{0,300}bar","suffix":"s","modifiers":"","count":2,"atoms":["626172","666F6F"],"sha256":null,"warnings":[],"error":null},
{"pattern":"a.{0,300}b","suffix":"s","modifiers":"","count":1,"atoms":["61"],"sha256":null,"warnings":["slow_pattern"],"error":null},
{"pattern":"abc.{0,300}d","suffix":"s","modifiers":"","count":1,"atoms":["616263"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcd.{0,300}efgh.{500,}ijkl","suffix":"s","modifiers":"","count":3,"atoms":["61626364","65666768","696A6B6C"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcd.*efgh","suffix":"s","modifiers":"","count":2,"atoms":["61626364","65666768"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcd.{0,300}e\\s*fgh","suffix":"s","modifiers":"","count":2,"atoms":["61626364","666768"],"sha256":null,"warnings":[],"error":null},
{"pattern":"abcd.{0,300}efgh","suffix":"s","modifiers":"wide","count":2,"atoms":["61006200","65006600"],"sha256":null,"warnings":[],"error":null},
{"pattern":"a*","suffix":"","modifiers":"","count":0,"atoms":null,"sha256":null,"warnings":[],"error":"E014"},
{"pattern":"foo{","suffix":"","modifiers":"","count":0,"atoms":null,"sha256":null,"warnings":[],"error":"E014"},
{"pattern":"a.*?b.*c","suffix":"","modifiers":"","count":0,"atoms":null,"sha256":null,"warnings":[],"error":"E015"},
{"pattern":".*foo","suffix":"s","modifiers":"","count":0,"atoms":null,"sha256":null,"warnings":[],"error":"E045"},
{"pattern":"abc","suffix":"i","modifiers":"nocase","count":8,"atoms":["414243","414263","416243","416263","614243","614263","616243","616263"],"sha256":null,"warnings":["redundant_modifier"],"error":null}
]}
```

Optional, only if a `yr` with `debug-cmd` is at hand: `YR=/path/to/yr node scripts/yarax/gen-atoms.mjs` must print `wrote 95 cases (yara-x-cli 1.21.0)` and leave `git diff src/lib/yarax/__fixtures__` empty.

- [ ] **Step 3: Write the failing test**

```ts
/// <reference types="node" />
import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import fixture from '../__fixtures__/atoms.json'
import { parseYaraRegex } from '../parse'
import { translate } from '../hir'
import { extractAtoms } from '../atoms'

const hex = (bytes: number[]) => bytes.map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join('')

function analyze(pattern: string, suffix: string, modifiers: string) {
  const mods = modifiers.split(' ')
  const parsed = parseYaraRegex(pattern)
  if (!parsed.ok) throw new Error(`parse failed: ${parsed.error.message}`)
  const nocase = mods.includes('nocase') || suffix.includes('i')
  const hir = translate(parsed.ast, { i: nocase, s: suffix.includes('s') })
  return extractAtoms(hir, {
    nocase,
    wide: mods.includes('wide'),
    ascii: mods.includes('ascii'),
    fullword: mods.includes('fullword'),
  })
}

describe('atoms match yr debug atoms (1.21.0)', () => {
  const cases = fixture.cases.filter((c) => c.error === null)
  it.each(cases.map((c) => [`/${c.pattern}/${c.suffix} ${c.modifiers}`, c] as const))('%s', (_, c) => {
    const r = analyze(c.pattern, c.suffix, c.modifiers)
    const got = r.all.map((a) => hex(a.bytes)).sort()
    expect(got).toHaveLength(c.count)
    if (c.atoms) expect(got).toEqual(c.atoms)
    else expect(createHash('sha256').update(got.join(',')).digest('hex')).toBe(c.sha256)
    expect(r.slow).toBe(c.warnings.includes('slow_pattern'))
  })
})

describe('where the atoms come from', () => {
  const plain = (pattern: string, suffix = '') => analyze(pattern, suffix, '')

  it('points at the atom in the pattern and measures verification around it', () => {
    const r = plain('eval\\s*\\(\\s*base64_decode\\s*\\(')
    expect(r.pieces).toHaveLength(1)
    expect(r.pieces[0]).toMatchObject({ path: 'pike', span: { start: 15, end: 19 }, extent: { backward: null, forward: null } })
    expect(r.pieces[0].pikeBecause).toEqual({ start: 4, end: 7 })
  })

  it('measures bounded gaps on the FastVM path', () => {
    expect(plain('foo.{0,10}bar').pieces[0]).toMatchObject({ path: 'fast', extent: { backward: 13, forward: 3 } })
  })

  it('splits at long any-byte gaps under /s and records the gap', () => {
    const r = plain('foo.{0,300}bar', 's')
    expect(r.pieces.map((p) => p.path)).toEqual(['literal', 'literal'])
    expect(r.gaps).toEqual([{ min: 0, max: 300, span: { start: 3, end: 11 } }])
  })

  it('uses source spans in UTF-16 units', () => {
    // The emoji's four UTF-8 bytes F0 9F 98 80 (88) beat `abcd` (80).
    expect(plain('😀abcd').pieces[0].span).toEqual({ start: 0, end: 2 })
    expect(plain('😀😀ab1234').pieces[0].span).toEqual({ start: 0, end: 2 })
    expect(plain('é ab 1234').pieces[0].span).toEqual({ start: 5, end: 9 })
  })

  it('reports a pattern that can match the empty string', () => {
    expect(plain('a?').emptyMatch).toBe(true)
  })

  it('stays fast on patterns with many atoms', () => {
    const t = performance.now()
    for (const p of ['[\\x80-\\xff]{4}', '\\d{4}-\\d{2}', '[A-Za-z0-9+\\/]{64,512}\\x00', '(\\w\\w\\w\\w|[a-f0-9]{8})+x']) plain(p)
    expect(performance.now() - t).toBeLessThan(1500)
  })
})
```

- [ ] **Step 4: Run it to verify it fails**

Run: `npx vitest run src/lib/yarax/__tests__/atoms.test.ts`
Expected: FAIL — `Failed to resolve import "../atoms"`.

- [ ] **Step 5: Write the implementation**

```ts
// Port of how Yara-X 1.21.0 picks the atoms for a regex string
// (`Compiler::c_regexp_pattern` and the code it calls):
//   1. split at large `.{n,m}` gaps under `/s` (chaining),
//   2. a literal or an alternation of literals: best 4-byte window of each,
//   3. a literal with masked bytes: best masked window,
//   4. FastVM: literal and masked pieces joined by `.` gaps,
//   5. PikeVM (Thompson compiler): literal extraction over the whole tree.
// `wide` atoms are the plain atoms with 00 interleaved, except for literal
// strings, whose atoms are taken from the UTF-16LE bytes directly.

import { type Hir, concat, hirSpan, repetition } from './hir'
import type { Span } from './parse'
import { AtomsQuality, bestRangeInBytes, bestRangeInMaskedBytes } from './quality'
import { DESIRED_ATOM_SIZE, MAX_ATOMS_PER_REGEXP, Seq, cmpBytes, extract, sameBytes } from './literal'

export interface Atom {
  bytes: number[]
  exact: boolean
  backtrack: number
}

export type AtomPath = 'literal' | 'masked' | 'fast' | 'pike'

// Bytes the engine may scan around an atom hit; null means unbounded.
export interface Extent {
  backward: number | null
  forward: number | null
}

export interface SearchedAtom {
  atom: Atom
  // A UTF-16LE variant added by the `wide` modifier.
  wide: boolean
}

export interface Piece {
  path: AtomPath
  hir: Hir
  atoms: Atom[]
  span: Span | null
  extent: Extent
  // Yara-X's slow_pattern conditions hold for this piece.
  slow: boolean
  // For a PikeVM piece: the construct FastVM can't handle, or null when
  // FastVM's best atom was shorter than 2 bytes.
  pikeBecause?: Span | null
  // The atoms the engine searches for this piece: the plain ones unless
  // `wide` alone is set, plus wide variants with `wide`.
  searched: SearchedAtom[]
}

export interface Gap {
  min: number
  max: number | null
  // The `.{n,m}` the pattern was split at.
  span: Span | null
}

export interface AtomOptions {
  nocase: boolean
  wide: boolean
  ascii: boolean
  fullword: boolean
}

export interface AtomResult {
  pieces: Piece[]
  gaps: Gap[]
  emptyMatch: boolean
  slow: boolean
  // Every atom the engine searches for, wide variants included.
  all: Atom[]
}

const PATTERN_CHAINING_THRESHOLD = 200
const MIN_PATTERN_LENGTH_IN_CHAIN = 2

export function cmpAtom(a: Atom, b: Atom): number {
  return cmpBytes(a.bytes, b.bytes) || Number(a.exact) - Number(b.exact) || a.backtrack - b.backtrack
}

function sameAtom(a: Atom, b: Atom): boolean {
  return cmpAtom(a, b) === 0
}

export function makeWide(a: Atom): Atom {
  return { bytes: a.bytes.flatMap((b) => [b, 0]), exact: a.exact, backtrack: a.backtrack * 2 }
}

function wideBytes(bytes: number[]): number[] {
  return bytes.flatMap((b) => [b, 0])
}

function atomFromRange(bytes: number[], [s, e]: [number, number]): Atom {
  return { bytes: bytes.slice(s, e), exact: e - s === bytes.length, backtrack: s }
}

function bestAtomInBytes(bytes: number[]): Atom {
  return atomFromRange(bytes, bestRangeInBytes(bytes).range)
}

function caseCombinations(a: Atom): Atom[] {
  let out: number[][] = [[]]
  for (const raw of a.bytes) {
    const b = raw >= 0x41 && raw <= 0x5a ? raw + 32 : raw
    const opts = b >= 0x61 && b <= 0x7a ? [b, b - 32] : [b]
    out = out.flatMap((p) => opts.map((o) => [...p, o]))
  }
  return out.map((bytes) => ({ bytes, exact: a.exact, backtrack: a.backtrack }))
}

function byteMaskCombinations(byte: number, mask: number): number[] {
  const out: number[] = []
  for (let v = 0; v < 256; v++) if ((v & mask) === (byte & mask)) out.push(v)
  return out
}

function maskCombinationCount(mask: number[]): number {
  return mask.reduce((n, m) => n * (1 << (8 - popcount(m))), 1)
}

function maskCombinations(a: Atom, mask: number[]): Atom[] {
  let out: number[][] = [[]]
  a.bytes.forEach((b, i) => {
    const opts = byteMaskCombinations(b, mask[i])
    out = out.flatMap((p) => opts.map((o) => [...p, o]))
  })
  return out.map((bytes) => ({ bytes, exact: a.exact, backtrack: a.backtrack }))
}

function popcount(b: number): number {
  let n = 0
  for (let x = b & 0xff; x; x >>= 1) n += x & 1
  return n
}

function unionSpans(spans: (Span | null)[]): Span | null {
  const ok = spans.filter((s): s is Span => s !== null)
  if (ok.length === 0) return null
  return { start: Math.min(...ok.map((s) => s.start)), end: Math.max(...ok.map((s) => s.end)) }
}

function add(a: number | null, b: number | null): number | null {
  return a === null || b === null ? null : a + b
}

function maxExtent(a: Extent, b: Extent): Extent {
  const m = (x: number | null, y: number | null) => (x === null || y === null ? null : Math.max(x, y))
  return { backward: m(a.backward, b.backward), forward: m(a.forward, b.forward) }
}

// ---------------------------------------------------------------- classes as masks

export function anyByte(h: Hir): boolean {
  return h.k === 'class' && h.ranges.length > 0 && h.ranges[0][0] === 0 && h.ranges[0][1] === (h.unicode ? 0x10ffff : 0xff)
}

function anyByteExceptNewline(h: Hir): boolean {
  return (
    h.k === 'class' &&
    !h.unicode &&
    h.ranges.length === 2 &&
    h.ranges[0][0] === 0 &&
    h.ranges[0][1] === 0x09 &&
    h.ranges[1][0] === 0x0b &&
    h.ranges[1][1] === 0xff
  )
}

function classToMaskedByte(ranges: [number, number][]): { value: number; mask: number } | null {
  if (ranges.length === 0) return null
  const lo = ranges[0][0]
  const hi = ranges[ranges.length - 1][1]
  const neg = hi ^ lo
  let count = 0
  for (const [s, e] of ranges) {
    for (let b = s; b <= e; b++) if ((b & lo) !== lo) return null
    count += e - s + 1
  }
  if (1 << popcount(neg) !== count) return null
  return { value: lo, mask: ~neg & 0xff }
}

function classToMaskedBytesAlternation(ranges: [number, number][]): { value: number; mask: number }[] | null {
  if (ranges.length === 0) return null
  const out: { value: number; mask: number }[] = []
  for (const [s, e] of ranges) {
    if ((s & e) !== s) return null
    const neg = s ^ e
    if (1 << popcount(neg) !== e - s + 1) return null
    out.push({ value: s, mask: ~neg & 0xff })
  }
  return out
}

// ---------------------------------------------------------------- seq helpers

function optimizeSeq(seq: Seq): Seq | null {
  const lits = seq.lits
  if (lits === null) return null
  if (lits.length === 1) return seq
  const map = new Map<string, Set<number>>()
  for (const l of lits) {
    if (l.bytes.length === 0) continue
    const key = l.bytes.slice(0, -1).join(',')
    if (!map.has(key)) map.set(key, new Set())
    map.get(key)!.add(l.bytes[l.bytes.length - 1])
  }
  for (const [k, v] of map) if (v.size !== 256) map.delete(k)
  if (map.size === 0) {
    seq.dedup()
    return seq
  }
  const emitted = new Set<string>()
  const out = Seq.empty()
  for (const l of lits) {
    if (l.bytes.length === 0) {
      out.push({ bytes: [...l.bytes], exact: l.exact })
      continue
    }
    const key = l.bytes.slice(0, -1).join(',')
    if (map.has(key)) {
      if (!emitted.has(key)) {
        emitted.add(key)
        out.push({ bytes: l.bytes.slice(0, -1), exact: false })
      }
    } else out.push({ bytes: [...l.bytes], exact: l.exact })
  }
  out.dedup()
  return out
}

function seqToAtoms(seq: Seq): Atom[] | null {
  const opt = optimizeSeq(seq)
  if (opt === null || opt.lits === null) return null
  let atoms: Atom[] = opt.lits.map((l) => ({ bytes: [...l.bytes], exact: l.exact, backtrack: 0 }))
  atoms.sort(cmpAtom)
  atoms = atoms.filter((a, i) => i === 0 || !sameAtom(a, atoms[i - 1]))
  const inexact = new Set<number>()
  const remove = new Set<number>()
  for (let i = 0; i + 1 < atoms.length; i++) {
    const a = atoms[i].bytes
    const n = atoms[i + 1].bytes
    if (sameBytes(a, n)) remove.add(i + 1)
    else if (n.length >= a.length && sameBytes(n.slice(0, a.length), a)) {
      inexact.add(i)
      remove.add(i + 1)
    }
  }
  inexact.forEach((i) => (atoms[i].exact = false))
  return atoms.filter((_, i) => !remove.has(i))
}

function concatSeq(seqs: Seq[]): { seq: Seq; added: number } | null {
  const first = seqs[0]
  if (!first) return null
  const len = first.len()
  if (len === null) return null
  if (len === 256) {
    const max = first.maxLiteralLen()
    if (max === 1 || max === null) return null
  }
  let emptyTail = 0
  for (let i = seqs.length - 1; i >= 0 && seqs[i].minLiteralLen() === 0; i--) emptyTail++
  const considered = seqs.length - emptyTail
  let added = 0
  let total = 0
  const result = Seq.singleton({ bytes: [], exact: true })
  for (const seq of seqs.slice(0, considered)) {
    const min = seq.minLiteralLen()
    if (min === null) break
    const cross = result.maxCrossLen(seq)
    if (cross === null || cross > MAX_ATOMS_PER_REGEXP) break
    result.crossForward(seq.clone())
    added++
    total += min
    if (total >= DESIRED_ATOM_SIZE) break
    if (result.isInexact()) break
  }
  if (added < seqs.length) result.makeInexact()
  result.keepFirstBytes(DESIRED_ATOM_SIZE)
  const opt = optimizeSeq(result)
  return opt ? { seq: opt, added } : null
}

function seqQuality(seq: Seq): AtomsQuality {
  return AtomsQuality.of(seq.lits ?? [])
}

// ---------------------------------------------------------------- extents

// Max bytes before each node's start and from its start to the pattern end.
type Where = Map<Hir, { before: number | null; after: number | null }>

function locate(root: Hir): Where {
  const where: Where = new Map()
  const walk = (h: Hir, before: number | null, tail: number | null) => {
    where.set(h, { before, after: add(h.p.maxLen, tail) })
    switch (h.k) {
      case 'cat': {
        let b = before
        h.subs.forEach((s, i) => {
          const rest = h.subs.slice(i + 1).reduce<number | null>((n, x) => add(n, x.p.maxLen), 0)
          walk(s, b, add(rest, tail))
          b = add(b, s.p.maxLen)
        })
        return
      }
      case 'alt':
        h.subs.forEach((s) => walk(s, before, tail))
        return
      case 'cap':
        walk(h.sub, before, tail)
        return
      case 'rep': {
        const extra = h.max === null ? null : h.max <= 1 ? 0 : h.sub.p.maxLen === null ? null : (h.max - 1) * h.sub.p.maxLen
        walk(h.sub, add(before, extra), add(extra, tail))
        return
      }
      default:
        return
    }
  }
  walk(root, 0, 0)
  return where
}

function extentAt(where: Where, node: Hir, offset: number): Extent {
  const w = where.get(node) ?? { before: null, after: null }
  return { backward: add(w.before, offset), forward: w.after === null ? null : w.after - offset }
}

// ---------------------------------------------------------------- Thompson (PikeVM)

// Where verification starts for a set of atoms: the node whose code runs
// forward from the hit, and how far into that node the atom begins.
interface Loc {
  node: Hir
  offset: number
}

interface Located {
  atoms: Atom[]
  quality: AtomsQuality
  locs: Loc[]
  span: Span | null
}

function emptyLocated(): Located {
  return { atoms: [], quality: AtomsQuality.min(), locs: [], span: null }
}

const MAX_ALTERNATIVES = 255

class TooManyAlternatives extends Error {}

function thompsonAtoms(root: Hir): Located {
  const stack: Located[] = [emptyLocated()]
  let depth = 0
  let zeroRep = 0

  const post = (h: Hir, atoms: Atom[] | null, node: Hir, offset: number, span: Span | null) => {
    if (!atoms || atoms.length === 0) return
    const canBeExact = depth === 0 && !h.p.hasLook
    if (!canBeExact) {
      atoms.forEach((a) => (a.exact = false))
      atoms.sort(cmpAtom)
      atoms = atoms.filter((a, i) => i === 0 || !sameAtom(a, atoms![i - 1]))
    }
    const quality = AtomsQuality.of(atoms)
    const best = stack[stack.length - 1]
    if (quality.cmp(best.quality) > 0) stack[stack.length - 1] = { atoms, quality, locs: [{ node, offset }], span }
  }

  const visit = (h: Hir): void => {
    // visit_pre
    if (h.k === 'alt') {
      if (h.subs.length > MAX_ALTERNATIVES) throw new TooManyAlternatives()
      stack.push(emptyLocated())
    }
    if (h.k === 'rep' && h.min === 0) zeroRep++
    depth++
    // children
    if (h.k === 'cat') h.subs.forEach(visit)
    else if (h.k === 'alt') {
      h.subs.forEach((s, i) => {
        if (i > 0) stack.push(emptyLocated())
        visit(s)
      })
    } else if (h.k === 'cap' || h.k === 'rep') visit(h.sub)
    // visit_post
    depth--
    switch (h.k) {
      case 'empty':
        if (zeroRep > 0) return
        post(h, [{ bytes: [], exact: true, backtrack: 0 }], h, 0, null)
        return
      case 'lit': {
        if (zeroRep > 0) return
        const a = bestAtomInBytes(h.bytes)
        const span = unionSpans(h.src.slice(a.backtrack, a.backtrack + a.bytes.length))
        post(h, [{ ...a, backtrack: 0 }], h, a.backtrack, span)
        return
      }
      case 'cap':
      case 'look':
      case 'class':
        if (zeroRep > 0) return
        post(h, seqToAtoms(extract(h)), h, 0, hirSpan(h))
        return
      case 'cat': {
        if (zeroRep > 0) return
        let best: Atom[] | null = null
        let bestQ = AtomsQuality.min()
        let node: Hir = h
        let span: Span | null = null
        const seqs = h.subs.map(extract)
        for (let i = 0; i < seqs.length; i++) {
          const r = concatSeq(seqs.slice(i))
          if (!r) continue
          if (i > 0) r.seq.makeInexact()
          const q = seqQuality(r.seq)
          if (q.cmp(bestQ) > 0) {
            bestQ = q
            best = seqToAtoms(r.seq)
            node = h.subs[i]
            span = unionSpans(h.subs.slice(i, i + Math.max(1, r.added)).map(hirSpan))
          }
        }
        post(h, best, node, 0, span)
        return
      }
      case 'alt': {
        const n = h.subs.length
        const branches = stack.splice(stack.length - n, n)
        const joined = branches.reduce((all, b) => {
          all.quality.merge(b.quality)
          all.atoms.push(...b.atoms)
          all.locs.push(...b.locs)
          all.span = unionSpans([all.span, b.span])
          return all
        })
        const best = stack[stack.length - 1]
        if (joined.atoms.length <= MAX_ATOMS_PER_REGEXP && joined.quality.cmp(best.quality) > 0) {
          stack[stack.length - 1] = joined
        }
        if (zeroRep > 0) return
        post(h, seqToAtoms(extract(h)), h, 0, hirSpan(h))
        return
      }
      case 'rep':
        if (h.min === 0) zeroRep--
        if (h.min === 0 || zeroRep > 0) return
        post(h, seqToAtoms(extract(h)), h, 0, hirSpan(h))
        return
    }
  }

  visit(root)
  const best = stack.pop()!
  if (best.atoms.length === 0) {
    return { atoms: [{ bytes: [], exact: false, backtrack: 0 }], quality: AtomsQuality.min(), locs: [{ node: root, offset: 0 }], span: null }
  }
  return best
}

// ---------------------------------------------------------------- FastVM

type FastPattern = { bytes: number[]; mask: number[] | null; src: (Span | null)[] }
type FastPiece =
  | { k: 'pattern'; pat: FastPattern }
  | { k: 'alt'; alts: FastPattern[] }
  | { k: 'jump'; min: number; max: number | null }

class FastIncompatible extends Error {
  readonly at: Span | null

  constructor(at: Span | null = null) {
    super('FastVM incompatible')
    this.at = at
  }
}

function splitFast(root: Hir): FastPiece[] {
  let bytes: number[] = []
  let mask: number[] = []
  let src: (Span | null)[] = []
  const pieces: FastPiece[] = []
  let alternatives: FastPattern[] = []
  let inAlt = false
  let inRep = false

  const finishLiteral = (): FastPattern | null => {
    if (!inAlt && bytes.length === 0) return null
    const pat: FastPattern = { bytes, mask: mask.every((m) => m === 0xff) ? null : mask, src }
    bytes = []
    mask = []
    src = []
    return pat
  }
  const pushPattern = () => {
    const pat = finishLiteral()
    if (pat) pieces.push({ k: 'pattern', pat })
  }

  const visit = (h: Hir): void => {
    switch (h.k) {
      case 'lit':
        bytes.push(...h.bytes)
        mask.push(...h.bytes.map(() => 0xff))
        src.push(...h.src)
        break
      case 'class': {
        if (inRep) break
        if (h.unicode) throw new FastIncompatible(hirSpan(h))
        const mb = classToMaskedByte(h.ranges)
        if (mb) {
          bytes.push(mb.value)
          mask.push(mb.mask)
          src.push(h.span)
          break
        }
        if (inAlt) throw new FastIncompatible(h.span)
        const alts = classToMaskedBytesAlternation(h.ranges)
        if (!alts) throw new FastIncompatible(h.span)
        pushPattern()
        pieces.push({ k: 'alt', alts: alts.map((b) => ({ bytes: [b.value], mask: [b.mask], src: [h.span] })) })
        break
      }
      case 'rep': {
        if (inRep || inAlt) throw new FastIncompatible(h.span)
        const ab = anyByte(h.sub)
        const abnl = anyByteExceptNewline(h.sub)
        if (!ab && !abnl) throw new FastIncompatible(h.span)
        const acceptNewlines = !abnl
        if (h.min === h.max && h.max <= 8 && acceptNewlines) {
          for (let i = 0; i < h.max; i++) {
            bytes.push(0)
            mask.push(0)
            src.push(h.span)
          }
        } else {
          pushPattern()
          pieces.push({ k: 'jump', min: h.min, max: h.max })
        }
        inRep = true
        break
      }
      case 'alt':
        if (inRep || inAlt) throw new FastIncompatible(hirSpan(h))
        if (h.subs.length > MAX_ALTERNATIVES) throw new TooManyAlternatives()
        pushPattern()
        inAlt = true
        break
      case 'look':
        throw new FastIncompatible(h.span)
      default:
        break
    }
    if (h.k === 'cat') h.subs.forEach(visit)
    else if (h.k === 'alt') {
      h.subs.forEach((s, i) => {
        if (i > 0) {
          const pat = finishLiteral()
          if (pat) alternatives.push(pat)
        }
        visit(s)
      })
    } else if (h.k === 'cap' || h.k === 'rep') visit(h.sub)
    if (h.k === 'rep') inRep = false
    if (h.k === 'alt') {
      const pat = finishLiteral()
      if (pat) alternatives.push(pat)
      pieces.push({ k: 'alt', alts: alternatives })
      alternatives = []
      inAlt = false
    }
  }

  visit(root)
  pushPattern()
  return pieces
}

function pieceLen(p: FastPiece): number | null {
  if (p.k === 'pattern') return p.pat.bytes.length
  if (p.k === 'alt') return Math.max(...p.alts.map((a) => a.bytes.length))
  return p.max
}

function fastAtoms(root: Hir): { atoms: Atom[]; span: Span | null; extent: Extent } {
  const pieces = splitFast(root)
  let bestQuality = -2147483648
  let best: { pat: FastPattern; range: [number, number] }[] | null = null
  let bestPiece = 0
  pieces.forEach((piece, i) => {
    const pats = piece.k === 'pattern' ? [piece.pat] : piece.k === 'alt' ? piece.alts : []
    const found = pats.map((pat) => {
      const r = pat.mask ? bestRangeInMaskedBytes(pat.bytes, pat.mask) : bestRangeInBytes(pat.bytes)
      return { pat, range: r.range, quality: r.quality }
    })
    const q = found.length ? Math.min(...found.map((f) => f.quality)) : -2147483648
    if (q > bestQuality) {
      bestQuality = q
      best = found
      bestPiece = i
    }
  })
  if (!best) throw new FastIncompatible()
  const atoms: Atom[] = []
  let extent: Extent = { backward: 0, forward: 0 }
  const before = pieces.slice(0, bestPiece).reduce<number | null>((n, p) => add(n, pieceLen(p)), 0)
  const after = pieces.slice(bestPiece + 1).reduce<number | null>((n, p) => add(n, pieceLen(p)), 0)
  const spans: (Span | null)[] = []
  for (const { pat, range } of best as { pat: FastPattern; range: [number, number] }[]) {
    const a = atomFromRange(pat.bytes, range)
    if (pat.mask) atoms.push(...maskCombinations(a, pat.mask.slice(range[0], range[1])))
    else atoms.push(a)
    spans.push(...pat.src.slice(range[0], range[1]))
    extent = maxExtent(extent, { backward: add(before, range[0]), forward: add(after, pat.bytes.length - range[0]) })
  }
  if (pieces.length > 1) atoms.forEach((a) => (a.exact = false))
  if (Math.min(...atoms.map((a) => a.bytes.length)) < 2) throw new FastIncompatible()
  return { atoms, span: unionSpans(spans), extent }
}

// ---------------------------------------------------------------- literal paths

function literalWithMask(root: Hir): { atoms: Atom[]; span: Span | null; extent: Extent } | null {
  const bytes: number[] = []
  const mask: number[] = []
  const src: (Span | null)[] = []
  const walk = (h: Hir): boolean => {
    switch (h.k) {
      case 'lit':
        bytes.push(...h.bytes)
        mask.push(...h.bytes.map(() => 0xff))
        src.push(...h.src)
        return true
      case 'rep':
        if (h.max !== h.min || !anyByte(h.sub)) return false
        for (let i = 0; i < h.min; i++) {
          bytes.push(0)
          mask.push(0)
          src.push(h.span)
        }
        return true
      case 'cat':
        return h.subs.every(walk)
      case 'class': {
        if (h.unicode) return false
        const mb = classToMaskedByte(h.ranges)
        if (!mb) return false
        bytes.push(mb.value)
        mask.push(mb.mask)
        src.push(h.span)
        return true
      }
      case 'cap':
        return walk(h.sub)
      default:
        return false
    }
  }
  if (!walk(root)) return null
  const { range } = bestRangeInMaskedBytes(bytes, mask)
  let atom = atomFromRange(bytes, range)
  let m = mask.slice(range[0], range[1])
  while (maskCombinationCount(m) > MAX_ATOMS_PER_REGEXP) {
    if (atom.bytes.length === 0) break
    atom = { ...atom, bytes: atom.bytes.slice(0, -1), exact: false }
    m = m.slice(0, -1)
    while (m.length && m[m.length - 1] === 0) {
      atom.bytes.pop()
      m.pop()
    }
  }
  if (atom.bytes.length === 0) return null
  return {
    atoms: maskCombinations(atom, m),
    span: unionSpans(src.slice(range[0], range[0] + atom.bytes.length)),
    extent: { backward: range[0], forward: bytes.length - range[0] },
  }
}

function isAlternationLiteral(h: Hir): boolean {
  if (h.p.altLiteral && h.k !== 'cat') return true
  return h.k === 'cap' && h.sub.p.altLiteral && h.sub.k !== 'cat'
}

function isSlowBytes(bytes: number[]): boolean {
  if (bytes.length === 1) return true
  return bytes.length > 0 && (bytes.every((b) => b === 0) || bytes.every((b) => b === 0x90) || bytes.every((b) => b === 0xff))
}

// c_regexp's slow-pattern rule, applied to the plain (not wide) atoms.
function slowAtoms(atoms: Atom[]): boolean {
  if (atoms.length === 0) return true
  const lens = atoms.map((a) => a.bytes.length)
  const min = Math.min(...lens)
  const max = Math.max(...lens)
  if (min < 2) return true
  return min === 2 && max === 2 && atoms.length > 2700
}

function regexpPiece(hir: Hir): Piece {
  let pikeBecause: Span | null = null
  try {
    const f = fastAtoms(hir)
    return { path: 'fast', hir, atoms: f.atoms, span: f.span, extent: f.extent, slow: slowAtoms(f.atoms), searched: [] }
  } catch (e) {
    if (!(e instanceof FastIncompatible)) throw e
    pikeBecause = e.at
  }
  const t = thompsonAtoms(hir)
  const where = locate(hir)
  const extent = t.locs.map((l) => extentAt(where, l.node, l.offset)).reduce(maxExtent)
  return { path: 'pike', hir, atoms: t.atoms, span: t.span, extent, slow: slowAtoms(t.atoms), pikeBecause, searched: [] }
}

function literalPiece(hir: Extract<Hir, { k: 'lit' }>, nocase: boolean, fullword: boolean): Piece {
  const a = bestAtomInBytes(hir.bytes)
  if (fullword) a.exact = false
  return {
    path: 'literal',
    hir,
    atoms: nocase ? caseCombinations(a) : [a],
    span: unionSpans(hir.src.slice(a.backtrack, a.backtrack + a.bytes.length)),
    extent: { backward: a.backtrack, forward: hir.bytes.length - a.backtrack },
    slow: false,
    searched: [],
  }
}

// ---------------------------------------------------------------- chaining

function splitAtLargeGaps(h: Hir): { head: Hir; tail: { gap: Gap; hir: Hir }[] } {
  if (h.k !== 'cat') return { head: h, tail: [] }
  let gapMin = 0
  let gapMax: number | null = null
  let gapGreedy = false
  let gapSpan: Span | null = null
  let chunks: Hir[] = []
  const chain: { gap: Gap; hir: Hir }[] = []
  for (const item of h.subs) {
    if (item.k === 'rep') {
      const span = (item.max ?? 4294967295) - item.min
      if (chunks.length > 0 && span > PATTERN_CHAINING_THRESHOLD && anyByte(item.sub)) {
        const piece = concat(chunks)
        if ((piece.p.minLen ?? 0) >= MIN_PATTERN_LENGTH_IN_CHAIN) {
          chain.push({ gap: { min: gapMin, max: gapMax, span: gapSpan }, hir: piece })
          gapMin = item.min
          gapMax = item.max
          gapGreedy = item.greedy
          gapSpan = item.span
          chunks = []
        } else {
          chunks = [piece, item]
        }
        continue
      }
    }
    chunks.push(item)
  }
  if (chunks.length === 0) {
    const [first, ...rest] = chain
    return { head: first.hir, tail: rest }
  }
  const last = concat(chunks)
  if (chain.length === 0 || (last.p.minLen ?? 0) >= MIN_PATTERN_LENGTH_IN_CHAIN) {
    chain.push({ gap: { min: gapMin, max: gapMax, span: gapSpan }, hir: last })
  } else {
    const prev = chain.pop()!
    const anyByteClass: Hir = { k: 'class', unicode: false, ranges: [[0, 0xff]], span: null, p: { minLen: 1, maxLen: 1, hasLook: false, literal: false, altLiteral: false } }
    prev.hir = concat([prev.hir, repetition(gapMin, gapMax, gapGreedy, anyByteClass, null), last])
    chain.push(prev)
  }
  const [first, ...rest] = chain
  return { head: first.hir, tail: rest }
}

// ---------------------------------------------------------------- entry point

export function extractAtoms(hir: Hir, opts: AtomOptions): AtomResult {
  const wide = opts.wide
  const raw = !opts.wide || opts.ascii
  const emptyMatch = hir.p.minLen === 0
  const plain = (atoms: Atom[]): SearchedAtom[] => atoms.map((atom) => ({ atom, wide: false }))
  const widen = (p: Piece, fullword: boolean): SearchedAtom[] => {
    const out: SearchedAtom[] = []
    if (p.path === 'literal' && p.hir.k === 'lit') {
      if (raw) out.push(...plain(p.atoms))
      if (wide) {
        const a = bestAtomInBytes(wideBytes(p.hir.bytes))
        if (fullword) a.exact = false
        out.push(...(opts.nocase ? caseCombinations(a) : [a]).map((atom) => ({ atom, wide: true })))
      }
      return out
    }
    if (wide) out.push(...p.atoms.map((a) => ({ atom: makeWide(a), wide: true })))
    if (raw) out.push(...plain(p.atoms))
    return out
  }
  const finish = (pieces: Piece[], gaps: Gap[], slow: boolean): AtomResult => ({
    pieces,
    gaps,
    emptyMatch,
    slow,
    all: pieces.flatMap((p) => p.searched.map((s) => s.atom)),
  })

  const { head, tail } = splitAtLargeGaps(hir)
  if (tail.length > 0) {
    const pieces = [head, ...tail.map((t) => t.hir)].map((h) => {
      const p = h.k === 'lit' ? literalPiece(h, opts.nocase, opts.fullword) : regexpPiece(h)
      return { ...p, searched: widen(p, opts.fullword) }
    })
    return finish(pieces, tail.map((t) => t.gap), pieces.some((p) => p.slow))
  }
  if (isAlternationLiteral(head)) {
    const inner = head.k === 'cap' ? head.sub : head
    const lits = (inner.k === 'alt' ? inner.subs : [inner]) as Extract<Hir, { k: 'lit' }>[]
    const ps = lits.map((l) => literalPiece(l, opts.nocase, false))
    const slow = head.k === 'lit' && !opts.fullword && isSlowBytes(head.bytes)
    const piece: Piece = {
      path: 'literal',
      hir: head,
      atoms: ps.flatMap((p) => p.atoms),
      span: unionSpans(ps.map((p) => p.span)),
      extent: ps.map((p) => p.extent).reduce(maxExtent),
      slow,
      searched: ps.flatMap((p) => widen(p, false)),
    }
    return finish([piece], [], slow)
  }
  const masked = !opts.nocase && !opts.wide ? literalWithMask(head) : null
  const p: Piece = masked
    ? { path: 'masked', hir: head, atoms: masked.atoms, span: masked.span, extent: masked.extent, slow: false, searched: [] }
    : regexpPiece(head)
  const piece = { ...p, searched: widen(p, opts.fullword) }
  return finish([piece], [], piece.slow)
}

export { TooManyAlternatives }
```

- [ ] **Step 6: Run it to verify it passes**

Run: `npx vitest run src/lib/yarax/__tests__/atoms.test.ts`
Expected: PASS, 97 tests (91 fixture cases + 6).

- [ ] **Step 7: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add src/lib/yarax/atoms.ts src/lib/yarax/__fixtures__/atoms.json scripts/yarax/gen-atoms.mjs src/lib/yarax/__tests__/atoms.test.ts
git commit -m "feat(yarax): port Yara-X 1.21.0 atom choice, checked against yr debug atoms

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Structure breakdown (`describe.ts`)

**Files:**
- Create: `src/lib/yarax/describe.ts`
- Test: `src/lib/yarax/__tests__/describe.test.ts`

**Interfaces:**
- Consumes: `Node`, `ClassItem`, `FlagChange`, `AssertKind`, `PerlKind`, `Span` (Task 1); `utf8` (Task 2).
- Produces: `describeYara(ast: Node, flags: { i: boolean; s: boolean }): StructureLine[]`, `StructureLine {depth, text, span}`.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest'
import { describeYara } from '../describe'
import { parseYaraRegex } from '../parse'

function lines(src: string, flags = { i: false, s: false }): string[] {
  const r = parseYaraRegex(src)
  if (!r.ok) throw new Error(r.error.message)
  return describeYara(r.ast, flags).map((l) => '  '.repeat(l.depth) + l.text)
}

describe('describeYara', () => {
  it('reads runs of characters as text and quantifiers as headers', () => {
    expect(lines('eval\\s*\\(')).toEqual([
      'the text `eval`',
      'zero or more times (as many as possible):',
      '  an ASCII whitespace byte (\\t \\n \\v \\f \\r or space)',
      'the character `(`',
    ])
  })

  it('words bytes and UTF-8 explicitly', () => {
    expect(lines('\\xFF')).toEqual(['the byte 0xFF'])
    expect(lines('é')).toEqual(['the UTF-8 bytes C3 A9 (é)'])
    expect(lines('\\x{E9}')).toEqual(['the UTF-8 bytes C3 A9 (é)'])
  })

  it('says groups never capture', () => {
    expect(lines('(ab)')).toEqual(["a group (Yara-X doesn't capture):", '  the text `ab`'])
    expect(lines('(?P<n>a)')[0]).toBe("a group named `n` (Yara-X doesn't capture):")
  })

  it('follows the flags in scope', () => {
    expect(lines('^.$')).toEqual(['the start of the data', 'any byte except \\n', 'the end of the data'])
    expect(lines('(?m)^.', { i: false, s: true })).toEqual([
      'from here on: `^` and `$` match at line breaks',
      'the start of a line',
      'any byte',
    ])
    expect(lines('ab', { i: true, s: false })).toEqual(['the text `ab`, any case'])
    expect(lines('[a-c]', { i: true, s: false })).toEqual(['one byte from: a-c, either case'])
  })

  it('lists alternatives', () => {
    expect(lines('ab|c')).toEqual(['either:', '  the text `ab`', 'or:', '  the character `c`'])
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/lib/yarax/__tests__/describe.test.ts`
Expected: FAIL — `Failed to resolve import "../describe"`.

- [ ] **Step 3: Write the implementation**

```ts
// Plain-English structure of a Yara-X regex, worded in bytes: Yara-X
// matches raw bytes, its classes and case folding are ASCII-only, and
// groups never capture.

import type { AssertKind, ClassItem, FlagChange, Node, PerlKind, Span } from './parse'
import { utf8 } from './hir'

export interface StructureLine {
  depth: number
  text: string
  span: Span | null
}

interface Scope {
  i: boolean
  s: boolean
  m: boolean
  U: boolean
}

const hex2 = (b: number) => b.toString(16).toUpperCase().padStart(2, '0')

const PERL_TEXT: Record<PerlKind, string> = {
  d: 'an ASCII digit (0-9)',
  s: 'an ASCII whitespace byte (\\t \\n \\v \\f \\r or space)',
  w: 'an ASCII word byte (A-Z, a-z, 0-9 or _)',
}

const PERL_NOT: Record<PerlKind, string> = {
  d: 'any byte except an ASCII digit',
  s: 'any byte except ASCII whitespace',
  w: 'any byte except an ASCII word byte',
}

function assertText(which: AssertKind, m: boolean): string {
  switch (which) {
    case 'start-line':
      return m ? 'the start of a line' : 'the start of the data'
    case 'end-line':
      return m ? 'the end of a line' : 'the end of the data'
    case 'start-text':
      return 'the start of the data'
    case 'end-text':
      return 'the end of the data'
    case 'word':
      return 'an ASCII word boundary'
    case 'not-word':
      return 'not an ASCII word boundary'
    case 'word-start':
      return 'the start of an ASCII word'
    case 'word-end':
      return 'the end of an ASCII word'
    case 'word-start-half':
      return 'a position not preceded by an ASCII word byte'
    case 'word-end-half':
      return 'a position not followed by an ASCII word byte'
  }
}

function quantText(min: number, max: number | null, greedy: boolean): string {
  let t: string
  if (min === 0 && max === null) t = 'zero or more times'
  else if (min === 1 && max === null) t = 'one or more times'
  else if (min === 0 && max === 1) t = 'optionally'
  else if (max === null) t = `${min} or more times`
  else if (min === max) t = `exactly ${min} time${min === 1 ? '' : 's'}`
  else t = `between ${min} and ${max} times`
  return `${t} (${greedy ? 'as many as possible' : 'as few as possible'})`
}

const FLAG_ON: Record<string, string> = {
  i: 'case-insensitive (ASCII letters only)',
  s: '`.` matches any byte, including \\n',
  m: '`^` and `$` match at line breaks',
  U: 'greedy and lazy quantifiers swapped',
}

const FLAG_OFF: Record<string, string> = {
  i: 'case-sensitive',
  s: '`.` matches any byte except \\n',
  m: '`^` and `$` match only at the ends of the data',
  U: 'quantifiers back to normal',
}

function flagText(f: FlagChange): string {
  return [...[...f.on].map((c) => FLAG_ON[c]), ...[...f.off].map((c) => FLAG_OFF[c])].join('; ')
}

function apply(scope: Scope, f: FlagChange): void {
  for (const c of f.on) scope[c as keyof Scope] = true
  for (const c of f.off) scope[c as keyof Scope] = false
}

function printable(cp: number): boolean {
  return cp >= 0x20 && cp < 0x7f
}

function charText(n: Extract<Node, { kind: 'char' }>, scope: Scope): string {
  if (n.byte && n.cp > 0x7f) return `the byte 0x${hex2(n.cp)}`
  if (n.cp > 0x7f) return `the UTF-8 bytes ${utf8(n.cp).map(hex2).join(' ')} (${String.fromCodePoint(n.cp)})`
  if (!printable(n.cp)) return `the byte 0x${hex2(n.cp)}`
  const c = String.fromCodePoint(n.cp)
  if (scope.i && /[A-Za-z]/.test(c)) return `\`${c.toLowerCase()}\` or \`${c.toUpperCase()}\``
  return `the character \`${c}\``
}

function itemText(item: ClassItem): string {
  switch (item.kind) {
    case 'char':
      return printable(item.cp) ? item.cp === 0x20 ? 'space' : String.fromCodePoint(item.cp) : `0x${hex2(item.cp)}`
    case 'range': {
      const e = (b: number) => (printable(b) && b !== 0x20 ? String.fromCodePoint(b) : `0x${hex2(b)}`)
      return `${e(item.lo)}-${e(item.hi)}`
    }
    case 'perl':
      return `\\${item.negated ? item.which.toUpperCase() : item.which}`
    case 'ascii':
      return `[:${item.negated ? '^' : ''}${item.name}:]`
    case 'bracket':
      return `[${item.negated ? '^' : ''}${item.items.map(itemText).join(' ')}]`
  }
}

// A run of plain printable characters reads as one line of text.
function textRun(items: Node[], from: number): number {
  let k = from
  while (k < items.length) {
    const n = items[k]
    if (n.kind !== 'char' || n.byte || !printable(n.cp)) break
    k++
  }
  return k
}

function walk(node: Node, depth: number, scope: Scope, out: StructureLine[]): void {
  const line = (text: string, span: Span | null = node.span) => out.push({ depth, text, span })
  switch (node.kind) {
    case 'empty':
      return
    case 'char':
      line(charText(node, scope))
      return
    case 'dot':
      line(scope.s ? 'any byte' : 'any byte except \\n')
      return
    case 'perl':
      line(node.negated ? PERL_NOT[node.which] : PERL_TEXT[node.which])
      return
    case 'assert':
      line(assertText(node.which, scope.m))
      return
    case 'class': {
      const set = node.items.map(itemText).join(' ')
      const fold = scope.i ? ', either case' : ''
      line(node.negated ? `one byte not in: ${set}${fold}` : `one byte from: ${set}${fold}`)
      return
    }
    case 'flags':
      apply(scope, node.flags)
      line(`from here on: ${flagText(node.flags)}`)
      return
    case 'repeat': {
      const greedy = scope.U ? !node.greedy : node.greedy
      line(`${quantText(node.min, node.max, greedy)}:`, node.opSpan)
      walk(node.sub, depth + 1, scope, out)
      return
    }
    case 'group': {
      const saved = { ...scope }
      if (node.flags) apply(scope, node.flags)
      const head = node.capture
        ? node.name
          ? `a group named \`${node.name}\` (Yara-X doesn't capture)`
          : "a group (Yara-X doesn't capture)"
        : node.flags
          ? `a group where ${flagText(node.flags)}`
          : 'a non-capturing group'
      line(`${head}:`)
      walk(node.sub, depth + 1, scope, out)
      Object.assign(scope, saved)
      return
    }
    case 'concat': {
      let k = 0
      while (k < node.items.length) {
        const end = textRun(node.items, k)
        if (end - k >= 2) {
          const run = node.items.slice(k, end) as Extract<Node, { kind: 'char' }>[]
          const text = run.map((c) => String.fromCodePoint(c.cp)).join('')
          const anyCase = scope.i && /[A-Za-z]/.test(text) ? ', any case' : ''
          out.push({ depth, text: `the text \`${text}\`${anyCase}`, span: { start: run[0].span.start, end: run[run.length - 1].span.end } })
          k = end
        } else {
          walk(node.items[k], depth, scope, out)
          k++
        }
      }
      return
    }
    case 'alt':
      node.items.forEach((item, i) => {
        line(i === 0 ? 'either:' : 'or:', i === 0 ? node.span : { start: node.bars[i - 1], end: node.bars[i - 1] + 1 })
        walk(item, depth + 1, scope, out)
      })
      return
  }
}

export function describeYara(ast: Node, flags: { i: boolean; s: boolean }): StructureLine[] {
  const out: StructureLine[] = []
  walk(ast, 0, { i: flags.i, s: flags.s, m: false, U: false }, out)
  return out
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `npx vitest run src/lib/yarax/__tests__/describe.test.ts`
Expected: PASS, 5 tests.

- [ ] **Step 5: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add src/lib/yarax/describe.ts src/lib/yarax/__tests__/describe.test.ts
git commit -m "feat(yarax): describe a pattern's structure in bytes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Cost, grade, span layering and the analysis entry point (`cost.ts`, `layer.ts`, `analyze.ts`)

**Files:**
- Create: `src/lib/yarax/cost.ts`, `src/lib/yarax/layer.ts`, `src/lib/yarax/analyze.ts`
- Test: `src/lib/yarax/__tests__/cost.test.ts`, `src/lib/yarax/__tests__/analyze.test.ts`

**Interfaces:**
- Consumes: Tasks 1-5; `knownCrash`, `Diag`, `YaraOptions`, `DEFAULT_YARA_OPTIONS` from `engine.ts` (exists).
- Produces: `cost.ts`: `assessCost(r: AtomResult, wide: boolean, engineSlow: boolean | null): Cost`, `Cost {grade: 'fast' | 'ok' | 'slow', weakest, average, count, minLength, tier: Tier, backward: Reach, forward: Reach, chained, portSlow, engineSlow, drift}`, `Reach {bytes, capped}`, `Tier`, `pieceTier(p)`, `TIER_LABEL`, constants `FAST_MIN_QUALITY = 60`, `FAST_MAX_EXTENT = 256`, `SCAN_LIMIT = 4096`, `MAX_QUALITY = 88`. `layer.ts`: `layerSpans(base: ClassSpan[], marks: ClassSpan[]): ClassSpan[]`. `analyze.ts`: `analyzePattern(pattern, opts): PatternAnalysis` (`{kind: 'empty'} | {kind: 'unparsed', message, span} | {kind: 'ok', tokens, atoms, structure}`), `costOf(analysis, diags: Diag[] | null, wide): Cost | null` (diags null = engine hasn't answered).

- [ ] **Step 1: Write the failing tests**

`src/lib/yarax/__tests__/cost.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { analyzePattern, costOf } from '../analyze'
import { DEFAULT_YARA_OPTIONS, type Diag, type YaraOptions } from '../engine'

const SLOW: Diag = { severity: 'warning', code: 'slow_pattern', title: 'slow pattern', labels: [], notes: [] }

function cost(pattern: string, o: Partial<YaraOptions> = {}, diags: Diag[] | null = []) {
  const opts = { ...DEFAULT_YARA_OPTIONS, ...o }
  const c = costOf(analyzePattern(pattern, opts), diags, opts.wide)
  if (!c) throw new Error('not analyzed')
  return c
}

describe('assessCost', () => {
  it('grades the default pattern OK: great atom, unbounded verification', () => {
    expect(cost('eval\\s*\\(\\s*base64_decode\\s*\\(')).toMatchObject({
      grade: 'ok',
      weakest: 86,
      count: 1,
      minLength: 4,
      tier: 'pikevm',
      forward: { bytes: 4096, capped: true },
      backward: { bytes: 4096, capped: true },
    })
  })

  it('grades a bounded pattern with good atoms Fast', () => {
    expect(cost('foo.{0,10}barz')).toMatchObject({ grade: 'fast', tier: 'fastvm', forward: { bytes: 4, capped: false }, backward: { bytes: 13, capped: false } })
  })

  it('counts an exact atom as nothing to verify', () => {
    expect(cost('evil')).toMatchObject({ grade: 'fast', tier: 'exact', forward: { bytes: 0 }, backward: { bytes: 0 } })
  })

  it('grades Slow by the port or by the engine, and flags disagreement', () => {
    expect(cost('[a-z]', {}, [SLOW])).toMatchObject({ grade: 'slow', portSlow: true, engineSlow: true, drift: false })
    expect(cost('abcd', {}, [SLOW])).toMatchObject({ grade: 'slow', portSlow: false, engineSlow: true, drift: true })
    expect(cost('abcd', {}, null)).toMatchObject({ engineSlow: null, drift: false })
  })

  it('doubles the verified bytes for wide', () => {
    expect(cost('foo.{0,10}barz', { wide: true })).toMatchObject({ backward: { bytes: 26 }, forward: { bytes: 8 } })
  })

  it('marks chained patterns', () => {
    expect(cost('abcd.{0,300}efgh', { s: true }).chained).toBe(true)
  })
})
```

`src/lib/yarax/__tests__/analyze.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { analyzePattern } from '../analyze'
import { DEFAULT_YARA_OPTIONS } from '../engine'
import { layerSpans } from '../layer'

describe('analyzePattern', () => {
  it('analyzes a pattern into tokens, atoms and structure', () => {
    const a = analyzePattern('ab+', DEFAULT_YARA_OPTIONS)
    expect(a.kind).toBe('ok')
    if (a.kind !== 'ok') return
    expect(a.tokens.map((t) => t.kind)).toEqual(['literal', 'literal', 'quant'])
    expect(a.atoms.all.map((x) => x.bytes)).toEqual([[0x61, 0x62]])
    expect(a.structure[0].text).toBe('the character `a`')
  })

  it('honors the i suffix and nocase alike', () => {
    const count = (o: object) => {
      const a = analyzePattern('abc', { ...DEFAULT_YARA_OPTIONS, ...o })
      return a.kind === 'ok' ? a.atoms.all.length : -1
    }
    expect(count({ i: true })).toBe(8)
    expect(count({ nocase: true })).toBe(8)
  })

  it("says why it can't analyze a pattern", () => {
    expect(analyzePattern('', DEFAULT_YARA_OPTIONS)).toEqual({ kind: 'empty' })
    expect(analyzePattern('a\nb', DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: 'a Yara-X regex must be on a single line' })
    expect(analyzePattern('(?u)\\w', DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: /crashes the Yara-X engine/ })
    expect(analyzePattern('foo{', DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: 'unclosed counted repetition', span: { start: 3, end: 4 } })
    const many = Array.from({ length: 256 }, (_, i) => `x${i}y`).join('|')
    expect(analyzePattern(`(${many})z`, DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: /255 alternatives/ })
  })
})

describe('layerSpans', () => {
  it('splits colored tokens at mark boundaries and joins the classes', () => {
    expect(
      layerSpans(
        [
          { start: 0, end: 4, className: 'tok-lit' },
          { start: 4, end: 6, className: 'tok-meta' },
        ],
        [
          { start: 2, end: 5, className: 'hl-atom' },
          { start: 3, end: 4, className: 'hl-err' },
        ],
      ),
    ).toEqual([
      { start: 0, end: 2, className: 'tok-lit' },
      { start: 2, end: 3, className: 'tok-lit hl-atom' },
      { start: 3, end: 4, className: 'tok-lit hl-atom hl-err' },
      { start: 4, end: 5, className: 'tok-meta hl-atom' },
      { start: 5, end: 6, className: 'tok-meta' },
    ])
  })

  it('keeps marks outside any token', () => {
    expect(layerSpans([], [{ start: 1, end: 2, className: 'hl-err' }])).toEqual([{ start: 1, end: 2, className: 'hl-err' }])
  })
})
```

- [ ] **Step 2: Run them to verify they fail**

Run: `npx vitest run src/lib/yarax/__tests__/cost.test.ts src/lib/yarax/__tests__/analyze.test.ts`
Expected: FAIL — `Failed to resolve import "../analyze"` (and `"../layer"`).

- [ ] **Step 3: Write `cost.ts`**

```ts
// Scan cost of a Yara-X regex: how good its atoms are, how much the engine
// verifies around each atom hit, and a headline grade. "Slow" is Yara-X's
// own slow_pattern rule; Fast/OK is this tester's heuristic, tuned by the
// two constants below.

import type { AtomResult, Extent, Piece } from './atoms'
import { atomQuality } from './quality'

export const FAST_MIN_QUALITY = 60
export const FAST_MAX_EXTENT = 256
// Yara-X's DEFAULT_SCAN_LIMIT: verification scans at most this many bytes
// in each direction from an atom hit.
export const SCAN_LIMIT = 4096
export const MAX_QUALITY = 88

export type Tier = 'exact' | 'compare' | 'masked' | 'fastvm' | 'pikevm'
export type Grade = 'fast' | 'ok' | 'slow'

export const TIER_LABEL: Record<Tier, string> = {
  exact: 'exact atom (no verification)',
  compare: 'byte compare',
  masked: 'masked compare',
  fastvm: 'FastVM',
  pikevm: 'PikeVM',
}

const TIER_ORDER: Tier[] = ['exact', 'compare', 'masked', 'fastvm', 'pikevm']

// Bytes verified in one direction. `capped` means the pattern allows more
// and the engine stops at SCAN_LIMIT.
export interface Reach {
  bytes: number
  capped: boolean
}

export interface Cost {
  grade: Grade
  weakest: number
  average: number
  count: number
  minLength: number
  tier: Tier
  backward: Reach
  forward: Reach
  chained: boolean
  // The slow_pattern verdict of this port and of the engine (null until
  // the engine has answered).
  portSlow: boolean
  engineSlow: boolean | null
  drift: boolean
}

export function pieceTier(p: Piece): Tier {
  if (p.atoms.length > 0 && p.atoms.every((a) => a.exact && a.bytes.length > 0)) return 'exact'
  if (p.path === 'literal') return 'compare'
  if (p.path === 'masked') return 'masked'
  if (p.path === 'fast') return 'fastvm'
  return 'pikevm'
}

function reach(n: number | null, wide: boolean): Reach {
  if (n === null) return { bytes: SCAN_LIMIT, capped: true }
  const bytes = wide ? n * 2 : n
  return bytes > SCAN_LIMIT ? { bytes: SCAN_LIMIT, capped: true } : { bytes, capped: false }
}

function pieceExtent(p: Piece): Extent {
  return pieceTier(p) === 'exact' ? { backward: 0, forward: 0 } : p.extent
}

function widest(a: Reach, b: Reach): Reach {
  return a.bytes > b.bytes || (a.bytes === b.bytes && a.capped) ? a : b
}

export function assessCost(r: AtomResult, wide: boolean, engineSlow: boolean | null): Cost {
  const qualities = r.all.map((a) => Math.max(0, atomQuality(a.bytes)))
  const weakest = qualities.length ? Math.min(...qualities) : 0
  const average = qualities.length ? qualities.reduce((n, q) => n + q, 0) / qualities.length : 0
  const minLength = r.all.length ? Math.min(...r.all.map((a) => a.bytes.length)) : 0
  const tiers = r.pieces.map(pieceTier)
  const tier = TIER_ORDER[Math.max(...tiers.map((t) => TIER_ORDER.indexOf(t)))]
  let backward: Reach = { bytes: 0, capped: false }
  let forward: Reach = { bytes: 0, capped: false }
  for (const p of r.pieces) {
    const e = pieceExtent(p)
    backward = widest(backward, reach(e.backward, wide))
    forward = widest(forward, reach(e.forward, wide))
  }
  const slow = r.slow || engineSlow === true
  const fast =
    !slow &&
    weakest >= FAST_MIN_QUALITY &&
    !backward.capped &&
    !forward.capped &&
    backward.bytes <= FAST_MAX_EXTENT &&
    forward.bytes <= FAST_MAX_EXTENT
  return {
    grade: slow ? 'slow' : fast ? 'fast' : 'ok',
    weakest,
    average,
    count: r.all.length,
    minLength,
    tier,
    backward,
    forward,
    chained: r.gaps.length > 0,
    portSlow: r.slow,
    engineSlow,
    drift: engineSlow !== null && engineSlow !== r.slow,
  }
}
```

- [ ] **Step 4: Write `layer.ts`**

```ts
// The highlighter gives each character one span (the shortest wins), so
// syntax colors and underlines can't simply overlap. This splits the
// colored tokens at every mark boundary and joins the class names, giving
// non-overlapping spans like `tok-lit hl-atom`.

export interface ClassSpan {
  start: number
  end: number
  className: string
}

export function layerSpans(base: ClassSpan[], marks: ClassSpan[]): ClassSpan[] {
  const all = [...base, ...marks]
  const points = [...new Set(all.flatMap((s) => [s.start, s.end]))].sort((a, b) => a - b)
  const out: ClassSpan[] = []
  for (let i = 0; i + 1 < points.length; i++) {
    const [a, b] = [points[i], points[i + 1]]
    const covers = (s: ClassSpan) => s.start <= a && s.end >= b
    const classes = [base.find(covers)?.className, ...marks.filter(covers).map((m) => m.className)].filter(
      (c, k, arr): c is string => !!c && arr.indexOf(c) === k,
    )
    if (classes.length === 0) continue
    const className = classes.join(' ')
    const prev = out[out.length - 1]
    if (prev && prev.end === a && prev.className === className) prev.end = b
    else out.push({ start: a, end: b, className })
  }
  return out
}
```

- [ ] **Step 5: Write `analyze.ts`**

```ts
// Everything the Analysis tab and the pattern coloring need, computed
// synchronously from the pattern and options (no engine involved).

import { extractAtoms, TooManyAlternatives, type AtomResult } from './atoms'
import { assessCost, type Cost } from './cost'
import { describeYara, type StructureLine } from './describe'
import { knownCrash, type Diag, type YaraOptions } from './engine'
import { translate } from './hir'
import { parseYaraRegex, type Span, type Token } from './parse'

export type PatternAnalysis =
  | { kind: 'empty' }
  | { kind: 'unparsed'; message: string; span: Span | null }
  | { kind: 'ok'; tokens: Token[]; atoms: AtomResult; structure: StructureLine[] }

export function analyzePattern(pattern: string, opts: YaraOptions): PatternAnalysis {
  if (pattern === '') return { kind: 'empty' }
  if (pattern.includes('\n')) return { kind: 'unparsed', message: 'a Yara-X regex must be on a single line', span: null }
  const crash = knownCrash(pattern)
  if (crash) return { kind: 'unparsed', message: `${crash} crashes the Yara-X engine, so it isn't analyzed`, span: null }
  const parsed = parseYaraRegex(pattern)
  if (!parsed.ok) return { kind: 'unparsed', message: parsed.error.message, span: parsed.error.span }
  const flags = { i: opts.i || opts.nocase, s: opts.s }
  try {
    const atoms = extractAtoms(translate(parsed.ast, flags), {
      nocase: flags.i,
      wide: opts.wide,
      ascii: opts.ascii,
      fullword: opts.fullword,
    })
    return { kind: 'ok', tokens: parsed.tokens, atoms, structure: describeYara(parsed.ast, flags) }
  } catch (e) {
    if (e instanceof TooManyAlternatives) {
      return { kind: 'unparsed', message: 'more than 255 alternatives in one alternation', span: null }
    }
    throw e
  }
}

// The cost needs the engine's slow_pattern verdict; `diags` is null until
// the engine has answered.
export function costOf(analysis: PatternAnalysis, diags: Diag[] | null, wide: boolean): Cost | null {
  if (analysis.kind !== 'ok') return null
  const engineSlow = diags ? diags.some((d) => d.code === 'slow_pattern') : null
  return assessCost(analysis.atoms, wide, engineSlow)
}
```

- [ ] **Step 6: Run them to verify they pass**

Run: `npx vitest run src/lib/yarax/__tests__/cost.test.ts src/lib/yarax/__tests__/analyze.test.ts`
Expected: PASS, 11 tests.

- [ ] **Step 7: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add src/lib/yarax/cost.ts src/lib/yarax/layer.ts src/lib/yarax/analyze.ts src/lib/yarax/__tests__/cost.test.ts src/lib/yarax/__tests__/analyze.test.ts
git commit -m "feat(yarax): grade scan cost and bundle the pattern analysis

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Suggestions (`advice.ts`)

**Files:**
- Create: `src/lib/yarax/advice.ts`
- Test: `src/lib/yarax/__tests__/advice.test.ts`

**Interfaces:**
- Consumes: Tasks 4 and 6; `Diag` from `engine.ts`.
- Produces: `suggest(pattern: string, r: AtomResult, cost: Cost, diags: Diag[]): Suggestion[]`, `Suggestion {rule, text, span}`, `showAtom(bytes): string`. Rules: `engine-diag`, `short-atom`, `common-bytes`, `atom-explosion`, `weak-branch`, `unbounded-forward`, `unbounded-backward`, `pikevm`, `chained`, `drift`. With an engine error, only `engine-diag` entries are returned.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from 'vitest'
import { analyzePattern, costOf } from '../analyze'
import { suggest } from '../advice'
import { DEFAULT_YARA_OPTIONS, type Diag, type YaraOptions } from '../engine'

function advise(pattern: string, o: Partial<YaraOptions> = {}, diags: Diag[] = []) {
  const opts = { ...DEFAULT_YARA_OPTIONS, ...o }
  const a = analyzePattern(pattern, opts)
  if (a.kind !== 'ok') throw new Error('not analyzed')
  return suggest(pattern, a.atoms, costOf(a, diags, opts.wide)!, diags)
}

const rules = (pattern: string, o: Partial<YaraOptions> = {}, diags: Diag[] = []) => advise(pattern, o, diags).map((s) => s.rule)

describe('suggest', () => {
  it('flags unbounded repetitions on each side of the atom, once per wording', () => {
    const s = advise('eval\\s*\\(\\s*base64_decode\\s*\\(')
    expect(s.map((x) => x.rule)).toEqual(['unbounded-backward', 'unbounded-forward', 'pikevm'])
    expect(s[0].text).toBe(
      '`\\s*` lets verification scan up to 4,096 bytes backward from each atom hit; bound it, for example `\\s{0,16}`.',
    )
    expect(s[1].span).toEqual({ start: 25, end: 28 })
    expect(s[2].text).toMatch(/^PikeVM is used because of `\\s\*`/)
  })

  it('flags short and common-byte atoms', () => {
    expect(advise('ab')[0]).toMatchObject({ rule: 'short-atom', text: 'The best atom is only `ab` (40/88). Put a distinctive literal of 4 or more bytes next to it.' })
    expect(rules('\\x00\\x00\\x00\\x00')).toContain('common-bytes')
  })

  it('flags atom explosions and weak branches', () => {
    expect(advise('[A-Za-z]{2,}x').find((s) => s.rule === 'atom-explosion')?.text).toBe(
      '`[A-Za-z]{2,}` expands to 2,704 atoms of 2 bytes. Anchor the pattern on a literal instead.',
    )
    expect(rules('abcd|e')).toContain('weak-branch')
  })

  it('explains chaining', () => {
    expect(advise('abcd.{0,300}efgh', { s: true }).find((s) => s.rule === 'chained')?.text).toBe(
      "This pattern is split at the `.{0,300}` gap and the pieces are checked separately; the gap isn't limited to 4,096 bytes.",
    )
  })

  it('has nothing to say about a good pattern', () => {
    expect(advise('foo.{0,10}barz')).toEqual([])
  })

  it('turns engine diagnostics into fixes, and stops there on errors', () => {
    const e015: Diag = { severity: 'error', code: 'E015', title: 'invalid regular expression', labels: [{ text: 'this is greedy', start: 1, end: 3 }], notes: [] }
    expect(advise('a.*?b.*c', {}, [e015])).toEqual([
      {
        rule: 'engine-diag',
        text: 'E015: invalid regular expression. Use only greedy (`*`, `+`, `{n,m}`) or only lazy (`*?`, `+?`, `{n,m}?`) quantifiers in one regex.',
        span: { start: 1, end: 3 },
      },
    ])
    const slow: Diag = { severity: 'warning', code: 'slow_pattern', title: 'slow pattern', labels: [], notes: [] }
    expect(rules('abcd', {}, [slow])).toEqual(['engine-diag', 'drift'])
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/lib/yarax/__tests__/advice.test.ts`
Expected: FAIL — `Failed to resolve import "../advice"`.

- [ ] **Step 3: Write the implementation**

```ts
// Rewrite suggestions for a Yara-X regex. Each rule looks at the atoms, the
// cost and the engine's diagnostics, and points at a span of the pattern.

import { type Atom, type AtomResult, type Piece, makeWide } from './atoms'
import { sameBytes } from './literal'
import type { Hir } from './hir'
import type { Span } from './parse'
import type { Diag } from './engine'
import { type Cost, FAST_MIN_QUALITY, MAX_QUALITY, SCAN_LIMIT, pieceTier } from './cost'
import { atomQuality } from './quality'

export interface Suggestion {
  rule: string
  text: string
  span: Span | null
}

const COMMON = new Set([0x00, 0x20, 0x90, 0xcc, 0xff])

const DIAG_FIX: Record<string, string> = {
  E001: 'Write each `/` inside the regex as `\\/`.',
  E014: 'Fix the regex syntax at the marked spot.',
  E015: 'Use only greedy (`*`, `+`, `{n,m}`) or only lazy (`*?`, `+?`, `{n,m}?`) quantifiers in one regex.',
  E030: 'Only the `i` and `s` suffixes are allowed after the closing `/`.',
  E033: '`xor` and `base64` only work on text strings, not on regexes.',
  E045: 'Under `/s` the regex must not start with `.*` or `.+`; start it with a literal.',
  slow_pattern: 'Make sure every match contains a distinctive literal of 3 or more bytes.',
  redundant_modifier: 'Drop either the `i` suffix or `nocase`; they do the same thing.',
}

export function showAtom(bytes: number[]): string {
  if (bytes.length === 0) return '(empty)'
  if (bytes.every((b) => b >= 0x20 && b < 0x7f)) return String.fromCharCode(...bytes)
  return bytes.map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join(' ')
}

function src(pattern: string, span: Span | null): string {
  return span ? pattern.slice(span.start, span.end) : ''
}

function diagFix(d: Diag): string | null {
  if (d.code === 'E014' && /empty strings/.test(d.title + d.labels.map((l) => l.text).join(' '))) {
    return 'Require at least one byte: right now every part of the regex is optional.'
  }
  return DIAG_FIX[d.code] ?? null
}

function weakestAtom(atoms: Atom[]): { atom: Atom; quality: number } | null {
  let best: { atom: Atom; quality: number } | null = null
  for (const atom of atoms) {
    const quality = Math.max(0, atomQuality(atom.bytes))
    if (!best || quality < best.quality || (quality === best.quality && atom.bytes.length < best.atom.bytes.length)) {
      best = { atom, quality }
    }
  }
  return best
}

// The piece an atom (plain or wide) belongs to.
function pieceOf(r: AtomResult, atom: Atom): Piece | undefined {
  return r.pieces.find((p) =>
    p.atoms.some((a) => sameBytes(a.bytes, atom.bytes) || sameBytes(makeWide(a).bytes, atom.bytes)),
  )
}

function unboundedReps(h: Hir, out: Extract<Hir, { k: 'rep' }>[] = []): Extract<Hir, { k: 'rep' }>[] {
  if (h.k === 'rep') {
    if (h.max === null && h.span) out.push(h)
    unboundedReps(h.sub, out)
  } else if (h.k === 'cat' || h.k === 'alt') h.subs.forEach((s) => unboundedReps(s, out))
  else if (h.k === 'cap') unboundedReps(h.sub, out)
  return out
}

// `\s*` -> `\s{0,16}`, `x+` -> `x{1,16}`, `y{3,}` -> `y{3,19}`.
function bounded(text: string, min: number): string {
  const body = text.replace(/(\*|\+|\?|\{\d*,?\d*\})\??$/, '')
  return `${body}{${min},${min + 16}}`
}

function unbounded(pattern: string, p: Piece, out: Suggestion[]): void {
  if (!p.span || pieceTier(p) === 'exact') return
  const atom = p.span
  for (const rep of unboundedReps(p.hir)) {
    const text = src(pattern, rep.span)
    const fix = `bound it, for example \`${bounded(text, rep.min)}\`.`
    if (p.extent.forward === null && rep.span!.end > atom.end) {
      out.push({
        rule: 'unbounded-forward',
        text: `\`${text}\` lets verification scan up to ${SCAN_LIMIT.toLocaleString('en-US')} bytes forward from each atom hit; ${fix}`,
        span: rep.span,
      })
    } else if (p.extent.backward === null && rep.span!.start < atom.start) {
      out.push({
        rule: 'unbounded-backward',
        text: `\`${text}\` lets verification scan up to ${SCAN_LIMIT.toLocaleString('en-US')} bytes backward from each atom hit; ${fix}`,
        span: rep.span,
      })
    }
  }
}

export function suggest(pattern: string, r: AtomResult, cost: Cost, diags: Diag[]): Suggestion[] {
  const out: Suggestion[] = []
  for (const d of diags) {
    const fix = diagFix(d)
    const label = d.labels.find((l) => l.start !== null && l.end !== null)
    const span = label ? { start: label.start!, end: label.end! } : null
    out.push({ rule: 'engine-diag', text: `${d.code}: ${d.title}.${fix ? ` ${fix}` : ''}`, span })
  }
  if (diags.some((d) => d.severity === 'error')) return out

  const weak = weakestAtom(r.all)
  const atomSpan = weak ? pieceOf(r, weak.atom)?.span ?? null : null
  if (weak && weak.atom.bytes.length === 0) {
    out.push({
      rule: 'short-atom',
      text: 'No atom could be extracted, so the regex engine runs at every offset of the data. Add a literal of 4 or more bytes that every match contains.',
      span: null,
    })
  } else if (weak && (weak.atom.bytes.length < 3 || weak.quality < FAST_MIN_QUALITY)) {
    out.push({
      rule: 'short-atom',
      text: `The best atom is only \`${showAtom(weak.atom.bytes)}\` (${weak.quality}/${MAX_QUALITY}). Put a distinctive literal of 4 or more bytes next to it.`,
      span: atomSpan,
    })
  }

  if (weak && weak.atom.bytes.length >= 2) {
    const common = weak.atom.bytes.filter((b) => COMMON.has(b)).length
    if (common * 2 >= weak.atom.bytes.length) {
      out.push({
        rule: 'common-bytes',
        text: `Atom \`${showAtom(weak.atom.bytes)}\` is mostly common bytes (00, 20, 90, CC, FF) and will hit constantly; pick a more distinctive literal.`,
        span: atomSpan,
      })
    }
  }

  for (const p of r.pieces) {
    const explosive = p.atoms.length > 256 || (p.slow && p.atoms.length > 2700)
    if (explosive) {
      const len = Math.min(...p.atoms.map((a) => a.bytes.length))
      out.push({
        rule: 'atom-explosion',
        text: `\`${src(pattern, p.span)}\` expands to ${p.atoms.length.toLocaleString('en-US')} atoms of ${len} byte${len === 1 ? '' : 's'}. Anchor the pattern on a literal instead.`,
        span: p.span,
      })
    }
  }

  for (const p of r.pieces) {
    if (p.atoms.length < 2 || p.atoms.length > 256) continue
    const qs = p.atoms.map((a) => Math.max(0, atomQuality(a.bytes)))
    const min = Math.min(...qs)
    if (min < FAST_MIN_QUALITY && Math.max(...qs) - min >= 20) {
      const w = p.atoms[qs.indexOf(min)]
      out.push({
        rule: 'weak-branch',
        text: `Atom \`${showAtom(w.bytes)}\` (${min}/${MAX_QUALITY}) holds this pattern's atom quality down; give each alternative a longer literal, or split them into separate strings.`,
        span: p.span,
      })
    }
  }

  for (const p of r.pieces) unbounded(pattern, p, out)

  for (const p of r.pieces) {
    if (p.path !== 'pike' || pieceTier(p) === 'exact') continue
    const why = p.pikeBecause
      ? `\`${src(pattern, p.pikeBecause)}\``
      : 'its best FastVM atom being shorter than 2 bytes'
    out.push({
      rule: 'pikevm',
      text: `PikeVM is used because of ${why}; FastVM only handles literals, single masked bytes and \`.\` gaps such as \`.{0,N}\`.`,
      span: p.pikeBecause ?? null,
    })
  }

  const gap = r.gaps.find((g) => g.span)
  if (gap) {
    out.push({
      rule: 'chained',
      text: `This pattern is split at the \`${src(pattern, gap.span)}\` gap and the pieces are checked separately; the gap isn't limited to ${SCAN_LIMIT.toLocaleString('en-US')} bytes.`,
      span: gap.span,
    })
  }

  if (cost.drift) {
    out.push({
      rule: 'drift',
      text: `The engine ${cost.engineSlow ? 'warns' : "doesn't warn"} that this pattern is slow, but this analysis says it ${cost.portSlow ? 'is' : "isn't"}: the analysis may be out of date with the engine.`,
      span: null,
    })
  }
  // Two `\s*` on the same side read the same; say it once.
  return out.filter((s, i) => out.findIndex((t) => t.text === s.text) === i)
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `npx vitest run src/lib/yarax/__tests__/advice.test.ts`
Expected: PASS, 6 tests.

- [ ] **Step 5: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add src/lib/yarax/advice.ts src/lib/yarax/__tests__/advice.test.ts
git commit -m "feat(yarax): suggest rewrites for weak atoms and costly verification

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Analysis tab, pattern coloring and atom underline (UI)

**Files:**
- Create: `src/components/yarax/YaraAnalysis.tsx`
- Modify: `src/components/yarax/YaraPatternPane.tsx` (full new content below), `src/components/yarax/YaraWorkbench.tsx` (full new content below), `src/components/yarax/__tests__/YaraPatternPane.test.tsx` (two props), `src/index.css` (append)
- Test: `src/components/yarax/__tests__/YaraAnalysis.test.tsx`

**Interfaces:**
- Consumes: `analyzePattern`, `costOf`, `PatternAnalysis` (Task 6), `suggest`, `showAtom` (Task 7), `pieceTier`, `TIER_LABEL`, `MAX_QUALITY`, `Cost`, `Reach` (Task 6), `layerSpans` (Task 6), `Token`, `TokenKind`, `Span` (Task 1), `atomQuality` (Task 3).
- Produces: `YaraAnalysis({ pattern, analysis, diags, cost })`; `YaraPatternPane` gains required props `tokens: Token[]` and `atomSpans: Span[]`.

- [ ] **Step 1: Write the failing test**

```tsx
// @vitest-environment jsdom
import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { YaraAnalysis } from '../YaraAnalysis'
import { YaraPatternPane } from '../YaraPatternPane'
import { analyzePattern, costOf } from '../../../lib/yarax/analyze'
import { DEFAULT_YARA_OPTIONS, type Diag } from '../../../lib/yarax/engine'

afterEach(cleanup)

function renderAnalysis(pattern: string, diags: Diag[] | null = []) {
  const analysis = analyzePattern(pattern, DEFAULT_YARA_OPTIONS)
  return render(
    <YaraAnalysis pattern={pattern} analysis={analysis} diags={diags} cost={costOf(analysis, diags, false)} />,
  )
}

describe('YaraAnalysis', () => {
  it('shows the grade, numbers, atoms, verification, suggestions and structure', () => {
    const { container } = renderAnalysis('eval\\s*\\(\\s*base64_decode\\s*\\(')
    const text = container.textContent ?? ''
    expect([...container.querySelectorAll('.ya-h')].map((h) => h.firstChild?.textContent)).toEqual([
      'Scan cost ',
      'Atoms',
      'Verification',
      'Suggestions',
      'Structure',
    ])
    expect(container.querySelector('.ya-grade')?.textContent).toBe('● OK')
    expect(text).toContain("(this tester's heuristic)")
    expect(text).toContain('weakest atom 86/88 · avg 86 · 1 atom · min length 4 B · verify: PikeVM')
    expect(text).toContain('forward ≤ 4,096 B (unbounded, capped) · backward ≤ 4,096 B (unbounded, capped)')
    expect(container.querySelector('.ya-atom')?.textContent).toBe('"e64_"')
    expect(text).toContain('inexact (needs verification)')
    expect(text).toContain('PikeVM is used because of `\\s*`')
    expect(text).toContain('the text `base64_decode`')
  })

  it("labels Slow as Yara-X's rule and lists only the first 16 atoms", () => {
    const { container } = renderAnalysis('[a-z]')
    expect(container.querySelector('.ya-grade')?.textContent).toBe('● Slow')
    expect(container.textContent).toContain("(Yara-X's rule)")
    expect(container.querySelectorAll('.ya-atom')).toHaveLength(16)
    expect(container.textContent).toContain('… 10 more · by length: 1 B × 26')
  })

  it('shows only the engine errors and their fixes when the engine rejects the pattern', () => {
    const e015: Diag = { severity: 'error', code: 'E015', title: 'invalid regular expression', labels: [], notes: [] }
    const { container } = renderAnalysis('a.*?b.*c', [e015])
    expect(container.querySelector('.ya-h')?.textContent).toBe('The engine rejected this pattern')
    expect(container.querySelectorAll('li')).toHaveLength(1)
  })

  it('grades without waiting for the engine', () => {
    const { container } = renderAnalysis('foo.{0,10}barz', null)
    expect(container.querySelector('.ya-grade')?.textContent).toBe('● Fast')
    expect(container.textContent).not.toContain('out of date')
  })

  it("explains when it can't analyze a pattern", () => {
    const { container } = renderAnalysis('foo{')
    expect(container.textContent).toBe(
      "Can't analyze this pattern: unclosed counted repetition. The Matches tab still shows what the engine reports.",
    )
  })
})

describe('YaraPatternPane coloring', () => {
  it('colors tokens and underlines the atom', () => {
    const analysis = analyzePattern('ab\\s*cdef', DEFAULT_YARA_OPTIONS)
    if (analysis.kind !== 'ok') throw new Error()
    const { container } = render(
      <YaraPatternPane
        pattern="ab\s*cdef"
        opts={DEFAULT_YARA_OPTIONS}
        errors={[]}
        warnings={[]}
        tokens={analysis.tokens}
        atomSpans={analysis.atoms.pieces.map((p) => p.span!)}
        onPattern={() => {}}
        onOpts={() => {}}
      />,
    )
    const spans = [...container.querySelectorAll('.codearea-hl span:not(.__hl-tail)')].map((s) => [s.className, s.textContent])
    expect(spans).toEqual([
      ['tok-lit', 'ab'],
      ['tok-meta', '\\s'],
      ['tok-quant', '*'],
      ['tok-lit hl-atom', 'cdef'],
    ])
  })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/components/yarax/__tests__/YaraAnalysis.test.tsx`
Expected: FAIL — `Failed to resolve import "../YaraAnalysis"`.

- [ ] **Step 3: Write `YaraAnalysis.tsx`**

```tsx
import { useMemo } from 'react'
import type { PatternAnalysis } from '../../lib/yarax/analyze'
import type { Piece, SearchedAtom } from '../../lib/yarax/atoms'
import { MAX_QUALITY, pieceTier, TIER_LABEL, type Cost, type Reach } from '../../lib/yarax/cost'
import { showAtom, suggest } from '../../lib/yarax/advice'
import type { Diag } from '../../lib/yarax/engine'
import { atomQuality } from '../../lib/yarax/quality'

const MAX_ATOM_ROWS = 16

const GRADE_TEXT = { fast: 'Fast', ok: 'OK', slow: 'Slow' } as const

function reachText(r: Reach): string {
  return r.capped ? `≤ ${r.bytes.toLocaleString('en-US')} B (unbounded, capped)` : `${r.bytes.toLocaleString('en-US')} B`
}

function quoteAtom(bytes: number[]): string {
  const s = showAtom(bytes)
  return bytes.length > 0 && bytes.every((b) => b >= 0x20 && b < 0x7f) ? `"${s}"` : s
}

function AtomRows({ pieces, pattern }: { pieces: Piece[]; pattern: string }) {
  const rows = pieces.flatMap((p) =>
    p.searched.map((s: SearchedAtom) => ({ ...s, quality: Math.max(0, atomQuality(s.atom.bytes)), from: p.span })),
  )
  rows.sort((a, b) => a.quality - b.quality)
  const shown = rows.slice(0, MAX_ATOM_ROWS)
  const byLength = new Map<number, number>()
  for (const r of rows) byLength.set(r.atom.bytes.length, (byLength.get(r.atom.bytes.length) ?? 0) + 1)
  return (
    <>
      <table className="ya-atoms">
        <tbody>
          {shown.map((r, i) => (
            <tr key={i}>
              <td className="ya-atom">{quoteAtom(r.atom.bytes)}</td>
              <td className="ynum">
                {r.quality}/{MAX_QUALITY}
              </td>
              <td className="ya-dim">
                {r.atom.exact ? 'exact (no verification)' : 'inexact (needs verification)'}
                {r.wide ? ' · wide' : ''}
              </td>
              <td className="ya-dim">from: {r.from ? <code>{pattern.slice(r.from.start, r.from.end)}</code> : '(whole pattern)'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > MAX_ATOM_ROWS && (
        <div className="ya-dim">
          … {(rows.length - MAX_ATOM_ROWS).toLocaleString('en-US')} more · by length:{' '}
          {[...byLength]
            .sort((a, b) => a[0] - b[0])
            .map(([len, n]) => `${len} B × ${n.toLocaleString('en-US')}`)
            .join(', ')}
        </div>
      )}
    </>
  )
}

function Verification({ pieces, pattern }: { pieces: Piece[]; pattern: string }) {
  return (
    <ul className="ya-list">
      {pieces.map((p, i) => {
        const label = pieces.length > 1 ? `piece ${i + 1} (${TIER_LABEL[pieceTier(p)]}): ` : ''
        if (p.atoms.every((a) => a.exact && a.bytes.length > 0)) {
          return <li key={i}>{label}the atoms cover the whole pattern; nothing is verified</li>
        }
        const before = p.span ? pattern.slice(0, p.span.start) : ''
        const after = p.span ? pattern.slice(p.span.end) : pattern
        return (
          <li key={i}>
            {label}→ forward: {after ? <code>{after}</code> : 'nothing after the atom'} · ← backward:{' '}
            {before ? <code>{before}</code> : 'nothing before the atom'}
          </li>
        )
      })}
    </ul>
  )
}

export function YaraAnalysis({
  pattern,
  analysis,
  diags,
  cost,
}: {
  pattern: string
  analysis: PatternAnalysis
  diags: Diag[] | null
  cost: Cost | null
}) {
  const suggestions = useMemo(
    () => (analysis.kind === 'ok' && cost ? suggest(pattern, analysis.atoms, cost, diags ?? []) : []),
    [pattern, analysis, cost, diags],
  )

  if (analysis.kind === 'empty') return <div className="empty">Enter a Yara-X regex to see its atoms and scan cost.</div>
  if (analysis.kind === 'unparsed') {
    return (
      <div className="empty">
        Can't analyze this pattern: {analysis.message}. The Matches tab still shows what the engine reports.
      </div>
    )
  }
  if (!cost) return null
  const rejected = (diags ?? []).some((d) => d.severity === 'error')
  if (rejected) {
    return (
      <div className="ya">
        <h3 className="ya-h">The engine rejected this pattern</h3>
        <ul className="ya-list">
          {suggestions.map((s, i) => (
            <li key={i}>{s.text}</li>
          ))}
        </ul>
      </div>
    )
  }
  const slowSource = cost.grade === 'slow' ? "Yara-X's rule" : "this tester's heuristic"
  return (
    <div className="ya">
      <h3 className="ya-h">
        Scan cost <span className={`ya-grade grade-${cost.grade}`}>● {GRADE_TEXT[cost.grade]}</span>{' '}
        <span className="ya-dim">({slowSource})</span>
      </h3>
      <div className="ya-nums">
        weakest atom {cost.weakest}/{MAX_QUALITY} · avg {Math.round(cost.average)} · {cost.count.toLocaleString('en-US')} atom
        {cost.count === 1 ? '' : 's'} · min length {cost.minLength} B · verify: {TIER_LABEL[cost.tier]}
      </div>
      <div className="ya-nums">
        forward {reachText(cost.forward)} · backward {reachText(cost.backward)}
        {cost.chained ? ' · chained: pieces are checked separately' : ''}
      </div>

      <h3 className="ya-h">Atoms</h3>
      <AtomRows pieces={analysis.atoms.pieces} pattern={pattern} />

      <h3 className="ya-h">Verification</h3>
      <Verification pieces={analysis.atoms.pieces} pattern={pattern} />

      <h3 className="ya-h">Suggestions</h3>
      {suggestions.length ? (
        <ul className="ya-list">
          {suggestions.map((s, i) => (
            <li key={i}>{s.text}</li>
          ))}
        </ul>
      ) : (
        <div className="ya-dim">None: this pattern has good atoms and bounded verification.</div>
      )}

      <h3 className="ya-h">Structure</h3>
      <ul className="expllist">
        {analysis.structure.map((l, i) => (
          <li key={i} className="expl">
            <span style={{ paddingLeft: `${l.depth * 14}px` }}>{l.text}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
```

- [ ] **Step 4: Replace `YaraPatternPane.tsx`**

```tsx
import { useMemo } from 'react'
import { CodeArea } from '../CodeArea'
import { Flag } from '../Flag'
import type { Span } from '../Highlighter'
import { formatDiag, type Diag, type YaraOptions } from '../../lib/yarax/engine'
import { layerSpans } from '../../lib/yarax/layer'
import type { Span as SourceSpan, Token, TokenKind } from '../../lib/yarax/parse'

const TOKEN_CLASS: Record<TokenKind, string> = {
  literal: 'tok-lit',
  escape: 'tok-esc',
  dot: 'tok-dot',
  meta: 'tok-meta',
  anchor: 'tok-anchor',
  class: 'tok-class',
  quant: 'tok-quant',
  group: 'tok-group',
  non: 'tok-non',
  alt: 'tok-alt',
}

const SUFFIXES = [
  { key: 'i', name: 'ignore case', tip: 'i suffix: case-insensitive (ASCII letters only)' },
  { key: 's', name: 'dot matches all', tip: 's suffix: . also matches \\n (any byte)' },
] as const

const MODIFIERS = [
  { key: 'nocase', tip: 'nocase: case-insensitive, same as the i suffix' },
  { key: 'wide', tip: 'wide: match UTF-16LE text (a 00 byte after each byte)' },
  { key: 'ascii', tip: 'ascii: match the plain bytes; with wide, search both encodings' },
  { key: 'fullword', tip: 'fullword: no ASCII letter or digit right before or after the match' },
] as const

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
  tokens,
  atomSpans,
  onPattern,
  onOpts,
}: {
  pattern: string
  opts: YaraOptions
  errors: Diag[]
  warnings: Diag[]
  tokens: Token[]
  atomSpans: SourceSpan[]
  onPattern: (v: string) => void
  onOpts: (o: YaraOptions) => void
}) {
  const spans = useMemo(
    () =>
      layerSpans(
        tokens.map((t) => ({ start: t.start, end: t.end, className: TOKEN_CLASS[t.kind] })),
        [...atomSpans.map((s) => ({ ...s, className: 'hl-atom' })), ...diagSpans([...errors, ...warnings])],
      ),
    [tokens, atomSpans, errors, warnings],
  )
  const error = errors.map(formatDiag).join('\n')
  const warning = warnings.map(formatDiag).join('\n')
  const flag = (key: keyof YaraOptions, tip: string, name?: string) => (
    <Flag
      key={key}
      label={key}
      name={name}
      tip={tip}
      checked={opts[key]}
      onChange={(on) => onOpts({ ...opts, [key]: on })}
    />
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
        spans={spans}
        error={error}
      />
      {error && <div className="errorbox">{error}</div>}
      {warning && <div className="warnbox">{warning}</div>}
      <footer className="flagbar">
        {SUFFIXES.map((s) => flag(s.key, s.tip, s.name))}
        <span className="flag-sep" aria-hidden />
        {MODIFIERS.map((m) => flag(m.key, m.tip))}
      </footer>
    </section>
  )
}
```

- [ ] **Step 5: Replace `YaraWorkbench.tsx`**

```tsx
import { useMemo, useState, type Dispatch, type ReactNode, type SetStateAction } from 'react'
import { Frame } from '../Frame'
import { InputPane } from '../InputPane'
import type { Span } from '../Highlighter'
import { YaraPatternPane } from './YaraPatternPane'
import { YaraMatchList } from './YaraMatchList'
import { YaraAnalysis } from './YaraAnalysis'
import { analyzePattern, costOf } from '../../lib/yarax/analyze'
import { useYaraScan } from './useYaraScan'
import { formatDiag, type YaraMatch, type YaraOptions } from '../../lib/yarax/engine'
import { mapBytes } from '../../lib/yarax/bytes'
import { YARA_SAMPLE_INPUT } from '../../lib/yarax/samples'
import type { Layout } from '../../lib/layout'
import type { Span as SourceSpan } from '../../lib/yarax/parse'

const NO_MATCHES: YaraMatch[] = []
const NO_SPANS: SourceSpan[] = []

const GRADE_BADGE = { fast: 'Fast', ok: 'OK', slow: 'Slow' } as const

export function YaraWorkbench({
  pattern,
  opts,
  input,
  onPattern,
  onOpts,
  onInput,
  layout,
  onLayout,
  sidebar,
}: {
  pattern: string
  opts: YaraOptions
  input: string
  onPattern: (v: string) => void
  onOpts: (o: YaraOptions) => void
  onInput: (v: string) => void
  layout: Layout
  onLayout: Dispatch<SetStateAction<Layout>>
  sidebar: ReactNode
}) {
  const [tab, setTab] = useState<'matches' | 'analysis'>('matches')
  const scan = useYaraScan(pattern, opts, input)
  const map = useMemo(() => mapBytes(input), [input])
  const result = scan.status === 'ready' ? scan.result : null
  const errors = result?.errors ?? []
  const warnings = result?.warnings ?? []
  const matches = result?.matches ?? NO_MATCHES
  const analysis = useMemo(() => analyzePattern(pattern, opts), [pattern, opts])
  const diags = useMemo(() => (result ? [...result.errors, ...result.warnings] : null), [result])
  const cost = useMemo(() => costOf(analysis, diags, opts.wide), [analysis, diags, opts.wide])
  const atomSpans = useMemo(
    () =>
      analysis.kind === 'ok' && !errors.length
        ? analysis.atoms.pieces.flatMap((p) => (p.span ? [p.span] : []))
        : NO_SPANS,
    [analysis, errors.length],
  )

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
    <Frame
      layout={layout}
      onLayout={onLayout}
      sidebar={sidebar}
      left={
        <YaraPatternPane
          pattern={pattern}
          opts={opts}
          errors={errors}
          warnings={warnings}
          tokens={analysis.kind === 'ok' ? analysis.tokens : []}
          atomSpans={atomSpans}
          onPattern={onPattern}
          onOpts={onOpts}
        />
      }
      right={<InputPane input={input} spans={inputSpans} onInput={onInput} sample={YARA_SAMPLE_INPUT} />}
      results={
        <section className="results">
          <div className="tabs">
            <button className={'tab' + (tab === 'matches' ? ' tab-on' : '')} onClick={() => setTab('matches')}>
              Matches
              <span className="tab-badge">{badge}</span>
            </button>
            <button className={'tab' + (tab === 'analysis' ? ' tab-on' : '')} onClick={() => setTab('analysis')}>
              Analysis
              <span className={'tab-badge' + (cost ? ` grade-${cost.grade}` : '')}>
                {cost ? GRADE_BADGE[cost.grade] : analysis.kind === 'unparsed' ? '!' : '–'}
              </span>
            </button>
          </div>
          <div className="results-body">
            {tab === 'analysis' ? (
              <YaraAnalysis pattern={pattern} analysis={analysis} diags={diags} cost={cost} />
            ) : scan.status === 'loading' ? (
              <div className="empty">Loading the Yara-X engine…</div>
            ) : scan.status === 'unavailable' ? (
              <div className="empty error-empty">
                Yara-X engine unavailable: {scan.reason}{' '}
                <button className="linkbtn" onClick={scan.retry}>
                  Retry
                </button>
              </div>
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
      }
    />
  )
}
```

- [ ] **Step 6: Pass the new props in the existing pane test**

In `src/components/yarax/__tests__/YaraPatternPane.test.tsx`, add two props after `warnings={[]}`:

```tsx
        warnings={[]}
        tokens={[]}
        atomSpans={[]}
```

- [ ] **Step 7: Append the styles to `src/index.css`**

```css
.hl-atom { text-decoration: underline 2px var(--accent); text-underline-offset: 4px; }
.hl-atom.hl-err, .hl-err.hl-atom { text-decoration: underline wavy var(--error-fg); }
.hl-atom.hl-warn, .hl-warn.hl-atom { text-decoration: underline wavy var(--warn-fg); }

.ya { font-size: 13px; }
.ya-h {
  font-size: 11px; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase;
  color: var(--text-dim); margin: 14px 0 6px; display: flex; gap: 8px; align-items: baseline;
}
.ya-h:first-child { margin-top: 2px; }
.ya-grade { font-size: 12px; letter-spacing: 0.4px; }
.grade-fast { color: var(--g2); }
.grade-ok { color: var(--warn-fg); }
.grade-slow { color: var(--error-fg); }
.ya-nums { font: 12px/1.6 var(--mono); color: var(--text); }
.ya-dim { color: var(--text-dim); font-size: 12px; text-transform: none; letter-spacing: 0; font-weight: 400; }
.ya-atoms { border-collapse: collapse; }
.ya-atoms td { padding: 2px 14px 2px 0; vertical-align: top; }
.ya-atom { font-family: var(--mono); color: var(--text-hi); white-space: nowrap; }
.ya-list { margin: 0; padding-left: 18px; }
.ya-list li { margin: 3px 0; line-height: 1.5; }
.ya code, .ya-dim code { font-family: var(--mono); color: var(--text-hi); }
```

- [ ] **Step 8: Run the component tests**

Run: `npx vitest run src/components/yarax`
Expected: PASS, 9 tests.

- [ ] **Step 9: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add src/components/yarax src/index.css
git commit -m "feat(yarax): Analysis tab with grade, atoms, verification, suggestions and structure

Color the Yara-X pattern and underline the chosen atom.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Expected gate result: `Tests  251 passed`, oxlint shows only the 2 `react(purity)` warnings.

---

### Task 9: Docs and browser check

**Files:**
- Modify: `CLAUDE.md`, `README.md`

- [ ] **Step 1: Document the analysis in `CLAUDE.md`**

After the bullet `- Tests load the engine with \`initSync\` and the \`.wasm\` from \`node_modules\`.`, add:

```markdown

**Yara-X analysis** (`lib/yarax/analyze.ts` → `components/yarax/YaraAnalysis.tsx`): a pure TypeScript port of how Yara-X 1.21.0 chooses atoms, run synchronously on every edit; the engine never exposes atoms.
- Pipeline: `parse.ts` (tree with UTF-16 spans + coloring tokens) → `hir.ts` (regex-syntax 0.8.11's normalized form: merged literals, single-char alternations folded into classes, common prefixes lifted; each literal byte keeps its source span) → `atoms.ts` (Yara-X's paths in order: split at `.{n,m}` gaps over 200 under `/s`, literal or alternation of literals, masked literal, FastVM, PikeVM via `literal.ts`'s extractor) → `cost.ts` (tier, extents, grade) / `advice.ts` / `describe.ts`.
- Keep the port faithful rather than "improving" it: small differences (alternation order, `Seq::dedup` only removing neighbors, i32::MIN for empty atoms) change which atoms win. `src/lib/yarax/__fixtures__/atoms.json` holds `yr debug atoms` output for 95 patterns and `atoms.test.ts` must match it exactly.
- Upgrading `@virustotal/yara-x`: build `yara-x-cli` at the same tag with `--features debug-cmd`, run `YR=… node scripts/yarax/gen-atoms.mjs`, and port whatever changed upstream until the fixture test passes again.
- The engine stays the authority: with an engine error the Analysis tab shows only the errors and fixes; the engine's `slow_pattern` warning is merged into the grade (`costOf`), and disagreement with the port is reported as drift.
- `layer.ts` exists because `Highlighter` gives each character one span: it splits coloring tokens at underline boundaries and joins class names (`tok-lit hl-atom`).
```

- [ ] **Step 2: Mention the analysis in `README.md`**

Replace the bullet list under the first paragraph:

```markdown
- matches and capture groups highlighted live in the text,
- a match table with one column per capture group,
- a plain-English explanation of the pattern,
- a token cheat sheet.
```

with:

```markdown
- matches and capture groups highlighted live in the text,
- a match table with one column per capture group,
- a plain-English explanation of the pattern,
- for Yara-X, an analysis of the atoms the engine searches for, how much it verifies around each hit, a Fast/OK/Slow grade and rewrite suggestions,
- a token cheat sheet.
```

- [ ] **Step 3: Check it in a browser**

Run `npm run dev`, open the printed URL, switch the flavor to Yara-X and open the Analysis tab. Expected with the default pattern `eval\s*\(\s*base64_decode\s*\(`:
- Matches badge `2 in … ms`; Analysis badge `OK`.
- Scan cost `● OK (this tester's heuristic)`, `weakest atom 86/88 · avg 86 · 1 atom · min length 4 B · verify: PikeVM`, `forward ≤ 4,096 B (unbounded, capped) · backward ≤ 4,096 B (unbounded, capped)`.
- Atoms: `"e64_"  86/88  inexact (needs verification)`; in the pattern, `e64_` inside `base64_decode` is underlined.
- Suggestions: one backward `\s*`, one forward `\s*`, one PikeVM line.

Then type each pattern and check the badge: `[a-z]` → `Slow` (and the engine's slow_pattern warning shows under the pattern), `foo.{0,10}barz` → `Fast`, `foo{` → `!` with "Can't analyze this pattern: unclosed counted repetition".

- [ ] **Step 4: Gate and commit**

```bash
npx tsc -b && npx oxlint && npx vitest run
git add CLAUDE.md README.md
git commit -m "docs: describe the Yara-X atom analysis and how to refresh its fixture

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
