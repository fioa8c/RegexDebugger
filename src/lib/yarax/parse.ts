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
