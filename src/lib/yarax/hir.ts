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
