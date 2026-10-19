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
import { DESIRED_ATOM_SIZE, MAX_ATOMS_PER_REGEXP, Seq, cmpBytes, extract, maxOf, minOf, pushAll, sameBytes } from './literal'

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
          pushAll(all.atoms, b.atoms)
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
    const q = found.length ? minOf(found.map((f) => f.quality)) : -2147483648
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
    if (pat.mask) pushAll(atoms, maskCombinations(a, pat.mask.slice(range[0], range[1])))
    else atoms.push(a)
    spans.push(...pat.src.slice(range[0], range[1]))
    extent = maxExtent(extent, { backward: add(before, range[0]), forward: add(after, pat.bytes.length - range[0]) })
  }
  if (pieces.length > 1) atoms.forEach((a) => (a.exact = false))
  if (minOf(atoms.map((a) => a.bytes.length)) < 2) throw new FastIncompatible()
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
  const min = minOf(lens)
  const max = maxOf(lens)
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
      if (raw) pushAll(out, plain(p.atoms))
      if (wide) {
        const a = bestAtomInBytes(wideBytes(p.hir.bytes))
        if (fullword) a.exact = false
        pushAll(out, (opts.nocase ? caseCombinations(a) : [a]).map((atom) => ({ atom, wide: true })))
      }
      return out
    }
    if (wide) pushAll(out, p.atoms.map((a) => ({ atom: makeWide(a), wide: true })))
    if (raw) pushAll(out, plain(p.atoms))
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
