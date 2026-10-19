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
