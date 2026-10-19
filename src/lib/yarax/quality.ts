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
