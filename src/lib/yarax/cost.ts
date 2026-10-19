// Scan cost of a Yara-X regex: how good its atoms are, how much the engine
// verifies around each atom hit, and a headline grade. "Slow" is Yara-X's
// own slow_pattern rule; Fast/OK is this tester's heuristic, tuned by the
// two constants below.

import type { Atom, AtomResult, Extent, Piece } from './atoms'
import { minOf } from './literal'
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
  // With `wide`, the quality numbers score the pattern's own atoms: the
  // 00 bytes wide interleaves would cap every atom below Fast, and the
  // pattern can't change them.
  wide: boolean
  // The slow_pattern verdict of this port and of the engine (null until
  // the engine has answered).
  portSlow: boolean
  engineSlow: boolean | null
  drift: boolean
}

const isExact = (a: Atom) => a.exact && a.bytes.length > 0

// Exact only if every atom actually searched is (a wide literal's atom is
// a window of the UTF-16 bytes, so it still needs verifying).
export function pieceTier(p: Piece): Tier {
  const exact = p.searched.length ? p.searched.every((s) => isExact(s.atom)) : p.atoms.length > 0 && p.atoms.every(isExact)
  if (exact) return 'exact'
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
  const scored = wide ? r.pieces.flatMap((p) => p.atoms) : r.all
  const qualities = scored.map((a) => Math.max(0, atomQuality(a.bytes)))
  const weakest = qualities.length ? minOf(qualities) : 0
  const average = qualities.length ? qualities.reduce((n, q) => n + q, 0) / qualities.length : 0
  const minLength = scored.length ? minOf(scored.map((a) => a.bytes.length)) : 0
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
    wide,
    portSlow: r.slow,
    engineSlow,
    drift: engineSlow !== null && engineSlow !== r.slow,
  }
}
