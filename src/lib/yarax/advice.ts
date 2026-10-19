// Rewrite suggestions for a Yara-X regex. Each rule looks at the atoms, the
// cost and the engine's diagnostics, and points at a span of the pattern.

import { type Atom, type AtomResult, type Piece, makeWide } from './atoms'
import { maxOf, minOf, sameBytes } from './literal'
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

// Forward verification starts at the atom's first byte and re-reads the
// atom, so a repetition anywhere after that point (even inside the atom's
// span, as in `foo\s*bar`) is on the forward side.
function unbounded(pattern: string, p: Piece, out: Suggestion[]): void {
  if (!p.span || pieceTier(p) === 'exact') return
  const atom = p.span
  for (const rep of unboundedReps(p.hir)) {
    const text = src(pattern, rep.span)
    const fix = `bound it, for example \`${bounded(text, rep.min)}\`.`
    if (p.extent.forward === null && rep.span!.end > atom.start) {
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

// The engine's errors and warnings, each with its fix when one is known.
export function diagSuggestions(diags: Diag[]): Suggestion[] {
  return diags.map((d) => {
    const fix = diagFix(d)
    const label = d.labels.find((l) => l.start !== null && l.end !== null)
    const span = label ? { start: label.start!, end: label.end! } : null
    return { rule: 'engine-diag', text: `${d.code}: ${d.title}.${fix ? ` ${fix}` : ''}`, span }
  })
}

export function suggest(pattern: string, r: AtomResult, cost: Cost, diags: Diag[]): Suggestion[] {
  const out = diagSuggestions(diags)
  if (diags.some((d) => d.severity === 'error')) return out

  // Score the pattern's own atoms; see Cost.wide.
  const weak = weakestAtom(cost.wide ? r.pieces.flatMap((p) => p.atoms) : r.all)
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
      const len = minOf(p.atoms.map((a) => a.bytes.length))
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
    const min = minOf(qs)
    if (min < FAST_MIN_QUALITY && maxOf(qs) - min >= 20) {
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
