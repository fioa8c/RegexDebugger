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
        // Forward verification starts at the atom's first byte (see extentAt).
        const before = p.span ? pattern.slice(0, p.span.start) : ''
        const after = p.span ? pattern.slice(p.span.start) : pattern
        return (
          <li key={i}>
            {label}→ forward: {after ? <code>{after}</code> : 'nothing from the atom on'} · ← backward:{' '}
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
