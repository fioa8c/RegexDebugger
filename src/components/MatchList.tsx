import type { MatchInfo } from '../lib/matcher'
import { groupColor } from '../lib/colors'

export interface GroupLabel {
  label: string
  index: number
}

export function MatchList({ matches, groupLabels }: { matches: MatchInfo[]; groupLabels: GroupLabel[] }) {
  if (matches.length === 0) {
    return <div className="empty">No matches found.</div>
  }

  return (
    <div className="matchlist">
      <table>
        <thead>
          <tr>
            <th className="mcol">Match</th>
            {groupLabels.map((g) => (
              <th key={g.index} className="gcol">
                <span className="glabel">
                  <span
                    className="swatch"
                    style={{ background: groupColor(g.index - 1) }}
                    aria-hidden
                  />
                  {g.label}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matches.map((m, mi) => (
            <tr key={mi}>
              <td className="mcol">
                <div className="idx">#{mi + 1}</div>
                <div className="mtext" title={m.text}>{m.text}</div>
              </td>
              {groupLabels.map((g) => {
                const hit = m.groups[g.index - 1]
                if (!hit) {
                  return (
                    <td key={g.index} className="gcol">
                      <div className="gvalue" title="(no match)">&mdash;</div>
                    </td>
                  )
                }
                return (
                  <td key={g.index} className="gcol">
                    <div className="gvalue" title={`${hit.value}`}>{hit.value}</div>
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
