import type { YaraMatch } from '../../lib/yarax/engine'
import { showBytes } from '../../lib/yarax/bytes'

export function YaraMatchList({
  matches,
  bytes,
  wideHint,
}: {
  matches: YaraMatch[]
  bytes: Uint8Array
  wideHint: boolean
}) {
  if (matches.length === 0) {
    return (
      <div className="empty">
        No matches found.
        {wideHint && (
          <div className="hint">
            <code>wide</code> searches for UTF-16LE text (a 00 byte after each byte), which
            pasted text doesn't contain. Turn on <code>ascii</code> too to search both.
          </div>
        )}
      </div>
    )
  }
  return (
    <div className="matchlist">
      <table>
        <thead>
          <tr>
            <th className="ynum">Match</th>
            <th className="ynum">Offset</th>
            <th className="ynum">Length</th>
            <th>Text</th>
          </tr>
        </thead>
        <tbody>
          {matches.map((m, i) => {
            const text = showBytes(bytes.slice(m.offset, m.offset + m.length))
            return (
              <tr key={i}>
                <td className="ynum idx">#{i + 1}</td>
                <td className="ynum">{m.offset}</td>
                <td className="ynum">{m.length}</td>
                <td>
                  <div className="mtext" title={text}>{text}</div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
