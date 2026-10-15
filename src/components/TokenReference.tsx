import { REFERENCE, YARAX_REFERENCE } from '../lib/tokens'

export function TokenReference({ flavor }: { flavor: 'javascript' | 'yarax' }) {
  const entries = flavor === 'yarax' ? YARAX_REFERENCE : REFERENCE
  return (
    <aside className="sidenav">
      <h2 className="sidenav-title">Token Reference</h2>
      <table className="sidenav-table">
        {entries.map((r, i) => (
          <tr key={i}>
            <td className="tok" title={r.pattern}>{r.pattern}</td>
            <td className="desc">{r.description}</td>
          </tr>
        ))}
      </table>
    </aside>
  )
}
