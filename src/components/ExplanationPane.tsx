import { describeToken } from '../lib/describe'
import { flattenTokens, type Token } from '../lib/explain'

export function ExplanationPane({ tokens, flags }: { tokens: Token[]; flags: string }) {
  const flat = flattenTokens(tokens)
  if (flat.length === 0) {
    return <div className="empty">Enter a regular expression to see its explanation.</div>
  }
  return (
    <ul className="expllist">
      {flat.map((ft, i) => {
        const t = ft.token
        const showLine = !(
          (t.type === 'group-start' || t.type === 'group-named') &&
          t.children &&
          t.children.length > 0 &&
          t.children[0].start === t.start
        )
        if (t.type === 'alt') {
          return (
            <li key={i} className="expl alt">
              <span className="expl-text" style={{ paddingLeft: `${ft.depth * 14}px` }}>
                or, continue matching from here:
              </span>
            </li>
          )
        }
        if ((t.type === 'group-start' || t.type === 'group-named') && t.children?.length) {
          return (
            <li key={i} className="expl group">
              <span className="expl-text group-open">
                <span style={{ paddingLeft: `${ft.depth * 14}px` }}>
                  {describeToken(t, flags)}:
                </span>
              </span>
            </li>
          )
        }
        if (!showLine) return null
        return (
          <li key={i} className="expl">
            <span className="expl-text" style={{ paddingLeft: `${ft.depth * 14}px` }}>
              {describeToken(t, flags)}
            </span>
          </li>
        )
      })}
    </ul>
  )
}
