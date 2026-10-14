import { CodeArea } from './CodeArea'
import type { Span } from './Highlighter'

export function PatternPane({
  pattern,
  flags,
  spans,
  error,
  onPattern,
  onFlag,
}: {
  pattern: string
  flags: string
  spans: Span[]
  error: string
  onPattern: (v: string) => void
  onFlag: (f: string, on: boolean) => void
}) {
  return (
    <section className="pane">
      <header className="pane-header">
        <span className="pane-title">Regular Expression</span>
        <span className="pane-flavor">JavaScript</span>
      </header>
      <CodeArea
        ariaLabel="Regular expression pattern"
        value={pattern}
        onChange={onPattern}
        spans={spans}
        error={error}
      />
      {error && <div className="errorbox">{error}</div>}
      <footer className="flagbar">
        {['g', 'i', 'm', 's', 'u'].map((f) => (
          <label key={f} className={'flag' + (flags.includes(f) ? ' flag-on' : '')}>
            <input
              type="checkbox"
              checked={flags.includes(f)}
              onChange={(e) => onFlag(f, e.target.checked)}
            />
            <span className="flag-key">{f}</span>
            <span className="flag-name">
              {f === 'g'
                ? 'global'
                : f === 'i'
                  ? 'ignore case'
                  : f === 'm'
                    ? 'multi-line'
                    : f === 's'
                      ? 'dot matches all'
                      : 'unicode'}
            </span>
          </label>
        ))}
      </footer>
    </section>
  )
}
