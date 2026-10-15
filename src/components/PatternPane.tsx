import { CodeArea } from './CodeArea'
import { Flag } from './Flag'
import type { Span } from './Highlighter'

const FLAGS = [
  { key: 'g', name: 'global', tip: 'g: find every match, not just the first' },
  { key: 'i', name: 'ignore case', tip: 'i: case-insensitive' },
  { key: 'm', name: 'multi-line', tip: 'm: ^ and $ match at line breaks' },
  { key: 's', name: 'dot matches all', tip: 's: . also matches line terminators' },
  { key: 'u', name: 'unicode', tip: 'u: Unicode mode' },
]

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
        {FLAGS.map((f) => (
          <Flag
            key={f.key}
            label={f.key}
            name={f.name}
            tip={f.tip}
            checked={flags.includes(f.key)}
            onChange={(on) => onFlag(f.key, on)}
          />
        ))}
      </footer>
    </section>
  )
}
