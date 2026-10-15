import { CodeArea } from '../CodeArea'
import type { Span } from '../Highlighter'
import { formatDiag, type Diag, type YaraOptions } from '../../lib/yarax/engine'

const SUFFIXES = [
  { key: 'i', name: 'ignore case' },
  { key: 's', name: 'dot matches all' },
] as const

const MODIFIERS = ['nocase', 'wide', 'ascii', 'fullword'] as const

function diagSpans(diags: Diag[]): Span[] {
  return diags.flatMap((d) =>
    d.labels
      .filter((l) => l.start !== null && l.end !== null)
      .map((l) => ({
        start: l.start ?? 0,
        end: l.end ?? 0,
        className: d.severity === 'error' ? 'hl-err' : 'hl-warn',
      })),
  )
}

export function YaraPatternPane({
  pattern,
  opts,
  errors,
  warnings,
  onPattern,
  onOpts,
}: {
  pattern: string
  opts: YaraOptions
  errors: Diag[]
  warnings: Diag[]
  onPattern: (v: string) => void
  onOpts: (o: YaraOptions) => void
}) {
  const error = errors.map(formatDiag).join('\n')
  const warning = warnings.map(formatDiag).join('\n')
  const flag = (key: keyof YaraOptions, label: string, name?: string) => (
    <label key={key} className={'flag' + (opts[key] ? ' flag-on' : '')}>
      <input
        type="checkbox"
        checked={opts[key]}
        onChange={(e) => onOpts({ ...opts, [key]: e.target.checked })}
      />
      <span className="flag-key">{label}</span>
      {name && <span className="flag-name">{name}</span>}
    </label>
  )
  return (
    <section className="pane">
      <header className="pane-header">
        <span className="pane-title">Regular Expression</span>
        <span className="pane-flavor">Yara-X</span>
      </header>
      <CodeArea
        ariaLabel="Yara-X regular expression"
        value={pattern}
        onChange={onPattern}
        spans={diagSpans([...errors, ...warnings])}
        error={error}
      />
      {error && <div className="errorbox">{error}</div>}
      {warning && <div className="warnbox">{warning}</div>}
      <footer className="flagbar">
        {SUFFIXES.map((s) => flag(s.key, s.key, s.name))}
        <span className="flag-sep" aria-hidden />
        {MODIFIERS.map((m) => flag(m, m))}
      </footer>
    </section>
  )
}
