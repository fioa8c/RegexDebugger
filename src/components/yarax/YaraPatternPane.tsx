import { CodeArea } from '../CodeArea'
import { Flag } from '../Flag'
import type { Span } from '../Highlighter'
import { formatDiag, type Diag, type YaraOptions } from '../../lib/yarax/engine'

const SUFFIXES = [
  { key: 'i', name: 'ignore case', tip: 'i suffix: case-insensitive (ASCII letters only)' },
  { key: 's', name: 'dot matches all', tip: 's suffix: . also matches \\n (any byte)' },
] as const

const MODIFIERS = [
  { key: 'nocase', tip: 'nocase: case-insensitive, same as the i suffix' },
  { key: 'wide', tip: 'wide: match UTF-16LE text (a 00 byte after each byte)' },
  { key: 'ascii', tip: 'ascii: match the plain bytes; with wide, search both encodings' },
  { key: 'fullword', tip: 'fullword: no ASCII letter or digit right before or after the match' },
] as const

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
  const flag = (key: keyof YaraOptions, tip: string, name?: string) => (
    <Flag
      key={key}
      label={key}
      name={name}
      tip={tip}
      checked={opts[key]}
      onChange={(on) => onOpts({ ...opts, [key]: on })}
    />
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
        {SUFFIXES.map((s) => flag(s.key, s.tip, s.name))}
        <span className="flag-sep" aria-hidden />
        {MODIFIERS.map((m) => flag(m.key, m.tip))}
      </footer>
    </section>
  )
}
