import { useMemo, type Dispatch, type ReactNode, type SetStateAction } from 'react'
import { Frame } from '../Frame'
import { InputPane } from '../InputPane'
import type { Span } from '../Highlighter'
import { YaraPatternPane } from './YaraPatternPane'
import { YaraMatchList } from './YaraMatchList'
import { useYaraScan } from './useYaraScan'
import { formatDiag, type YaraMatch, type YaraOptions } from '../../lib/yarax/engine'
import { mapBytes } from '../../lib/yarax/bytes'
import { YARA_SAMPLE_INPUT } from '../../lib/yarax/samples'
import type { Layout } from '../../lib/layout'

const NO_MATCHES: YaraMatch[] = []

export function YaraWorkbench({
  pattern,
  opts,
  input,
  onPattern,
  onOpts,
  onInput,
  layout,
  onLayout,
  sidebar,
}: {
  pattern: string
  opts: YaraOptions
  input: string
  onPattern: (v: string) => void
  onOpts: (o: YaraOptions) => void
  onInput: (v: string) => void
  layout: Layout
  onLayout: Dispatch<SetStateAction<Layout>>
  sidebar: ReactNode
}) {
  const scan = useYaraScan(pattern, opts, input)
  const map = useMemo(() => mapBytes(input), [input])
  const result = scan.status === 'ready' ? scan.result : null
  const errors = result?.errors ?? []
  const warnings = result?.warnings ?? []
  const matches = result?.matches ?? NO_MATCHES

  const inputSpans: Span[] = useMemo(
    () =>
      matches.map((m) => ({
        start: map.charStart(m.offset),
        end: map.charEnd(m.offset + m.length),
        className: 'hl-match',
      })),
    [matches, map],
  )

  const badge =
    scan.status === 'loading'
      ? '…'
      : scan.status === 'unavailable' || errors.length
        ? '!'
        : `${matches.length} in ${scan.ms.toFixed(2)} ms`

  return (
    <Frame
      layout={layout}
      onLayout={onLayout}
      sidebar={sidebar}
      left={
        <YaraPatternPane
          pattern={pattern}
          opts={opts}
          errors={errors}
          warnings={warnings}
          onPattern={onPattern}
          onOpts={onOpts}
        />
      }
      right={<InputPane input={input} spans={inputSpans} onInput={onInput} sample={YARA_SAMPLE_INPUT} />}
      results={
        <section className="results">
          <div className="tabs">
            <button className="tab tab-on">
              Matches
              <span className="tab-badge">{badge}</span>
            </button>
          </div>
          <div className="results-body">
            {scan.status === 'loading' ? (
              <div className="empty">Loading the Yara-X engine…</div>
            ) : scan.status === 'unavailable' ? (
              <div className="empty error-empty">
                Yara-X engine unavailable: {scan.reason}{' '}
                <button className="linkbtn" onClick={scan.retry}>
                  Retry
                </button>
              </div>
            ) : errors.length ? (
              <div className="empty error-empty yerr">{errors.map(formatDiag).join('\n')}</div>
            ) : (
              <YaraMatchList
                matches={matches}
                bytes={map.bytes}
                wideHint={opts.wide && !opts.ascii}
              />
            )}
          </div>
        </section>
      }
    />
  )
}
