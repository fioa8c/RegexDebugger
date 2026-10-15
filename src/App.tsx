import { useMemo, useState } from 'react'
import { PatternPane } from './components/PatternPane'
import { InputPane, SAMPLE_INPUT } from './components/InputPane'
import { MatchList, type GroupLabel } from './components/MatchList'
import { ExplanationPane } from './components/ExplanationPane'
import { TokenReference } from './components/TokenReference'
import { YaraWorkbench } from './components/yarax/YaraWorkbench'
import { tokenize, flattenTokens, extractGroupLabels, type Token } from './lib/explain'
import { runRegex, RegexError } from './lib/matcher'
import { groupColor } from './lib/colors'
import type { MatchInfo } from './lib/matcher'
import type { Span } from './components/Highlighter'
import { DEFAULT_YARA_OPTIONS } from './lib/yarax/engine'
import { YARA_DEFAULT_PATTERN, YARA_SAMPLE_INPUT } from './lib/yarax/samples'
import './index.css'

type Flavor = 'javascript' | 'yarax'

const DEFAULT_PATTERN = '([A-Z]+)\\s+(/\\S+)\\s+HTTP/(\\d\\.\\d)'

const TOKEN_CLASS: Record<Token['type'], string> = {
  literal: 'tok-lit',
  anchor: 'tok-anchor',
  dot: 'tok-dot',
  'meta-class': 'tok-meta',
  'escape-seq': 'tok-esc',
  backref: 'tok-back',
  'char-class': 'tok-class',
  alt: 'tok-alt',
  quantifier: 'tok-quant',
  'group-start': 'tok-group',
  'group-named': 'tok-named',
  'group-non': 'tok-non',
  'group-lookahead': 'tok-look',
  'group-lookbehind': 'tok-look',
}

function buildInputSpans(matches: MatchInfo[]): Span[] {
  const spans: Span[] = []
  for (const m of matches) {
    spans.push({ start: m.index, end: m.index + m.text.length, className: 'hl-match' })
    m.groups.forEach((g, i) => {
      if (g.value !== null && g.offset >= 0) {
        spans.push({
          start: g.offset,
          end: g.offset + g.value.length,
          className: `hl-g${i % 8}`,
        })
      }
    })
  }
  return spans
}

export default function App() {
  const [pattern, setPattern] = useState(DEFAULT_PATTERN)
  const [flags, setFlags] = useState('g')
  const [input, setInput] = useState(SAMPLE_INPUT)
  const [tab, setTab] = useState<'matches' | 'explain'>('matches')
  const [flavor, setFlavor] = useState<Flavor>('javascript')
  const [yPattern, setYPattern] = useState(YARA_DEFAULT_PATTERN)
  const [yOpts, setYOpts] = useState(DEFAULT_YARA_OPTIONS)
  const [yInput, setYInput] = useState(YARA_SAMPLE_INPUT)

  const onFlag = (f: string, on: boolean) =>
    setFlags((prev) => (on ? [...new Set(prev + f)].join('') : prev.replace(f, '')))

  const { error, tokens, groupLabels, matches, ms } = useMemo(() => {
    const tokens: Token[] = pattern ? tokenize(pattern) : []
    const groupLabels: GroupLabel[] = extractGroupLabels(tokens)
      .map((label, i) => ({ label: label.startsWith('Group') ? label : label, index: i + 1 }))
    let error = ''
    let matches: MatchInfo[] = []
    let ms = 0
    if (pattern && !error) {
      const t0 = performance.now()
      try {
        matches = runRegex(pattern, flags, input, groupLabels.length)
      } catch (e) {
        error = e instanceof RegexError ? e.message : String(e)
      }
      ms = performance.now() - t0
    }
    return {
      error,
      tokens,
      groupLabels: groupLabels.map((g) => ({ ...g, color: groupColor(g.index - 1) })),
      matches,
      ms,
    }
  }, [pattern, flags, input])

  const patternSpans: Span[] = useMemo(() => {
    const spans: Span[] = flattenTokens(tokens).map(({ token }) => ({
      start: token.start,
      end: token.end,
      className: TOKEN_CLASS[token.type],
    }))
    return spans
  }, [tokens])

  const inputSpans: Span[] = useMemo(() => buildInputSpans(matches), [matches])

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">&lt;/&gt;</span>
          <span className="brand-name">regex101.clone</span>
        </div>
        <label className="flavor">
          Flavor
          <select value={flavor} onChange={(e) => setFlavor(e.target.value as Flavor)}>
            <option value="javascript">JavaScript</option>
            <option value="yarax">Yara-X</option>
          </select>
        </label>
      </header>

      {flavor === 'yarax' ? (
        <YaraWorkbench
          pattern={yPattern}
          opts={yOpts}
          input={yInput}
          onPattern={setYPattern}
          onOpts={setYOpts}
          onInput={setYInput}
        />
      ) : (
        <>
          <main className="main">
            <PatternPane
              pattern={pattern}
              flags={flags}
              spans={patternSpans}
              error={error}
              onPattern={setPattern}
              onFlag={onFlag}
            />
            <InputPane input={input} spans={inputSpans} onInput={setInput} />
          </main>

          <section className="results">
            <div className="tabs">
              <button
                className={'tab' + (tab === 'matches' ? ' tab-on' : '')}
                onClick={() => setTab('matches')}
              >
                Matches
                <span className="tab-badge">
                  {error ? '!' : `${matches.length} in ${ms.toFixed(2)} ms`}
                </span>
              </button>
              <button
                className={'tab' + (tab === 'explain' ? ' tab-on' : '')}
                onClick={() => setTab('explain')}
              >
                Explanation
              </button>
            </div>
            <div className="results-body">
              {tab === 'matches'
                ? error
                  ? <div className="empty error-empty">{error}</div>
                  : <MatchList matches={matches} groupLabels={groupLabels} />
                : <ExplanationPane tokens={tokens} flags={flags} />}
            </div>
          </section>
        </>
      )}

      <TokenReference flavor={flavor} />
    </div>
  )
}
