// @vitest-environment jsdom
import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { YaraAnalysis } from '../YaraAnalysis'
import { YaraPatternPane } from '../YaraPatternPane'
import { analyzePattern, costOf } from '../../../lib/yarax/analyze'
import { DEFAULT_YARA_OPTIONS, type Diag, type YaraOptions } from '../../../lib/yarax/engine'

afterEach(cleanup)

function renderAnalysis(pattern: string, diags: Diag[] | null = [], o: Partial<YaraOptions> = {}) {
  const opts = { ...DEFAULT_YARA_OPTIONS, ...o }
  const analysis = analyzePattern(pattern, opts)
  return render(
    <YaraAnalysis pattern={pattern} analysis={analysis} diags={diags} cost={costOf(analysis, diags, opts.wide)} />,
  )
}

describe('YaraAnalysis', () => {
  it('shows the grade, numbers, atoms, verification, suggestions and structure', () => {
    const { container } = renderAnalysis('eval\\s*\\(\\s*base64_decode\\s*\\(')
    const text = container.textContent ?? ''
    expect([...container.querySelectorAll('.ya-h')].map((h) => h.firstChild?.textContent)).toEqual([
      'Scan cost ',
      'Atoms',
      'Verification',
      'Suggestions',
      'Structure',
    ])
    expect(container.querySelector('.ya-grade')?.textContent).toBe('● OK')
    expect(text).toContain("(this tester's heuristic)")
    expect(text).toContain('weakest atom 86/88 · avg 86 · 1 atom · min length 4 B · verify: PikeVM')
    expect(text).toContain('forward ≤ 4,096 B (unbounded, capped) · backward ≤ 4,096 B (unbounded, capped)')
    expect(container.querySelector('.ya-atom')?.textContent).toBe('"e64_"')
    expect(text).toContain('inexact (needs verification)')
    expect(text).toContain('PikeVM is used because of `\\s*`')
    expect(text).toContain('the text `base64_decode`')
  })

  it('verifies forward from the start of the atom', () => {
    const { container } = renderAnalysis('foo\\s*bar')
    expect(container.textContent).toContain('→ forward: foo\\s*bar · ← backward: nothing before the atom')
  })

  it('verifies wide literals and says the grade ignores the 00 bytes', () => {
    const { container } = renderAnalysis('abcd', [], { wide: true })
    expect(container.textContent).toContain("weakest atom 80/88 (without wide's 00 bytes)")
    expect(container.textContent).not.toContain('nothing is verified')
  })

  it("labels Slow as Yara-X's rule and lists only the first 16 atoms", () => {
    const { container } = renderAnalysis('[a-z]')
    expect(container.querySelector('.ya-grade')?.textContent).toBe('● Slow')
    expect(container.textContent).toContain("(Yara-X's rule)")
    expect(container.querySelectorAll('.ya-atom')).toHaveLength(16)
    expect(container.textContent).toContain('… 10 more · by length: 1 B × 26')
  })

  it('shows only the engine errors and their fixes when the engine rejects the pattern', () => {
    const e015: Diag = { severity: 'error', code: 'E015', title: 'invalid regular expression', labels: [], notes: [] }
    const { container } = renderAnalysis('a.*?b.*c', [e015])
    expect(container.querySelector('.ya-h')?.textContent).toBe('The engine rejected this pattern')
    expect(container.querySelectorAll('li')).toHaveLength(1)
  })

  it('grades without waiting for the engine', () => {
    const { container } = renderAnalysis('foo.{0,10}barz', null)
    expect(container.querySelector('.ya-grade')?.textContent).toBe('● Fast')
    expect(container.textContent).not.toContain('out of date')
  })

  it("explains when it can't analyze a pattern", () => {
    const { container } = renderAnalysis('foo{')
    expect(container.textContent).toBe(
      "Can't analyze this pattern: unclosed counted repetition. The Matches tab still shows what the engine reports.",
    )
  })
})

describe('YaraPatternPane coloring', () => {
  it('colors tokens and underlines the atom', () => {
    const analysis = analyzePattern('ab\\s*cdef', DEFAULT_YARA_OPTIONS)
    if (analysis.kind !== 'ok') throw new Error()
    const { container } = render(
      <YaraPatternPane
        pattern="ab\s*cdef"
        opts={DEFAULT_YARA_OPTIONS}
        errors={[]}
        warnings={[]}
        tokens={analysis.tokens}
        atomSpans={analysis.atoms.pieces.map((p) => p.span!)}
        onPattern={() => {}}
        onOpts={() => {}}
      />,
    )
    const spans = [...container.querySelectorAll('.codearea-hl span:not(.__hl-tail)')].map((s) => [s.className, s.textContent])
    expect(spans).toEqual([
      ['tok-lit', 'ab'],
      ['tok-meta', '\\s'],
      ['tok-quant', '*'],
      ['tok-lit hl-atom', 'cdef'],
    ])
  })
})
