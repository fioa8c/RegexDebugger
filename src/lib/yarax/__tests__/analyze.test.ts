import { describe, expect, it } from 'vitest'
import { analysisBadge, analyzePattern, costOf } from '../analyze'
import { DEFAULT_YARA_OPTIONS } from '../engine'
import { layerSpans } from '../layer'

describe('analyzePattern', () => {
  it('analyzes a pattern into tokens, atoms and structure', () => {
    const a = analyzePattern('ab+', DEFAULT_YARA_OPTIONS)
    expect(a.kind).toBe('ok')
    if (a.kind !== 'ok') return
    expect(a.tokens.map((t) => t.kind)).toEqual(['literal', 'literal', 'quant'])
    expect(a.atoms.all.map((x) => x.bytes)).toEqual([[0x61, 0x62]])
    expect(a.structure[0].text).toBe('the character `a`')
  })

  it('honors the i suffix and nocase alike', () => {
    const count = (o: object) => {
      const a = analyzePattern('abc', { ...DEFAULT_YARA_OPTIONS, ...o })
      return a.kind === 'ok' ? a.atoms.all.length : -1
    }
    expect(count({ i: true })).toBe(8)
    expect(count({ nocase: true })).toBe(8)
  })

  it("says why it can't analyze a pattern", () => {
    expect(analyzePattern('', DEFAULT_YARA_OPTIONS)).toEqual({ kind: 'empty' })
    expect(analyzePattern('a\nb', DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: 'a Yara-X regex must be on a single line' })
    expect(analyzePattern('(?u)\\w', DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: /crashes the Yara-X engine/ })
    expect(analyzePattern('foo{', DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: 'unclosed counted repetition', span: { start: 3, end: 4 } })
    const many = Array.from({ length: 256 }, (_, i) => `x${i}y`).join('|')
    expect(analyzePattern(`(${many})z`, DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: /255 alternatives/ })
  })

  it('grades patterns with more atoms than a call can take as arguments', () => {
    const opts = { ...DEFAULT_YARA_OPTIONS, s: true, wide: true, ascii: true }
    const a = analyzePattern(Array(4).fill('[\\x80-\\xff]{4}').join('.{0,300}'), opts)
    expect(a.kind).toBe('ok')
    expect(costOf(a, null, true)?.count).toBe(131072)
  })

  it("says it can't analyze patterns nested deeper than it can recurse", () => {
    const deep = '('.repeat(5000) + 'a' + ')'.repeat(5000)
    expect(analyzePattern(deep, DEFAULT_YARA_OPTIONS)).toMatchObject({ kind: 'unparsed', message: 'too large or too deeply nested to analyze', span: null })
  })
})

describe('analysisBadge', () => {
  it('shows the grade, or ! when the engine or the parser rejects the pattern', () => {
    const ok = analyzePattern('foo.{0,10}barz', DEFAULT_YARA_OPTIONS)
    expect(analysisBadge(ok, costOf(ok, [], false), false)).toBe('Fast')
    expect(analysisBadge(ok, costOf(ok, [], false), true)).toBe('!')
    expect(analysisBadge(analyzePattern('foo{', DEFAULT_YARA_OPTIONS), null, false)).toBe('!')
    expect(analysisBadge(analyzePattern('', DEFAULT_YARA_OPTIONS), null, false)).toBe('–')
  })
})

describe('layerSpans', () => {
  it('splits colored tokens at mark boundaries and joins the classes', () => {
    expect(
      layerSpans(
        [
          { start: 0, end: 4, className: 'tok-lit' },
          { start: 4, end: 6, className: 'tok-meta' },
        ],
        [
          { start: 2, end: 5, className: 'hl-atom' },
          { start: 3, end: 4, className: 'hl-err' },
        ],
      ),
    ).toEqual([
      { start: 0, end: 2, className: 'tok-lit' },
      { start: 2, end: 3, className: 'tok-lit hl-atom' },
      { start: 3, end: 4, className: 'tok-lit hl-atom hl-err' },
      { start: 4, end: 5, className: 'tok-meta hl-atom' },
      { start: 5, end: 6, className: 'tok-meta' },
    ])
  })

  it('keeps marks outside any token', () => {
    expect(layerSpans([], [{ start: 1, end: 2, className: 'hl-err' }])).toEqual([{ start: 1, end: 2, className: 'hl-err' }])
  })
})
