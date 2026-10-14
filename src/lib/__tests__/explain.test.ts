import { describe, expect, it } from 'vitest'
import { tokenize, flattenTokens, extractGroupLabels } from '../explain'

describe('tokenize', () => {
  it('tokenizes a simple pattern into literals', () => {
    const t = tokenize('abc')
    expect(t.map((x) => x.text)).toEqual(['a', 'b', 'c'])
    expect(t.every((x) => x.type === 'literal')).toBe(true)
  })

  it('attaches ? to the preceding token', () => {
    const t = tokenize('ab?')
    expect(t).toHaveLength(2)
    expect(t[0]).toMatchObject({ text: 'a' })
    expect(t[0].quantifier).toBeUndefined()
    expect(t[1]).toMatchObject({ text: 'b?', quantifier: '?', start: 1, end: 3 })
  })

  it('attaches {n,m} to the preceding token', () => {
    const t = tokenize('x{3,6}')
    expect(t).toHaveLength(1)
    expect(t[0].text).toBe('x{3,6}')
    expect(t[0].quantifier).toBe('{3,6}')
  })

  it('attaches {n} when more pattern follows', () => {
    const t = tokenize('x{3}y')
    expect(t.map((x) => x.text)).toEqual(['x{3}', 'y'])
    expect(t[0]).toMatchObject({ quantifier: '{3}', start: 0, end: 4 })
    expect(t[1]).toMatchObject({ type: 'literal', start: 4, end: 5 })
  })

  it('folds lazy suffixes into the quantifier', () => {
    expect(tokenize('a??')).toEqual([
      { type: 'literal', text: 'a??', start: 0, end: 3, quantifier: '??' },
    ])
    expect(tokenize('a{2,3}?')).toEqual([
      { type: 'literal', text: 'a{2,3}?', start: 0, end: 7, quantifier: '{2,3}?' },
    ])
    const t = tokenize('a*??')
    expect(t.map((x) => x.text)).toEqual(['a*?', '?'])
    expect(t[1].type).toBe('quantifier')
  })

  it('treats bare { as a literal', () => {
    const t = tokenize('x{not}a}')
    const texts = t.map((x) => x.text)
    expect(texts).toContain('{')
    expect(texts).toContain('}')
  })

  it('tokenizes character classes with ranges and escapes', () => {
    const t = tokenize('[^a-z0-9_-]')
    expect(t).toHaveLength(1)
    expect(t[0]).toMatchObject({ type: 'char-class', text: '[^a-z0-9_-]' })
  })

  it('tokenizes anchors and alternation', () => {
    const t = flattenTokens(tokenize('^a|b$'))
    const types = t.map((x) => x.token.type)
    expect(types).toEqual(['anchor', 'literal', 'alt', 'literal', 'anchor'])
  })

  it('tokenizes capturing group with children', () => {
    const t = tokenize('(ab)+')
    expect(t).toHaveLength(1)
    expect(t[0].type).toBe('group-start')
    expect(t[0].children).toHaveLength(2)
    expect(t[0].quantifier).toBe('+')
  })

  it('tokenizes non-capturing, lookahead, lookbehind, named groups', () => {
    expect(tokenize('(?:ab)')[0].type).toBe('group-non')
    expect(tokenize('(?=ab)')[0].type).toBe('group-lookahead')
    expect(tokenize('(?<=ab)')[0].type).toBe('group-lookbehind')
    expect(tokenize('(?<name>ab)')[0].type).toBe('group-named')
  })

  it('keeps absolute offsets in nested group children', () => {
    const t = tokenize('(a(b)?)')
    const outer = t[0]
    expect(outer.children?.[0].start).toBe(1)
    const inner = outer.children?.[1]
    expect(inner?.start).toBe(2)
    expect(inner?.children?.[0].start).toBe(3)
  })

  it('keeps absolute offsets three levels deep', () => {
    const t = tokenize('x((a(b)))')
    const g1 = t[1]
    const g2 = g1.children?.[0]
    const g3 = g2?.children?.[1]
    expect(g1).toMatchObject({ start: 1, end: 9 })
    expect(g2).toMatchObject({ start: 2, end: 8 })
    expect(g2?.children?.[0]).toMatchObject({ text: 'a', start: 3, end: 4 })
    expect(g3).toMatchObject({ start: 4, end: 7 })
    expect(g3?.children?.[0]).toMatchObject({ text: 'b', start: 5, end: 6 })
  })

  it('extracts group labels in order', () => {
    expect(extractGroupLabels(tokenize('(a)(?<name>b)'))).toEqual([
      'Group 1',
      'name',
    ])
    expect(extractGroupLabels(tokenize('(?:a)(?=b)'))).toEqual([])
  })
})
