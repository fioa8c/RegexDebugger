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
    expect(t).toHaveLength(1)
    expect(t[0]).toMatchObject({ text: 'ab?', quantifier: '?' })
  })

  it('attaches {n,m} to the preceding token', () => {
    const t = tokenize('x{3,6}')
    expect(t).toHaveLength(1)
    expect(t[0].text).toBe('x{3,6}')
    expect(t[1].quantifier).toBe('{3,6}')
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

  it('extracts group labels in order', () => {
    expect(extractGroupLabels(tokenize('(a)(?<name>b)'))).toEqual([
      'Group 1',
      'name',
    ])
    expect(extractGroupLabels(tokenize('(?:a)(?=b)'))).toEqual([])
  })
})
