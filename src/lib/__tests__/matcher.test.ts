import { describe, expect, it } from 'vitest'
import { runRegex } from '../matcher'
import { tokenize, extractGroupLabels } from '../explain'

describe('runRegex', () => {
  it('returns no matches for empty pattern', () => {
    expect(runRegex('', 'g', 'abc', 0)).toEqual([])
  })

  it('runs a single match without g flag', () => {
    const r = runRegex('\\d+', '', 'abc 123 def', 0)
    expect(r).toEqual([{ index: 4, text: '123', groups: [] }])
  })

  it('runs all matches with g flag', () => {
    const r = runRegex('\\d+', 'g', 'a1 b22 cc333', 0)
    expect(r.map((m) => m.text)).toEqual(['1', '22', '333'])
    expect(r[0].index).toBe(1)
    expect(r[1].index).toBe(4)
  })

  it('captures group values and offsets', () => {
    const r = runRegex('(<[^>]+>\\s+\\w+\\s+[\\d.]+)', '', 'x <html> tag 3.14', 1)
    expect(r).toHaveLength(1)
    expect(r[0].groups[0].value).toBe('<html> tag 3.14')
    expect(r[0].groups[0].offset).toBe(2)
  })

  it('reports unmatched optional groups as null', () => {
    const r = runRegex('a(b)?c', '', 'ac', 1)
    expect(r).toHaveLength(1)
    expect(r[0].groups[0].value).toBeNull()
    expect(r[0].groups[0].offset).toBe(-1)
  })

  it('reports group offsets for every match with g flag', () => {
    const r = runRegex('(\\d)(\\w)', 'g', '1a 2b', 2)
    expect(r.map((m) => m.groups.map((g) => [g.value, g.offset]))).toEqual([
      [['1', 0], ['a', 1]],
      [['2', 3], ['b', 4]],
    ])
  })

  it('accepts flags that already include d', () => {
    const r = runRegex('(b)', 'gd', 'abab', 1)
    expect(r.map((m) => m.groups[0].offset)).toEqual([1, 3])
  })

  it('matches without capture groups, with or without a user d flag', () => {
    const expected = [
      { index: 0, text: 'a', groups: [] },
      { index: 1, text: 'a', groups: [] },
    ]
    expect(runRegex('a', 'g', 'aa', 0)).toEqual(expected)
    expect(runRegex('a', 'gd', 'aa', 0)).toEqual(expected)
  })

  it('does not infinite-loop on zero-width matches', () => {
    const r = runRegex('a*', 'g', 'abc', 0)
    expect(r.length).toBeLessThan(100)
    expect(r.filter((m) => m.text === '')).toHaveLength(3)
  })

  it('throws a friendly error for invalid patterns', () => {
    expect(() => runRegex('(', '', 'text', 0)).toThrow(/Invalid regular expression/)
  })

  it('supports multi-line matching with m flag', () => {
    const r = runRegex('^\\w+', 'gm', 'ab\ncd\nef', 0)
    expect(r.map((m) => m.text)).toEqual(['ab', 'cd', 'ef'])
  })


  it('reports offsets alongside other flags', () => {
    expect(runRegex('(b)', 'gimsu', 'aBab', 1).map((m) => m.groups[0].offset)).toEqual([1, 3])
  })

  it('gives a modifier-group pattern one column per real capture', () => {
    const p = '(?i:a)(?<x>b)'
    const labels = extractGroupLabels(tokenize(p))
    expect(labels).toEqual(['x'])
    const r = runRegex(p, '', 'Ab', labels.length)
    expect(r[0].groups.map((g) => g.value)).toEqual(['b'])
  })
})
