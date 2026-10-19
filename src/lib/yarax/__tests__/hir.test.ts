import { describe, expect, it } from 'vitest'
import { parseYaraRegex } from '../parse'
import { translate, type Hir } from '../hir'

function hir(src: string, flags = { i: false, s: false }): Hir {
  const r = parseYaraRegex(src)
  if (!r.ok) throw new Error(r.error.message)
  return translate(r.ast, flags)
}

// A compact, span-free rendering of a HIR for assertions.
function show(h: Hir): string {
  const hex = (b: number) => b.toString(16).padStart(2, '0')
  switch (h.k) {
    case 'empty':
      return 'ε'
    case 'lit':
      return `"${h.bytes.map(hex).join(' ')}"`
    case 'class':
      return `${h.unicode ? 'U' : 'B'}[${h.ranges.map(([a, b]) => (a === b ? hex(a) : `${hex(a)}-${hex(b)}`)).join(',')}]`
    case 'look':
      return `look(${h.look})`
    case 'rep':
      return `rep{${h.min},${h.max ?? ''}${h.greedy ? '' : '?'}}(${show(h.sub)})`
    case 'cap':
      return `cap${h.index}(${show(h.sub)})`
    case 'cat':
      return `cat(${h.subs.map(show).join(' ')})`
    case 'alt':
      return `alt(${h.subs.map(show).join(' | ')})`
  }
}

describe('translate', () => {
  it('merges adjacent characters into one literal and encodes UTF-8', () => {
    expect(show(hir('ab\\x41é'))).toBe('"61 62 41 c3 a9"')
    expect(show(hir('\\xE9'))).toBe('"e9"')
  })

  it('keeps per-byte source spans on literals', () => {
    const h = hir('aé')
    expect(h.k === 'lit' && h.src).toEqual([
      { start: 0, end: 1 },
      { start: 1, end: 2 },
      { start: 1, end: 2 },
    ])
  })

  it('folds ASCII letters into two-byte classes when case-insensitive', () => {
    expect(show(hir('a1', { i: true, s: false }))).toBe('cat(B[41,61] "31")')
    expect(show(hir('a(?-i)b', { i: true, s: false }))).toBe('cat(B[41,61] "62")')
    expect(show(hir('[a-c]', { i: true, s: false }))).toBe('B[41-43,61-63]')
  })

  it('scopes inline flags to their group and swaps greed under (?U)', () => {
    expect(show(hir('(?i)a(?-i:b)c'))).toBe('cat(B[41,61] "62" B[43,63])')
    expect(show(hir('(?U)a*b+?'))).toBe('cat(rep{0,?}("61") rep{1,}("62"))')
  })

  it('maps . to any byte but \\n, or to any byte under s', () => {
    expect(show(hir('.'))).toBe('B[00-09,0b-ff]')
    expect(show(hir('.', { i: false, s: true }))).toBe('B[00-ff]')
  })

  it('maps ^ and $ to the data ends unless (?m)', () => {
    expect(show(hir('^a$'))).toBe('cat(look(start-text) "61" look(end-text))')
    expect(show(hir('(?m)^a'))).toBe('cat(look(start-line) "61")')
  })

  it('drops non-capturing groups and keeps captures', () => {
    expect(show(hir('(?:ab)(c)'))).toBe('cat("61 62" cap1("63"))')
  })

  it('folds alternations of single characters into classes', () => {
    expect(show(hir('a|b'))).toBe('U[61-62]')
    expect(show(hir('\\xFF|a'))).toBe('B[61,ff]')
    expect(show(hir('[ab]|[cd]'))).toBe('U[61-64]')
  })

  it('lifts a common prefix out of an alternation of concatenations', () => {
    expect(show(hir('ab[cx]|ab[dy]'))).toBe('cat("61 62" U[63-64,78-79])')
    // Plain literals are not concatenations, so nothing is lifted.
    expect(show(hir('abc|abd'))).toBe('alt("61 62 63" | "61 62 64")')
  })

  it('simplifies repetitions', () => {
    expect(show(hir('a{1}'))).toBe('"61"')
    expect(show(hir('a{0}b'))).toBe('"62"')
    expect(show(hir('a*?'))).toBe('rep{0,?}("61")')
  })

  it('computes minimum and maximum lengths', () => {
    expect(hir('ab{2,5}c').p).toMatchObject({ minLen: 4, maxLen: 7 })
    expect(hir('a+').p).toMatchObject({ minLen: 1, maxLen: null })
    expect(hir('a*').p.minLen).toBe(0)
    expect(hir('\\ba').p.hasLook).toBe(true)
  })
})
