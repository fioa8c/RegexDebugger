import { describe, expect, it } from 'vitest'
import { parseYaraRegex, type Node } from '../parse'

function ast(src: string): Node {
  const r = parseYaraRegex(src)
  if (!r.ok) throw new Error(r.error.message)
  return r.ast
}

function err(src: string) {
  const r = parseYaraRegex(src)
  if (r.ok) throw new Error('expected an error')
  return r.error
}

describe('parseYaraRegex', () => {
  it('parses a concatenation of characters, escapes and quantifiers with spans', () => {
    const n = ast('ab\\s*')
    expect(n.kind).toBe('concat')
    if (n.kind !== 'concat') return
    expect(n.items.map((i) => i.kind)).toEqual(['char', 'char', 'repeat'])
    const rep = n.items[2]
    expect(rep).toMatchObject({ kind: 'repeat', min: 0, max: null, greedy: true, span: { start: 2, end: 5 }, opSpan: { start: 4, end: 5 } })
  })

  it('reads counted repetitions, including {,n} and lazy forms', () => {
    const q = (src: string) => {
      const n = ast(src)
      return n.kind === 'repeat' ? [n.min, n.max, n.greedy] : null
    }
    expect(q('a{3}')).toEqual([3, 3, true])
    expect(q('a{3,}')).toEqual([3, null, true])
    expect(q('a{2,5}?')).toEqual([2, 5, false])
    expect(q('a{,4}')).toEqual([0, 4, true])
    expect(q('a+?')).toEqual([1, null, false])
  })

  it('treats \\xHH as a raw byte and \\x{..} as a code point', () => {
    expect(ast('\\xE9')).toMatchObject({ kind: 'char', cp: 0xe9, byte: true })
    expect(ast('\\x{E9}')).toMatchObject({ kind: 'char', cp: 0xe9, byte: false })
    expect(ast('é')).toMatchObject({ kind: 'char', cp: 0xe9, byte: false, escaped: false })
  })

  it('reads \\< and \\> as literal angle brackets', () => {
    expect(ast('\\<')).toMatchObject({ kind: 'char', cp: 0x3c, escaped: true })
    expect(ast('\\>')).toMatchObject({ kind: 'char', cp: 0x3e, escaped: true })
  })

  it('parses groups, named groups, flag groups and inline flags', () => {
    expect(ast('(a)')).toMatchObject({ kind: 'group', capture: true, index: 1, name: null })
    expect(ast('(?P<x>a)')).toMatchObject({ kind: 'group', capture: true, name: 'x' })
    expect(ast('(?<x>a)')).toMatchObject({ kind: 'group', capture: true, name: 'x' })
    expect(ast('(?:a)')).toMatchObject({ kind: 'group', capture: false, flags: null })
    expect(ast('(?i-s:a)')).toMatchObject({ kind: 'group', capture: false, flags: { on: 'i', off: 's' } })
    expect(ast('(?m)')).toMatchObject({ kind: 'flags', flags: { on: 'm', off: '' } })
  })

  it('parses classes with ranges, negation, perl and ASCII classes', () => {
    const n = ast('[^a-f\\d[:space:]]')
    expect(n).toMatchObject({ kind: 'class', negated: true })
    if (n.kind !== 'class') return
    expect(n.items.map((i) => i.kind)).toEqual(['range', 'perl', 'ascii'])
    expect(ast('[]a]')).toMatchObject({ kind: 'class', items: [{ kind: 'char', cp: 0x5d }, { kind: 'char', cp: 0x61 }] })
    expect(ast('[a-]')).toMatchObject({ kind: 'class', items: [{ kind: 'char' }, { kind: 'char', cp: 0x2d }] })
  })

  it('records alternation bars', () => {
    expect(ast('ab|c|d')).toMatchObject({ kind: 'alt', bars: [2, 4] })
  })

  it('keeps UTF-16 spans for characters outside the BMP', () => {
    const n = ast('😀a')
    expect(n).toMatchObject({ kind: 'concat', items: [{ span: { start: 0, end: 2 } }, { span: { start: 2, end: 3 } }] })
  })

  it('rejects what the engine rejects, or what this tester does not model', () => {
    expect(err('foo{').message).toBe('unclosed counted repetition')
    expect(err('(?=a)').message).toMatch(/look-around/)
    expect(err('\\1').message).toMatch(/backreferences/)
    expect(err('\\p{L}').message).toBe('Unicode not allowed here')
    expect(err('[é]').message).toBe('Unicode not allowed here')
    expect(err('[z-a]').message).toMatch(/invalid character class range/)
    expect(err('*a').message).toMatch(/missing expression/)
    expect(err('(?u)a').message).toMatch(/Unicode mode/)
    expect(err('(?x)a').message).toMatch(/not analyzed/)
    expect(err('[a&&b]').message).toMatch(/set operations/)
    expect(err('(a').message).toBe('unclosed group')
    expect(err('a)').message).toBe('unopened group')
    expect(err('\\q').message).toBe('unrecognized escape sequence')
  })

  it('produces coloring tokens', () => {
    const r = parseYaraRegex('(a|\\d)+.^')
    if (!r.ok) throw new Error()
    expect(r.tokens.map((t) => [t.kind, t.start, t.end])).toEqual([
      ['group', 0, 1],
      ['literal', 1, 2],
      ['alt', 2, 3],
      ['meta', 3, 5],
      ['group', 5, 6],
      ['quant', 6, 7],
      ['dot', 7, 8],
      ['anchor', 8, 9],
    ])
  })
})
