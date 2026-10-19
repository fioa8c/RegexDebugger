import { describe, expect, it } from 'vitest'
import { describeYara } from '../describe'
import { parseYaraRegex } from '../parse'

function lines(src: string, flags = { i: false, s: false }): string[] {
  const r = parseYaraRegex(src)
  if (!r.ok) throw new Error(r.error.message)
  return describeYara(r.ast, flags).map((l) => '  '.repeat(l.depth) + l.text)
}

describe('describeYara', () => {
  it('reads runs of characters as text and quantifiers as headers', () => {
    expect(lines('eval\\s*\\(')).toEqual([
      'the text `eval`',
      'zero or more times (as many as possible):',
      '  an ASCII whitespace byte (\\t \\n \\v \\f \\r or space)',
      'the character `(`',
    ])
  })

  it('words bytes and UTF-8 explicitly', () => {
    expect(lines('\\xFF')).toEqual(['the byte 0xFF'])
    expect(lines('é')).toEqual(['the UTF-8 bytes C3 A9 (é)'])
    expect(lines('\\x{E9}')).toEqual(['the UTF-8 bytes C3 A9 (é)'])
  })

  it('says groups never capture', () => {
    expect(lines('(ab)')).toEqual(["a group (Yara-X doesn't capture):", '  the text `ab`'])
    expect(lines('(?P<n>a)')[0]).toBe("a group named `n` (Yara-X doesn't capture):")
  })

  it('follows the flags in scope', () => {
    expect(lines('^.$')).toEqual(['the start of the data', 'any byte except \\n', 'the end of the data'])
    expect(lines('(?m)^.', { i: false, s: true })).toEqual([
      'from here on: `^` and `$` match at line breaks',
      'the start of a line',
      'any byte',
    ])
    expect(lines('ab', { i: true, s: false })).toEqual(['the text `ab`, any case'])
    expect(lines('[a-c]', { i: true, s: false })).toEqual(['one byte from: a-c, either case'])
  })

  it('lists alternatives', () => {
    expect(lines('ab|c')).toEqual(['either:', '  the text `ab`', 'or:', '  the character `c`'])
  })
})
