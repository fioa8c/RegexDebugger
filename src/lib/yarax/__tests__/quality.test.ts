import { describe, expect, it } from 'vitest'
import { AtomsQuality, atomQuality, bestRangeInBytes, bestRangeInMaskedBytes } from '../quality'
import { Seq, extract } from '../literal'
import { parseYaraRegex } from '../parse'
import { translate } from '../hir'

const bytes = (s: string) => [...s].map((c) => c.charCodeAt(0))

describe('atomQuality', () => {
  it('scores atoms like Yara-X 1.21.0', () => {
    expect(atomQuality(bytes('1234'))).toBe(88)
    expect(atomQuality(bytes('e64_'))).toBe(86)
    expect(atomQuality(bytes('(bas'))).toBe(82)
    expect(atomQuality(bytes('abcd'))).toBe(80)
    expect(atomQuality(bytes('eval'))).toBe(80)
    expect(atomQuality(bytes('aaaa'))).toBe(74)
    expect(atomQuality(bytes('    '))).toBe(43)
    expect(atomQuality(bytes('ab'))).toBe(40)
    expect(atomQuality(bytes('a'))).toBe(20)
    expect(atomQuality([0, 0, 0, 0])).toBe(19)
    expect(atomQuality([])).toBe(-2147483648)
  })
})

describe('best ranges', () => {
  it('picks the best 4-byte window of a literal', () => {
    expect(bestRangeInBytes(bytes('base64_decode'))).toEqual({ range: [3, 7], quality: 86 })
    expect(bestRangeInBytes(bytes('ab'))).toEqual({ range: [0, 2], quality: 40 })
  })

  it('scores masked bytes and keeps the first of equally good windows', () => {
    // [\x40-\x4f]b: 0x40 with mask 0xF0, then `b`.
    expect(bestRangeInMaskedBytes([0x40, 0x62], [0xf0, 0xff])).toEqual({ range: [0, 2], quality: 24 })
    // A fully masked byte costs 13, but `ab?c` (47) still beats `ab` (40).
    expect(bestRangeInMaskedBytes(bytes('ab\0cd'), [0xff, 0xff, 0, 0xff, 0xff])).toEqual({ range: [0, 4], quality: 47 })
  })
})

describe('AtomsQuality', () => {
  const q = (...atoms: string[]) => AtomsQuality.of(atoms.map((a) => ({ bytes: bytes(a), exact: false })))

  it('prefers a higher minimum quality, then longer atoms', () => {
    expect(q('abcd').cmp(q('ab'))).toBeGreaterThan(0)
    expect(q('ab', 'abcd').cmp(q('abc'))).toBeLessThan(0)
  })

  it('prefers 1 atom over 256 atoms that are only one byte longer', () => {
    const many = AtomsQuality.of(Array.from({ length: 256 }, (_, i) => ({ bytes: [0x61, 0x62, i], exact: false })))
    expect(q('ab').cmp(many)).toBeGreaterThan(0)
  })

  it('is better than the empty sentinel', () => {
    expect(q('a').cmp(AtomsQuality.min())).toBeGreaterThan(0)
  })
})

describe('extract (regex-syntax literal extraction)', () => {
  const seq = (src: string) => {
    const r = parseYaraRegex(src)
    if (!r.ok) throw new Error(r.error.message)
    const s = extract(translate(r.ast, { i: false, s: false }))
    return s.lits === null ? null : s.lits.map((l) => String.fromCharCode(...l.bytes) + (l.exact ? '' : '…'))
  }

  it('crosses concatenations and stops at 4 bytes', () => {
    expect(seq('ab[cd]')).toEqual(['abc', 'abd'])
    expect(seq('abcdef')).toEqual(['abcd…'])
  })

  it('handles optional and repeated parts', () => {
    expect(seq('ab*c')).toEqual(['ab…', 'ac'])
    expect(seq('a+')).toEqual(['a…'])
    expect(seq('(ab){2}')).toEqual(['abab'])
  })

  it('expands byte classes into one literal per byte', () => {
    expect(seq('[a-z]')).toHaveLength(26)
    expect(seq('.')).toHaveLength(255)
  })

  it('dedups consecutive literals, keeping inexactness', () => {
    const s = new Seq([
      { bytes: [1], exact: true },
      { bytes: [1], exact: false },
    ])
    s.dedup()
    expect(s.lits).toEqual([{ bytes: [1], exact: false }])
  })
})
