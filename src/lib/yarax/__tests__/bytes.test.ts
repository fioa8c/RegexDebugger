import { describe, expect, it } from 'vitest'
import { mapBytes, showBytes } from '../bytes'

describe('mapBytes', () => {
  it('maps byte offsets to string indices for ASCII', () => {
    const m = mapBytes('abc')
    expect([...m.bytes]).toEqual([0x61, 0x62, 0x63])
    expect([0, 1, 2, 3].map(m.charStart)).toEqual([0, 1, 2, 3])
  })

  it('maps offsets after 2-, 3- and 4-byte characters', () => {
    const m = mapBytes('éx€y😀z')
    expect(m.bytes.length).toBe(2 + 1 + 3 + 1 + 4 + 1)
    expect(m.charStart(2)).toBe(1)
    expect(m.charStart(6)).toBe(3)
    expect(m.charStart(11)).toBe(6)
    expect(m.charStart(12)).toBe(7)
  })

  it('widens a range that splits a character to the whole character', () => {
    const m = mapBytes('aéb')
    expect(m.charStart(2)).toBe(1)
    expect(m.charEnd(2)).toBe(2)
    expect(m.charEnd(3)).toBe(2)
    expect(m.charEnd(4)).toBe(3)
  })
})

describe('showBytes', () => {
  it('shows valid UTF-8 as text with control characters escaped', () => {
    expect(showBytes(new TextEncoder().encode('é\tx\n\u0001'))).toBe('é\\tx\\n\\x01')
  })

  it('shows invalid UTF-8 byte by byte', () => {
    expect(showBytes(new Uint8Array([0x61, 0xc3, 0x00]))).toBe('a\\xC3\\x00')
  })
})
