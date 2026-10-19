/// <reference types="node" />
import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import fixture from '../__fixtures__/atoms.json'
import { parseYaraRegex } from '../parse'
import { translate } from '../hir'
import { extractAtoms } from '../atoms'

const hex = (bytes: number[]) => bytes.map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join('')

function analyze(pattern: string, suffix: string, modifiers: string) {
  const mods = modifiers.split(' ')
  const parsed = parseYaraRegex(pattern)
  if (!parsed.ok) throw new Error(`parse failed: ${parsed.error.message}`)
  const nocase = mods.includes('nocase') || suffix.includes('i')
  const hir = translate(parsed.ast, { i: nocase, s: suffix.includes('s') })
  return extractAtoms(hir, {
    nocase,
    wide: mods.includes('wide'),
    ascii: mods.includes('ascii'),
    fullword: mods.includes('fullword'),
  })
}

describe('atoms match yr debug atoms (1.21.0)', () => {
  const cases = fixture.cases.filter((c) => c.error === null)
  it.each(cases.map((c) => [`/${c.pattern}/${c.suffix} ${c.modifiers}`, c] as const))('%s', (_, c) => {
    const r = analyze(c.pattern, c.suffix, c.modifiers)
    const got = r.all.map((a) => hex(a.bytes)).sort()
    expect(got).toHaveLength(c.count)
    if (c.atoms) expect(got).toEqual(c.atoms)
    else expect(createHash('sha256').update(got.join(',')).digest('hex')).toBe(c.sha256)
    expect(r.slow).toBe(c.warnings.includes('slow_pattern'))
  })
})

describe('where the atoms come from', () => {
  const plain = (pattern: string, suffix = '') => analyze(pattern, suffix, '')

  it('points at the atom in the pattern and measures verification around it', () => {
    const r = plain('eval\\s*\\(\\s*base64_decode\\s*\\(')
    expect(r.pieces).toHaveLength(1)
    expect(r.pieces[0]).toMatchObject({ path: 'pike', span: { start: 15, end: 19 }, extent: { backward: null, forward: null } })
    expect(r.pieces[0].pikeBecause).toEqual({ start: 4, end: 7 })
  })

  it('measures bounded gaps on the FastVM path', () => {
    expect(plain('foo.{0,10}bar').pieces[0]).toMatchObject({ path: 'fast', extent: { backward: 13, forward: 3 } })
  })

  it('splits at long any-byte gaps under /s and records the gap', () => {
    const r = plain('foo.{0,300}bar', 's')
    expect(r.pieces.map((p) => p.path)).toEqual(['literal', 'literal'])
    expect(r.gaps).toEqual([{ min: 0, max: 300, span: { start: 3, end: 11 } }])
  })

  it('uses source spans in UTF-16 units', () => {
    // The emoji's four UTF-8 bytes F0 9F 98 80 (88) beat `abcd` (80).
    expect(plain('😀abcd').pieces[0].span).toEqual({ start: 0, end: 2 })
    expect(plain('😀😀ab1234').pieces[0].span).toEqual({ start: 0, end: 2 })
    expect(plain('é ab 1234').pieces[0].span).toEqual({ start: 5, end: 9 })
  })

  it('reports a pattern that can match the empty string', () => {
    expect(plain('a?').emptyMatch).toBe(true)
  })

  it('stays fast on patterns with many atoms', () => {
    const t = performance.now()
    for (const p of ['[\\x80-\\xff]{4}', '\\d{4}-\\d{2}', '[A-Za-z0-9+\\/]{64,512}\\x00', '(\\w\\w\\w\\w|[a-f0-9]{8})+x']) plain(p)
    expect(performance.now() - t).toBeLessThan(1500)
  })
})
