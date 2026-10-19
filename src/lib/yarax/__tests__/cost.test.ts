import { describe, expect, it } from 'vitest'
import { analyzePattern, costOf } from '../analyze'
import { DEFAULT_YARA_OPTIONS, type Diag, type YaraOptions } from '../engine'

const SLOW: Diag = { severity: 'warning', code: 'slow_pattern', title: 'slow pattern', labels: [], notes: [] }

function cost(pattern: string, o: Partial<YaraOptions> = {}, diags: Diag[] | null = []) {
  const opts = { ...DEFAULT_YARA_OPTIONS, ...o }
  const c = costOf(analyzePattern(pattern, opts), diags, opts.wide)
  if (!c) throw new Error('not analyzed')
  return c
}

describe('assessCost', () => {
  it('grades the default pattern OK: great atom, unbounded verification', () => {
    expect(cost('eval\\s*\\(\\s*base64_decode\\s*\\(')).toMatchObject({
      grade: 'ok',
      weakest: 86,
      count: 1,
      minLength: 4,
      tier: 'pikevm',
      forward: { bytes: 4096, capped: true },
      backward: { bytes: 4096, capped: true },
    })
  })

  it('grades a bounded pattern with good atoms Fast', () => {
    expect(cost('foo.{0,10}barz')).toMatchObject({ grade: 'fast', tier: 'fastvm', forward: { bytes: 4, capped: false }, backward: { bytes: 13, capped: false } })
  })

  it('counts an exact atom as nothing to verify', () => {
    expect(cost('evil')).toMatchObject({ grade: 'fast', tier: 'exact', forward: { bytes: 0 }, backward: { bytes: 0 } })
  })

  it('grades Slow by the port or by the engine, and flags disagreement', () => {
    expect(cost('[a-z]', {}, [SLOW])).toMatchObject({ grade: 'slow', portSlow: true, engineSlow: true, drift: false })
    expect(cost('abcd', {}, [SLOW])).toMatchObject({ grade: 'slow', portSlow: false, engineSlow: true, drift: true })
    expect(cost('abcd', {}, null)).toMatchObject({ engineSlow: null, drift: false })
  })

  it('doubles the verified bytes for wide', () => {
    expect(cost('foo.{0,10}barz', { wide: true })).toMatchObject({ backward: { bytes: 26 }, forward: { bytes: 8 } })
  })

  it('marks chained patterns', () => {
    expect(cost('abcd.{0,300}efgh', { s: true }).chained).toBe(true)
  })
})
