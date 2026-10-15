import { describe, expect, it } from 'vitest'
import {
  DEFAULT_LAYOUT,
  clampMainHeight,
  clampSideWidth,
  clampSplit,
  loadLayout,
  saveLayout,
} from '../layout'

const store = (value: string | null) => {
  const data = new Map<string, string>()
  if (value !== null) data.set('regexdebugger.layout', value)
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
  }
}

describe('clampSplit', () => {
  it('keeps each editor at least 200px wide', () => {
    expect(clampSplit(0.5, 1006)).toBe(0.5)
    expect(clampSplit(0.05, 1006)).toBe(0.2)
    expect(clampSplit(0.95, 1006)).toBe(0.8)
  })

  it('falls back to an even split when both editors cannot fit', () => {
    expect(clampSplit(0.9, 300)).toBe(0.5)
  })
})

describe('clampMainHeight', () => {
  it('keeps the editors at least 160px and the results at least 120px tall', () => {
    expect(clampMainHeight(100, 800)).toBe(160)
    expect(clampMainHeight(400, 800)).toBe(400)
    expect(clampMainHeight(790, 800)).toBe(674)
  })
})

describe('clampSideWidth', () => {
  it('keeps the sidebar between 220 and 600px and the results at least 200px wide', () => {
    expect(clampSideWidth(100, 1400)).toBe(220)
    expect(clampSideWidth(450, 1400)).toBe(450)
    expect(clampSideWidth(900, 1400)).toBe(600)
    expect(clampSideWidth(500, 600)).toBe(394)
  })
})

describe('loadLayout and saveLayout', () => {
  it('round-trip a layout through storage', () => {
    const s = store(null)
    saveLayout(s, { split: 0.3, mainHeight: 420, sideWidth: 300 })
    expect(loadLayout(s)).toEqual({ split: 0.3, mainHeight: 420, sideWidth: 300 })
  })

  it('fall back to the defaults for missing, invalid or out-of-range data', () => {
    expect(loadLayout(undefined)).toEqual(DEFAULT_LAYOUT)
    expect(loadLayout(store('not json'))).toEqual(DEFAULT_LAYOUT)
    expect(loadLayout(store(JSON.stringify({ split: 5, mainHeight: -1, sideWidth: 'x' })))).toEqual({
      split: 0.9,
      mainHeight: 160,
      sideWidth: 340,
    })
  })

  it('ignore storage that throws', () => {
    const denied = {
      getItem(): string {
        throw new Error('denied')
      },
      setItem(): void {
        throw new Error('denied')
      },
    }
    expect(loadLayout(denied)).toEqual(DEFAULT_LAYOUT)
    expect(() => saveLayout(denied, DEFAULT_LAYOUT)).not.toThrow()
  })
})
