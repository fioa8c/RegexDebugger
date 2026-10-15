export interface Layout {
  split: number
  mainHeight: number
  sideWidth: number
}

export const DEFAULT_LAYOUT: Layout = { split: 0.5, mainHeight: 280, sideWidth: 340 }
export const SPLITTER = 6

const MIN_PANE = 200
const MIN_MAIN = 160
const MIN_RESULTS = 120
const MIN_SIDE = 220
const MAX_SIDE = 600
const KEY = 'regexdebugger.layout'

const clamp = (v: number, min: number, max: number) => Math.min(Math.max(v, min), max)

export function clampSplit(split: number, width: number): number {
  const usable = width - SPLITTER
  if (usable < 2 * MIN_PANE) return 0.5
  const min = MIN_PANE / usable
  return clamp(split, min, 1 - min)
}

export function clampMainHeight(height: number, available: number): number {
  return clamp(height, MIN_MAIN, Math.max(MIN_MAIN, available - SPLITTER - MIN_RESULTS))
}

export function clampSideWidth(width: number, available: number): number {
  const max = Math.max(MIN_SIDE, Math.min(MAX_SIDE, available - SPLITTER - MIN_PANE))
  return clamp(width, MIN_SIDE, max)
}

export function browserStorage(): Storage | undefined {
  try {
    return window.localStorage
  } catch {
    return undefined
  }
}

export function loadLayout(storage: Pick<Storage, 'getItem'> | undefined): Layout {
  try {
    const raw: unknown = JSON.parse(storage?.getItem(KEY) ?? 'null')
    const saved = (raw ?? {}) as Record<string, unknown>
    const num = (key: keyof Layout) => {
      const v = saved[key]
      return typeof v === 'number' && Number.isFinite(v) ? v : DEFAULT_LAYOUT[key]
    }
    return {
      split: clamp(num('split'), 0.1, 0.9),
      mainHeight: Math.max(num('mainHeight'), MIN_MAIN),
      sideWidth: clamp(num('sideWidth'), MIN_SIDE, MAX_SIDE),
    }
  } catch {
    return DEFAULT_LAYOUT
  }
}

export function saveLayout(storage: Pick<Storage, 'setItem'> | undefined, layout: Layout): void {
  try {
    storage?.setItem(KEY, JSON.stringify(layout))
  } catch {
    // storage can be full or blocked; the layout just isn't remembered
  }
}
