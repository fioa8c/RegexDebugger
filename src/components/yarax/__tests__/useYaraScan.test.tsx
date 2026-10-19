// @vitest-environment jsdom
import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useYaraScan } from '../useYaraScan'
import { DEFAULT_YARA_OPTIONS, type YaraModule } from '../../../lib/yarax/engine'

const stub: YaraModule = {
  Compiler: class {
    addSource() {}
    build() {
      return {
        scanner: () => ({
          setMaxMatchesPerPattern() {},
          scan: () => ({ matches: [{ patterns: [{ matches: [{ offset: 0, length: 1 }] }] }] }),
          free() {},
        }),
        free() {},
      }
    }
    readonly warnings: string[] = []
    free() {}
  },
}

afterEach(() => {
  vi.useRealTimers()
})

describe('useYaraScan', () => {
  it('shows the result on the first render when the engine is already loaded', () => {
    vi.useFakeTimers()
    const engine = { load: () => Promise.resolve(stub), loaded: () => stub }
    const { result } = renderHook(() => useYaraScan('a', DEFAULT_YARA_OPTIONS, 'a', engine))
    expect(result.current.status).toBe('ready')
    expect(result.current.status === 'ready' && result.current.result.matches).toEqual([
      { offset: 0, length: 1 },
    ])
  })

  it('marks the result stale until it has been computed for the current pattern and options', () => {
    vi.useFakeTimers()
    const engine = { load: () => Promise.resolve(stub), loaded: () => stub }
    const { result, rerender } = renderHook(({ p, o, i }) => useYaraScan(p, o, i, engine), {
      initialProps: { p: 'a', o: DEFAULT_YARA_OPTIONS, i: 'a' },
    })
    const fresh = () => result.current.status === 'ready' && result.current.fresh
    const wide = { ...DEFAULT_YARA_OPTIONS, wide: true }
    expect(fresh()).toBe(true)
    rerender({ p: 'ab', o: DEFAULT_YARA_OPTIONS, i: 'a' })
    expect(fresh()).toBe(false)
    act(() => vi.advanceTimersByTime(150))
    expect(fresh()).toBe(true)
    rerender({ p: 'ab', o: wide, i: 'a' })
    expect(fresh()).toBe(false)
    act(() => vi.advanceTimersByTime(150))
    // The diagnostics don't depend on the input, so typing there keeps them.
    rerender({ p: 'ab', o: wide, i: 'ab' })
    expect(fresh()).toBe(true)
  })

  it('offers a retry after the engine fails to load', async () => {
    const load = vi
      .fn<() => Promise<YaraModule>>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(stub)
    const engine = { load, loaded: () => null }
    const { result } = renderHook(() => useYaraScan('a', DEFAULT_YARA_OPTIONS, 'a', engine))
    await waitFor(() => expect(result.current.status).toBe('unavailable'))
    const failed = result.current
    expect(failed.status === 'unavailable' && failed.reason).toBe('offline')
    act(() => {
      if (failed.status === 'unavailable') failed.retry()
    })
    await waitFor(() => expect(result.current.status).toBe('ready'))
    expect(load).toHaveBeenCalledTimes(2)
  })
})
