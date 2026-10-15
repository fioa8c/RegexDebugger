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
