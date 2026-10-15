import { useEffect, useState } from 'react'
import {
  loadEngine,
  runYara,
  type EngineResult,
  type YaraModule,
  type YaraOptions,
} from '../../lib/yarax/engine'

export type ScanState =
  | { status: 'loading' }
  | { status: 'unavailable'; reason: string }
  | { status: 'ready'; result: EngineResult; ms: number }

const DEBOUNCE_MS = 150

export function useYaraScan(pattern: string, opts: YaraOptions, input: string): ScanState {
  const [mod, setMod] = useState<YaraModule | null>(null)
  const [failure, setFailure] = useState('')
  const [scan, setScan] = useState<{ result: EngineResult; ms: number } | null>(null)

  useEffect(() => {
    let live = true
    loadEngine().then(
      (m) => live && setMod(m),
      (e: unknown) => live && setFailure(e instanceof Error ? e.message : String(e)),
    )
    return () => {
      live = false
    }
  }, [])

  useEffect(() => {
    if (!mod) return
    const timer = setTimeout(() => {
      const t0 = performance.now()
      const result = runYara(mod, pattern, opts, input)
      setScan({ result, ms: performance.now() - t0 })
    }, DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [mod, pattern, opts, input])

  if (failure) return { status: 'unavailable', reason: failure }
  if (!scan) return { status: 'loading' }
  return { status: 'ready', ...scan }
}
