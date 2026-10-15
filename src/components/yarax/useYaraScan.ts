import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import {
  loadEngine,
  loadedEngine,
  runYara,
  type EngineResult,
  type YaraModule,
  type YaraOptions,
} from '../../lib/yarax/engine'

export type ScanState =
  | { status: 'loading' }
  | { status: 'unavailable'; reason: string; retry: () => void }
  | { status: 'ready'; result: EngineResult; ms: number }

export interface EngineSource {
  load: () => Promise<YaraModule>
  loaded: () => YaraModule | null
}

const DEFAULT_ENGINE: EngineSource = { load: loadEngine, loaded: loadedEngine }
const DEBOUNCE_MS = 150

export function useYaraScan(
  pattern: string,
  opts: YaraOptions,
  input: string,
  engine: EngineSource = DEFAULT_ENGINE,
): ScanState {
  const [mod, setMod] = useState<YaraModule | null>(engine.loaded)
  const [failure, setFailure] = useState('')
  const [attempt, setAttempt] = useState(0)
  const [scan, setScan] = useState<{ result: EngineResult; ms: number } | null>(null)
  const scanned = useRef(false)

  useEffect(() => {
    if (mod) return
    let live = true
    engine.load().then(
      (m) => live && setMod(m),
      (e: unknown) => live && setFailure(e instanceof Error ? e.message : String(e)),
    )
    return () => {
      live = false
    }
  }, [mod, engine, attempt])

  useLayoutEffect(() => {
    if (!mod) return
    const run = () => {
      const t0 = performance.now()
      const result = runYara(mod, pattern, opts, input)
      setScan({ result, ms: performance.now() - t0 })
    }
    if (!scanned.current) {
      scanned.current = true
      run()
      return
    }
    const timer = setTimeout(run, DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [mod, pattern, opts, input])

  if (failure) {
    const retry = () => {
      setFailure('')
      setAttempt((n) => n + 1)
    }
    return { status: 'unavailable', reason: failure, retry }
  }
  if (!scan) return { status: 'loading' }
  return { status: 'ready', ...scan }
}
