import { useRef, type Dispatch, type ReactNode, type SetStateAction } from 'react'
import { Splitter } from './Splitter'
import {
  DEFAULT_LAYOUT,
  SPLITTER,
  clampMainHeight,
  clampSideWidth,
  clampSplit,
  type Layout,
} from '../lib/layout'

export function Frame({
  layout,
  onLayout,
  left,
  right,
  results,
  sidebar,
}: {
  layout: Layout
  onLayout: Dispatch<SetStateAction<Layout>>
  left: ReactNode
  right: ReactNode
  results: ReactNode
  sidebar: ReactNode
}) {
  const mainRef = useRef<HTMLElement>(null)
  const start = useRef(layout)
  const begin = () => {
    start.current = layout
  }
  const measure = () => {
    const main = mainRef.current?.getBoundingClientRect()
    const app = mainRef.current?.parentElement?.getBoundingClientRect()
    return {
      mainWidth: main?.width ?? 0,
      appWidth: app?.width ?? 0,
      below: (app?.bottom ?? 0) - (main?.top ?? 0),
    }
  }
  const reset = (key: keyof Layout) => () =>
    onLayout((l) => ({ ...l, [key]: DEFAULT_LAYOUT[key] }))

  return (
    <>
      <main className="main" ref={mainRef}>
        {left}
        <Splitter
          orientation="vertical"
          label="Resize the pattern and test string"
          onBegin={begin}
          onMove={(d) => {
            const { mainWidth } = measure()
            const split = clampSplit(start.current.split + d / (mainWidth - SPLITTER), mainWidth)
            onLayout((l) => ({ ...l, split }))
          }}
          onReset={reset('split')}
        />
        {right}
      </main>
      <Splitter
        orientation="horizontal"
        label="Resize the editors and results"
        onBegin={begin}
        onMove={(d) => {
          const mainHeight = clampMainHeight(start.current.mainHeight + d, measure().below)
          onLayout((l) => ({ ...l, mainHeight }))
        }}
        onReset={reset('mainHeight')}
      />
      {results}
      <Splitter
        orientation="vertical"
        label="Resize the token reference"
        onBegin={begin}
        onMove={(d) => {
          const sideWidth = clampSideWidth(start.current.sideWidth - d, measure().appWidth)
          onLayout((l) => ({ ...l, sideWidth }))
        }}
        onReset={reset('sideWidth')}
      />
      {sidebar}
    </>
  )
}
