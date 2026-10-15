import { useRef, type PointerEvent } from 'react'

const STEP = 16

export function Splitter({
  orientation,
  label,
  onBegin,
  onMove,
  onReset,
}: {
  orientation: 'vertical' | 'horizontal'
  label: string
  onBegin: () => void
  onMove: (delta: number) => void
  onReset: () => void
}) {
  const origin = useRef<number | null>(null)
  const axis = (e: PointerEvent) => (orientation === 'vertical' ? e.clientX : e.clientY)
  const back = orientation === 'vertical' ? 'ArrowLeft' : 'ArrowUp'
  const forward = orientation === 'vertical' ? 'ArrowRight' : 'ArrowDown'
  return (
    <div
      role="separator"
      aria-orientation={orientation}
      aria-label={label}
      tabIndex={0}
      className={`splitter splitter-${orientation}`}
      onPointerDown={(e) => {
        origin.current = axis(e)
        e.currentTarget.setPointerCapture?.(e.pointerId)
        onBegin()
      }}
      onPointerMove={(e) => {
        if (origin.current !== null) onMove(axis(e) - origin.current)
      }}
      onPointerUp={() => {
        origin.current = null
      }}
      onPointerCancel={() => {
        origin.current = null
      }}
      onDoubleClick={onReset}
      onKeyDown={(e) => {
        if (e.key !== back && e.key !== forward) return
        e.preventDefault()
        onBegin()
        onMove(e.key === forward ? STEP : -STEP)
      }}
    />
  )
}
