// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Splitter } from '../Splitter'

afterEach(cleanup)

const setup = (orientation: 'vertical' | 'horizontal') => {
  const onBegin = vi.fn()
  const onMove = vi.fn()
  const onReset = vi.fn()
  render(
    <Splitter orientation={orientation} label="Resize" onBegin={onBegin} onMove={onMove} onReset={onReset} />,
  )
  return { el: screen.getByRole('separator', { name: 'Resize' }), onBegin, onMove, onReset }
}

describe('Splitter', () => {
  it('is a focusable separator for its orientation', () => {
    const { el } = setup('horizontal')
    expect(el.getAttribute('aria-orientation')).toBe('horizontal')
    expect(el.tabIndex).toBe(0)
  })

  it('reports the distance from where the drag started', () => {
    const { el, onBegin, onMove } = setup('vertical')
    fireEvent.pointerDown(el, { clientX: 100, clientY: 5, pointerId: 1 })
    fireEvent.pointerMove(el, { clientX: 130, clientY: 50, pointerId: 1 })
    fireEvent.pointerMove(el, { clientX: 90, clientY: 50, pointerId: 1 })
    fireEvent.pointerUp(el, { clientX: 90, pointerId: 1 })
    fireEvent.pointerMove(el, { clientX: 200, pointerId: 1 })
    expect(onBegin).toHaveBeenCalledTimes(1)
    expect(onMove.mock.calls).toEqual([[30], [-10]])
  })

  it('follows the vertical axis when horizontal', () => {
    const { el, onMove } = setup('horizontal')
    fireEvent.pointerDown(el, { clientX: 0, clientY: 300, pointerId: 1 })
    fireEvent.pointerMove(el, { clientX: 80, clientY: 260, pointerId: 1 })
    expect(onMove.mock.calls).toEqual([[-40]])
  })

  it('moves 16px per arrow key along its own axis', () => {
    const v = setup('vertical')
    fireEvent.keyDown(v.el, { key: 'ArrowRight' })
    fireEvent.keyDown(v.el, { key: 'ArrowLeft' })
    fireEvent.keyDown(v.el, { key: 'ArrowDown' })
    expect(v.onBegin).toHaveBeenCalledTimes(2)
    expect(v.onMove.mock.calls).toEqual([[16], [-16]])
    cleanup()
    const h = setup('horizontal')
    fireEvent.keyDown(h.el, { key: 'ArrowDown' })
    fireEvent.keyDown(h.el, { key: 'ArrowRight' })
    expect(h.onMove.mock.calls).toEqual([[16]])
  })

  it('resets on double-click', () => {
    const { el, onReset } = setup('vertical')
    fireEvent.doubleClick(el)
    expect(onReset).toHaveBeenCalledTimes(1)
  })
})
