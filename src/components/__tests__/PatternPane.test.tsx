// @vitest-environment jsdom
import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { PatternPane } from '../PatternPane'

afterEach(cleanup)

describe('PatternPane', () => {
  it('describes every flag in a tooltip linked to its checkbox', () => {
    const { container } = render(
      <PatternPane pattern="a" flags="g" spans={[]} error="" onPattern={() => {}} onFlag={() => {}} />,
    )
    const boxes = [...container.querySelectorAll('input[type=checkbox]')]
    const tips = boxes.map((b) => document.getElementById(b.getAttribute('aria-describedby') ?? '')?.textContent)
    expect(tips).toEqual([
      'g: find every match, not just the first',
      'i: case-insensitive',
      'm: ^ and $ match at line breaks',
      's: . also matches line terminators',
      'u: Unicode mode',
    ])
    expect(container.querySelector('[title]')).toBeNull()
  })
})
