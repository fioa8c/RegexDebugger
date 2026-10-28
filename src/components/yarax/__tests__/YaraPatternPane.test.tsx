// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { YaraPatternPane } from '../YaraPatternPane'
import { DEFAULT_YARA_OPTIONS } from '../../../lib/yarax/engine'

afterEach(cleanup)

describe('YaraPatternPane', () => {
  it('describes every suffix and modifier toggle in a tooltip linked to its checkbox', () => {
    const { container } = render(
      <YaraPatternPane
        pattern="abc"
        opts={DEFAULT_YARA_OPTIONS}
        errors={[]}
        warnings={[]}
        tokens={[]}
        atomSpans={[]}
        onPattern={() => {}}
        onOpts={() => {}}
      />,
    )
    const boxes = [...container.querySelectorAll('input[type=checkbox]')]
    const tips = boxes.map((b) => document.getElementById(b.getAttribute('aria-describedby') ?? '')?.textContent)
    expect(container.querySelector('[title]')).toBeNull()
    expect(tips).toEqual([
      'i suffix: case-insensitive (ASCII letters only)',
      's suffix: . also matches \\n (any byte)',
      'nocase: case-insensitive, same as the i suffix',
      'wide: match UTF-16LE text (a 00 byte after each byte)',
      'ascii: match the plain bytes; with wide, search both encodings',
      'fullword: no ASCII letter or digit right before or after the match',
    ])
  })

  it('loads the regex out of a pasted fixerRegex meta line', () => {
    const onPattern = vi.fn()
    const pane = (pattern: string) => (
      <YaraPatternPane
        pattern={pattern}
        opts={DEFAULT_YARA_OPTIONS}
        errors={[]}
        warnings={[]}
        tokens={[]}
        atomSpans={[]}
        onPattern={onPattern}
        onOpts={() => {}}
      />
    )
    const { container, rerender } = render(pane('fixerRegex = "eval\\\\(\\"x\\"\\\\)"'))
    expect(container.querySelector('.infobox code:last-child')?.textContent).toBe('eval\\("x"\\)')
    fireEvent.click(screen.getByRole('button', { name: 'Load its regex' }))
    expect(onPattern).toHaveBeenCalledWith('eval\\("x"\\)')
    rerender(pane('eval\\("x"\\)'))
    expect(container.querySelector('.infobox')).toBeNull()
  })
})
