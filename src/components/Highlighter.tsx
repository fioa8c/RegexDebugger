import { useMemo } from 'react'

export interface Span {
  start: number
  end: number
  className: string
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function buildHtml(text: string, spans: Span[]): string {
  if (text.length === 0) return ''

  const MAX = 200000
  const n = Math.min(text.length, MAX)
  let color: (string | null)[] = new Array(n).fill(null)
  let len: number[] = new Array(n).fill(Infinity)
  for (const s of spans) {
    const start = Math.max(0, Math.min(s.start, n))
    const end = Math.max(start, Math.min(s.end, n))
    for (let p = start; p < end; p++) {
      if (end - start <= len[p]) {
        len[p] = end - start
        color[p] = s.className
      }
    }
  }

  let html = ''
  let i = 0
  while (i < n) {
    const c = color[i]
    let j = i + 1
    while (j < n && color[j] === c) j++
    const chunk = escapeHtml(text.slice(i, j))
    html += c === null ? chunk : `<span class="${c}">${chunk}</span>`
    i = j
  }
  if (text.length > n) html += escapeHtml(text.slice(n))
  return html
}

export function Highlighter(props: {
  text: string
  spans: Span[]
  className?: string
  ref?: React.Ref<HTMLDivElement>
}) {
  const { text, spans, className, ref: elRef } = props
  const html = useMemo(
    () => buildHtml(text, spans),
    [text, spans],
  )
  return (
    <div
      ref={elRef}
      className={className}
      aria-hidden="true"
      dangerouslySetInnerHTML={{ __html: html + '<span class="__hl-tail"></span>' }}
    />
  )
}
