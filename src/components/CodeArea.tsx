import { useRef } from 'react'
import { Highlighter, type Span } from './Highlighter'

export function CodeArea({
  ariaLabel,
  value,
  placeholder,
  onChange,
  spans,
  error,
}: {
  ariaLabel: string
  value: string
  placeholder?: string
  onChange: (v: string) => void
  spans: Span[]
  error?: string
}) {
  const taRef = useRef<HTMLTextAreaElement>(null)
  const hlRef = useRef<HTMLDivElement>(null)
  const lineCount = value.split('\n').length

  const sync = () => {
    if (taRef.current && hlRef.current) {
      hlRef.current.scrollTop = taRef.current.scrollTop
      hlRef.current.scrollLeft = taRef.current.scrollLeft
    }
  }

  return (
    <div className={'codearea' + (error ? ' codearea-error' : '')}>
      <div className="codearea-scrim">
        <Highlighter
          ref={hlRef}
          text={value}
          spans={spans}
          className="codearea-hl"
        />
        <textarea
          ref={taRef}
          aria-label={ariaLabel}
          className="codearea-ta"
          value={value}
          placeholder={placeholder}
          wrap="off"
          spellCheck={false}
          onChange={(e) => onChange(e.target.value)}
          onScroll={sync}
        />
      </div>
      <div className="codearea-linecount">{lineCount} line{lineCount === 1 ? '' : 's'}</div>
    </div>
  )
}
