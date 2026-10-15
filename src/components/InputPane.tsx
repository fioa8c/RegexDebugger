import { CodeArea } from './CodeArea'
import type { Span } from './Highlighter'

export const SAMPLE_INPUT =
  'GET /api/products?id=123 HTTP/1.1\n' +
  'POST /api/orders/2981/checkout HTTP/1.1\n' +
  'PUT /api/users/42 HTTP/1.1\n' +
  'GET /static/app.js?v=1.2.3 HTTP/1.1\n'

export function InputPane({
  input,
  spans,
  onInput,
  sample = SAMPLE_INPUT,
}: {
  input: string
  spans: Span[]
  onInput: (v: string) => void
  sample?: string
}) {
  return (
    <section className="pane">
      <header className="pane-header">
        <span className="pane-title">Test String</span>
        <button className="linkbtn" onClick={() => onInput(sample)}>
          Reset
        </button>
      </header>
      <CodeArea
        ariaLabel="Test string"
        value={input}
        onChange={onInput}
        spans={spans}
      />
    </section>
  )
}
