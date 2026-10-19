// The highlighter gives each character one span (the shortest wins), so
// syntax colors and underlines can't simply overlap. This splits the
// colored tokens at every mark boundary and joins the class names, giving
// non-overlapping spans like `tok-lit hl-atom`.

export interface ClassSpan {
  start: number
  end: number
  className: string
}

export function layerSpans(base: ClassSpan[], marks: ClassSpan[]): ClassSpan[] {
  const all = [...base, ...marks]
  const points = [...new Set(all.flatMap((s) => [s.start, s.end]))].sort((a, b) => a - b)
  const out: ClassSpan[] = []
  for (let i = 0; i + 1 < points.length; i++) {
    const [a, b] = [points[i], points[i + 1]]
    const covers = (s: ClassSpan) => s.start <= a && s.end >= b
    const classes = [base.find(covers)?.className, ...marks.filter(covers).map((m) => m.className)].filter(
      (c, k, arr): c is string => !!c && arr.indexOf(c) === k,
    )
    if (classes.length === 0) continue
    const className = classes.join(' ')
    const prev = out[out.length - 1]
    if (prev && prev.end === a && prev.className === className) prev.end = b
    else out.push({ start: a, end: b, className })
  }
  return out
}
