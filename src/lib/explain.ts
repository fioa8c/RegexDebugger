export type TokenType =
  | 'literal'
  | 'anchor'
  | 'dot'
  | 'meta-class'
  | 'escape-seq'
  | 'backref'
  | 'char-class'
  | 'alt'
  | 'quantifier'
  | 'group-start'
  | 'group-named'
  | 'group-non'
  | 'group-lookahead'
  | 'group-lookbehind'

export interface Token {
  type: TokenType
  text: string
  start: number
  end: number
  children?: Token[]
  quantifier?: string
}

export interface FlatToken {
  token: Token
  depth: number
}

const QUANTIFIABLE = new Set<TokenType>([
  'literal',
  'dot',
  'meta-class',
  'escape-seq',
  'backref',
  'char-class',
  'group-start',
  'group-named',
  'group-non',
  'group-lookahead',
  'group-lookbehind',
])

function isLazy(q: string): boolean {
  return q.length > 1 && q.endsWith('?')
}

function shift(t: Token, by: number): Token {
  return {
    ...t,
    start: t.start + by,
    end: t.end + by,
    ...(t.children && { children: t.children.map((c) => shift(c, by)) }),
  }
}

function classEnd(src: string, i: number): number {
  let k = i + 1
  if (src[k] === '^') k++
  if (src[k] === ']') k++
  while (k < src.length && src[k] !== ']') {
    if (src[k] === '\\' && k + 1 < src.length) k++
    k++
  }
  return k >= src.length ? src.length - 1 : k
}

function groupClose(src: string, i: number): number {
  let depth = 1
  let j = i + 1
  while (j < src.length) {
    const c = src[j]
    if (c === '\\') {
      j += 2
      continue
    }
    if (c === '[') {
      j = classEnd(src, j) + 1
      continue
    }
    if (c === '(') depth++
    else if (c === ')') {
      depth--
      if (depth === 0) return j
    }
    j++
  }
  return -1
}

function groupHeader(src: string, i: number): { type: TokenType; len: number } {
  if (src[i + 1] === '?') {
    const c = src[i + 2]
    if (c === ':') return { type: 'group-non', len: 3 }
    if (c === '=' || c === '!') {
      return { type: c === '=' ? 'group-lookahead' : 'group-lookbehind', len: 3 }
    }
    if (c === '<') {
      if (src[i + 3] === '=' || src[i + 3] === '!') {
        return { type: 'group-lookbehind', len: 4 }
      }
      let j = i + 2
      while (j < src.length && src[j] !== '>') j++
      return { type: 'group-named', len: j - i + 1 }
    }
  }
  return { type: 'group-start', len: 1 }
}

export function tokenize(pattern: string): Token[] {
  const src = pattern
  const out: Token[] = []
  let i = 0
  while (i < src.length) {
    const ch = src[i]

    if (ch === '\\') {
      const next = src[i + 1]
      if (next === undefined) {
        out.push({ type: 'literal', text: '\\', start: i, end: i + 1 })
      } else if (/\d/.test(next)) {
        let j = i + 1
        while (j + 1 < src.length && /\d/.test(src[j + 1])) j++
        out.push({ type: 'backref', text: src.slice(i, j + 1), start: i, end: j + 1 })
        i = j + 1
        continue
      } else if ('dDwWsS'.includes(next)) {
        out.push({ type: 'meta-class', text: src.slice(i, i + 2), start: i, end: i + 2 })
        i += 2
        continue
      } else if ('nrtvf0'.includes(next)) {
        out.push({ type: 'escape-seq', text: src.slice(i, i + 2), start: i, end: i + 2 })
        i += 2
        continue
      } else if ('bB'.includes(next)) {
        out.push({ type: 'anchor', text: src.slice(i, i + 2), start: i, end: i + 2 })
        i += 2
        continue
      } else {
        out.push({ type: 'literal', text: src.slice(i, i + 2), start: i, end: i + 2 })
        i += 2
        continue
      }
    }

    if (ch === '[') {
      const j = classEnd(src, i)
      out.push({ type: 'char-class', text: src.slice(i, j + 1), start: i, end: j + 1 })
      i = j + 1
      continue
    }

    if (ch === '(') {
      const { type, len } = groupHeader(src, i)
      const j = groupClose(src, i)
      if (j < 0) {
        out.push({ type, text: src.slice(i, i + len), start: i, end: src.length })
        i = src.length
      } else {
        const children = tokenize(src.slice(i + len, j)).map((c) => shift(c, i + len))
        out.push({ type, text: src.slice(i, i + len), start: i, end: j + 1, children })
        i = j + 1
      }
      continue
    }

    if (ch === '^' || ch === '$') {
      out.push({ type: 'anchor', text: ch, start: i, end: i + 1 })
      i++
      continue
    }

    if (ch === '.') {
      out.push({ type: 'dot', text: ch, start: i, end: i + 1 })
      i++
      continue
    }

    if (ch === '|') {
      out.push({ type: 'alt', text: ch, start: i, end: i + 1 })
      i++
      continue
    }

    if (ch === '*' || ch === '+' || ch === '?') {
      const prev = out[out.length - 1]
      let ok = false
      if (prev && QUANTIFIABLE.has(prev.type) && prev.end === i) {
        if (prev.quantifier === undefined) ok = true
        else if (ch === '?' && !isLazy(prev.quantifier)) ok = true
      }
      if (ok) {
        prev.text += ch
        prev.end = i + 1
        prev.quantifier = (prev.quantifier ?? '') + ch
      } else {
        out.push({ type: 'quantifier', text: ch, start: i, end: i + 1 })
      }
      i++
      continue
    }

    if (ch === '{') {
      const m = /^\{\d+(?:,\d*)?\}/.exec(src.slice(i))
      if (m) {
        const prev = out[out.length - 1]
        if (
          prev &&
          QUANTIFIABLE.has(prev.type) &&
          prev.end === i &&
          prev.quantifier === undefined
        ) {
          prev.text += m[0]
          prev.end = i + m[0].length
          prev.quantifier = m[0]
        } else {
          out.push({ type: 'quantifier', text: m[0], start: i, end: i + m[0].length })
        }
        i += m[0].length
        continue
      }
      out.push({ type: 'literal', text: '{', start: i, end: i + 1 })
      i++
      continue
    }

    out.push({ type: 'literal', text: ch, start: i, end: i + 1 })
    i++
  }
  return out
}

export function flattenTokens(tokens: Token[]): FlatToken[] {
  const out: FlatToken[] = []
  const walk = (ts: Token[], depth: number): void => {
    for (const t of ts) {
      out.push({ token: t, depth })
      if (t.children) walk(t.children, depth + 1)
    }
  }
  walk(tokens, 0)
  return out
}

export function extractGroupLabels(tokens: Token[]): string[] {
  const labels: string[] = []
  let n = 0
  const walk = (ts: Token[]): void => {
    for (const t of ts) {
      if (t.type === 'group-start' || t.type === 'group-named') {
        n++
        const name = t.text.match(/\(\?<([a-zA-Z_$][a-zA-Z0-9_$]*)>/)?.[1]
        labels.push(name ?? `Group ${n}`)
      }
      if (t.children) walk(t.children)
    }
  }
  walk(tokens)
  return labels
}
