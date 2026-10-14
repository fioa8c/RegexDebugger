import { isLazy, type Token } from './explain'

const CONTROL: Record<string, string> = {
  '\\n': 'a line feed',
  '\\r': 'a carriage return',
  '\\t': 'a tab character',
  '\\v': 'a vertical tab',
  '\\f': 'a form feed',
  '\\0': 'a null character',
}

const META: Record<string, string> = {
  '\\d': 'a digit (0-9)',
  '\\D': 'any character that is not a digit',
  '\\w': 'a word character (A-Z a-z 0-9 _)',
  '\\W': 'any non-word character',
  '\\s': 'a whitespace character',
  '\\S': 'any non-whitespace character',
}

function unesc(s: string): string {
  return s.replace(/\\(.)/g, '$1')
}

function atomText(t: Token): string {
  return t.quantifier ? t.text.slice(0, -t.quantifier.length) : t.text
}

function classEscape(esc: string): string {
  if (esc === '\\b') return 'a backspace'
  return META[esc] ?? CONTROL[esc] ?? `"${esc[1]}"`
}

function describeClass(text: string): string {
  const neg = text[1] === '^'
  let body = text.slice(neg ? 2 : 1)
  if (body.endsWith(']')) body = body.slice(0, -1)
  const parts: string[] = []
  let i = 0
  while (i < body.length) {
    if (body[i] === '\\' && i + 1 < body.length) {
      parts.push(classEscape(body.slice(i, i + 2)))
      i += 2
      continue
    }
    if (body[i + 1] === '-' && i + 2 < body.length) {
      parts.push(`"${body.slice(i, i + 3)}"`)
      i += 3
      continue
    }
    parts.push(`"${body[i]}"`)
    i++
  }
  if (parts.length === 0) {
    return neg ? 'any character, including line terminators' : 'an empty character class'
  }
  const list =
    parts.length === 1
      ? parts[0]
      : parts.length === 2
        ? `${parts[0]} or ${parts[1]}`
        : parts.slice(0, -1).join(', ') + ', or ' + parts[parts.length - 1]
  return neg ? `any character other than ${list}` : `one of ${list}`
}

function quantSuffix(q?: string): string {
  if (!q) return ''
  let core = q
  let lazy = false
  if (isLazy(core)) {
    core = core.slice(0, -1)
    lazy = true
  }
  let phrase = ''
  if (core === '*') phrase = 'zero or more times'
  else if (core === '+') phrase = 'one or more times'
  else if (core === '?') phrase = 'zero or one times'
  else {
    const m = /^\{(\d+)(?:,(\d*))?\}$/.exec(core)
    if (m) {
      phrase =
        m[2] === undefined
          ? `exactly ${m[1]} times`
          : m[2] === ''
            ? `${m[1]} or more times`
            : `between ${m[1]} and ${m[2]} times`
    }
  }
  if (!phrase) return ''
  return `, ${phrase}${lazy ? ' (lazy)' : ''}`
}

function baseAtom(t: Token, flags: string): string {
  const text = atomText(t)
  switch (t.type) {
    case 'literal':
      return `matches "${unesc(text)}"`
    case 'dot':
      return flags.includes('s')
        ? 'any character'
        : 'any character except line terminators'
    case 'meta-class':
      return META[text] ?? `escape sequence ${text}`
    case 'escape-seq':
      return CONTROL[text] ?? `escape sequence ${text}`
    case 'backref':
      return `the text captured by group ${unesc(text)}`
    case 'char-class':
      return describeClass(text)
    case 'anchor':
      if (text === '^') return flags.includes('m') ? 'the start of a line' : 'the start of the string'
      if (text === '$') return flags.includes('m') ? 'the end of a line' : 'the end of the string'
      if (text === '\\b') return 'a word boundary'
      if (text === '\\B') return 'a non-word boundary'
      return 'an anchor'
    case 'alt':
      return 'an alternation branch (or)'
    case 'quantifier':
      return 'a quantifier'
    default:
      return 'a token'
  }
}

export function describeToken(t: Token, flags = ''): string {
  if (t.type.startsWith('group-')) {
    const inner = (t.children ?? []).map((c) => describeToken(c, flags)).join(' ')
    const name = t.text.match(/\(\?<([a-zA-Z_$][a-zA-Z0-9_$]*)>/)?.[1]
    let label = ''
    if (t.type === 'group-start') {
      label = inner ? `a group capturing: ${inner}` : 'an empty group'
    } else if (t.type === 'group-named') {
      label = inner
        ? `a named capturing group "${name ?? ''}": ${inner}`
        : `an empty named group "${name ?? ''}"`
    } else if (t.type === 'group-non') {
      label = inner ? `a non-capturing group: ${inner}` : 'an empty non-capturing group'
    } else {
      const ahead = t.type === 'group-lookahead'
      const neg = t.text.startsWith(ahead ? '(?!' : '(?<!')
      const kind = `${neg ? 'negative ' : ''}${ahead ? 'lookahead' : 'lookbehind'}`
      const rel = `${neg ? 'not ' : ''}be ${ahead ? 'followed' : 'preceded'} by`
      label = inner ? `a ${kind}: the input must ${rel} ${inner}` : `an empty ${kind}`
    }
    return label + quantSuffix(t.quantifier)
  }
  return baseAtom(t, flags) + quantSuffix(t.quantifier)
}
