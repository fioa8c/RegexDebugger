// Plain-English structure of a Yara-X regex, worded in bytes: Yara-X
// matches raw bytes, its classes and case folding are ASCII-only, and
// groups never capture.

import type { AssertKind, ClassItem, FlagChange, Node, PerlKind, Span } from './parse'
import { utf8 } from './hir'

export interface StructureLine {
  depth: number
  text: string
  span: Span | null
}

interface Scope {
  i: boolean
  s: boolean
  m: boolean
  U: boolean
}

const hex2 = (b: number) => b.toString(16).toUpperCase().padStart(2, '0')

const PERL_TEXT: Record<PerlKind, string> = {
  d: 'an ASCII digit (0-9)',
  s: 'an ASCII whitespace byte (\\t \\n \\v \\f \\r or space)',
  w: 'an ASCII word byte (A-Z, a-z, 0-9 or _)',
}

const PERL_NOT: Record<PerlKind, string> = {
  d: 'any byte except an ASCII digit',
  s: 'any byte except ASCII whitespace',
  w: 'any byte except an ASCII word byte',
}

function assertText(which: AssertKind, m: boolean): string {
  switch (which) {
    case 'start-line':
      return m ? 'the start of a line' : 'the start of the data'
    case 'end-line':
      return m ? 'the end of a line' : 'the end of the data'
    case 'start-text':
      return 'the start of the data'
    case 'end-text':
      return 'the end of the data'
    case 'word':
      return 'an ASCII word boundary'
    case 'not-word':
      return 'not an ASCII word boundary'
    case 'word-start':
      return 'the start of an ASCII word'
    case 'word-end':
      return 'the end of an ASCII word'
    case 'word-start-half':
      return 'a position not preceded by an ASCII word byte'
    case 'word-end-half':
      return 'a position not followed by an ASCII word byte'
  }
}

function quantText(min: number, max: number | null, greedy: boolean): string {
  let t: string
  if (min === 0 && max === null) t = 'zero or more times'
  else if (min === 1 && max === null) t = 'one or more times'
  else if (min === 0 && max === 1) t = 'optionally'
  else if (max === null) t = `${min} or more times`
  else if (min === max) t = `exactly ${min} time${min === 1 ? '' : 's'}`
  else t = `between ${min} and ${max} times`
  return `${t} (${greedy ? 'as many as possible' : 'as few as possible'})`
}

const FLAG_ON: Record<string, string> = {
  i: 'case-insensitive (ASCII letters only)',
  s: '`.` matches any byte, including \\n',
  m: '`^` and `$` match at line breaks',
  U: 'greedy and lazy quantifiers swapped',
}

const FLAG_OFF: Record<string, string> = {
  i: 'case-sensitive',
  s: '`.` matches any byte except \\n',
  m: '`^` and `$` match only at the ends of the data',
  U: 'quantifiers back to normal',
}

function flagText(f: FlagChange): string {
  return [...[...f.on].map((c) => FLAG_ON[c]), ...[...f.off].map((c) => FLAG_OFF[c])].join('; ')
}

function apply(scope: Scope, f: FlagChange): void {
  for (const c of f.on) scope[c as keyof Scope] = true
  for (const c of f.off) scope[c as keyof Scope] = false
}

function printable(cp: number): boolean {
  return cp >= 0x20 && cp < 0x7f
}

function charText(n: Extract<Node, { kind: 'char' }>, scope: Scope): string {
  if (n.byte && n.cp > 0x7f) return `the byte 0x${hex2(n.cp)}`
  if (n.cp > 0x7f) return `the UTF-8 bytes ${utf8(n.cp).map(hex2).join(' ')} (${String.fromCodePoint(n.cp)})`
  if (!printable(n.cp)) return `the byte 0x${hex2(n.cp)}`
  const c = String.fromCodePoint(n.cp)
  if (scope.i && /[A-Za-z]/.test(c)) return `\`${c.toLowerCase()}\` or \`${c.toUpperCase()}\``
  return `the character \`${c}\``
}

function itemText(item: ClassItem): string {
  switch (item.kind) {
    case 'char':
      return printable(item.cp) ? item.cp === 0x20 ? 'space' : String.fromCodePoint(item.cp) : `0x${hex2(item.cp)}`
    case 'range': {
      const e = (b: number) => (printable(b) && b !== 0x20 ? String.fromCodePoint(b) : `0x${hex2(b)}`)
      return `${e(item.lo)}-${e(item.hi)}`
    }
    case 'perl':
      return `\\${item.negated ? item.which.toUpperCase() : item.which}`
    case 'ascii':
      return `[:${item.negated ? '^' : ''}${item.name}:]`
    case 'bracket':
      return `[${item.negated ? '^' : ''}${item.items.map(itemText).join(' ')}]`
  }
}

// A run of plain printable characters reads as one line of text.
function textRun(items: Node[], from: number): number {
  let k = from
  while (k < items.length) {
    const n = items[k]
    if (n.kind !== 'char' || n.byte || !printable(n.cp)) break
    k++
  }
  return k
}

function walk(node: Node, depth: number, scope: Scope, out: StructureLine[]): void {
  const line = (text: string, span: Span | null = node.span) => out.push({ depth, text, span })
  switch (node.kind) {
    case 'empty':
      return
    case 'char':
      line(charText(node, scope))
      return
    case 'dot':
      line(scope.s ? 'any byte' : 'any byte except \\n')
      return
    case 'perl':
      line(node.negated ? PERL_NOT[node.which] : PERL_TEXT[node.which])
      return
    case 'assert':
      line(assertText(node.which, scope.m))
      return
    case 'class': {
      const set = node.items.map(itemText).join(' ')
      const fold = scope.i ? ', either case' : ''
      line(node.negated ? `one byte not in: ${set}${fold}` : `one byte from: ${set}${fold}`)
      return
    }
    case 'flags':
      apply(scope, node.flags)
      line(`from here on: ${flagText(node.flags)}`)
      return
    case 'repeat': {
      const greedy = scope.U ? !node.greedy : node.greedy
      line(`${quantText(node.min, node.max, greedy)}:`, node.opSpan)
      walk(node.sub, depth + 1, scope, out)
      return
    }
    case 'group': {
      const saved = { ...scope }
      if (node.flags) apply(scope, node.flags)
      const head = node.capture
        ? node.name
          ? `a group named \`${node.name}\` (Yara-X doesn't capture)`
          : "a group (Yara-X doesn't capture)"
        : node.flags
          ? `a group where ${flagText(node.flags)}`
          : 'a non-capturing group'
      line(`${head}:`)
      walk(node.sub, depth + 1, scope, out)
      Object.assign(scope, saved)
      return
    }
    case 'concat': {
      let k = 0
      while (k < node.items.length) {
        const end = textRun(node.items, k)
        if (end - k >= 2) {
          const run = node.items.slice(k, end) as Extract<Node, { kind: 'char' }>[]
          const text = run.map((c) => String.fromCodePoint(c.cp)).join('')
          const anyCase = scope.i && /[A-Za-z]/.test(text) ? ', any case' : ''
          out.push({ depth, text: `the text \`${text}\`${anyCase}`, span: { start: run[0].span.start, end: run[run.length - 1].span.end } })
          k = end
        } else {
          walk(node.items[k], depth, scope, out)
          k++
        }
      }
      return
    }
    case 'alt':
      node.items.forEach((item, i) => {
        line(i === 0 ? 'either:' : 'or:', i === 0 ? node.span : { start: node.bars[i - 1], end: node.bars[i - 1] + 1 })
        walk(item, depth + 1, scope, out)
      })
      return
  }
}

export function describeYara(ast: Node, flags: { i: boolean; s: boolean }): StructureLine[] {
  const out: StructureLine[] = []
  walk(ast, 0, { i: flags.i, s: flags.s, m: false, U: false }, out)
  return out
}
