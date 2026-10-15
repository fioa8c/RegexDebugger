/// <reference types="node" />
import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'
import * as yarax from '@virustotal/yara-x'
import {
  DEFAULT_YARA_OPTIONS,
  buildRuleSource,
  formatDiag,
  hasUnescapedSlash,
  parseDiag,
  runYara,
  type YaraModule,
  type YaraOptions,
} from '../engine'
import { YARA_DEFAULT_PATTERN, YARA_SAMPLE_INPUT } from '../samples'

const mod = yarax as unknown as YaraModule
const opts = (o: Partial<YaraOptions> = {}): YaraOptions => ({ ...DEFAULT_YARA_OPTIONS, ...o })

beforeAll(() => {
  yarax.initSync({ module: readFileSync('node_modules/@virustotal/yara-x/pkg/yara_x_js_bg.wasm') })
})

const E014 =
  'error[E014]: invalid regular expression\n' +
  ' --> line:1:28\n' +
  '  |\n' +
  '1 | rule t { strings: $a = /foo{/ condition: $a }\n' +
  '  |                            ^ unclosed counted repetition\n' +
  '  |\n' +
  '  = note: did you mean `\\{` instead of `{`?'

const REDUNDANT =
  'warning[redundant_modifier]: redundant case-insensitive modifier\n' +
  ' --> line:1:29\n' +
  '  |\n' +
  '1 | rule t { strings: $a = /abc/i nocase condition: $a }\n' +
  '  |                             - ------ the `nocase` modifier does the same\n' +
  '  |                             |\n' +
  '  |                             the `i` suffix indicates that the pattern is case-insensitive'

describe('buildRuleSource', () => {
  it('wraps the pattern with suffix and modifiers', () => {
    expect(buildRuleSource('ab\\/c', opts({ i: true, s: true, nocase: true, fullword: true }))).toBe(
      'rule t { strings: $a = /ab\\/c/is nocase fullword condition: $a }',
    )
    expect(buildRuleSource('x', opts())).toBe('rule t { strings: $a = /x/ condition: $a }')
  })
})

describe('parseDiag', () => {
  it('reads code, title, label position and note', () => {
    expect(parseDiag(E014, 4)).toEqual({
      severity: 'error',
      code: 'E014',
      title: 'invalid regular expression',
      labels: [{ text: 'unclosed counted repetition', start: 3, end: 4 }],
      notes: ['did you mean `\\{` instead of `{`?'],
    })
  })

  it('reads every label of a multi-label diagnostic', () => {
    const d = parseDiag(REDUNDANT, 3)
    expect(d.severity).toBe('warning')
    expect(d.code).toBe('redundant_modifier')
    expect(d.labels.map((l) => l.text)).toEqual([
      'the `i` suffix indicates that the pattern is case-insensitive',
      'the `nocase` modifier does the same',
    ])
    expect(d.labels.every((l) => l.start === null && l.end === null)).toBe(true)
  })
})

describe('hasUnescapedSlash', () => {
  it('finds a slash that is not escaped', () => {
    expect(hasUnescapedSlash('a/b')).toBe(true)
    expect(hasUnescapedSlash('a\\/b')).toBe(false)
    expect(hasUnescapedSlash('a\\\\/b')).toBe(true)
    expect(hasUnescapedSlash('abc')).toBe(false)
  })
})

describe('formatDiag', () => {
  it('joins code, title, labels and notes into banner text', () => {
    expect(formatDiag(parseDiag(E014, 4))).toBe(
      'E014: invalid regular expression — unclosed counted repetition\n' +
        'note: did you mean `\\{` instead of `{`?',
    )
    expect(formatDiag(parseDiag(REDUNDANT, 3))).toBe(
      'redundant_modifier: redundant case-insensitive modifier — ' +
        'the `i` suffix indicates that the pattern is case-insensitive; ' +
        'the `nocase` modifier does the same',
    )
  })

  it('shows only the title for errors raised by the tester itself', () => {
    expect(
      formatDiag({ severity: 'error', code: 'input', title: 'a Yara-X regex must be on a single line', labels: [], notes: [] }),
    ).toBe('a Yara-X regex must be on a single line')
  })
})

describe('runYara', () => {
  it('reports byte offsets and lengths of every match', () => {
    const r = runYara(
      mod,
      'eval\\s*\\(\\s*base64_decode\\s*\\(',
      opts(),
      "<?php eval(base64_decode('x')); eval ( base64_decode ( 'y' );",
    )
    expect(r.errors).toEqual([])
    expect(r.matches).toEqual([
      { offset: 6, length: 19 },
      { offset: 32, length: 22 },
    ])
  })

  it('reports overlapping matches and byte offsets after multibyte text', () => {
    expect(runYara(mod, 'aa', opts(), 'aaaa').matches).toEqual([
      { offset: 0, length: 2 },
      { offset: 1, length: 2 },
      { offset: 2, length: 2 },
    ])
    expect(runYara(mod, 'x', opts(), 'éx').matches).toEqual([{ offset: 2, length: 1 }])
  })

  it('returns engine errors with the label mapped into the pattern', () => {
    const r = runYara(mod, 'foo{', opts(), 'foo')
    expect(r.matches).toEqual([])
    expect(r.errors).toEqual([parseDiag(E014, 4)])
  })

  it('returns engine warnings alongside matches', () => {
    const r = runYara(mod, 'a', opts(), 'banana')
    expect(r.warnings.map((w) => [w.code, w.labels[0].start, w.labels[0].end])).toEqual([
      ['slow_pattern', 0, 1],
    ])
    expect(r.matches.map((m) => m.offset)).toEqual([1, 3, 5])
  })

  it('applies suffixes and modifiers', () => {
    expect(runYara(mod, 'abc', opts({ nocase: true }), 'xABC').matches).toEqual([
      { offset: 1, length: 3 },
    ])
    expect(runYara(mod, 'abcd', opts({ fullword: true }), 'xabcd abcd').matches).toEqual([
      { offset: 6, length: 4 },
    ])
    expect(runYara(mod, 'abc', opts({ i: true, nocase: true }), 'abc').warnings[0].code).toBe(
      'redundant_modifier',
    )
  })

  it('reads a label whose text contains hyphens', () => {
    const r = runYara(mod, '(?=a)', opts(), 'a')
    expect(r.errors.map((e) => e.labels)).toEqual([
      [{ text: 'look-around, including look-ahead and look-behind, is not supported', start: 0, end: 3 }],
    ])
    expect(formatDiag(r.errors[0])).toBe(
      'E014: invalid regular expression — look-around, including look-ahead and look-behind, is not supported',
    )
  })

  it('never sends patterns that crash Yara-X 1.21.0 to the engine', () => {
    let compiled = 0
    const spy: YaraModule = {
      Compiler: class {
        constructor() {
          compiled++
        }
        addSource() {}
        build(): never {
          throw new Error('not reached')
        }
        readonly warnings: string[] = []
        free() {}
      },
    }
    for (const p of ['\\b{start-half}a', 'a\\b{end-half}', '(?u)\\w', 'x(?iu:.)', '(?u)[^a]']) {
      expect(runYara(spy, p, opts(), 'a').errors.map((e) => e.code)).toEqual(['unsupported'])
    }
    expect(compiled).toBe(0)
    expect(runYara(mod, '(?-u)a\\(\\?u\\)[(?u)]', opts(), 'a(?u))').matches).toEqual([{ offset: 0, length: 6 }])
    expect(runYara(mod, '\\b{start}a', opts(), 'a').matches).toEqual([{ offset: 0, length: 1 }])
  })

  it('reports an engine crash and says how to recover', () => {
    const crashing = (message: string): YaraModule => ({
      Compiler: class {
        addSource(): never {
          throw new WebAssembly.RuntimeError(message)
        }
        build(): never {
          throw new Error('not reached')
        }
        readonly warnings: string[] = []
        free(): never {
          throw new Error('a poisoned compiler must not be freed')
        }
      },
    })
    const r = runYara(crashing('unreachable'), 'abc', opts(), 'abc')
    expect(r.errors.map((e) => [e.code, e.title])).toEqual([
      [
        'crash',
        'the Yara-X engine crashed on this pattern (unreachable). ' +
          'Each crash leaks engine memory; reload the page if valid patterns start failing',
      ],
    ])
    expect(runYara(mod, 'abc', opts(), 'abc').matches).toEqual([{ offset: 0, length: 3 }])
  })

  it('explains an unescaped slash, which ends the regex early', () => {
    const r = runYara(mod, 'a/b', opts(), 'a/b')
    expect(r.errors.map((e) => [e.code, e.notes])).toEqual([
      ['E001', ['Yara-X ends the regex at an unescaped `/`; write it as `\\/`']],
    ])
    expect(runYara(mod, 'a\\/b', opts(), 'xa/b').matches).toEqual([{ offset: 1, length: 3 }])
  })

  it('finds nothing with wide alone in pasted text, and the plain bytes with ascii wide', () => {
    expect(runYara(mod, 'abc', opts({ wide: true }), 'abc').matches).toEqual([])
    expect(runYara(mod, 'abc', opts({ wide: true, ascii: true }), 'abc').matches).toEqual([
      { offset: 0, length: 3 },
    ])
  })

  it('stops at 10,000 matches', () => {
    expect(runYara(mod, 'aa', opts(), 'a'.repeat(20001)).matches).toHaveLength(10000)
  })

  it('rejects a pattern with a line break before calling the engine', () => {
    expect(runYara(mod, 'a\nb', opts(), 'ab').errors.map((e) => e.code)).toEqual(['input'])
  })

  it('returns nothing for an empty pattern', () => {
    expect(runYara(mod, '', opts(), 'abc')).toEqual({ matches: [], errors: [], warnings: [] })
  })
})

describe('Yara-X defaults', () => {
  it('match the sample twice and skip the near-miss', () => {
    const r = runYara(mod, YARA_DEFAULT_PATTERN, opts(), YARA_SAMPLE_INPUT)
    expect(r.errors).toEqual([])
    expect(r.warnings).toEqual([])
    const text = r.matches.map((m) =>
      new TextDecoder().decode(new TextEncoder().encode(YARA_SAMPLE_INPUT).slice(m.offset, m.offset + m.length)),
    )
    expect(text).toEqual(['eval(base64_decode(', 'eval ( base64_decode ('])
  })
})
