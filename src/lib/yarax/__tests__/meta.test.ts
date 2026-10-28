/// <reference types="node" />
import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'
import * as yarax from '@virustotal/yara-x'
import { escapeMeta, fixerRegexLine, fromFixerRegexLine, unescapeMeta } from '../meta'

beforeAll(() => {
  yarax.initSync({ module: readFileSync('node_modules/@virustotal/yara-x/pkg/yara_x_js_bg.wasm') })
})

// A signature's fixer regex, and its meta line as written in the rule.
const FIXER = `echo '<script>eval\\("(\\\\u0[a-f0-9]{3}){300,}"\\);<.script>';`
const LINE = String.raw`fixerRegex = "echo '<script>eval\\(\"(\\\\u0[a-f0-9]{3}){300,}\"\\);<.script>';"`

// The value the engine reads from `meta: fixerRegex = "<escaped>"`. It
// reports a string with escapes as bytes.
function engineValue(escaped: string): string {
  const compiler = new yarax.Compiler()
  compiler.addSource(`rule t { meta: fixerRegex = "${escaped}" condition: true }`)
  const rules = compiler.build()
  const value = rules.scan(new Uint8Array()).matches[0].metadata[0].value as string | number[]
  rules.free()
  compiler.free()
  return typeof value === 'string' ? value : new TextDecoder().decode(new Uint8Array(value))
}

describe('escapeMeta', () => {
  it('doubles backslashes and escapes quotes', () => {
    expect(escapeMeta('a\\/b"c')).toBe('a\\\\/b\\"c')
    expect(fixerRegexLine(FIXER)).toBe(LINE)
  })

  it('names tab, newline and carriage return, and writes other control bytes as \\xNN', () => {
    expect(escapeMeta('a\tb\nc\rd\x01e\x7f')).toBe('a\\tb\\nc\\rd\\x01e\\x7f')
  })

  it('keeps non-ASCII text as it is', () => {
    expect(escapeMeta('café ✓ 😀')).toBe('café ✓ 😀')
  })

  it.each([
    FIXER,
    'eval\\s*\\(\\s*base64_decode\\s*\\(',
    '<\\/script>',
    '"[^"\\\\]*"',
    '\\x00\\xFF\\.\\d+',
    'a\tb\x01\x7f',
    'café ✓ 😀',
  ])('is read back by the engine unchanged: %s', (pattern) => {
    expect(engineValue(escapeMeta(pattern))).toBe(pattern)
  })

  it('is needed: the engine rejects a regex escape such as \\/ inside a text string', () => {
    expect(() => engineValue('<\\/script>')).toThrow(/E029/)
  })
})

describe('unescapeMeta', () => {
  it('undoes escapeMeta', () => {
    for (const s of [FIXER, 'a\tb\nc\rd\x01e\x7f', 'café ✓ 😀', '']) expect(unescapeMeta(escapeMeta(s))).toBe(s)
  })

  it('reads \\xNN bytes as UTF-8', () => {
    expect(unescapeMeta('\\x41\\xc3\\xa9')).toBe('Aé')
  })

  it('rejects what the engine rejects: unknown escapes, bare quotes, a trailing backslash, bad UTF-8', () => {
    expect(unescapeMeta('a\\/b')).toBeNull()
    expect(unescapeMeta('a"b')).toBeNull()
    expect(unescapeMeta('a\\')).toBeNull()
    expect(unescapeMeta('\\x4')).toBeNull()
    expect(unescapeMeta('\\xff')).toBeNull()
  })
})

describe('fromFixerRegexLine', () => {
  it('reads the regex out of a pasted meta line', () => {
    expect(fromFixerRegexLine(LINE)).toBe(FIXER)
    expect(fromFixerRegexLine(`  ${LINE}  `)).toBe(FIXER)
    expect(fromFixerRegexLine('fixerRegex="a\\\\d"')).toBe('a\\d')
  })

  it('ignores anything that is not a valid fixerRegex line', () => {
    expect(fromFixerRegexLine(FIXER)).toBeNull()
    expect(fromFixerRegexLine('fixer = "regex-clean"')).toBeNull()
    expect(fromFixerRegexLine('fixerRegex = "a\\/b"')).toBeNull()
    expect(fromFixerRegexLine('fixerRegex = "a"b"')).toBeNull()
  })
})
