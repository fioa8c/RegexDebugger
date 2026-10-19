import { describe, expect, it } from 'vitest'
import { analyzePattern, costOf } from '../analyze'
import { suggest } from '../advice'
import { DEFAULT_YARA_OPTIONS, type Diag, type YaraOptions } from '../engine'

function advise(pattern: string, o: Partial<YaraOptions> = {}, diags: Diag[] = []) {
  const opts = { ...DEFAULT_YARA_OPTIONS, ...o }
  const a = analyzePattern(pattern, opts)
  if (a.kind !== 'ok') throw new Error('not analyzed')
  return suggest(pattern, a.atoms, costOf(a, diags, opts.wide)!, diags)
}

const rules = (pattern: string, o: Partial<YaraOptions> = {}, diags: Diag[] = []) => advise(pattern, o, diags).map((s) => s.rule)

describe('suggest', () => {
  it('flags unbounded repetitions on each side of the atom, once per wording', () => {
    const s = advise('eval\\s*\\(\\s*base64_decode\\s*\\(')
    expect(s.map((x) => x.rule)).toEqual(['unbounded-backward', 'unbounded-forward', 'pikevm'])
    expect(s[0].text).toBe(
      '`\\s*` lets verification scan up to 4,096 bytes backward from each atom hit; bound it, for example `\\s{0,16}`.',
    )
    expect(s[1].span).toEqual({ start: 25, end: 28 })
    expect(s[2].text).toMatch(/^PikeVM is used because of `\\s\*`/)
  })

  it('flags a repetition inside the atom span as forward, since verification re-reads the atom', () => {
    expect(advise('foo\\s*bar').map((x) => x.rule)).toEqual(['unbounded-forward', 'pikevm'])
  })

  it('flags short and common-byte atoms', () => {
    expect(advise('ab')[0]).toMatchObject({ rule: 'short-atom', text: 'The best atom is only `ab` (40/88). Put a distinctive literal of 4 or more bytes next to it.' })
    expect(rules('\\x00\\x00\\x00\\x00')).toContain('common-bytes')
  })

  it('flags atom explosions and weak branches', () => {
    expect(advise('[A-Za-z]{2,}x').find((s) => s.rule === 'atom-explosion')?.text).toBe(
      '`[A-Za-z]{2,}` expands to 2,704 atoms of 2 bytes. Anchor the pattern on a literal instead.',
    )
    expect(rules('abcd|e')).toContain('weak-branch')
  })

  it('explains chaining', () => {
    expect(advise('abcd.{0,300}efgh', { s: true }).find((s) => s.rule === 'chained')?.text).toBe(
      "This pattern is split at the `.{0,300}` gap and the pieces are checked separately; the gap isn't limited to 4,096 bytes.",
    )
  })

  it('has nothing to say about a good pattern', () => {
    expect(advise('foo.{0,10}barz')).toEqual([])
  })

  it('turns engine diagnostics into fixes, and stops there on errors', () => {
    const e015: Diag = { severity: 'error', code: 'E015', title: 'invalid regular expression', labels: [{ text: 'this is greedy', start: 1, end: 3 }], notes: [] }
    expect(advise('a.*?b.*c', {}, [e015])).toEqual([
      {
        rule: 'engine-diag',
        text: 'E015: invalid regular expression. Use only greedy (`*`, `+`, `{n,m}`) or only lazy (`*?`, `+?`, `{n,m}?`) quantifiers in one regex.',
        span: { start: 1, end: 3 },
      },
    ])
    const slow: Diag = { severity: 'warning', code: 'slow_pattern', title: 'slow pattern', labels: [], notes: [] }
    expect(rules('abcd', {}, [slow])).toEqual(['engine-diag', 'drift'])
  })
})
