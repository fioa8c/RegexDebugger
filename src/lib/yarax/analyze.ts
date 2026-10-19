// Everything the Analysis tab and the pattern coloring need, computed
// synchronously from the pattern and options (no engine involved).

import { extractAtoms, TooManyAlternatives, type AtomResult } from './atoms'
import { assessCost, type Cost } from './cost'
import { describeYara, type StructureLine } from './describe'
import { knownCrash, type Diag, type YaraOptions } from './engine'
import { translate } from './hir'
import { parseYaraRegex, type Span, type Token } from './parse'

export type PatternAnalysis =
  | { kind: 'empty' }
  | { kind: 'unparsed'; message: string; span: Span | null }
  | { kind: 'ok'; tokens: Token[]; atoms: AtomResult; structure: StructureLine[] }

export function analyzePattern(pattern: string, opts: YaraOptions): PatternAnalysis {
  if (pattern === '') return { kind: 'empty' }
  if (pattern.includes('\n')) return { kind: 'unparsed', message: 'a Yara-X regex must be on a single line', span: null }
  const crash = knownCrash(pattern)
  if (crash) return { kind: 'unparsed', message: `${crash} crashes the Yara-X engine, so it isn't analyzed`, span: null }
  const parsed = parseYaraRegex(pattern)
  if (!parsed.ok) return { kind: 'unparsed', message: parsed.error.message, span: parsed.error.span }
  const flags = { i: opts.i || opts.nocase, s: opts.s }
  try {
    const atoms = extractAtoms(translate(parsed.ast, flags), {
      nocase: flags.i,
      wide: opts.wide,
      ascii: opts.ascii,
      fullword: opts.fullword,
    })
    return { kind: 'ok', tokens: parsed.tokens, atoms, structure: describeYara(parsed.ast, flags) }
  } catch (e) {
    if (e instanceof TooManyAlternatives) {
      return { kind: 'unparsed', message: 'more than 255 alternatives in one alternation', span: null }
    }
    throw e
  }
}

// The cost needs the engine's slow_pattern verdict; `diags` is null until
// the engine has answered.
export function costOf(analysis: PatternAnalysis, diags: Diag[] | null, wide: boolean): Cost | null {
  if (analysis.kind !== 'ok') return null
  const engineSlow = diags ? diags.some((d) => d.code === 'slow_pattern') : null
  return assessCost(analysis.atoms, wide, engineSlow)
}
