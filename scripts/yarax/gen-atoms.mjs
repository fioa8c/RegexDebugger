// Regenerates src/lib/yarax/__fixtures__/atoms.json from a real `yr` build.
//
// `yr debug atoms` only exists with the `debug-cmd` feature, so build the
// CLI at the same tag as the pinned @virustotal/yara-x package:
//
//   cargo install --git https://github.com/VirusTotal/yara-x --tag v1.21.0 \
//     yara-x-cli --features debug-cmd --root /some/dir
//   YR=/some/dir/bin/yr node scripts/yarax/gen-atoms.mjs
//
// Each case records the atoms `yr` prints (hex, sorted), the warning codes
// and, when the rule doesn't compile, the error code. Lists longer than
// MAX_LISTED keep only their count and the SHA-256 of the sorted list
// joined with commas, so the fixture stays small.

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const YR = process.env.YR
if (!YR) {
  console.error('Set YR to a yr binary built with --features debug-cmd')
  process.exit(1)
}

const MAX_LISTED = 32

// [pattern, suffix, modifiers]
const CASES = [
  // literals and alternations of literals
  ['abc', '', ''],
  ['abcd', '', ''],
  ['base64_decode', '', ''],
  ['eval', '', 'fullword'],
  ['a', '', ''],
  ['ab', '', ''],
  ['\\x00\\x00\\x00\\x00', '', ''],
  ['\\x90\\x90', '', ''],
  ['abc|def', '', ''],
  ['(abc|d)', '', ''],
  ['ab|c', '', ''],
  ['1234', '', 'nocase'],
  ['abcdef', '', 'wide'],
  ['abc', '', 'ascii wide'],
  ['caf\\x{E9}', '', ''],
  ['café', '', ''],
  ['\\xE9\\xFF\\x00\\x01', '', ''],
  // case-insensitive
  ['abc', 'i', ''],
  ['abc', '', 'nocase'],
  ['abcd', 'i', ''],
  ['aaaa1234', '', 'nocase'],
  ['(?i)abc', '', ''],
  ['a(?i)bc', '', ''],
  ['(?i:ab)cd', '', ''],
  // masked literals
  ['[\\x40-\\x4f]b', '', ''],
  ['a.{2}bcd', 's', ''],
  ['[aA]bcd', '', ''],
  ['x[ac]yz', '', ''],
  ['MZ.{2}\\x90\\x00', 's', ''],
  // FastVM
  ['foo.{0,10}bar', '', ''],
  ['foo.{0,10}bar', 's', ''],
  ['foo.*bar', '', ''],
  ['abcd.{3}efgh', '', ''],
  ['(foo|bar).{0,5}bazz', '', ''],
  ['x[ac]yz.{0,4}hello', '', ''],
  ['[0-9a-f]{2}', '', ''],
  // PikeVM
  ['eval\\s*\\(\\s*base64_decode\\s*\\(', '', ''],
  ['foo\\s*bar', '', ''],
  ['foo\\s*bar', '', 'wide'],
  ['foo\\s*bar', '', 'ascii wide'],
  ['(abc|def)ghi', '', ''],
  ['a(bcd|efg)h', '', ''],
  ['(a|b)cd', '', ''],
  ['x(a|c)yz', '', ''],
  ['Look(at|into)this', '', ''],
  ['x[0-9]y', '', ''],
  ['[A-Za-z]{2,}x', '', ''],
  ['[A-Za-z0-9+\\/]{64,512}\\x00', '', ''],
  ['[a-z]', '', ''],
  ['a|b', '', ''],
  ['\\beval\\b', '', ''],
  ['^MZ', '', ''],
  ['abc$', '', ''],
  ['(?m)^abc', '', ''],
  ['ab+c', '', ''],
  ['ab*c', '', ''],
  ['ab?cd', '', ''],
  ['(ab){2}c', '', ''],
  ['(abc){3,}', '', ''],
  ['a(bc)?d', '', ''],
  ['\\d{4}-\\d{2}', '', ''],
  ['[a-z0-9]{8}\\.php', '', ''],
  ['https?:\\/\\/[a-z]+', '', ''],
  ['(foo|bar|baz)\\d+', '', ''],
  ['(foo|)bar', '', ''],
  ['x(?:ab|cd|ef)+y', '', ''],
  ['\\w+@\\w+\\.com', '', ''],
  ['GET \\/[^ ]+ HTTP', '', ''],
  ['\\x00\\x00[\\x01-\\x05]', '', ''],
  ['abc[^a]def', '', ''],
  ['[\\x80-\\xff]{4}', '', ''],
  ['(a|é)bc', '', ''],
  ['é|a', '', ''],
  ['(\\xFF|a)bc', '', ''],
  ['ab.{2}cd', '', ''],
  ['abc\\b', '', 'nocase'],
  ['[ab]|[cd]', '', ''],
  ['(abc)', '', ''],
  ['(?P<n>abc)d', '', ''],
  ['a{,3}bcd', '', ''],
  ['abc.*?def', '', ''],
  ['abcd', '', 'wide fullword'],
  ['\\s*eval', '', ''],
  // chaining
  ['foo.{0,300}bar', 's', ''],
  ['a.{0,300}b', 's', ''],
  ['abc.{0,300}d', 's', ''],
  ['abcd.{0,300}efgh.{500,}ijkl', 's', ''],
  ['abcd.*efgh', 's', ''],
  ['abcd.{0,300}e\\s*fgh', 's', ''],
  ['abcd.{0,300}efgh', 's', 'wide'],
  // errors and warnings
  ['a*', '', ''],
  ['foo{', '', ''],
  ['a.*?b.*c', '', ''],
  ['.*foo', 's', ''],
  ['abc', 'i', 'nocase'],
]

const dir = mkdtempSync(join(tmpdir(), 'yarax-atoms-'))
const out = []
try {
  for (const [pattern, suffix, mods] of CASES) {
    const file = join(dir, 'p.yar')
    writeFileSync(file, `rule t { strings: $a = /${pattern}/${suffix} ${mods} condition: $a }\n`)
    const run = (args) => {
      try {
        return { ok: true, text: execFileSync(YR, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) }
      } catch (e) {
        return { ok: false, text: String(e.stdout ?? '') + String(e.stderr ?? '') }
      }
    }
    const check = run(['check', file])
    const warnings = [...check.text.matchAll(/warning\[([a-z_0-9]+)\]/g)].map((m) => m[1])
    const debug = run(['debug', 'atoms', '--json', file])
    const entry = { pattern, suffix, modifiers: mods, count: 0, atoms: null, sha256: null, warnings, error: null }
    if (debug.ok) {
      const atoms = [...JSON.parse(debug.text)[0].atoms].sort()
      entry.count = atoms.length
      if (atoms.length <= MAX_LISTED) entry.atoms = atoms
      else entry.sha256 = createHash('sha256').update(atoms.join(',')).digest('hex')
    } else {
      entry.error = (/error\[([A-Z0-9]+)\]/.exec(debug.text) ?? [null, 'unknown'])[1]
    }
    out.push(entry)
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}
const version = execFileSync(YR, ['--version'], { encoding: 'utf8' }).trim()
// One case per line keeps the file short and its diffs readable.
writeFileSync(
  new URL('../../src/lib/yarax/__fixtures__/atoms.json', import.meta.url),
  `{"generatedBy": ${JSON.stringify(version)}, "cases": [\n${out.map((c) => JSON.stringify(c)).join(',\n')}\n]}\n`,
)
console.log(`wrote ${out.length} cases (${version})`)
