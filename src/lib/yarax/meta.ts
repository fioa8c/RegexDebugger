// The regex-clean fixer reads its regex from a rule's `fixerRegex` meta
// value, a Yara-X text string. These convert between that string's escaped
// form and the regex in the pattern pane.

const NAMED: Record<string, string> = { '\\': '\\\\', '"': '\\"', '\t': '\\t', '\n': '\\n', '\r': '\\r' }
const UNNAMED: Record<string, number> = { '\\': 0x5c, '"': 0x22, t: 0x09, n: 0x0a, r: 0x0d }

// Text-string escapes are only `\\ \" \t \n \r \xNN`; anything else after a
// backslash (`\/`, `\.`) is error E029, so every backslash is doubled.
export function escapeMeta(s: string): string {
  let out = ''
  for (const c of s) {
    const code = c.charCodeAt(0)
    out += NAMED[c] ?? (code < 0x20 || code === 0x7f ? `\\x${code.toString(16).padStart(2, '0')}` : c)
  }
  return out
}

// null when the body isn't a valid text string: a bare `"`, an unknown
// escape, or `\xNN` bytes that aren't UTF-8.
export function unescapeMeta(s: string): string | null {
  const bytes: number[] = []
  const enc = new TextEncoder()
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (c === '"') return null
    if (c !== '\\') {
      const cp = s.codePointAt(i)!
      if (cp > 0xffff) i++
      bytes.push(...enc.encode(String.fromCodePoint(cp)))
      continue
    }
    const e = s[++i]
    if (e === 'x' && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16))
      i += 2
    } else if (e !== undefined && e in UNNAMED) bytes.push(UNNAMED[e])
    else return null
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes))
  } catch {
    return null
  }
}

export function fixerRegexLine(pattern: string): string {
  return `fixerRegex = "${escapeMeta(pattern)}"`
}

// The regex in a pasted `fixerRegex = "…"` line, or null for anything else.
export function fromFixerRegexLine(text: string): string | null {
  const m = /^\s*fixerRegex\s*=\s*"(.*)"\s*$/.exec(text)
  return m ? unescapeMeta(m[1]) : null
}
