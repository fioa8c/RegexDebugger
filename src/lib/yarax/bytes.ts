export interface ByteMap {
  bytes: Uint8Array
  charStart: (byteOffset: number) => number
  charEnd: (byteOffset: number) => number
}

export function mapBytes(text: string): ByteMap {
  const bytes = new TextEncoder().encode(text)
  const owner = new Int32Array(bytes.length + 1)
  let b = 0
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i) ?? 0
    const units = cp > 0xffff ? 2 : 1
    const size = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4
    for (let k = 0; k < size; k++) owner[b + k] = i
    b += size
    i += units
  }
  owner[bytes.length] = text.length
  const charStart = (offset: number) => owner[Math.max(0, Math.min(offset, bytes.length))]
  const charEnd = (offset: number) => {
    const o = Math.max(0, Math.min(offset, bytes.length))
    if (o === 0 || o === bytes.length || owner[o] !== owner[o - 1]) return owner[o]
    let k = o
    while (k < bytes.length && owner[k] === owner[o - 1]) k++
    return owner[k]
  }
  return { bytes, charStart, charEnd }
}

function hex(v: number): string {
  return '\\x' + v.toString(16).toUpperCase().padStart(2, '0')
}

function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return null
  }
}

export function showBytes(bytes: Uint8Array): string {
  const text = decodeUtf8(bytes)
  if (text === null) {
    return [...bytes].map((v) => (v >= 0x20 && v < 0x7f ? String.fromCharCode(v) : hex(v))).join('')
  }
  let out = ''
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0
    if (ch === '\n') out += '\\n'
    else if (ch === '\t') out += '\\t'
    else if (ch === '\r') out += '\\r'
    else if (c < 0x20 || c === 0x7f) out += hex(c)
    else out += ch
  }
  return out
}
