export interface GroupHit {
  value: string | null
  offset: number
}

export interface MatchInfo {
  index: number
  text: string
  groups: GroupHit[]
}

type IterMatch = RegExpExecArray & {
  indices: (readonly (readonly [number, number] | undefined)[])
}

const MAX_MATCHES = 10_000

export class RegexError extends Error {}

export function runRegex(
  pattern: string,
  flags: string,
  text: string,
  groupCount: number,
): MatchInfo[] {
  if (!pattern) return []

  let source: string
  let effectiveFlags: string
  try {
    const probe = new RegExp(pattern, flags)
    source = probe.source
    effectiveFlags = probe.flags
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    throw new RegexError(`Invalid regular expression: /${pattern}/${flags}\n${msg}`)
  }

  const force = effectiveFlags.includes('g')
    ? new RegExp(source, effectiveFlags)
    : new RegExp(source, effectiveFlags + 'g')

  const iterator = text.matchAll(force) as Iterator<IterMatch>
  let collected: IterMatch[] = []
  let m = iterator.next()
  while (!m.done && collected.length < MAX_MATCHES) {
    collected.push(m.value as IterMatch)
    m = iterator.next()
  }
  if (!effectiveFlags.includes('g')) collected = collected.slice(0, 1)

  return collected.map((it) => {
    const groups: GroupHit[] = []
    const upper = Math.min(it.length, groupCount + 1)
    for (let gi = 1; gi < upper; gi++) {
      const pos = it.indices?.[gi]
      groups.push({ value: it[gi] ?? null, offset: pos ? pos[0] : -1 })
    }
    return { index: it.index, text: it[0], groups }
  })
}
