const GROUP_COLORS = [
  '#ffb86c',
  '#6cb3ff',
  '#7ee787',
  '#f07ab8',
  '#b388ff',
  '#ffd166',
  '#4dd0e1',
  '#f4845f',
]

export const MATCH_BG = 'rgba(126, 231, 135, 0.25)'

export function groupColor(i: number): string {
  return GROUP_COLORS[i % GROUP_COLORS.length]
}

function hexToRgba(hex: string, a: number): string {
  const n = parseInt(hex.slice(1), 16)
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`
}

export function groupBg(i: number): string {
  return hexToRgba(groupColor(i), 0.4)
}
