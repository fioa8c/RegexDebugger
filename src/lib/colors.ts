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

export function groupColor(i: number): string {
  return GROUP_COLORS[i % GROUP_COLORS.length]
}
