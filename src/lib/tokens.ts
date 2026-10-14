export interface ReferenceEntry {
  pattern: string
  description: string
}

export const REFERENCE: ReferenceEntry[] = [
  { pattern: '[abc]', description: 'any one of a, b, or c' },
  { pattern: '[^abc]', description: 'any character other than a, b, or c' },
  { pattern: '[a-z]', description: 'any character between a and z' },
  { pattern: '[^a-z]', description: 'any character other than a through z' },
  { pattern: '[a-zA-Z]', description: 'any uppercase or lowercase letter' },
  { pattern: '.', description: 'any single character (no line terminators)' },
  { pattern: 'a|b', description: 'either a or b (alternation)' },
  { pattern: '\\s', description: 'any whitespace' },
  { pattern: '\\S', description: 'any non-whitespace' },
  { pattern: '\\d', description: 'any digit (0-9)' },
  { pattern: '\\D', description: 'any non-digit' },
  { pattern: '\\w', description: 'any word character (A-Z a-z 0-9 _)' },
  { pattern: '\\W', description: 'any non-word character' },
  { pattern: '(?:...)', description: 'a non-capturing group' },
  { pattern: '(...)', description: 'a capturing group' },
  { pattern: '(?<name>...)', description: 'a named capturing group' },
  { pattern: '(?=...)', description: 'positive lookahead' },
  { pattern: '(?<=...)', description: 'positive lookbehind' },
  { pattern: '(?<!...)', description: 'negative lookbehind' },
  { pattern: 'a?', description: 'zero or one occurrence of a' },
  { pattern: 'a*', description: 'zero or more occurrences of a' },
  { pattern: 'a+?...', description: 'one or more occurrences of a, lazy' },
  { pattern: 'a{3}', description: 'exactly 3 occurrences of a' },
  { pattern: 'a{3,}', description: '3 or more occurrences of a' },
  { pattern: 'a{3,6}', description: 'between 3 and 6 occurrences of a' },
  { pattern: '^', description: 'start of the string (or line with m)' },
  { pattern: '$', description: 'end of the string (or line with m)' },
  { pattern: '\\b', description: 'a word boundary' },
  { pattern: '\\B', description: 'a non-word boundary' },
  { pattern: '\\n', description: 'a line feed' },
  { pattern: '\\t', description: 'a tab character' },
]
