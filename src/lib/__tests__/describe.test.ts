import { describe, expect, it } from 'vitest'
import { describeToken } from '../describe'
import { tokenize } from '../explain'

const first = (text: string) => describeToken(tokenize(text)[0], '')
const last = (text: string) => {
  const t = tokenize(text)
  return describeToken(t[t.length - 1], '')
}

describe('describeToken', () => {
  it('describes literals', () => {
    expect(first('a')).toBe('matches "a"')
  })

  it('describes escapes and meta classes', () => {
    expect(first('\\d')).toBe('a digit (0-9)')
    expect(first('\\n')).toBe('a line feed')
    expect(first('\\b')).toBe('a word boundary')
  })

  it('describes backreferences', () => {
    expect(first('\\1')).toBe('the text captured by group 1')
  })

  it('describes character classes with negation and ranges', () => {
    expect(first('[abc]')).toBe('one of "a", "b", or "c"')
    expect(first('[^a-z]')).toBe('any character other than "a-z"')
    expect(first('[-a]')).toBe('one of "-" or "a"')
  })

  it('describes anchors by flag context', () => {
    expect(first('^')).toBe('the start of the string')
    expect(describeToken(tokenize('^')[0], 'm')).toBe('the start of a line')
    expect(describeToken(tokenize('$')[0], 'ms')).toBe('the end of a line')
  })

  it('describes quantified atoms', () => {
    expect(last('ab+?')).toBe('matches "b", one or more times (lazy)')
    expect(last('a{3,}')).toBe('matches "a", 3 or more times')
    expect(last('a*')).toBe('matches "a", zero or more times')
  })

  it('describes plain and lazy optional quantifiers', () => {
    expect(last('ab?')).toBe('matches "b", zero or one times')
    expect(last('a??')).toBe('matches "a", zero or one times (lazy)')
    expect(last('a{2,3}?')).toBe('matches "a", between 2 and 3 times (lazy)')
  })

  it('describes quantified non-literal atoms', () => {
    expect(first('\\d+')).toBe('a digit (0-9), one or more times')
    expect(first('[ab]*')).toBe('one of "a" or "b", zero or more times')
    expect(first('\\1?')).toBe('the text captured by group 1, zero or one times')
    expect(first('\\n{2}')).toBe('a line feed, exactly 2 times')
  })

  it('describes groups with children', () => {
    expect(first('(ab)')).toBe('a group capturing: matches "a" matches "b"')
    expect(first('(?:x)')).toBe('a non-capturing group: matches "x"')
    expect(first('(?<name>ab)')).toBe('a named capturing group "name": matches "a" matches "b"')
    expect(first('(?=a)')).toBe('a lookahead: the input must be followed by matches "a"')
    expect(first('(?<=a)')).toBe('a lookbehind: the input must be preceded by matches "a"')
  })

  it('describes negative lookarounds', () => {
    expect(first('(?!a)')).toBe(
      'a negative lookahead: the input must not be followed by matches "a"',
    )
    expect(first('(?<!\\$)')).toBe(
      'a negative lookbehind: the input must not be preceded by matches "$"',
    )
    expect(first('(?!)')).toBe('an empty negative lookahead')
    expect(first('(?=)')).toBe('an empty lookahead')
  })


  it('describes a negated two-member class', () => {
    expect(first('[^ab]')).toBe('any character other than "a" or "b"')
  })

  it('describes escapes inside character classes', () => {
    expect(first('[\\d.]')).toBe('one of a digit (0-9) or "."')
    expect(first('[\\n\\t]')).toBe('one of a line feed or a tab character')
    expect(first('[^\\d\\s]')).toBe(
      'any character other than a digit (0-9) or a whitespace character',
    )
    expect(first('[\\b\\w-]')).toBe(
      'one of a backspace, a word character (A-Z a-z 0-9 _), or "-"',
    )
    expect(first('[\\]-]')).toBe('one of "]" or "-"')
  })

  it('describes empty and match-anything classes', () => {
    expect(first('[]')).toBe('an empty character class')
    expect(first('[^]')).toBe('any character, including line terminators')
  })
})
