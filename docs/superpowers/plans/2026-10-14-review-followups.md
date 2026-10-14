# Code-Review Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the code-review findings the user approved on `main` @ `3762054`. Two of them are wrong explanations; one is a tokenizer bug that drops capture-group columns.

**Architecture:** Every change is in `src/lib/` and its tests, plus deleting dead code in `src/lib/colors.ts`. Task 1 fixes character classes (tokenizer + describer). Task 2 fixes negative lookarounds (tokenizer + describer). Task 3 is a batch of small cleanups.

**Tech Stack:** TypeScript 6 (strict), Vitest 5 (node environment), Node 24.

**Spec:** None. The authority is ECMAScript `RegExp` semantics in non-`v` mode, as the UI exposes only the flags g, i, m, s and u. Approved findings, numbered as in the review: 1 (class escapes), 2 (negative lookarounds), 3 (`[]` / `[^]`), 5 (`d` flag without groups), 6 (dead `colors.ts` helpers only, no CSS fallback), 7 (duplicated lazy check).

## Global Constraints

- No new dependencies. No changes outside `src/lib/` and `src/lib/__tests__/`.
- Match existing style: no semicolons, single quotes, 2-space indent, trailing commas in multi-line literals.
- Exported signatures stay the same: `tokenize(pattern: string): Token[]`, `describeToken(t: Token, flags = ''): string`, `runRegex(pattern, flags, text, groupCount): MatchInfo[]`. Task 3 adds one export, `isLazy`.
- `TokenType` doesn't change. Negation is read from the token's `text`, not from a new type.
- Before each commit, run in order: `npx tsc -b` (must pass), `npx oxlint` (no new warnings beyond the 2 existing `react(purity)` warnings in `src/App.tsx`), then `npx vitest run` (all green).
- End every commit message with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Shorthand escapes inside negated or mixed classes** (`[^\d\s]`, `[\b\w-]`). Expect each escape to be described by meaning; inside a class, `\b` means backspace. Pinned in Task 1.
2. **The `[^]` "any character, including newlines" idiom inside a larger pattern** (`a[^]*b`, `([^])(a)`). Expect one class token and the correct capture-group count. Pinned in Task 1.
3. **An escaped `]` inside a class** (`[\]a]b`). Changing `classEnd` must not end the class at the escaped bracket. Pinned in Task 1.
4. **The common negative-lookbehind idiom with an escaped character** (`(?<!\$)`). Expect "must not be preceded by matches "$"". Pinned in Task 2.
5. **Patterns with no capture groups, including a user-supplied `d` flag** (`a` with flags `gd`, groupCount 0). Expect normal matches with empty `groups` and no duplicate-flag error after the `d` change. Pinned in Task 3.

## Out of scope (known, not fixed here)

- `\xHH`, `\uHHHH` and `\cX` escapes, inside or outside classes. They are split into separate literal characters.
- A `color-mix()` fallback for Safari < 16.2 / Firefox < 113. The user approved only the dead-code cleanup for finding 6.
- Keeping the quantifier out of `Token.text` (the `atomText` redesign), the per-level copying in `shift`, `src.slice(i)` per `{`, and the second `RegExp` construction outside `try`.

---

### Task 1: Character classes — describe escapes by meaning; `[]` and `[^]` are complete classes

**Files:**
- Modify: `src/lib/explain.ts` (`classEnd`)
- Modify: `src/lib/describe.ts` (add `classEscape`, replace `describeClass`)
- Test: `src/lib/__tests__/explain.test.ts`, `src/lib/__tests__/describe.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: `tokenize` ends a class at the first unescaped `]` after `[` or `[^`, so `[]` and `[^]` are whole tokens. `describeToken` on a `char-class` token describes escaped members by meaning (using the same text as single tokens), quotes literal members, and describes `[^]` as matching any character.

- [ ] **Step 1: Write the failing tests**

In `src/lib/__tests__/explain.test.ts`, add before the `'extracts group labels in order'` test:

```ts
  it('treats [] and [^] as complete classes', () => {
    expect(tokenize('[]a]').map((x) => x.text)).toEqual(['[]', 'a', ']'])
    expect(tokenize('a[^]*b').map((x) => x.text)).toEqual(['a', '[^]*', 'b'])
    expect(extractGroupLabels(tokenize('([^])(a)'))).toEqual(['Group 1', 'Group 2'])
  })

  it('keeps an escaped ] inside a class', () => {
    expect(tokenize('[\\]a]b').map((x) => x.text)).toEqual(['[\\]a]', 'b'])
  })
```

In `src/lib/__tests__/describe.test.ts`, add after the `'describes a negated two-member class'` test:

```ts
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/lib/__tests__/explain.test.ts src/lib/__tests__/describe.test.ts`
Expected: 3 failures: `treats [] and [^] as complete classes`, `describes escapes inside character classes`, and `describes empty and match-anything classes` (on the `[^]` assertion). `keeps an escaped ] inside a class` already passes; it guards Step 3's `classEnd` change.

- [ ] **Step 3: Implement**

In `src/lib/explain.ts`, delete this line from `classEnd` (in JavaScript, `]` right after `[` or `[^` closes the class):

```ts
  if (src[k] === ']') k++
```

In `src/lib/describe.ts`, add this helper directly after `atomText`:

```ts
function classEscape(esc: string): string {
  if (esc === '\\b') return 'a backspace'
  return META[esc] ?? CONTROL[esc] ?? `"${esc[1]}"`
}
```

Replace the whole `describeClass` function with:

```ts
function describeClass(text: string): string {
  const neg = text[1] === '^'
  let body = text.slice(neg ? 2 : 1)
  if (body.endsWith(']')) body = body.slice(0, -1)
  const parts: string[] = []
  let i = 0
  while (i < body.length) {
    if (body[i] === '\\' && i + 1 < body.length) {
      parts.push(classEscape(body.slice(i, i + 2)))
      i += 2
      continue
    }
    if (body[i + 1] === '-' && i + 2 < body.length) {
      parts.push(`"${body.slice(i, i + 3)}"`)
      i += 3
      continue
    }
    parts.push(`"${body[i]}"`)
    i++
  }
  if (parts.length === 0) {
    return neg ? 'any character, including line terminators' : 'an empty character class'
  }
  const list =
    parts.length === 1
      ? parts[0]
      : parts.length === 2
        ? `${parts[0]} or ${parts[1]}`
        : parts.slice(0, -1).join(', ') + ', or ' + parts[parts.length - 1]
  return neg ? `any character other than ${list}` : `one of ${list}`
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx tsc -b && npx oxlint && npx vitest run`
Expected: tsc exits 0. oxlint shows only the 2 existing `react(purity)` warnings. All tests pass (40 total).

- [ ] **Step 5: Commit**

```bash
git add src/lib/explain.ts src/lib/describe.ts src/lib/__tests__/explain.test.ts src/lib/__tests__/describe.test.ts
git commit -m "fix(classes): describe class escapes by meaning; [] and [^] are complete classes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Negative lookarounds — type `(?!` as a lookahead; describe negation

**Files:**
- Modify: `src/lib/explain.ts` (`groupHeader`)
- Modify: `src/lib/describe.ts` (the lookaround branches of `describeToken`)
- Test: `src/lib/__tests__/explain.test.ts`, `src/lib/__tests__/describe.test.ts`

**Interfaces:**
- Consumes: Task 1's `describe.ts`. This task touches only `describeToken`, not `describeClass`.
- Produces: `(?=` and `(?!` are typed `group-lookahead`; `(?<=` and `(?<!` are typed `group-lookbehind`. The token's `text` starts with the header (`(?!`, `(?<!`, ...), and `describeToken` reads negation from it.

- [ ] **Step 1: Write the failing tests**

In `src/lib/__tests__/explain.test.ts`, add after the `'tokenizes non-capturing, lookahead, lookbehind, named groups'` test:

```ts
  it('types negative lookarounds by direction', () => {
    expect(tokenize('(?!ab)')[0]).toMatchObject({ type: 'group-lookahead', text: '(?!' })
    expect(tokenize('(?<!ab)')[0]).toMatchObject({ type: 'group-lookbehind', text: '(?<!' })
  })
```

In `src/lib/__tests__/describe.test.ts`, add after the `'describes groups with children'` test:

```ts
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/lib/__tests__/explain.test.ts src/lib/__tests__/describe.test.ts`
Expected: 2 failures: `types negative lookarounds by direction` (on `(?!`) and `describes negative lookarounds` (on the first assertion).

- [ ] **Step 3: Implement**

In `src/lib/explain.ts` `groupHeader`, replace:

```ts
    if (c === '=' || c === '!') {
      return { type: c === '=' ? 'group-lookahead' : 'group-lookbehind', len: 3 }
    }
```

with:

```ts
    if (c === '=' || c === '!') return { type: 'group-lookahead', len: 3 }
```

In `src/lib/describe.ts` `describeToken`, replace:

```ts
    } else if (t.type === 'group-lookahead') {
      label = inner ? `a lookahead: the input must be followed by ${inner}` : 'an empty lookahead'
    } else {
      label = inner
        ? `a lookbehind: the input must be preceded by ${inner}`
        : 'an empty lookbehind'
    }
```

with:

```ts
    } else {
      const ahead = t.type === 'group-lookahead'
      const neg = t.text.startsWith(ahead ? '(?!' : '(?<!')
      const kind = `${neg ? 'negative ' : ''}${ahead ? 'lookahead' : 'lookbehind'}`
      const rel = `${neg ? 'not ' : ''}be ${ahead ? 'followed' : 'preceded'} by`
      label = inner ? `a ${kind}: the input must ${rel} ${inner}` : `an empty ${kind}`
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx tsc -b && npx oxlint && npx vitest run`
Expected: tsc exits 0. oxlint shows only the 2 existing `react(purity)` warnings. All tests pass (42 total).

- [ ] **Step 5: Commit**

```bash
git add src/lib/explain.ts src/lib/describe.ts src/lib/__tests__/explain.test.ts src/lib/__tests__/describe.test.ts
git commit -m "fix(lookaround): type (?! as a lookahead and describe negative lookarounds

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Cleanups — `d` only when groups are read; one lazy check; delete dead color helpers

**Files:**
- Modify: `src/lib/matcher.ts` (the `iterFlags` block)
- Modify: `src/lib/explain.ts` (export `isLazy`)
- Modify: `src/lib/describe.ts` (import line, `quantSuffix`)
- Modify: `src/lib/colors.ts` (delete `MATCH_BG`, `hexToRgba`, `groupBg`)
- Test: `src/lib/__tests__/matcher.test.ts`

**Interfaces:**
- Consumes: Task 2's `describe.ts` (the import line at the top of the file and `quantSuffix` are unchanged by Tasks 1–2).
- Produces: `export function isLazy(q: string): boolean` from `src/lib/explain.ts`. `colors.ts` exports only `groupColor`. The only existing importers, `src/App.tsx` and `src/components/MatchList.tsx`, import just `groupColor`.

- [ ] **Step 1: Add the guard test**

In `src/lib/__tests__/matcher.test.ts`, add after the `'accepts flags that already include d'` test:

```ts
  it('matches without capture groups, with or without a user d flag', () => {
    const expected = [
      { index: 0, text: 'a', groups: [] },
      { index: 1, text: 'a', groups: [] },
    ]
    expect(runRegex('a', 'g', 'aa', 0)).toEqual(expected)
    expect(runRegex('a', 'gd', 'aa', 0)).toEqual(expected)
  })
```

- [ ] **Step 2: Run the test**

Run: `npx vitest run src/lib/__tests__/matcher.test.ts`
Expected: PASS. This is a guard. None of the three cleanups changes any output, so there is no RED step; the test pins Review Focus 5 across Step 3.

- [ ] **Step 3: Implement**

In `src/lib/matcher.ts`, replace:

```ts
  if (!iterFlags.includes('d')) iterFlags += 'd'
```

with:

```ts
  if (groupCount > 0 && !iterFlags.includes('d')) iterFlags += 'd'
```

In `src/lib/explain.ts`, replace:

```ts
function isLazy(q: string): boolean {
```

with:

```ts
export function isLazy(q: string): boolean {
```

In `src/lib/describe.ts`, replace the first line:

```ts
import type { Token } from './explain'
```

with:

```ts
import { isLazy, type Token } from './explain'
```

and in `quantSuffix` replace:

```ts
  if (core.length > 1 && core.endsWith('?')) {
```

with:

```ts
  if (isLazy(core)) {
```

In `src/lib/colors.ts`, delete the `MATCH_BG` constant, the `hexToRgba` function and the `groupBg` function, plus the blank lines left between them. The file must end up exactly:

```ts
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
```

- [ ] **Step 4: Run the full verification**

Run: `npx tsc -b && npx oxlint && npx vitest run`
Expected: tsc exits 0. oxlint shows only the 2 existing `react(purity)` warnings. All tests pass (43 total).

- [ ] **Step 5: Commit**

```bash
git add src/lib/matcher.ts src/lib/explain.ts src/lib/describe.ts src/lib/colors.ts src/lib/__tests__/matcher.test.ts
git commit -m "refactor: add d flag only when groups are read, share isLazy, drop dead color helpers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
