# Fix Failing Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `npx vitest run` green (7 of 25 tests fail at baseline commit `f917720`). Fix the code bugs behind the failures and correct the tests that assert wrong behavior.

**Architecture:** All changes are in the pure-logic layer, `src/lib/`. Each task owns one module and its test file: tokenizer (`explain.ts`), describer (`describe.ts`), matcher (`matcher.ts`). No component or CSS changes.

**Tech Stack:** TypeScript 6 (strict), Vitest 5 (node environment), Node 24.

**Spec:** None. The authority is ECMAScript `RegExp` semantics (what `new RegExp(...)` does in Node 24) plus the evident intent of the existing tests. Where a test contradicts regex semantics, the test is wrong and gets corrected. Every such correction is called out below.

## Root-cause summary

| Failing test | Cause | Fix |
|---|---|---|
| explain › attaches ? to the preceding token | **Test wrong.** `ab?` is `a` then optional `b`, so 2 tokens. The tokenizer is already correct. | Task 1: correct the test |
| explain › attaches {n,m} to the preceding token | **Test wrong.** It asserts length 1, then reads `t[1]`. Separately, the code bug: the brace regex is anchored with `$`, so `{n}` only works at end of pattern (`x{3}y` breaks). | Task 1: fix test + code |
| explain › keeps absolute offsets in nested group children | **Code bug.** Child offsets are shifted one level only; grandchildren keep relative offsets. | Task 1 |
| describe › character classes with negation and ranges | **Code bug.** Class members aren't quoted when there are 2+ of them, and two members get `", or"`. | Task 2 |
| describe › quantified atoms | **Code bug.** The atom description uses `t.text`, which includes the folded quantifier (`b+?`). | Task 2 |
| matcher › captures group values and offsets | **Test wrong.** The pattern `<[^>]+>\w+` can't match `<html> tag` because a space follows `>`. Separately, the code bug: group offsets need the `d` flag, which is never set, so offsets are always `-1` (group highlighting in the UI never shows). | Task 3: fix test + code |
| matcher › reports unmatched optional groups as null | **Test wrong.** `a(b)?c` doesn't match `adc` at all, so `r[0]` is undefined. | Task 3: correct the input to `ac` |

## Global Constraints

- No new dependencies. No changes outside `src/lib/`, `src/lib/__tests__/` and `CLAUDE.md`.
- Match existing style: no semicolons, single quotes, 2-space indent, trailing commas in multi-line literals.
- Exported signatures stay the same: `tokenize(pattern: string): Token[]`, `describeToken(t: Token, flags = ''): string`, `runRegex(pattern, flags, text, groupCount): MatchInfo[]`.
- Before each commit, run in order: `npx tsc -b` (must pass), `npx oxlint` (no new warnings beyond the 2 existing `react(purity)` warnings in `src/App.tsx`), then the task's test file.
- End every commit message with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A `{n}` / `{n,m}` quantifier followed by more pattern** (`x{3}y`, `\d{2,4}-`). Expect the quantifier to attach to the preceding atom. At baseline it splits into literal `{`, `3`, `}` tokens. Pinned in Task 1.
2. **Groups nested 3+ levels deep** (`x((a(b)))`). Expect every token's `start`/`end` to be absolute in the full pattern, because pattern coloring uses them. Pinned in Task 1.
3. **Plain `?` and lazy `??` / `{n,m}?`.** Expect `a?` to describe as "zero or one times" (baseline drops the suffix), and `a??` / `a{2,3}?` to fold into one token. At baseline they become a stray `quantifier` token. Pinned in Tasks 1 and 2.
4. **Quantified non-literal atoms** (`\d+`, `[ab]*`, `\1?`). Expect the normal atom description plus the quantifier suffix. Baseline produces "escape sequence \d+" and "one of a, b, ], or *". Pinned in Task 2.
5. **Group offsets across multiple matches with `g`**, and flags that already contain `d`. Expect a correct offset per match, and no "duplicate flag" error. Pinned in Task 3.

## Out of scope (known, not fixed here)

- `(?!...)` is typed `group-lookbehind` in `groupHeader` (`src/lib/explain.ts`), so negative lookaheads are described as lookbehinds. Negative lookarounds are also described as positive.
- No-op ternary in `src/App.tsx` (`label.startsWith('Group') ? label : label`).
- The 2 `react(purity)` lint warnings in `src/App.tsx`.

---

### Task 1: Tokenizer — nested offsets, brace quantifiers, lazy suffixes

**Files:**
- Modify: `src/lib/explain.ts` (the `QUANTIFIABLE` area, the `(` branch, the `*+?` branch and the `{` branch of `tokenize`)
- Test: `src/lib/__tests__/explain.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `tokenize(pattern: string): Token[]`, same signature. After this task, every token at every depth has absolute `start`/`end`. A quantifier that follows a quantifiable atom is always folded into it, including `{n}`, `{n,}` and `{n,m}` anywhere in the pattern, and a lazy `?` after any non-lazy quantifier (`??`, `*?`, `+?`, `{n,m}?`). `Token.quantifier` holds the full quantifier string, e.g. `'?'`, `'??'`, `'{2,3}?'`.

- [ ] **Step 1: Correct the two wrong tests and add Review Focus tests**

In `src/lib/__tests__/explain.test.ts`, replace the `'attaches ? to the preceding token'` and `'attaches {n,m} to the preceding token'` tests with:

```ts
  it('attaches ? to the preceding token', () => {
    const t = tokenize('ab?')
    expect(t).toHaveLength(2)
    expect(t[0]).toMatchObject({ text: 'a' })
    expect(t[0].quantifier).toBeUndefined()
    expect(t[1]).toMatchObject({ text: 'b?', quantifier: '?', start: 1, end: 3 })
  })

  it('attaches {n,m} to the preceding token', () => {
    const t = tokenize('x{3,6}')
    expect(t).toHaveLength(1)
    expect(t[0].text).toBe('x{3,6}')
    expect(t[0].quantifier).toBe('{3,6}')
  })

  it('attaches {n} when more pattern follows', () => {
    const t = tokenize('x{3}y')
    expect(t.map((x) => x.text)).toEqual(['x{3}', 'y'])
    expect(t[0]).toMatchObject({ quantifier: '{3}', start: 0, end: 4 })
    expect(t[1]).toMatchObject({ type: 'literal', start: 4, end: 5 })
  })

  it('folds lazy suffixes into the quantifier', () => {
    expect(tokenize('a??')).toEqual([
      { type: 'literal', text: 'a??', start: 0, end: 3, quantifier: '??' },
    ])
    expect(tokenize('a{2,3}?')).toEqual([
      { type: 'literal', text: 'a{2,3}?', start: 0, end: 7, quantifier: '{2,3}?' },
    ])
    const t = tokenize('a*??')
    expect(t.map((x) => x.text)).toEqual(['a*?', '?'])
    expect(t[1].type).toBe('quantifier')
  })
```

After the existing `'keeps absolute offsets in nested group children'` test (leave that test unchanged; it is correct), add:

```ts
  it('keeps absolute offsets three levels deep', () => {
    const t = tokenize('x((a(b)))')
    const g1 = t[1]
    const g2 = g1.children?.[0]
    const g3 = g2?.children?.[1]
    expect(g1).toMatchObject({ start: 1, end: 9 })
    expect(g2).toMatchObject({ start: 2, end: 8 })
    expect(g2?.children?.[0]).toMatchObject({ text: 'a', start: 3, end: 4 })
    expect(g3).toMatchObject({ start: 4, end: 7 })
    expect(g3?.children?.[0]).toMatchObject({ text: 'b', start: 5, end: 6 })
  })
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/lib/__tests__/explain.test.ts`
Expected: 4 failures: `attaches {n} when more pattern follows`, `folds lazy suffixes into the quantifier`, `keeps absolute offsets in nested group children` (`expected 2 to be 3`), and `keeps absolute offsets three levels deep`. The two corrected tests pass (they now assert existing correct behavior).

- [ ] **Step 3: Implement**

In `src/lib/explain.ts`, add these two helpers directly after the `QUANTIFIABLE` set:

```ts
function isLazy(q: string): boolean {
  return q.length > 1 && q.endsWith('?')
}

function shift(t: Token, by: number): Token {
  return {
    ...t,
    start: t.start + by,
    end: t.end + by,
    ...(t.children && { children: t.children.map((c) => shift(c, by)) }),
  }
}
```

In the `(` branch, replace:

```ts
        const children = tokenize(src.slice(i + len, j)).map((c) => ({
          ...c,
          start: c.start + i + len,
          end: c.end + i + len,
        }))
```

with:

```ts
        const children = tokenize(src.slice(i + len, j)).map((c) => shift(c, i + len))
```

In the `*`/`+`/`?` branch, replace:

```ts
        else if (ch === '?' && /^[*+]?$/.test(prev.quantifier)) ok = true
```

with:

```ts
        else if (ch === '?' && !isLazy(prev.quantifier)) ok = true
```

In the `{` branch, replace:

```ts
      const m = /^\{\d+(?:,\d*)?\}$/.exec(src.slice(i, i + 16))
```

with:

```ts
      const m = /^\{\d+(?:,\d*)?\}/.exec(src.slice(i))
```

The `{` branch's attach condition (`prev.quantifier === undefined`) stays as is. A lazy `?` after `{n,m}` is handled by the `?` branch, because `isLazy('{2,3}')` is false.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/lib/__tests__/explain.test.ts`
Expected: all tests in the file pass.

Then run: `npx tsc -b && npx oxlint`
Expected: tsc exits 0. oxlint shows only the 2 existing `react(purity)` warnings in `src/App.tsx`.

- [ ] **Step 5: Commit**

```bash
git add src/lib/explain.ts src/lib/__tests__/explain.test.ts
git commit -m "fix(tokenizer): absolute offsets at every depth, mid-pattern {n,m}, lazy ?? and {n,m}?

Correct two tests that asserted wrong behavior: 'ab?' is two tokens,
and the {n,m} test read t[1] after asserting length 1.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Describer — quantified atoms and character-class lists

**Files:**
- Modify: `src/lib/describe.ts` (`describeClass`, `quantSuffix`, `baseAtom`)
- Test: `src/lib/__tests__/describe.test.ts`

**Interfaces:**
- Consumes: `tokenize` from `src/lib/explain.ts`, and `Token.quantifier` holding the full quantifier string, e.g. `'+?'`, `'{3,}'`, `'??'`. `Token.text` includes the quantifier at its end.
- Produces: `describeToken(t: Token, flags = ''): string`, same signature. For quantified atoms it returns the unquantified atom's description plus the quantifier suffix. Class members are always quoted.

- [ ] **Step 1: Add Review Focus tests**

The two failing tests in this file (`describes character classes with negation and ranges`, `describes quantified atoms`) are correct; leave them unchanged. Add these tests after `'describes quantified atoms'`:

```ts
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/lib/__tests__/describe.test.ts`
Expected: 4 failures: the 2 pre-existing ones plus the 2 new ones. The `a??` and `a{2,3}?` assertions depend on Task 1's tokenizer fix, which is already committed.

- [ ] **Step 3: Implement**

In `src/lib/describe.ts`, add this helper directly after `unesc`:

```ts
function atomText(t: Token): string {
  return t.quantifier ? t.text.slice(0, -t.quantifier.length) : t.text
}
```

In `describeClass`, replace:

```ts
  const list =
    parts.length === 1
      ? `"${parts[0]}"`
      : parts.slice(0, -1).join(', ') + ', or ' + parts[parts.length - 1]
```

with:

```ts
  const quoted = parts.map((p) => `"${p}"`)
  const list =
    quoted.length === 1
      ? quoted[0]
      : quoted.length === 2
        ? `${quoted[0]} or ${quoted[1]}`
        : quoted.slice(0, -1).join(', ') + ', or ' + quoted[quoted.length - 1]
```

In `quantSuffix`, replace:

```ts
  if (core.endsWith('?')) {
    core = core.slice(0, -1)
    lazy = core !== ''
  }
```

with:

```ts
  if (core.length > 1 && core.endsWith('?')) {
    core = core.slice(0, -1)
    lazy = true
  }
```

Replace the whole `baseAtom` function with this version. It reads `atomText(t)` instead of `t.text`; nothing else changes:

```ts
function baseAtom(t: Token, flags: string): string {
  const text = atomText(t)
  switch (t.type) {
    case 'literal':
      return `matches "${unesc(text)}"`
    case 'dot':
      return flags.includes('s')
        ? 'any character'
        : 'any character except line terminators'
    case 'meta-class':
      return META[text] ?? `escape sequence ${text}`
    case 'escape-seq':
      return CONTROL[text] ?? `escape sequence ${text}`
    case 'backref':
      return `the text captured by group ${unesc(text)}`
    case 'char-class':
      return describeClass(text)
    case 'anchor':
      if (text === '^') return flags.includes('m') ? 'the start of a line' : 'the start of the string'
      if (text === '$') return flags.includes('m') ? 'the end of a line' : 'the end of the string'
      if (text === '\\b') return 'a word boundary'
      if (text === '\\B') return 'a non-word boundary'
      return 'an anchor'
    case 'alt':
      return 'an alternation branch (or)'
    case 'quantifier':
      return 'a quantifier'
    default:
      return 'a token'
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/lib/__tests__/describe.test.ts`
Expected: all tests in the file pass.

Then run: `npx tsc -b && npx oxlint`
Expected: tsc exits 0. oxlint shows only the 2 existing `react(purity)` warnings.

- [ ] **Step 5: Commit**

```bash
git add src/lib/describe.ts src/lib/__tests__/describe.test.ts
git commit -m "fix(describe): describe quantified atoms without the quantifier, quote class members, plain ? suffix

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Matcher — group offsets via the `d` flag; correct two tests; refresh CLAUDE.md

**Files:**
- Modify: `src/lib/matcher.ts` (the `force` RegExp construction)
- Test: `src/lib/__tests__/matcher.test.ts`
- Modify: `CLAUDE.md` (the "Current baseline" paragraph and one sentence in "Architecture")

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `runRegex(pattern, flags, text, groupCount): MatchInfo[]`, same signature. `GroupHit.offset` is now the real start index of a participating group (it was always `-1` before), and still `-1` for a group that didn't participate.

- [ ] **Step 1: Correct the two wrong tests and add Review Focus tests**

In `src/lib/__tests__/matcher.test.ts`, replace the `'captures group values and offsets'` and `'reports unmatched optional groups as null'` tests with:

```ts
  it('captures group values and offsets', () => {
    const r = runRegex('(<[^>]+>\\s+\\w+\\s+[\\d.]+)', '', 'x <html> tag 3.14', 1)
    expect(r).toHaveLength(1)
    expect(r[0].groups[0].value).toBe('<html> tag 3.14')
    expect(r[0].groups[0].offset).toBe(2)
  })

  it('reports unmatched optional groups as null', () => {
    const r = runRegex('a(b)?c', '', 'ac', 1)
    expect(r).toHaveLength(1)
    expect(r[0].groups[0].value).toBeNull()
    expect(r[0].groups[0].offset).toBe(-1)
  })

  it('reports group offsets for every match with g flag', () => {
    const r = runRegex('(\\d)(\\w)', 'g', '1a 2b', 2)
    expect(r.map((m) => m.groups.map((g) => [g.value, g.offset]))).toEqual([
      [['1', 0], ['a', 1]],
      [['2', 3], ['b', 4]],
    ])
  })

  it('accepts flags that already include d', () => {
    const r = runRegex('(b)', 'gd', 'abab', 1)
    expect(r.map((m) => m.groups[0].offset)).toEqual([1, 3])
  })
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/lib/__tests__/matcher.test.ts`
Expected: 2 failures: `captures group values and offsets` (offset `-1` instead of `2`) and `reports group offsets for every match with g flag`. `reports unmatched optional groups as null` now passes, because its input was the only bug. `accepts flags that already include d` already passes; it guards the fix in Step 3 against adding `d` twice, which `RegExp` rejects as an invalid flag.

- [ ] **Step 3: Implement**

In `src/lib/matcher.ts`, replace:

```ts
  const force = effectiveFlags.includes('g')
    ? new RegExp(source, effectiveFlags)
    : new RegExp(source, effectiveFlags + 'g')
```

with:

```ts
  let iterFlags = effectiveFlags
  if (!iterFlags.includes('g')) iterFlags += 'g'
  if (!iterFlags.includes('d')) iterFlags += 'd'
  const force = new RegExp(source, iterFlags)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/lib/__tests__/matcher.test.ts`
Expected: all tests in the file pass.

- [ ] **Step 5: Refresh CLAUDE.md**

In `CLAUDE.md`, replace this paragraph under "## Current baseline":

```
`tsc -b` passes. `npx oxlint` reports 2 `react/purity` warnings (`performance.now` in `App.tsx`'s `useMemo`). `npx vitest run` has **7 of 25 tests failing** in the tokenizer, describer and matcher suites. Some of these are real code issues. Don't assume your change caused them; compare against this baseline.
```

with:

```
`tsc -b` passes and `npx vitest run` is green. `npx oxlint` reports 2 pre-existing `react/purity` warnings (`performance.now` in `App.tsx`'s `useMemo`); your change didn't cause them.
```

In the same file, replace this sentence:

```
Group offsets come from `RegExpExecArray.indices`, which is only populated when the `d` flag is set.
```

with:

```
Group offsets come from `RegExpExecArray.indices`, so the matcher always adds the `d` flag internally (the UI doesn't expose it).
```

- [ ] **Step 6: Run the full verification**

Run: `npx tsc -b && npx oxlint && npx vitest run`
Expected: tsc exits 0. oxlint shows only the 2 existing `react(purity)` warnings. Vitest shows 3 test files passed and 0 failed.

- [ ] **Step 7: Commit**

```bash
git add src/lib/matcher.ts src/lib/__tests__/matcher.test.ts CLAUDE.md
git commit -m "fix(matcher): always set the d flag so group offsets are reported

Correct two tests whose inputs never matched their patterns.
Update CLAUDE.md baseline: suite is green.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
