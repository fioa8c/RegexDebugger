# Modifier Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Treat JavaScript modifier groups (`(?i:...)`, `(?-i:...)`, `(?ims-ims:...)`) as non-capturing groups. They should stop adding a phantom capture column. The explanation should describe them correctly and use the flags each one turns on or off.

**Architecture:** Task 1 changes the tokenizer (`groupHeader` in `src/lib/explain.ts`) so a modifier header becomes one `group-non` token instead of a capturing `(` followed by the literals `?`, `i` and `:`. That alone fixes the group count. Task 2 adds two helpers to `explain.ts`. `groupModifiers` reads the on/off letters from a group token. `scopedFlags` computes the flags in effect inside the group. The describer and `flattenTokens` use them, so `(?s:.)` reads "any character" and `(?m:^)` reads "the start of a line". The explanation pane passes each row's scoped flags to the describer.

**Tech Stack:** TypeScript 6 (strict), Vitest 5 (node environment), Node 24 (supports modifier groups natively).

**Spec:** None. The authority is ECMAScript 2025 `RegExp` modifiers. The syntax is `(?` then zero or more of `i`, `m`, `s`, then optionally `-` and zero or more of `i`, `m`, `s`, then `:`. Only `i`, `m` and `s` are allowed. `(?-:...)` and repeated letters are SyntaxErrors. Inside the group, the "on" letters are added to the flags in effect and the "off" letters are removed. Modifier groups never capture. This plan comes from the follow-up the final review raised on the previous plan: `(?i:a)(b)` shows "Group 1" holding `b` and an empty "Group 2" column.

## Global Constraints

- No new dependencies.
- Change only these files:
  - `src/lib/` and `src/lib/__tests__/`
  - `src/components/ExplanationPane.tsx` (Task 2)
  - `CLAUDE.md` (Task 2)
- `TokenType` doesn't change. A modifier group is a `group-non` token, and its modifiers are read from the token's `text`. So `TOKEN_CLASS`, the `.tok-*` CSS and `QUANTIFIABLE` need no changes.
- Exported signatures stay compatible. `flattenTokens` gains an optional second parameter, `flags = ''`, and `FlatToken` gains a `flags: string` field. Task 2 adds two exports to `explain.ts`: `groupModifiers` and `scopedFlags`.
- Match the existing style: no semicolons, single quotes, 2-space indent, trailing commas in multi-line literals.
- Before each commit, run in order:
  1. `npx tsc -b`, which must pass
  2. `npx oxlint`, which must show no new warnings beyond the 2 existing `react(purity)` warnings in `src/App.tsx`
  3. `npx vitest run`, which must be all green
- End every commit message with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Capture groups inside a modifier group** (`(?i:(a)|(?<n>b))(c)`). Labels should be `Group 1`, `n`, `Group 3`, numbered the way the engine numbers them. Pinned in Task 1.
2. **A quantified modifier group** (`(?i:ab)+`). The quantifier is folded into the token's `text`, which becomes `(?i:+`. Header parsing therefore must not anchor at the end of `text`, and the description must keep ", one or more times". Pinned in Tasks 1 and 2.
3. **Flag-sensitive atoms inside a modifier group** (`(?s:.)`, `(?m:^)`, and `(?-m:$)` under a global `m`). Each should be described with the flags inside the group, not the global ones. Pinned in Task 2.
4. **Nested modifiers** (`(?m:^(?-m:^))`). The innermost group's flags win: "start of a line", then "start of the string". Pinned in Task 2.
5. **Rows in the explanation pane.** The component isn't tested because Vitest runs in node. Each flattened row must carry its scoped flags, and the pane must pass `ft.flags`, not the global flags. `flattenTokens` is pinned in Task 2. Check the one-line pane change by reading the diff.

## Out of scope (known, not fixed here)

- **Invalid modifier syntax** such as `(?ii:a)`, `(?-:a)` and `(?x:a)`. `RegExp` throws a SyntaxError, which the app already shows as an error, so the tokenizer handles these on a best-effort basis only. `(?x:a)` stays a `group-start`, and `(?ii:a)` is described as "case-insensitive (i) and case-insensitive (i) on".
- **Engines without modifier support.** Older browsers throw a SyntaxError for `(?i:...)`, which shows up as the usual error.
- **The `i` flag** doesn't change any description, inside or outside a group. That matches how a global `i` is treated today.

---

### Task 1: Tokenize modifier groups as non-capturing

**Files:**
- Modify: `src/lib/explain.ts` (add `MODIFIER_HEAD` above `isLazy`; add a branch in `groupHeader`)
- Modify: `src/lib/tokens.ts` (add a cheat-sheet entry)
- Test: `src/lib/__tests__/explain.test.ts`, `src/lib/__tests__/matcher.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `tokenize` returns a modifier group as one `group-non` token. Its `text` is the header, for example `(?i-ms:`, plus any folded quantifier. Its `children` are the group body, at absolute offsets.
  - `extractGroupLabels` therefore doesn't count it.
  - A module-level constant, `const MODIFIER_HEAD = /^\(\?([ims]*)(?:-([ims]*))?:/`, which Task 2 reuses. Capture 1 is the "on" letters. Capture 2 is the "off" letters, or `undefined` when there's no `-`.

- [ ] **Step 1: Write the failing tests**

In `src/lib/__tests__/explain.test.ts`, add these tests directly before the `'extracts group labels in order'` test:

```ts
  it('tokenizes modifier groups as non-capturing', () => {
    const t = tokenize('(?i:ab)+c')
    expect(t.map((x) => x.text)).toEqual(['(?i:+', 'c'])
    expect(t[0]).toMatchObject({ type: 'group-non', quantifier: '+', start: 0, end: 8 })
    expect(t[0].children?.map((c) => [c.text, c.start])).toEqual([['a', 4], ['b', 5]])
    expect(tokenize('(?i-ms:x)')[0]).toMatchObject({ type: 'group-non', text: '(?i-ms:' })
    expect(tokenize('(?-s:x)')[0]).toMatchObject({ type: 'group-non', text: '(?-s:' })
  })

  it('does not count modifier groups as captures', () => {
    expect(extractGroupLabels(tokenize('(?i:a)(b)'))).toEqual(['Group 1'])
    expect(extractGroupLabels(tokenize('(?i:(a)|(?<n>b))(c)'))).toEqual([
      'Group 1',
      'n',
      'Group 3',
    ])
  })
```

In `src/lib/__tests__/matcher.test.ts`, add a second import directly below `import { runRegex } from '../matcher'`:

```ts
import { tokenize, extractGroupLabels } from '../explain'
```

Then add this test as the last test inside the `describe('runRegex', ...)` block, after `'reports offsets alongside other flags'`. It mirrors what `App.tsx` does: the tokenizer's label count becomes `groupCount`.

```ts
  it('gives a modifier-group pattern one column per real capture', () => {
    const p = '(?i:a)(?<x>b)'
    const labels = extractGroupLabels(tokenize(p))
    expect(labels).toEqual(['x'])
    const r = runRegex(p, '', 'Ab', labels.length)
    expect(r[0].groups.map((g) => g.value)).toEqual(['b'])
  })
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/lib/__tests__/explain.test.ts src/lib/__tests__/matcher.test.ts`

Expected: all 3 new tests fail.
- The first test gets `type: 'group-start'` with text `(`.
- The second gets `['Group 1', 'Group 2']`.
- The third gets `['Group 1', 'x']`.

All other tests still pass.

- [ ] **Step 3: Implement**

In `src/lib/explain.ts`, add this constant directly above `export function isLazy(`, followed by a blank line:

```ts
const MODIFIER_HEAD = /^\(\?([ims]*)(?:-([ims]*))?:/
```

In `groupHeader`, add two lines after the `if (c === '<') { ... }` block and before the closing `}` of `if (src[i + 1] === '?')`. The function then reads:

```ts
function groupHeader(src: string, i: number): { type: TokenType; len: number } {
  if (src[i + 1] === '?') {
    const c = src[i + 2]
    if (c === ':') return { type: 'group-non', len: 3 }
    if (c === '=' || c === '!') return { type: 'group-lookahead', len: 3 }
    if (c === '<') {
      if (src[i + 3] === '=' || src[i + 3] === '!') {
        return { type: 'group-lookbehind', len: 4 }
      }
      let j = i + 2
      while (j < src.length && src[j] !== '>') j++
      return { type: 'group-named', len: j - i + 1 }
    }
    const mod = MODIFIER_HEAD.exec(src.slice(i, i + 10))
    if (mod) return { type: 'group-non', len: mod[0].length }
  }
  return { type: 'group-start', len: 1 }
}
```

The slice is 10 characters because the longest valid header, `(?ims-ims:`, is 10 characters long.

In `src/lib/tokens.ts`, add this line directly after the `(?<name>...)` entry:

```ts
  { pattern: '(?i:...)', description: 'case-insensitive inside the group only' },
```

- [ ] **Step 4: Run the gate**

Run: `npx tsc -b && npx oxlint && npx vitest run`

Expected:
- `tsc` exits 0.
- oxlint shows only the 2 existing `react(purity)` warnings.
- Vitest passes 47/47.

- [ ] **Step 5: Commit**

```bash
git add src/lib/explain.ts src/lib/tokens.ts src/lib/__tests__/explain.test.ts src/lib/__tests__/matcher.test.ts
git commit -m "$(cat <<'EOF'
fix(tokenizer): modifier groups (?i:...) are non-capturing

They were tokenized as a capturing group followed by the literals ?, i
and :, so the match table gained an always-empty column and every later
group was shifted one label to the right.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Describe modifier groups with the flags in scope

**Files:**
- Modify: `src/lib/explain.ts` (`FlatToken`; add `groupModifiers` and `scopedFlags` after `isLazy`; `flattenTokens`)
- Modify: `src/lib/describe.ts` (import; add `MODIFIER_NAME`, `joinList` and `modifierPhrase`; use `joinList` in `describeClass`; update the group branch of `describeToken`)
- Modify: `src/components/ExplanationPane.tsx` (pass the scoped flags)
- Modify: `CLAUDE.md` (one architecture note)
- Test: `src/lib/__tests__/explain.test.ts`, `src/lib/__tests__/describe.test.ts`

**Interfaces:**
- Consumes: `MODIFIER_HEAD` from Task 1 (module-private in `explain.ts`). A `group-non` token's `text` starts with the modifier header.
- Produces:
  - `export function groupModifiers(t: Token): { on: string; off: string } | null`. It returns `null` for a token that isn't `group-non`, for a plain `(?:`, and for `(?-:`.
  - `export function scopedFlags(flags: string, t: Token): string`. It returns `flags` unchanged unless `t` is a modifier group.
  - `export interface FlatToken { token: Token; depth: number; flags: string }`.
  - `export function flattenTokens(tokens: Token[], flags = ''): FlatToken[]`.

- [ ] **Step 1: Write the failing tests**

In `src/lib/__tests__/explain.test.ts`, add this test directly before the `'tokenizes capturing group with children'` test:

```ts
  it('carries modifier-scoped flags into flattened children', () => {
    const t = flattenTokens(tokenize('^(?m-s:^.)$'), 's')
    expect(t.map((x) => [x.token.text, x.flags])).toEqual([
      ['^', 's'],
      ['(?m-s:', 's'],
      ['^', 'm'],
      ['.', 'm'],
      ['$', 's'],
    ])
  })
```

In `src/lib/__tests__/describe.test.ts`, add these tests directly before the `'describes negative lookarounds'` test:

```ts
  it('describes modifier groups', () => {
    expect(first('(?i:ab)')).toBe(
      'a non-capturing group with case-insensitive (i) on: matches "a" matches "b"',
    )
    expect(first('(?-i:a)')).toBe(
      'a non-capturing group with case-insensitive (i) off: matches "a"',
    )
    expect(first('(?is-m:a)')).toBe(
      'a non-capturing group with case-insensitive (i) and dot-all (s) on, multiline (m) off: matches "a"',
    )
    expect(first('(?ims:a)')).toBe(
      'a non-capturing group with case-insensitive (i), multiline (m), and dot-all (s) on: matches "a"',
    )
    expect(first('(?i:ab)+')).toBe(
      'a non-capturing group with case-insensitive (i) on: matches "a" matches "b", one or more times',
    )
    expect(first('(?i:)')).toBe('an empty non-capturing group with case-insensitive (i) on')
  })

  it('describes atoms inside a modifier group with the flags in scope', () => {
    expect(first('(?s:.)')).toBe('a non-capturing group with dot-all (s) on: any character')
    expect(first('(?m:^)')).toBe('a non-capturing group with multiline (m) on: the start of a line')
    expect(describeToken(tokenize('(?-m:$)')[0], 'm')).toBe(
      'a non-capturing group with multiline (m) off: the end of the string',
    )
    expect(first('(?m:^(?-m:^))')).toBe(
      'a non-capturing group with multiline (m) on: the start of a line ' +
        'a non-capturing group with multiline (m) off: the start of the string',
    )
  })
```

The existing `'describes groups with children'` test keeps `(?:x)` → `'a non-capturing group: matches "x"'`. That pins the plain non-capturing group as unchanged.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/lib/__tests__/explain.test.ts src/lib/__tests__/describe.test.ts`

Expected: all 3 new tests fail.
- The flatten test fails because `x.flags` is `undefined`.
- The two describe tests fail because the label reads `a non-capturing group: ...` with no modifier phrase, and `.`, `^` and `$` are described with the global flags.

All other tests still pass.

- [ ] **Step 3: Implement the helpers and `flattenTokens` in `src/lib/explain.ts`**

Replace the `FlatToken` interface with:

```ts
export interface FlatToken {
  token: Token
  depth: number
  flags: string
}
```

Directly after the `isLazy` function, add:

```ts
export function groupModifiers(t: Token): { on: string; off: string } | null {
  if (t.type !== 'group-non') return null
  const m = MODIFIER_HEAD.exec(t.text)
  if (!m || (m[1] === '' && m[2] === undefined)) return null
  return { on: m[1], off: m[2] ?? '' }
}

export function scopedFlags(flags: string, t: Token): string {
  const mod = groupModifiers(t)
  if (!mod) return flags
  const kept = [...flags].filter((f) => !mod.off.includes(f)).join('')
  return kept + [...mod.on].filter((f) => !kept.includes(f)).join('')
}
```

`MODIFIER_HEAD` is anchored at the start only, not at the end. A quantified group's `text` ends with the quantifier (for example `(?i:+`), and the header must still match.

Replace `flattenTokens` with:

```ts
export function flattenTokens(tokens: Token[], flags = ''): FlatToken[] {
  const out: FlatToken[] = []
  const walk = (ts: Token[], depth: number, fl: string): void => {
    for (const t of ts) {
      out.push({ token: t, depth, flags: fl })
      if (t.children) walk(t.children, depth + 1, scopedFlags(fl, t))
    }
  }
  walk(tokens, 0, flags)
  return out
}
```

`App.tsx` calls `flattenTokens(tokens)` for pattern coloring and ignores `flags`, so it needs no change.

- [ ] **Step 4: Implement the describer in `src/lib/describe.ts`**

Change the import on line 1 to:

```ts
import { groupModifiers, isLazy, scopedFlags, type Token } from './explain'
```

Directly before `function unesc(`, add:

```ts
const MODIFIER_NAME: Record<string, string> = {
  i: 'case-insensitive (i)',
  m: 'multiline (m)',
  s: 'dot-all (s)',
}

function joinList(parts: string[], conj: 'and' | 'or'): string {
  if (parts.length <= 2) return parts.join(` ${conj} `)
  return parts.slice(0, -1).join(', ') + `, ${conj} ` + parts[parts.length - 1]
}

function modifierPhrase(mod: { on: string; off: string }): string {
  const names = (fs: string) => joinList([...fs].map((f) => MODIFIER_NAME[f]), 'and')
  const parts: string[] = []
  if (mod.on) parts.push(`${names(mod.on)} on`)
  if (mod.off) parts.push(`${names(mod.off)} off`)
  return parts.join(', ')
}
```

In `describeClass`, replace the `const list = ...` expression, which is the nested ternary that builds "a or b" and "a, b, or c", with:

```ts
  const list = joinList(parts, 'or')
```

The output is identical. The existing class tests pin it.

In `describeToken`, change the first line of the group branch from

```ts
    const inner = (t.children ?? []).map((c) => describeToken(c, flags)).join(' ')
```

to

```ts
    const childFlags = scopedFlags(flags, t)
    const inner = (t.children ?? []).map((c) => describeToken(c, childFlags)).join(' ')
```

Then replace the `group-non` branch with:

```ts
    } else if (t.type === 'group-non') {
      const mod = groupModifiers(t)
      const kind = mod ? `non-capturing group with ${modifierPhrase(mod)}` : 'non-capturing group'
      label = inner ? `a ${kind}: ${inner}` : `an empty ${kind}`
```

- [ ] **Step 5: Pass the scoped flags in `src/components/ExplanationPane.tsx`**

Change `const flat = flattenTokens(tokens)` to:

```ts
  const flat = flattenTokens(tokens, flags)
```

Then change **both** calls to `describeToken(t, flags)`, the one in the group-open row and the one in the plain row, to:

```tsx
describeToken(t, ft.flags)
```

Afterwards, `grep -n "describeToken(t, flags)" src/components/ExplanationPane.tsx` must print nothing.

- [ ] **Step 6: Update `CLAUDE.md`**

In the `**Explanation pane:**` paragraph under `## Architecture`, add this sentence at the end:

```markdown
`flattenTokens(tokens, flags)` tags each row with the flags in scope. A modifier group `(?ims-ims:...)` is a `group-non` token, and `scopedFlags` applies its on/off letters to its children, so pass `ft.flags`, not the global flags, to `describeToken`.
```

- [ ] **Step 7: Run the gate**

Run: `npx tsc -b && npx oxlint && npx vitest run`

Expected:
- `tsc` exits 0.
- oxlint shows only the 2 existing `react(purity)` warnings.
- Vitest passes 50/50.

- [ ] **Step 8: Commit**

```bash
git add src/lib/explain.ts src/lib/describe.ts src/components/ExplanationPane.tsx CLAUDE.md src/lib/__tests__/explain.test.ts src/lib/__tests__/describe.test.ts
git commit -m "$(cat <<'EOF'
fix(describe): explain modifier groups with the flags in scope

(?i-m:...) reads "a non-capturing group with case-insensitive (i) on,
multiline (m) off", and atoms inside are described with the group's
flags, so (?s:.) is "any character" and (?m:^) is "the start of a line".
flattenTokens carries each row's scoped flags to the explanation pane.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```
