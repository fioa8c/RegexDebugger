# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

A regex101-style regex tester (JavaScript flavor only), built with React + Vite. See `AGENTS.md` for stack, the command table, and the pre-commit order (typecheck → lint → test).

## Commands not in AGENTS.md
- Single test file: `npx vitest run src/lib/__tests__/matcher.test.ts`
- Single test by name: `npx vitest run -t "captures group values"`

## Corrections to AGENTS.md
- Vitest runs in its default **node** environment, not jsdom. There is no `vitest.config.*` and no `test` block in `vite.config.ts`. `jsdom` and `@testing-library/*` are installed but unused. All tests are pure-logic tests in `src/lib/__tests__/`. To test components, add `test: { environment: 'jsdom' }` or a per-file `// @vitest-environment jsdom` comment.
- The Vite template assets are already gone. `src/assets/` does not exist.
- `index.css` defines a single dark palette in `:root`. There is no light theme or `prefers-color-scheme` switch.

## Current baseline
`tsc -b` passes and `npx vitest run` is green. `npx oxlint` reports 2 pre-existing `react/purity` warnings (`performance.now` in `App.tsx`'s `useMemo`); your change didn't cause them.

## Architecture

All state lives in `App.tsx` (`pattern`, `flags`, `input`, active tab). One `useMemo` derives everything else. There is no router, store or context.

**Two independent regex systems that must agree:**
- `lib/explain.ts`: a hand-written recursive tokenizer used for syntax coloring, the explanation, and group labels. Group tokens carry `children`, re-offset to **absolute** positions in the full pattern. Quantifiers (`*`, `+`, `?`, `{n,m}`, lazy `?`) are folded into the preceding token's `text`/`end` and recorded in its `quantifier` field. They become a standalone `quantifier` token only when nothing quantifiable precedes them.
- `lib/matcher.ts`: runs the native `RegExp` via `matchAll`, always forcing `g` and truncating to one match when the user didn't set `g`. Capped at 10,000 matches. Group offsets come from `RegExpExecArray.indices`, so the matcher always adds the `d` flag internally (the UI doesn't expose it).
- The glue: `App.tsx` passes `extractGroupLabels(tokens).length` to `runRegex` as `groupCount`. So the tokenizer's count of capturing groups (`group-start` + `group-named`) limits how many groups the matcher reports. A tokenizer bug therefore shows up as missing or extra match columns.

**Explanation pane:** `flattenTokens` (depth-tagged, pre-order) → `describeToken` from `lib/describe.ts` for each token. Indentation comes from depth. `describeToken` recurses into group children to build the group's summary line.

**Highlighting overlay** (`components/CodeArea.tsx` + `Highlighter.tsx`): a transparent `<textarea>` sits on top of a `Highlighter` div that renders colored spans via `dangerouslySetInnerHTML`. Scroll position is synced by hand in `onScroll`. Both layers must keep identical font and metrics in CSS (`.codearea-ta, .codearea-hl`). `buildHtml` resolves overlapping spans per character, with the **shortest span winning** and ties going to the later span (so a group that covers the whole match still shows its color). This is how group highlights appear over the whole-match highlight. HTML is escaped there; keep it that way when you change rendering.

**Class/color tables that must stay in sync:**
- `TOKEN_CLASS` in `App.tsx` ↔ `.tok-*` rules in `index.css`. Adding a `TokenType` means updating both, plus `QUANTIFIABLE` in `explain.ts` if it applies, and `baseAtom`/`describeToken` in `describe.ts`.
- `GROUP_COLORS` in `lib/colors.ts` (match-table swatches) ↔ `--g0`…`--g7` and `.hl-g0`…`.hl-g7` in `index.css` (input highlights). Both cycle modulo 8.

`lib/tokens.ts` is only the static content of the sidebar "Token Reference". It is not used by the tokenizer.
