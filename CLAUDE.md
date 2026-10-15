# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

A regex101-style regex tester with JavaScript and Yara-X flavors, built with React + Vite. See `AGENTS.md` for stack, the command table, and the pre-commit order (typecheck → lint → test).

## Commands not in AGENTS.md
- Single test file: `npx vitest run src/lib/__tests__/matcher.test.ts`
- Single test by name: `npx vitest run -t "captures group values"`
- Yara-X engine tests only: `npx vitest run src/lib/yarax`

## Corrections to AGENTS.md
- Vitest runs in its default **node** environment, not jsdom. There is no `vitest.config.*` and no `test` block in `vite.config.ts`. `jsdom` and `@testing-library/*` are installed but unused. All tests are pure-logic tests in `src/lib/__tests__/` and `src/lib/yarax/__tests__/`. To test components, add `test: { environment: 'jsdom' }` or a per-file `// @vitest-environment jsdom` comment.
- The Vite template assets are already gone. `src/assets/` does not exist.
- `index.css` defines a single dark palette in `:root`. There is no light theme or `prefers-color-scheme` switch.

## Current baseline
`tsc -b` passes and `npx vitest run` is green. `npx oxlint` reports 2 pre-existing `react/purity` warnings (`performance.now` in `App.tsx`'s `useMemo`); your change didn't cause them.

## Architecture

All state lives in `App.tsx` (`pattern`, `flags`, `input`, active tab). One `useMemo` derives everything else. There is no router, store or context.

**Flavors:** `App.tsx` holds `flavor` (`'javascript' | 'yarax'`) and separate state for each flavor. The JavaScript UI is rendered inline. Yara-X renders `components/yarax/YaraWorkbench`, which receives its state from `App` so that switching flavors keeps it.

**Yara-X engine** (`lib/yarax/engine.ts`): `loadEngine()` dynamically imports the official `@virustotal/yara-x` WebAssembly package, pinned exactly to `1.21.0`, and caches it. That is the only non-test import of the package, so it stays out of the main bundle. Vite rewrites the package's own `new URL('yara_x_js_bg.wasm', import.meta.url)` for dev and for the base-path build, so no Vite config is needed.
- `runYara` wraps the pattern as `rule t { strings: $a = /…/<is> <modifiers> condition: $a }`, scans the UTF-8 bytes, and returns byte offsets.
- `parseDiag` turns the engine's formatted error and warning text into structured diagnostics. Label columns map back into the pattern by subtracting the rule prefix (24 characters) after the 4-character gutter.
- After a panic, the thrown `Compiler` is poisoned, so never touch it again. A new one works, but each panic leaks wasm memory for good (about 18 MB for `(?u)\w`), and enough of them kill the engine until the page is reloaded. `knownCrash` therefore stops the known crashers (`\b{start-half}`, `\b{end-half}`, Unicode mode `(?u)`) before they reach the engine.
- `lib/yarax/bytes.ts` maps byte offsets to string indices for the highlighter.
- Tests load the engine with `initSync` and the `.wasm` from `node_modules`.

**Two independent regex systems that must agree:**
- `lib/explain.ts`: a hand-written recursive tokenizer used for syntax coloring, the explanation, and group labels. Group tokens carry `children`, re-offset to **absolute** positions in the full pattern. Quantifiers (`*`, `+`, `?`, `{n,m}`, lazy `?`) are folded into the preceding token's `text`/`end` and recorded in its `quantifier` field. They become a standalone `quantifier` token only when nothing quantifiable precedes them.
- `lib/matcher.ts`: runs the native `RegExp` via `matchAll`, always forcing `g` and truncating to one match when the user didn't set `g`. Capped at 10,000 matches. Group offsets come from `RegExpExecArray.indices`, so the matcher always adds the `d` flag internally (the UI doesn't expose it).
- The glue: `App.tsx` passes `extractGroupLabels(tokens).length` to `runRegex` as `groupCount`. So the tokenizer's count of capturing groups (`group-start` + `group-named`) limits how many groups the matcher reports. A tokenizer bug therefore shows up as missing or extra match columns.

**Explanation pane:** `flattenTokens` (depth-tagged, pre-order) → `describeToken` from `lib/describe.ts` for each token. Indentation comes from depth. `describeToken` recurses into group children to build the group's summary line. `flattenTokens(tokens, flags)` tags each row with the flags in scope. A modifier group such as `(?i-ms:...)` is a `group-non` token, and `scopedFlags` applies its on/off letters to its children, so pass `ft.flags`, not the global flags, to `describeToken`.

**Highlighting overlay** (`components/CodeArea.tsx` + `Highlighter.tsx`): a transparent `<textarea>` sits on top of a `Highlighter` div that renders colored spans via `dangerouslySetInnerHTML`. Scroll position is synced by hand in `onScroll`. Both layers must keep identical font and metrics in CSS (`.codearea-ta, .codearea-hl`). `buildHtml` resolves overlapping spans per character, with the **shortest span winning** and ties going to the later span (so a group that covers the whole match still shows its color). This is how group highlights appear over the whole-match highlight. HTML is escaped there; keep it that way when you change rendering.

**Class/color tables that must stay in sync:**
- `TOKEN_CLASS` in `App.tsx` ↔ `.tok-*` rules in `index.css`. Adding a `TokenType` means updating both, plus `QUANTIFIABLE` in `explain.ts` if it applies, and `baseAtom`/`describeToken` in `describe.ts`.
- `GROUP_COLORS` in `lib/colors.ts` (match-table swatches) ↔ `--g0`…`--g7` and `.hl-g0`…`.hl-g7` in `index.css` (input highlights). Both cycle modulo 8.

`lib/tokens.ts` is only the static content of the sidebar "Token Reference". It is not used by the tokenizer.
