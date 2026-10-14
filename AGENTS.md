# AGENTS.md — regex101clone

## Stack
- Vite 8, React 19, TypeScript 6 (strict)
- Oxlint for linting; Vitest + jsdom for tests
- No Tailwind or CSS framework — plain CSS only

## Commands
| Step | Command |
|---|---|
| Dev server | `npm run dev` |
| Typecheck | `tsc -b` |
| Lint | `npx oxlint` |
| Test | `npx vitest run` |
| Build | `npm run build` |

Run in order before committing: **typecheck → lint → test**.

## Source layout
- `src/lib/` — pure logic (regex engine, tokenizer)
- `src/components/` — React components
- `src/index.css` — global styles + dark-mode tokens
- No other entry point besides `vite.config.ts`

## Gotchas
- Vitest uses jsdom environment by default — SSR/fetch APIs will break; add `@vitest/vite-server` or switch env if needed.
- The Vite template ships assets (`hero.png`, react.svg, vite.svg) that are **unused** in this project — safe to delete.
