# regex101clone

A regex101-style regular expression tester for the JavaScript regex flavor. Type a pattern and some test text, and you get:

- matches and capture groups highlighted live in the text,
- a match table with one column per capture group,
- a plain-English explanation of the pattern,
- a token cheat sheet.

Everything runs in the browser with the native `RegExp` engine. There is no backend, so the production build is a static site you can host anywhere.

Built with React 19, Vite 8 and TypeScript 6.

## Requirements

- **Node.js 22.12 or newer.** Node 24 LTS is recommended, and the project is tested on it. Vitest needs at least 22.12. Vite alone accepts 20.19, but you can't run the tests on that.
- **npm**, which ships with Node.

Check your version with `node -v`. If you use a version manager, run `nvm install 24 && nvm use 24`, or the `fnm`/`volta` equivalent.

## Run it locally

```bash
npm ci        # install exact versions from package-lock.json
npm run dev   # start the dev server with hot reload
```

Open the URL Vite prints, usually <http://localhost:5173>. Edits under `src/` reload instantly.

To try the production build locally:

```bash
npm run build     # type-check, then bundle into dist/
npm run preview   # serve dist/ at http://localhost:4173
```

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Dev server with hot module reload |
| `npm run build` | Type-checks (`tsc -b`), then builds the static site into `dist/` |
| `npm run preview` | Serves the built `dist/` locally to check the production build |
| `npm test` | Runs the unit tests once (Vitest) |
| `npm run lint` | Lints with Oxlint |
| `npx tsc -b` | Type-checks only, without building |

Run single tests with `npx vitest run src/lib/__tests__/matcher.test.ts` or `npx vitest run -t "captures group values"`.

Before committing, run **typecheck → lint → test**:

```bash
npx tsc -b && npm run lint && npm test
```

Lint reports 2 existing `react(purity)` warnings in `src/App.tsx`. They are known and don't block a commit. New warnings should be fixed.

## Deploy

`npm run build` writes a self-contained static site to `dist/`: an `index.html`, a favicon, and hashed JS and CSS files under `assets/`. It's about 250 KB, or 75 KB gzipped. Upload that folder to any static host. You don't need a server runtime, environment variables, or SPA rewrite rules, because the app is a single page with no client-side routes.

### Base path

By default, asset URLs are absolute from the site root (`/assets/...`). That works when the app is served at the root of a domain, like `https://regex.example.com/`.

If you serve it from a subpath, like `https://<user>.github.io/RegexDebugger/`, pass the path at build time. Keep the leading and trailing slashes:

```bash
npm run build -- --base=/RegexDebugger/
```

To make it permanent, set `base: '/RegexDebugger/'` in `vite.config.ts` instead. Without the right base, the page loads blank and the browser console shows 404s for `/assets/*.js`.

### Netlify, Vercel or Cloudflare Pages

Connect the Git repository and use these settings. All three detect Vite, so the preset usually fills them in.

| Setting | Value |
|---|---|
| Build command | `npm run build` |
| Output / publish directory | `dist` |
| Node version | 22.12+ (24 recommended), set in the host's project settings |

Every push to the production branch then deploys, and pull requests get preview URLs.

### GitHub Pages

1. Push the repository to GitHub.
2. Go to **Settings → Pages → Build and deployment → Source** and select **GitHub Actions**.
3. Add `.github/workflows/deploy.yml`. It builds with the repository name as the base path, as a project site needs:

   ```yaml
   name: Deploy to GitHub Pages

   on:
     push:
       branches: ['main']
     workflow_dispatch:

   permissions:
     contents: read
     pages: write
     id-token: write

   concurrency:
     group: 'pages'
     cancel-in-progress: true

   jobs:
     deploy:
       environment:
         name: github-pages
         url: ${{ steps.deployment.outputs.page_url }}
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v7
         - uses: actions/setup-node@v7
           with:
             node-version: 24
             cache: 'npm'
         - run: npm ci
         - run: npm test
         - run: npm run build -- --base=/${{ github.event.repository.name }}/
         - uses: actions/configure-pages@v6
         - uses: actions/upload-pages-artifact@v5
           with:
             path: './dist'
         - id: deployment
           uses: actions/deploy-pages@v5
   ```

4. Push to `main`. The site is published at `https://<user>.github.io/<repo>/`. For a custom domain or a `<user>.github.io` repository, drop the `--base` flag.

### Your own server (nginx, Apache, S3, …)

Copy the contents of `dist/` to the web root. For caching, files under `assets/` have content hashes in their names, so they can be cached for a long time (`Cache-Control: public, max-age=31536000, immutable`). Serve `index.html` with `no-cache`, so visitors pick up new deploys.

## Browser support

The app targets current evergreen browsers. The UI uses CSS `color-mix()`. Regex features are whatever the visitor's browser engine supports: newer syntax such as modifier groups (`(?i:...)`) shows a syntax error in browsers that don't support it yet.

## Project layout

- `src/lib/`: pure logic, with unit tests in `src/lib/__tests__/`:
  - the tokenizer and explainer (`explain.ts`, `describe.ts`)
  - the matcher (`matcher.ts`)
  - colors and cheat-sheet data
- `src/components/`: React components. All app state lives in `src/App.tsx`.
- `src/index.css`: global styles, a single dark theme.

See `CLAUDE.md` and `AGENTS.md` for architecture notes and contributor conventions.
