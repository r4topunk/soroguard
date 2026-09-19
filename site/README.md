# soroguard site

TL;DR: the soroguard landing page. Vite + React + TypeScript, deployed on Vercel. The only external resource is Google Fonts.

```sh
pnpm install
pnpm dev        # local dev server (http://localhost:5173)
pnpm build      # tsc (strict) + vite build -> dist/
pnpm preview    # serve dist/ (http://localhost:4173)
```

`?lang=en` opens the English version. PT is the default, and the PT/EN toggle stays in the top bar.

## Vercel

| Setting | Value |
|---|---|
| Root Directory | `site` |
| Framework Preset | Vite |
| Build Command | `pnpm build` (default) |
| Output Directory | `dist` |

No `vercel.json` is needed. This folder is its own pnpm project (not a workspace), and it is kept out of the npm package by the root `package.json` `files` whitelist.

## Domain and social preview

The site URL lives in one place: `site/.env` → `VITE_SITE_URL=https://soroguard.r4to.com` (no trailing slash). At build time Vite substitutes `%VITE_SITE_URL%` in `index.html`, which sets `og:url`, `og:image` and `twitter:image`. To change the domain, edit that line. You can also set `VITE_SITE_URL` in the Vercel project's environment variables, which overrides `.env` for that environment (e.g. previews). Check with `grep og:image dist/index.html` after `pnpm build`.

The share image is `public/og.png` (1200×630, English). It is generated from `og/og.html`. `og/` is not part of the build; only `public/og.png` ships.

```sh
pnpm og   # re-render public/og.png with the cached Playwright Chromium (needs network for Google Fonts)
```

`og/render.mjs` looks for the newest Chromium under the Playwright cache. Set `CHROMIUM_PATH` to use another browser. If the web fonts fail to load, the script refuses to render rather than fall back to system fonts.

## Layout

- `src/strings.ts`: all PT/EN copy.
- `src/model.ts`: `computeVals(state)`. Derives everything the sections render: explorer data, evidence tiers, the threat → monitor mapping, install tabs.
- `src/sections/*.tsx`: one component per page section.
- `src/styles.css`: the page CSS (plain CSS, breakpoints at 960px and 1180px).
- `src/sx.ts`: converts the inline style strings produced by `model.ts` into React style objects.

Every claim on the page must trace to the repository `README.md` or `docs/`. The page only shows the escrow contract `CDZZ5HUO…742T5`.
