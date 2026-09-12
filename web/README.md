# Throughline web UI

React + TypeScript + Vite front end for the Throughline security context graph (see `docs/05-api-contract.md`
for every endpoint it consumes and `docs/01-product-definition.md` section 8 for the UI concept).

Wiz-like dark theme: left navigation rail (Dashboard, Alerts, Storylines, Graph Explorer, Threat Intel), a top bar
with global search (grouped hits, Enter opens the node in the explorer) and a persistent right-side **Analyst** drawer
that streams answers over SSE and draws its evidence on whichever graph canvas is visible.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server on http://localhost:5173 with `/api` proxied to `http://127.0.0.1:8000`. If `/api/v1/health` is unreachable the UI falls back to the in-browser mock adapter automatically (badge "Mock data" in the top bar). |
| `VITE_MOCK=1 npm run dev` | Force the mock adapter (no backend needed). `?mock=1` / `?mock=0` on any URL toggles it per browser session. |
| `npm run build` | `tsc -b && vite build` -> `dist/`, which FastAPI serves at `/` with an SPA fallback (`throughline/api/app.py`). |
| `npm run preview` | Serve `dist/` on http://localhost:4173 (API calls still need the backend or `?mock=1`). |
| `npm run lint` | oxlint (`npx oxlint src` must be clean). |
| `node scripts/screenshot.mjs` | Starts a mock-backed dev server on :5199, captures the demo screens with Playwright into `../docs/screenshots/mock-*.png` (1440x900) and exits. `SCREENSHOT_BASE=http://127.0.0.1:8000` captures a running server instead; `SCREENSHOT_PREFIX=` changes the file prefix. |

Node 22 / npm. Playwright's Chromium is expected under `/opt/pw-browsers` (`PLAYWRIGHT_BROWSERS_PATH`); do not run `playwright install`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `VITE_MOCK` | unset | `1` builds/serves against the mock adapter only (`src/api/mock`). Production builds default to the real API. |
| `SCREENSHOT_OUT` | `../docs/screenshots` | Output directory for `scripts/screenshot.mjs`. |
| `SCREENSHOT_PORT` | `5199` | Port of the temporary dev server started by the screenshot script. |
| `SCREENSHOT_BASE` | unset | Capture an already running UI instead of starting one. |
| `SCREENSHOT_PREFIX` | `mock-` | File-name prefix for captured screenshots. |

The API base is `/api/v1` (relative), so the same bundle works behind FastAPI and behind the Vite proxy.

## Routes

| URL | Screen |
|---|---|
| `/` | Dashboard: KPI tiles, "the #1 alert was a vendor Medium" callout, contextual vs vendor leaderboards, storyline cards, alerts by band/source, TI pressure, coverage. |
| `/alerts` | Alerts table with server-side sort (`?sort=contextual|vendor|time&order=`), filters in the URL (`q, band, severity, source, storyline, rcj=1, oap=1`), pagination (`offset, limit`). |
| `/alerts/:id?tab=flat|graph` | Flat view (raw vendor fields) vs Graph context (evidence canvas honouring `layout_hint`, score breakdown, attack paths, storyline timeline, insights, blast radius, TI, related alerts). |
| `/storylines`, `/storylines/:id` | Storyline cards; detail with dagre kill-chain canvas, stage strip, timeline, member alerts, crown jewels and the containment simulator (`POST /investigate/containment`). |
| `/explorer?id=<node id>` | Graph explorer: seed search, label/edge filters, path finder, blast radius (depth slider), attack paths, read-only Cypher with example queries. `?seed=` is accepted as an alias. |
| `/threat-intel?tab=actors|reports|exposure` | Actor table -> `/threat-intel/actors/:id` (campaigns, malware, techniques, indicators, reports, matched alerts, affected-assets canvas); `/threat-intel/campaigns/:id`; reports -> `/threat-intel/reports/:id`; Exposure = demo question 5 with the sector-only toggle. |

Test ids used by the screenshot scripts: `data-testid="analyst-toggle"` (top bar) and `data-testid="analyst-input"` (drawer textarea; Enter sends).

## Structure

```
src/
  api/          client.ts (typed fetch, transport selection, SSE), types.ts (mirror of throughline/models.py), hooks.ts (TanStack Query), sse.ts
  api/mock/     in-memory fixture graph and handlers for every endpoint (VITE_MOCK=1 / dev fallback); fixtures follow docs/04-storyline.md ids
  components/   shared UI: chips, tables, panels, storyline card/timeline, attack-path list, containment form/result, node details, analyst drawer
  graph/        Cytoscape wrapper (GraphCanvas: setFragment / mergeFragment / highlight / focus / layout), styles, per-label SVG icons, layouts
                (dagre LR for compact paths, fcose with the attack path pinned left-to-right for large storyline fragments), viewport helpers,
                canvas host registration (highlight bus), canvas ops, context-menu actions, legend
  screens/      Dashboard, Alerts, AlertDetail, Storylines, StorylineDetail, Explorer, ThreatIntel (+ per-screen sub-components in folders)
  store/        zustand: canvasStore (evidence/highlight bus), drawerStore (chat session + streaming), selectionStore
  lib/          format helpers, URL search-param hooks
  theme.ts      colour constants shared with Cytoscape (kept in sync with index.css @theme)
scripts/screenshot.mjs   Playwright capture of the demo screens
```

## Conventions

- Every graph-returning endpoint yields a `GraphFragment`; canvases merge fragments (`mergeFragment`) rather than replacing them, so
  expand / blast radius / paths / analyst evidence accumulate on the same canvas. Highlighted elements get a bright ring, everything else dims to 30%.
- Layouts: `fcose` for neighborhoods and blast radius, `dagre` (left-to-right) for paths and storylines (`layout_hint`).
- Severity colours: critical red, high orange, medium amber, low blue, informational/noise grey. Category colours: cloud blue, identity violet,
  software teal, business slate, endpoint green, alerts by severity, threat intel magenta.
- Components stay under 300 lines; no `any` outside `src/api/mock`.
