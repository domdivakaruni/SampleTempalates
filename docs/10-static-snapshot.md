# Static Snapshot Edition (build contract)

Goal: a build of the web UI that runs with **no backend at all**, so the prototype can be shared as a static site
(private Claude artifact, GitHub Pages, any file host). Every screen shows real analytics: a Python exporter
precomputes the API payloads from the generated graph, the UI's transport layer gets a third mode (`snapshot`)
that answers requests from those JSON files, and the analyst drawer replays precomputed answers to the demo
questions and the contextual suggestions. Free-form questions, arbitrary Cypher and arbitrary containment inputs
are out of scope for the static edition and must degrade with a clear message, never an error page.

Two deliverables, built in parallel against this contract:

* `scripts/export_snapshot.py` (Python; Agent F) writes `web/snapshot-out/` from `data/generated` using
  `AnalyticsEngine`, the offline `Analyst`, `suggestions_for` and the `ContextGraph`.
* `web/src/api/snapshot/` (TypeScript; Agent G) implements the transport; `VITE_STATIC=1 npm run build` produces
  `web/dist-static/` with relative asset paths and hash routing; `scripts/build_static.sh` runs exporter + build +
  copies `web/snapshot-out/` into `web/dist-static/snapshot/`.

All paths the UI fetches are **relative** (`snapshot/...`, no leading slash) because the site may live under a
sub-path (GitHub Pages) or an artifact origin. JSON only; no file may exceed 15 MB; the whole `snapshot/` tree
should stay under 50 MB uncompressed (trim as described below). All payload shapes are exactly the API shapes in
docs/05-api-contract.md and `web/src/api/types.ts`; the exporter serialises pydantic models with
`model_dump(mode="json")`.

## 1. Files (`web/snapshot-out/`)

| File | Content |
|---|---|
| `manifest.json` | `{version: 1, generated_at, seed, node_count, edge_count, alert_count, shards: {alert_details: [file...], edges: [file...]}, notes: string}` |
| `meta.json` | `{health: HealthOut (backend "snapshot", agent_mode "offline", analyst_mode "precomputed"), stats: StatsOut (backend "snapshot", capabilities.cypher false), schema: SchemaOut (registry view from GET /schema incl. example_queries if available), dashboard: DashboardOut}` |
| `alerts.json` | `{items: AlertSummary[]}` every alert, in contextual order (the adapter re-sorts/filters/pages client-side exactly like the mock adapter's `alertsList`) |
| `alert_details/<NN>.json` | `{ "<alert id>": {alert: AlertSummary, flat_view: object, risk: RiskBreakdown, insights: Insight[], context?: AlertContext} }`; shard key = the first hex char(s) of sha1(alert id): one char by default (16 shards, so the whole tree stays under the artifact publisher's 255-file limit; `manifest.alert_shard_prefix_len` says which), two with `--alert-shard-chars 2`. `context` (the full `GET /alerts/{id}/context` payload) is included for: every storyline member, the top 400 alerts by contextual score, every alert in `ALERT_N`/`QUARANTINE_ALERT_IDS`, and every alert that is a `rerank_examples` entry; other alerts have no `context` key and the adapter synthesises a lite context (section 3). Evidence fragments inside contexts are capped at 150 nodes / 400 edges (the engine already does this) |
| `storylines.json` | `{items: StorylineOut[] (no fragment), details: { "<id>": StorylineOut (with fragment) }}` |
| `ti.json` | `{actors: ActorListOut, actor_details: {id: ActorDetailOut}, campaign_details: {id: object (GET /threat-intel/campaigns/{id})}, reports: ReportListOut, report_details: {id: ReportDetailOut}, exposure: {sector_only: ExposureOut, all: ExposureOut}, lookups: { "<lower-cased value>": TIContext } }` where lookups cover every storyline indicator value (hashes, IPs, domain, url), every CVE id with an EXPLOITS edge, every actor/campaign/report id and name (lower-cased), and the ATT&CK technique ids used by the two storylines |
| `investigate.json` | `{credential_joins: CredentialJoinsOut, alerts_reaching_crown_jewels: { "": default, "<jewel id>": ... for each crown-jewel bucket/database }, medium_alerts_with_data_path: { "medium|falcon": ..., "medium|": ..., "high|falcon": ..., "low|falcon": ... }, identity_footprint: { "<id>": BlastRadiusResult } for every IamRole/IamUser/HumanUser/Credential that is a storyline member or has is_admin/privilege_score >= 0.7 (cap 60), containment: [ {targets: string[], actions: string[], result: ContainmentSimulation} ] for: storyline A defaults ([EP_BASTION, BASTION_ROLE] x {[isolate_endpoint, rotate_role_credentials], [isolate_endpoint, rotate_role_credentials, tighten_trust_policy], [isolate_endpoint], [rotate_role_credentials]}), [EP_BASTION, BASTION_VM, BASTION_ROLE] with the same action sets, storyline B ([EP_EDGE, EDGE_ROLE] and [EP_EDGE, EDGE_VM, EDGE_ROLE] x the same sets), and the storyline B endpoint alone }` |
| `graph/nodes.json` | `{nodes: NodeOut[]}` for every node, with `props` trimmed to the typed columns of the label (drop `raw`, `score_breakdown`, `stages`, `statements`, `inbound_rules`, `body`, `description` longer than 200 chars) |
| `graph/edges-<NN>.json` | `{edges: [ [src, type, dst, derived(0|1), confidence] ]}` compact arrays, sharded by 40,000 edges per file |
| `graph/blast_radius.json` | `{ "<root id>": BlastRadiusResult }` (fragment capped at 100 nodes) for: every alert that has a `context`, its anchor endpoint/VM, every storyline member node, every crown jewel's top 3 principals, and the identities in `identity_footprint` |
| `graph/attack_paths.json` | `{ "<through id>": AttackPathsOut }` for every storyline member alert and anchor, plus the entries `"internet->{crown jewel id}"` (entry Internet, target jewel) for the five named crown jewels |
| `node_cards.json` | `{ "<id>": NodeDetailOut }` (GET /nodes/{id} payload) for the storyline member nodes, all crown jewels, all actors/campaigns/reports/malware, the roles/buckets/secrets/database in the storyline, the eight scripted exposed hosts and their endpoints, and every node referenced by the `rerank_examples` alerts (cap 400) |
| `search.json` | `{entries: [ [id, label, name, category, snippet|"" , extra_tokens: string] ]}` for every node; `extra_tokens` is a space-joined string of hostname, IPs, hashes, values, emails, CVE ids, technique ids (lower-cased) so the adapter can do prefix/substring search |
| `chat.json` | `{suggestions: { "<context key>": string[] }, answers: [ {question, normalized, context_key, answer: AnalystAnswer} ]}` — see section 2 |

Context key format: `""` (global), `alert:<alert id>`, `node:<node id>`, `storyline:<storyline id>`.

## 2. Precomputed chat

Use `throughline.agent.prompts.suggestions_for(alert_id=..., node_id=..., storyline_id=...)` for suggestions and the
offline `Analyst.answer(question, context=..., mode="offline")` for answers. Precompute:

1. Global: the 12 demo questions plus `suggestions_for()` with no context, answered with `context={}`.
2. Per alert (context `{"alert_id": id}`), for the top 60 alerts by contextual score plus every storyline member and the named noise alerts: each suggestion question, plus the two generic phrasings "Why is this alert risky?" and "What can an attacker reach from this alert?".
3. Per storyline (context `{"storyline_id": id}`): each suggestion plus "Summarize this storyline" and "If we contain this storyline now, what breaks?".
4. Per node (context `{"selected_node_ids": [id]}`) for the storyline member nodes, crown jewels, the eight exposed hosts, the actors: each suggestion plus "What is this?" and "What is connected to this node?".

Normalisation for matching (both sides): lower-case, strip punctuation except `:/.-`, collapse whitespace. Cap the
answers list at 320 entries (drop node-level answers first), and cap each answer's `evidence` fragment at 120
nodes / 300 edges (keep highlighted nodes first). The adapter matches a typed question by exact normalised
string, then by highest Jaccard token overlap >= 0.55 within the same context key, then within the global key;
otherwise it streams a fallback answer (section 3).

## 3. Adapter behaviour (`web/src/api/snapshot/`)

* Mode selection in `client.ts`: `VITE_STATIC=1` at build time selects `snapshot` (also `?snapshot=1` for dev
  testing); the header badge reads "Static edition" (the mock badge reads "Mock data"). `import.meta.env.VITE_STATIC`
  also switches `App.tsx` to `HashRouter` and `vite.config.ts` to `base: './'` (and `outDir: 'dist-static'`).
* Lazy loading with an in-memory cache: `meta.json`, `alerts.json`, `storylines.json`, `ti.json`, `investigate.json`,
  `chat.json` on first use of the relevant endpoint; `graph/nodes.json`, `graph/edges-*.json`, `search.json` only when
  the explorer, search or an expansion needs them; `alert_details/<shard>` per alert.
* Endpoints: mirror the mock adapter's route table (`web/src/api/mock/index.ts`) exactly, serving snapshot payloads:
  `/alerts` (client-side filter/sort/page over `alerts.json`), `/alerts/{id}` + `/context` + `/risk` + `/insights`,
  `/storylines[/{id}]`, `/threat-intel/*`, `/investigate/*` (key lookup; unknown keys return the closest default with
  `meta.note = "static edition: precomputed for the default parameters"` where the payload has a `meta`/fragment,
  otherwise the default), `/dashboard`, `/health`, `/stats`, `/schema`, `/search` (over `search.json`),
  `/nodes/{id}` (node_cards, else built from nodes + edges + alerts: degree, edge_type_counts, alerts by entity_id,
  threat_intel null), `/nodes/batch`, `/graph/neighborhood` (client-side k-hop BFS over the edge shards honouring
  depth, edge_types, labels, direction, max_nodes; fragment built from nodes.json), `/graph/paths` (BFS shortest
  paths, k up to 3), `/graph/blast-radius` (precomputed by root id, else a BFS approximation over the attack-graph
  edge types HAS_ROLE, CAN_ASSUME, CAN_ACCESS, UNLOCKS, SAME_AS, CREDENTIAL_FOR, DERIVED_FROM, LATERAL_MOVEMENT_TO,
  MAPS_TO with `summary` prefixed "Approximate (static edition):"), `/graph/attack-paths` (precomputed by
  `through` or `internet->target`, else `{paths: [], fragment: empty}` with `meta.note`), `/graph/cypher` (501
  `not_supported`: "The static edition has no query engine; run the container to use Cypher."), chat sessions in
  memory, `streamChat` replaying the precomputed answer as events (`session`, then one `tool_call` + `tool_result`
  per recorded `tool_calls` entry with a 120 ms pace, `evidence`, `text_delta` chunks of the narrative, `answer`,
  `done`), `/chat/suggestions` from `chat.json`.
* Fallback answer for unmatched questions: `mode: "offline"`, `intent: "help"`, narrative explaining that the static
  edition answers the prepared questions, listing the 12 demo questions and the current context's suggestions as
  follow-ups; `evidence` empty; `confidence` 0.
* Errors follow the API envelope (`ApiError`), never throw raw.

## 4. Build and verification

`scripts/build_static.sh`:
1. `.venv/bin/python scripts/export_snapshot.py --out web/snapshot-out` (requires `data/generated`; builds it when missing),
2. `cd web && VITE_STATIC=1 npm run build` -> `web/dist-static/`,
3. `rm -rf web/dist-static/snapshot && cp -r web/snapshot-out web/dist-static/snapshot`,
4. prints the total size and file count of `web/dist-static`.

Verification: `python -m http.server` on `web/dist-static` and a Playwright pass over `#/`, `#/alerts`,
`#/alerts/alert:falcon:ldt-a009?tab=graph`, `#/storylines/storyline:derived:embercast-larkspur`,
`#/explorer?id=endpoint:falcon:aid-bas01`, `#/threat-intel?tab=exposure`, and an analyst question, with zero page
errors and zero failed requests.

## 5. Result (first build, 2026-09-12)

| Item | Value |
|---|---|
| Export (`scripts/export_snapshot.py`, real API in-process over the NetworkX store) | 59 s; 32 data files, 59.4 MB |
| Static site (`web/dist-static`) | 40 files, 59 MB; web bundle 1.4 MB (snapshot transport is a 25 KB lazy chunk) |
| Alerts | 1,666 summaries, 57 with the full API context (13 storyline members, the named noise and quarantine alerts, the rerank examples, and the top 39 by contextual score); the rest open with the lite context |
| Analyst answers | 122 (12 global demo questions, 8 storyline, 102 alert-level = 6 for each storyline and named-noise alert); 264 suggestion contexts |
| Graph | `graph/nodes.json` 11.2 MB with typed props, three edge shards (7.4 MB), 178 blast-radius roots, 23 attack-path keys (13 storyline alerts, anchors, 5 `internet->jewel`), 204 node cards, 229 TI lookups, 60 identity footprints, 17 containment simulations |
| Trim ladder that fired | typed props only (153 MB) -> blank props on fragment nodes inside analytics payloads (125 MB) -> node-level chat answers dropped (122 MB) -> top contexts reduced from 400 to 39 (59.4 MB) |
| Verification | `web/scripts/check-snapshot-routes.mjs` (60+ routes through the real adapter, no browser) and `web/scripts/check-static.mjs` (Playwright: routes, badge, replayed answer, fallback answer, zero page errors / failed requests) both pass; `tests/unit/test_export_snapshot.py` checks shapes, sharding and coverage in 29 s |

Decisions taken at integration time:

- **Budget 60 MB instead of 50 MB.** The mandatory coverage alone (all alert details, the node table, the edges, the
  crown-jewel tables and identity footprints, TI, search) is about 51 MB after every shape-preserving trim, and the
  artifact publisher's ceiling is 64 MB per version, so the fit budget is 60 MB and the exporter reports both numbers
  in `manifest.budget`.
- **16 alert-detail shards by default** (`--alert-shard-chars 1`): 256 shards put the tree over the publisher's
  255-files-per-publish limit; 16 shards of 0.5-1 MB are also fewer requests for the browser.
- **U+FFFD escaped in the static bundle.** micromark emits a literal replacement character inside a template
  literal and the publisher rejects files containing it; a `generateBundle` hook in `web/vite.config.ts` rewrites
  it to the `\uFFFD` escape after minification (a `renderChunk` rewrite is folded back by the minifier).
- **Props blanked on fragment nodes** inside analytics payloads is invisible to the UI: the node details panel reads
  from `node_cards.json`, and the adapter re-hydrates fragment props from the cards or the loaded graph when present.

Published: the private Claude artifact (shared from its share menu) and GitHub Pages at
<https://domdivakaruni.github.io/SampleTempalates/> (the `pages` workflow, on every push).
