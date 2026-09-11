# Build Plan, Module Ownership and Interfaces (build contract)

Read first: 01-product-definition.md (what and why), 02-architecture.md (decisions), 03-graph-schema.md (data model),
04-storyline.md (ground truth), 05-api-contract.md (API and tools). This document says who builds what, the exact
Python interfaces between components, and how the pieces are integrated and tested.

## 1. Repository layout

```
throughline/                 Python package (installed with `pip install -e .`)
  config.py                  Settings (env vars; see 02 section 9)                       [written]
  models.py                  Shared pydantic models                                      [written]
  schema/registry.py         Labels, edge types, typed columns, pairs, validation        [written]
  simulator/
    common.py                rng(namespace), NOW, ts(), node(), edge(), write_jsonl()    [written]
    storyline_constants.py   Canonical ids/values for the storylines                     [written]
    catalog/cves.py          60 CVEs (real + synthetic) with components                  [written]
    catalog/techniques.py    ATT&CK techniques with tactics and kill-chain stages        [written]
    inventory/               Agent A1: world, cloud, identity, business, endpoints, vulns, posture derivations, CSPM issues
    events/                  Agent A2: EDR detections/processes/files/logons/network, cloud audit events, WAF/IDS/Okta alerts, storyline overlay, noise
    threat_intel/            Agent A3: actors, campaigns, malware, indicators, reports, EXPLOITS, vulnerability TI overlay
    build.py                 Pipeline: inventory -> threat intel -> events -> merge -> validate -> analytics.enrich -> write graph -> load DB  [integration]
  graph/
    context_graph.py         NetworkX projection                                         [written]
    store.py                 GraphStore protocol, CypherResult, exceptions                Agent B
    cypher_gate.py           read-only Cypher statement gate                             Agent B
    ladybug_store.py         LadybugDB / Kuzu embedded store (one engine per process)     Agent B
    networkx_store.py        GraphStore over ContextGraph (no Cypher)                    Agent B
    neo4j_store.py           Bolt store (not exercised in CI; conformance tests skip)    Agent B
    loader.py                load_context_graph(), build_embedded_db(), export helpers   Agent B
    factory.py               make_store(settings, graph) -> GraphStore                   Agent B
  analytics/
    semantics.py             attack-graph edge semantics, crown-jewel predicate, source-of-label map   Agent C
    weights.yaml             scoring weights and rails                                    Agent C
    scoring.py, paths.py, blast.py, ti.py, correlation.py, insights.py, containment.py, questions.py  Agent C
    materialize.py           enrich(graph) build-time enrichment                           Agent C
    engine.py                AnalyticsEngine facade (section 3.2)                          Agent C
  agent/
    tools.py                 ToolRegistry: typed tools over AnalyticsEngine + GraphStore   Agent D
    llm.py                   Claude tool-use streaming loop                                Agent D
    offline.py               intent -> playbook -> templated AnalystAnswer                 Agent D
    prompts.py               system prompt, tool descriptions, playbook hints              Agent D
    session.py               in-memory chat sessions                                       Agent D
  api/
    app.py                   FastAPI app factory, lifespan (load graph, store, engine, agent), static UI  Agent D
    routers/                 meta, alerts, graph, threat_intel, investigate, chat, agent   Agent D
    errors.py                error envelope                                                Agent D
  cli.py                     `throughline build-data | serve | ask "<question>" | demo`     [integration]
web/                         Vite + React + TypeScript UI                                  Agent E
scripts/                     build_data.py, serve.py, demo_questions.py, screenshots.py    [integration]
tests/unit, tests/conformance, tests/scenarios, tests/api                                  each agent + integration
data/generated/              gitignored build output; data/fixtures/ small committed fixtures
Makefile, README.md, .env.example
```

Conventions: Python 3.11, type hints everywhere, pydantic v2, `ruff` clean (line length 110), no `print` in library
code (use `logging`), deterministic outputs (no wall-clock time in generated data; use `simulator.common.NOW`),
tests under `tests/` runnable with `pytest -q` from the repo root, and **never import `kuzu` and `ladybug` in the
same process**. Agents work only inside their own directories plus their tests; shared modules
(`models.py`, `schema/registry.py`, `context_graph.py`, `common.py`, `storyline_constants.py`, catalogs) may be
extended (add, do not change or remove) with a note in the final report.

## 2. Data pipeline interfaces (Agents A1, A2, A3)

Each simulator stage is a module exposing `generate(out_dir: Path) -> GenerateResult` where
`GenerateResult = {"nodes": Path, "edges": Path, "raw": [Path...], "counts": {...}}`. Stages write:

| Stage | Reads | Writes |
|---|---|---|
| `inventory.generate(out)` | catalogs, constants | `out/graph/inventory_nodes.jsonl`, `out/graph/inventory_edges.jsonl`, raw feeds under `out/raw/wiz/*.jsonl`, `out/raw/falcon/devices.jsonl`, `out/raw/okta/users.jsonl`, `out/raw/business/*.jsonl`; plus `out/inventory.json` (compact index: vms, endpoints, users, roles, buckets, secrets, databases, apps, teams; see 2.1) |
| `threat_intel.generate(out)` | catalogs, constants | `out/graph/ti_nodes.jsonl`, `out/graph/ti_edges.jsonl`, raw under `out/raw/ti/*` |
| `events.generate(out)` | `out/inventory.json` (must exist), catalogs, constants | `out/graph/events_nodes.jsonl`, `out/graph/events_edges.jsonl`, raw under `out/raw/falcon/*.jsonl`, `out/raw/cloudtrail/events.jsonl`, `out/raw/waf/alerts.jsonl`, `out/raw/ids/alerts.jsonl`, `out/raw/okta/alerts.jsonl` |

Node/edge JSON lines follow 03 section 2 exactly. Node records must pass `schema.validate_node`; every edge must
reference ids that exist after the merge (events may reference inventory and TI ids; TI may reference
`cve:` ids from the CVE catalog and nothing else outside its own output; inventory references only itself and
`cve:` ids). The merge step (`build.py`) concatenates the three node files (ids must be globally unique across
stages; a duplicate id is an error) and the three edge files, validates pairs with `schema.validate_edge`, builds a
`ContextGraph`, runs `analytics.materialize.enrich(graph)`, then writes `out/graph/nodes.jsonl`, `edges.jsonl`,
`manifest.json`.

### 2.1 `inventory.json` (consumed by the events stage)
```json
{"vms": [{"id": "vm:aws:i-...", "name": "bas-01", "hostname": "...", "private_ip": "...", "public_ip": null, "os": "...", "os_family": "linux",
          "account_id": "222222222222", "environment": "prod", "exposure": "internal", "has_edr_sensor": true, "endpoint_id": "endpoint:falcon:aid-...", "role_ids": ["role:aws:..."], "app_id": "app:larkspur:..."}],
 "endpoints": [{"id": "endpoint:falcon:aid-...", "hostname": "WKS-3391", "device_type": "workstation", "os_family": "windows", "private_ip": "10.40.12.77", "primary_user_id": "user:okta:dwhitfield", "vm_id": null, "site": "Boston office"}],
 "users": [{"id": "user:okta:dwhitfield", "login": "dwhitfield", "display_name": "Dana Whitfield", "title": "...", "department": "Finance", "team_id": "team:larkspur:finance-treasury", "is_privileged": false, "is_executive": false, "endpoint_id": "endpoint:falcon:aid-wks3391", "location": "Boston"}],
 "roles": [{"id": "role:aws:...", "name": "...", "account_id": "...", "arn": "...", "role_type": "instance", "attached_vm_ids": [...]}],
 "buckets": [{"id": "bucket:aws:...", "name": "...", "account_id": "...", "sensitivity": "critical", "crown_jewel": true, "public": false}],
 "secrets": [...], "databases": [...], "apps": [...], "teams": [...], "service_accounts": [...],
 "storyline": {"bastion_vm": "vm:aws:i-0b4571e2c9a8f3d01", "...": "every named id from storyline_constants that inventory created"}}
```

## 3. Graph and analytics interfaces (Agents B, C)

### 3.1 `throughline/graph/store.py`
```python
class CypherResult(BaseModel): columns: list[str]; rows: list[list[Any]]; elapsed_ms: int; truncated: bool
class NotSupported(Exception) ...; class QueryRejected(Exception) ...; class QueryTimeout(Exception) ...

class GraphStore(Protocol):
    name: str
    def capabilities(self) -> dict[str, Any]: ...            # {"cypher": bool, "multi_label_patterns": bool, "shortest_path": bool, "read_only": bool}
    def build(self, nodes_path: Path, edges_path: Path, manifest: dict) -> None: ...   # (re)create the database from canonical files
    def open(self) -> None: ...; def close(self) -> None: ...
    def get_node(self, node_id: str) -> dict | None: ...                # record dict as in nodes.jsonl (props flattened not required)
    def get_nodes(self, ids: Sequence[str]) -> list[dict]: ...
    def search(self, text: str, labels: Sequence[str] | None = None, limit: int = 25) -> list[SearchHit]: ...
    def neighborhood(self, node_id: str, depth: int = 1, edge_types: Sequence[str] | None = None, direction: str = "both", labels: Sequence[str] | None = None, max_nodes: int = 150) -> GraphFragment: ...
    def run_readonly_cypher(self, query: str, params: dict | None = None, row_limit: int = 200, timeout_ms: int = 3000) -> CypherResult: ...
    def stats(self) -> StatsOut: ...
    def schema_summary(self) -> dict[str, Any]: ...
```
`factory.make_store(settings, graph: ContextGraph) -> GraphStore` picks the backend; the NetworkX store wraps the
already-loaded `ContextGraph` so every backend works without a database file. `loader.load_context_graph(data_dir)`
returns the `ContextGraph`; `loader.build_embedded_db(store, data_dir)` builds `graph.lbdb` from the JSONL files
(skips the rebuild when `manifest.json.checksum` matches the one stored in the database directory).

### 3.2 `throughline/analytics/engine.py`
```python
class AnalyticsEngine:
    def __init__(self, graph: ContextGraph) -> None: ...
    # alerts
    def list_alerts(self, *, sort: str = "contextual", order: str = "desc", band=None, severity=None, source=None, storyline_id=None,
                    reaches_crown_jewel=None, on_attack_path=None, q=None, limit: int = 50, offset: int = 0) -> tuple[list[AlertSummary], int]: ...
    def alert_summary(self, alert_id: str) -> AlertSummary: ...
    def flat_view(self, alert_id: str) -> dict: ...
    def risk_breakdown(self, alert_id: str) -> RiskBreakdown: ...
    def insights(self, alert_id: str) -> list[Insight]: ...
    def alert_context(self, alert_id: str) -> AlertContext: ...
    # graph analytics
    def blast_radius(self, root_id: str, depth: int = 4, max_nodes: int = 500) -> BlastRadiusResult: ...
    def attack_paths(self, through_id: str | None = None, target_id: str | None = None, entry_id: str | None = None, k: int = 5) -> list[AttackPathOut]: ...
    def find_paths(self, src_id: str, dst_id: str, max_hops: int = 6, k: int = 3, edge_types=None) -> GraphFragment: ...
    def neighborhood(self, node_id: str, depth: int = 1, edge_types=None, direction: str = "both", labels=None, max_nodes: int = 150) -> GraphFragment: ...
    def node_card(self, node_id: str) -> dict: ...                                   # per 05 GET /nodes/{id}
    # storylines & TI
    def list_storylines(self) -> list[StorylineOut]: ...
    def storyline(self, storyline_id: str, with_fragment: bool = True) -> StorylineOut: ...
    def threat_intel_context(self, node_or_alert_id: str) -> TIContext: ...
    def ti_lookup(self, value: str) -> TIContext: ...
    def ti_actors(self) -> list[dict]: ...; def ti_actor(self, actor_id: str) -> dict: ...; def ti_campaign(self, campaign_id: str) -> dict: ...
    def ti_reports(self) -> list[NodeOut]: ...; def ti_report(self, report_id: str) -> dict: ...
    def ti_exposure(self, sector_only: bool = True) -> list[dict]: ...              # question 5
    # typed investigations
    def credential_joins(self) -> dict: ...                                          # question 8
    def alerts_reaching_crown_jewels(self, jewel_id: str | None = None, classification: str | None = None) -> dict: ...  # question 10
    def medium_alerts_with_data_path(self, severity: str = "medium", source: str | None = "falcon") -> dict: ...          # question 2
    def identity_footprint(self, identity_id: str) -> BlastRadiusResult: ...       # question 4
    def simulate_containment(self, target_ids: list[str], actions: list[str]) -> ContainmentSimulation: ...  # question 12
    def dashboard(self) -> dict: ...                                                 # per 05 section 1.1
```
`materialize.enrich(graph: ContextGraph) -> dict` (report of what was added) runs at build time and must be
idempotent. It adds: `MATCHES_IOC` edges; `ATTRIBUTED_TO` from alerts to campaigns/actors; vulnerability TI overlay
props (`exploitation_status`, `actor_interest`, `sector_targeting_relevance`, `ti_report_ids`) and
`ti_exposure_score` on internet-exposed assets; `LATERAL_MOVEMENT_TO`; `Storyline` nodes with `IN_STORYLINE` and
`NEXT_STAGE`; per-alert `contextual_score`, `contextual_band`, `score_breakdown`, `graph_reasons`, `storyline_id`,
`reaches_crown_jewel`, `on_attack_path`, `ioc_match_count`, `ti_actor_ids`; per-VM `crown_jewel_reach`.

Scoring (from 01 section 5.2; weights in `weights.yaml`): factors S (vendor severity), E (exposure), P (privilege
reach), D (data sensitivity reachable), T (threat-intel relevance), C (incident/storyline correlation), all 0..1.
`context = 0.15E + 0.20P + 0.25D + 0.20T + 0.20C`; `raw = 100 * (0.30S + 0.70 context)`; rails: attack-path floor
90 when the alert is on a storyline that reaches a crown jewel; TI booster floor 80 when `exploitation_status` in
{active, mass_exploitation} on the asset's vulnerability and sector relevance >= 0.7; no-context ceiling 25 when
D = 0 and T < 0.1 and P < 0.2; benign-context ceiling 35 when a change ticket or known-scanner tag explains the
alert. Every factor carries evidence ids and a reason string.

## 4. API, agent and UI (Agents D, E)

Agent D implements 05 exactly on top of `AnalyticsEngine` and `GraphStore`, with a `ToolRegistry` that produces
Anthropic tool definitions and executes calls, the Claude streaming loop (manual loop, `claude-opus-5` default,
adaptive thinking, server-side fallbacks enabled by default, `strict` tools, `tool_choice: auto`, parallel tool
results returned in one user message, prompt caching on the system prompt) and the offline analyst (intent
classification with regexes and entity linking through `search_entities`; one playbook per demo question in 04
section 6 plus generic fallbacks: "what is X", "what can reach X", "why is this alert risky", "show me the
neighborhood of X"). The lifespan loads the `ContextGraph`, makes the store, builds the engine and the agent.

Agent E builds the UI in `web/` against 05 with a dev proxy to `http://127.0.0.1:8000`, and a production build served
by FastAPI at `/` from `web/dist`. Screens: Dashboard, Alerts, Alert detail (Flat view vs Graph context), Graph
explorer (search, expand, filters, path finder, Cypher panel), Threat intel (actors, campaigns, reports, exposure
table), Storylines, and the Analyst chat drawer on every screen. Wiz-like dark theme, left nav, dense tables,
severity/score chips, category-coloured node icons, dagre left-to-right for paths, fcose for neighborhoods.

## 5. Integration order and definition of done

1. A1 inventory generates and validates (`schema.validate_node`, pairs) in < 30 s; counts within 04 section 7 targets.
2. A3 threat intel generates; every storyline indicator/actor/campaign/report id exists.
3. A2 events generate from `inventory.json`; storyline alerts/events exist with exact ids and timestamps.
4. `simulator/build.py` merges, validates, enriches (Agent C), writes the canonical graph; `graph.loader` builds the LadybugDB file.
5. Scenario tests (`tests/scenarios/test_demo_questions.py`) assert 04 section 6 expectations through `AnalyticsEngine` and through the offline analyst.
6. API tests (`tests/api`) cover every endpoint's shape and limits with FastAPI's TestClient on the generated data.
7. UI builds (`npm run build`), Playwright screenshots of the demo script steps are saved to `docs/screenshots/`.
8. `make demo` = build data if missing, build UI if missing, serve on :8000.

Each agent's final report must list: files created, how to run its tests, what is stubbed, and any deviation from
the contracts.
