# 02 — Architecture Decision Record: Security Context Graph Prototype

| | |
|---|---|
| **Status** | Accepted (v1). Supersedes nothing. Revisit the embedded-engine decision (§2) quarterly. |
| **Date** | 2026-09-11 |
| **Owner** | Founding engineer / architect |
| **Scope** | The zero-infrastructure prototype and the production path it must not foreclose. |

## Decision summary

1. **Canonical data is engine-neutral**: the pipeline emits typed Parquet tables (one per node label / edge type). Every graph engine is a *projection* of those tables; none is the system of record.
2. **Demo graph engine: LadybugDB** (`pip install ladybug`, the maintained Kuzu fork) opened read-only by the API; **Kuzu 0.11.3 pinned** as a drop-in fallback behind the same adapter; **NetworkX-only** as the last-resort backend.
3. **Production graph engine: Neo4j** over Bolt (Memgraph and Amazon Neptune via the same Bolt adapter with dialect flags); **BigQuery Graph** as the future analytics-at-scale consumer of the same Parquet tables.
4. **A `GraphStore` interface + schema registry + portable-Cypher query library** isolates dialects; conformance tests run against every available backend.
5. **An in-memory NetworkX projection is kept alongside the graph DB** for algorithms with custom edge semantics (blast radius, attack paths, correlation, insight patterns).
6. **One primary label per node, `uid = label:provider:natural-key`, provenance on everything, derived edges never overwrite raw edges.**
7. **Analytics are explainable**: additive risk factors with evidence ids; attack paths are k-shortest simple paths over a weighted attack graph; every insight records hop count and sources crossed.
8. **Analyst agent = Claude tool use over the same typed, bounded, read-only tools the UI uses**; a deterministic playbook engine answers the demo questions when no API key is present; one tool registry serves Anthropic tools, REST and MCP.
9. **Frontend: React 19 + TypeScript + Vite, TanStack Query, Zustand, Cytoscape.js (+fcose, +dagre).**
10. **One command runs everything**: `make demo` builds the data if missing and serves API + UI from a single FastAPI process.

## 0. Assumptions and verified facts

Assumptions (decided, not asked): single-tenant demo; laptop = 4 cores / 16 GB; latest Chrome/Edge; vendor feed shapes are "loosely" mimicked (field names and nesting, not full schemas); Python 3.11, Node 22; no Docker in CI; outbound network cannot be assumed at runtime.

Verified on 2026-09-11 by installing and running in throwaway venvs (scripts in scratchpad, not committed):

| Fact | Result |
|---|---|
| Kuzu status | GitHub `kuzudb/kuzu` archived 2025-10-10 (team acqui-hired by Apple). Last PyPI `kuzu` = 0.11.3, MIT. `docs.kuzudb.com` no longer resolves. |
| LadybugDB status | Live PyPI package is **`ladybug`** (0.20.4 released 2026-09-10, daily dev builds; `import ladybug as lb`), MIT, Python 3.10–3.14. Repo `LadybugDB/ladybug` last commit 2026-09-10 (CMake version 0.21.0); separate `ladybug-python` and `ladybug-docs` repos, both active this week. **`real-ladybug` 0.15.3 (2026-04-01) is a stale package name** — do not use it. |
| Feature smoke test (both engines) | In-memory and on-disk DBs; `CREATE REL TABLE X(FROM A TO B, FROM C TO B, ...)` multi-pair rel tables; `MERGE ... ON CREATE SET`; `[e:A\|B*1..3]`; `SHORTEST`, `ALL SHORTEST`, `WSHORTEST(prop)`; recursive filters `(r, n \| WHERE ...)`; `$params`; `EXPLAIN`; `CALL show_tables()`; `Connection.set_query_timeout()` **enforced** ("Interrupted."); `Connection.interrupt()`; `Database(path, read_only=True)` **enforced**. |
| Divergences | Kuzu 0.11.3 rejects multi-label node patterns `(n:A\|B)` (parser error); LadybugDB accepts them. Kuzu 0.11.3 `COPY t FROM <pandas DataFrame>` crashes (`KU_UNREACHABLE` in its numpy binding) with numpy 2.4.6 / pandas 3.0.5 — first bit-rot symptom of a frozen wheel; its Parquet `COPY FROM` (nodes and multi-pair rels), `get_as_df` and `get_as_arrow` all work. LadybugDB: DataFrame and Parquet `COPY FROM` both work. |
| Extensions | `algo` (PageRank/WCC/SCC/Louvain/k-core), `fts`, `vector`, `neo4j` importer are fetched by `INSTALL <ext>` from an extension server at runtime → **never assume them offline**. |
| In-memory restriction | An in-memory Ladybug database cannot be opened `READ_ONLY`; only on-disk databases can. One `Database` object per process; many `Connection`s (or `AsyncConnection(db, max_concurrent_queries=n)`). |
| BigQuery Graph | GA announced 2026-09-07. ISO GQL over `CREATE PROPERTY GRAPH` definitions on tables; GQL needs an Enterprise / Enterprise Plus reservation (on-demand gets only `GRAPH_EXPAND`). Query-only surface; data lands via SQL/loads. |
| Frontend libs | Cytoscape.js core and first-party extensions MIT; `cytoscape-dagre` 4.0.0 released 2026-06; `cytoscape-fcose` (iVis-at-Bilkent) MIT. |
| LLM SDK | `anthropic` 1.x Python SDK; default model `claude-opus-5` (env-configurable), adaptive thinking, streaming, `strict` tool schemas, `tool_choice: auto` (forced tool choice is rejected on Claude Fable 5.1, so the design never relies on it). |

## 1. Architecture overview

```mermaid
flowchart LR
  subgraph S1[1. Connectors: simulated today, real later]
    A1[Cloud feeds<br/>AWS/Azure/GCP/K8s JSONL]
    A2[EDR feeds<br/>Falcon / Cortex XDR JSONL]
    A3[TI feeds<br/>STIX-like actors, IOCs, KEV, reports]
    A4[Business context<br/>apps, owners, criticality]
  end
  subgraph S2[2. Normalize and resolve]
    B1[Per-source normalizers<br/>vendor shape to NodeRecord/EdgeRecord]
    B2[Entity resolution<br/>SAME_AS with confidence]
  end
  subgraph S3[3. Canonical store]
    C1[(Parquet per label/type<br/>data/build/canonical)]
  end
  subgraph S4[4. Projection and load]
    D1[GraphStore adapters<br/>Ladybug/Kuzu, NetworkX, Bolt, Neptune]
    D2[NetworkX AnalyticsGraph<br/>in-process projection]
  end
  subgraph S5[5. Analytics]
    E1[Build-time materializers<br/>CAN_ACCESS, EXPOSED_TO_INTERNET, MATCHES_IOC, risk, attack paths]
    E2[On-demand engines<br/>blast radius, paths, correlation, insights]
  end
  subgraph S6[6. Serving]
    F1[FastAPI REST + SSE]
  end
  subgraph S7[7. Consumers]
    G1[Web UI<br/>React + Cytoscape]
    G2[Analyst agent<br/>Claude tool use or offline playbooks]
    G3[Agent-facing API<br/>tool manifest REST + MCP]
  end
  A1 & A2 & A3 & A4 --> B1 --> B2 --> C1 --> D1 & D2 --> E1 --> E2 --> F1 --> G1 & G2 & G3
```

Two rules govern the whole system. First, **nothing downstream of normalization knows vendor shapes**; connectors and normalizers are the only code that reads Falcon or EC2 field names. Second, **the canonical Parquet tables are the contract**: the graph DB, the NetworkX projection, the tests and, later, BigQuery all load from them. Analytics are split into build-time *materializers* (derived edges and scores written back into the canonical tables, so they are visible to Cypher and to every backend) and on-demand *engines* (per-request traversals that must stay interactive).

## 2. Graph database decision

### 2.1 Comparison

| Engine | Multi-hop / path fit | Language & GQL / BigQuery path | Zero-infra | Scale ceiling | License | Maturity & maintenance risk | Ecosystem | Verdict |
|---|---|---|---|---|---|---|---|---|
| **NetworkX** (in-process) | Excellent for custom algorithms (weighted, filtered BFS; Yen's k-paths; centrality). No query language. | None; would need a hand-written pattern matcher. | Yes | ~1–5M edges in RAM, single process, no persistence | BSD-3 | Very mature, boring, safe | Huge (Python) | **Keep as algorithm projection and fallback backend** |
| **Kuzu 0.11.3** (embedded) | Native `*min..max`, `SHORTEST`/`WSHORTEST`, recursive filters; columnar joins, fast | Cypher (openCypher-ish); typed DDL; GQL-portable read subset | Yes (pip) | 100Ms of edges on disk | MIT | **Archived Oct 2025**; frozen wheel already breaking against new numpy | Shrinking | **Pinned fallback only** |
| **LadybugDB** (embedded, Kuzu fork) | Same as Kuzu plus multi-label patterns, DataFrame/Parquet `COPY`, async connections | Same Cypher dialect; adds Arrow/Parquet/DuckDB interop | Yes (pip) | Same as Kuzu | MIT | 11-month-old community fork; **very active** (commits, releases this week); no vendor behind it; extensions need network | Growing; Kuzu docs/tutorials mostly apply | **Demo default** |
| **Neo4j** 5 / 2025.x | Excellent; quantified path patterns, `SHORTEST k`, GDS library | Cypher 25 with most mandatory ISO GQL features; strongest GQL migration story | No (JVM server; Docker/AuraDB) | Billions of edges (Enterprise clustering) | Community GPLv3 (single DB, no RBAC); Enterprise commercial | Most mature property-graph DB | Largest (drivers, GDS, Bloom, APOC) | **Production primary** |
| **Memgraph** | Very good, in-memory, deep-path algorithms (MAGE) | Cypher over Bolt (Neo4j drivers work) | No (server) | RAM-bound; 100Ms edges | BSL 1.1 (→ Apache 2.0 after 4 yrs) + commercial MEL | Mature, VC-backed | Good; MAGE algorithms | **Supported via Bolt adapter, `dialect=memgraph`** |
| **FalkorDB** | Good (sparse-matrix/GraphBLAS) | openCypher subset; Redis protocol, own client | No (Redis module) | 100Ms edges | SSPL v1 (not OSI) | Successor to RedisGraph; Rust rewrite 2026 | Moderate | Not adopted (license, operational model) |
| **Amazon Neptune** (DB + Analytics) | Good; Analytics engine for global algorithms | openCypher (subset) + Gremlin + SPARQL; Bolt endpoint works with Neo4j drivers | No (managed only) | Very high (managed) | Proprietary managed service | Mature; AWS-only | AWS-native | **Supported later via Bolt adapter, `dialect=neptune`** |
| **TigerGraph** | Excellent for deep analytics | GSQL first; openCypher embedded in GSQL; claims GQL | No (server; Community Edition ≤300 GB, single server) | Very high | Proprietary | Mature, enterprise-focused | Smaller, GSQL skills scarce | Not adopted |
| **Apache AGE** (Postgres) | Weak beyond 3–4 hops (openCypher compiled to recursive SQL) | openCypher subset inside SQL | Needs Postgres server | Postgres limits | Apache 2.0 | Mature project; Azure managed support | Postgres ecosystem | Not adopted (traversal performance) |
| **DuckDB + DuckPGQ** | SQL/PGQ path patterns; young optimizer | SQL/PGQ (SQL:2023) — sibling standard of GQL with near-identical `MATCH` pattern syntax | Yes (pip) but the extension is pinned to DuckDB 1.4.4, not 1.5.x | Analytical, single node | MIT | CWI research project, breaks across DuckDB patch versions | Small | Watch list; not adopted |
| **BigQuery Graph** | GQL path patterns at petabyte scale, batch-latency | **ISO GQL** over property graph definitions on tables; query-only | No (GCP; Enterprise reservation for GQL) | Effectively unbounded | Proprietary service | GA Sept 2026 | Google ecosystem | **Future analytics tier; consumer of our Parquet, never the source of truth** |

### 2.2 Decision

**Demo runs on LadybugDB.** The pipeline writes an on-disk database `data/build/graph.lbdb` via `COPY ... FROM parquet`; the API opens it with `read_only=True` (engine-level defense for the agent's Cypher tool) and one `Connection` per worker thread. `GRAPH_BACKEND=kuzu` flips the same adapter to `kuzu==0.11.3` (verified in our container); the adapter never uses the DataFrame `COPY` path, only Parquet, so both work. `GRAPH_BACKEND=networkx` runs the entire product minus the raw Cypher tool, for CI and as a safety net.

**Production runs on Neo4j** (Enterprise for RBAC, multi-database tenancy and clustering; Community for small single-tenant deployments), through a `BoltStore` adapter that also drives Memgraph and Neptune with dialect flags. BigQuery Graph is adopted as an *analytics consumer*: because our canonical data is already "table per label / table per edge type", a `CREATE PROPERTY GRAPH` definition over exported tables is a 200-line script, and our portable read queries are written in the GQL-compatible subset (§2.4). Lock-in is avoided structurally: BigQuery never becomes the source of truth, and nothing in the product depends on GQL features Neo4j lacks.

**Maintenance-risk assessment (honest).** Kuzu is dead as a project: no fixes, no new Python wheels, and we already observed a numpy-related crash in 0.11.3. LadybugDB is the healthiest possible outcome for a fork — a permissive license, weekly releases, docs and Python bindings under active development — but it is eleven months old, has no commercial entity we can contract with, and its storage format will keep changing. We accept this because the exposure is small and reversible: the embedded adapter is a few hundred lines, the data is rebuilt from Parquet on every launch (no migration burden), the NetworkX backend passes the same conformance suite, and versions are pinned in the lockfile. Review criteria each quarter: release cadence, unanswered-issue age, wheel coverage for our Python versions. If the fork stalls, the documented fallback is Kuzu-pinned (short term) and NetworkX-only for demos, with production already on Neo4j.

### 2.3 The `GraphStore` interface

One Python `Protocol`, implemented by `LadybugStore` (drives `ladybug` or `kuzu` via an import shim), `NetworkXStore`, `BoltStore` (Neo4j / Memgraph / Neptune), and later `BigQueryGraphStore` (read-only).

```
ensure_schema(registry)                       # DDL/constraints from the schema registry
load_canonical(parquet_dir)                   # bulk load, idempotent
get_nodes(uids) / get_edges(eids)             # by id
search(text, labels?, limit)                  # name/uid/ip/hash prefix + token search
neighborhood(uid, depth<=3, edge_types?, direction, max_nodes) -> GraphFragment
paths(src, dst, max_hops<=6, edge_types?, k<=5, mode=shortest|all_shortest) -> [Path]
subgraph(uids, include_edges=True) -> GraphFragment
count(label?) / stats() -> Stats
run_readonly(cypher, params, row_limit, timeout_s) -> Rows   # raises NotSupported on NetworkXStore
capabilities() -> {multi_label_patterns, weighted_shortest, cypher, ...}
```

Adapters return canonical `GraphFragment`s (§7), so callers never see driver records.

### 2.4 Handling Cypher dialect differences

* **Schema registry is the single source of truth** (`graph/schema.py`): labels, typed properties, edge types with their allowed `(from, to)` pairs. It compiles to Ladybug/Kuzu DDL (`CREATE NODE TABLE IF NOT EXISTS Label(uid STRING PRIMARY KEY, kind STRING, name STRING, ..., props_json STRING)`, `CREATE REL TABLE IF NOT EXISTS TYPE(FROM A TO B, FROM C TO D, eid STRING, confidence DOUBLE, ...)`), to Neo4j uniqueness constraints and indexes, and to a BigQuery `CREATE PROPERTY GRAPH`.
* **Single primary label everywhere.** Kuzu's "one node table per node" constraint becomes our convention: every node has exactly one `kind`; category groupings (Asset, Identity, Data) are properties and, on Neo4j only, convenience labels that shared queries never rely on. `kind` is a stored property, so queries never call `label(n)` vs `labels(n)`.
* **Typed core + JSON long tail.** Core properties are typed columns; vendor long-tail attributes go into `props_json` (a string). Neo4j stores the same properties flattened; the adapter maps both ways.
* **Portable Cypher subset** for the query library: `MATCH / OPTIONAL MATCH / WHERE / WITH / UNWIND / RETURN / ORDER BY / SKIP / LIMIT`, `count/collect/min/max`, `$params`, variable-length with explicit bounds `*1..k`, no procedures, no APOC, no MERGE in read paths. Every template is a named entry in `graph/queries/*.cypher` with per-dialect overrides only where needed:

| Concern | Ladybug/Kuzu | Neo4j / Memgraph | Neptune openCypher | BigQuery GQL |
|---|---|---|---|---|
| Shortest path | `-[e* SHORTEST 1..k]->` | `shortestPath((a)-[*..k]->(b))` or Cypher 25 `ANY SHORTEST` | `shortestPath` unsupported → k-hop + client-side selection | `ANY SHORTEST ... ->{1,k}` |
| Multi-label node pattern | Ladybug `(n:A\|B)`; Kuzu: `UNION` or label-less `(n)` + `WHERE n.kind IN [...]` | `(n:A\|B)` | `(n)` + `WHERE n.kind IN` | `(n:A\|B)` |
| Variable length | `*1..3` | `*1..3` (quantified paths optional) | `*1..3` | `->{1,3}` |
| Writes / bulk load | `COPY tbl FROM 'x.parquet'` | `UNWIND $rows MERGE ... SET n += row` in 5k batches, or `neo4j-admin import` | batch `UNWIND ... MERGE` | SQL loads only |
| Timeouts | `Connection.set_query_timeout(ms)` | driver `timeout` / tx timeout, `READ` access mode | request timeout | job timeout |
| Strings | `lower()` | `toLower()` | `toLower()` | `LOWER()` |

The `capabilities()` map lets engines pick an override at runtime; **conformance tests** (§9) execute every template on every available backend and compare results on the same fixture graph.

### 2.5 Keep the in-memory NetworkX projection? Yes.

Reasons: (1) blast radius and attack paths need *custom edge semantics* — per-edge traversal predicates (direction depends on type), weights from confidence, hub caps, and "must pass through node X" — which portable Cypher cannot express and which the embedded `algo` extension cannot provide offline; (2) Yen's k-shortest simple paths, personalized PageRank for choke points, and union-find correlation are one-liners in NetworkX; (3) it gives us the NetworkX backend for free. Cost: ~40k nodes / 100k edges is roughly 200–300 MB of Python objects and ~5 s to load from Parquet; acceptable on a laptop. Consistency rule: the projection is built from the same canonical Parquet at startup and is immutable for the process lifetime; the graph DB is authoritative for lookup, search and Cypher; both key by `uid`/`eid`. In production the projection becomes per-tenant, lazily built from the "attack graph" edge subset only (≈30% of edges), or is replaced by Neo4j GDS / Neptune Analytics behind the same `AnalyticsGraph` interface.

## 3. Data model conventions

### 3.1 Node label taxonomy (one `kind` per node)

| Category | Labels |
|---|---|
| Cloud infrastructure | `CloudAccount`, `Vpc`, `Subnet`, `SecurityGroup`, `VirtualMachine`, `LoadBalancer`, `KubernetesCluster`, `KubernetesNamespace`, `KubernetesWorkload`, `KubernetesServiceAccount`, `ServerlessFunction`, `ContainerImage` |
| Identity & access | `IamUser`, `IamRole`, `IamGroup`, `IamPolicy`, `IdpUser`, `AccessKey`, `Secret` |
| Data | `StorageBucket`, `Database`, `Snapshot` |
| Software & vulnerability | `SoftwarePackage`, `Cve`, `Vulnerability` (a CVE *instance* on an asset), `Misconfiguration` |
| Business context | `Application`, `BusinessUnit`, `Team`, `Environment` |
| Endpoint / EDR | `Device`, `Process`, `File` (by hash), `Detection`, `VendorIncident`, `EndpointUser`, `Domain`, `IpAddress` |
| Threat intelligence | `ThreatActor`, `Campaign`, `Technique` (ATT&CK), `Malware`, `Indicator`, `IntelReport`, `Sector` |
| Derived / analytic | `Alert`, `Issue` (toxic combination), `AttackPath`, `Storyline` (correlated incident), `Internet` (singleton pseudo-node) |

### 3.2 Relationship taxonomy and direction conventions

Edges read as *subject → verb → object*. Containment points parent → child; access points principal → resource; network points source → destination; detections point from the `Detection` to what it involves; TI points from actor/indicator to what it uses/indicates.

| Type | From → To | Raw / derived |
|---|---|---|
| `CONTAINS` | Account→Vpc→Subnet; Cluster→Namespace→Workload; Account→Bucket/Database/Function | raw |
| `MEMBER_OF_SG`, `IN_SUBNET`, `FRONTS` (LoadBalancer→VM/Workload) | infra topology | raw |
| `RUNS` (VM/Workload→SoftwarePackage), `RUNS_IMAGE` (Workload→ContainerImage) | inventory | raw |
| `HAS_VULNERABILITY` (asset→Vulnerability), `INSTANCE_OF` (Vulnerability→Cve) | findings | raw |
| `HAS_POLICY` (User/Role/Group→IamPolicy), `MEMBER_OF` (User→Group), `TRUSTS` (Role→principal), `HAS_INSTANCE_PROFILE` (VM→Role), `BOUND_TO` (Workload→K8s ServiceAccount→Role), `HAS_KEY` (User→AccessKey), `OWNS` (Team→Application), `SERVES` (asset→Application), `IN_ENVIRONMENT` | identity & business | raw |
| `ON_DEVICE` (Detection/Process→Device), `SPAWNED` (Process→Process), `HAS_FILE` (Process→File), `LOGGED_ON` (EndpointUser→Device, props: type, time), `CONNECTED_TO` (Device→IpAddress/Device, props: port, proto, time), `RESOLVED` (Device→Domain), `INVOLVES` (Detection→Process/User/File/IpAddress), `PART_OF` (Detection→VendorIncident) | EDR | raw |
| `USES` (Actor/Campaign→Technique/Malware), `EXPLOITS` (Actor/Malware→Cve), `TARGETS` (Actor→Sector), `INDICATES` (Indicator→Actor/Campaign/Malware), `MENTIONS` (IntelReport→any), `ATTRIBUTED_TO` (Campaign→Actor) | TI | raw |
| **`CAN_ACCESS`** (principal→resource; `actions[]`, `effect`, `via`, `confidence`) | IAM policy evaluation | **derived** |
| **`CAN_ASSUME`** (principal→Role) | trust-policy evaluation | derived |
| **`EXPOSED_TO_INTERNET`** (Internet→asset; `ports[]`, `via`) | SG/LB/public-IP evaluation | derived |
| **`CAN_REACH`** (asset→asset; `ports[]`) | simplified network reachability | derived |
| **`MATCHES_IOC`** (File/IpAddress/Domain→Indicator) | exact hash/IP/domain join | derived |
| **`SAME_AS`** (Device→VirtualMachine; EndpointUser→IamUser/IdpUser; `method`, `confidence`) | entity resolution | derived |
| **`ABOUT`** (Alert→anchor entities), **`EVIDENCE`** (Issue/AttackPath→nodes, `step`), **`GROUPS`** (Storyline→Alert, `order`, `stage`) | analytics outputs | derived |

### 3.3 Identity, provenance, time

* **Global id**: `uid = <label_snake>:<provider>:<natural-key>`, e.g. `virtual_machine:aws:i-0abc12`, `iam_role:aws:arn:aws:iam::123:role/Web`, `device:crowdstrike:aid-7f3…`, `cve:nvd:CVE-2024-3400`, `file:sha256:9f86d…`, `threat_actor:sim:TA-0007`, `alert:derived:a1b2…`. Provider is the system that owns the natural key; derived nodes use provider `derived` and a content hash. Edge id `eid = sha1(type|src|dst|discriminator)`; the discriminator is `""` for singletons, the event time for repeatable events (logons, connections).
* **Provenance on every node and edge**: `sources: [{system, source_id, collected_at}]`, `first_seen`, `last_seen`, `confidence ∈ [0,1]` (1.0 for raw facts), `derived: bool`, `derivation: "<rule>@<version>"`. Derived edges are recomputed from raw on every build and never overwrite raw edges.
* **Temporal handling**: events carry `event_time` (vendor timestamp) and `ingest_time` (pipeline time); entities carry `first_seen`/`last_seen`. Correlation, storylines and time-window resolution use `event_time`; freshness/latency dashboards use `ingest_time`. Default query window: last 30 days of `event_time`; the simulator anchors "now" at build time so demos are always fresh.

### 3.4 Entity resolution: EDR device ↔ cloud VM

A rule cascade, highest match wins, never merges nodes (a `SAME_AS` edge is reversible and auditable):

| Rule | Evidence | Confidence |
|---|---|---|
| A | Sensor cloud metadata instance id (Falcon `instance_id` + `service_provider_account_id`; Cortex `cloud_info`) equals VM `instance_id` in the same account | 0.98 |
| B | Normalized hostname equals VM name/private DNS **and** same account or VPC | 0.85 |
| C | Sensor `local_ip` equals a VM ENI private IP in the same account/VPC **and** `[first_seen,last_seen]` windows overlap | 0.60 |
| — | Multiple candidates at the same tier → pick most recent, set `ambiguous=true`; no candidate → `resolution=unresolved` | — |

The same machinery links `EndpointUser` (`DOMAIN\user`) to `IamUser`/`IdpUser` by email/UPN (0.9) or username + team (0.6). The UI renders a resolved pair as one "identity card" with both source ids; analytics traverse `SAME_AS` with its confidence as the edge weight.

## 4. Analytics design

Edge weights used by (a) and (b) — the **attack-graph semantics table** (`analytics/semantics.py`), the single place where security meaning is encoded:

| Edge | Traversal direction from a compromised node | p |
|---|---|---|
| `SAME_AS` | both | 0.95 × confidence |
| `HAS_INSTANCE_PROFILE`, `BOUND_TO` (workload→SA→role) | forward | 0.90 |
| `CAN_ASSUME`, `MEMBER_OF`→`HAS_POLICY` | forward | 0.80 |
| `CAN_ACCESS` | forward | 0.90 write / 0.70 read |
| `HAS_KEY`, `Secret`→`AccessKey`→principal | forward | 0.70 |
| `CAN_REACH` | forward | 0.50 (0.7 if admin ports) |
| `LOGGED_ON` | reverse (device → users whose credentials are cached) | 0.60 |
| `RUNS_IMAGE` | reverse (image → every workload running it) | 0.70 |
| `CONTAINS`, `HAS_VULNERABILITY`, TI edges | not traversed (context only) | — |

**(a) Blast radius.** Best-first search (Dijkstra on cost `−ln p`) from the compromised node over the attack graph, `depth ≤ 4` default (hard cap 6), reached-node budget 500 (cap 2,000), hub cap: nodes with out-degree > 300 are not expanded except through `CAN_ACCESS`/`CAN_ASSUME`. Output: reached nodes grouped by hop with `reach_score = Π p × 0.85^hops`, the best path to each, and a summary (crown jewels reached, admin identities reached, accounts touched). Complexity is bounded by the explored frontier, `O((V'+E') log V')`, typically < 100 ms.

**(b) Attack paths Internet → crown jewel through node X.** Entry = the `Internet` node via `EXPOSED_TO_INTERNET` (p from port sensitivity and whether an exploitable `Vulnerability` exists on the entry asset: 0.9 with exploited CVE, 0.5 otherwise). Targets = nodes with `crown_jewel=true` or `criticality ≥ high` (data stores, secrets, admin roles). Compute k-shortest simple paths (Yen's algorithm, `networkx.shortest_simple_paths`) for Internet→X and X→target, join, discard non-simple joins, cap total hops at 8 and k at 5 per target, rank by `likelihood = Π p` × target impact. Each step gets a kill-chain stage (Initial Access, Execution, Credential Access, Privilege Escalation, Lateral Movement, Collection). Paths for every exposed asset are **precomputed at build time** (bounded, ~1–2 s total) and stored as `AttackPath` nodes; on-demand paths for arbitrary X hit a 1.5 s budget then return best-so-far.

**(c) Contextual risk score** (0–100, per Alert/Issue; assets inherit the max of their alerts plus intrinsic factors). Additive factors so each contribution is visible, one multiplier for compensating controls:

| Factor | Range | Inputs | Evidence attached |
|---|---|---|---|
| F0 Base severity | 0–40 | vendor severity, CVSS, detection confidence | the alert/vulnerability node |
| F1 Exploitability | 0–15 | KEV listed, actor `EXPLOITS`, EPSS ≥ 0.5, public exploit | `Cve` + TI edges |
| F2 Exposure | 0–15 | `EXPOSED_TO_INTERNET` directly 15, via LB 10, internal 0 | exposure edge |
| F3 Privilege & reach | 0–15 | admin role within 2 hops, blast-radius size bucket | `CAN_ASSUME`/`CAN_ACCESS` paths |
| F4 Crown-jewel proximity | 0–15 | hops to nearest crown jewel: 1→15, 2→10, 3→5 | attack path |
| F5 Threat-intel pressure | 0–10 | propagated actor relevance, IOC match | `MATCHES_IOC`, actor edges |
| F6 EDR corroboration | 0–10 | detections on the `SAME_AS` device within 7 days | detections |
| M Compensating controls | ×0.6–1.0 | MFA enforced, no network path, patched, isolated | control evidence |

`score = min(100, (F0+…+F6) × M)`; the response carries the `RiskBreakdown` list with each factor's value, reason string and evidence ids. Weights live in one YAML file so the CEO can tune them without code.

**(d) Threat-intel impact enrichment.** IOC matching is a build-time hash join of `File.sha256`, `IpAddress.ip`, `Domain.name` against `Indicator` values → `MATCHES_IOC` edges carrying indicator confidence and validity window. Exploited-CVE overlay: KEV entries and `EXPLOITS` edges set `Cve.exploited=true`, `exploited_by[]`, `kev_added`; `Vulnerability` instances inherit `ti_priority`. Actor relevance `∈ [0,1]` = weighted sum of sector match (our `BusinessUnit.sector`), geography, campaign recency (≤ 90 days), and tech-stack overlap (actor's exploited CVEs ∩ our inventory). Propagation: `ti_pressure(n) = max(own(n), max over incoming edges of ti_pressure(m) × decay(edge))`, decay 0.8 for `MATCHES_IOC`/`INSTANCE_OF`/`HAS_VULNERABILITY`, 0.6 for `SAME_AS`/`RUNS`/`ON_DEVICE`, limited to 2 hops, computed once per build. It feeds F5 and the TI screen's "why this matters to us" panel.

**(e) Alert correlation into storylines.** Alerts share pivot entities (Device, EndpointUser, IpAddress, File, VirtualMachine, IamRole) via `ABOUT`; two alerts connect if they share a pivot within a window (24 h; 7 days for identities), excluding hub pivots (`hub=true`, e.g. shared service accounts, NAT IPs). Union-find yields clusters capped at 50 alerts; each cluster becomes a `Storyline` with alerts ordered by `event_time` and labelled by ATT&CK tactic. A cluster that joins an EDR alert to a cloud issue through `SAME_AS` gets a "cross-domain" flag and a +10 storyline boost — this is the demo's headline.

**(f) "Graph advantage" insights.** For each alert, run a catalog of 12–15 bounded path templates from its anchors; keep results with `hops ≥ 2` **and** `sources_crossed ≥ 2`; emit `Insight{statement, hops, sources[], evidence_path}` ranked by sources, hops and risk delta. Examples: *"The process hash matches an indicator attributed to TA-0007, which exploits CVE-2024-3400 — present unpatched on this host"* (3 hops; CrowdStrike + TI + vuln scanner); *"This device is the EC2 instance whose role can write to `customer-data`, a crown jewel"* (3 hops; EDR + AWS IAM + business context); *"Another alert 40 minutes later on a host this device connected to on 445"* (2 hops; two EDR alerts + network telemetry).

**Complexity bounds** (the demo must stay interactive):

| Operation | Default / hard limit | Target |
|---|---|---|
| Node lookup, search | 50 / 500 results | < 20 ms |
| Neighborhood | depth 1 / 3; 300 / 1,000 nodes | < 150 ms |
| Blast radius | depth 4 / 6; 500 / 2,000 nodes | < 300 ms |
| Attack paths | cached; cold ≤ 8 hops, k ≤ 5 | < 50 ms / < 1.5 s |
| Read-only Cypher tool | 200 rows, 3 s timeout, `*..k` with k ≤ 5 | ≤ 3 s |
| Offline analyst turn | ≤ 8 tool calls | < 1 s |
| Build (simulate → load) | 40k nodes / 100k edges | < 60 s |

## 5. Analyst agent design

### 5.1 Tools (typed with pydantic, bounded, read-only)

| Tool | Arguments (bounded) | Returns |
|---|---|---|
| `search_entities` | `query`, `kinds?`, `limit ≤ 50` | entity cards |
| `get_entity` | `uid` | node + 1-hop summary counts |
| `get_neighborhood` | `uid`, `depth ≤ 3`, `edge_types?`, `max_nodes ≤ 300` | `GraphFragment` |
| `find_paths` | `src`, `dst`, `max_hops ≤ 6`, `k ≤ 5` | paths as `GraphFragment` + ordered steps |
| `blast_radius` | `uid`, `depth ≤ 6`, `max_nodes ≤ 2000` | reach summary + `GraphFragment` |
| `attack_paths` | `through_uid?`, `target_uid?`, `k ≤ 5` | ranked paths with stages |
| `get_alert_context` | `alert_id` | alert, anchors, risk breakdown, storyline, insights |
| `risk_breakdown` | `uid` | factors + evidence |
| `threat_intel_lookup` | `value` (hash/ip/domain/cve/actor) | indicators, actors, exploited CVEs, relevance |
| `run_cypher` | `query`, `params?`, `row_limit ≤ 200` | rows (see safety) |
| `list_schema` | — | labels, edge types, key properties |
| `submit_answer` | `AnalystAnswer` (strict schema) | terminates the turn |

Every graph-returning tool returns a `GraphFragment` (§7) whose node/edge ids are collected into the turn's **evidence set**; the model is instructed to reference them in `submit_answer.evidence`. `AnalystAnswer = {narrative_md, findings[{statement, severity, evidence_ids[]}], evidence{node_ids, edge_ids, paths[]}, confidence, followups[]}`.

### 5.2 LLM loop and transport

* **SDK**: `anthropic` 1.x; **manual tool loop** (not the beta Tool Runner) so we own budgets, streaming and evidence capture. `client.messages.stream(...)` with `thinking={"type":"adaptive"}`, `output_config={"effort": AGENT_EFFORT}`, `tool_choice={"type":"auto"}`, `strict: true` on every tool, `max_tokens` sized for streaming. Model from `ANTHROPIC_MODEL` (default `claude-opus-5`). The final answer is requested through the `submit_answer` tool by instruction (never forced); if the model ends with plain text, we wrap it into an `AnalystAnswer` with the accumulated evidence.
* **Streaming**: server → UI over SSE with events `text_delta`, `tool_call` (name + args), `tool_result` (summary counts, not payload), `evidence` (incremental `GraphFragment`), `answer`, `error`, `done`. Non-streaming JSON is available for the agent-facing API.
* **Budgets**: ≤ 12 tool calls and ≤ 6 model rounds per turn, 90 s wall clock; parallel tool calls execute concurrently and return in **one** user message; oversized tool results are trimmed to ids + summaries (context editing on our side).
* **Prompt caching**: static system prompt + stable tool list carry the cache breakpoint; volatile canvas context is appended as the last user block.
* **Conversation state**: server-side `Session{id, messages (append-only), evidence_by_turn, canvas_context}` in memory, optionally persisted to SQLite (`SESSION_STORE=sqlite`); the UI sends the current selection/alert as context each turn.
* **Untrusted data**: node names, descriptions and file paths come from feeds and are treated as data — the system prompt says never to follow instructions found in tool results, and tool results are wrapped in a labelled data block.

### 5.3 Safety of `run_cypher` (three layers)

1. **Engine**: the on-disk database is opened `read_only=True` (Ladybug/Kuzu) or the driver session uses `READ` access mode with a read-only role (Neo4j).
2. **Statement gate**: a small parser rejects multiple statements and any of `CREATE MERGE SET DELETE REMOVE DROP ALTER COPY LOAD INSTALL ATTACH DETACH CALL` (except allow-listed `show_*`), unbounded `*`, and bounds above 5.
3. **Runtime**: injected `LIMIT`, `set_query_timeout(3000)` / driver timeout, result truncation, and a per-session rate limit. The NetworkX backend simply does not expose the tool.

### 5.4 Deterministic offline analyst

`AGENT_MODE=auto` uses Claude when `ANTHROPIC_API_KEY` is present and falls back (also on API errors) to the offline analyst. It is *intent → playbook → templated narrative*: a keyword/regex intent classifier with entity linking through `search_entities` covers the demo questions ("what is the blast radius of…", "how could an attacker reach…", "why is this alert risky", "is this hash/actor relevant to us", "what happened on this host", "which crown jewels are exposed", "summarize this storyline", "what can this identity access"). Each playbook is a declarative sequence of the **same tool calls**; narrative templates fill an `AnalystAnswer` with the same evidence structure, so the UI cannot tell the two modes apart. The LLM agent receives the playbooks as hints in its system prompt, keeping both paths aligned, and scenario tests (§9) assert the playbooks' findings.

### 5.5 Agent-facing API

One `ToolRegistry` (pydantic models) generates the Anthropic tool definitions, an OpenAPI-documented REST surface — `GET /v1/agent/tools` (JSON Schema manifest), `POST /v1/agent/tools/{name}` (invoke), `POST /v1/agent/answer` (run the analyst, streaming or not) — and an **MCP server** (official `mcp` Python SDK; stdio for local agents, streamable HTTP for remote) exposing the identical tools. External agents therefore get exactly the read-only, bounded surface our own analyst uses; in production each agent has its own token and tenant scope.

## 6. Ingestion / simulation design

```
simulator/
  world.py          # deterministic org model from SIM_SEED: business units, apps, environments, tiers
  generators/       # one per source, writes vendor-shaped JSONL: aws.py azure.py gcp.py k8s.py
                    #   crowdstrike.py cortex.py nvd_kev.py threat_intel.py business.py
  storylines/       # scripted attack chains layered over background noise, each with expected_findings.yaml
  noise.py          # benign detections, routine logons, patch churn, false-positive IOC hits
```

Background generation produces a plausible enterprise; **storyline overlays** then inject 3–4 scripted chains (e.g. *internet-exposed VM with an exploited CVE → sensor detection → instance-role assumption → crown-jewel bucket access*; *phishing on a workstation → credential dump → lateral movement to a build server → cloud keys*; *malicious dependency in a container image deployed to 40 workloads*). Each storyline declares the entities it touches and the facts the analyst must find; those files are the fixtures for scenario tests. Feeds land as `data/feeds/<source>/<object>.jsonl` mimicking vendor API shapes: `aws/ec2_instances.jsonl` (DescribeInstances-like), `aws/iam_roles.jsonl`, `aws/s3_buckets.jsonl`, `k8s/workloads.jsonl`, `crowdstrike/devices.jsonl` (Falcon devices-style with `aid`, `hostname`, `local_ip`, `instance_id`), `crowdstrike/detections.jsonl` (alerts-v2 style with `composite_id`, `tactic`, `technique`, `behaviors[]`), `cortex/incidents.jsonl`, `ti/intrusion_sets.jsonl` and `ti/indicators.jsonl` (STIX 2.1-like), `nvd/cves.jsonl`, `cisa/kev.jsonl`, `business/applications.csv`.

Pipeline stages (`pipeline/`): normalizers (vendor dict → `NodeRecord`/`EdgeRecord`), entity resolution (§3.4), materializers (§4 derived edges and scores), writer (Parquet per label/type → `GraphStore.load_canonical`). Everything is deterministic under `SIM_SEED`; `SIM_SCALE` multiplies volumes.

Scale targets (`SIM_SCALE=1.0`): ~42k nodes — 2,500 VMs, 900 K8s workloads, 400 functions, 600 buckets, 250 databases, 3,000 IAM principals/policies, 1,500 CVEs, 8,000 vulnerability instances, 3,000 devices (≈85% resolve to VMs), 8,000 processes, 4,000 file hashes, 1,200 detections, 3,000 indicators, 40 actors, 600 alerts, 60 issues, ~120 attack paths — and ~100k edges, of which ~30% are derived.

Attaching real APIs later: a `Connector` yields vendor-shaped pages (`fetch_pages()`), so normalizers do not change; incremental mode upserts by `uid`, bumps `last_seen`, tombstones stale entities after N days, and re-runs materializers on the changed neighborhood. The JSONL feeds become the connector's local cache, which doubles as a replayable fixture.

## 7. Serving API (FastAPI, `/v1`)

| Endpoint | Purpose | Limits |
|---|---|---|
| `GET /alerts` | list; filters `severity`, `kind`, `storyline`, `since`; sort by risk | cursor pagination, `limit` 50 / 500 |
| `GET /alerts/{id}` | alert + anchors + risk breakdown | — |
| `GET /alerts/{id}/context` | evidence fragment, insights, attack paths, storyline | fragment ≤ 300 nodes |
| `GET /nodes/{uid}`, `POST /nodes:batch` | node cards | batch ≤ 200 |
| `GET /search?q=&kinds=` | prefix/token search | 50 / 500 |
| `GET /nodes/{uid}/neighborhood?depth=&edge_types=&max_nodes=` | expand-on-click | depth ≤ 3, ≤ 1,000 nodes |
| `GET /paths?src=&dst=&max_hops=&k=` | shortest paths | hops ≤ 6, k ≤ 5 |
| `GET /nodes/{uid}/blast-radius?depth=` | reach analysis | depth ≤ 6 |
| `GET /attack-paths?through=&target=&k=` | ranked attack paths | k ≤ 5 |
| `GET /threat-intel/lookup?value=` , `GET /threat-intel/actors` | TI overlays | 100 |
| `GET /storylines`, `GET /storylines/{id}` | correlated incidents | pagination |
| `GET /stats` | counts by label/type, build info, backend, capabilities | — |
| `POST /chat/sessions`, `POST /chat/sessions/{id}/messages` (SSE), `GET /chat/sessions/{id}` | analyst conversation | 12 tool calls / turn |
| `GET /agent/tools`, `POST /agent/tools/{name}`, `POST /agent/answer` | agent-facing surface | tool bounds |
| `POST /admin/cypher` | read-only Cypher for the UI query panel | same gate as the tool |

Pagination is cursor-based (`?cursor=&limit=`), responses carry `next_cursor`. Errors use `{error: {code, message, details}}` with RFC-style codes (`limit_exceeded`, `not_found`, `query_rejected`, `timeout`).

**GraphFragment** (every graph-returning endpoint and tool):

```json
{
  "nodes": [{"uid": "virtual_machine:aws:i-0abc", "kind": "VirtualMachine", "name": "web-1",
             "severity": "high", "risk_score": 82, "props": {"instance_id": "i-0abc", "exposed": true},
             "sources": ["aws"], "highlight": true, "tags": ["crown_jewel_path", "storyline:S1"]}],
  "edges": [{"eid": "6f1…", "type": "CAN_ACCESS", "src": "iam_role:aws:…", "dst": "storage_bucket:aws:…",
             "props": {"actions": ["s3:GetObject"]}, "derived": true, "confidence": 0.9, "highlight": true}],
  "paths": [{"node_uids": ["internet:derived:internet", "virtual_machine:aws:i-0abc", "…"],
             "edge_eids": ["…"], "likelihood": 0.41, "stages": ["Initial Access", "Privilege Escalation", "Collection"]}],
  "meta": {"truncated": false, "total_nodes": 37, "backend": "ladybug", "elapsed_ms": 48}
}
```

## 8. Frontend architecture

| Concern | Choice | Why |
|---|---|---|
| Framework | React 19 + TypeScript + Vite | required; fast dev loop |
| Server state | TanStack Query v5 | caching, pagination, retries; SSE handled by a small hook |
| UI / canvas state | Zustand | selection, highlight set, layout mode, drawer state without prop drilling |
| Styling | Tailwind CSS + shadcn/ui (Radix) | dense analyst UI, dark theme, accessible primitives |
| Graph rendering | **Cytoscape.js** + `cytoscape-fcose` + `cytoscape-dagre` | best fit for a few hundred nodes with per-kind SVG icons (`background-image` data URIs), labels, edge labels (`text-rotation: autorotate`), compound nodes for collapsing hubs, built-in styling by class (highlight/dim), and both force and layered layouts. Sigma.js wins only above ~5k visible nodes (WebGL) at the cost of layouts and algorithms; G6 is capable but heavier and less idiomatic in React; react-force-graph lacks hierarchical layouts; vis-network suits interactive diagrams but has weaker layout and styling control for analysis views. |
| Charts | Recharts | risk breakdown bars, timeline |

Screens: **Graph Explorer** (search → seed → expand-on-click, filters by kind/edge type, Cypher panel), **Alerts** (table with risk, storyline chips), **Alert Detail** (evidence subgraph, attack paths in dagre LR, risk breakdown, insights list with hop/source badges, storyline timeline), **Threat Intel** (actors/campaigns with relevance and affected assets), **Stats**, and the **Assistant drawer** on every screen.

Highlight bus: chat `evidence` events → `useCanvasStore.addEvidence(fragment)` → the canvas merges nodes/edges not yet present (`cy.add`), applies `.highlight` to the evidence ids and `.dim` to everything else, runs an incremental fcose (`randomize:false`) and fits to the highlighted set; clicking an evidence chip in a chat bubble re-centres it. The same store powers "add to canvas" from alert detail.

Layouts: fcose for neighborhoods and blast radius (with hop rings via `concentric` as an alternative), dagre `rankDir: LR` for attack paths and storylines (ordered by stage/time), preset positions restored per session. Performance limits: ≤ 500 visible nodes / 1,500 edges; beyond that the API truncates and the UI offers grouping (hubs collapse into compound nodes with counts); labels hidden below 60% zoom; `cy.batch` for merges; `textureOnViewport` during pans.

## 9. Repository layout, run commands, configuration, testing

```
/
  simulator/     world, generators, storylines, noise
  pipeline/      normalizers/, resolution/, materializers/, writer.py
  graph/         schema.py (registry), store.py (GraphStore protocol), stores/{ladybug,networkx,bolt}.py, queries/*.cypher, dialects.py
  analytics/     semantics.py, blast_radius.py, attack_paths.py, risk.py, ti_enrichment.py, correlation.py, insights.py, analytics_graph.py
  api/           app.py, routers/, models/ (pydantic v2), sse.py
  agent/         registry.py, tools/, llm_agent.py, offline/{intents,playbooks,templates}, mcp_server.py, prompts/
  web/           Vite + React app (src/{screens,components,store,api,graph})
  data/          feeds/ (generated JSONL, gitignored), build/ (parquet, graph.lbdb), fixtures/ (small committed graphs)
  scripts/       build_data.py, run_demo.py, export_bigquery.py, bench.py
  tests/         unit/, conformance/, scenarios/, e2e/
  docs/          this ADR and successors
  Makefile, pyproject.toml, .env.example
```

Commands: `make setup` (`pip install -e .[dev]`, `npm ci` in `web/`), `make demo` (builds data if `data/build/` is missing, builds the web bundle, starts uvicorn on `:8000` serving API + static UI; opens the browser), `make dev` (uvicorn `--reload` + Vite dev server with proxy), `make data SIM_SEED=7 SIM_SCALE=2`, `make test`.

| Env var | Default | Meaning |
|---|---|---|
| `GRAPH_BACKEND` | `ladybug` | `ladybug` \| `kuzu` \| `networkx` \| `neo4j` \| `memgraph` \| `neptune` |
| `GRAPH_DB_PATH` | `data/build/graph.lbdb` | embedded DB file |
| `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `NEO4J_DATABASE` | — | Bolt backends |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` (`claude-opus-5`), `AGENT_EFFORT` (`high`) | — | LLM analyst |
| `AGENT_MODE` | `auto` | `auto` \| `llm` \| `offline` |
| `SIM_SEED`, `SIM_SCALE` | `42`, `1.0` | simulation determinism and size |
| `API_PORT`, `LOG_LEVEL`, `SESSION_STORE` | `8000`, `info`, `memory` | serving |

Testing strategy:

* **Unit tests** (`tests/unit`) run analytics on hand-built fixture graphs (20–200 nodes) with known answers: blast radius sets, k-paths, risk factor arithmetic, IOC matching, resolution cascade, correlation clusters.
* **Backend conformance tests** (`tests/conformance`) are parametrized over every backend that can start in the environment: `networkx` and `ladybug` (and `kuzu`) always; Neo4j/Memgraph when `NEO4J_URI` is set (a nightly Docker job uses testcontainers). They load the same fixture, run every query template and every `GraphStore` method, and compare canonical results; unavailable backends are skipped with a reason, never silently.
* **Scenario tests** (`tests/scenarios`) build the full simulated dataset once per session, then run each storyline's key demo questions through the offline analyst and assert the expected findings and evidence ids from `expected_findings.yaml`; a `--llm` marker runs the same questions through Claude and scores evidence recall plus an LLM-judged faithfulness check when a key is present.
* **API/e2e**: FastAPI `TestClient` contract tests for every endpoint's shape and limits; Playwright smoke for the three main screens.

## 10. Risks, mitigations, path to production

| Risk | Mitigation |
|---|---|
| LadybugDB fork stalls or breaks compatibility | Pinned versions; adapter isolation; Parquet canonical data; Kuzu/NetworkX fallbacks pass the same suite; quarterly review criteria (§2.2) |
| Cypher dialect drift across backends | Portable subset + per-dialect overrides + conformance tests; no APOC/procedures in product code |
| Interactive latency degrades with scale | Hard limits and budgets in every engine; build-time materialization; hub caps; truncation flags surfaced in the UI |
| Agent hallucination or prompt injection via feed data | Tool-grounded answers with evidence ids the UI renders; untrusted-data framing; read-only three-layer Cypher gate; evidence-recall evals |
| Risk score credibility | Additive, explainable factors with evidence; weights in YAML; scenario tests pin expected rankings |
| Simulation overfits the demo | Storylines layered on independent background noise; seeds and scale configurable; the same normalizers will run on real APIs |
| GQL/BigQuery migration cost | Queries in the GQL-compatible subset; table-per-label storage maps directly to property graph definitions; `export_bigquery.py` exercised in CI against a schema check |
| Browser canvas overload | 500-node cap, compound grouping, label culling, incremental layouts |

**Path to production.** (1) Real connectors for AWS/Azure/GCP inventory and IAM, Falcon and Cortex XDR APIs, and STIX/TAXII intel, reusing the normalizers; (2) streaming ingest (Kinesis/Kafka → normalizer workers → graph upserts + change events → incremental materializers on the affected neighborhood); (3) multi-tenancy — database-per-tenant on Neo4j Enterprise (or `tenant_id` scoping on Neptune) with per-tenant NetworkX projections built lazily from the attack-graph subset; (4) RBAC via OIDC, per-tool authorization and per-agent tokens on the MCP/REST surface; (5) scale-out to Neo4j clusters or Neptune, with Neo4j GDS / Neptune Analytics replacing the in-process algorithms behind `AnalyticsGraph`; (6) BigQuery Graph for fleet-wide, cross-tenant analytics and long-horizon hunting over the exported Parquet, queried in ISO GQL; (7) a standing evaluation harness for agent answers — golden question sets derived from storylines and real incidents, evidence recall, faithfulness judged by a second model, tool-call efficiency and latency — gating every prompt or tool change.

## 11. Founder review and final decisions (2026-09-11)

I reviewed the ADR above against the product definition (01) and made the following calls. Where this section and
the sections above disagree, this section wins; 03-06 already reflect it.

1. **Embedded engine: LadybugDB** (`pip install ladybug`, `import ladybug as lb`). Verified in the build container:
   multi-pair rel tables, multi-label patterns, `SHORTEST` paths, list functions, parameters, enforced read-only
   mode and query timeouts. Kuzu 0.11.3 stays available as an optional extra behind the same adapter, but the two
   engines must never be imported in the same process (they clash at the native level; observed as an import
   failure followed by a segfault). NetworkX is the always-available fallback backend. Neo4j is the server-side
   backend; its adapter ships but is not exercised in CI here (conformance tests skip when `NEO4J_URI` is unset).
2. **Canonical data is the JSONL pair `nodes.jsonl` / `edges.jsonl` plus `manifest.json`** (03 section 2), not
   Parquet. Parquet tables per label and edge type are a *loader artifact* used for fast `COPY` into LadybugDB and
   for the BigQuery Graph export; they are regenerated from the JSONL on every build.
3. **Identifiers use short type prefixes** (`vm:aws:i-…`, `alert:falcon:ldt-a009`, `role:aws:<account>:<name>`)
   as specified in 03, because analysts and the agent read and cite them constantly. The label taxonomy in 03 is
   canonical (for example `Endpoint` rather than `Device`, one unified `Alert` label with `source_system`,
   `Vulnerability` as the CVE node with `VULNERABLE_TO` carrying the instance, `HumanUser` for the Okta identity).
4. **Scale targets are those in 04 section 7** (roughly 20-30k nodes, 80-150k edges), sized so generation and load
   stay under a minute each on a laptop.
5. **Scoring uses the product definition's formula** (weighted factors plus explicit rails) rather than the additive
   F0-F6 variant: it is easier to explain on stage, and the worked examples in 01 section 5.2 are the acceptance
   tests. Every factor still carries evidence ids and a reason.
6. **Build-time enrichment lives in the analytics library** (`analytics.materialize.enrich`), so the same code that
   scores alerts in the pipeline is what the API explains at request time; the simulator only emits raw facts and
   posture derivations (exposure, vulnerability roll-ups, effective access, entity resolution).
7. **The analyst agent** follows section 5 with the default model `claude-opus-5`, adaptive thinking, streaming, and
   Anthropic's server-side refusal fallbacks enabled by default (configurable). The offline analyst is a first-class
   product path, not a stub: it must answer all twelve demo questions with evidence.
8. **Frontend** as in section 8, with Tailwind only (no component library) and no charting dependency; risk factor
   bars and small sparklines are plain CSS/SVG.
9. **Repository layout** uses a single installable Python package `throughline/` with subpackages (06 section 1)
   instead of top-level directories, so imports are unambiguous and the CLI installs cleanly.
