# Serving API and Agent Tool Contract (build contract)

Base path: `/api/v1`. JSON everywhere except the chat stream (`text/event-stream`). All models are defined in
`throughline/models.py` (pydantic) and mirrored in `web/src/api/types.ts`. Every graph-returning endpoint returns a
`GraphFragment` (nodes, edges, paths, focus, layout_hint, truncated). IDs are the canonical node ids from
docs/03-graph-schema.md; edge ids are `src|TYPE|dst`.

Errors: HTTP status + `{"error": {"code": "...", "message": "...", "details": {...}}}` with codes
`not_found` (404), `invalid_argument` (400), `limit_exceeded` (400), `query_rejected` (400), `not_supported` (501),
`timeout` (504), `upstream_error` (502).

Limits (defaults / hard caps): neighborhood depth 1 / 3, fragment nodes 150 / 300, blast radius depth 4 / 6 and
500 / 2000 reached nodes, paths k 3 / 5 and max_hops 6 / 8, search limit 25 / 100, alert page 50 / 500,
Cypher rows 200 / 500 with a 3 s timeout.

## 1. Meta

| Method & path | Returns |
|---|---|
| `GET /health` | `{status, backend, total_nodes, total_edges, agent_mode, model, build}` |
| `GET /stats` | `StatsOut` |
| `GET /schema` | `{categories, labels: [{name, category, id_prefix, columns: [{name, type}]}], edge_types: [{name, pairs: [[from,to]], columns, derived}]}` |
| `GET /dashboard` | see section 1.1 |

### 1.1 Dashboard payload
```json
{
  "kpis": {"open_alerts": 0, "critical_contextual": 0, "storylines": 0, "crown_jewels": 0, "crown_jewels_at_risk": 0,
           "internet_exposed_exploited": 0, "endpoints": 0, "endpoint_coverage_pct": 0.0, "ioc_matches": 0},
  "leaderboard_contextual": ["AlertSummary x 10, sorted by contextual_score desc"],
  "leaderboard_vendor": ["AlertSummary x 10, sorted by vendor_severity_rank desc, then detected_at desc"],
  "storylines": ["StorylineOut without fragment"],
  "alerts_by_band": {"critical": 0, "high": 0, "medium": 0, "low": 0, "noise": 0},
  "alerts_by_source": {"falcon": 0, "cspm": 0, "waf": 0, "ids": 0, "cloud-anomaly": 0, "okta": 0},
  "coverage": {"vms_total": 0, "vms_with_sensor": 0, "vms_without_sensor_prod": 0, "endpoints_total": 0, "endpoints_resolved_to_vm": 0},
  "ti_pressure": [{"actor_id": "", "actor_name": "", "sector_relevance": 0.9, "campaigns": 1, "ioc_matches": 4, "exploited_cves_present": 1, "alerts": 9}],
  "rerank_examples": [{"alert_id": "", "title": "", "vendor_severity": "medium", "contextual_score": 92, "vendor_rank_position": 210, "contextual_rank_position": 1}]
}
```

## 2. Alerts and storylines

| Method & path | Query / body | Returns |
|---|---|---|
| `GET /alerts` | `sort=contextual|vendor|time` (default contextual), `order=desc|asc`, `band=`, `severity=`, `source=`, `storyline=`, `reaches_crown_jewel=true`, `on_attack_path=true`, `q=` (text on title/hostname/entity), `limit`, `offset` | `{items: [AlertSummary], total, limit, offset}` |
| `GET /alerts/{id}` | | `{alert: AlertSummary, flat_view: {...}}` (flat view = the vendor's raw fields, unchanged) |
| `GET /alerts/{id}/context` | | `AlertContext` (alert, flat_view, risk, insights, blast_radius, attack_paths, storyline, threat_intel, related_alerts, evidence fragment with `layout_hint: "path"` when a storyline path exists) |
| `GET /alerts/{id}/risk` | | `RiskBreakdown` |
| `GET /alerts/{id}/insights` | | `{insights: [Insight]}` |
| `GET /storylines` | | `{items: [StorylineOut (no fragment)]}` |
| `GET /storylines/{id}` | | `StorylineOut` with `fragment` (`layout_hint: "storyline"`, stages ordered) |

## 3. Graph

| Method & path | Query / body | Returns |
|---|---|---|
| `GET /search` | `q`, `labels=A,B`, `limit` | `{hits: [SearchHit]}` |
| `GET /nodes/{id}` | | `{node: NodeOut, degree: {"in": n, "out": n}, edge_type_counts: {TYPE: n}, alerts: [AlertSummary], threat_intel: TIContext or null}` |
| `POST /nodes/batch` | `{ids: [..<=200]}` | `{nodes: [NodeOut]}` |
| `GET /graph/neighborhood` | `id`, `depth`, `edge_types=A,B`, `direction=both|in|out`, `labels=A,B`, `max_nodes` | `GraphFragment` (`focus=[id]`) |
| `GET /graph/paths` | `src`, `dst`, `max_hops`, `k`, `edge_types` | `GraphFragment` with `paths`, `layout_hint: "path"` |
| `GET /graph/blast-radius` | `id`, `depth`, `max_nodes` | `BlastRadiusResult` (`fragment.layout_hint: "blast_radius"`) |
| `GET /graph/attack-paths` | `through`, `target`, `entry`, `k` | `{paths: [AttackPathOut], fragment: GraphFragment}` |
| `POST /graph/cypher` | `{query, params?, row_limit?}` | `{columns: [..], rows: [[..]], elapsed_ms, truncated, fragment: GraphFragment or null}`; node/relationship values in rows are rendered as `{id,label,name}` / `{src,type,dst}` and collected into `fragment`. 400 `query_rejected` on gate failure, 501 `not_supported` on the NetworkX backend |

## 4. Threat intelligence

| Method & path | Returns |
|---|---|
| `GET /threat-intel/actors` | `{items: [{actor: NodeOut, campaigns: [NodeOut], sector_relevance, active, ioc_matches, matched_alerts, exploited_cves_present, affected_assets}]}` sorted by relevance then matches |
| `GET /threat-intel/actors/{id}` | `{actor, campaigns, malware, techniques, indicators, reports, context: TIContext, affected: GraphFragment}` |
| `GET /threat-intel/campaigns/{id}` | same shape for a campaign |
| `GET /threat-intel/reports` | `{items: [NodeOut]}` newest first |
| `GET /threat-intel/reports/{id}` | `{report: NodeOut, actors, campaigns, malware, cves, indicators, techniques, impact: {matched_alerts: [AlertSummary], exposed_assets: [NodeOut], summary}}` |
| `GET /threat-intel/lookup?value=` | `TIContext` for a hash, ip, domain, CVE id, technique id or actor/campaign name |
| `GET /threat-intel/exposure` | `{items: [{vm: NodeOut, cve: NodeOut, exploitation_status, actors: [NodeOut], campaigns: [NodeOut], sector_relevance, contextual_score, crown_jewels_reachable: [NodeOut], has_edr_sensor, alert_ids}]}` = demo question 5, sorted by contextual_score desc; query `sector_only=true` (default) keeps actors with relevance >= 0.7 |

## 5. Investigations (typed questions; also the agent's tools)

| Method & path | Body / query | Returns |
|---|---|---|
| `GET /investigate/credential-joins` | | `{items: [{credential: NodeOut, stolen_by_alert: AlertSummary, endpoint: NodeOut, principal: NodeOut, used_in_events: [NodeOut], derived_credentials: [NodeOut], first_use, source_ips: [..]}], fragment}` (question 8) |
| `GET /investigate/alerts-reaching-crown-jewels` | `jewel_id?`, `classification?` | `{items: [AlertSummary], jewels: [NodeOut], fragment}` (question 10) |
| `GET /investigate/identity-footprint` | `id` | `BlastRadiusResult` rooted at the identity (question 4) |
| `GET /investigate/medium-alerts-with-data-path` | `severity=medium` (default), `source=falcon` | `{items: [AlertSummary], fragment}` (question 2) |
| `POST /investigate/containment` | `{target_ids: [..], actions: ["isolate_endpoint" | "rotate_role_credentials" | "tighten_trust_policy" | "block_ip" | "disable_user" | "revoke_sessions"]}` | `ContainmentSimulation` (question 12) |

## 6. Chat (analyst assistant)

| Method & path | Body | Returns |
|---|---|---|
| `POST /chat/sessions` | `{context?: {alert_id?, storyline_id?, selected_node_ids?}}` | `ChatSession` |
| `GET /chat/sessions/{id}` | | `ChatSession` |
| `POST /chat/sessions/{id}/messages` | `ChatMessageIn` | **SSE stream** of `ChatEvent` (default) or `{turn: ChatTurn}` when `?stream=false` |
| `GET /chat/suggestions` | `alert_id?`, `node_id?`, `storyline_id?` | `{questions: [str]}` the demo questions, contextualized to the selection |

SSE framing: each event is `event: <type>` + `data: <json>` + blank line. Types and payloads:

| type | data |
|---|---|
| `session` | `{session_id, mode: "llm"|"offline", model}` |
| `text_delta` | `{text}` (narrative markdown chunk) |
| `thinking` | `{text}` (optional summarized thinking) |
| `tool_call` | `{id, name, arguments}` |
| `tool_result` | `{id, name, summary, duration_ms, error?}` |
| `evidence` | `GraphFragment` (incremental; the UI merges it into the canvas and highlights it) |
| `answer` | `AnalystAnswer` (final; includes merged evidence and findings) |
| `error` | `{code, message}` |
| `done` | `{mode, model, tool_calls, elapsed_ms}` |

## 7. Agent-facing API

| Method & path | Body | Returns |
|---|---|---|
| `GET /agent/tools` | | `{tools: [{name, description, input_schema}]}` (Anthropic tool-definition compatible, `strict` schemas) |
| `POST /agent/tools/{name}` | tool arguments | `{result: <tool result json>, evidence: GraphFragment or null, elapsed_ms}` |
| `POST /agent/answer` | `{question, context?, mode?}` | `AnalystAnswer` (non-streaming) |

### 7.1 Tool set (identical for the LLM analyst, the offline analyst and the REST surface)

| Tool | Arguments (bounded) | Result |
|---|---|---|
| `search_entities` | `query`, `labels?`, `limit<=25` | `[SearchHit]` |
| `get_entity` | `id` | node card: `NodeOut` + `degree` + `edge_type_counts` + up to 10 alerts on it + TI summary |
| `get_neighborhood` | `id`, `depth<=2`, `edge_types?`, `labels?`, `max_nodes<=100` | `GraphFragment` |
| `find_paths` | `src_id`, `dst_id`, `max_hops<=6`, `k<=3` | `GraphFragment` with paths |
| `blast_radius` | `id`, `depth<=5` | `BlastRadiusResult` (fragment capped at 100 nodes) |
| `attack_paths` | `through_id?`, `target_id?`, `k<=5` | `[AttackPathOut]` (fragments capped) |
| `list_alerts` | `sort`, `band?`, `severity?`, `source?`, `storyline_id?`, `reaches_crown_jewel?`, `q?`, `limit<=50` | `[AlertSummary]` + total |
| `get_alert` | `alert_id` | `AlertSummary` + `flat_view` + `RiskBreakdown` + `[Insight]` + storyline summary (no large fragments) |
| `get_alert_context` | `alert_id` | `AlertContext` |
| `explain_risk` | `alert_id` | `RiskBreakdown` |
| `get_storyline` | `storyline_id` | `StorylineOut` |
| `list_storylines` | | `[StorylineOut]` (no fragments) |
| `threat_intel_lookup` | `value` (hash, ip, domain, CVE id, technique id, actor/campaign/report id or name) | `TIContext` |
| `exposed_hosts_with_exploited_vulns` | `sector_only=true` | question-5 table |
| `credential_joins` | | question-8 table |
| `alerts_reaching_crown_jewels` | `jewel_id?` | question-10 table |
| `identity_footprint` | `identity_id` | `BlastRadiusResult` |
| `simulate_containment` | `target_ids`, `actions` | `ContainmentSimulation` |
| `run_cypher` | `query`, `row_limit<=200` | rows + fragment (read-only; three-layer gate; `not_supported` on NetworkX) |
| `get_schema` | | labels, edge types, pairs, key properties, example queries |
| `submit_answer` | `narrative_md`, `findings[{statement, severity, evidence_ids}]`, `evidence_ids`, `confidence`, `followups` | terminates an LLM turn; evidence ids are validated against the turn's evidence set |

Every tool result that contains a fragment is also emitted as an `evidence` SSE event, and its node/edge ids are added to the turn's evidence set. `submit_answer` rejects evidence ids that were not returned by a tool in this turn (the model is told to only cite what it saw).
