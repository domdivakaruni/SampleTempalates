# Analyst Agent and Serving API (as built)

This document describes what `throughline/agent` and `throughline/api` actually do. The contract they implement is
docs/05-api-contract.md; the interfaces they consume are docs/06-build-plan.md sections 3.1 (`GraphStore`) and 3.2
(`AnalyticsEngine`). Everything here works with no API key, no graph database file and no web bundle: the offline
analyst answers, the NetworkX store serves every non-Cypher endpoint, and `GET /` returns a small JSON pointer when
`web/dist` has not been built.

## 1. Two analysts, one tool set

```
question ──► Analyst (facade, mode = request > constructor > settings.agent_mode)
               ├─ mode "llm"  ─► LLMAnalyst   (Claude tool-use loop)   ─┐
               └─ mode "offline" ► OfflineAnalyst (intent -> playbook)   ├─► ToolRegistry ─► AnalyticsEngine + GraphStore
                                                                         ┘
             AnalystAnswer {narrative_md, findings[evidence_ids], evidence: GraphFragment, confidence, followups, tool_calls, mode, intent, model}
```

Both analysts call the same `ToolRegistry` (`throughline/agent/tools.py`), so an answer looks the same to the UI whichever
path produced it: markdown with `## Findings / ## Evidence / ## Impact / ## Recommended actions`, node ids in backticks,
a merged `GraphFragment` the canvas can highlight, findings whose `evidence_ids` are guaranteed to have come back from a
tool in that turn, 2-3 follow-up questions and the tool-call trace.

### Mode resolution

| `agent_mode` / request `mode` | key or client available | effective |
|---|---|---|
| `offline` | any | offline |
| `llm` | yes | llm; API errors produce an `error` event and an error answer with `mode: "llm"` (no silent fallback) |
| `llm` | no | offline, after an `error` event `no_api_key` |
| `auto` (default) | yes | llm; SDK errors (`APIConnectionError`, `RateLimitError`, `APIStatusError`), refusals and budget failures emit an `error` event and the **offline analyst answers the same question** (`mode: "offline"`) |
| `auto` | no | offline |

`Analyst(registry, settings=None, *, mode=None, sessions=None, client_factory=None)`; `analyst.answer(question, context, mode)`
is synchronous (CLI, `POST /agent/answer`), `analyst.stream(session_id, ChatMessageIn)` is the async `ChatEvent` iterator
behind the SSE endpoint, `analyst.respond(session_id, message)` is the non-streaming chat turn.

### The LLM analyst (`agent/llm.py`)

* `anthropic.Anthropic()` (key from `ANTHROPIC_API_KEY` / settings), model `settings.anthropic_model` (default
  `claude-opus-5`), `max_tokens` 16000, adaptive thinking (`{"type": "adaptive", "display": "summarized"}`, no
  `budget_tokens`), `output_config={"effort": settings.agent_effort}`, `tool_choice={"type": "auto"}`.
* Streaming through `client.beta.messages.stream(..., betas=["server-side-fallback-2026-07-01"], fallbacks="default")`
  when `agent_enable_fallbacks` is true (default), else `client.messages.stream(...)`. The model that actually served the
  turn is recorded in `AnalystAnswer.model`.
* System prompt = one text block with `cache_control: {"type": "ephemeral"}`; tool definitions are emitted in a fixed
  order; the volatile canvas context (`alert_id`, `selected_node_ids`, `storyline_id`) rides in the user message as
  data, so the cached prefix is stable across turns.
* Manual loop: every `tool_use` block of a response is executed (independent calls in parallel), and **all** `tool_result`
  blocks are returned in **one** user message, in block order; `end_turn` finishes, `pause_turn` continues,
  `max_tokens` asks the model to continue once, `refusal` surfaces `stop_details` in an `error` event. Unknown tools,
  invalid arguments and engine errors become `is_error` tool results the model can react to.
* Tool results sent to the model are compact JSON (ids and summaries; fragments are reduced to counts + node briefs,
  bounded to ~12 KB). Fragments go to the UI instead, as `evidence` SSE events, and their node/edge ids form the turn's
  evidence set. `submit_answer` ends the turn; evidence ids the model cites that no tool returned are dropped and the
  narrative gets a visible note.
* Budgets: `agent_max_tool_calls` (default 12; the model is told when it is exhausted), `agent_max_rounds` (default 8),
  120 s wall clock. Exhaustion produces an `error` event `budget_exhausted` and a partial answer with the evidence
  gathered so far.

### The offline analyst (`agent/offline.py`)

Deterministic, no model, sub-second. Pipeline per question:

1. **Classify** with weighted regex rules -> one of the intents below (score < 2 -> `help`).
2. **Link entities** through `search_entities`: explicit node ids, hostnames (`BAS-01`, `WKS-3391`, `stmt-render-2a`),
   alert refs (`ldt-a009`), role names, `larkspur-*` bucket names, CVE / technique ids, IPs / hashes / domains, quoted
   strings ("S3 bucket public"), capitalised actor/report names (Cinder Jackal), plus a last-resort word search for
   entity-centric questions ("the bastion", "cardholder vault"). Canvas context resolves "this alert" / "this host" /
   "this storyline" (`alert_id`, `selected_node_ids`, `storyline_id`).
3. **Playbook**: an ordered sequence of tool calls (the same `ToolRegistry`), every fragment merged into the answer's
   evidence, every cited id validated against it (cited nodes missing from the fragment are fetched from the store so
   the canvas can highlight them).
4. **Narrative**: templated markdown with the four sections, findings with severities, confidence, follow-ups.

| intent | demo question | tools |
|---|---|---|
| `blast_radius_of_alert` | 1 | `search_entities`, `list_alerts`, `get_alert`, `blast_radius`, `find_paths` |
| `medium_alerts_with_data_path` | 2 | `alerts_with_data_path`, `get_alert_context` |
| `cloud_activity_related_to_endpoint` | 3 | `search_entities`, `get_entity`, `credential_joins`, `get_neighborhood` |
| `identity_footprint` | 4 | `search_entities`, `get_entity`, `identity_footprint` |
| `exposed_exploited_hosts` | 5 | `exposed_hosts_with_exploited_vulns` |
| `rank_alerts_explain_top` | 6 | `list_alerts`, `explain_risk` x3 |
| `attack_path_from_alert` | 7 | `search_entities`, `list_alerts`, `get_alert`, `attack_paths`, `get_storyline` |
| `credential_joins` | 8 | `credential_joins` |
| `ioc_ttp_matches_for_actor_or_report` | 9 | `threat_intel_lookup`, `list_alerts`, `get_neighborhood`, `get_storyline` |
| `alerts_reaching_crown_jewels` | 10 | `alerts_reaching_crown_jewels`, `list_alerts` |
| `is_alert_actually_risky` | 11 | `list_alerts` / `search_entities`, `get_alert`, `get_entity`, `threat_intel_lookup` |
| `containment_simulation` | 12 | `search_entities`, `get_alert`, `simulate_containment` |
| generic: `alerts_on_entity`, `what_is_entity`, `neighborhood_of_entity`, `why_is_alert_risky`, `summarize_storyline`, `list_storylines`, `help` | | `get_entity`, `get_neighborhood`, `get_alert`, `explain_risk`, `get_storyline`, `list_storylines` |

Unknown or unresolvable questions return intent `help` (confidence 0.2) with the demo questions as suggestions
rather than binding to a random node.

## 2. Tool set (`agent/tools.py`)

One `Tool` per row of 05 section 7.1, each with a pydantic argument model (`extra="forbid"`, bounds clamped:
`limit<=25`, `depth<=2` for neighbourhoods, `depth<=5` for blast radius, `max_hops<=6`, `k<=3`/`5`, `row_limit<=200`),
turned into an Anthropic **strict** tool definition (`strict: true`, `additionalProperties: false`, `required`, no
numeric/string constraints, `$ref`s inlined). `run(name, args) -> ToolResult{result, evidence, summary, result_ids}`.

`search_entities`, `get_entity`, `get_neighborhood`, `find_paths`, `blast_radius`, `attack_paths`, `list_alerts`,
`get_alert`, `get_alert_context`, `explain_risk`, `get_storyline`, `list_storylines`, `threat_intel_lookup`,
`exposed_hosts_with_exploited_vulns`, `credential_joins`, `alerts_reaching_crown_jewels`, `identity_footprint`,
`simulate_containment`, `run_cypher`, `get_schema`, `submit_answer`, plus one addition beyond the contract table:
`alerts_with_data_path` (question 2, mirrors `GET /investigate/medium-alerts-with-data-path`).

* `run_cypher` calls `store.run_readonly_cypher` (three-layer read-only gate inside the store, 3 s timeout) and returns
  `{status: "not_supported", hint}` instead of failing when the backend has no Cypher engine (NetworkX). Node and
  relationship values in rows are collected into a fragment.
* `submit_answer` is a pseudo-tool: inside an LLM turn it terminates the loop and its evidence ids are validated
  against the turn's evidence set; over REST it just echoes the structured answer (`mode: "llm"`).
* Fragments are capped (blast radius 100 nodes, paths 60, storylines 150) before they leave the tool.

## 3. Safety

* Read-only by construction: no tool or endpoint mutates the graph; `simulate_containment` is a what-if.
* Cypher passes the store's read-only gate; the API returns 400 `query_rejected` on gate failure, 501 `not_supported`
  on NetworkX, 504 `timeout` after 3 s, and rows are capped (200 default / 500 hard).
* Grounding: the model may only cite ids that a tool returned in the same turn (`submit_answer` validation), and the
  system prompt tells it that names, titles, command lines and report text inside tool results are data, never
  instructions. The offline analyst's findings are validated the same way.
* Tool arguments are validated (unknown fields rejected, labels and edge types checked against the schema registry,
  bounds clamped) before anything reaches the engine or the store.
* Budgets bound every turn (tool calls, rounds, wall clock); sessions are in-memory, bounded (LRU 500) and hold only
  canvas context plus turns.

## 4. REST surface for external agents

An external agent (or a script) can drive the same tools without the chat UI:

| call | purpose |
|---|---|
| `GET /api/v1/agent/tools` | `{tools: [{name, description, input_schema, strict}]}` - paste straight into an Anthropic `tools=` parameter |
| `POST /api/v1/agent/tools/{name}` with the tool arguments | `{result, evidence: GraphFragment | null, elapsed_ms, summary}`; 404 `not_found` for unknown tools, 400 `invalid_argument` with pydantic error details |
| `POST /api/v1/agent/answer` `{question, context?, mode?}` | full `AnalystAnswer`, non-streaming |
| `POST /api/v1/chat/sessions` -> `POST /api/v1/chat/sessions/{id}/messages` | SSE stream (`session`, `text_delta`, `thinking`, `tool_call`, `tool_result`, `evidence`, `answer`, `error`, `done`); `?stream=false` returns `{turn}` |
| `GET /api/v1/schema`, `GET /api/v1/stats` | labels, edge types, pairs and counts for query planning |
| `POST /api/v1/graph/cypher` | read-only Cypher on the embedded backend |

Typed investigation endpoints under `/api/v1/investigate/*`, the graph endpoints under `/api/v1/graph/*` and the
threat-intel endpoints under `/api/v1/threat-intel/*` return the same pydantic shapes as the tools (docs/05 sections
2-5). Errors are always `{"error": {"code", "message", "details"}}`; limits above the hard caps are 400
`limit_exceeded`, unknown ids 404 `not_found`.

## 5. Runtime, CLI and environment

`api/app.py` `create_app(graph=None, store=None, engine=None, analyst=None, *, registry=None, settings=None, web_dist=None)`.
With nothing injected the lifespan loads `ContextGraph` via `throughline.graph.loader.load_context_graph(settings.data_dir)`,
picks the store with `throughline.graph.factory.make_store(settings, graph)` (falls back to the NetworkX store when the
database file or engine is missing), builds `AnalyticsEngine(graph)`, the `ToolRegistry` and the `Analyst`. If the data
is missing the process still starts and `GET /api/v1/health` reports `status: "degraded"` with the error. The web bundle
in `settings.web_dist` is served at `/` with an SPA fallback; `/api/*` misses never fall back to the SPA.

```
throughline serve [--host] [--port] [--reload]      # uvicorn, factory app
throughline ask "question" [--alert ID] [--node ID] [--storyline ID] [--mode offline|llm|auto] [--json]
throughline build-data                              # throughline.simulator.build.main
throughline demo                                    # build data if missing, then serve
python scripts/demo_questions.py --mode offline     # the twelve questions end to end
```

| variable | default | meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | enables the LLM analyst in `auto` / `llm` mode |
| `ANTHROPIC_MODEL` | `claude-opus-5` | model id for the LLM analyst |
| `AGENT_MODE` | `auto` | `auto` / `llm` / `offline` (per-request `mode` overrides) |
| `AGENT_EFFORT` | `high` | `output_config.effort`: low / medium / high / xhigh / max |
| `AGENT_ENABLE_FALLBACKS` | `true` | server-side fallbacks beta (`fallbacks="default"`) |
| `AGENT_MAX_TOOL_CALLS` / `AGENT_MAX_ROUNDS` | 12 / 8 | per-turn budgets |
| `DATA_DIR` | `data/generated` | canonical `graph/nodes.jsonl`, `edges.jsonl`, `manifest.json` |
| `GRAPH_BACKEND` / `GRAPH_DB_PATH` | `ladybug` / `data/generated/graph.lbdb` | store selection (NetworkX fallback when the file is missing) |
| `API_HOST` / `API_PORT` / `LOG_LEVEL` | `127.0.0.1` / 8000 / `info` | serving |
| `WEB_DIST` | `web/dist` | production UI bundle |
| `CYPHER_ROW_LIMIT` / `CYPHER_TIMEOUT_MS` | 200 / 3000 | Cypher defaults |

## 6. Tests

`python -m pytest tests/api -q` (no data, no key, no database): `test_endpoints.py` (every endpoint, limits, error
envelope, SSE stream, agent surface, SPA fallback, over `FakeEngine`/`FakeStore` from `tests/api/fakes.py`),
`test_offline_analyst.py` (the twelve demo questions phrased as in docs/04 section 6 plus generic intents, canvas
context and unknown questions), `test_llm_loop.py` (the Claude loop against `tests/api/fake_anthropic.py`: request
shape, parallel tool results in one message, submit_answer validation, stop reasons, SDK-error fallbacks, budgets).
`tests/scenarios/test_demo_questions.py` runs the same questions against the generated dataset once `make data` has run.
