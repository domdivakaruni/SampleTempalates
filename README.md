# Throughline

**A security context graph that fuses cloud posture, endpoint (EDR) telemetry and threat-intelligence impact, so a
human or an AI analyst can ask questions about an alert and get answers no single tool can give.**

Throughline is a working prototype built by a (fictional) startup for human and agent security analysts. It extends a
Wiz-style cloud security graph with CrowdStrike Falcon / Cortex XDR-style endpoint telemetry and with impact
metadata derived from threat-intel reports, and puts a graph explorer, a re-ranked alert queue and a chat-based
analyst on top. Everything in the repository is simulated: the customer (Larkspur Financial), its estate, the
intrusions, the threat actors and the intel reports are fictional.

> Status: prototype. One command runs the whole thing on a laptop with no infrastructure (an embedded graph
> database). See `docs/` for the product definition, architecture decisions, data model and storyline.

## What it demonstrates

The estate is under two simultaneous, fictional attacks plus realistic background noise:

* **EMBERCAST (Cinder Jackal)**: phishing on a finance workstation, credential theft, SSH to a bastion that is also a
  cloud VM, instance-metadata credential theft, cross-account role assumption, and collection from the cardholder
  data vault. The EDR sees a handful of medium alerts on two hosts; the cloud audit log sees "valid" API calls. Only
  the graph joins them into one seven-stage storyline whose blast radius is PCI data.
* **SALTWORKS (Hollow Tide)**: mass exploitation of Log4Shell on an internet-facing statement-rendering service. One
  medium WAF alert among thousands becomes the second-highest priority because the graph knows the host is exposed,
  vulnerable, actively targeted by an actor working against fintechs, and holds a role that reaches database
  credentials.
* **Noise**: an EICAR test file rated High, a Critical "public S3 bucket" finding on marketing assets, an admin's
  PsExec inside an approved change window, an executive's impossible-travel login over VPN, scanner traffic.

The contextual score re-ranks the queue: a vendor *Medium* becomes #1 (score >= 90) and a vendor *Critical* drops to
noise (<= 25), each with a visible factor breakdown. The analyst chat answers questions such as:

1. Show me everything connected to the credential-dumping alert on BAS-01. What can an attacker reach from here?
2. Which of today's medium-severity endpoint alerts sit on assets with a path to regulated data?
3. Is the cloud API activity from the bastion role related to any endpoint detection?
4. What is the blast radius if the bastion role is fully compromised?
5. Which internet-exposed hosts have a vulnerability an actor is actively exploiting against fintechs right now?
6. Rank all open alerts by contextual risk, not vendor severity, and explain the top 3.
7. Trace the full attack path from the phishing detection on WKS-3391 to any regulated data store.
8. Which credentials used in cloud API calls today were seen being stolen on an endpoint?
9. Do any current detections match IOCs or TTPs from the Cinder Jackal report, and what do they touch?
10. Show only alerts on assets that can reach cardholder data.
11. Is the "S3 bucket public" critical finding actually risky?
12. If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?

Every answer is grounded in graph traversals, cites node ids, and highlights its evidence subgraph on the canvas.
The same typed tools power the UI, the chat (Claude with tool use when an API key is present, a deterministic
playbook analyst otherwise) and a REST surface for external AI agents.

## Quick start

Requirements: Python 3.11+, Node 22+. No Docker, no database server.

```bash
make setup      # python venv + dependencies, web dependencies
make demo       # simulate the estate, enrich it, build the embedded graph DB, build the UI, serve on :8000
```

Then open http://127.0.0.1:8000. Optional: put `ANTHROPIC_API_KEY=...` in `.env` to switch the analyst from the
offline playbooks to Claude (`claude-opus-5` by default, configurable with `ANTHROPIC_MODEL`).

Other useful commands:

```bash
make data                       # regenerate the dataset (deterministic; seed in .env)
make ask Q="Which credentials used in cloud API calls today were seen being stolen on an endpoint?"
.venv/bin/python scripts/demo_questions.py      # run the twelve demo questions through the offline analyst
make test                       # unit, conformance, API and scenario tests
make dev                        # API with reload + Vite dev server (http://localhost:5173)
```

## Architecture in one paragraph

Simulated connectors emit vendor-shaped feeds (Wiz-like inventory and issues, Falcon-like devices and detections,
CloudTrail-like events, WAF/IDS/Okta alerts, STIX-like intel). Normalizers and entity resolution (EDR device to
cloud VM, endpoint users to identities, credentials as first-class join keys) produce a canonical property graph
(`data/generated/graph/nodes.jsonl`, `edges.jsonl`). The analytics library enriches it at build time (IOC matching,
exploited-CVE overlays, lateral movement, storyline correlation, explainable contextual scores) and answers on-demand
questions (blast radius, attack paths, credential joins, containment simulation) on an in-process NetworkX
projection. The graph is loaded into an embedded Cypher graph database (LadybugDB, the maintained fork of Kuzu) that
the UI's Cypher panel and the agent's read-only `run_cypher` tool query; a Neo4j adapter provides the server-side
path, and the table-per-label layout maps directly onto BigQuery Graph property-graph definitions for
analytics at scale later. FastAPI serves the REST API, the SSE chat stream and the React/Cytoscape UI.

```
feeds (simulated) -> normalize + resolve -> canonical graph JSONL -> enrich (analytics) -> LadybugDB + NetworkX
                                                                                              |
                                              React + Cytoscape UI  <-  FastAPI + SSE  <-  AnalyticsEngine + ToolRegistry
                                              Claude / offline analyst  <-----------------------'
```

## Repository map

| Path | What |
|---|---|
| `docs/01-product-definition.md` | Product, users, graph-advantage questions, scoring concept, demo script |
| `docs/02-architecture.md` | Architecture decision record incl. graph database comparison and founder decisions |
| `docs/03-graph-schema.md` | Labels, typed properties, relationship types, id scheme, entity resolution |
| `docs/04-storyline.md` | The simulated customer, the two intrusions, the noise, ground truth for tests |
| `docs/05-api-contract.md` | REST API, SSE chat protocol, agent tool set |
| `docs/06-build-plan.md` | Module ownership and Python interfaces |
| `docs/07-agent-and-api.md` | How the analyst agent works and how external agents use the API |
| `throughline/simulator/` | Deterministic estate, telemetry and threat-intel simulation; `build.py` pipeline |
| `throughline/graph/` | `ContextGraph` projection, `GraphStore` backends (LadybugDB/Kuzu, NetworkX, Neo4j), loader |
| `throughline/analytics/` | Enrichment, scoring, blast radius, attack paths, correlation, insights, containment |
| `throughline/agent/` | Tool registry, Claude tool-use loop, offline playbook analyst |
| `throughline/api/` | FastAPI application and routers |
| `web/` | React + TypeScript + Cytoscape UI |
| `tests/` | unit, backend conformance, API and scenario tests |

## Fiction and safety notes

All organisations, people, threat actors, campaigns, malware, domains, hashes and reports are fictional. External IP
addresses use documentation ranges. Real CVE identifiers appear for realism; any attribution to a fictional actor is
fictional. The analyst agent only has read-only tools; Cypher from the agent or the UI passes a statement gate, a
read-only database handle and a timeout.

## License

Apache-2.0.
