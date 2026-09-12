# Critique and Improvement Log

After the first end-to-end build, the prototype was reviewed as a skeptical founder and as a SOC analyst would review
it: every screen on the real dataset, every demo question, the API under load, a fresh clone of the repository, and
the data for realism. Each round lists what was found and what changed.

## Round 1: correctness on real data

| Finding | Change |
|---|---|
| Background WAF/IDS/EDR noise matched threat-intel indicators by accident because indicators, estate public IPs and noise sources all drew from the same two documentation /24 ranges (about 120 spurious IOC matches, 38 storylines before the analytics hardened) | Disjoint address blocks per generator (`storyline_constants.IP_BLOCK_*`); IOC matches dropped to the 17 intended ones |
| Storyline stages placed the SSH lateral-movement alert and the cloud-anomaly alert under "Initial Access" because ATT&CK files "Valid Accounts" (T1078) under that tactic | Valid Accounts techniques are stage-neutral; members with only neutral techniques inherit the stage of the closest earlier member in time |
| The evidence graph of a noise alert on a public bucket showed 40 human users with SSO access to it, which made the "this is noise" moment look busy | Non-storyline alert evidence caps 2-hop fan-in at six nodes per label, preferring alerts, storyline members and sensitive or exposed assets |
| The Cypher console fell back to built-in examples because `GET /schema` did not expose the store's example queries | The schema endpoint merges backend, dialect, notes and `example_queries` from the active store |
| Intel report pages showed "no match" for indicators that had matched in the estate | The report endpoint returns per-indicator matches (`matches: TIMatch[]`) |
| Attack-path stage for the VM hop printed "unknown time"; containment recommendations were machine-style lowercase action ids | Stage times carry forward through telemetry-less hops; recommendations are sentences |
| A dashboard tile label truncated at 1440 px | Renamed |
| Killing the dev server with a process-pattern search matched the calling shell | `scripts/serve.sh` and `scripts/stop.sh` |
| No continuous integration | GitHub Actions: lint, dataset build, tests, web lint and build |

## Round 2: usability and fidelity

| Finding | Change |
|---|---|
| Offline analyst answers repeated 120-character node descriptors several times per finding | A node or alert is described in full on first mention and by id afterwards (per-answer context variable) |
| Fresh-clone quick start had never been exercised | `make setup`, `make data`, `make web` verified on a clean clone (about 3 minutes) |
| API latency unknown under the real dataset | Measured: dashboard 140 ms, alert context 25 ms, blast radius 8 ms, search 30 ms warm (400 ms cold, index build) |
| Example Cypher queries returned duplicate rows when several role chains reach the same bucket | Examples use `RETURN DISTINCT` |
| README lacked a demo walkthrough | Five-minute demo section |

## Round 3: final checks

| Check | Result |
|---|---|
| Data sweep: 105 noise alerts (WAF, IDS, EDR) carried detection times later than the simulation clock because "today" was spread over 24 hours | The shared alert constructor moves any post-clock time back one day; zero future-dated alerts, events or logons |
| Data sweep: vendor severities, contextual bands, per-entity alert counts, crown-jewel fan-in, sensor coverage and degree outliers | All within expected ranges (46 vendor-critical alerts: 19 land in noise, 1 in high) |
| Full Python suite (unit, conformance, API, scenarios) | green |
| Web lint and production build | clean |
| Screenshots regenerated from the running prototype | `docs/screenshots/` |
| Known limitations recorded | README "Status and limitations"; docs/07 safety notes |

## Open items worth a next iteration

- The Claude path is verified with a fake client only; run `scripts/demo_questions.py --mode llm` with an API key and compare against the offline answers (evidence recall, faithfulness).
- Neo4j backend: run the conformance suite against a real server (`NEO4J_URI`).
- The simulator's noise WAF alerts against the exposed Log4Shell host legitimately score in the high band; a real product would fold them into the SALTWORKS storyline when they share infrastructure.
- Storyline "stage" counts follow ATT&CK tactic mapping; a narrative "step" view (the seven rows of the product definition) could sit alongside it.
