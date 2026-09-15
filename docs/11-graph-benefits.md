# Why a graph? The benefits, measured

The question this document answers: what does the security context graph actually buy us, and can every demo
scenario be answered without one? The short version: yes, every scenario can be answered without a graph, and we
proved it by doing so. What the graph buys is not *possibility*; it is work, time, query complexity and the
number of things a human or an agent has to know to get the answer right. The numbers below come from
`scripts/graph_vs_sql.py`, which runs the twelve demo questions of [docs/04](04-storyline.md) through four tiers on
the same simulated estate and checks that they agree. The full per-question table is regenerated into
[benchmarks/graph_vs_sql.md](benchmarks/graph_vs_sql.md); the raw numbers are in `benchmarks/graph_vs_sql.json`.

## 1. The experiment

| Tier | What it is | What it tests |
|---|---|---|
| `graph` | The product's in-process context graph (`ContextGraph`, the move rules of `analytics/semantics.py`) queried by a breadth-first traversal | The graph model and an adjacency-indexed engine |
| `sql-norm` | DuckDB over the normalised graph tables (`nodes`, `edges`) with the same move rules as one SQL view | The graph *model* on a relational engine: "do you need a graph database?" |
| `sql-raw` | DuckDB over the raw vendor feeds (Wiz resources, IAM, vulnerabilities; Falcon devices, detections, processes, logons, network connections; CloudTrail; Okta; IDS; WAF; STIX threat intel) with every join, entity resolution and access derivation written into the query | No graph at all: "do you need the graph *model*?" |
| `graph-db` | The embedded LadybugDB the product ships for the Cypher console | A disk-based graph database and its query language |

Same questions, same data, answers cross-checked (set agreement between tiers is recorded for every question).
Timings are medians of five runs after a warm-up, on four cores; DuckDB uses all four, the graph tier is
single-threaded Python. `--replicate 3,10` clones the estate to 64k and 214k nodes (242k and 806k edges) to see how
each tier grows; the raw tier only runs on the real feeds.

The questions fall into two families. **Traversal questions** ask "what is connected to X within k moves" in some
direction with some semantics: blast radius (Q1, Q4), which alerts can reach regulated data (Q2, Q6, Q10), the
shortest attack path (Q7), containment simulation (Q12), what can reach a bucket (Q11). **Join questions** have a
fixed shape: events of a role near detections on its machine (Q3), exposed hosts with an exploited vulnerability (Q5),
keys used in the cloud after a credential theft (Q8), indicator and technique matches from a report (Q9).

## 2. Results

Wall time per question, estate of 21k nodes / 81k edges (x1), plus the x10 estate for the tiers that scale:

| Question | graph x1 | sql-norm x1 | sql-raw x1 | graph-db x1 | graph x10 | sql-norm x10 |
|---|---:|---:|---:|---:|---:|---:|
| Q1 blast radius of the bastion alert | 0.01 ms | 11 ms | 780 ms | 11 ms (52% of the answer) | 0.01 ms | 22 ms |
| Q4 footprint of the bastion role | 0.00 ms | 6.3 ms | 476 ms | 9.1 ms | 0.00 ms | 11 ms |
| Q10 alerts that can reach the cardholder vault (reverse) | 0.1 ms | 11 ms |  | 8.4 ms (23% of the answer) | 0.2 ms | 32 ms |
| Q7 shortest path, phishing alert to regulated data | 0.01 ms | 23 ms |  |  | 0.01 ms | 71 ms |
| Q12 containment: isolate bas-01, rotate the role | 0.01 ms | 20 ms |  |  | 0.01 ms | 73 ms |
| Q11 the public bucket: contents and who can reach it | 0.2 ms | 12 ms |  |  | 0.2 ms | 49 ms |
| Q2 medium endpoint alerts with a path to regulated data (173 roots; 1,730 at x10) | 0.8 ms | 27 ms |  |  | 12 ms | 113 ms |
| Q6 crown-jewel reach for every alert, the scoring input (1,666 roots; 16,660 at x10) | 6.7 ms | 72 ms |  |  | 105 ms | 529 ms |
| Q3 bastion-role events near endpoint detections | 0.07 ms |  | 7.0 ms |  | 0.06 ms |  |
| Q5 exposed hosts with an actively exploited vulnerability | 0.7 ms |  | 4.5 ms | 3.8 ms | 10 ms |  |
| Q8 cloud keys used after a credential theft on an endpoint | 0.04 ms |  | 3.3 ms |  | 0.3 ms |  |
| Q9 report indicators and techniques matched, endpoints touched | 1.7 ms |  | 5.1 ms |  | 36 ms |  |

Every answer agrees across tiers (Jaccard 1.0 on every traversal question at every size; the raw tier reproduces
the graph's reach set exactly once its joins are right; join questions agree on the comparable parts). The
benchmark traversal also matches the product's own blast radius exactly (Jaccard 1.0 against
`AnalyticsContext.reach`).

Work done to get the same 19-node answer to Q1, and how it grows with the estate:

| Estate | graph: nodes settled | sql-norm: rows produced by all operators |
|---|---:|---:|
| x1 (21k nodes) | 20 | 46,659 |
| x3 (64k nodes) | 20 | 139,363 |
| x10 (214k nodes) | 20 | 503,582 |

Query text a human or an agent has to write (characters, whitespace collapsed):

| Tier | Traversal question | Join question |
|---|---:|---:|
| graph | 20 to 70 (a call such as `reach(alert, depth=4)`) | 65 to 101 |
| sql-norm | 258 to 516 (one recursive query, reused for every traversal question) | 419 |
| sql-raw | 5,059 (every join and derivation inlined) | 474 to 1,006 |
| graph-db (Cypher) | 112 to 166 | 216 |

Cost to have the structure at all (x1, then x10): the graph loads in 0.8 s and builds its move index in 0.6 s
(7.9 s + 5.8 s at x10); DuckDB loads the same tables in 0.6 s and builds the moves view in 0.05 s (5.1 s + 0.2 s);
the raw feeds load in 0.7 s and need nothing else. The graph is the most expensive tier to build and hold in memory;
that is the price of the query-time numbers.

## 3. What the numbers say, benefit by benefit

**1. Query-time cost and performance (the hypothesis).** Confirmed, with a boundary. On traversal questions the
graph answers in microseconds where SQL over the same model takes 6 to 70 ms and SQL over the raw feeds takes half
a second to a second. On join questions the advantage disappears: 3 to 7 ms in SQL against 0.03 to 2 ms in the
graph, the same order of magnitude, and a warehouse would call that fine. The graph wins on the questions that are
about *reach*, which is most of what makes the demo interesting, and ties on the rest.

**2. Work proportional to the answer, not to the estate.** This is the mechanism behind benefit 1 and the reason it
holds at scale. The graph settled 20 nodes for Q1 whether the estate had 21k or 214k nodes; DuckDB's operators
produced 47k rows at x1 and 503k at x10 for the same 19-node answer, because every iteration of a recursive join
scans the edge table. Wall time followed: constant for the graph, 11 ms to 22 ms for SQL. For a per-query-billed
warehouse, work is money; for an interactive analyst or an agent making six tool calls per question, it is latency.

**3. The joins are done once, at ingest.** The raw tier had to rebuild entity resolution (Falcon device to cloud
instance), the role attachment of instances, role assumption, effective access from policy documents, and exposure
inside every reachability query; that is where its 0.5 to 0.8 s goes. More telling than the time: getting those
joins right took four rounds, because each one needs vendor knowledge that lives nowhere in the data. CloudTrail
names a role through its STS assumed-role ARN, not the IAM ARN. Wiz calls internet exposure `internet`, not
`public`. A policy wildcard for a secret expects the random suffix real secret ARNs carry. A grant on
`bucket/prefix/*` is access to the bucket. The graph encodes each of these once (`simulator/inventory/posture.py`,
`analytics/semantics.py`); every consumer, human or agent, inherits them.

**4. One query shape for every question.** The same 258-character recursive query answered Q1, Q4, Q10, Q11 and
Q12 in the SQL-over-graph tier, and the same 40-character call answered them in the graph; only the root, the
direction and the depth changed. The raw tier needed a different query per question, 5,000 characters for the
reachability ones. For an agent this is the difference between a fixed tool surface of six typed calls (what the
analyst uses today) and writing SQL against 24 tables with vendor-specific join keys. Fewer tokens, fewer wrong
joins, and the agent cannot ask a question the model does not support.

**5. Direction and depth are free parameters.** "What can this alert reach" and "what can reach this bucket" are
the same operation run backwards (Q1 and Q10). Containment simulation is the same traversal with three moves
blocked (Q12: 0.01 ms for the before-and-after comparison; in SQL it is a query rewrite; in the raw tier a
re-derivation). Counterfactuals such as "if we enforce IMDSv2 on every internet-facing VM, how many paths
disappear" are the same trick and cost the same.

**6. The answer is a path, not a count.** Q7 returns the six-hop path from the phishing alert through the
workstation, the bastion, the instance, two roles and into the vault, which is what an analyst reads and what the
UI draws. Traversal produces the evidence as a by-product; a join produces a number, and the explanation is a
second query.

**7. Whole-population questions stay affordable.** Scoring every alert needs a reach per alert (Q6). Both tiers
grow linearly with the alert count, but the graph did 16,660 reaches in 105 ms against 529 ms in SQL, and it can
do them incrementally when a new alert arrives instead of recomputing the population.

## 4. What the graph does not buy you

- **Not correctness.** Every scenario was answered without a graph, exactly. The graph is an efficiency and
  ergonomics argument, not a capability argument, and the pitch should say so.
- **Not join questions.** Fixed-shape joins (Q3, Q5, Q8, Q9) are what SQL engines are built for; there is nothing
  to win there and a customer's warehouse already has the data.
- **Not the storage engine, at this scale.** The embedded graph database answered Q4 and Q5 exactly in 4 to 9 ms,
  about the same as DuckDB over the normalised tables, not the microseconds of the in-memory traversal. And its
  query language could not express the product's semantics: Cypher's variable-length patterns run in one
  direction, while the move rules go both ways through `SAME_AS` and `PRIMARY_USER` and backwards through
  `DERIVED_FROM` and `HAS_NODE`. The forward-only approximation found 52% of the Q1 answer and 23% of Q10. The
  in-memory projection exists because the analytics need semantics a query language does not have.
- **Not free.** The graph is the most expensive tier to build (1.5 s at x1, 14 s at x10) and to keep in memory.
  On a laptop-sized estate that is invisible; at millions of nodes it is an engineering budget.

## 5. What this means for the product

- **The differentiator is the model and the analytics, not the database.** Tier 2 shows that the graph model with
  its move semantics can run on a relational engine at acceptable interactive latency (tens of milliseconds at
  214k nodes). That is the answer to "can this live in our warehouse": yes, as the normalised tables plus the
  moves view, with the in-memory projection reserved for the per-alert scoring loop and the path analytics. It is
  also the honest framing for BigQuery Graph or a customer's Snowflake: the graph *model* travels; the traversal
  engine is an optimisation we can place wherever the latency budget says.
- **The ingest-time joins are the product.** Benefit 3 is where the vendor knowledge accumulates: entity
  resolution across EDR and cloud, effective access from policies, exposure from network rules, credential
  lineage from telemetry. Nobody's warehouse has those joins written down, and every raw-tier query in this
  benchmark had to reinvent them. That is what to protect and extend.
- **For agents, the graph is a small tool surface.** Six typed calls, each answering in under a millisecond,
  with the evidence attached. The benchmark's query-length column is a proxy for tokens and for the number of
  ways an agent can be wrong.

## 6. Reproduce

```bash
.venv/bin/pip install duckdb                       # in the dev extras as well
.venv/bin/python scripts/graph_vs_sql.py --replicate 1,3,10 --runs 5
# writes docs/benchmarks/graph_vs_sql.json and docs/benchmarks/graph_vs_sql.md
make bench                                        # the same, at x1 only
```

The script builds the dataset if `data/generated` is missing. `--threads 1` pins DuckDB to one core for a
like-for-like comparison with the single-threaded graph tier; `--no-cypher` skips the embedded database.
