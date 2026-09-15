#!/usr/bin/env python3
"""Does the security context graph earn its keep? Benchmark the twelve demo questions with and without a graph.

Three tiers answer the same questions on the same simulated estate (docs/04-storyline.md):

* ``graph``    the in-process context graph the product uses (``ContextGraph`` + the move semantics of
               ``throughline.analytics.semantics``), queried with a breadth-first traversal;
* ``sql-norm`` DuckDB over the normalised graph tables (``nodes``/``edges`` with the same move rules as a view):
               "a graph model, but a relational engine";
* ``sql-raw``  DuckDB over the raw vendor feeds (Wiz, Falcon, CloudTrail, Okta, IDS, WAF, threat intel) with every
               join, entity resolution and access derivation written into the query: "no graph at all".

For each question and tier the script records the median wall time, the work done (nodes settled for the graph,
rows produced by every DuckDB operator for SQL), the length of the query text, and whether the answers agree.
``--replicate N`` clones the estate N times (ids suffixed ``~k``; the Internet singleton stays shared) so the
graph and normalised-SQL tiers can be compared as the estate grows.

Usage::

    .venv/bin/python scripts/graph_vs_sql.py [--data data/generated] [--replicate 1,3,10] [--runs 5]
        [--out docs/benchmarks/graph_vs_sql.json] [--markdown docs/benchmarks/graph_vs_sql.md]
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import tempfile
import time
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import duckdb  # noqa: E402

from throughline.analytics import semantics as sem  # noqa: E402
from throughline.analytics.context import AnalyticsContext  # noqa: E402
from throughline.graph.context_graph import ContextGraph  # noqa: E402
from throughline.simulator import storyline_constants as C  # noqa: E402

INTERNET = sem.INTERNET_ID
NOW = datetime.fromisoformat("2026-09-11T14:00:00+00:00")
DEPTH = 4
PATH_DEPTH = 6
HUB = sem.HUB_OUT_DEGREE
ALERT_A009 = C.ALERT_A["a009"][0]          # bastion IMDS credential access (vendor medium)
ALERT_A001 = C.ALERT_A["a001"][0]          # phishing on WKS-3391
ALERT_N002 = C.ALERT_N["n002"][0]          # "S3 bucket public" critical (noise)
BAS01_ENDPOINT = "endpoint:falcon:aid-bas01"
REGULATED = sorted(sem.REGULATED_CLASSES)

# The move rules of throughline.analytics.semantics.RULES, flattened for SQL: (edge type, direction, depth cost,
# access when forward, access when reverse). Probabilities are irrelevant for depth-bounded reachability.
RULES: list[tuple[str, str, int, bool, bool]] = []
for _t, _r in sem.RULES.items():
    RULES.append((_t, _r.direction, _r.depth_cost, _r.is_access("forward"), _r.is_access("reverse")))


# ============================================================================ helpers


def med_ms(fn: Callable[[], Any], runs: int) -> tuple[float, Any]:
    fn()  # warm-up (caches, JIT, page cache)
    times: list[float] = []
    out = None
    for _ in range(runs):
        t0 = time.perf_counter()
        out = fn()
        times.append((time.perf_counter() - t0) * 1000)
    return statistics.median(times), out


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def suffix(node_id: str, k: int) -> str:
    return node_id if k == 0 or node_id == INTERNET else f"{node_id}~{k}"


# ============================================================================ tier 1: the graph


class GraphTier:
    """The product's graph, with a benchmark-defined traversal (min semantic depth, same rules as the SQL view)."""

    name = "graph"

    def __init__(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
        t0 = time.perf_counter()
        self.g = ContextGraph.from_records(nodes, edges)
        self.ctx = AnalyticsContext(self.g)
        self.load_ms = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        self.out: dict[str, list[tuple[str, int, bool]]] = defaultdict(list)
        self.inn: dict[str, list[tuple[str, int, bool]]] = defaultdict(list)
        self._build_moves()
        self.index_ms = (time.perf_counter() - t0) * 1000

    # -- the move index: one pass over the edges, the graph equivalent of the SQL `moves` view
    def _build_moves(self) -> None:
        g = self.g
        raw: dict[tuple[str, str], tuple[int, bool]] = {}

        def add(u: str, v: str, cost: int, access: bool) -> None:
            if u == v or u == INTERNET:
                return
            cur = raw.get((u, v))
            if cur is None:
                raw[(u, v)] = (cost, access)
            else:
                raw[(u, v)] = (min(cur[0], cost), cur[1] or access)

        for t, direction, cost, acc_f, acc_r in RULES:
            for u, v, d in g.G.edges(data=True):
                if d.get("type") != t:
                    continue
                if t == "CAN_ACCESS" and d.get("transitive"):
                    continue
                if direction in ("forward", "both"):
                    add(u, v, cost, acc_f)
                if direction in ("reverse", "both"):
                    add(v, u, cost, acc_r)
        for label, key in (("StorageBucket", "contains_credentials_for"), ("Secret", "grants_access_to")):
            for n in g.nodes_by_label(label):
                for t in g.get(n, key) or []:
                    if t in g:
                        add(n, t, 1, True)
        degree: dict[str, int] = defaultdict(int)
        for (u, _v) in raw:
            degree[u] += 1
        for (u, v), (cost, access) in raw.items():
            if degree[u] > HUB and not access:
                continue
            self.out[u].append((v, cost, access))
            self.inn[v].append((u, cost, access))
        self.move_count = sum(len(v) for v in self.out.values())

    # -- traversal
    def reach(self, root: str, depth: int = DEPTH, mode: str = "full", blocked: Callable[[str, str], bool] | None = None,
              reverse: bool = False) -> tuple[dict[str, int], int]:
        """Min semantic depth of every node reachable from ``root`` within ``depth``; returns (depths, settled)."""
        adj = self.inn if reverse else self.out
        best: dict[str, int] = {root: 0}
        q: deque[str] = deque([root])
        settled = 0
        while q:
            u = q.popleft()
            settled += 1
            du = best[u]
            for v, cost, access in adj[u]:
                if mode == "access" and not access:
                    continue
                if blocked is not None and blocked(u, v):
                    continue
                nd = du + cost
                if nd > depth or v == root:
                    continue
                if v not in best or nd < best[v]:
                    best[v] = nd
                    q.append(v)  # a shorter depth re-expands the node (zero-cost moves make this necessary)
        best.pop(root, None)
        return best, settled

    def shortest(self, root: str, is_target: Callable[[str], bool], depth: int = PATH_DEPTH) -> tuple[list[str] | None, int]:
        parent: dict[str, str | None] = {root: None}
        best: dict[str, int] = {root: 0}
        q: deque[str] = deque([root])
        settled = 0
        found: str | None = None
        while q:
            u = q.popleft()
            settled += 1
            if u != root and is_target(u):
                if found is None or best[u] < best[found]:
                    found = u
                continue
            for v, cost, _access in self.out[u]:
                nd = best[u] + cost
                if nd > depth or v == root:
                    continue
                if v not in best or nd < best[v]:
                    best[v] = nd
                    parent[v] = u
                    q.append(v)
        if found is None:
            return None, settled
        path = [found]
        while parent[path[-1]] is not None:
            path.append(parent[path[-1]])  # type: ignore[arg-type]
        return path[::-1], settled

    # -- node predicates
    def is_crown(self, n: str) -> bool:
        return sem.is_crown_jewel(self.g.node(n))

    def is_regulated_data(self, n: str) -> bool:
        a = self.g.node(n)
        return sem.is_data_holder(a) and sem.is_regulated(a)

    def label(self, n: str) -> str:
        return self.g.label_of(n) or "?"


# ============================================================================ tier 2: SQL over the graph tables

MOVES_SQL = """
CREATE OR REPLACE TABLE moves AS
WITH rules(type, direction, depth_cost, access_f, access_r) AS (VALUES {rules}),
e AS (
  SELECT src, dst, type, coalesce(CAST(json_extract(props, '$.transitive') AS BOOLEAN), false) AS transitive FROM edges
),
fwd AS (
  SELECT e.src, e.dst, r.depth_cost, r.access_f AS access FROM e JOIN rules r USING (type)
  WHERE r.direction IN ('forward', 'both') AND NOT (e.type = 'CAN_ACCESS' AND e.transitive)
),
rev AS (
  SELECT e.dst AS src, e.src AS dst, r.depth_cost, r.access_r AS access FROM e JOIN rules r USING (type)
  WHERE r.direction IN ('reverse', 'both')
),
implicit AS (
  SELECT n.id AS src, u.t AS dst, 1 AS depth_cost, true AS access
  FROM nodes n, unnest(CAST(json_extract(n.props, CASE n.label WHEN 'StorageBucket' THEN '$.contains_credentials_for' ELSE '$.grants_access_to' END) AS VARCHAR[])) AS u(t)
  WHERE n.label IN ('StorageBucket', 'Secret') AND u.t IN (SELECT id FROM nodes)
),
allm AS (SELECT * FROM fwd UNION ALL SELECT * FROM rev UNION ALL SELECT * FROM implicit),
best AS (
  SELECT src, dst, min(depth_cost) AS depth_cost, bool_or(access) AS access FROM allm
  WHERE src <> dst AND src <> '{internet}' GROUP BY src, dst
),
deg AS (SELECT src, count(*) AS n FROM best GROUP BY src)
SELECT b.src, b.dst, b.depth_cost, b.access FROM best b JOIN deg d USING (src) WHERE d.n <= {hub} OR b.access
"""

REACH_SQL = """
WITH RECURSIVE r(node, depth) AS (
  SELECT ?, 0
  UNION
  SELECT m.dst, r.depth + m.depth_cost FROM r JOIN {moves} m ON m.src = r.node
  WHERE r.depth + m.depth_cost <= ? AND m.dst <> ? {extra}
)
SELECT node, min(depth) AS depth FROM r WHERE node <> ? GROUP BY node
"""

REACH_MULTI_SQL = """
WITH RECURSIVE roots AS ({roots}),
r(root, node, depth) AS (
  SELECT id, id, 0 FROM roots
  UNION
  SELECT r.root, m.dst, r.depth + m.depth_cost FROM r JOIN {moves} m ON m.src = r.node
  WHERE r.depth + m.depth_cost <= ? AND m.dst <> r.root {extra}
)
SELECT r.root, count(DISTINCT r.node) FILTER (WHERE {target}) AS hits
FROM r LEFT JOIN nodes n ON n.id = r.node WHERE r.node <> r.root GROUP BY r.root
"""

SHORTEST_SQL = """
WITH RECURSIVE r(node, depth, parent) AS (
  SELECT ?, 0, CAST(NULL AS VARCHAR)
  UNION
  SELECT m.dst, r.depth + m.depth_cost, r.node FROM r JOIN moves m ON m.src = r.node
  JOIN nodes n ON n.id = r.node
  WHERE r.depth + m.depth_cost <= ? AND m.dst <> ? AND NOT ({target_of_n})
)
SELECT node, depth, parent FROM r
"""


class NormSQLTier:
    name = "sql-norm"

    def __init__(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]], threads: int | None = None) -> None:
        self.con = duckdb.connect()
        if threads:
            self.con.execute(f"SET threads={threads}")
        t0 = time.perf_counter()
        # bulk load through JSONL files (row-by-row inserts take minutes; this is how a warehouse would ingest anyway)
        tmp = Path(tempfile.mkdtemp(prefix="throughline-bench-"))
        with (tmp / "nodes.jsonl").open("w") as fh:
            for n in nodes:
                fh.write(json.dumps({"id": n["id"], "label": n["label"], "name": n.get("name"), "props": n.get("props") or {}}) + "\n")
        with (tmp / "edges.jsonl").open("w") as fh:
            for e in edges:
                fh.write(json.dumps({"src": e["src"], "dst": e["dst"], "type": e["type"], "confidence": e.get("confidence"), "props": e.get("props") or {}}) + "\n")
        self.con.execute(f"CREATE TABLE nodes AS SELECT * FROM read_json('{tmp / 'nodes.jsonl'}', format='newline_delimited', columns={{'id': 'VARCHAR', 'label': 'VARCHAR', 'name': 'VARCHAR', 'props': 'JSON'}}, maximum_object_size=4000000)")
        self.con.execute(f"CREATE TABLE edges AS SELECT * FROM read_json('{tmp / 'edges.jsonl'}', format='newline_delimited', columns={{'src': 'VARCHAR', 'dst': 'VARCHAR', 'type': 'VARCHAR', 'confidence': 'DOUBLE', 'props': 'JSON'}}, maximum_object_size=4000000)")
        shutil.rmtree(tmp, ignore_errors=True)
        self.load_ms = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        rules = ", ".join(f"('{t}', '{d}', {c}, {str(af).lower()}, {str(ar).lower()})" for t, d, c, af, ar in RULES)
        self.con.execute(MOVES_SQL.format(rules=rules, internet=INTERNET, hub=HUB))
        self.con.execute("CREATE OR REPLACE TABLE rmoves AS SELECT dst AS src, src AS dst, depth_cost, access FROM moves")
        self.index_ms = (time.perf_counter() - t0) * 1000
        self.move_count = self.con.execute("SELECT count(*) FROM moves").fetchone()[0]

    def reach(self, root: str, depth: int = DEPTH, mode: str = "full", reverse: bool = False, blocked_sql: str = "") -> dict[str, int]:
        extra = (" AND m.access" if mode == "access" else "") + blocked_sql
        sql = REACH_SQL.format(moves="rmoves" if reverse else "moves", extra=extra)
        return dict(self.con.execute(sql, [root, depth, root, root]).fetchall())

    def reach_multi(self, roots_sql: str, target_sql: str, depth: int = DEPTH, mode: str = "access") -> dict[str, int]:
        extra = " AND m.access" if mode == "access" else ""
        sql = REACH_MULTI_SQL.format(roots=roots_sql, moves="moves", extra=extra, target=target_sql)
        return dict(self.con.execute(sql, [depth]).fetchall())

    def shortest(self, root: str, target_of_n: str, depth: int = PATH_DEPTH) -> list[str] | None:
        rows = self.con.execute(SHORTEST_SQL.format(target_of_n=target_of_n), [root, depth, root]).fetchall()
        targets = self.con.execute(f"SELECT id FROM nodes n WHERE {target_of_n}").fetchall()
        target_ids = {t[0] for t in targets}
        best: dict[str, tuple[int, str | None]] = {}
        for node, depth_, parent in rows:
            if node not in best or depth_ < best[node][0]:
                best[node] = (depth_, parent)
        hits = [(best[n][0], n) for n in best if n in target_ids and n != root]
        if not hits:
            return None
        _d, node = min(hits)
        path = [node]
        while best.get(path[-1], (0, None))[1] is not None:
            path.append(best[path[-1]][1])  # type: ignore[arg-type]
        return path[::-1]

    def q_one(self, sql: str, params: list[Any]) -> tuple[Any, ...]:
        return self.con.execute(sql, params).fetchone()

    def profile_rows(self, sql: str, params: list[Any]) -> int:
        """Rows produced by every operator of the query (DuckDB profiling), the SQL analogue of "nodes settled"."""
        con = self.con
        con.execute("PRAGMA enable_profiling='json'")
        con.execute("PRAGMA profiling_output='/tmp/throughline_profile.json'")
        try:
            con.execute(sql, params).fetchall()
        finally:
            con.execute("PRAGMA disable_profiling")
        try:
            prof = json.loads(Path("/tmp/throughline_profile.json").read_text())
        except Exception:
            return -1

        def walk(node: dict[str, Any]) -> int:
            total = int(node.get("operator_cardinality") or node.get("cardinality") or 0)
            for ch in node.get("children", []):
                total += walk(ch)
            return total

        return walk(prof)


# ============================================================================ tier 3: SQL over the raw feeds


RAW_FILES = {
    "wiz_resources": "wiz/cloud_resources.jsonl", "wiz_iam": "wiz/iam.jsonl", "wiz_network": "wiz/network.jsonl",
    "wiz_vulns": "wiz/vulnerabilities.jsonl", "wiz_issues": "wiz/issues.jsonl", "wiz_business": "wiz/business_context.jsonl",
    "falcon_devices": "falcon/devices.jsonl", "falcon_detections": "falcon/detections.jsonl", "falcon_incidents": "falcon/incidents.jsonl",
    "falcon_processes": "falcon/processes.jsonl", "falcon_logons": "falcon/logons.jsonl", "falcon_netconn": "falcon/network_connections.jsonl",
    "cloudtrail": "cloudtrail/events.jsonl", "okta_users": "okta/users.jsonl", "okta_alerts": "okta/alerts.jsonl",
    "ids_alerts": "ids/alerts.jsonl", "waf_alerts": "waf/alerts.jsonl", "ti_indicators": "ti/indicators.jsonl",
    "biz_apps": "business/applications.jsonl", "biz_teams": "business/teams.jsonl",
}
RAW_JSON_FILES = {"ti_actors": "ti/actors.json", "ti_campaigns": "ti/campaigns.json", "ti_exploited": "ti/exploited_cves.json", "ti_reports": "ti/reports.json"}

# Every join the graph materialised at ingest, written back as SQL over the vendor feeds. This block is the price of
# "no graph": it runs inside every reachability question of the raw tier.
RAW_MOVES_CTE = """
res AS (
  SELECT graphEntityId AS id, type, name, subscriptionExternalId AS account, pj AS p FROM wiz_resources
),
principals AS (
  SELECT graphEntityId AS id, type, arn, subscriptionExternalId AS account, attachedPolicies, canAssume, accessKeys FROM wiz_iam WHERE type IN ('SERVICE_ACCOUNT', 'USER_ACCOUNT')
),
policies AS (SELECT arn, graphEntityId AS id, docj AS document FROM wiz_iam WHERE type = 'ACCESS_ROLE_POLICY'),
statements AS (
  SELECT p.arn AS policy_arn, s.st FROM policies p, unnest(CAST(json_extract(p.document, '$.Statement') AS JSON[])) AS s(st)
  WHERE json_extract_string(s.st, '$.Effect') = 'Allow'
),
stmt_res AS (
  SELECT policy_arn, r.pat, a.act FROM statements,
    unnest(CASE WHEN json_type(json_extract(st, '$.Resource')) = 'ARRAY' THEN CAST(json_extract(st, '$.Resource') AS VARCHAR[]) ELSE [json_extract_string(st, '$.Resource')] END) AS r(pat),
    unnest(CASE WHEN json_type(json_extract(st, '$.Action')) = 'ARRAY' THEN CAST(json_extract(st, '$.Action') AS VARCHAR[]) ELSE [json_extract_string(st, '$.Action')] END) AS a(act)
),
res_arn AS (
  SELECT id, account, type,
    CASE type WHEN 'BUCKET' THEN 'arn:aws:s3:::' || name
              WHEN 'SECRET' THEN 'arn:aws:secretsmanager:' || coalesce(json_extract_string(p, '$.region'), 'us-east-1') || ':' || account || ':secret:' || name || '-AbCdEf'
              WHEN 'DATABASE' THEN 'arn:aws:rds:' || coalesce(json_extract_string(p, '$.region'), 'us-east-1') || ':' || account || ':db:' || name END AS arn,
    CASE type WHEN 'BUCKET' THEN 's3' WHEN 'SECRET' THEN 'secretsmanager' WHEN 'DATABASE' THEN 'rds' END AS service
  FROM res WHERE type IN ('BUCKET', 'SECRET', 'DATABASE')
),
-- direct effective access: attached policy statements matched to resource ARNs (wildcards -> LIKE); "*" scopes to the
-- resources of the action's service in the principal's account
can_access AS (
  SELECT DISTINCT pr.id AS src, ra.id AS dst FROM principals pr, unnest(pr.attachedPolicies) AS ap(policy_arn)
  JOIN stmt_res sr ON sr.policy_arn = ap.policy_arn
  JOIN res_arn ra ON (sr.pat = '*' AND ra.account = pr.account AND (sr.act = '*' OR sr.act LIKE ra.service || ':%'))
                  OR (sr.pat <> '*' AND (ra.arn LIKE replace(sr.pat, '*', '%')
                                         OR (ra.service = 's3' AND split_part(sr.pat, '/', 1) = ra.arn)))
),
can_assume AS (
  SELECT pr.id AS src, tgt.id AS dst FROM principals pr, unnest(pr.canAssume) AS ca(arn) JOIN principals tgt ON tgt.arn = ca.arn
),
has_role AS (
  SELECT r.id AS src, pr.id AS dst FROM res r, unnest(CAST(json_extract(r.p, '$.instanceProfileRoles') AS VARCHAR[])) AS ipr(arn) JOIN principals pr ON pr.arn = ipr.arn
  WHERE r.type = 'VIRTUAL_MACHINE'
),
devices AS (SELECT device_id, 'endpoint:falcon:' || device_id AS id, hostname, local_ip, instance_id, primary_user FROM falcon_devices),
-- entity resolution: the EDR device and the cloud instance are the same machine (instance id, else hostname or IP)
same_as AS (
  SELECT d.id AS src, r.id AS dst FROM devices d JOIN res r ON r.type = 'VIRTUAL_MACHINE'
   AND ((d.instance_id IS NOT NULL AND r.id = 'vm:aws:' || d.instance_id)
        OR (d.instance_id IS NULL AND (lower(d.hostname) = lower(r.name) OR d.local_ip = json_extract_string(r.p, '$.private_ip'))))
),
on_endpoint AS (SELECT 'alert:falcon:' || det.alert_id AS src, 'endpoint:falcon:' || det.device.device_id AS dst FROM falcon_detections det),
unlocks AS (
  SELECT r.id AS src, u.t AS dst FROM res r, unnest(CAST(json_extract(r.p, CASE r.type WHEN 'BUCKET' THEN '$.contains_credentials_for' ELSE '$.grants_access_to' END) AS VARCHAR[])) AS u(t)
  WHERE r.type IN ('BUCKET', 'SECRET')
),
has_key AS (SELECT pr.id AS src, 'accesskey:aws:' || k.key.accessKeyId AS dst FROM principals pr, unnest(pr.accessKeys) AS k(key)),
primary_user AS (SELECT d.id AS src, d.primary_user AS dst FROM devices d WHERE d.primary_user IS NOT NULL),
logged_on AS (SELECT DISTINCT 'endpoint:falcon:' || device_id AS src, principal_id AS dst FROM falcon_logons WHERE principal_id IS NOT NULL),
exposes AS (
  SELECT '{internet}' AS src, r.id AS dst FROM res r WHERE r.type = 'VIRTUAL_MACHINE'
   AND json_extract_string(r.p, '$.exposure') = 'internet' AND json_array_length(json_extract(r.p, '$.public_ports')) > 0
),
raw_moves AS (
  SELECT src, dst, 0 AS depth_cost, true AS access FROM on_endpoint
  UNION ALL SELECT src, dst, 0, true FROM same_as UNION ALL SELECT dst, src, 0, true FROM same_as
  UNION ALL SELECT src, dst, 1, true FROM has_role
  UNION ALL SELECT src, dst, 1, true FROM can_assume
  UNION ALL SELECT src, dst, 1, true FROM can_access
  UNION ALL SELECT src, dst, 1, true FROM unlocks
  UNION ALL SELECT src, dst, 1, true FROM has_key
  UNION ALL SELECT src, dst, 1, true FROM primary_user UNION ALL SELECT dst, src, 1, false FROM primary_user
  UNION ALL SELECT src, dst, 1, false FROM logged_on UNION ALL SELECT dst, src, 1, false FROM logged_on
  UNION ALL SELECT src, dst, 1, false FROM exposes
)
"""

RAW_REACH_SQL = """
WITH RECURSIVE {moves},
r(node, depth) AS (
  SELECT ?, 0
  UNION
  SELECT m.dst, r.depth + m.depth_cost FROM r JOIN raw_moves m ON m.src = r.node
  WHERE r.depth + m.depth_cost <= ? AND m.dst <> ? {extra}
)
SELECT node, min(depth) FROM r WHERE node <> ? GROUP BY node
"""


class RawSQLTier:
    name = "sql-raw"

    def __init__(self, data_dir: Path, threads: int | None = None, alert_names: list[tuple[str, str]] | None = None) -> None:
        self.con = duckdb.connect()
        if threads:
            self.con.execute(f"SET threads={threads}")
        raw = data_dir / "raw"
        t0 = time.perf_counter()
        extra_cols = {"wiz_resources": ", to_json(properties) AS pj", "wiz_iam": ", to_json(document) AS docj"}
        for table, rel in RAW_FILES.items():
            self.con.execute(f"CREATE TABLE {table} AS SELECT *{extra_cols.get(table, '')} FROM read_json_auto('{raw / rel}', format='newline_delimited', union_by_name=true, sample_size=-1, maximum_object_size=4000000)")
        for table, rel in RAW_JSON_FILES.items():
            self.con.execute(f"CREATE TABLE {table} AS SELECT * FROM read_json_auto('{raw / rel}', union_by_name=true, sample_size=-1, maximum_object_size=4000000)")
        # Naming only: the graph calls the bastion detection alert:falcon:ldt-a009, the feed calls it ldt:aid-bas01:...;
        # the raw tier answers with the graph's names so the answers can be compared (no join uses this table).
        self.con.execute("CREATE TABLE alert_ids (composite_id VARCHAR, alert_id VARCHAR)")
        if alert_names:
            self.con.executemany("INSERT INTO alert_ids VALUES (?, ?)", alert_names)
        self.con.execute("ALTER TABLE falcon_detections ADD COLUMN alert_id VARCHAR")
        self.con.execute("UPDATE falcon_detections SET alert_id = coalesce((SELECT a.alert_id FROM alert_ids a WHERE a.composite_id = falcon_detections.composite_id), 'ldt-' || substr(md5(composite_id), 1, 8))")
        self.load_ms = (time.perf_counter() - t0) * 1000
        self.moves_cte = RAW_MOVES_CTE.format(internet=INTERNET)

    def reach(self, root: str, depth: int = DEPTH, mode: str = "full", blocked_sql: str = "") -> dict[str, int]:
        extra = (" AND m.access" if mode == "access" else "") + blocked_sql
        sql = RAW_REACH_SQL.format(moves=self.moves_cte, extra=extra)
        return dict(self.con.execute(sql, [root, depth, root, root]).fetchall())

    def q(self, sql: str, params: list[Any] | None = None) -> list[tuple[Any, ...]]:
        return self.con.execute(sql, params or []).fetchall()


# ============================================================================ tier 4: the embedded graph database (Cypher)

CYPHER_QUERIES: dict[str, tuple[str, str]] = {
    # Cypher's variable-length patterns run in one direction; the product's move semantics mix directions
    # (SAME_AS and PRIMARY_USER both ways, DERIVED_FROM and HAS_NODE backwards), so these are forward-only approximations.
    "Q1": ("MATCH (a:Alert {id: $id})-[:ON_ENDPOINT|SAME_AS|HAS_ROLE|CAN_ASSUME|CAN_ACCESS|UNLOCKS|HAS_ACCESS_KEY|PRIMARY_USER*1..5]->(x) RETURN DISTINCT x.id AS id", "id"),
    "Q4": ("MATCH (a:IamRole {id: $id})-[:CAN_ASSUME|CAN_ACCESS|UNLOCKS|HAS_ACCESS_KEY*1..4]->(x) RETURN DISTINCT x.id AS id", "id"),
    "Q5": ("MATCH (i:Internet)-[:EXPOSES]->(vm:VirtualMachine)-[:VULNERABLE_TO]->(c:Vulnerability) WHERE c.exploitation_status IN ['active','mass_exploitation'] AND c.sector_targeting_relevance >= 0.5 RETURN DISTINCT vm.id AS id", ""),
    "Q10": ("MATCH (b:StorageBucket {id: $id})<-[:ON_ENDPOINT|SAME_AS|HAS_ROLE|CAN_ASSUME|CAN_ACCESS|UNLOCKS|HAS_ACCESS_KEY|PRIMARY_USER*1..5]-(a:Alert) RETURN DISTINCT a.id AS id", "id"),
}


class CypherTier:
    """The embedded LadybugDB the product ships for the Cypher console (one node table per label, one rel table per edge type)."""

    name = "graph-db"

    def __init__(self, db_path: Path) -> None:
        from throughline.graph.ladybug_store import LadybugStore

        t0 = time.perf_counter()
        self.store = LadybugStore(db_path, engine="ladybug")
        self.store.open()
        self.load_ms = (time.perf_counter() - t0) * 1000

    def ids(self, query: str, params: dict[str, Any]) -> set[str]:
        res = self.store.run_readonly_cypher(query, params, row_limit=5000, timeout_ms=20000)
        out: set[str] = set()
        for row in res.rows:
            v = row[0] if isinstance(row, (list, tuple)) else (list(row.values())[0] if isinstance(row, dict) else row)
            out.add(v if isinstance(v, str) else str(v))
        return out


# ============================================================================ the questions


def q_text(sql: str) -> int:
    return len(" ".join(sql.split()))


def run_questions(gt: GraphTier, nt: NormSQLTier | None, rt: RawSQLTier | None, runs: int, k: int, ct: CypherTier | None = None) -> list[dict[str, Any]]:
    """Run every question on every available tier; return one record per (question, tier)."""
    rows: list[dict[str, Any]] = []
    g = gt.g
    a009, a001, n002 = suffix(ALERT_A009, 0), suffix(ALERT_A001, 0), suffix(ALERT_N002, 0)
    role, vault = C.BASTION_ROLE, C.CARDHOLDER_VAULT
    crown = {n for n in g.G.nodes if gt.is_crown(n)}
    regulated_data = {n for n in g.G.nodes if gt.is_regulated_data(n)}

    def rec(qid: str, tier: str, ms: float, answer: Any, work: int | None = None, qlen: int | None = None, note: str = "") -> None:
        rows.append({"q": qid, "tier": tier, "ms": round(ms, 2), "answer": answer, "work": work, "query_chars": qlen, "note": note, "replicate": k})

    # ---------------------------------------------------------------- Q1 blast radius of the bastion alert
    def graph_q1() -> dict[str, int]:
        return gt.reach(a009, DEPTH, "full")[0]
    ms, reach1 = med_ms(graph_q1, runs)
    settled = gt.reach(a009, DEPTH, "full")[1]
    product = gt.ctx.reach(a009, DEPTH, "full", max_nodes=100_000)
    summary1 = {"nodes": len(reach1), "crown_jewels": len(set(reach1) & crown), "regulated": len(set(reach1) & regulated_data),
                "product_reach_jaccard": round(jaccard(reach1, product.ids()), 3)}
    rec("Q1", "graph", ms, summary1, settled, len("reach('alert:falcon:ldt-a009', depth=4)"))
    if nt:
        ms, r = med_ms(lambda: nt.reach(a009), runs)
        work = nt.profile_rows(REACH_SQL.format(moves="moves", extra=""), [a009, DEPTH, a009, a009])
        rec("Q1", "sql-norm", ms, {"nodes": len(r), "agrees_with_graph": round(jaccard(r, reach1), 3)}, work, q_text(REACH_SQL))
    if rt:
        ms, r = med_ms(lambda: rt.reach(a009), runs)
        cover = len(set(r) & set(reach1)) / max(len(reach1), 1)
        rec("Q1", "sql-raw", ms, {"nodes": len(r), "coverage_of_graph_reach": round(cover, 3), "extra_nodes": len(set(r) - set(reach1))}, None,
            q_text(RAW_REACH_SQL.format(moves=rt.moves_cte, extra="")), "reconstructs every join from the vendor feeds inside the query")

    # ---------------------------------------------------------------- Q4 identity footprint of the bastion role
    ms, reach4 = med_ms(lambda: gt.reach(role, DEPTH, "full")[0], runs)
    rec("Q4", "graph", ms, {"nodes": len(reach4), "crown_jewels": len(set(reach4) & crown)}, gt.reach(role, DEPTH, "full")[1], len("reach(role, depth=4)"))
    if nt:
        ms, r = med_ms(lambda: nt.reach(role), runs)
        rec("Q4", "sql-norm", ms, {"nodes": len(r), "agrees_with_graph": round(jaccard(r, reach4), 3)}, nt.profile_rows(REACH_SQL.format(moves="moves", extra=""), [role, DEPTH, role, role]), q_text(REACH_SQL))
    if rt:
        ms, r = med_ms(lambda: rt.reach(role), runs)
        rec("Q4", "sql-raw", ms, {"nodes": len(r), "coverage_of_graph_reach": round(len(set(r) & set(reach4)) / max(len(reach4), 1), 3)}, None, q_text(RAW_REACH_SQL.format(moves=rt.moves_cte, extra="")))

    # ---------------------------------------------------------------- Q2 medium endpoint alerts with a path to regulated data
    medium = [n for n in g.nodes_by_label("Alert") if g.get(n, "source_system") == "falcon" and g.get(n, "vendor_severity") == "medium"]

    def graph_q2() -> tuple[list[str], int]:
        hits, work = [], 0
        for a in medium:
            r, s = gt.reach(a, DEPTH, "access")
            work += s
            if any(n in regulated_data for n in r):
                hits.append(a)
        return hits, work
    ms, (hits2, work2) = med_ms(graph_q2, runs)
    rec("Q2", "graph", ms, {"roots": len(medium), "alerts_with_path": len(hits2), "storyline_a_included": sum(1 for a in hits2 if a in {v[0] for v in C.ALERT_A.values()})}, work2, len("for a in medium_alerts: reach(a, 4, 'access') & regulated"))
    if nt:
        roots_sql = "SELECT id FROM nodes WHERE label = 'Alert' AND json_extract_string(props, '$.source_system') = 'falcon' AND json_extract_string(props, '$.vendor_severity') = 'medium'"
        target = "n.label IN ('StorageBucket','Database','Secret') AND list_has_any(CAST(json_extract(n.props, '$.data_classifications') AS VARCHAR[]), ['PCI','PHI','PII','SECRETS'])"
        ms, r = med_ms(lambda: nt.reach_multi(roots_sql, target), runs)
        hits = sorted(k_ for k_, v in r.items() if v > 0)
        rec("Q2", "sql-norm", ms, {"roots": len(r), "alerts_with_path": len(hits), "agrees_with_graph": round(jaccard(hits, hits2), 3)}, None, q_text(REACH_MULTI_SQL))

    # ---------------------------------------------------------------- Q6 crown-jewel reach for every alert (the scoring input)
    alerts = list(g.nodes_by_label("Alert"))

    def graph_q6() -> tuple[dict[str, int], int]:
        out, work = {}, 0
        for a in alerts:
            r, s = gt.reach(a, DEPTH, "access")
            work += s
            out[a] = len(set(r) & crown)
        return out, work
    ms, (per_alert, work6) = med_ms(graph_q6, runs)
    top = sorted(per_alert.items(), key=lambda kv: -kv[1])[:3]
    rec("Q6", "graph", ms, {"alerts": len(alerts), "alerts_reaching_jewels": sum(1 for v in per_alert.values() if v), "a009_jewels": per_alert.get(a009), "top3": top}, work6, len("for a in alerts: reach(a, 4, 'access') & crown_jewels"))
    if nt:
        target = "(CAST(json_extract(n.props, '$.crown_jewel') AS BOOLEAN) OR (n.label = 'IamRole' AND CAST(json_extract(n.props, '$.is_admin') AS BOOLEAN)) OR (n.label IN ('StorageBucket','Database') AND json_extract_string(n.props, '$.sensitivity') IN ('high','critical') AND list_has_any(CAST(json_extract(n.props, '$.data_classifications') AS VARCHAR[]), ['PCI','PHI','PII','SECRETS'])))"
        ms, r = med_ms(lambda: nt.reach_multi("SELECT id FROM nodes WHERE label = 'Alert'", target), runs)
        agree = sum(1 for a in alerts if (r.get(a, 0) > 0) == (per_alert.get(a, 0) > 0)) / max(len(alerts), 1)
        rec("Q6", "sql-norm", ms, {"alerts": len(r), "alerts_reaching_jewels": sum(1 for v in r.values() if v), "a009_jewels": r.get(a009), "agreement": round(agree, 3)}, None, q_text(REACH_MULTI_SQL))

    # ---------------------------------------------------------------- Q10 alerts on assets that can reach cardholder data (reverse traversal)
    def graph_q10() -> tuple[set[str], int]:
        r, s = gt.reach(vault, DEPTH, "full", reverse=True)
        return {n for n in r if gt.label(n) == "Alert"}, s
    ms, (alerts10, work10) = med_ms(graph_q10, runs)
    rec("Q10", "graph", ms, {"alerts": len(alerts10), "a009_included": a009 in alerts10}, work10, len("reach(vault, 4, reverse=True) & alerts"))
    if nt:
        ms, r = med_ms(lambda: nt.reach(vault, reverse=True), runs)
        got = {n for n in r if n.startswith("alert:")}
        rec("Q10", "sql-norm", ms, {"alerts": len(got), "agrees_with_graph": round(jaccard(got, alerts10), 3)}, nt.profile_rows(REACH_SQL.format(moves="rmoves", extra=""), [vault, DEPTH, vault, vault]), q_text(REACH_SQL))

    # ---------------------------------------------------------------- Q7 shortest attack path from the phishing alert to regulated data
    ms, (path7, settled7) = med_ms(lambda: gt.shortest(a001, lambda n: n in regulated_data), runs)
    rec("Q7", "graph", ms, {"hops": (len(path7) - 1) if path7 else None, "path": path7}, settled7, len("shortest(a001, is_regulated_data, depth=6)"))
    if nt:
        target_of_n = "n.label IN ('StorageBucket','Database','Secret') AND list_has_any(CAST(json_extract(n.props, '$.data_classifications') AS VARCHAR[]), ['PCI','PHI','PII','SECRETS'])"
        ms, p = med_ms(lambda: nt.shortest(a001, target_of_n), runs)
        rec("Q7", "sql-norm", ms, {"hops": (len(p) - 1) if p else None, "same_length_as_graph": bool(p and path7 and len(p) == len(path7)), "path": p}, None, q_text(SHORTEST_SQL))

    # ---------------------------------------------------------------- Q12 containment: isolate bas-01 and rotate the bastion role
    def blocked(u: str, v: str) -> bool:
        return BAS01_ENDPOINT in (u, v) or u == role
    ms, before_after = med_ms(lambda: (gt.reach(a001, DEPTH + 2, "full")[0], gt.reach(a001, DEPTH + 2, "full", blocked=blocked)[0]), runs)
    before, after = before_after
    rec("Q12", "graph", ms, {"reach_before": len(before), "reach_after": len(after), "jewels_before": len(set(before) & crown), "jewels_after": len(set(after) & crown)}, None, len("reach(a001, 6) vs reach(a001, 6, blocked=isolate(bas-01)+rotate(role))"))
    if nt:
        blocked_sql = f" AND m.src <> '{BAS01_ENDPOINT}' AND m.dst <> '{BAS01_ENDPOINT}' AND m.src <> '{role}'"
        ms, ba = med_ms(lambda: (nt.reach(a001, DEPTH + 2), nt.reach(a001, DEPTH + 2, blocked_sql=blocked_sql)), runs)
        rec("Q12", "sql-norm", ms, {"reach_before": len(ba[0]), "reach_after": len(ba[1]), "agrees_with_graph": round(jaccard(ba[1], after), 3)}, None, q_text(REACH_SQL) * 2)

    # ---------------------------------------------------------------- fixed-depth joins: Q3, Q5, Q8, Q9, Q11
    if k == 0 or True:
        # Q3 cloud API activity by the bastion role near endpoint detections on the same machine
        def graph_q3() -> list[tuple[str, str]]:
            pairs = []
            vms = [v for v, _ in g.in_edges(role, ("HAS_ROLE",))]
            eps = [e for vm in vms for e, _ in g.in_edges(vm, ("SAME_AS",))] + [e for vm in vms for e, _ in g.out_edges(vm, ("SAME_AS",))]
            dets = [(a, g.get(a, "detected_at")) for ep in eps for a, _ in g.in_edges(ep, ("ON_ENDPOINT",))]
            events = [(e, g.get(e, "event_time")) for e, _ in g.in_edges(role, ("PERFORMED_BY",))]
            for e, et in events:
                for a, at in dets:
                    if et and at and abs((datetime.fromisoformat(et.replace("Z", "+00:00")) - datetime.fromisoformat(at.replace("Z", "+00:00"))).total_seconds()) <= 6 * 3600:
                        pairs.append((e, a))
            return pairs
        ms, pairs3 = med_ms(graph_q3, runs)
        rec("Q3", "graph", ms, {"event_alert_pairs": len(pairs3), "events": len({p[0] for p in pairs3}), "alerts": len({p[1] for p in pairs3})}, None, len("role<-HAS_ROLE-vm-SAME_AS-endpoint<-ON_ENDPOINT-alert x role<-PERFORMED_BY-event within 6h"))
        if rt:
            sql3 = """
            WITH role_vm AS (
              SELECT r.graphEntityId AS vm_id, r.id AS instance_id FROM wiz_resources r, unnest(CAST(json_extract(r.pj, '$.instanceProfileRoles') AS VARCHAR[])) AS ipr(arn)
              WHERE r.type = 'VIRTUAL_MACHINE' AND ipr.arn = ?
            ),
            dets AS (
              SELECT d.alert_id, d.timestamp AS ts FROM falcon_detections d JOIN falcon_devices dev ON dev.device_id = d.device.device_id
              JOIN role_vm rv ON dev.instance_id = rv.instance_id
            ),
            events AS (SELECT eventTime AS et, eventName, userIdentity.arn AS arn FROM cloudtrail WHERE userIdentity.arn LIKE ?)
            SELECT count(*), count(DISTINCT events.et || events.eventName), count(DISTINCT dets.alert_id)
            FROM events JOIN dets ON abs(epoch(CAST(events.et AS TIMESTAMP)) - epoch(CAST(dets.ts AS TIMESTAMP))) <= 6 * 3600
            """
            sts_pattern = C.BASTION_ROLE_ARN.replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/") + "/%"
            ms, r = med_ms(lambda: rt.q(sql3, [C.BASTION_ROLE_ARN, sts_pattern]), runs)
            rec("Q3", "sql-raw", ms, {"event_alert_pairs": r[0][0], "events": r[0][1], "alerts": r[0][2]}, None, q_text(sql3))

        # Q5 internet-exposed hosts with a vulnerability an actor is actively exploiting against the sector
        def graph_q5() -> list[str]:
            out = []
            for vm, _ in g.out_edges(INTERNET, ("EXPOSES",)):
                for cve, _d in g.out_edges(vm, ("VULNERABLE_TO",)):
                    if g.get(cve, "exploitation_status") in sem.EXPLOITED_STATUSES and (g.get(cve, "sector_targeting_relevance") or 0) >= 0.5:
                        out.append(vm)
                        break
            return sorted(set(out))
        ms, hosts5 = med_ms(graph_q5, runs)
        rec("Q5", "graph", ms, {"hosts": len(hosts5), "includes_stmt_render_2a": C.EDGE_VM in hosts5}, None, len("internet-EXPOSES->vm-VULNERABLE_TO->cve where exploited and sector relevant"))
        if rt:
            sql5 = """
            SELECT DISTINCT v.vulnerableAsset.graphEntityId
            FROM wiz_vulns v
            JOIN wiz_resources r ON r.graphEntityId = v.vulnerableAsset.graphEntityId
            JOIN ti_exploited x ON x.cveID = v.name
            -- attributions name a campaign or an actor; either has to target the sector
            LEFT JOIN ti_campaigns c ON list_contains(list_transform(x.x_attributions, a -> a.id), c.x_throughline_id)
            LEFT JOIN ti_actors act ON list_contains(list_transform(x.x_attributions, a -> a.id), act.x_throughline_id)
            WHERE v.status = 'OPEN' AND json_extract_string(r.pj, '$.exposure') = 'internet'
              AND json_array_length(json_extract(r.pj, '$.public_ports')) > 0
              AND x.x_exploitation_status IN ('active', 'mass_exploitation')
              AND (list_contains(c.x_targeted_sectors, 'financial-services') OR list_contains(act.goals, 'target financial-services'))
            """
            ms, r = med_ms(lambda: rt.q(sql5), runs)
            got = sorted({row[0] for row in r})
            rec("Q5", "sql-raw", ms, {"hosts": len(got), "agrees_with_graph": round(jaccard(got, hosts5), 3)}, None, q_text(sql5))

        # Q8 cloud API keys used today that were stolen on an endpoint
        def graph_q8() -> list[str]:
            out = set()
            for cred in g.nodes_by_label("Credential"):
                stolen = [a for a, _ in g.out_edges(cred, ("STOLEN_BY",)) if gt.label(a) == "Alert"]
                used = [e for e, _ in g.in_edges(cred, ("USED_CREDENTIAL",))]
                if stolen and used:
                    out.add(cred)
            return sorted(out)
        ms, creds8 = med_ms(graph_q8, runs)
        rec("Q8", "graph", ms, {"credentials": len(creds8), "ids": creds8}, None, len("credential-STOLEN_BY->alert and event-USED_CREDENTIAL->credential"))
        if rt:
            sql8 = """
            WITH cred_theft AS (
              SELECT d.alert_id, d.timestamp AS ts, dev.instance_id FROM falcon_detections d JOIN falcon_devices dev ON dev.device_id = d.device.device_id
              WHERE d.technique_id = 'T1552.005' AND dev.instance_id IS NOT NULL
            )
            SELECT DISTINCT e.userIdentity.accessKeyId
            FROM cloudtrail e JOIN cred_theft t ON e.userIdentity.arn LIKE '%/' || t.instance_id
            WHERE CAST(e.eventTime AS TIMESTAMP) BETWEEN CAST(t.ts AS TIMESTAMP) AND CAST(t.ts AS TIMESTAMP) + INTERVAL 24 HOUR
            """
            ms, r = med_ms(lambda: rt.q(sql8), runs)
            got = sorted({f"credential:aws:{row[0]}" for row in r})
            rec("Q8", "sql-raw", ms, {"credentials": len(got), "ids": got, "agrees_with_graph": round(jaccard(got, creds8), 3)}, None, q_text(sql8), "raw feeds carry no stolen-credential record; the join goes through the instance id in the assumed-role session")

        # Q9 detections matching the Cinder Jackal report's indicators or techniques, and what they touch
        report = "report:ti:TL-2026-0142"

        def endpoint_of(n: str) -> str | None:
            lab = gt.label(n)
            if lab == "Endpoint":
                return n
            if lab == "Alert":
                ent = g.get(n, "entity_id")
                return ent if ent and gt.label(ent) == "Endpoint" else None
            if lab == "Process":
                return next((v for v, _ in g.out_edges(n, ("RAN_ON",))), None)
            if lab in ("File", "IpAddress", "Domain"):
                for u, _ in g.in_edges(n, ("CONNECTED_TO", "EXECUTED", "HAS_FILE")):
                    ep = endpoint_of(u)
                    if ep:
                        return ep
            return None

        def graph_q9() -> dict[str, Any]:
            iocs = [i for i in g.nodes_by_label("Indicator") if g.get(i, "report_id") == report]
            matched = {src for i in iocs for src, _ in g.in_edges(i, ("MATCHES_IOC",))}
            touched = {ep for m in matched if (ep := endpoint_of(m))}
            techs = {t.removeprefix("technique:attack:") for t, _ in g.out_edges(report, ("REPORTS_ON",)) if t.startswith("technique:attack:")}
            if not techs:
                techs = {t.removeprefix("technique:attack:") for t in g.G.nodes if t.startswith("technique:attack:") and any(u == report for u, _ in g.in_edges(t))}
            ttp_alerts = {a for a in g.nodes_by_label("Alert") if g.get(a, "source_system") == "falcon" and set(g.get(a, "techniques") or []) & techs}
            return {"ioc_hits": len(matched), "endpoints_touched": sorted(touched), "ttp_alerts": len(ttp_alerts), "report_techniques": len(techs)}
        ms, r9 = med_ms(graph_q9, runs)
        rec("Q9", "graph", ms, {**r9, "endpoints_touched": len(r9["endpoints_touched"])}, None, len("report<-indicators<-MATCHES_IOC-x-ON_ENDPOINT/RAN_ON->endpoint ; report techniques & alert techniques"))
        if rt:
            sql9 = """
            WITH iocs AS (SELECT x_ioc_type AS t, name AS v FROM ti_indicators WHERE x_report_id = ?),
            hits AS (
              SELECT n.device_id FROM falcon_netconn n JOIN iocs ON iocs.t IN ('domain', 'ipv4') AND n.remote_address = iocs.v
              UNION ALL SELECT d.device.device_id FROM falcon_detections d JOIN iocs ON (iocs.t = 'sha256' AND d.sha256 = iocs.v) OR (iocs.t = 'filename' AND d.filename = iocs.v)
              UNION ALL SELECT p.device_id FROM falcon_processes p JOIN iocs ON (iocs.t = 'sha256' AND p.sha256 = iocs.v) OR (iocs.t = 'filename' AND p.file_name = iocs.v)
            ),
            ttps AS (SELECT replace(ref, 'technique:attack:', '') AS tid FROM (SELECT unnest(object_refs) AS ref FROM ti_reports WHERE x_throughline_id = ?) WHERE ref LIKE 'technique:attack:%'),
            ttp_alerts AS (SELECT DISTINCT d.alert_id FROM falcon_detections d JOIN ttps ON d.technique_id = ttps.tid)
            SELECT (SELECT count(*) FROM hits), (SELECT list(DISTINCT 'endpoint:falcon:' || device_id ORDER BY 1) FROM hits), (SELECT count(*) FROM ttp_alerts), (SELECT count(*) FROM ttps)
            """
            ms, r = med_ms(lambda: rt.q(sql9, [report, report]), runs)
            rec("Q9", "sql-raw", ms, {"ioc_hits": r[0][0], "endpoints_touched": len(r[0][1] or []), "endpoints_agree": round(jaccard(r[0][1] or [], r9["endpoints_touched"]), 3),
                                      "ttp_alerts": r[0][2], "ttp_alerts_agree": r[0][2] == r9["ttp_alerts"], "report_techniques": r[0][3]}, None, q_text(sql9),
                "ioc_hits count raw matches (rows), the graph counts matched entities; endpoints touched and technique matches are the comparable answers")

        # Q11 is the public bucket risky: what it holds and who can reach it (reverse reach, depth 4)
        bucket = g.get(n002, "entity_id")

        def graph_q11() -> dict[str, Any]:
            attrs = g.node(bucket) or {}
            r, _ = gt.reach(bucket, DEPTH, "full", reverse=True)
            return {"public": attrs.get("public"), "classes": sem.data_classes(attrs), "sensitivity": attrs.get("sensitivity"),
                    "alerts_that_can_reach_it": len([n for n in r if gt.label(n) == "Alert"]), "internet_can_reach": INTERNET in r}
        ms, r11 = med_ms(graph_q11, runs)
        rec("Q11", "graph", ms, r11, None, len("bucket props + reach(bucket, 4, reverse=True)"))
        if nt:
            sql11 = "SELECT json_extract_string(props, '$.public'), json_extract(props, '$.data_classifications'), json_extract_string(props, '$.sensitivity') FROM nodes WHERE id = ?"
            ms, r = med_ms(lambda: (nt.q_one(sql11, [bucket]), nt.reach(bucket, reverse=True)), runs)
            rec("Q11", "sql-norm", ms, {"public": r[0][0], "classes": r[0][1], "sensitivity": r[0][2], "alerts_that_can_reach_it": len([n for n in r[1] if n.startswith("alert:")])}, None, q_text(sql11) + q_text(REACH_SQL))
    # ---------------------------------------------------------------- the embedded graph database, where Cypher can express the question
    if ct:
        refs = {"Q1": (set(reach1), {"id": a009}), "Q4": (set(reach4), {"id": role}), "Q5": (set(hosts5), {}), "Q10": (set(alerts10), {"id": vault})}
        for qid, (query, _p) in CYPHER_QUERIES.items():
            ref, params = refs[qid]
            ms, got = med_ms(lambda q=query, p=params: ct.ids(q, p), runs)
            rec(qid, "graph-db", ms, {"rows": len(got), "coverage_of_graph_answer": round(len(got & ref) / max(len(ref), 1), 3), "extra": len(got - ref)}, None, q_text(query),
                "forward-only variable-length pattern; Cypher cannot mix directions inside one path expression" if qid != "Q5" else "")
    return rows


# ============================================================================ data loading and replication


def load_records(data_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = [json.loads(line) for line in (data_dir / "graph" / "nodes.jsonl").open()]
    edges = [json.loads(line) for line in (data_dir / "graph" / "edges.jsonl").open()]
    return nodes, edges


def replicate(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], copies: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Clone the estate ``copies`` times. Ids get a ``~k`` suffix (k >= 1); props that reference ids are rewritten."""
    if copies <= 1:
        return nodes, edges
    ids = {n["id"] for n in nodes}
    out_n: list[dict[str, Any]] = list(nodes)
    out_e: list[dict[str, Any]] = list(edges)
    for k in range(1, copies):
        for n in nodes:
            if n["id"] == INTERNET:
                continue
            c = dict(n)
            c["id"] = suffix(n["id"], k)
            props = dict(n.get("props") or {})
            for key in ("entity_id", "contains_credentials_for", "grants_access_to", "primary_user_id"):
                v = props.get(key)
                if isinstance(v, str) and v in ids:
                    props[key] = suffix(v, k)
                elif isinstance(v, list):
                    props[key] = [suffix(x, k) if isinstance(x, str) and x in ids else x for x in v]
            c["props"] = props
            out_n.append(c)
        for e in edges:
            c = dict(e)
            c["src"], c["dst"] = suffix(e["src"], k), suffix(e["dst"], k)
            out_e.append(c)
    return out_n, out_e


# ============================================================================ main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=REPO_ROOT / "data" / "generated")
    ap.add_argument("--replicate", default="1", help="comma-separated estate multipliers, e.g. 1,3,10 (raw tier runs at 1 only)")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--threads", type=int, default=None, help="DuckDB threads (default: all cores)")
    ap.add_argument("--no-cypher", action="store_true", help="skip the embedded graph database tier")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "docs" / "benchmarks" / "graph_vs_sql.json")
    ap.add_argument("--markdown", type=Path, default=REPO_ROOT / "docs" / "benchmarks" / "graph_vs_sql.md")
    args = ap.parse_args(argv)

    nodes0, edges0 = load_records(args.data)
    results: dict[str, Any] = {"data": str(args.data), "runs": args.runs, "duckdb": duckdb.__version__, "sizes": {}, "rows": []}
    for mult in [int(x) for x in args.replicate.split(",")]:
        nodes, edges = replicate(nodes0, edges0, mult)
        print(f"== x{mult}: {len(nodes):,} nodes / {len(edges):,} edges", flush=True)
        gt = GraphTier(nodes, edges)
        nt = NormSQLTier(nodes, edges, threads=args.threads)
        names = [((n.get("props") or {}).get("raw", {}).get("composite_id"), n.get("source_id")) for n in nodes0 if n["label"] == "Alert" and (n.get("props") or {}).get("source_system") == "falcon"]
        rt = RawSQLTier(args.data, threads=args.threads, alert_names=[x for x in names if x[0] and x[1]]) if mult == 1 else None
        results["sizes"][str(mult)] = {
            "nodes": len(nodes), "edges": len(edges), "moves_graph": gt.move_count, "moves_sql": nt.move_count,
            "graph_load_ms": round(gt.load_ms), "graph_index_ms": round(gt.index_ms), "sql_load_ms": round(nt.load_ms), "sql_index_ms": round(nt.index_ms),
            "raw_load_ms": round(rt.load_ms) if rt else None,
        }
        results["sizes"][str(mult)]["threads"] = args.threads or duckdb.connect().execute("SELECT current_setting('threads')").fetchone()[0]
        print(f"   load: graph {gt.load_ms:.0f} ms + index {gt.index_ms:.0f} ms | duckdb tables {nt.load_ms:.0f} ms + moves view {nt.index_ms:.0f} ms"
              + (f" | raw feeds {rt.load_ms:.0f} ms" if rt else ""), flush=True)
        ct = None
        if mult == 1 and (args.data / "graph.lbdb").exists() and not args.no_cypher:
            try:
                ct = CypherTier(args.data / "graph.lbdb")
                print(f"   embedded graph database opened in {ct.load_ms:.0f} ms", flush=True)
            except Exception as exc:  # the engine is optional
                print(f"   embedded graph database unavailable: {exc}", flush=True)
        rows = run_questions(gt, nt, rt, args.runs, 0 if mult == 1 else mult, ct)
        for r in rows:
            r["replicate"] = mult
            print(f"   {r['q']:<4} {r['tier']:<9} {r['ms']:>10.2f} ms  work={r['work']}  q={r['query_chars']}  {json.dumps(r['answer'])[:150]}", flush=True)
        results["rows"].extend(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=1, default=str))
    args.markdown.write_text(render_markdown(results))
    print(f"wrote {args.out} and {args.markdown}")
    return 0


def render_markdown(results: dict[str, Any]) -> str:
    lines = ["# Graph vs SQL benchmark (generated by scripts/graph_vs_sql.py)", "",
             f"DuckDB {results['duckdb']}, median of {results['runs']} runs after a warm-up. Work = nodes settled (graph) or rows produced by all operators (SQL).", ""]
    for mult, s in results["sizes"].items():
        lines.append(f"- x{mult}: {s['nodes']:,} nodes / {s['edges']:,} edges; graph load {s['graph_load_ms']} ms + move index {s['graph_index_ms']} ms; DuckDB load {s['sql_load_ms']} ms + moves view {s['sql_index_ms']} ms"
                     + (f"; raw feeds {s['raw_load_ms']} ms" if s.get("raw_load_ms") else ""))
    lines.append("")
    lines.append("| estate | question | tier | median ms | work | query chars | answer |")
    lines.append("|---|---|---|---:|---:|---:|---|")
    for r in results["rows"]:
        ans = json.dumps(r["answer"], default=str)
        if len(ans) > 140:
            ans = ans[:137] + "..."
        lines.append(f"| x{r['replicate']} | {r['q']} | {r['tier']} | {r['ms']:.2f} | {r['work'] if r['work'] is not None else ''} | {r['query_chars'] or ''} | `{ans}` |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
