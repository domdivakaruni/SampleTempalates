"""GraphStore over a Neo4j server (Bolt) using the official ``neo4j`` driver.

Not exercised in CI (no server here; conformance tests skip unless ``NEO4J_URI`` is set), written against the
neo4j 5.x / 6.x driver API: ``GraphDatabase.driver(uri, auth=(user, password))``, ``driver.execute_query`` with
``routing_=RoutingControl.READ``, ``Query(text, timeout=seconds)`` for per-query timeouts, ``neo4j.graph.Node``
(``element_id``, ``labels``, ``items()``), ``Relationship`` (``type``, ``start_node``, ``end_node``) and ``Path``.

Data model on Neo4j
-------------------
* every node gets its canonical label plus the ``Node`` super-label; ``Node.id`` carries the unique constraint that
  makes ``MATCH (a:Node {id: ...})`` an index lookup (docs/03 section 1);
* common columns and typed props are stored flattened as properties (TIMESTAMP columns as ``datetime``, STRING[]
  as lists); nested props that Neo4j cannot store (maps, lists of maps) become JSON strings; the complete
  ``props`` object is kept as ``props_json`` so ``get_node`` returns exactly the ``nodes.jsonl`` record;
* relationships carry ``source, first_seen, last_seen, confidence`` plus typed props and ``props_json``;
* a ``ThroughlineMeta {key: 'manifest'}`` node stores the build checksum for ``loader.build_embedded_db``.

Reads run in READ access mode (the server refuses writes in a read transaction) after the shared read-only
gate; timeouts are the driver/transaction timeout mapped to ``QueryTimeout``.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from throughline.graph import loader
from throughline.graph.context_graph import ContextGraph
from throughline.graph.cypher_gate import check_readonly
from throughline.graph.store import (
    BaseStore,
    CypherResult,
    NotSupported,
    QueryRejected,
    QueryTimeout,
    format_timestamp,
)
from throughline.models import GraphFragment, SearchHit, StatsOut
from throughline.schema import EDGE_TYPES, LABELS

log = logging.getLogger(__name__)

SUPER_LABEL = "Node"
META_LABEL = "ThroughlineMeta"
BATCH_SIZE = 5000

EXAMPLE_QUERIES: list[dict[str, Any]] = [
    {
        "title": "Alerts whose host can reach a crown-jewel bucket through role assumption (the storyline path)",
        "query": (
            "MATCH (a:Alert)-[:ON_ENDPOINT]->(e:Endpoint)-[:SAME_AS]->(v:VirtualMachine)-[:HAS_ROLE]->(r:IamRole)"
            "-[:CAN_ASSUME*0..2]->(r2:IamRole)-[:CAN_ACCESS]->(b:StorageBucket) WHERE b.crown_jewel "
            "RETURN a.id, b.name LIMIT 20"
        ),
    },
    {
        "title": "Top alerts by contextual score",
        "query": "MATCH (a:Alert) WHERE a.contextual_score >= 76 RETURN a.id, a.title, a.vendor_severity, a.contextual_score ORDER BY a.contextual_score DESC LIMIT 20",
    },
    {
        "title": "Internet-exposed VMs carrying actively exploited CVEs",
        "query": (
            "MATCH (:Internet)-[:EXPOSES]->(v:VirtualMachine)-[:VULNERABLE_TO]->(c:Vulnerability) "
            "WHERE c.exploitation_status IN ['active', 'mass_exploitation'] RETURN v.name, c.cve_id, c.exploitation_status LIMIT 25"
        ),
    },
    {
        "title": "Credential join",
        "query": "MATCH (c:Credential)-[:STOLEN_BY]->(a:Alert) MATCH (ev:CloudEvent)-[:USED_CREDENTIAL]->(c) RETURN c.id, a.id, collect(ev.event_name) AS events LIMIT 20",
    },
    {
        "title": "Neighborhood with hop distance",
        "query": "MATCH p = (n:Node {id: $id})-[*1..3]-(m:Node) WHERE m.id <> $id RETURN m.id, head([l IN labels(m) WHERE l <> 'Node']) AS label, min(length(p)) AS hops ORDER BY hops, m.id LIMIT 50",
        "params": {"id": "alert:falcon:ldt-a009"},
    },
    {
        "title": "IOC matches and what they indicate",
        "query": "MATCH (x)-[:MATCHES_IOC]->(i:Indicator)-[:INDICATES]->(t) RETURN labels(x) AS matched, x.name, i.value, labels(t) AS indicates, t.name LIMIT 25",
    },
    {
        "title": "Alerts using a technique (lists use IN)",
        "query": "MATCH (a:Alert) WHERE 'T1552.005' IN a.techniques RETURN a.id, a.title, a.hostname LIMIT 20",
    },
    {
        "title": "Text search on names",
        "query": "MATCH (n:Node) WHERE toLower(n.name) CONTAINS 'bas-01' RETURN n.id, labels(n), n.name LIMIT 10",
    },
]

DIALECT_NOTES: list[str] = [
    "Every node has its canonical label plus the Node super-label; the unique constraint is on Node.id.",
    "Use toLower()/toUpper(), type(r) for relationship types, labels(n) for labels, 'x' IN list for STRING[] columns.",
    "TIMESTAMP columns are datetime values: compare with datetime('2026-09-10T00:00:00Z').",
    "JSON columns (raw, tags, statements, score_breakdown, stages) and props_json are strings.",
    "Variable-length patterns need explicit bounds with an upper bound <= 5, e.g. -[*1..3]-.",
    "Read-only: CREATE/MERGE/SET/DELETE/CALL are refused; queries run in READ access mode with a timeout.",
]


def _neo4j():
    try:
        import neo4j  # noqa: PLC0415 - optional dependency
    except ImportError as exc:  # pragma: no cover
        raise NotSupported(f"the neo4j driver is not installed: {exc}") from exc
    return neo4j


def _to_native(value: Any) -> Any:
    """neo4j.time values -> stdlib datetime/date/time; everything else unchanged."""
    to_native = getattr(value, "to_native", None)
    return to_native() if callable(to_native) else value


def _storable(value: Any) -> Any:
    """Neo4j properties must be scalars, temporal values or homogeneous lists of scalars; anything else becomes
    a JSON string. TIMESTAMP columns arrive as naive UTC ``datetime`` values from ``loader.coerce`` and are stored
    as zoned ``DateTime`` (UTC) so ``datetime('2026-09-10T00:00:00Z')`` comparisons work in queries."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, dt.datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)
    if isinstance(value, dt.date | dt.time):
        return value
    if isinstance(value, list | tuple):
        items = [v for v in value if v is not None]
        if all(isinstance(v, str) for v in items):
            return list(items)
        if all(isinstance(v, bool) for v in items) or all(isinstance(v, int | float) and not isinstance(v, bool) for v in items):
            return list(items)
        return loader.json_dumps(list(value))
    return loader.json_dumps(value)


class Neo4jStore(BaseStore):
    name = "neo4j"

    def __init__(
        self,
        uri: str,
        user: str = "neo4j",
        password: str | None = None,
        database: str = "neo4j",
        graph: ContextGraph | None = None,
        max_var_length: int = 5,
    ) -> None:
        self.uri = uri
        self.user = user
        self.password = password or ""
        self.database = database
        self.graph = graph
        self.max_var_length = max_var_length
        self._driver: Any = None

    # ------------------------------------------------------------------ lifecycle

    def capabilities(self) -> dict[str, Any]:
        return {
            "cypher": True,
            "multi_label_patterns": True,
            "shortest_path": True,
            "read_only": True,  # READ access mode + gate; the server is not assumed to be read-only
            "quantified_paths": True,
            "engine": "neo4j",
            "engine_version": self._server_version,
            "dialect": "neo4j",
        }

    @property
    def _server_version(self) -> str:
        if self._driver is None:
            return "unknown"
        try:
            info = self._driver.get_server_info()
            return str(getattr(info, "agent", "unknown"))
        except Exception:  # pragma: no cover - server dependent
            return "unknown"

    def open(self) -> None:
        if self._driver is not None:
            return
        neo4j = _neo4j()
        self._driver = neo4j.GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        self._driver.verify_connectivity()
        log.info("connected to neo4j at %s (database %s)", self.uri, self.database)

    def close(self) -> None:
        if self._driver is not None:
            try:
                self._driver.close()
            finally:
                self._driver = None

    def _require_open(self) -> None:
        if self._driver is None:
            raise RuntimeError("neo4j store is not open; call open() first")

    # ------------------------------------------------------------------ execution helpers

    def _read(self, query: str, params: dict[str, Any] | None = None, timeout_ms: int | None = None) -> tuple[list[str], list[list[Any]]]:
        """Run a read query in READ access mode; returns (keys, raw rows)."""
        self._require_open()
        neo4j = _neo4j()
        text: Any = neo4j.Query(query, timeout=timeout_ms / 1000.0) if timeout_ms else query
        with self._driver.session(database=self.database, default_access_mode=neo4j.READ_ACCESS) as session:
            result = session.run(text, params or {})
            keys = list(result.keys())
            rows = [list(record.values()) for record in result]
        return keys, rows

    def _write(self, query: str, params: dict[str, Any] | None = None) -> None:
        self._require_open()
        neo4j = _neo4j()
        self._driver.execute_query(query, params or {}, database_=self.database, routing_=neo4j.RoutingControl.WRITE)

    # ------------------------------------------------------------------ build

    def constraint_statements(self) -> list[str]:
        statements = [
            f"CREATE CONSTRAINT node_id IF NOT EXISTS FOR (n:{SUPER_LABEL}) REQUIRE n.id IS UNIQUE",
            f"CREATE INDEX node_name IF NOT EXISTS FOR (n:{SUPER_LABEL}) ON (n.name)",
            f"CREATE CONSTRAINT throughline_meta_key IF NOT EXISTS FOR (m:{META_LABEL}) REQUIRE m.key IS UNIQUE",
        ]
        statements += [
            f"CREATE CONSTRAINT {lbl.name.lower()}_id IF NOT EXISTS FOR (n:{lbl.name}) REQUIRE n.id IS UNIQUE" for lbl in LABELS.values()
        ]
        return statements

    def _wipe(self) -> None:
        while True:
            _, rows = self._read(f"MATCH (n:{SUPER_LABEL}) RETURN count(n) AS c")
            if not rows or not rows[0][0]:
                break
            self._write(f"MATCH (n:{SUPER_LABEL}) WITH n LIMIT 10000 DETACH DELETE n")
        self._write(f"MATCH (m:{META_LABEL}) DELETE m")

    @staticmethod
    def _node_row(label: str, rec: dict[str, Any]) -> dict[str, Any]:
        values = loader.node_row_values(LABELS[label], rec)
        props = {k: _storable(v) for k, v in values.items() if k not in ("id", "props") and v is not None}
        props["label"] = label
        props["props_json"] = values["props"]
        return {"id": rec["id"], "props": props}

    @staticmethod
    def _edge_row(etype: str, rec: dict[str, Any]) -> dict[str, Any]:
        values = loader.edge_row_values(EDGE_TYPES[etype], rec)
        props = {k: _storable(v) for k, v in values.items() if k != "props" and v is not None}
        props["props_json"] = values["props"]
        return {"src": rec["src"], "dst": rec["dst"], "props": props}

    def build(self, nodes_path: Path, edges_path: Path, manifest: dict) -> None:
        self.open()
        t0 = time.perf_counter()
        for stmt in self.constraint_statements():
            self._write(stmt)
        self._wipe()
        plan = loader.plan_tables(nodes_path, edges_path)
        for label, rows in plan.node_rows.items():
            query = f"UNWIND $rows AS row MERGE (n:{label} {{id: row.id}}) SET n:{SUPER_LABEL}, n += row.props"
            for start in range(0, len(rows), BATCH_SIZE):
                self._write(query, {"rows": [self._node_row(label, r) for r in rows[start : start + BATCH_SIZE]]})
        for (etype, _, _), rows in sorted(plan.edge_rows.items()):
            query = (
                f"UNWIND $rows AS row MATCH (a:{SUPER_LABEL} {{id: row.src}}), (b:{SUPER_LABEL} {{id: row.dst}}) "
                f"MERGE (a)-[r:{etype}]->(b) SET r += row.props"
            )
            for start in range(0, len(rows), BATCH_SIZE):
                self._write(query, {"rows": [self._edge_row(etype, r) for r in rows[start : start + BATCH_SIZE]]})
        meta = {
            "checksum": manifest.get("checksum"),
            "engine": "neo4j",
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "node_counts": plan.node_counts(),
            "edge_counts": plan.edge_counts(),
            "manifest": {k: v for k, v in manifest.items() if k != "checksums"},
        }
        self._write(
            f"MERGE (m:{META_LABEL} {{key: 'manifest'}}) SET m.checksum = $checksum, m.json = $json",
            {"checksum": manifest.get("checksum"), "json": json.dumps(meta, default=str)},
        )
        log.info("built neo4j graph: %d nodes, %d edges in %.1fs", plan.node_count, plan.edge_count, time.perf_counter() - t0)

    def stored_manifest(self) -> dict[str, Any] | None:
        try:
            self.open()
            _, rows = self._read(f"MATCH (m:{META_LABEL} {{key: 'manifest'}}) RETURN m.json AS j LIMIT 1")
        except Exception as exc:  # pragma: no cover - server dependent
            log.warning("could not read the neo4j build manifest: %s", exc)
            return None
        if not rows or not rows[0][0]:
            return None
        return json.loads(rows[0][0])

    # ------------------------------------------------------------------ record conversion

    @staticmethod
    def _label_of(node: Any) -> str:
        labels = [lbl for lbl in getattr(node, "labels", ()) if lbl != SUPER_LABEL]
        stored = node.get("label") if hasattr(node, "get") else None
        return stored or (labels[0] if labels else "Unknown")

    def _node_record(self, node: Any) -> dict[str, Any]:
        raw = node.get("props_json")
        props = json.loads(raw) if isinstance(raw, str) and raw else {}
        return {
            "id": node.get("id"),
            "label": self._label_of(node),
            "name": node.get("name"),
            "source": node.get("source"),
            "source_id": node.get("source_id"),
            "first_seen": format_timestamp(_to_native(node.get("first_seen"))),
            "last_seen": format_timestamp(_to_native(node.get("last_seen"))),
            "confidence": node.get("confidence"),
            "props": props,
        }

    @staticmethod
    def _edge_record(src: str, dst: str, etype: str, props: dict[str, Any]) -> dict[str, Any]:
        raw = props.get("props_json")
        return {
            "type": etype,
            "src": src,
            "dst": dst,
            "source": props.get("source"),
            "first_seen": format_timestamp(_to_native(props.get("first_seen"))),
            "last_seen": format_timestamp(_to_native(props.get("last_seen"))),
            "confidence": props.get("confidence"),
            "props": json.loads(raw) if isinstance(raw, str) and raw else {},
        }

    # ------------------------------------------------------------------ lookups

    def get_node(self, node_id: str) -> dict | None:
        _, rows = self._read(f"MATCH (n:{SUPER_LABEL} {{id: $id}}) RETURN n LIMIT 1", {"id": node_id})
        return self._node_record(rows[0][0]) if rows else None

    def get_nodes(self, ids: Sequence[str]) -> list[dict]:
        wanted = list(dict.fromkeys(i for i in ids if i))
        if not wanted:
            return []
        _, rows = self._read(f"MATCH (n:{SUPER_LABEL}) WHERE n.id IN $ids RETURN n", {"ids": wanted})
        found = {rec["id"]: rec for rec in (self._node_record(r[0]) for r in rows)}
        return [found[i] for i in wanted if i in found]

    def search(self, text: str, labels: Sequence[str] | None = None, limit: int = 25) -> list[SearchHit]:
        if self.graph is not None:
            return self.graph.search(text, labels, limit)
        q = (text or "").strip().lower()
        if not q:
            return []
        wanted = self.check_labels(labels)
        where = ["(toLower(n.name) CONTAINS $q OR toLower(n.id) CONTAINS $q)"]
        params: dict[str, Any] = {"q": q, "k": max(int(limit) * 4, 50)}
        if wanted:
            where.append("any(l IN labels(n) WHERE l IN $labels)")
            params["labels"] = wanted
        _, rows = self._read(f"MATCH (n:{SUPER_LABEL}) WHERE {' AND '.join(where)} RETURN n LIMIT $k", params)
        scored = [(self.score_text_match(q, {"id": n.get("id"), "name": n.get("name")}), self._node_record(n)) for (n,) in rows]
        scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
        return [self.search_hit(rec, score) for score, rec in scored[: int(limit)]]

    # ------------------------------------------------------------------ neighborhood

    def _edges_among(self, ids: Sequence[str]) -> list[dict[str, Any]]:
        if len(ids) < 2:
            return []
        _, rows = self._read(
            f"MATCH (a:{SUPER_LABEL})-[e]->(b:{SUPER_LABEL}) WHERE a.id IN $ids AND b.id IN $ids "
            "RETURN a.id, b.id, type(e), properties(e)",
            {"ids": list(ids)},
        )
        position = {nid: i for i, nid in enumerate(ids)}
        records = [self._edge_record(src, dst, etype, dict(props)) for src, dst, etype, props in rows]
        records.sort(key=lambda r: (position[r["src"]], r["type"], position[r["dst"]]))
        return records

    def neighborhood(
        self,
        node_id: str,
        depth: int = 1,
        edge_types: Sequence[str] | None = None,
        direction: str = "both",
        labels: Sequence[str] | None = None,
        max_nodes: int = 150,
    ) -> GraphFragment:
        depth = self.check_depth(depth)
        direction = self.check_direction(direction)
        types = self.check_edge_types(edge_types)
        wanted = self.check_labels(labels)
        max_nodes = max(1, int(max_nodes))
        start = self.get_node(node_id)
        if start is None:
            return GraphFragment(focus=[node_id], layout_hint="neighborhood", total_nodes=0)
        left, right = {"out": ("-", "->"), "in": ("<-", "-"), "both": ("-", "-")}[direction]
        where = ["m.id <> $id"]
        params: dict[str, Any] = {"id": node_id, "k": max_nodes}
        if types:
            where.append("all(r IN relationships(p) WHERE type(r) IN $types)")
            params["types"] = types
        if wanted:
            where.append("all(x IN tail(nodes(p)) WHERE any(l IN labels(x) WHERE l IN $labels))")
            params["labels"] = wanted
        pattern = (
            f"MATCH p = (n:{SUPER_LABEL} {{id: $id}}){left}[*1..{depth}]{right}(m:{SUPER_LABEL}) WHERE {' AND '.join(where)}"
        )
        _, rows = self._read(f"{pattern} WITH m, min(length(p)) AS hops RETURN m, hops ORDER BY hops, m.id LIMIT $k", params)
        truncated = len(rows) >= max_nodes
        others = [self._node_record(n) for n, _ in rows[: max_nodes - 1]]
        records = [start, *others]
        ids = [r["id"] for r in records]
        total = len(records)
        if truncated:
            _, count_rows = self._read(f"{pattern} RETURN count(DISTINCT m) AS c", params)
            total = 1 + int(count_rows[0][0]) if count_rows else len(records)
        if self.graph is not None and all(i in self.graph for i in ids):
            fragment = self.graph.fragment(ids, focus=[node_id], layout_hint="neighborhood", max_nodes=max_nodes)
            fragment.truncated = fragment.truncated or truncated
            fragment.total_nodes = total
            return fragment
        return self.fragment_from_records(records, self._edges_among(ids), focus=[node_id], truncated=truncated, total_nodes=total)

    # ------------------------------------------------------------------ Cypher

    def _resolve_element_ids(self, element_ids: Iterable[str]) -> dict[str, str]:
        wanted = list(dict.fromkeys(element_ids))
        if not wanted:
            return {}
        _, rows = self._read(
            f"MATCH (n:{SUPER_LABEL}) WHERE elementId(n) IN $eids RETURN elementId(n) AS eid, n.id AS id", {"eids": wanted}
        )
        return {eid: nid for eid, nid in rows}

    def _collect_element_ids(self, value: Any, out: set[str]) -> None:
        graph_mod = _neo4j().graph
        if isinstance(value, graph_mod.Relationship):
            for node in (value.start_node, value.end_node):
                if node is not None and node.get("id") is None:
                    out.add(node.element_id)
        elif isinstance(value, graph_mod.Path):
            for rel in value.relationships:
                self._collect_element_ids(rel, out)
        elif isinstance(value, list | tuple):
            for v in value:
                self._collect_element_ids(v, out)
        elif isinstance(value, dict):
            for v in value.values():
                self._collect_element_ids(v, out)

    def _render_graph_value(self, value: Any, ctx: Any = None) -> tuple[bool, Any]:
        graph_mod = _neo4j().graph
        ids: dict[str, str] = ctx or {}
        if isinstance(value, graph_mod.Node):
            return True, {"id": value.get("id"), "label": self._label_of(value), "name": value.get("name")}
        if isinstance(value, graph_mod.Relationship):

            def endpoint(node: Any) -> str | None:
                if node is None:
                    return None
                return node.get("id") or ids.get(node.element_id)

            return True, {"src": endpoint(value.start_node), "type": value.type, "dst": endpoint(value.end_node)}
        if isinstance(value, graph_mod.Path):
            return True, {
                "nodes": [self.render_value(n, ctx) for n in value.nodes],
                "rels": [self.render_value(r, ctx) for r in value.relationships],
            }
        native = _to_native(value)
        if native is not value:
            return True, self.render_value(native, ctx)
        return False, None

    def run_readonly_cypher(
        self, query: str, params: dict | None = None, row_limit: int = 200, timeout_ms: int = 3000
    ) -> CypherResult:
        neo4j = _neo4j()
        row_limit = max(1, min(int(row_limit), 5000))
        normalized = check_readonly(query, max_var_length=self.max_var_length, row_limit=row_limit + 1)
        t0 = time.perf_counter()
        try:
            columns, rows = self._read(normalized, params or {}, timeout_ms=timeout_ms)
        except neo4j.exceptions.ClientError as exc:
            code = str(getattr(exc, "code", "") or "")
            message = str(getattr(exc, "message", None) or exc)
            if "TimedOut" in code or "Timeout" in code or "timed out" in message.lower():
                raise QueryTimeout(f"query exceeded {timeout_ms} ms") from exc
            raise QueryRejected(message) from exc
        except neo4j.exceptions.TransientError as exc:
            code = str(getattr(exc, "code", "") or "")
            if "TimedOut" in code or "Timeout" in code or "timed out" in str(exc).lower():
                raise QueryTimeout(f"query exceeded {timeout_ms} ms") from exc
            raise
        truncated = len(rows) > row_limit
        rows = rows[:row_limit]
        element_ids: set[str] = set()
        for row in rows:
            for value in row:
                self._collect_element_ids(value, element_ids)
        ctx = self._resolve_element_ids(element_ids)
        rendered = self.render_rows(rows, ctx)
        return CypherResult(columns=columns, rows=rendered, elapsed_ms=int((time.perf_counter() - t0) * 1000), truncated=truncated)

    # ------------------------------------------------------------------ stats & schema

    def stats(self) -> StatsOut:
        _, node_rows = self._read(f"MATCH (n:{SUPER_LABEL}) RETURN n.label AS l, count(*) AS c")
        _, edge_rows = self._read("MATCH ()-[r]->() RETURN type(r) AS t, count(*) AS c")
        node_counts = {str(lbl or "Unknown"): int(c) for lbl, c in node_rows}
        edge_counts = {str(t): int(c) for t, c in edge_rows}
        build = self.stored_manifest() or {}
        build["uri"] = self.uri
        build["database"] = self.database
        return self.stats_out(node_counts, edge_counts, build)

    def schema_summary(self) -> dict[str, Any]:
        return self.schema_summary_for("neo4j", DIALECT_NOTES, EXAMPLE_QUERIES)
