"""Embedded GraphStore over LadybugDB (default) or Kuzu 0.11.3 (pinned fallback) -- one engine per process.

Engine handling
---------------
``engine="ladybug"`` imports ``ladybug`` and ``engine="kuzu"`` imports ``kuzu``; the two share a native core and
crash when loaded together, so ``load_engine`` refuses to import one while the other is in ``sys.modules``.
The Python APIs are identical for everything this module uses (``Database(path, read_only=)``,
``Connection(db)``, ``set_query_timeout(ms)``, ``execute(query, params)``, ``QueryResult.get_all()``); the only
visible differences are handled in one place each:

* node/relationship values carry ``_ID/_LABEL/_SRC/_DST`` keys on Ladybug and ``_id/_label/_src/_dst`` on Kuzu;
* Ladybug accepts multi-label patterns ``(n:A|B)``, Kuzu does not (``capabilities()["multi_label_patterns"]``);
  internal queries only ever use label-less patterns with ``label(n) IN [...]`` so they run on both;
* the reserved word ``Group`` (our label) must be backtick-quoted in DDL and patterns on both engines.

Build
-----
``build`` compiles the schema registry to DDL (one node table per label with the common columns, the typed
columns and ``props`` as a JSON string; one rel table per edge type with every allowed ``FROM A TO B`` pair),
writes one Parquet file per label and per (type, from, to) pair (``loader.write_parquet_tables``) and bulk loads
them with ``COPY <table> FROM '<file>'`` (``(from='A', to='B')`` for multi-pair rel tables). If a COPY fails for a
table the rows are inserted with parameterised ``CREATE`` statements instead (logged). The build checksum and
counts are stored in a sidecar file ``<db_path>.manifest.json`` (the database is a single file, so nothing can
live "inside" it) which ``loader.build_embedded_db`` reads to skip unnecessary rebuilds.

Reads
-----
``open`` reopens the database with ``read_only=True`` (engine-enforced), every call uses its own ``Connection``
with ``set_query_timeout``; user Cypher goes through ``cypher_gate.check_readonly`` first. ``neighborhood`` uses
``-[e* SHORTEST 1..depth]-`` so each reachable node is reported once with its hop distance (the same set as
``ContextGraph.k_hop``); ``search`` delegates to the attached ``ContextGraph`` (token index, identical ranking
to the NetworkX backend) and falls back to a Cypher ``lower(n.name) CONTAINS`` scan when none is attached.
"""
from __future__ import annotations

import importlib
import json
import logging
import shutil
import sys
import time
from collections import defaultdict
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

from throughline.graph import loader
from throughline.graph.context_graph import ContextGraph
from throughline.graph.cypher_gate import check_readonly
from throughline.graph.store import BaseStore, CypherResult, NotSupported, QueryRejected, QueryTimeout, format_timestamp
from throughline.models import GraphFragment, SearchHit, StatsOut
from throughline.schema import EDGE_TYPES, LABELS, label_for_id

log = logging.getLogger(__name__)

ENGINES = ("ladybug", "kuzu")

# Table/column names that must be backtick-quoted in this dialect. ``Group`` is the one that bites us; the rest
# are engine keywords kept here so a future label or column with one of these names keeps working.
RESERVED_IDENTIFIERS: frozenset[str] = frozenset(
    {
        "GROUP", "TABLE", "COLUMN", "MATCH", "RETURN", "WITH", "WHERE", "ORDER", "LIMIT", "UNION", "ALL", "AND", "OR",
        "NOT", "NULL", "TRUE", "FALSE", "CASE", "DEFAULT", "EXISTS", "FROM", "TO", "IN", "IS", "AS", "ON", "BY", "SET",
        "CREATE", "DELETE", "DROP", "ALTER", "COPY", "CALL", "END", "ELSE", "THEN", "WHEN", "CAST", "DISTINCT",
        "OPTIONAL", "UNWIND", "PRIMARY", "KEY", "REL", "NODE", "STARTS", "ENDS", "CONTAINS", "SHORTEST", "XOR",
        "MACRO", "INSTALL", "GLOB", "HEADERS", "PROFILE", "EXPLAIN", "BEGIN", "COMMIT", "ROLLBACK", "TRANSACTION",
        "ONLY", "ASC", "DESC", "ASCENDING", "DESCENDING", "ADD", "ATTACH", "DETACH", "CHECKPOINT", "COMMENT",
        "EXPORT", "IMPORT", "LOAD", "USE", "SEQUENCE", "TYPE", "GRAPH", "PROJECT", "RENAME", "EXTENSION", "IF",
        "READ", "START", "YIELD", "ANY", "SINGLE", "NONE", "COUNT", "DBTYPE", "DECIMAL",
    }
)

_loaded_engines: dict[str, ModuleType] = {}


def ident(name: str) -> str:
    """Quote a table/column identifier when it collides with an engine keyword (``Group`` -> ``\\`Group\\```)."""
    return f"`{name}`" if name.upper() in RESERVED_IDENTIFIERS else name


def lit(value: str) -> str:
    """A single-quoted Cypher string literal (only used for registry names and file paths)."""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def load_engine(engine: str) -> ModuleType:
    """Import ``ladybug`` or ``kuzu`` -- never both in one process. Raises ``NotSupported`` when unavailable."""
    engine = engine.lower()
    if engine not in ENGINES:
        raise ValueError(f"engine must be one of {ENGINES}, got {engine!r}")
    if engine in _loaded_engines:
        return _loaded_engines[engine]
    other = "kuzu" if engine == "ladybug" else "ladybug"
    if other in sys.modules:
        raise NotSupported(
            f"cannot import {engine!r}: {other!r} is already loaded in this process and the two engines clash "
            "at the native level (use one engine per process)"
        )
    try:
        module = importlib.import_module(engine)
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise NotSupported(f"graph engine {engine!r} is not installed: {exc}") from exc
    _loaded_engines[engine] = module
    return module


def _meta(d: dict[str, Any], key: str) -> Any:
    """Read an engine meta key (``_LABEL`` on Ladybug, ``_label`` on Kuzu)."""
    if key in d:
        return d[key]
    return d.get(key.lower())


def _is_rel(d: dict[str, Any]) -> bool:
    return "_SRC" in d or "_src" in d


def _is_recursive_rel(d: dict[str, Any]) -> bool:
    return ("_NODES" in d or "_nodes" in d) and ("_RELS" in d or "_rels" in d)


def _is_node(d: dict[str, Any]) -> bool:
    return ("_LABEL" in d or "_label" in d) and ("_ID" in d or "_id" in d) and "id" in d


def _ref(internal: Any) -> tuple[int, int] | None:
    if isinstance(internal, dict) and "table" in internal and "offset" in internal:
        return int(internal["table"]), int(internal["offset"])
    return None


@dataclass
class _RenderCtx:
    ids: dict[tuple[int, int], str] = field(default_factory=dict)


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
        "query": (
            "MATCH (a:Alert) WHERE a.contextual_score >= 76 RETURN a.id, a.title, a.vendor_severity, "
            "a.contextual_score, a.storyline_id ORDER BY a.contextual_score DESC LIMIT 20"
        ),
    },
    {
        "title": "Internet-exposed VMs carrying actively exploited CVEs",
        "query": (
            "MATCH (:Internet)-[:EXPOSES]->(v:VirtualMachine)-[:VULNERABLE_TO]->(c:Vulnerability) "
            "WHERE c.exploitation_status IN ['active', 'mass_exploitation'] "
            "RETURN v.name, v.environment, c.cve_id, c.exploitation_status, v.has_edr_sensor ORDER BY c.cvss DESC LIMIT 25"
        ),
    },
    {
        "title": "Credential join: credentials stolen on an endpoint and later used in cloud API calls",
        "query": (
            "MATCH (c:Credential)-[:STOLEN_BY]->(a:Alert) MATCH (ev:CloudEvent)-[:USED_CREDENTIAL]->(c) "
            "RETURN c.id, a.id AS stolen_by, collect(ev.event_name) AS events, count(ev) AS calls LIMIT 20"
        ),
    },
    {
        "title": "Neighborhood of a node with hop distance (SHORTEST gives one row per reachable node)",
        "query": (
            "MATCH (n {id: $id})-[e* SHORTEST 1..3]-(m) RETURN m.id, label(m) AS label, m.name, length(e) AS hops "
            "ORDER BY hops, m.id LIMIT 50"
        ),
        "params": {"id": "alert:falcon:ldt-a009"},
    },
    {
        "title": "IOC matches and what they indicate",
        "query": (
            "MATCH (x)-[:MATCHES_IOC]->(i:Indicator)-[:INDICATES]->(t) "
            "RETURN label(x) AS matched_label, x.name, i.ioc_type, i.value, label(t) AS indicates, t.name LIMIT 25"
        ),
    },
    {
        "title": "Alerts using a technique (STRING[] columns use list_contains)",
        "query": (
            "MATCH (a:Alert) WHERE list_contains(a.techniques, 'T1552.005') "
            "RETURN a.id, a.title, a.hostname, a.detected_at ORDER BY a.detected_at LIMIT 20"
        ),
    },
    {
        "title": "Group membership (the Group label is a reserved word: quote it with backticks)",
        "query": "MATCH (u:HumanUser)-[:MEMBER_OF]->(g:`Group`) RETURN g.name, count(u) AS members ORDER BY members DESC LIMIT 10",
    },
]

DIALECT_NOTES: list[str] = [
    "One label per node; use label(n) / label(e) to get the label or relationship type as a string.",
    "Functions: lower()/upper() (not toLower), list_contains(list, x) for STRING[] columns, cast(x, 'STRING'), "
    "timestamp('2026-09-10 00:00:00') for TIMESTAMP comparisons, size(list), starts_with(), contains().",
    "JSON columns (props, raw, tags, statements, inbound_rules, score_breakdown, stages) are STRING; filter with CONTAINS.",
    "Variable-length patterns need explicit bounds with an upper bound <= 5: -[e*1..3]-, -[e* SHORTEST 1..3]-. "
    "Recursive filters: -[e*1..3 (r, n | WHERE label(r) IN ['CAN_ASSUME','CAN_ACCESS'])]->.",
    "The reserved word Group must be written as `Group` (backticks) in patterns.",
    "Read-only: CREATE/MERGE/SET/DELETE/COPY/LOAD/CALL are refused; results are capped at row_limit rows and 3 s.",
]


class LadybugStore(BaseStore):
    """GraphStore over an on-disk LadybugDB/Kuzu database (see the module docstring)."""

    def __init__(
        self,
        db_path: str | Path,
        engine: str = "ladybug",
        graph: ContextGraph | None = None,
        parquet_dir: str | Path | None = None,
        max_var_length: int = 5,
    ) -> None:
        engine = engine.lower()
        if engine not in ENGINES:
            raise ValueError(f"engine must be one of {ENGINES}, got {engine!r}")
        self.engine = engine
        self.name = engine
        self.db_path = Path(db_path)
        self.manifest_path = Path(f"{self.db_path}.manifest.json")
        self.graph = graph
        self.parquet_dir = Path(parquet_dir) if parquet_dir else None
        self.max_var_length = max_var_length
        self._module: ModuleType | None = None
        self._db: Any = None
        self._sidecar: dict[str, Any] = {}
        self._node_tables: dict[int, str] | None = None

    # ------------------------------------------------------------------ engine plumbing

    def _engine(self) -> ModuleType:
        if self._module is None:
            self._module = load_engine(self.engine)
        return self._module

    @property
    def engine_version(self) -> str:
        try:
            return str(getattr(self._engine(), "__version__", "unknown"))
        except NotSupported:
            return "unavailable"

    def db_exists(self) -> bool:
        return self.db_path.exists()

    def stored_manifest(self) -> dict[str, Any] | None:
        """The sidecar written by ``build`` (checksum, engine, counts) or None when there is no database."""
        if not self.manifest_path.exists() or not self.db_path.exists():
            return None
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _require_open(self) -> None:
        if self._db is None:
            raise RuntimeError(f"{self.name} store is not open; call open() first")

    @contextmanager
    def _connection(self, timeout_ms: int | None = None) -> Iterator[Any]:
        self._require_open()
        con = self._engine().Connection(self._db)
        try:
            if timeout_ms:
                con.set_query_timeout(int(timeout_ms))
            yield con
        finally:
            con.close()

    def _execute(
        self, query: str, params: dict[str, Any] | None = None, timeout_ms: int | None = None, *, user: bool = False
    ) -> tuple[list[str], list[str], list[list[Any]]]:
        """Run one statement on a fresh connection -> (column names, column types, rows).

        For user queries engine errors are mapped: an interrupt -> ``QueryTimeout``; parser/binder/catalog and
        read-only violations -> ``QueryRejected`` (the message is the engine's, which agents can act on).
        """
        with self._connection(timeout_ms) as con:
            try:
                result = con.execute(query, params or {})
            except RuntimeError as exc:
                message = str(exc)
                lowered = message.lower()
                if "interrupt" in lowered or "timeout" in lowered or "timed out" in lowered:
                    raise QueryTimeout(f"query exceeded {timeout_ms} ms") from exc
                if user:
                    raise QueryRejected(message.strip()) from exc
                raise
            if isinstance(result, list):  # several statements were executed; only the last carries the rows
                for extra in result[:-1]:
                    extra.close()
                result = result[-1]
            try:
                columns = list(result.get_column_names())
                types = list(result.get_column_data_types())
                rows = [list(r) for r in result.get_all()]
            finally:
                result.close()
        return columns, types, rows

    # ------------------------------------------------------------------ lifecycle

    def capabilities(self) -> dict[str, Any]:
        return {
            "cypher": True,
            "multi_label_patterns": self.engine == "ladybug",
            "shortest_path": True,
            "read_only": True,
            "recursive_filters": True,
            "parquet_copy": True,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "dialect": "kuzu",
        }

    def open(self) -> None:
        if self._db is not None:
            return
        if not self.db_path.exists():
            raise FileNotFoundError(f"embedded graph database not found at {self.db_path}; build it first")
        module = self._engine()
        self._db = module.Database(str(self.db_path), read_only=True)
        self._sidecar = self.stored_manifest() or {}
        self._node_tables = None
        log.info("opened %s database %s read-only (engine %s %s)", self.engine, self.db_path, self.engine, self.engine_version)

    def close(self) -> None:
        if self._db is not None:
            try:
                self._db.close()
            finally:
                self._db = None
                self._node_tables = None

    # ------------------------------------------------------------------ build

    @staticmethod
    def ddl_statements() -> list[str]:
        """DDL compiled from the schema registry: one node table per label, one rel table per edge type."""
        statements: list[str] = []
        for lbl in LABELS.values():
            cols = ", ".join(f"{ident(c.name)} {c.ddl_type}" for c in loader.node_columns(lbl))
            statements.append(f"CREATE NODE TABLE {ident(lbl.name)}({cols}, PRIMARY KEY(id))")
        for et in EDGE_TYPES.values():
            pairs = ", ".join(f"FROM {ident(a)} TO {ident(b)}" for a, b in et.pairs)
            cols = ", ".join(f"{ident(c.name)} {c.ddl_type}" for c in loader.edge_columns(et))
            statements.append(f"CREATE REL TABLE {ident(et.name)}({pairs}, {cols})")
        return statements

    def _remove_database_files(self) -> None:
        if self.db_path.is_dir():
            shutil.rmtree(self.db_path)
        for suffix in ("", ".wal", ".shadow", ".lock"):
            p = Path(f"{self.db_path}{suffix}")
            if p.exists() and not p.is_dir():
                p.unlink()
        if self.manifest_path.exists():
            self.manifest_path.unlink()

    def build(self, nodes_path: Path, edges_path: Path, manifest: dict) -> None:
        """(Re)create the database from the canonical JSONL files (see the module docstring)."""
        self.close()
        module = self._engine()
        t0 = time.perf_counter()
        plan = loader.plan_tables(nodes_path, edges_path)
        t_plan = time.perf_counter()
        parquet_dir = self.parquet_dir or loader.default_parquet_dir(nodes_path)
        files = loader.write_parquet_tables(plan, parquet_dir)
        t_parquet = time.perf_counter()

        self._remove_database_files()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        load_method: dict[str, str] = {}
        db = module.Database(str(self.db_path))
        con = module.Connection(db)
        try:
            for stmt in self.ddl_statements():
                con.execute(stmt)
            t_ddl = time.perf_counter()
            for label, path in files.nodes.items():
                try:
                    con.execute(f"COPY {ident(label)} FROM {lit(str(path))}")
                    load_method[label] = "copy"
                except RuntimeError as exc:
                    log.warning("COPY into %s failed (%s); falling back to batched CREATE", label, str(exc).splitlines()[0])
                    self._insert_nodes(con, label, plan.node_rows[label])
                    load_method[label] = "insert"
            for (etype, a, b), path in files.edges.items():
                options = f" (from={lit(a)}, to={lit(b)})" if len(EDGE_TYPES[etype].pairs) > 1 else ""
                try:
                    con.execute(f"COPY {ident(etype)} FROM {lit(str(path))}{options}")
                    load_method.setdefault(etype, "copy")
                except RuntimeError as exc:
                    log.warning("COPY into %s (%s->%s) failed (%s); falling back to batched CREATE", etype, a, b, str(exc).splitlines()[0])
                    self._insert_edges(con, etype, a, b, plan.edge_rows[(etype, a, b)])
                    load_method[etype] = "insert"
            t_load = time.perf_counter()
        finally:
            con.close()
            db.close()

        sidecar = {
            "checksum": manifest.get("checksum"),
            "engine": self.engine,
            "engine_version": self.engine_version,
            "built_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "node_counts": plan.node_counts(),
            "edge_counts": plan.edge_counts(),
            "duplicate_nodes": plan.duplicate_nodes,
            "duplicate_edges": plan.duplicate_edges,
            "skipped_nodes": dict(plan.skipped_nodes),
            "skipped_edges": dict(plan.skipped_edges),
            "coercion_failures": dict(files.coercion_failures),
            "load_method": load_method,
            "timings_s": {
                "plan": round(t_plan - t0, 3),
                "parquet": round(t_parquet - t_plan, 3),
                "ddl": round(t_ddl - t_parquet, 3),
                "load": round(t_load - t_ddl, 3),
                "total": round(t_load - t0, 3),
            },
            "manifest": {k: v for k, v in manifest.items() if k not in ("checksums",)},
        }
        self.manifest_path.write_text(json.dumps(sidecar, indent=2, default=str), encoding="utf-8")
        self._sidecar = sidecar
        log.info(
            "built %s database %s: %d nodes, %d edges in %.1fs (plan %.1fs, parquet %.1fs, ddl %.1fs, load %.1fs)",
            self.engine, self.db_path, plan.node_count, plan.edge_count, t_load - t0, t_plan - t0,
            t_parquet - t_plan, t_ddl - t_parquet, t_load - t_ddl,
        )

    @staticmethod
    def _param_values(values: dict[str, Any]) -> dict[str, Any]:
        # empty lists have no inferable element type as parameters -> NULL
        return {f"p_{k}": (None if isinstance(v, list) and not v else v) for k, v in values.items()}

    def _insert_nodes(self, con: Any, label: str, rows: Sequence[dict[str, Any]], batch: int = 500) -> None:
        lbl = LABELS[label]
        cols = loader.node_columns(lbl)
        props = ", ".join(f"{ident(c.name)}: $p_{c.name}" for c in cols)
        stmt = f"CREATE (n:{ident(label)} {{{props}}})"
        for start in range(0, len(rows), batch):
            con.execute("BEGIN TRANSACTION")
            for rec in rows[start : start + batch]:
                con.execute(stmt, self._param_values(loader.node_row_values(lbl, rec)))
            con.execute("COMMIT")

    def _insert_edges(self, con: Any, etype: str, a: str, b: str, rows: Sequence[dict[str, Any]], batch: int = 500) -> None:
        et = EDGE_TYPES[etype]
        cols = loader.edge_columns(et)
        props = ", ".join(f"{ident(c.name)}: $p_{c.name}" for c in cols)
        stmt = (
            f"MATCH (x:{ident(a)} {{id: $p_src}}), (y:{ident(b)} {{id: $p_dst}}) "
            f"CREATE (x)-[:{ident(etype)} {{{props}}}]->(y)"
        )
        for start in range(0, len(rows), batch):
            con.execute("BEGIN TRANSACTION")
            for rec in rows[start : start + batch]:
                params = self._param_values(loader.edge_row_values(et, rec))
                params["p_src"], params["p_dst"] = rec["src"], rec["dst"]
                con.execute(stmt, params)
            con.execute("COMMIT")

    # ------------------------------------------------------------------ record conversion

    @staticmethod
    def _node_record(d: dict[str, Any]) -> dict[str, Any]:
        raw = d.get("props")
        props = json.loads(raw) if isinstance(raw, str) and raw else {}
        return {
            "id": d["id"],
            "label": _meta(d, "_LABEL"),
            "name": d.get("name"),
            "source": d.get("source"),
            "source_id": d.get("source_id"),
            "first_seen": format_timestamp(d.get("first_seen")),
            "last_seen": format_timestamp(d.get("last_seen")),
            "confidence": d.get("confidence"),
            "props": props,
        }

    @staticmethod
    def _edge_record(src: str, dst: str, d: dict[str, Any]) -> dict[str, Any]:
        raw = d.get("props")
        props = json.loads(raw) if isinstance(raw, str) and raw else {}
        return {
            "type": _meta(d, "_LABEL"),
            "src": src,
            "dst": dst,
            "source": d.get("source"),
            "first_seen": format_timestamp(d.get("first_seen")),
            "last_seen": format_timestamp(d.get("last_seen")),
            "confidence": d.get("confidence"),
            "props": props,
        }

    # ------------------------------------------------------------------ lookups

    def get_node(self, node_id: str) -> dict | None:
        label = label_for_id(node_id)
        pattern = f"(n:{ident(label)} {{id: $id}})" if label in LABELS else "(n {id: $id})"
        _, _, rows = self._execute(f"MATCH {pattern} RETURN n LIMIT 1", {"id": node_id})
        return self._node_record(rows[0][0]) if rows else None

    def get_nodes(self, ids: Sequence[str]) -> list[dict]:
        wanted = list(dict.fromkeys(i for i in ids if i))
        if not wanted:
            return []
        by_label: dict[str | None, list[str]] = defaultdict(list)
        for nid in wanted:
            label = label_for_id(nid)
            by_label[label if label in LABELS else None].append(nid)
        found: dict[str, dict[str, Any]] = {}
        for label, group in by_label.items():
            pattern = f"(n:{ident(label)})" if label else "(n)"
            for start in range(0, len(group), 500):
                _, _, rows = self._execute(f"MATCH {pattern} WHERE n.id IN $ids RETURN n", {"ids": group[start : start + 500]})
                for (d,) in rows:
                    rec = self._node_record(d)
                    found[rec["id"]] = rec
        return [found[i] for i in wanted if i in found]

    def search(self, text: str, labels: Sequence[str] | None = None, limit: int = 25) -> list[SearchHit]:
        """Delegates to ``ContextGraph.search`` when a graph is attached (same ranking as the NetworkX backend);
        otherwise a Cypher scan over ``lower(n.name)`` / ``lower(n.id)`` ranked exact > prefix > contains."""
        if self.graph is not None:
            return self.graph.search(text, labels, limit)
        q = (text or "").strip().lower()
        if not q:
            return []
        wanted = self.check_labels(labels)
        where = ["(lower(n.name) CONTAINS $q OR lower(n.id) CONTAINS $q)"]
        if wanted:
            where.append("label(n) IN [" + ", ".join(lit(lbl) for lbl in wanted) + "]")
        candidates = max(int(limit) * 4, 50)
        _, _, rows = self._execute(f"MATCH (n) WHERE {' AND '.join(where)} RETURN n LIMIT {candidates}", {"q": q})
        scored = [(self.score_text_match(q, d), self._node_record(d)) for (d,) in rows]
        scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
        return [self.search_hit(rec, score) for score, rec in scored[: int(limit)]]

    # ------------------------------------------------------------------ neighborhood

    def _edges_among(self, ids: Sequence[str]) -> list[dict[str, Any]]:
        if len(ids) < 2:
            return []
        _, _, rows = self._execute(
            "MATCH (a)-[e]->(b) WHERE a.id IN $ids AND b.id IN $ids RETURN a.id, b.id, e", {"ids": list(ids)}
        )
        position = {nid: i for i, nid in enumerate(ids)}
        records = [self._edge_record(src, dst, e) for src, dst, e in rows]
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
        filters: list[str] = []
        if types:
            filters.append("label(r) IN [" + ", ".join(lit(t) for t in types) + "]")
        if wanted:
            filters.append("label(x) IN [" + ", ".join(lit(lbl) for lbl in wanted) + "]")
        recursive_filter = f" (r, x | WHERE {' AND '.join(filters)})" if filters else ""
        where = ["m.id <> $id"]
        if wanted:
            where.append("label(m) IN [" + ", ".join(lit(lbl) for lbl in wanted) + "]")
        start_pattern = f"(n:{ident(start['label'])} {{id: $id}})" if start["label"] in LABELS else "(n {id: $id})"
        pattern = f"MATCH {start_pattern}{left}[e* SHORTEST 1..{depth}{recursive_filter}]{right}(m) WHERE {' AND '.join(where)}"
        _, _, rows = self._execute(
            f"{pattern} RETURN m AS node, length(e) AS hops ORDER BY hops, m.id LIMIT {max_nodes}", {"id": node_id}
        )
        truncated = len(rows) >= max_nodes  # start node + max_nodes others would exceed the cap
        others = [self._node_record(d) for d, _ in rows[: max_nodes - 1]]
        records = [start, *others]
        ids = [r["id"] for r in records]
        total = len(records)
        if truncated:
            _, _, count_rows = self._execute(f"{pattern} RETURN count(DISTINCT m.id)", {"id": node_id})
            total = 1 + int(count_rows[0][0]) if count_rows else len(records)

        if self.graph is not None and all(i in self.graph for i in ids):
            fragment = self.graph.fragment(ids, focus=[node_id], layout_hint="neighborhood", max_nodes=max_nodes)
            fragment.truncated = fragment.truncated or truncated
            fragment.total_nodes = total
            return fragment
        return self.fragment_from_records(
            records, self._edges_among(ids), focus=[node_id], truncated=truncated, total_nodes=total
        )

    # ------------------------------------------------------------------ Cypher

    def _node_table_names(self) -> dict[int, str]:
        if self._node_tables is None:
            _, _, rows = self._execute("CALL show_tables() RETURN *")
            self._node_tables = {int(r[0]): str(r[1]) for r in rows if len(r) > 2 and str(r[2]).upper() == "NODE"}
        return self._node_tables

    def _collect_refs(self, value: Any, refs: set[tuple[int, int]]) -> None:
        if isinstance(value, dict):
            if _is_rel(value):
                for key in ("_SRC", "_DST"):
                    ref = _ref(_meta(value, key))
                    if ref is not None:
                        refs.add(ref)
            elif _is_recursive_rel(value):
                for rel in _meta(value, "_RELS") or []:
                    self._collect_refs(rel, refs)
            elif not _is_node(value):
                for v in value.values():
                    self._collect_refs(v, refs)
        elif isinstance(value, list | tuple):
            for v in value:
                self._collect_refs(v, refs)

    def _resolve_refs(self, refs: set[tuple[int, int]]) -> dict[tuple[int, int], str]:
        """Internal ``{table, offset}`` ids of relationship endpoints -> canonical node ids (one query per table)."""
        resolved: dict[tuple[int, int], str] = {}
        if not refs:
            return resolved
        names = self._node_table_names()
        by_table: dict[int, set[int]] = defaultdict(set)
        for table, offset in refs:
            by_table[table].add(offset)
        for table, offsets in by_table.items():
            name = names.get(table)
            if name is None:
                continue
            _, _, rows = self._execute(
                f"MATCH (n:{ident(name)}) WHERE offset(id(n)) IN $offs RETURN offset(id(n)) AS off, n.id AS id",
                {"offs": sorted(offsets)},
            )
            for off, nid in rows:
                resolved[(table, int(off))] = nid
        return resolved

    def _render_graph_value(self, value: Any, ctx: Any = None) -> tuple[bool, Any]:
        if not isinstance(value, dict):
            return False, None
        ids = ctx.ids if isinstance(ctx, _RenderCtx) else {}
        if _is_rel(value):
            src = _ref(_meta(value, "_SRC"))
            dst = _ref(_meta(value, "_DST"))
            return True, {"src": ids.get(src) if src else None, "type": _meta(value, "_LABEL"), "dst": ids.get(dst) if dst else None}
        if _is_recursive_rel(value):
            return True, {
                "nodes": [self.render_value(n, ctx) for n in (_meta(value, "_NODES") or [])],
                "rels": [self.render_value(r, ctx) for r in (_meta(value, "_RELS") or [])],
            }
        if _is_node(value):
            return True, {"id": value["id"], "label": _meta(value, "_LABEL"), "name": value.get("name")}
        return False, None

    @staticmethod
    def _pretty_column(name: str) -> str:
        """Kuzu names unaliased expressions like ``LABEL(e._ID,[...])`` or ``COUNT_STAR()``; tidy the common ones."""
        if name == "COUNT_STAR()":
            return "count(*)"
        if name.startswith("LABEL(") and "._ID," in name:
            return f"label({name[6:name.index('._ID,')]})"
        if name.endswith("._LENGTH"):
            return f"length({name[:-8]})"
        return name

    def run_readonly_cypher(
        self, query: str, params: dict | None = None, row_limit: int = 200, timeout_ms: int = 3000
    ) -> CypherResult:
        row_limit = max(1, min(int(row_limit), 5000))
        normalized = check_readonly(query, max_var_length=self.max_var_length, row_limit=row_limit + 1)
        t0 = time.perf_counter()
        columns, _, rows = self._execute(normalized, params or {}, timeout_ms=timeout_ms, user=True)
        truncated = len(rows) > row_limit
        rows = rows[:row_limit]
        refs: set[tuple[int, int]] = set()
        for row in rows:
            for value in row:
                self._collect_refs(value, refs)
        ctx = _RenderCtx(ids=self._resolve_refs(refs))
        rendered = self.render_rows(rows, ctx)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        return CypherResult(columns=[self._pretty_column(c) for c in columns], rows=rendered, elapsed_ms=elapsed_ms, truncated=truncated)

    # ------------------------------------------------------------------ stats & schema

    def build_info(self) -> dict[str, Any]:
        info = dict(self._sidecar or self.stored_manifest() or {})
        info.setdefault("engine", self.engine)
        info.setdefault("engine_version", self.engine_version)
        info["db_path"] = str(self.db_path)
        return json.loads(json.dumps(info, default=str))

    def stats(self) -> StatsOut:
        _, _, node_rows = self._execute("MATCH (n) RETURN label(n) AS l, count(*) AS c")
        _, _, edge_rows = self._execute("MATCH ()-[e]->() RETURN label(e) AS l, count(*) AS c")
        return self.stats_out({r[0]: r[1] for r in node_rows}, {r[0]: r[1] for r in edge_rows}, self.build_info())

    def schema_summary(self) -> dict[str, Any]:
        notes = list(DIALECT_NOTES)
        if self.engine == "ladybug":
            notes.append("Multi-label patterns (n:Alert|CloudEvent) are supported on this engine.")
        else:
            notes.append("Multi-label patterns (n:A|B) are NOT supported on Kuzu; use (n) WHERE label(n) IN ['A', 'B'].")
        return self.schema_summary_for(f"kuzu/{self.engine}", notes, EXAMPLE_QUERIES)
