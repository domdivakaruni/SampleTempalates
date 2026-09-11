"""Canonical graph loading, embedded-database building and loader-artifact exports.

Canonical data is the JSONL pair ``graph/nodes.jsonl`` / ``graph/edges.jsonl`` plus ``graph/manifest.json``
(docs/03-graph-schema.md section 2; docs/02-architecture.md section 11 item 2). Everything else here is a
*projection* of those files:

* ``load_context_graph(data_dir)`` builds the in-process NetworkX ``ContextGraph``;
* ``build_embedded_db(store, data_dir)`` (re)builds the embedded LadybugDB/Kuzu database through the store's
  ``build`` method, skipping the rebuild when the manifest checksum already stored next to the database matches;
* ``plan_tables`` / ``node_arrow_table`` / ``edge_arrow_table`` turn the JSONL into typed tables (one per node label,
  one per (edge type, from label, to label) pair) following the schema registry -- shared by the Parquet ``COPY``
  path of ``LadybugStore`` and by the exports;
* ``export_neo4j_import`` writes CSV files plus a ``LOAD CSV`` script for a manual Neo4j import;
* ``export_bigquery_tables`` writes Parquet tables plus a ``CREATE PROPERTY GRAPH`` SQL template for BigQuery Graph.

Type coercion is deliberately forgiving (``"true"`` -> BOOLEAN, ``1`` -> DOUBLE, ISO strings -> TIMESTAMP,
scalars -> single-element STRING[]) and never raises: an unconvertible value becomes NULL and is counted, so
one bad generator value cannot break the build. The full ``props`` object is always kept as a JSON string.
"""
from __future__ import annotations

import csv
import hashlib
import json
import logging
from collections import Counter, defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from throughline.graph.context_graph import ContextGraph
from throughline.graph.store import GraphStore, format_timestamp, parse_timestamp
from throughline.schema import (
    COMMON_EDGE_COLUMNS,
    COMMON_NODE_COLUMNS,
    EDGE_TYPES,
    LABELS,
    Column,
    EdgeType,
    NodeLabel,
)

log = logging.getLogger(__name__)

GRAPH_SUBDIR = "graph"
NODES_FILE = "nodes.jsonl"
EDGES_FILE = "edges.jsonl"
MANIFEST_FILE = "manifest.json"
PARQUET_SUBDIR = "parquet"

COMMON_NODE_NAMES = frozenset(c.name for c in COMMON_NODE_COLUMNS)
COMMON_EDGE_NAMES = frozenset(c.name for c in COMMON_EDGE_COLUMNS)

ARROW_TYPES: dict[str, pa.DataType] = {
    "STRING": pa.string(),
    "JSON": pa.string(),
    "INT64": pa.int64(),
    "DOUBLE": pa.float64(),
    "BOOLEAN": pa.bool_(),
    "TIMESTAMP": pa.timestamp("us"),
    "STRING[]": pa.list_(pa.string()),
}
_TRUE = {"true", "t", "yes", "y", "1"}
_FALSE = {"false", "f", "no", "n", "0"}


# ----------------------------------------------------------------------------- canonical files


def graph_paths(data_dir: Path | str) -> tuple[Path, Path, Path]:
    """``(nodes.jsonl, edges.jsonl, manifest.json)`` under ``<data_dir>/graph/``."""
    base = Path(data_dir) / GRAPH_SUBDIR
    return base / NODES_FILE, base / EDGES_FILE, base / MANIFEST_FILE


def iter_jsonl(path: Path | str) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def read_manifest(data_dir: Path | str) -> dict[str, Any]:
    _, _, manifest_path = graph_paths(data_dir)
    if not manifest_path.exists():
        return {}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def file_checksum(*paths: Path | str) -> str:
    h = hashlib.sha256()
    for p in paths:
        with Path(p).open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def manifest_checksum(data_dir: Path | str, manifest: dict[str, Any] | None = None) -> str:
    """The checksum identifying a build: ``manifest.checksum`` (or the joined ``checksums`` map) when the
    pipeline recorded one, otherwise a sha256 over the two JSONL files."""
    manifest = read_manifest(data_dir) if manifest is None else manifest
    if isinstance(manifest.get("checksum"), str) and manifest["checksum"]:
        return manifest["checksum"]
    checks = manifest.get("checksums")
    if isinstance(checks, dict) and checks:
        return hashlib.sha256("|".join(f"{k}={checks[k]}" for k in sorted(checks)).encode()).hexdigest()
    nodes_path, edges_path, _ = graph_paths(data_dir)
    return file_checksum(nodes_path, edges_path)


def load_context_graph(data_dir: Path | str) -> ContextGraph:
    """Load the canonical JSONL files under ``<data_dir>/graph/`` into a ``ContextGraph``."""
    nodes_path, edges_path, manifest_path = graph_paths(data_dir)
    for p in (nodes_path, edges_path):
        if not p.exists():
            raise FileNotFoundError(f"canonical graph file missing: {p} (run `throughline build-data` first)")
    graph = ContextGraph.from_jsonl(nodes_path, edges_path, manifest_path if manifest_path.exists() else None)
    log.info("loaded context graph from %s: %d nodes, %d edges", data_dir, len(graph), graph.G.number_of_edges())
    return graph


def build_embedded_db(store: GraphStore, data_dir: Path | str, force: bool = False) -> bool:
    """(Re)build ``store`` from the canonical files. Returns True when a build ran, False when it was skipped
    because the checksum recorded by the store (``store.stored_manifest()``) matches the current manifest.

    The store is left closed after a build; callers ``open()`` it afterwards.
    """
    nodes_path, edges_path, _ = graph_paths(data_dir)
    manifest = dict(read_manifest(data_dir))
    checksum = manifest_checksum(data_dir, manifest)
    manifest["checksum"] = checksum
    if not force:
        stored_fn = getattr(store, "stored_manifest", None)
        stored = stored_fn() if callable(stored_fn) else None
        if stored and stored.get("checksum") == checksum:
            log.info("embedded database is up to date (checksum %s); skipping rebuild", checksum[:12])
            return False
    store.build(nodes_path, edges_path, manifest)
    return True


# ----------------------------------------------------------------------------- typed tables


def node_columns(lbl: NodeLabel) -> list[Column]:
    """Common columns, then the label's typed columns (deduplicated against the common ones), then ``props``."""
    cols = [c for c in COMMON_NODE_COLUMNS if c.name != "props"]
    seen = {c.name for c in cols}
    for c in lbl.columns:
        if c.name not in seen and c.name != "props":
            cols.append(c)
            seen.add(c.name)
    cols.append(COMMON_NODE_COLUMNS[-1])
    return cols


def edge_columns(et: EdgeType) -> list[Column]:
    cols = [c for c in COMMON_EDGE_COLUMNS if c.name != "props"]
    seen = {c.name for c in cols}
    for c in et.columns:
        if c.name not in seen and c.name != "props":
            cols.append(c)
            seen.add(c.name)
    cols.append(COMMON_EDGE_COLUMNS[-1])
    return cols


def json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def coerce(value: Any, col_type: str) -> tuple[Any, bool]:
    """Convert a JSON value to the Python value for a typed column. Returns ``(value, failed)``; a failed
    conversion yields ``(None, True)`` so the caller can count it while the load continues."""
    if value is None or (isinstance(value, str) and value == "" and col_type != "STRING"):
        return None, False
    if col_type == "STRING":
        if isinstance(value, str):
            return value, False
        if isinstance(value, bool):
            return ("true" if value else "false"), False
        if isinstance(value, int | float):
            return str(value), False
        return json_dumps(value), False
    if col_type == "JSON":
        return (value if isinstance(value, str) else json_dumps(value)), False
    if col_type == "INT64":
        if isinstance(value, bool):
            return int(value), False
        if isinstance(value, int):
            return value, False
        if isinstance(value, float):
            return (int(value), False) if value.is_integer() else (None, True)
        if isinstance(value, str):
            try:
                return int(value.strip()), False
            except ValueError:
                try:
                    f = float(value.strip())
                    return (int(f), False) if f.is_integer() else (None, True)
                except ValueError:
                    return None, True
        return None, True
    if col_type == "DOUBLE":
        if isinstance(value, bool):
            return float(value), False
        if isinstance(value, int | float):
            return float(value), False
        if isinstance(value, str):
            try:
                return float(value.strip()), False
            except ValueError:
                return None, True
        return None, True
    if col_type == "BOOLEAN":
        if isinstance(value, bool):
            return value, False
        if isinstance(value, int | float) and value in (0, 1):
            return bool(value), False
        if isinstance(value, str):
            v = value.strip().lower()
            if v in _TRUE:
                return True, False
            if v in _FALSE:
                return False, False
        return None, True
    if col_type == "TIMESTAMP":
        parsed = parse_timestamp(value)
        return (parsed, False) if parsed is not None else (None, True)
    if col_type == "STRING[]":
        if isinstance(value, list | tuple | set | frozenset):
            return [x if isinstance(x, str) else json_dumps(x) for x in value if x is not None], False
        if isinstance(value, str):
            return [value], False
        return [json_dumps(value)], False
    return None, True


@dataclass
class TablePlan:
    """The canonical files regrouped into typed tables, deduplicated and validated against the registry."""

    node_rows: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    edge_rows: dict[tuple[str, str, str], list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    label_of: dict[str, str] = field(default_factory=dict)
    duplicate_nodes: int = 0
    duplicate_edges: int = 0
    skipped_nodes: Counter = field(default_factory=Counter)
    skipped_edges: Counter = field(default_factory=Counter)

    @property
    def node_count(self) -> int:
        return sum(len(v) for v in self.node_rows.values())

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self.edge_rows.values())

    def node_counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in sorted(self.node_rows.items())}

    def edge_counts(self) -> dict[str, int]:
        out: Counter = Counter()
        for (etype, _, _), rows in self.edge_rows.items():
            out[etype] += len(rows)
        return dict(sorted(out.items()))


def plan_tables(nodes_path: Path | str, edges_path: Path | str) -> TablePlan:
    """Read the JSONL files into per-label / per-(type, from, to) row lists.

    * duplicate node ids keep the first record; edges of one type between one pair keep the first edge
      (deterministic output; Ladybug rel tables would otherwise accept the duplicates);
    * nodes with an unknown label and edges with an unknown type, a dangling endpoint or a pair the registry
      does not allow are skipped and counted (the pipeline validates upstream; this is defensive).
    """
    plan = TablePlan()
    seen_edges: set[tuple[str, str, str]] = set()
    for rec in iter_jsonl(nodes_path):
        label = rec.get("label")
        nid = rec.get("id")
        if not nid or label not in LABELS:
            plan.skipped_nodes[f"unknown label {label!r}"] += 1
            continue
        if nid in plan.label_of:
            plan.duplicate_nodes += 1
            continue
        plan.label_of[nid] = label
        plan.node_rows[label].append(rec)
    for rec in iter_jsonl(edges_path):
        etype = rec.get("type")
        et = EDGE_TYPES.get(etype or "")
        if et is None:
            plan.skipped_edges[f"unknown type {etype!r}"] += 1
            continue
        src, dst = rec.get("src"), rec.get("dst")
        s_label, d_label = plan.label_of.get(src or ""), plan.label_of.get(dst or "")
        if s_label is None or d_label is None:
            plan.skipped_edges["dangling endpoint"] += 1
            continue
        if not et.allows(s_label, d_label):
            plan.skipped_edges[f"pair not allowed for {etype}: {s_label}->{d_label}"] += 1
            continue
        key = (etype, src, dst)  # type: ignore[arg-type]
        if key in seen_edges:
            plan.duplicate_edges += 1
            continue
        seen_edges.add(key)
        plan.edge_rows[(etype, s_label, d_label)].append(rec)  # type: ignore[index]
    if plan.duplicate_nodes or plan.duplicate_edges or plan.skipped_nodes or plan.skipped_edges:
        log.warning(
            "table plan: %d duplicate nodes, %d duplicate edges, skipped nodes %s, skipped edges %s",
            plan.duplicate_nodes, plan.duplicate_edges, dict(plan.skipped_nodes), dict(plan.skipped_edges),
        )
    return plan


def node_row_values(lbl: NodeLabel, rec: dict[str, Any], failures: Counter | None = None) -> dict[str, Any]:
    """Typed Python values for one node record, keyed by column name (``props`` becomes a JSON string)."""
    out: dict[str, Any] = {}
    props = rec.get("props") or {}
    for col in node_columns(lbl):
        if col.name == "props":
            out["props"] = json_dumps(props)
            continue
        raw = rec.get(col.name) if col.name in COMMON_NODE_NAMES else props.get(col.name)
        value, failed = coerce(raw, col.type)
        if failed and failures is not None:
            failures[f"{lbl.name}.{col.name}"] += 1
        out[col.name] = value
    return out


def edge_row_values(et: EdgeType, rec: dict[str, Any], failures: Counter | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    props = rec.get("props") or {}
    for col in edge_columns(et):
        if col.name == "props":
            out["props"] = json_dumps(props)
            continue
        raw = rec.get(col.name) if col.name in COMMON_EDGE_NAMES else props.get(col.name)
        value, failed = coerce(raw, col.type)
        if failed and failures is not None:
            failures[f"{et.name}.{col.name}"] += 1
        out[col.name] = value
    return out


def node_arrow_table(lbl: NodeLabel, rows: Sequence[dict[str, Any]], failures: Counter | None = None) -> pa.Table:
    cols = node_columns(lbl)
    values = [node_row_values(lbl, rec, failures) for rec in rows]
    return pa.table({c.name: pa.array([v[c.name] for v in values], type=ARROW_TYPES[c.type]) for c in cols})


def edge_arrow_table(
    et: EdgeType, rows: Sequence[dict[str, Any]], failures: Counter | None = None, src_col: str = "from", dst_col: str = "to"
) -> pa.Table:
    cols = edge_columns(et)
    values = [edge_row_values(et, rec, failures) for rec in rows]
    arrays: dict[str, pa.Array] = {
        src_col: pa.array([r["src"] for r in rows], type=pa.string()),
        dst_col: pa.array([r["dst"] for r in rows], type=pa.string()),
    }
    for c in cols:
        arrays[c.name] = pa.array([v[c.name] for v in values], type=ARROW_TYPES[c.type])
    return pa.table(arrays)


def default_parquet_dir(nodes_path: Path | str) -> Path:
    """``<data_dir>/parquet`` for ``<data_dir>/graph/nodes.jsonl``; a sibling ``parquet`` dir otherwise."""
    p = Path(nodes_path).resolve()
    base = p.parent.parent if p.parent.name == GRAPH_SUBDIR else p.parent
    return base / PARQUET_SUBDIR


@dataclass
class ParquetFiles:
    nodes: dict[str, Path]
    edges: dict[tuple[str, str, str], Path]
    coercion_failures: Counter


def write_parquet_tables(plan: TablePlan, out_dir: Path | str, *, src_col: str = "from", dst_col: str = "to", include_empty_labels: bool = False) -> ParquetFiles:
    """One Parquet file per node label (``nodes/<Label>.parquet``) and per (type, from, to) pair
    (``edges/<TYPE>__<From>__<To>.parquet``), column order = registry DDL order (COPY maps positionally)."""
    out = Path(out_dir)
    (out / "nodes").mkdir(parents=True, exist_ok=True)
    (out / "edges").mkdir(parents=True, exist_ok=True)
    failures: Counter = Counter()
    node_files: dict[str, Path] = {}
    for lbl in LABELS.values():
        rows = plan.node_rows.get(lbl.name, [])
        if not rows and not include_empty_labels:
            continue
        path = out / "nodes" / f"{lbl.name}.parquet"
        pq.write_table(node_arrow_table(lbl, rows, failures), path, compression="snappy")
        node_files[lbl.name] = path
    edge_files: dict[tuple[str, str, str], Path] = {}
    for key in sorted(plan.edge_rows):
        etype, a, b = key
        path = out / "edges" / f"{etype}__{a}__{b}.parquet"
        pq.write_table(edge_arrow_table(EDGE_TYPES[etype], plan.edge_rows[key], failures, src_col, dst_col), path, compression="snappy")
        edge_files[key] = path
    if failures:
        log.warning("typed-column coercion failures (stored as NULL): %s", dict(failures.most_common(20)))
    return ParquetFiles(nodes=node_files, edges=edge_files, coercion_failures=failures)


# ----------------------------------------------------------------------------- exports


def _csv_value(value: Any, col_type: str) -> str:
    if value is None:
        return ""
    if col_type == "STRING[]":
        return ";".join(value)
    if col_type == "TIMESTAMP":
        return format_timestamp(value) or ""
    if col_type == "BOOLEAN":
        return "true" if value else "false"
    return str(value)


def _neo4j_conversion(col: Column) -> str:
    expr = f"row.`{col.name}`"
    if col.type == "INT64":
        return f"toInteger({expr})"
    if col.type == "DOUBLE":
        return f"toFloat({expr})"
    if col.type == "BOOLEAN":
        return f"toBoolean({expr})"
    if col.type == "TIMESTAMP":
        return f"CASE WHEN {expr} IS NULL OR {expr} = '' THEN null ELSE datetime({expr}) END"
    if col.type == "STRING[]":
        return f"CASE WHEN {expr} IS NULL OR {expr} = '' THEN null ELSE split({expr}, ';') END"
    return f"CASE WHEN {expr} = '' THEN null ELSE {expr} END"


def export_neo4j_import(data_dir: Path | str, out_dir: Path | str) -> dict[str, Any]:
    """Write ``nodes_<Label>.csv`` / ``rels_<TYPE>.csv`` plus ``import.cypher`` (constraints and ``LOAD CSV``
    statements in 5k-row transactions) for a manual Neo4j import. Lists are ``;``-joined, JSON columns and the
    full ``props`` object are strings (``props_json``), timestamps ISO-8601. Returns the files written."""
    nodes_path, edges_path, _ = graph_paths(data_dir)
    plan = plan_tables(nodes_path, edges_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    failures: Counter = Counter()
    files: list[str] = []
    script: list[str] = [
        "// Throughline graph -> Neo4j import script (generated by throughline.graph.loader.export_neo4j_import)",
        "// 1. copy the CSV files from this directory into the Neo4j `import/` folder",
        "// 2. run:  cat import.cypher | cypher-shell -u neo4j -p <password> -d neo4j",
        "// Every node carries its own label plus the `Node` super-label; lists are `;`-joined in the CSV.",
        "",
        "CREATE CONSTRAINT node_id IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE;",
        "CREATE INDEX node_name IF NOT EXISTS FOR (n:Node) ON (n.name);",
    ]
    for lbl in LABELS.values():
        script.append(f"CREATE CONSTRAINT {lbl.name.lower()}_id IF NOT EXISTS FOR (n:{lbl.name}) REQUIRE n.id IS UNIQUE;")
    script.append("")
    for lbl in LABELS.values():
        rows = plan.node_rows.get(lbl.name)
        if not rows:
            continue
        cols = node_columns(lbl)
        header = [c.name if c.name != "props" else "props_json" for c in cols]
        fname = f"nodes_{lbl.name}.csv"
        with (out / fname).open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for rec in rows:
                values = node_row_values(lbl, rec, failures)
                writer.writerow([_csv_value(values[c.name], c.type) for c in cols])
        files.append(fname)
        sets = ", ".join(
            f"n.`{c.name}` = {_neo4j_conversion(c)}" for c in cols if c.name not in ("id", "props")
        )
        script.append(
            f"LOAD CSV WITH HEADERS FROM 'file:///{fname}' AS row\n"
            f"CALL {{ WITH row MERGE (n:{lbl.name}:Node {{id: row.id}}) SET {sets}, n.props_json = row.props_json }}\n"
            f"IN TRANSACTIONS OF 5000 ROWS;"
        )
    script.append("")
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for (etype, _, _), rows in sorted(plan.edge_rows.items()):
        by_type[etype].extend(rows)
    for etype, rows in by_type.items():
        et = EDGE_TYPES[etype]
        cols = edge_columns(et)
        header = ["src", "dst"] + [c.name if c.name != "props" else "props_json" for c in cols]
        fname = f"rels_{etype}.csv"
        with (out / fname).open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for rec in rows:
                values = edge_row_values(et, rec, failures)
                writer.writerow([rec["src"], rec["dst"]] + [_csv_value(values[c.name], c.type) for c in cols])
        files.append(fname)
        sets = ", ".join(f"r.`{c.name}` = {_neo4j_conversion(c)}" for c in cols if c.name != "props")
        script.append(
            f"LOAD CSV WITH HEADERS FROM 'file:///{fname}' AS row\n"
            f"CALL {{ WITH row MATCH (a:Node {{id: row.src}}), (b:Node {{id: row.dst}}) MERGE (a)-[r:{etype}]->(b) "
            f"SET {sets}, r.props_json = row.props_json }}\nIN TRANSACTIONS OF 5000 ROWS;"
        )
    (out / "import.cypher").write_text("\n".join(script) + "\n", encoding="utf-8")
    files.append("import.cypher")
    result = {
        "out_dir": str(out), "files": files, "node_counts": plan.node_counts(), "edge_counts": plan.edge_counts(),
        "coercion_failures": dict(failures),
    }
    (out / "export_manifest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def export_bigquery_tables(data_dir: Path | str, out_dir: Path | str, project: str = "${PROJECT}", dataset: str = "${DATASET}") -> dict[str, Any]:
    """Write Parquet tables (``nodes/<Label>.parquet`` for every label, ``edges/<TYPE>__<From>__<To>.parquet`` per
    populated pair with ``src``/``dst`` columns) plus ``create_property_graph.sql``, a GoogleSQL
    ``CREATE PROPERTY GRAPH`` template naming every exported table. Export only; BigQuery never becomes the
    source of truth (docs/02-architecture.md section 2.2)."""
    nodes_path, edges_path, _ = graph_paths(data_dir)
    plan = plan_tables(nodes_path, edges_path)
    out = Path(out_dir)
    files = write_parquet_tables(plan, out, src_col="src", dst_col="dst", include_empty_labels=True)
    prefix = f"`{project}.{dataset}"
    node_tables = [f"    {prefix}.n_{lbl}` AS {lbl} KEY (id) LABEL {lbl} PROPERTIES ARE ALL COLUMNS" for lbl in files.nodes]
    edge_tables = [
        f"    {prefix}.e_{etype}__{a}__{b}` AS {etype}_{a}_{b}\n"
        f"      SOURCE KEY (src) REFERENCES {a} (id)\n"
        f"      DESTINATION KEY (dst) REFERENCES {b} (id)\n"
        f"      LABEL {etype} PROPERTIES ARE ALL COLUMNS EXCEPT (src, dst)"
        for (etype, a, b) in files.edges
    ]
    loads = [
        f"-- bq load --source_format=PARQUET {project}:{dataset}.n_{lbl} {path.relative_to(out).as_posix()}"
        for lbl, path in files.nodes.items()
    ] + [
        f"-- bq load --source_format=PARQUET {project}:{dataset}.e_{etype}__{a}__{b} {path.relative_to(out).as_posix()}"
        for (etype, a, b), path in files.edges.items()
    ]
    sql = "\n".join(
        [
            "-- Throughline graph -> BigQuery Graph property-graph definition (template).",
            "-- Generated by throughline.graph.loader.export_bigquery_tables; substitute ${PROJECT} / ${DATASET}.",
            "-- One node table per label, one edge table per (edge type, from label, to label) pair;",
            "-- TIMESTAMP columns are UTC, STRING[] columns are ARRAY<STRING>, JSON columns are STRING.",
            "-- Load the Parquet files first, e.g.:",
            *loads,
            "",
            f"CREATE OR REPLACE PROPERTY GRAPH {prefix}.throughline`",
            "  NODE TABLES (",
            ",\n".join(node_tables),
            "  )",
            "  EDGE TABLES (",
            ",\n".join(edge_tables),
            "  );",
            "",
        ]
    )
    (out / "create_property_graph.sql").write_text(sql, encoding="utf-8")
    result = {
        "out_dir": str(out),
        "node_tables": {lbl: str(p.relative_to(out)) for lbl, p in files.nodes.items()},
        "edge_tables": {f"{e}__{a}__{b}": str(p.relative_to(out)) for (e, a, b), p in files.edges.items()},
        "sql": "create_property_graph.sql",
        "node_counts": plan.node_counts(),
        "edge_counts": plan.edge_counts(),
        "coercion_failures": dict(files.coercion_failures),
    }
    (out / "export_manifest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
