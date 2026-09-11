"""GraphStore protocol, shared result/exception types and the ``BaseStore`` helper mixin.

The protocol is the exact contract from docs/06-build-plan.md section 3.1. Every backend
(``LadybugStore`` for LadybugDB/Kuzu, ``NetworkXStore`` over the in-process projection, ``Neo4jStore``
over Bolt) implements it; ``factory.make_store`` picks one from the settings and the conformance
tests in ``tests/conformance`` run the same assertions against every backend that is available.

``BaseStore`` carries the pieces that must render identically on every backend:

* node/edge records (the ``nodes.jsonl`` / ``edges.jsonl`` shapes) -> ``NodeOut`` / ``EdgeOut`` exactly as
  ``ContextGraph.node_out`` / ``edge_out`` render them (tags, severity, score, category);
* JSON-serialisation of Cypher row values: node values become ``{"id", "label", "name"}``, relationship
  values ``{"src", "type", "dst"}``, paths ``{"nodes": [...], "rels": [...]}``, timestamps ISO-8601 UTC
  strings, lists and maps are preserved, everything exotic (decimal, uuid, blob, interval) is made JSON-safe;
* the schema summary served to agents (labels, typed columns, edge types with pairs) plus per-dialect notes;
* argument validation shared by ``neighborhood`` implementations.
"""
from __future__ import annotations

import base64
import datetime as dt
import decimal
import math
import uuid
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from throughline.graph.context_graph import EDGE_META_KEYS, NODE_META_KEYS, edge_id
from throughline.models import EdgeOut, GraphFragment, NodeOut, SearchHit, StatsOut
from throughline.schema import CATEGORIES, COMMON_EDGE_COLUMNS, COMMON_NODE_COLUMNS, EDGE_TYPES, LABELS, category_of

# ----------------------------------------------------------------------------- contract types


class CypherResult(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    elapsed_ms: int
    truncated: bool = False


class NotSupported(Exception):
    """The backend cannot perform the operation (for example Cypher on the NetworkX backend)."""


class QueryRejected(Exception):
    """The read-only gate refused the query, or the engine's parser/binder could not compile it."""


class QueryTimeout(Exception):
    """The query exceeded its time budget and was interrupted."""


@runtime_checkable
class GraphStore(Protocol):
    name: str

    def capabilities(self) -> dict[str, Any]: ...

    def build(self, nodes_path: Path, edges_path: Path, manifest: dict) -> None: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def get_node(self, node_id: str) -> dict | None: ...

    def get_nodes(self, ids: Sequence[str]) -> list[dict]: ...

    def search(self, text: str, labels: Sequence[str] | None = None, limit: int = 25) -> list[SearchHit]: ...

    def neighborhood(
        self,
        node_id: str,
        depth: int = 1,
        edge_types: Sequence[str] | None = None,
        direction: str = "both",
        labels: Sequence[str] | None = None,
        max_nodes: int = 150,
    ) -> GraphFragment: ...

    def run_readonly_cypher(
        self, query: str, params: dict | None = None, row_limit: int = 200, timeout_ms: int = 3000
    ) -> CypherResult: ...

    def stats(self) -> StatsOut: ...

    def schema_summary(self) -> dict[str, Any]: ...


# ----------------------------------------------------------------------------- record helpers

DIRECTIONS = ("both", "in", "out")
SNIPPET_KEYS = ("hostname", "title", "email", "address", "fqdn", "cve_id", "arn", "description")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def format_timestamp(value: Any) -> str | None:
    """Render a datetime as the canonical ISO-8601 UTC string (``2026-09-10T02:11:45Z``).

    Naive datetimes are taken to be UTC (both embedded engines return naive UTC values). Strings are
    returned unchanged so records that never went through a TIMESTAMP column round-trip losslessly.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(dt.UTC).replace(tzinfo=None)
        if value.microsecond:
            return value.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"
        return value.strftime(TIMESTAMP_FORMAT)
    if isinstance(value, dt.date):
        return value.isoformat()
    return str(value)


def parse_timestamp(value: Any) -> dt.datetime | None:
    """Parse an ISO-8601 string (or epoch number / datetime) into a naive UTC datetime; None if impossible."""
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day)
    if isinstance(value, int | float) and not isinstance(value, bool):
        return dt.datetime.fromtimestamp(float(value), tz=dt.UTC).replace(tzinfo=None)
    if isinstance(value, str):
        text = value.strip()
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00") if text.endswith("Z") else text)
        except ValueError:
            text = text.replace(" ", "T")
            try:
                parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00") if text.endswith("Z") else text)
            except ValueError:
                return None
        return parsed.astimezone(dt.UTC).replace(tzinfo=None) if parsed.tzinfo else parsed
    return None


def flatten_record(rec: Mapping[str, Any]) -> dict[str, Any]:
    """``nodes.jsonl`` record -> flat attribute dict (meta keys plus ``props``), like ContextGraph stores it."""
    attrs = {k: rec.get(k) for k in NODE_META_KEYS}
    for k, v in (rec.get("props") or {}).items():
        if k not in NODE_META_KEYS:
            attrs[k] = v
    return attrs


def record_from_flat(attrs: Mapping[str, Any]) -> dict[str, Any]:
    """Flat attribute dict (ContextGraph node attributes) -> ``nodes.jsonl`` record."""
    rec = {k: attrs.get(k) for k in NODE_META_KEYS}
    rec["props"] = {k: v for k, v in attrs.items() if k not in NODE_META_KEYS}
    return rec


def edge_record_from_flat(src: str, dst: str, data: Mapping[str, Any]) -> dict[str, Any]:
    """Flat ContextGraph edge attributes -> ``edges.jsonl`` record."""
    rec: dict[str, Any] = {"type": data["type"], "src": src, "dst": dst}
    for k in EDGE_META_KEYS[1:]:
        rec[k] = data.get(k)
    rec["props"] = {k: v for k, v in data.items() if k not in EDGE_META_KEYS}
    return rec


class BaseStore:
    """Shared helpers for GraphStore implementations (rendering, schema summary, validation)."""

    name: str = "base"

    # ------------------------------------------------------------------ record -> output models

    @staticmethod
    def record_to_node_out(rec: Mapping[str, Any], highlight: bool = False, extra_tags: Iterable[str] = ()) -> NodeOut:
        """Mirror of ``ContextGraph.node_out`` for a ``nodes.jsonl``-shaped record (kept in lock-step by tests)."""
        attrs = flatten_record(rec)
        node_id = attrs["id"]
        label = attrs.get("label") or "Unknown"
        props = {k: v for k, v in attrs.items() if k not in NODE_META_KEYS and v is not None}
        tags = list(extra_tags)
        if attrs.get("crown_jewel"):
            tags.append("crown_jewel")
        if attrs.get("exposure") == "internet" or attrs.get("public") is True:
            tags.append("internet_exposed")
        if attrs.get("storyline_id"):
            tags.append(f"storyline:{attrs['storyline_id']}")
        if (attrs.get("ioc_match_count") or 0) > 0:
            tags.append("ioc_match")
        severity = attrs.get("vendor_severity") if label == "Alert" else attrs.get("severity")
        score = attrs.get("contextual_score") if label in ("Alert", "Storyline") else None
        return NodeOut(
            id=node_id, label=label, name=attrs.get("name") or node_id, category=category_of(label),
            severity=severity, score=score, highlight=highlight, tags=list(dict.fromkeys(tags)), props=props,
        )

    @staticmethod
    def edge_record_to_out(rec: Mapping[str, Any], highlight: bool = False) -> EdgeOut:
        """Mirror of ``ContextGraph.edge_out`` for an ``edges.jsonl``-shaped record."""
        etype = rec["type"]
        props = {k: v for k, v in (rec.get("props") or {}).items() if k not in EDGE_META_KEYS and v is not None}
        et = EDGE_TYPES.get(etype)
        return EdgeOut(
            id=edge_id(rec["src"], etype, rec["dst"]), type=etype, src=rec["src"], dst=rec["dst"],
            derived=bool(et and et.derived) or rec.get("source") == "derived",
            confidence=float(rec.get("confidence") or 1.0), highlight=highlight, props=props,
        )

    @staticmethod
    def snippet_for(attrs: Mapping[str, Any]) -> str | None:
        for key in SNIPPET_KEYS:
            val = attrs.get(key)
            if isinstance(val, str) and val and val != attrs.get("name"):
                return val[:120]
        return None

    @classmethod
    def search_hit(cls, rec: Mapping[str, Any], score: float) -> SearchHit:
        attrs = flatten_record(rec)
        label = attrs.get("label") or "Unknown"
        return SearchHit(
            id=attrs["id"], label=label, name=attrs.get("name") or attrs["id"], category=category_of(label),
            snippet=cls.snippet_for(attrs), score=score,
        )

    @staticmethod
    def score_text_match(query: str, rec: Mapping[str, Any]) -> float:
        """Simple deterministic ranking used by the Cypher-based ``search`` paths (exact > prefix > contains)."""
        q = query.lower()
        name = str(rec.get("name") or "").lower()
        node_id = str(rec.get("id") or "").lower()
        score = 0.0
        if name == q:
            score += 3.0
        elif name.startswith(q):
            score += 2.0
        elif q in name:
            score += 1.0
        if node_id == q:
            score += 3.0
        elif q in node_id:
            score += 1.0
        return score

    def fragment_from_records(
        self,
        node_records: Sequence[Mapping[str, Any]],
        edge_records: Iterable[Mapping[str, Any]],
        *,
        focus: Iterable[str] = (),
        highlight_ids: Iterable[str] = (),
        layout_hint: str = "neighborhood",
        truncated: bool = False,
        total_nodes: int | None = None,
        max_edges: int = 800,
    ) -> GraphFragment:
        """Assemble a GraphFragment from record dicts; parallel edges of one type collapse (first wins)."""
        hl = set(highlight_ids)
        nodes = [self.record_to_node_out(r, highlight=r["id"] in hl) for r in node_records]
        idset = {n.id for n in nodes}
        seen: set[str] = set()
        edges: list[EdgeOut] = []
        for rec in edge_records:
            if rec["src"] not in idset or rec["dst"] not in idset:
                continue
            eid = edge_id(rec["src"], rec["type"], rec["dst"])
            if eid in seen:
                continue
            seen.add(eid)
            edges.append(self.edge_record_to_out(rec, highlight=rec["src"] in hl and rec["dst"] in hl))
        if len(edges) > max_edges:
            edges, truncated = sorted(edges, key=lambda e: not e.highlight)[:max_edges], True
        return GraphFragment(
            nodes=nodes, edges=edges, focus=list(focus), layout_hint=layout_hint,  # type: ignore[arg-type]
            truncated=truncated, total_nodes=total_nodes if total_nodes is not None else len(nodes),
        )

    # ------------------------------------------------------------------ Cypher row rendering

    def render_rows(self, rows: Iterable[Sequence[Any]], ctx: Any = None) -> list[list[Any]]:
        return [[self.render_value(v, ctx) for v in row] for row in rows]

    def render_value(self, value: Any, ctx: Any = None) -> Any:
        """Make any driver value JSON-safe; graph values go through ``_render_graph_value`` first."""
        handled, rendered = self._render_graph_value(value, ctx)
        if handled:
            return rendered
        if value is None or isinstance(value, bool | int | str):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, dt.datetime | dt.date):
            return format_timestamp(value)
        if isinstance(value, dt.time):
            return value.isoformat()
        if isinstance(value, dt.timedelta):
            return str(value)
        if isinstance(value, decimal.Decimal):
            return float(value)
        if isinstance(value, uuid.UUID):
            return str(value)
        if isinstance(value, bytes | bytearray):
            return base64.b64encode(bytes(value)).decode("ascii")
        if isinstance(value, Mapping):
            return {str(k): self.render_value(v, ctx) for k, v in value.items()}
        if isinstance(value, list | tuple | set | frozenset):
            return [self.render_value(v, ctx) for v in value]
        return str(value)

    def _render_graph_value(self, value: Any, ctx: Any = None) -> tuple[bool, Any]:
        """Backend hook: return ``(True, rendered)`` for node/relationship/path values, else ``(False, None)``."""
        return False, None

    # ------------------------------------------------------------------ schema summary

    @staticmethod
    def schema_tables() -> dict[str, Any]:
        labels = [
            {
                "name": lbl.name,
                "category": lbl.category,
                "id_prefix": lbl.id_prefix,
                "columns": [{"name": c.name, "type": c.type} for c in (*COMMON_NODE_COLUMNS[:-1], *lbl.columns, COMMON_NODE_COLUMNS[-1])],
            }
            for lbl in LABELS.values()
        ]
        edge_types = [
            {
                "name": et.name,
                "pairs": [list(p) for p in et.pairs],
                "columns": [{"name": c.name, "type": c.type} for c in (*COMMON_EDGE_COLUMNS[:-1], *et.columns, COMMON_EDGE_COLUMNS[-1])],
                "derived": et.derived,
            }
            for et in EDGE_TYPES.values()
        ]
        return {"categories": dict(CATEGORIES), "labels": labels, "edge_types": edge_types}

    def schema_summary_for(self, dialect: str, notes: Sequence[str], examples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        summary = self.schema_tables()
        summary.update(
            {
                "backend": self.name,
                "dialect": dialect,
                "notes": list(notes),
                "key_properties": {
                    "every node": ["id", "label (one per node)", "name", "source", "first_seen", "last_seen", "confidence", "props (JSON string)"],
                    "Alert": ["source_system", "vendor_severity", "contextual_score", "contextual_band", "techniques", "storyline_id", "reaches_crown_jewel"],
                    "StorageBucket/Database/Secret": ["sensitivity", "data_classifications", "crown_jewel", "public"],
                    "VirtualMachine": ["exposure", "environment", "has_edr_sensor", "crown_jewel_reach"],
                    "Vulnerability": ["cve_id", "cvss", "kev", "exploitation_status", "sector_targeting_relevance"],
                },
                "example_queries": [dict(e) for e in examples],
            }
        )
        return summary

    # ------------------------------------------------------------------ stats

    def stats_out(self, node_counts: Mapping[str, int], edge_counts: Mapping[str, int], build: Mapping[str, Any] | None = None) -> StatsOut:
        nodes = {k: int(v) for k, v in sorted(node_counts.items())}
        edges = {k: int(v) for k, v in sorted(edge_counts.items())}
        return StatsOut(
            node_counts=nodes, edge_counts=edges, total_nodes=sum(nodes.values()), total_edges=sum(edges.values()),
            backend=self.name, capabilities=self.capabilities(), build=dict(build or {}),  # type: ignore[attr-defined]
        )

    # ------------------------------------------------------------------ argument validation

    @staticmethod
    def check_direction(direction: str) -> str:
        d = (direction or "both").lower()
        if d not in DIRECTIONS:
            raise ValueError(f"direction must be one of {DIRECTIONS}, got {direction!r}")
        return d

    @staticmethod
    def check_depth(depth: int, max_depth: int = 6) -> int:
        if not isinstance(depth, int) or depth < 1 or depth > max_depth:
            raise ValueError(f"depth must be an integer between 1 and {max_depth}, got {depth!r}")
        return depth

    @staticmethod
    def check_edge_types(edge_types: Sequence[str] | None) -> list[str] | None:
        if not edge_types:
            return None
        unknown = [t for t in edge_types if t not in EDGE_TYPES]
        if unknown:
            raise ValueError(f"unknown edge type(s): {unknown}")
        return list(dict.fromkeys(edge_types))

    @staticmethod
    def check_labels(labels: Sequence[str] | None) -> list[str] | None:
        if not labels:
            return None
        unknown = [lbl for lbl in labels if lbl not in LABELS]
        if unknown:
            raise ValueError(f"unknown label(s): {unknown}")
        return list(dict.fromkeys(labels))
