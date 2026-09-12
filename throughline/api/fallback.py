"""Minimal GraphStore over the in-memory ``ContextGraph`` (no Cypher).

The real backends live in ``throughline.graph`` (Agent B). This adapter exists so the API, the CLI and the tests
can serve every non-Cypher endpoint from the canonical JSONL files even when ``throughline.graph.factory`` is not
importable (or the embedded database cannot be opened). It follows the ``GraphStore`` protocol of
docs/06-build-plan.md section 3.1.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from throughline.api.errors import NotSupported
from throughline.graph.context_graph import NODE_META_KEYS, ContextGraph
from throughline.models import GraphFragment, SearchHit, StatsOut
from throughline.schema import EDGE_TYPES, LABELS


def graph_paths(data_dir: Path) -> tuple[Path, Path, Path]:
    base = Path(data_dir) / "graph"
    return base / "nodes.jsonl", base / "edges.jsonl", base / "manifest.json"


def load_context_graph_fallback(data_dir: Path) -> ContextGraph:
    nodes, edges, manifest = graph_paths(data_dir)
    if not nodes.is_file() or not edges.is_file():
        raise FileNotFoundError(f"no graph data at {nodes.parent}; run `throughline build-data` first")
    return ContextGraph.from_jsonl(nodes, edges, manifest if manifest.is_file() else None)


class ContextGraphStore:
    """GraphStore protocol implementation backed by a ``ContextGraph``; Cypher is not supported."""

    name = "networkx"

    def __init__(self, graph: ContextGraph) -> None:
        self.graph = graph
        self._open = True

    # -- lifecycle --------------------------------------------------------
    def capabilities(self) -> dict[str, Any]:
        return {"cypher": False, "multi_label_patterns": False, "shortest_path": True, "read_only": True}

    def build(self, nodes_path: Path, edges_path: Path, manifest: dict[str, Any]) -> None:
        self.graph = ContextGraph.from_jsonl(nodes_path, edges_path)
        self.graph.build_info = dict(manifest or {})

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    # -- nodes ------------------------------------------------------------
    def _record(self, node_id: str) -> dict[str, Any] | None:
        attrs = self.graph.node(node_id)
        if attrs is None:
            return None
        rec = {k: attrs.get(k) for k in NODE_META_KEYS}
        rec["props"] = {k: v for k, v in attrs.items() if k not in NODE_META_KEYS and v is not None}
        return rec

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        return self._record(node_id)

    def get_nodes(self, ids: Sequence[str]) -> list[dict[str, Any]]:
        out = []
        for i in dict.fromkeys(ids):
            rec = self._record(i)
            if rec is not None:
                out.append(rec)
        return out

    def search(self, text: str, labels: Sequence[str] | None = None, limit: int = 25) -> list[SearchHit]:
        return self.graph.search(text, labels, limit)

    def neighborhood(
        self, node_id: str, depth: int = 1, edge_types: Sequence[str] | None = None, direction: str = "both",
        labels: Sequence[str] | None = None, max_nodes: int = 150,
    ) -> GraphFragment:
        if node_id not in self.graph:
            raise KeyError(f"node {node_id!r} not found")
        dist = self.graph.k_hop(node_id, depth=depth, edge_types=edge_types, direction=direction, max_nodes=max_nodes, node_labels=labels)
        ordered = [n for n, _ in sorted(dist.items(), key=lambda kv: (kv[1], kv[0]))]
        frag = self.graph.fragment(ordered, highlight_ids=[node_id], focus=[node_id], layout_hint="neighborhood", max_nodes=max_nodes)
        return frag

    def run_readonly_cypher(self, query: str, params: dict[str, Any] | None = None, row_limit: int = 200, timeout_ms: int = 3000) -> Any:
        raise NotSupported("Cypher is not available on the NetworkX backend; use the typed graph endpoints instead")

    def stats(self) -> StatsOut:
        return StatsOut(
            node_counts=self.graph.count_by_label(), edge_counts=self.graph.count_by_edge_type(), total_nodes=len(self.graph),
            total_edges=self.graph.G.number_of_edges(), backend=self.name, capabilities=self.capabilities(),
            build=_compact_build(self.graph.build_info),
        )

    def schema_summary(self) -> dict[str, Any]:
        counts = self.graph.count_by_label()
        edge_counts = self.graph.count_by_edge_type()
        return {
            "backend": self.name,
            "labels": [{"name": lbl.name, "category": lbl.category, "id_prefix": lbl.id_prefix, "count": counts.get(lbl.name, 0), "properties": [c.name for c in lbl.columns]} for lbl in LABELS.values()],
            "edge_types": [{"name": et.name, "count": edge_counts.get(et.name, 0), "pairs": [list(p) for p in et.pairs], "properties": [c.name for c in et.columns], "derived": et.derived} for et in EDGE_TYPES.values()],
        }


def _compact_build(info: dict[str, Any] | None) -> dict[str, Any]:
    if not info:
        return {}
    out: dict[str, Any] = {}
    for key in ("seed", "generated_at", "checksum", "version", "storylines", "storyline_ids", "now"):
        if key in info:
            out[key] = info[key]
    if "counts" in info and isinstance(info["counts"], dict):
        try:
            out["counts_summary"] = {k: (sum(v.values()) if isinstance(v, dict) else v) for k, v in info["counts"].items()}
        except Exception:  # pragma: no cover
            out["counts_summary"] = json.loads(json.dumps(info["counts"], default=str))
    return out
