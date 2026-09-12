"""GraphStore over the in-process ``ContextGraph`` projection (NetworkX). No Cypher.

This is the always-available backend: it needs no database file, so the whole product minus the raw Cypher tool
runs on it (CI, laptops without the embedded engine, safety net when the database is missing). Every other
backend is checked against it by the conformance tests, so its behaviour defines the reference semantics:

* ``get_node`` / ``get_nodes`` return the ``nodes.jsonl`` record shape rebuilt from the flattened attributes;
* ``search`` is ``ContextGraph.search`` (token index over names, hostnames, IPs, hashes, ids);
* ``neighborhood`` is ``ContextGraph.k_hop`` (BFS bounded by depth, optional edge-type / label filters and
  direction) rendered through ``ContextGraph.fragment``; nodes are ordered start first, then by (hop, id);
* ``run_readonly_cypher`` raises ``NotSupported`` and ``capabilities()["cypher"]`` is False.

When ``factory.make_store`` cannot open the configured embedded database (fresh checkout, nothing built yet) it
returns a ``NetworkXStore`` that *stands in for* the un-opened ``LadybugStore`` (``embedded``). ``build`` then also
builds that database and ``stored_manifest`` reports its sidecar, so ``loader.build_embedded_db(store, data_dir)``
creates the embedded database on the first run and skips it afterwards, exactly as with the real store.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import networkx as nx

from throughline.graph.context_graph import ContextGraph
from throughline.graph.store import BaseStore, CypherResult, GraphStore, NotSupported, record_from_flat
from throughline.models import GraphFragment, SearchHit, StatsOut

log = logging.getLogger(__name__)

EXAMPLE_QUERIES: list[dict[str, Any]] = [
    {
        "title": "Not available on this backend",
        "query": "-- the NetworkX backend has no Cypher engine; use get_neighborhood / find_paths / blast_radius instead",
    }
]


class NetworkXStore(BaseStore):
    name = "networkx"

    def __init__(self, graph: ContextGraph, embedded: GraphStore | None = None) -> None:
        self.graph = graph
        self.embedded = embedded  # the un-opened embedded store this one stands in for (see the module docstring)

    # ------------------------------------------------------------------ lifecycle

    def capabilities(self) -> dict[str, Any]:
        caps: dict[str, Any] = {
            "cypher": False,
            "multi_label_patterns": False,
            "shortest_path": True,
            "read_only": True,
            "engine": "networkx",
            "engine_version": nx.__version__,
            "dialect": "none",
        }
        if self.embedded is not None:
            caps["stands_in_for"] = self.embedded.name
        return caps

    def build(self, nodes_path: Path, edges_path: Path, manifest: dict) -> None:
        """Reload the projection from the canonical files in place (callers holding the graph see the new data)
        and, when this store stands in for an embedded one, build that database too."""
        fresh = ContextGraph.from_jsonl(nodes_path, edges_path)
        fresh.build_info = dict(manifest)
        self.graph.reload_from(fresh)
        log.info("networkx store reloaded %d nodes, %d edges", len(self.graph), self.graph.G.number_of_edges())
        if self.embedded is not None:
            log.info("building the %s database this store stands in for", self.embedded.name)
            self.embedded.build(nodes_path, edges_path, manifest)

    def open(self) -> None:  # nothing to open: the projection is already in memory
        return None

    def close(self) -> None:
        return None

    def stored_manifest(self) -> dict[str, Any] | None:
        """The build this store already holds: the embedded database's sidecar when standing in for one (None until
        it is built), otherwise the manifest the projection was loaded with."""
        if self.embedded is not None:
            stored = getattr(self.embedded, "stored_manifest", None)
            return stored() if callable(stored) else None
        info = self.graph.build_info or {}
        return dict(info) if info.get("checksum") else None

    # ------------------------------------------------------------------ lookups

    def get_node(self, node_id: str) -> dict | None:
        attrs = self.graph.node(node_id)
        return record_from_flat(attrs) if attrs is not None else None

    def get_nodes(self, ids: Sequence[str]) -> list[dict]:
        out: list[dict] = []
        for nid in dict.fromkeys(ids):
            attrs = self.graph.node(nid)
            if attrs is not None:
                out.append(record_from_flat(attrs))
        return out

    def search(self, text: str, labels: Sequence[str] | None = None, limit: int = 25) -> list[SearchHit]:
        return self.graph.search(text, labels, limit)

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
        if node_id not in self.graph:
            return GraphFragment(focus=[node_id], layout_hint="neighborhood", total_nodes=0)
        # Expand without a cap so truncation is deterministic (start first, then by hop distance and id) and
        # identical to the embedded backends' ORDER BY hops, id LIMIT n.
        dist = self.graph.k_hop(node_id, depth=depth, edge_types=types, direction=direction, max_nodes=len(self.graph) + 1, node_labels=wanted)
        ordered = [node_id] + sorted((n for n in dist if n != node_id), key=lambda n: (dist[n], n))
        return self.graph.fragment(ordered, focus=[node_id], layout_hint="neighborhood", max_nodes=max_nodes)

    # ------------------------------------------------------------------ Cypher

    def run_readonly_cypher(
        self, query: str, params: dict | None = None, row_limit: int = 200, timeout_ms: int = 3000
    ) -> CypherResult:
        raise NotSupported("the networkx backend has no Cypher engine (set GRAPH_BACKEND=ladybug for run_cypher)")

    # ------------------------------------------------------------------ stats & schema

    def stats(self) -> StatsOut:
        return self.stats_out(self.graph.count_by_label(), self.graph.count_by_edge_type(), self.graph.build_info)

    def schema_summary(self) -> dict[str, Any]:
        return self.schema_summary_for(
            "none",
            [
                "This backend has no Cypher engine: run_cypher is not supported (HTTP 501 not_supported).",
                "Use the typed tools (get_neighborhood, find_paths, blast_radius, attack_paths) instead.",
            ],
            EXAMPLE_QUERIES,
        )
