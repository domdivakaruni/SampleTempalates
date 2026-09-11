"""Inventory stage entry point: ``generate(out_dir) -> {"nodes", "edges", "raw", "counts"}``."""
from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any

from throughline.schema import validate_edge, validate_node
from throughline.simulator.catalog.cves import CVES
from throughline.simulator.common import write_jsonl
from throughline.simulator.inventory._base import Inventory
from throughline.simulator.inventory.business import build_apps, emit_business_edges
from throughline.simulator.inventory.cloud import build_cloud
from throughline.simulator.inventory.endpoints import build_endpoints
from throughline.simulator.inventory.feeds import write_feeds
from throughline.simulator.inventory.identity import build_identity
from throughline.simulator.inventory.index import write_index
from throughline.simulator.inventory.issues import build_issues
from throughline.simulator.inventory.posture import derive_posture
from throughline.simulator.inventory.vulns import build_vulns
from throughline.simulator.inventory.world import build_world

log = logging.getLogger(__name__)


def build_inventory() -> Inventory:
    """Run every pass and return the in-memory inventory (no files written)."""
    inv = Inventory()
    world = build_world(inv)
    apps = build_apps(inv, world)
    est = build_cloud(inv, world, apps)
    build_identity(inv, world, apps, est)
    build_vulns(inv, est)
    build_endpoints(inv, world, est)
    emit_business_edges(inv, apps)
    derive_posture(inv, est)
    build_issues(inv, est)
    validate(inv)
    return inv


def validate(inv: Inventory) -> None:
    problems: list[str] = []
    label_of = {nid: rec["label"] for nid, rec in inv.nodes.items()}
    for cve in CVES.values():
        label_of[cve.node_id] = "Vulnerability"
    for rec in inv.nodes.values():
        problems.extend(validate_node(rec))
    for e in inv.edges:
        problems.extend(validate_edge(e, label_of))
    if problems:
        raise ValueError(f"inventory validation failed ({len(problems)} problems): " + "; ".join(problems[:10]))


def counts_of(inv: Inventory) -> dict[str, Any]:
    nodes = Counter(rec["label"] for rec in inv.nodes.values())
    edges = Counter(e["type"] for e in inv.edges)
    return {"nodes": dict(sorted(nodes.items())), "edges": dict(sorted(edges.items())), "total_nodes": len(inv.nodes), "total_edges": len(inv.edges)}


def generate(out_dir: Path) -> dict[str, Any]:
    out_dir = Path(out_dir)
    inv = build_inventory()
    counts = counts_of(inv)
    graph_dir = out_dir / "graph"
    nodes_path = graph_dir / "inventory_nodes.jsonl"
    edges_path = graph_dir / "inventory_edges.jsonl"
    write_jsonl(nodes_path, inv.nodes.values())
    write_jsonl(edges_path, inv.edges)
    raw_paths = write_feeds(inv, out_dir)
    index_path = write_index(inv, out_dir, counts)
    log.info("inventory: %d nodes, %d edges -> %s", counts["total_nodes"], counts["total_edges"], graph_dir)
    return {"nodes": nodes_path, "edges": edges_path, "raw": raw_paths, "index": index_path, "counts": counts}
