"""Data build pipeline: simulate -> merge -> validate -> enrich -> write canonical graph -> build embedded DB.

Usage: ``python -m throughline.simulator.build [--out data/generated] [--skip-db] [--force]``
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import time
from collections import Counter
from pathlib import Path
from typing import Any

from throughline.config import settings
from throughline.graph.context_graph import ContextGraph
from throughline.schema import validate_edge, validate_node
from throughline.simulator.common import NOW, SEED, read_jsonl, rng, ts, write_jsonl

log = logging.getLogger("throughline.build")

STAGE_FILES = {
    "inventory": ("inventory_nodes.jsonl", "inventory_edges.jsonl"),
    "threat_intel": ("ti_nodes.jsonl", "ti_edges.jsonl"),
    "events": ("events_nodes.jsonl", "events_edges.jsonl"),
}


class BuildError(RuntimeError):
    pass


def _sha256_of_files(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in paths:
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def run_stages(out: Path) -> dict[str, Any]:
    """Run the three simulator stages in dependency order and return their reports."""
    from throughline.simulator.events import generate as gen_events
    from throughline.simulator.inventory import generate as gen_inventory
    from throughline.simulator.threat_intel import generate as gen_ti

    reports: dict[str, Any] = {}
    for name, fn, kwargs in (
        ("inventory", gen_inventory, {}),
        ("threat_intel", gen_ti, {}),
        ("events", gen_events, {"inventory_path": out / "inventory.json"}),
    ):
        t0 = time.perf_counter()
        reports[name] = fn(out, **kwargs) or {}
        reports[name]["seconds"] = round(time.perf_counter() - t0, 2)
        log.info("stage %-12s done in %5.1fs", name, reports[name]["seconds"])
    return reports


def merge_and_validate(out: Path) -> ContextGraph:
    graph_dir = out / "graph"
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    owner: dict[str, str] = {}
    problems: list[str] = []
    for stage, (nfile, efile) in STAGE_FILES.items():
        npath, epath = graph_dir / nfile, graph_dir / efile
        if not npath.exists() or not epath.exists():
            raise BuildError(f"stage {stage} did not produce {nfile}/{efile}")
        for rec in read_jsonl(npath):
            if rec["id"] in owner:
                problems.append(f"duplicate id {rec['id']} from {stage} (already from {owner[rec['id']]})")
                continue
            owner[rec["id"]] = stage
            problems.extend(validate_node(rec))
            nodes.append(rec)
        edges.extend(read_jsonl(epath))
    label_of = {n["id"]: n["label"] for n in nodes}
    dangling = 0
    kept_edges = []
    for e in edges:
        errs = validate_edge(e, label_of)
        if errs:
            if any("dangling" in x for x in errs):
                dangling += 1
                if dangling <= 20:
                    problems.append(errs[0])
                continue
            problems.extend(errs)
            continue
        kept_edges.append(e)
    if dangling > 20:
        problems.append(f"... {dangling} dangling edges in total")
    if problems:
        preview = "\n  ".join(problems[:40])
        raise BuildError(f"{len(problems)} validation problems:\n  {preview}")
    graph = ContextGraph.from_records(nodes, kept_edges)
    return graph


def plant_low_confidence_iocs(graph: ContextGraph, out: Path) -> int:
    """Plant the threat-intel stage's low-confidence indicator values on random background telemetry so the TI
    page shows how confidence matters (docs/04-storyline.md section 5)."""
    plants_path = out / "raw" / "ti" / "low_confidence_plants.json"
    if not plants_path.exists():
        return 0
    plants = json.loads(plants_path.read_text(encoding="utf-8"))
    if isinstance(plants, dict):
        plants = plants.get("indicators") or plants.get("plants") or list(plants.values())
    r = rng("plant-iocs")
    processes = [p for p in graph.nodes_by_label("Process")]
    endpoints = list(graph.nodes_by_label("Endpoint"))
    if not endpoints:
        return 0
    planted = 0
    for plant in plants[:8]:
        ioc_type = plant.get("ioc_type") or plant.get("type")
        value = plant.get("value")
        if not ioc_type or not value:
            continue
        host_proc = r.choice(processes) if processes else None
        host_ep = graph.node(host_proc)["endpoint_id"] if host_proc and graph.get(host_proc, "endpoint_id") in graph else r.choice(endpoints)
        when = ts(NOW.replace(hour=int(r.random() * 23), minute=int(r.random() * 59)) - __import__("datetime").timedelta(days=r.randint(3, 20)))
        if ioc_type == "ipv4":
            nid = f"ip:v4:{value}"
            if nid not in graph:
                graph.add_node_record({"id": nid, "label": "IpAddress", "name": value, "source": "falcon-sim", "source_id": value, "first_seen": when, "last_seen": when, "confidence": 1.0,
                                       "props": {"address": value, "is_private": False, "asn": "AS64512", "asn_org": "Documentation range (fictional)", "country": "ZZ", "reputation": "unknown"}})
            src = host_proc or host_ep
            graph.add_edge_record({"type": "CONNECTED_TO", "src": src, "dst": nid, "source": "falcon-sim", "first_seen": when, "last_seen": when, "confidence": 1.0,
                                   "props": {"port": 443, "protocol": "tcp", "direction": "outbound", "count": 1, "bytes_out": 2048, "first_time": when, "last_time": when}})
        elif ioc_type == "domain":
            nid = f"domain:dns:{value}"
            if nid not in graph:
                graph.add_node_record({"id": nid, "label": "Domain", "name": value, "source": "falcon-sim", "source_id": value, "first_seen": when, "last_seen": when, "confidence": 1.0,
                                       "props": {"fqdn": value, "registered_days_ago": r.randint(200, 2000), "reputation": "unknown"}})
            src = host_proc or host_ep
            graph.add_edge_record({"type": "CONNECTED_TO", "src": src, "dst": nid, "source": "falcon-sim", "first_seen": when, "last_seen": when, "confidence": 1.0,
                                   "props": {"port": 443, "protocol": "tcp", "direction": "outbound", "count": 1, "bytes_out": 1024, "first_time": when, "last_time": when}})
        elif ioc_type == "sha256" and host_proc:
            nid = f"file:sha256:{value}"
            if nid not in graph:
                graph.add_node_record({"id": nid, "label": "File", "name": plant.get("file_name") or f"{value[:8]}.bin", "source": "falcon-sim", "source_id": value, "first_seen": when, "last_seen": when, "confidence": 1.0,
                                       "props": {"sha256": value, "file_name": plant.get("file_name") or f"{value[:8]}.bin", "file_path": f"C:\\Users\\Public\\{value[:8]}.bin", "size_bytes": r.randint(20000, 900000), "signed": False, "verdict": "unknown"}})
            graph.add_edge_record({"type": "EXECUTED", "src": host_proc, "dst": nid, "source": "falcon-sim", "first_seen": when, "last_seen": when, "confidence": 1.0, "props": {"action": "wrote"}})
        else:
            continue
        planted += 1
    return planted


def write_graph(graph: ContextGraph, out: Path, stage_reports: dict[str, Any], enrich_report: dict[str, Any]) -> dict[str, Any]:
    graph_dir = out / "graph"
    nodes_path, edges_path = graph_dir / "nodes.jsonl", graph_dir / "edges.jsonl"
    n = write_jsonl(nodes_path, graph.iter_node_records())
    m = write_jsonl(edges_path, graph.iter_edge_records())
    storylines = sorted(graph.nodes_by_label("Storyline"))
    manifest = {
        "product": "throughline",
        "customer": "Larkspur Financial (simulated)",
        "seed": SEED,
        "now": ts(NOW),
        "generated_at": ts(NOW),
        "node_count": n,
        "edge_count": m,
        "nodes_by_label": graph.count_by_label(),
        "edges_by_type": graph.count_by_edge_type(),
        "storylines": storylines,
        "stage_reports": {k: {kk: vv for kk, vv in v.items() if kk in ("counts", "seconds")} for k, v in stage_reports.items()},
        "enrichment": enrich_report,
        "checksum": _sha256_of_files([nodes_path, edges_path]),
    }
    (graph_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def build(out_dir: Path | None = None, *, skip_db: bool = False, force: bool = False) -> dict[str, Any]:
    out = Path(out_dir or settings.data_dir)
    (out / "graph").mkdir(parents=True, exist_ok=True)
    t_all = time.perf_counter()
    stage_reports = run_stages(out)
    t0 = time.perf_counter()
    graph = merge_and_validate(out)
    log.info("merged %d nodes / %d edges in %.1fs", len(graph), graph.G.number_of_edges(), time.perf_counter() - t0)
    planted = plant_low_confidence_iocs(graph, out)
    from throughline.analytics.materialize import enrich

    t0 = time.perf_counter()
    enrich_report = enrich(graph) or {}
    enrich_report["seconds"] = round(time.perf_counter() - t0, 2)
    enrich_report["planted_low_confidence_iocs"] = planted
    log.info("enrichment done in %.1fs", enrich_report["seconds"])
    problems = graph.validate()
    if problems:
        raise BuildError("post-enrichment validation failed:\n  " + "\n  ".join(problems[:40]))
    manifest = write_graph(graph, out, stage_reports, enrich_report)
    if not skip_db:
        from throughline.graph.factory import make_store
        from throughline.graph.loader import build_embedded_db

        t0 = time.perf_counter()
        store = make_store(settings, graph)
        build_embedded_db(store, out, force=force)
        manifest["db_seconds"] = round(time.perf_counter() - t0, 2)
        log.info("embedded database ready in %.1fs (%s)", manifest["db_seconds"], getattr(store, "name", "?"))
    manifest["total_seconds"] = round(time.perf_counter() - t_all, 2)
    counts = Counter(graph.label_of(n) for n in graph.G.nodes)
    log.info("build complete: %d nodes, %d edges, %d labels, %.1fs total", len(graph), graph.G.number_of_edges(), len(counts), manifest["total_seconds"])
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the simulated Throughline dataset and graph database.")
    parser.add_argument("--out", default=str(settings.data_dir))
    parser.add_argument("--skip-db", action="store_true", help="write the canonical JSONL only; do not build the embedded database")
    parser.add_argument("--force", action="store_true", help="rebuild the embedded database even if the checksum matches")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    manifest = build(Path(args.out), skip_db=args.skip_db, force=args.force)
    print(json.dumps({k: manifest[k] for k in ("node_count", "edge_count", "storylines", "total_seconds") if k in manifest}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
