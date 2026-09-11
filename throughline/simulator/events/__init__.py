"""Events stage of the data simulator.

Produces the EDR telemetry (Falcon-style detections, incidents, processes, files, logons, network
connections), the cloud audit events (CloudTrail-style), the WAF/IDS/identity-provider alerts, the two
scripted intrusion storylines (EMBERCAST, SALTWORKS) and the background noise for Larkspur Financial.

Interface (docs/06 section 2)::

    generate(out_dir: Path, inventory_path: Path | None = None) -> dict
      writes  out/graph/events_nodes.jsonl, out/graph/events_edges.jsonl
              out/raw/{falcon,cloudtrail,waf,ids,okta}/*.jsonl
      returns {"nodes": Path, "edges": Path, "raw": [Path...], "counts": {...}}

The stage consumes ``out/inventory.json`` when present (the inventory stage writes it) and otherwise falls
back to a deterministic synthesized stub with a logged warning. Everything is derived from ``rng(namespace)``
so two runs are byte-identical.
"""
from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any

from throughline.simulator.common import write_jsonl
from throughline.simulator.events import (
    cloudtrail,
    feeds,
    incidents,
    logons,
    network,
    noise,
    storyline_a,
    storyline_b,
)
from throughline.simulator.events.ctx import Ctx
from throughline.simulator.events.inventory_stub import (
    FLEET_ENDPOINT_FLOOR,
    Inventory,
    build_stub_inventory,
    inventory_from_json,
    synthesize_fleet,
)

logger = logging.getLogger(__name__)

N_BG_CLOUDTRAIL = 2500
N_BG_LOGONS = 3000
N_BG_ACTIVITY_TREES = 1000  # benign process/file/network telemetry samples across the fleet


def resolve_inventory(inventory_path: Path | None, out_dir: Path) -> Inventory:
    """Load ``inventory.json`` (explicit path, or ``out/inventory.json``); else synthesize a stub.

    A thin inventory (the mini fixture) is padded with a synthesized background fleet so the noise
    generators have material; a full inventory (~2,000 endpoints) is left untouched.
    """
    candidate = None
    if inventory_path is not None and Path(inventory_path).exists():
        candidate = Path(inventory_path)
    elif (out_dir / "inventory.json").exists():
        candidate = out_dir / "inventory.json"

    if candidate is not None:
        inv = inventory_from_json(candidate)
        if len(inv.endpoints) < FLEET_ENDPOINT_FLOOR:
            synthesize_fleet(inv, FLEET_ENDPOINT_FLOOR)
        return inv

    logger.warning("events stage: no inventory.json found (looked at %s and %s); "
                   "falling back to a synthesized stub inventory",
                   inventory_path, out_dir / "inventory.json")
    return build_stub_inventory()


def generate(out_dir: Path, inventory_path: Path | None = None) -> dict[str, Any]:
    out_dir = Path(out_dir)
    inv = resolve_inventory(inventory_path, out_dir)
    ctx = Ctx(inv=inv)

    # --- storylines (scripted, exact) ---------------------------------------------------------------
    network.register_named_infrastructure(ctx)
    logons.add_storyline_logons(ctx)
    storyline_a.generate_storyline_a(ctx)
    cloudtrail.add_storyline_events(ctx)
    storyline_b.generate_storyline_b(ctx)

    # --- noise (so prioritization matters) ----------------------------------------------------------
    noise.add_named_noise(ctx)
    n_ids = noise.add_ids_alerts(ctx)
    n_waf = noise.add_waf_alerts(ctx)
    n_general = noise.add_general_edr(ctx)
    n_ca_bg = noise.add_background_cloud_anomaly(ctx)
    n_okta_bg = noise.add_background_okta(ctx)

    # --- background telemetry -----------------------------------------------------------------------
    activity = noise.add_background_activity(ctx, N_BG_ACTIVITY_TREES)
    n_ct_bg = cloudtrail.add_background_events(ctx, N_BG_CLOUDTRAIL)
    n_logon_bg = logons.add_background_logons(ctx, N_BG_LOGONS)

    # --- incident grouping (after all falcon alerts exist) ------------------------------------------
    n_incidents = incidents.generate_incidents(ctx)

    # --- write graph + raw feeds --------------------------------------------------------------------
    graph_dir = out_dir / "graph"
    nodes_path = graph_dir / "events_nodes.jsonl"
    edges_path = graph_dir / "events_edges.jsonl"
    write_jsonl(nodes_path, ctx.nodes)
    write_jsonl(edges_path, ctx.edges)
    raw_paths = feeds.write_feeds(ctx, out_dir)

    counts = _counts(ctx)
    counts.update({"ids_alerts": n_ids, "waf_alerts": n_waf, "general_edr": n_general,
                   "cloud_anomaly_bg": n_ca_bg, "okta_bg": n_okta_bg, "cloudtrail_bg": n_ct_bg,
                   "logons_bg": n_logon_bg, "incidents": n_incidents, "background_activity": activity,
                   "inventory_source": inv.source, "inventory_endpoints": len(inv.endpoints)})
    return {"nodes": nodes_path, "edges": edges_path, "raw": raw_paths, "counts": counts}


def _counts(ctx: Ctx) -> dict[str, Any]:
    by_label = Counter(rec["label"] for rec in ctx.nodes)
    by_edge = Counter(e["type"] for e in ctx.edges)
    alerts_by_source = Counter(rec["props"].get("source_system") for rec in ctx.nodes if rec["label"] == "Alert")
    return {
        "nodes": len(ctx.nodes), "edges": len(ctx.edges),
        "by_label": dict(sorted(by_label.items())), "by_edge_type": dict(sorted(by_edge.items())),
        "alerts_total": sum(alerts_by_source.values()), "alerts_by_source": dict(sorted(alerts_by_source.items())),
    }
