"""Build-time enrichment: ``enrich(graph)`` (docs/06 section 3.2).

Order: strip previously derived artifacts (idempotency) -> vulnerability TI overlay -> IOC matching -> attribution
-> lateral movement -> storylines -> scoring of every alert -> storyline scores -> per-VM crown-jewel reach ->
TI-adjusted exposure scores. Everything is written through ``ContextGraph`` so ``iter_node_records()`` /
``iter_edge_records()`` reflect the result and the pipeline can write it back to JSONL.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from throughline.analytics import correlation, ti
from throughline.analytics import semantics as sem
from throughline.analytics.context import AnalyticsContext, as_list
from throughline.analytics.scoring import Scorer
from throughline.graph.context_graph import ContextGraph

log = logging.getLogger(__name__)

DERIVED_EDGE_TYPES = ("MATCHES_IOC", "IN_STORYLINE", "NEXT_STAGE", "LATERAL_MOVEMENT_TO", "ATTRIBUTED_TO")
ALERT_SCORE_PROPS = ("contextual_score", "contextual_band", "score_breakdown", "graph_reasons", "storyline_id", "reaches_crown_jewel",
                     "on_attack_path", "ioc_match_count", "ti_actor_ids")


def strip_derived(graph: ContextGraph) -> dict[str, int]:
    """Remove everything a previous enrichment pass added so the pass can be re-run on the same graph."""
    removed: dict[str, int] = {}
    for sid in list(graph.nodes_by_label("Storyline")):
        graph.remove_node_record(sid)
        removed["Storyline"] = removed.get("Storyline", 0) + 1
    for et in ("MATCHES_IOC", "IN_STORYLINE", "NEXT_STAGE"):
        removed[et] = graph.remove_edges(et)
    removed["LATERAL_MOVEMENT_TO"] = graph.remove_edges("LATERAL_MOVEMENT_TO", lambda u, v, d: d.get("source") == "derived")
    removed["ATTRIBUTED_TO"] = graph.remove_edges("ATTRIBUTED_TO", lambda u, v, d: graph.label_of(u) in ("Alert", "Storyline"))
    for a in graph.nodes_by_label("Alert"):
        attrs = graph.node(a) or {}
        cleared = {k: None for k in ALERT_SCORE_PROPS if k in attrs}
        if cleared:
            cleared["ioc_match_count"] = 0
            cleared["ti_actor_ids"] = []
            cleared["reaches_crown_jewel"] = False
            cleared["on_attack_path"] = False
            graph.set_node_props(a, **cleared)
    for ev in graph.nodes_by_label("CloudEvent"):
        attrs = graph.node(ev) or {}
        if "storyline_id" in attrs or "ioc_match_count" in attrs:
            graph.set_node_props(ev, storyline_id=None, ioc_match_count=0)
    return removed


def enrich(graph: ContextGraph) -> dict[str, Any]:
    t0 = time.perf_counter()
    report: dict[str, Any] = {"removed": strip_derived(graph)}
    ctx = AnalyticsContext(graph)

    report["vulnerability_overlay"] = ti.overlay_vulnerabilities(ctx)
    report["ioc_matching"] = ti.match_iocs(ctx)
    ctx.invalidate()
    report["attribution"] = ti.attribute_alerts(ctx)
    ctx.invalidate()
    report["lateral_movement"] = correlation.derive_lateral_movement(ctx)
    scorer = Scorer(ctx)
    storylines = correlation.build_storylines(ctx, scorer.is_benign)
    report["storylines"] = storylines
    ctx.invalidate()

    scorer = Scorer(ctx)
    scores: dict[str, int] = {}
    bands: dict[str, int] = {}
    for alert_id in ctx.alerts:
        res = scorer.score_alert(alert_id)
        bd = res.breakdown
        graph.set_node_props(
            alert_id,
            contextual_score=bd.contextual_score, contextual_band=bd.band, score_breakdown=bd.model_dump(),
            graph_reasons=list(bd.reasons), storyline_id=res.storyline_id, reaches_crown_jewel=res.reaches_crown_jewel,
            on_attack_path=res.on_attack_path, ioc_match_count=res.ioc_match_count, ti_actor_ids=list(res.ti_actor_ids),
        )
        scores[alert_id] = bd.contextual_score
        bands[bd.band] = bands.get(bd.band, 0) + 1
    report["alerts_scored"] = len(scores)
    report["bands"] = dict(sorted(bands.items()))

    for sid in storylines:
        member_scores = [scores.get(a, 0) for a in as_list(graph.get(sid, "alert_ids"))]
        graph.set_node_props(sid, contextual_score=max(member_scores, default=0))
    report["storyline_scores"] = {sid: int(graph.get(sid, "contextual_score") or 0) for sid in storylines}

    reach_counts = 0
    for vm in graph.nodes_by_label("VirtualMachine"):
        jewels = ctx.reaches_crown_jewel(vm, 4, "access")
        graph.set_node_props(vm, crown_jewel_reach=len(jewels))
        reach_counts += 1 if jewels else 0
    report["vms_reaching_crown_jewels"] = reach_counts
    report["ti_exposure"] = ti.ti_exposure_scores(ctx)
    report["crown_jewels"] = len(ctx.crown_jewels)
    report["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
    report["node_count"] = len(graph)
    report["edge_count"] = graph.G.number_of_edges()
    log.info("enrich: %s", {k: v for k, v in report.items() if k not in ("storyline_scores",)})
    return report


def top_alerts(graph: ContextGraph, n: int = 10) -> list[tuple[str, int]]:
    """Convenience for reports and tests: (alert id, score) sorted by contextual score."""
    rows = [(a, int(graph.get(a, "contextual_score") or 0)) for a in graph.nodes_by_label("Alert")]
    rows.sort(key=lambda r: (-r[1], r[0]))
    return rows[:n]


__all__ = ["enrich", "strip_derived", "top_alerts", "sem"]
