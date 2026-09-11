"""Typed investigations behind the demo questions (docs/05 section 5) and the dashboard payload (section 1.1)."""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

from throughline.analytics import semantics as sem
from throughline.analytics import ti as ti_mod
from throughline.analytics.blast import blast_radius
from throughline.analytics.context import AnalyticsContext, as_list
from throughline.analytics.correlation import credential_lineage, root_credential
from throughline.models import AlertSummary, BlastRadiusResult, GraphFragment

Summarize = Callable[[str], AlertSummary]


# ---------------------------------------------------------------------- question 8


def credential_joins(ctx: AnalyticsContext, summarize: Summarize) -> dict[str, Any]:
    """Credentials used in cloud API calls that were seen stolen on an endpoint (directly or via a derived session)."""
    g = ctx.graph
    items: list[dict[str, Any]] = []
    frag_nodes: list[str] = []
    for cred in g.nodes_by_label("Credential"):
        uses = sorted((ev for ev, _ in g.in_edges(cred, ("USED_CREDENTIAL",))), key=lambda e: (str(g.get(e, "event_time") or ""), e))
        if not uses:
            continue
        root = root_credential(ctx, cred)
        stolen_alerts = [a for a, _ in g.out_edges(root, ("STOLEN_BY",)) if g.label_of(a) == "Alert"]
        if not stolen_alerts:
            stolen_alerts = [a for c in credential_lineage(ctx, root) for a, _ in g.out_edges(c, ("STOLEN_BY",)) if g.label_of(a) == "Alert"]
        if not stolen_alerts:
            # stolen by a process only: find the alert involving the process
            procs = [p for c in credential_lineage(ctx, root) for p, _ in g.out_edges(c, ("STOLEN_BY",)) if g.label_of(p) == "Process"]
            stolen_alerts = sorted({a for p in procs for a, _ in g.in_edges(p, ("INVOLVES",)) if g.label_of(a) == "Alert"})
        if not stolen_alerts:
            continue
        alert = sorted(stolen_alerts, key=lambda a: (str(g.get(a, "detected_at") or ""), a))[0]
        endpoint = ctx.anchor_of(alert)
        principal = next((p for p, _ in g.out_edges(cred, ("CREDENTIAL_FOR",))), None)
        derived = sorted(c for c, _ in g.in_edges(cred, ("DERIVED_FROM",)))
        ips = sorted({str(g.get(e, "source_ip") or "") for e in uses} - {""})
        items.append({
            "credential": g.node_out(cred, highlight=True),
            "stolen_by_alert": summarize(alert),
            "endpoint": g.node_out(endpoint) if endpoint else None,
            "principal": g.node_out(principal) if principal else None,
            "used_in_events": [g.node_out(e) for e in uses],
            "derived_credentials": [g.node_out(c) for c in derived],
            "derived_from": g.node_out(root) if root != cred else None,
            "first_use": g.get(uses[0], "event_time"),
            "last_use": g.get(uses[-1], "event_time"),
            "source_ips": ips,
            "event_names": list(dict.fromkeys(str(g.get(e, "event_name") or "") for e in uses)),
        })
        frag_nodes += [alert, endpoint or "", cred, principal or "", root] + uses + derived
        frag_nodes += [t for e in uses for t, _ in g.out_edges(e, ("TARGETED", "ASSUMED"))]
    items.sort(key=lambda it: (str(it["first_use"] or ""), it["credential"].id))
    creds = [it["credential"].id for it in items]
    frag = g.fragment([n for n in frag_nodes if n], highlight_ids=set(creds), focus=creds, layout_hint="path", max_nodes=150)
    return {"items": items, "fragment": frag, "summary": f"{len(items)} credential{'s' if len(items) != 1 else ''} seen stolen on an endpoint and used in cloud API calls"}


# ---------------------------------------------------------------------- question 10


def _data_crown_jewels(ctx: AnalyticsContext) -> list[str]:
    g = ctx.graph
    return [j for j in ctx.crown_jewels if g.label_of(j) in sem.DATA_HOLDER_LABELS]


def alerts_reaching_crown_jewels(ctx: AnalyticsContext, summarize: Summarize, jewel_id: str | None = None,
                                 classification: str | None = None, depth: int = 4) -> dict[str, Any]:
    """Alerts whose anchor asset has an access chain (roles, effective access, credential stores) to a crown jewel."""
    g = ctx.graph
    if jewel_id:
        jewels = [jewel_id] if jewel_id in g else []
    else:
        jewels = _data_crown_jewels(ctx)
        if classification:
            wanted = classification.upper()
            jewels = [j for j in jewels if wanted in sem.data_classes(g.node(j))]
    jewel_set = set(jewels)
    items: list[tuple[AlertSummary, list[str]]] = []
    frag_nodes: list[str] = list(jewels)
    per_anchor: dict[str, list[str]] = {}
    for alert in ctx.alerts:
        anchor = ctx.anchor_of(alert)
        if not anchor:
            continue
        if anchor not in per_anchor:
            reach = ctx.reach(anchor, depth, "access")
            per_anchor[anchor] = [n for n in reach.ids() if n in jewel_set]
        hit = per_anchor[anchor]
        if not hit:
            continue
        items.append((summarize(alert), hit))
        reach = ctx.reach(anchor, depth, "access")
        for j in hit[:2]:
            frag_nodes.extend(reach.nodes[j].path)
        frag_nodes.append(alert)
    items.sort(key=lambda it: (-it[0].contextual_score, it[0].vendor_rank_position or 0, it[0].id))
    summaries = [s for s, _ in items]
    frag = g.fragment(frag_nodes, highlight_ids=set(jewels) | {s.id for s in summaries}, focus=jewels[:3], layout_hint="path", max_nodes=150)
    return {
        "items": summaries, "jewels": [g.node_out(j, highlight=True) for j in jewels], "fragment": frag,
        "reach": {s.id: hit for s, hit in items},
        "summary": f"{len(summaries)} alert{'s' if len(summaries) != 1 else ''} on assets that can reach {len(jewels)} crown jewel{'s' if len(jewels) != 1 else ''}",
    }


# ---------------------------------------------------------------------- question 2


def medium_alerts_with_data_path(ctx: AnalyticsContext, summarize: Summarize, severity: str = "medium",
                                 source: str | None = "falcon", depth: int = 4) -> dict[str, Any]:
    """Alerts of a vendor severity (default medium, EDR) on assets with an access path to regulated data."""
    g = ctx.graph
    sev = (severity or "medium").lower()
    items: list[tuple[AlertSummary, list[str]]] = []
    frag_nodes: list[str] = []
    for alert in ctx.alerts:
        if str(g.get(alert, "vendor_severity") or "").lower() != sev:
            continue
        if source and str(g.get(alert, "source_system") or "") != source:
            continue
        anchor = ctx.anchor_of(alert)
        if not anchor:
            continue
        reach = ctx.reach(anchor, depth, "access")
        regulated = [n for n in reach.ids() if sem.is_regulated(g.node(n)) or (sem.is_crown_jewel(g.node(n)) and g.label_of(n) in sem.DATA_HOLDER_LABELS)]
        if not regulated:
            continue
        regulated.sort(key=lambda n: (not sem.is_crown_jewel(g.node(n)), reach.nodes[n].hops, n))
        items.append((summarize(alert), regulated))
        frag_nodes.append(alert)
        for n in regulated[:2]:
            frag_nodes.extend(reach.nodes[n].path)
    items.sort(key=lambda it: (-it[0].contextual_score, it[0].id))
    summaries = [s for s, _ in items]
    frag = g.fragment(frag_nodes, highlight_ids={s.id for s in summaries} | {n for _, r in items for n in r[:1]}, focus=[s.id for s in summaries[:3]], layout_hint="path", max_nodes=150)
    return {
        "items": summaries, "fragment": frag, "data_reached": {s.id: r for s, r in items},
        "summary": f"{len(summaries)} {sev} {source or 'any-source'} alert{'s' if len(summaries) != 1 else ''} on assets with a path to regulated data",
    }


# ---------------------------------------------------------------------- question 4


def identity_footprint(ctx: AnalyticsContext, identity_id: str, depth: int = 4) -> BlastRadiusResult:
    return blast_radius(ctx, identity_id, depth=depth, max_nodes=500, mode="full")


# ---------------------------------------------------------------------- dashboard


def dashboard(ctx: AnalyticsContext, list_alerts: Callable[..., tuple[list[AlertSummary], int]], summarize: Summarize,
              storylines: Callable[[], list[Any]]) -> dict[str, Any]:
    g = ctx.graph
    alerts = ctx.alerts
    open_alerts = [a for a in alerts if str(g.get(a, "status") or "new") not in ("closed", "benign")]
    bands: Counter[str] = Counter(str(g.get(a, "contextual_band") or "noise") for a in alerts)
    sources: Counter[str] = Counter(str(g.get(a, "source_system") or "unknown") for a in alerts)
    contextual, _ = list_alerts(sort="contextual", order="desc", limit=10, offset=0)
    vendor, _ = list_alerts(sort="vendor", order="desc", limit=10, offset=0)
    story_list = storylines()
    vms = list(g.nodes_by_label("VirtualMachine"))
    with_sensor = [v for v in vms if g.get(v, "has_edr_sensor") or v in ctx.endpoint_of_vm]
    prod_no_sensor = [v for v in vms if str(g.get(v, "environment") or "") == "prod" and v not in with_sensor]
    endpoints = list(g.nodes_by_label("Endpoint"))
    resolved = [e for e in endpoints if e in ctx.vm_of_endpoint]
    exposure_rows = ti_mod.ti_exposure(ctx, sector_only=False)
    at_risk: set[str] = set()
    for s in story_list:
        at_risk.update(x for x in s.crown_jewels_reached if x in g and sem.is_crown_jewel(g.node(x)))
    for a in alerts:
        if str(g.get(a, "contextual_band") or "") in ("high", "critical") and g.get(a, "reaches_crown_jewel"):
            anchor = ctx.anchor_of(a)
            if anchor:
                at_risk.update(ctx.reaches_crown_jewel(anchor, 4, "access"))
    ioc_matches = sum(1 for _, _, d in g.G.edges(data=True) if d.get("type") == "MATCHES_IOC")
    ti_rows = []
    for row in ti_mod.ti_actors(ctx):
        ti_rows.append({
            "actor_id": row["actor"].id, "actor_name": row["actor"].name, "sector_relevance": row["sector_relevance"],
            "campaigns": len(row["campaigns"]), "ioc_matches": row["ioc_matches"], "exploited_cves_present": row["exploited_cves_present"],
            "alerts": row["matched_alerts"],
        })
    rerank = _rerank_examples(ctx, summarize)
    return {
        "kpis": {
            "open_alerts": len(open_alerts), "critical_contextual": bands.get("critical", 0), "storylines": len(story_list),
            "crown_jewels": len(_data_crown_jewels(ctx)), "crown_jewels_at_risk": len(at_risk),
            "internet_exposed_exploited": len(exposure_rows), "endpoints": len(endpoints),
            "endpoint_coverage_pct": round(100.0 * len(with_sensor) / len(vms), 1) if vms else 0.0, "ioc_matches": ioc_matches,
        },
        "leaderboard_contextual": contextual,
        "leaderboard_vendor": vendor,
        "storylines": story_list,
        "alerts_by_band": {b: bands.get(b, 0) for b in ("critical", "high", "medium", "low", "noise")},
        "alerts_by_source": {s: sources.get(s, 0) for s in ("falcon", "cspm", "waf", "ids", "cloud-anomaly", "okta")} | {k: v for k, v in sources.items() if k not in ("falcon", "cspm", "waf", "ids", "cloud-anomaly", "okta")},
        "coverage": {
            "vms_total": len(vms), "vms_with_sensor": len(with_sensor), "vms_without_sensor_prod": len(prod_no_sensor),
            "endpoints_total": len(endpoints), "endpoints_resolved_to_vm": len(resolved),
        },
        "ti_pressure": ti_rows,
        "rerank_examples": rerank,
    }


def _rerank_examples(ctx: AnalyticsContext, summarize: Summarize, n_each: int = 3) -> list[dict[str, Any]]:
    """Alerts the graph moved the most: the top contextual alerts a vendor queue would have buried, and the
    highest vendor severities that landed in the bottom half."""
    rows = []
    for a in ctx.alerts:
        s = summarize(a)
        if s.vendor_rank_position is None or s.contextual_rank_position is None:
            continue
        rows.append(s)
    total = len(rows)
    ups = sorted((s for s in rows if s.vendor_rank_position - s.contextual_rank_position >= 3),
                 key=lambda s: (s.contextual_rank_position, -s.vendor_rank_position))[:n_each]
    downs = sorted((s for s in rows if s.contextual_rank_position > total / 2 and s.contextual_rank_position - s.vendor_rank_position >= 3),
                   key=lambda s: (s.vendor_rank_position, -s.contextual_rank_position))[:n_each]
    out = []
    for s in ups + downs:
        delta = s.vendor_rank_position - s.contextual_rank_position
        out.append({
            "alert_id": s.id, "title": s.title, "vendor_severity": s.vendor_severity, "contextual_score": s.contextual_score,
            "vendor_rank_position": s.vendor_rank_position, "contextual_rank_position": s.contextual_rank_position,
            "direction": "up" if delta > 0 else "down", "graph_reasons": s.graph_reasons,
        })
    return out


def storyline_alert_ids(ctx: AnalyticsContext, sid: str) -> list[str]:
    return [a for a in as_list(ctx.graph.get(sid, "alert_ids")) if a in ctx.graph]


__all__ = ["credential_joins", "alerts_reaching_crown_jewels", "medium_alerts_with_data_path", "identity_footprint", "dashboard", "GraphFragment"]
