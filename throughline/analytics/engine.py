"""AnalyticsEngine: the facade the API, the analyst agent and the scenario tests call (docs/06 section 3.2).

The engine works on an already enriched ``ContextGraph`` (``materialize.enrich``); if the graph carries no
contextual scores it runs the enrichment itself so the engine is always self-sufficient.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import timedelta
from typing import Any

from throughline.analytics import blast, containment, correlation, insights, paths, questions, ti
from throughline.analytics import semantics as sem
from throughline.analytics.context import NOW, AnalyticsContext, as_dict, as_list
from throughline.analytics.materialize import enrich
from throughline.analytics.scoring import Scorer
from throughline.graph.context_graph import ContextGraph
from throughline.models import (
    AlertContext,
    AlertSummary,
    AttackPathOut,
    BlastRadiusResult,
    ContainmentSimulation,
    GraphFragment,
    Insight,
    NodeOut,
    RiskBreakdown,
    StorylineOut,
    TIContext,
    band_for_score,
)

log = logging.getLogger(__name__)

RELATED_WINDOW = timedelta(days=7)


class AnalyticsEngine:
    def __init__(self, graph: ContextGraph, enrich_if_needed: bool = True) -> None:
        self.graph = graph
        if enrich_if_needed and not self._is_enriched():
            log.info("graph carries no contextual scores; running enrichment")
            enrich(graph)
        self.ctx = AnalyticsContext(graph)
        self.scorer = Scorer(self.ctx)
        self._summaries: dict[str, AlertSummary] = {}
        self._contexts: dict[str, AlertContext] = {}
        self._insights: dict[str, list[Insight]] = {}
        self._contextual_order: list[str] = []
        self._vendor_order: list[str] = []
        self._contextual_pos: dict[str, int] = {}
        self._vendor_pos: dict[str, int] = {}
        self._rank()

    # ------------------------------------------------------------------ setup

    def _is_enriched(self) -> bool:
        for a in self.graph.nodes_by_label("Alert"):
            return self.graph.get(a, "contextual_score") is not None
        return True

    def refresh(self) -> None:
        """Rebuild indexes and caches after the graph changed (e.g. a rebuild reloaded it in place)."""
        self.ctx.invalidate()
        self.scorer = Scorer(self.ctx)
        self._summaries.clear()
        self._contexts.clear()
        self._insights.clear()
        self._rank()

    def _raw(self, alert_id: str) -> float:
        bd = as_dict(self.graph.get(alert_id, "score_breakdown"))
        try:
            return float(bd.get("raw_score") or 0.0)
        except (TypeError, ValueError):
            return 0.0

    def _rank(self) -> None:
        g = self.graph
        alerts = list(self.ctx.alerts)

        def ctx_key(a: str) -> tuple:
            return (-int(g.get(a, "contextual_score") or 0), -self._raw(a), -int(g.get(a, "vendor_severity_rank") or 0), _rev(str(g.get(a, "detected_at") or "")), a)

        def vendor_key(a: str) -> tuple:
            return (-int(g.get(a, "vendor_severity_rank") or 0), _rev(str(g.get(a, "detected_at") or "")), a)

        self._contextual_order = sorted(alerts, key=ctx_key)
        self._vendor_order = sorted(alerts, key=vendor_key)
        self._contextual_pos = {a: i + 1 for i, a in enumerate(self._contextual_order)}
        self._vendor_pos = {a: i + 1 for i, a in enumerate(self._vendor_order)}

    # ------------------------------------------------------------------ alerts

    def alert_summary(self, alert_id: str) -> AlertSummary:
        cached = self._summaries.get(alert_id)
        if cached is not None:
            return cached
        g = self.graph
        a = g.node(alert_id)
        if a is None or a.get("label") != "Alert":
            raise KeyError(alert_id)
        anchor = self.ctx.anchor_of(alert_id)
        score = int(a.get("contextual_score") or 0)
        summary = AlertSummary(
            id=alert_id, title=str(a.get("title") or a.get("name") or alert_id), source_system=str(a.get("source_system") or "unknown"),
            alert_type=str(a.get("alert_type") or "detection"), vendor_severity=str(a.get("vendor_severity") or "medium"),
            vendor_severity_rank=int(a.get("vendor_severity_rank") or 0), contextual_score=score,
            contextual_band=a.get("contextual_band") or band_for_score(score), detected_at=a.get("detected_at"), status=str(a.get("status") or "new"),
            entity_id=anchor, entity_name=self.ctx.short(anchor) if anchor else None, entity_label=g.label_of(anchor) if anchor else a.get("entity_label"),
            hostname=a.get("hostname"), user=a.get("user"), techniques=[str(t) for t in as_list(a.get("techniques"))],
            storyline_id=a.get("storyline_id") or None, graph_reasons=[str(r) for r in as_list(a.get("graph_reasons"))],
            reaches_crown_jewel=bool(a.get("reaches_crown_jewel")), on_attack_path=bool(a.get("on_attack_path")),
            ioc_match_count=int(a.get("ioc_match_count") or 0), ti_actor_ids=[str(x) for x in as_list(a.get("ti_actor_ids"))],
            vendor_rank_position=self._vendor_pos.get(alert_id), contextual_rank_position=self._contextual_pos.get(alert_id),
        )
        self._summaries[alert_id] = summary
        return summary

    def list_alerts(self, *, sort: str = "contextual", order: str = "desc", band: str | None = None, severity: str | None = None,
                    source: str | None = None, storyline_id: str | None = None, reaches_crown_jewel: bool | None = None,
                    on_attack_path: bool | None = None, q: str | None = None, limit: int = 50, offset: int = 0) -> tuple[list[AlertSummary], int]:
        g = self.graph
        if sort == "vendor":
            ordered = list(self._vendor_order)
        elif sort == "time":
            ordered = sorted(self.ctx.alerts, key=lambda a: (_rev(str(g.get(a, "detected_at") or "")), a))
        else:
            ordered = list(self._contextual_order)
        if order == "asc":
            ordered.reverse()
        text = (q or "").strip().lower()
        out: list[AlertSummary] = []
        for a in ordered:
            attrs = g.node(a) or {}
            if band and str(attrs.get("contextual_band") or "") != band:
                continue
            if severity and str(attrs.get("vendor_severity") or "").lower() != severity.lower():
                continue
            if source and str(attrs.get("source_system") or "") != source:
                continue
            if storyline_id and str(attrs.get("storyline_id") or "") != storyline_id:
                continue
            if reaches_crown_jewel is not None and bool(attrs.get("reaches_crown_jewel")) != reaches_crown_jewel:
                continue
            if on_attack_path is not None and bool(attrs.get("on_attack_path")) != on_attack_path:
                continue
            if text:
                hay = " ".join(str(attrs.get(k) or "") for k in ("title", "hostname", "entity_id", "user", "description")).lower() + " " + a.lower()
                anchor = self.ctx.anchor_of(a)
                if anchor:
                    hay += " " + self.ctx.short(anchor).lower()
                if text not in hay:
                    continue
            out.append(self.alert_summary(a))
        total = len(out)
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        return out[offset:offset + limit], total

    def flat_view(self, alert_id: str) -> dict[str, Any]:
        a = self.graph.node(alert_id)
        if a is None:
            raise KeyError(alert_id)
        raw = as_dict(a.get("raw"))
        if raw:
            return dict(raw)
        keys = ("title", "description", "vendor_severity", "status", "detected_at", "techniques", "tactic", "hostname", "user", "source_system", "alert_type", "vendor_incident_id", "change_ticket")
        return {k: a.get(k) for k in keys if a.get(k) is not None}

    def risk_breakdown(self, alert_id: str) -> RiskBreakdown:
        a = self.graph.node(alert_id)
        if a is None or a.get("label") != "Alert":
            raise KeyError(alert_id)
        stored = as_dict(a.get("score_breakdown"))
        try:
            bd = RiskBreakdown.model_validate(stored) if stored else self.scorer.score_alert(alert_id).breakdown
        except Exception:  # pragma: no cover - stale breakdown shape
            bd = self.scorer.score_alert(alert_id).breakdown
        cpos, vpos = self._contextual_pos.get(alert_id), self._vendor_pos.get(alert_id)
        if cpos is not None and vpos is not None:
            bd.delta_vs_vendor = cpos - vpos
        return bd

    def insights(self, alert_id: str) -> list[Insight]:
        cached = self._insights.get(alert_id)
        if cached is None:
            if alert_id not in self.graph:
                raise KeyError(alert_id)
            cached = insights.insights_for_alert(self.ctx, alert_id)
            self._insights[alert_id] = cached
        return list(cached)

    def related_alerts(self, alert_id: str) -> list[AlertSummary]:
        g = self.graph
        related: list[str] = []
        sid = g.get(alert_id, "storyline_id")
        if sid and sid in g:
            related.extend(a for a in as_list(g.get(sid, "alert_ids")) if a != alert_id and a in g)
        anchor = self.ctx.anchor_of(alert_id)
        t0 = self.ctx.alert_time(alert_id)
        if anchor:
            for other in self.ctx.alerts_on(anchor):
                if other == alert_id or other in related:
                    continue
                t1 = self.ctx.alert_time(other)
                if t0 is None or t1 is None or abs(t0 - t1) <= RELATED_WINDOW:
                    related.append(other)
        summaries = [self.alert_summary(a) for a in related]
        summaries.sort(key=lambda s: (-s.contextual_score, s.detected_at or "", s.id))
        return summaries[:25]

    def alert_context(self, alert_id: str) -> AlertContext:
        cached = self._contexts.get(alert_id)
        if cached is not None:
            return cached
        g = self.graph
        summary = self.alert_summary(alert_id)
        anchor = self.ctx.anchor_of(alert_id)
        risk = self.risk_breakdown(alert_id)
        ins = self.insights(alert_id)
        br = blast.blast_radius(self.ctx, anchor, depth=4, max_nodes=500, mode="full") if anchor else None
        sid = summary.storyline_id if summary.storyline_id and summary.storyline_id in g else None
        ap = paths.attack_paths(self.ctx, through_id=alert_id, k=3, storyline_scope=sid)
        story = correlation.storyline_out(self.ctx, sid, with_fragment=False) if sid else None
        tic = ti.threat_intel_context(self.ctx, alert_id)
        related = self.related_alerts(alert_id)
        evidence = self._evidence_fragment(alert_id, anchor, sid, br)
        result = AlertContext(alert=summary, flat_view=self.flat_view(alert_id), risk=risk, insights=ins, blast_radius=br, attack_paths=ap,
                              storyline=story, threat_intel=tic, related_alerts=related, evidence=evidence)
        self._contexts[alert_id] = result
        return result

    def _evidence_fragment(self, alert_id: str, anchor: str | None, sid: str | None, br: BlastRadiusResult | None) -> GraphFragment:
        g = self.graph
        if sid:
            nodes = [alert_id] + correlation.storyline_path_nodes(self.ctx, sid) + [sid]
            frag = g.fragment(nodes, highlight_ids={alert_id} | set(as_list(g.get(sid, "crown_jewels_reached"))), focus=[alert_id], layout_hint="path", max_nodes=150)
            members = [m for m in as_list(g.get(sid, "alert_ids")) + as_list(g.get(sid, "event_ids")) if m in g]
            members.sort(key=lambda m: (self.ctx.member_time(m) or NOW, m))
            if members:
                p = g.path_out(members, label="storyline timeline")
                frag.paths = [p]
            frag.meta = {"storyline_id": sid, "kind": "storyline_path"}
            return frag
        nodes = [alert_id]
        if anchor:
            hop2 = g.k_hop(alert_id, depth=2, max_nodes=120)
            # keep every 1-hop node, but cap the 2-hop fan-in per label (dozens of users with access to a public
            # bucket say nothing new); prefer nodes that carry alerts or are sensitive
            per_label: dict[str, int] = {}
            ranked = sorted(hop2, key=lambda n: (hop2[n], not self._interesting(n), n))
            for n in ranked:
                lbl = g.label_of(n) or ""
                if hop2[n] >= 2:
                    if per_label.get(lbl, 0) >= 6:
                        continue
                    per_label[lbl] = per_label.get(lbl, 0) + 1
                nodes.append(n)
        path_outs = []
        if br is not None:
            for r in br.crown_jewels[:5]:
                nodes += r.via_path
                path_outs.append(g.path_out(r.via_path, label=f"to {self.ctx.short(r.node.id)}", likelihood=r.reach_score))
        frag = g.fragment(nodes, highlight_ids={alert_id} | {r.node.id for r in (br.crown_jewels if br else [])}, focus=[alert_id], layout_hint="neighborhood", max_nodes=150, paths=path_outs)
        frag.meta = {"kind": "neighborhood_plus_blast"}
        return frag

    def _interesting(self, node_id: str) -> bool:
        """Nodes worth keeping when a neighborhood is trimmed: alerts, storyline members, sensitive or exposed assets."""
        g = self.graph
        a = g.node(node_id) or {}
        if a.get("label") in ("Alert", "Storyline", "Credential", "Indicator", "ThreatActor", "Campaign"):
            return True
        return bool(a.get("crown_jewel") or a.get("storyline_id") or a.get("exposure") == "internet" or a.get("is_admin"))

    # ------------------------------------------------------------------ graph analytics

    def blast_radius(self, root_id: str, depth: int = 4, max_nodes: int = 500) -> BlastRadiusResult:
        if root_id not in self.graph:
            raise KeyError(root_id)
        return blast.blast_radius(self.ctx, root_id, depth=depth, max_nodes=max_nodes, mode="full")

    def attack_paths(self, through_id: str | None = None, target_id: str | None = None, entry_id: str | None = None, k: int = 5) -> list[AttackPathOut]:
        for nid in (through_id, target_id, entry_id):
            if nid and nid not in self.graph:
                raise KeyError(nid)
        scope = None
        if through_id and self.graph.label_of(through_id) == "Alert":
            sid = self.graph.get(through_id, "storyline_id")
            scope = sid if sid and sid in self.graph else None
        return paths.attack_paths(self.ctx, through_id=through_id, target_id=target_id, entry_id=entry_id, k=k, storyline_scope=scope)

    def find_paths(self, src_id: str, dst_id: str, max_hops: int = 6, k: int = 3, edge_types: Iterable[str] | None = None) -> GraphFragment:
        for nid in (src_id, dst_id):
            if nid not in self.graph:
                raise KeyError(nid)
        return paths.find_paths(self.ctx, src_id, dst_id, max_hops=max_hops, k=k, edge_types=edge_types)

    def neighborhood(self, node_id: str, depth: int = 1, edge_types: Iterable[str] | None = None, direction: str = "both",
                     labels: Iterable[str] | None = None, max_nodes: int = 150) -> GraphFragment:
        g = self.graph
        if node_id not in g:
            raise KeyError(node_id)
        depth = max(1, min(int(depth), 3))
        max_nodes = max(1, min(int(max_nodes), 1000))
        et = list(edge_types) if edge_types else None
        lbls = set(labels) if labels else None
        hop = g.k_hop(node_id, depth=depth, edge_types=et, direction=direction, max_nodes=max_nodes, node_labels=lbls)
        ordered = sorted(hop, key=lambda n: (hop[n], n))
        frag = g.fragment(ordered, highlight_ids={node_id}, focus=[node_id], layout_hint="neighborhood", max_nodes=max_nodes)
        if et:
            frag.edges = [e for e in frag.edges if e.type in set(et)]
        frag.meta = {"depth": depth, "direction": direction}
        return frag

    def node_card(self, node_id: str) -> dict[str, Any]:
        g = self.graph
        if node_id not in g:
            raise KeyError(node_id)
        counts: dict[str, int] = {}
        for _, d in g.out_edges(node_id):
            counts[d["type"]] = counts.get(d["type"], 0) + 1
        for _, d in g.in_edges(node_id):
            counts[d["type"]] = counts.get(d["type"], 0) + 1
        alerts = [self.alert_summary(a) for a in self.ctx.alerts_on(node_id)]
        if g.label_of(node_id) == "Alert":
            alerts = [self.alert_summary(node_id)]
        alerts.sort(key=lambda s: (-s.contextual_score, s.id))
        label = g.label_of(node_id)
        tic = ti.threat_intel_context(self.ctx, node_id) if label not in ("Team", "Application", "Group") else None
        if tic is not None and not (tic.matches or tic.actors or tic.exploited_vulnerabilities or tic.campaigns):
            tic = None
        return {
            "node": g.node_out(node_id),
            "degree": {"in": len(g.in_edges(node_id)), "out": len(g.out_edges(node_id))},
            "edge_type_counts": dict(sorted(counts.items())),
            "alerts": alerts[:10],
            "threat_intel": tic,
        }

    # ------------------------------------------------------------------ storylines & TI

    def list_storylines(self) -> list[StorylineOut]:
        out = [correlation.storyline_out(self.ctx, sid, with_fragment=False) for sid in self.graph.nodes_by_label("Storyline")]
        out.sort(key=lambda s: (-s.contextual_score, s.first_event or "", s.id))
        return out

    def storyline(self, storyline_id: str, with_fragment: bool = True) -> StorylineOut:
        if storyline_id not in self.graph:
            raise KeyError(storyline_id)
        return correlation.storyline_out(self.ctx, storyline_id, with_fragment=with_fragment)

    def threat_intel_context(self, node_or_alert_id: str) -> TIContext:
        if node_or_alert_id not in self.graph:
            raise KeyError(node_or_alert_id)
        return ti.threat_intel_context(self.ctx, node_or_alert_id)

    def ti_lookup(self, value: str) -> TIContext:
        return ti.ti_lookup(self.ctx, value)

    def ti_actors(self) -> list[dict[str, Any]]:
        return ti.ti_actors(self.ctx)

    def ti_actor(self, actor_id: str) -> dict[str, Any]:
        return ti.ti_actor(self.ctx, actor_id, summarize=self.alert_summary)

    def ti_campaign(self, campaign_id: str) -> dict[str, Any]:
        return ti.ti_campaign(self.ctx, campaign_id, summarize=self.alert_summary)

    def ti_reports(self) -> list[NodeOut]:
        return ti.ti_reports(self.ctx)

    def ti_report(self, report_id: str) -> dict[str, Any]:
        return ti.ti_report(self.ctx, report_id, summarize=self.alert_summary)

    def ti_exposure(self, sector_only: bool = True) -> list[dict[str, Any]]:
        return ti.ti_exposure(
            self.ctx, sector_only=sector_only, score_asset=lambda vm: self.scorer.score_asset(vm)[0],
            alert_score=lambda a: None if self.scorer.is_benign(a) else (int(self.graph.get(a, "contextual_score") or 0), self._raw(a)),
        )

    # ------------------------------------------------------------------ typed investigations

    def credential_joins(self) -> dict[str, Any]:
        return questions.credential_joins(self.ctx, self.alert_summary)

    def alerts_reaching_crown_jewels(self, jewel_id: str | None = None, classification: str | None = None) -> dict[str, Any]:
        return questions.alerts_reaching_crown_jewels(self.ctx, self.alert_summary, jewel_id=jewel_id, classification=classification)

    def medium_alerts_with_data_path(self, severity: str = "medium", source: str | None = "falcon") -> dict[str, Any]:
        return questions.medium_alerts_with_data_path(self.ctx, self.alert_summary, severity=severity, source=source)

    def identity_footprint(self, identity_id: str) -> BlastRadiusResult:
        if identity_id not in self.graph:
            raise KeyError(identity_id)
        return questions.identity_footprint(self.ctx, identity_id)

    def simulate_containment(self, target_ids: list[str], actions: list[str]) -> ContainmentSimulation:
        return containment.simulate_containment(self.ctx, list(target_ids), list(actions))

    def dashboard(self) -> dict[str, Any]:
        return questions.dashboard(self.ctx, self.list_alerts, self.alert_summary, self.list_storylines)

    # ------------------------------------------------------------------ misc helpers used by the API layer

    def search(self, text: str, labels: Sequence[str] | None = None, limit: int = 25):
        return self.graph.search(text, labels=labels, limit=limit)

    def crown_jewels(self) -> list[NodeOut]:
        return [self.graph.node_out(j) for j in self.ctx.crown_jewels if self.graph.label_of(j) in sem.DATA_HOLDER_LABELS]


def _rev(text: str) -> str:
    """Sort helper: a key that orders ISO timestamps descending inside an ascending sort."""
    return "".join(chr(0x10FFFF - ord(c)) for c in text)
