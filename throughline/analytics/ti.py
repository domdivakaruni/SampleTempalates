"""Threat-intelligence impact: IOC matching, attribution, vulnerability overlay, TI context and exposure table.

Build time (called by ``materialize.enrich``): :func:`overlay_vulnerabilities`, :func:`match_iocs`,
:func:`attribute_alerts`, :func:`ti_exposure_scores`.
Request time: :func:`threat_intel_context`, :func:`ti_lookup`, :func:`ti_actors`, :func:`ti_actor`,
:func:`ti_campaign`, :func:`ti_reports`, :func:`ti_report`, :func:`ti_exposure`.
"""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from throughline.analytics import semantics as sem
from throughline.analytics.context import AnalyticsContext, as_list
from throughline.graph.context_graph import edge_id
from throughline.models import GraphFragment, NodeOut, TIContext, TIMatch

DERIVED = "derived"
STATUS_WEIGHT = {"mass_exploitation": 1.0, "active": 0.8, "poc_public": 0.4, "none": 0.1}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_TECH = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def _norm(ioc_type: str, value: Any) -> str:
    v = str(value or "").strip()
    if ioc_type in ("sha256", "domain", "url", "email"):
        v = v.lower().rstrip(".")
    if ioc_type == "filename":
        v = v.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return v


# ---------------------------------------------------------------------- build-time: vulnerability overlay


def actor_of(ctx: AnalyticsContext, node_id: str) -> str | None:
    """Actor behind an actor / campaign / indicator / malware node."""
    g = ctx.graph
    label = g.label_of(node_id)
    if label == "ThreatActor":
        return node_id
    if label == "Campaign":
        a = g.get(node_id, "actor_id")
        if a and a in g:
            return str(a)
        for who, _ in g.out_edges(node_id, ("ATTRIBUTED_TO",)):
            if g.label_of(who) == "ThreatActor":
                return who
        return None
    if label == "Indicator":
        a = g.get(node_id, "actor_id")
        if a and a in g:
            return str(a)
        for tgt, _ in g.out_edges(node_id, ("INDICATES",)):
            found = actor_of(ctx, tgt)
            if found:
                return found
        return None
    if label == "Malware":
        for who, _ in g.in_edges(node_id, ("USES_MALWARE",)):
            if g.label_of(who) == "ThreatActor":
                return who
        for who, _ in g.in_edges(node_id, ("USES_MALWARE",)):
            found = actor_of(ctx, who)
            if found:
                return found
    return None


def campaign_of(ctx: AnalyticsContext, node_id: str) -> str | None:
    g = ctx.graph
    label = g.label_of(node_id)
    if label == "Campaign":
        return node_id
    if label == "Indicator":
        c = g.get(node_id, "campaign_id")
        if c and c in g:
            return str(c)
        for tgt, _ in g.out_edges(node_id, ("INDICATES",)):
            if g.label_of(tgt) == "Campaign":
                return tgt
        for tgt, _ in g.out_edges(node_id, ("INDICATES",)):
            if g.label_of(tgt) == "Malware":
                for who, _ in g.in_edges(tgt, ("USES_MALWARE",)):
                    if g.label_of(who) == "Campaign":
                        return who
    return None


def relevance_of(ctx: AnalyticsContext, node_id: str | None) -> float:
    if not node_id:
        return 0.0
    try:
        return float(ctx.graph.get(node_id, "sector_targeting_relevance") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def overlay_vulnerabilities(ctx: AnalyticsContext) -> dict[str, int]:
    """Stamp exploitation_status / actor_interest / sector_targeting_relevance / ti_report_ids on CVEs."""
    g = ctx.graph
    touched = exploited = 0
    for cve in g.nodes_by_label("Vulnerability"):
        attrs = g.node(cve) or {}
        statuses = [str(attrs.get("exploitation_status") or "none")]
        actors: set[str] = set()
        relevance = 0.0
        for who, d in g.in_edges(cve, ("EXPLOITS",)):
            statuses.append(str(d.get("status") or "active"))
            actor = actor_of(ctx, who)
            if actor:
                actors.add(actor)
            relevance = max(relevance, relevance_of(ctx, who), relevance_of(ctx, actor))
        status = max(statuses, key=lambda s: sem.EXPLOITATION_RANK.get(s, 0))
        reports = sorted(r for r, _ in g.in_edges(cve, ("REPORTS_ON",)))
        g.set_node_props(cve, exploitation_status=status, actor_interest=sorted(actors), sector_targeting_relevance=round(relevance, 3), ti_report_ids=reports)
        touched += 1
        if status in sem.EXPLOITED_STATUSES:
            exploited += 1
    return {"vulnerabilities": touched, "exploited": exploited}


# ---------------------------------------------------------------------- build-time: IOC matching


def _indicator_index(ctx: AnalyticsContext) -> dict[tuple[str, str], list[str]]:
    g = ctx.graph
    idx: dict[tuple[str, str], list[str]] = defaultdict(list)
    for ind in g.nodes_by_label("Indicator"):
        t = str(g.get(ind, "ioc_type") or "").lower()
        v = _norm(t, g.get(ind, "value"))
        if t and v:
            idx[(t, v)].append(ind)
    return idx


def match_iocs(ctx: AnalyticsContext) -> dict[str, int]:
    """Hash-join telemetry against indicators and record MATCHES_IOC edges (entities, then alerts and events)."""
    g = ctx.graph
    idx = _indicator_index(ctx)
    if not idx:
        return {"entity_matches": 0, "alert_matches": 0, "event_matches": 0}
    entity_hits: dict[str, list[tuple[str, str, float]]] = defaultdict(list)  # node -> [(indicator, match_type, conf)]

    def hit(node: str, key: tuple[str, str], match_type: str) -> None:
        for ind in idx.get(key, []):
            conf = float(g.get(ind, "confidence") or 0.5)
            entity_hits[node].append((ind, match_type, conf))

    for f in g.nodes_by_label("File"):
        sha = g.get(f, "sha256")
        if sha:
            hit(f, ("sha256", _norm("sha256", sha)), "exact")
        name = g.get(f, "file_name") or g.get(f, "file_path")
        if name:
            hit(f, ("filename", _norm("filename", name)), "fuzzy")
    for p in g.nodes_by_label("Process"):
        sha = g.get(p, "sha256")
        if sha:
            hit(p, ("sha256", _norm("sha256", sha)), "exact")
        img = g.get(p, "image_path")
        if img:
            hit(p, ("filename", _norm("filename", img)), "fuzzy")
    for ip in g.nodes_by_label("IpAddress"):
        addr = g.get(ip, "address")
        if addr:
            hit(ip, ("ipv4", _norm("ipv4", addr)), "exact")
    for dom in g.nodes_by_label("Domain"):
        fqdn = g.get(dom, "fqdn") or g.get(dom, "name")
        if fqdn:
            hit(dom, ("domain", _norm("domain", fqdn)), "exact")

    n_entity = 0
    for node, hits in entity_hits.items():
        best: dict[str, tuple[str, float]] = {}
        for ind, mt, conf in hits:
            cur = best.get(ind)
            if cur is None or conf > cur[1]:
                best[ind] = (mt, conf)
        for ind, (mt, conf) in best.items():
            _add_match(g, node, ind, mt, conf)
            n_entity += 1

    # alerts: through INVOLVES, and one hop further through processes (files executed, network destinations)
    n_alert = 0
    for a in ctx.alerts:
        found: dict[str, tuple[str, float, str]] = {}
        for ent, _ in g.out_edges(a, ("INVOLVES",)):
            for ind, mt, conf in entity_hits.get(ent, []):
                found.setdefault(ind, (mt, conf, ent))
            if g.label_of(ent) == "Process":
                for nb, d in g.out_edges(ent, ("EXECUTED", "CONNECTED_TO")):
                    for ind, mt, conf in entity_hits.get(nb, []):
                        found.setdefault(ind, (mt, conf, nb))
        for ind, (mt, conf, via) in found.items():
            _add_match(g, a, ind, mt, conf, via=via)
            n_alert += 1
        g.set_node_props(a, ioc_match_count=len(found))
    n_event = 0
    for ev in ctx.cloud_events:
        found = {}
        for ip, _ in g.out_edges(ev, ("FROM_IP",)):
            for ind, mt, conf in entity_hits.get(ip, []):
                found.setdefault(ind, (mt, conf, ip))
        for ind, (mt, conf, via) in found.items():
            _add_match(g, ev, ind, mt, conf, via=via)
            n_event += 1
        if found:
            g.set_node_props(ev, ioc_match_count=len(found))
    return {"entity_matches": n_entity, "alert_matches": n_alert, "event_matches": n_event}


def _add_match(g, src: str, ind: str, match_type: str, conf: float, via: str | None = None) -> None:
    props: dict[str, Any] = {"match_type": match_type, "confidence": round(conf, 3)}
    if via:
        props["via"] = via
    g.add_edge_record({"type": "MATCHES_IOC", "src": src, "dst": ind, "source": DERIVED, "first_seen": g.get(ind, "first_seen"),
                       "last_seen": g.get(ind, "last_seen"), "confidence": round(conf, 3), "props": props})


# ---------------------------------------------------------------------- build-time: attribution


def campaign_techniques(ctx: AnalyticsContext, who: str) -> set[str]:
    g = ctx.graph
    out: set[str] = set()
    for t, _ in g.out_edges(who, ("USES_TECHNIQUE",)):
        tid = g.get(t, "technique_id") or t.rsplit(":", 1)[-1]
        out.add(str(tid))
    return out


def attribute_alerts(ctx: AnalyticsContext, min_ttp_ratio: float = 0.5, min_ttp_overlap: int = 3) -> dict[str, int]:
    """ATTRIBUTED_TO edges from alerts to campaigns and actors (IOC match, or TTP overlap >= 0.5 covering >= 3 techniques)."""
    g = ctx.graph
    campaigns = list(g.nodes_by_label("Campaign"))
    ttps = {c: campaign_techniques(ctx, c) for c in campaigns}
    n_edges = 0
    for a in ctx.alerts:
        votes: dict[str, dict[str, Any]] = {}
        for ind, d in g.out_edges(a, ("MATCHES_IOC",)):
            conf = float(d.get("confidence") or 0.5)
            camp = campaign_of(ctx, ind)
            actor = actor_of(ctx, ind)
            for target in (camp, actor):
                if target:
                    v = votes.setdefault(target, {"basis": "ioc", "confidence": 0.0, "ttp_overlap": 0.0})
                    v["confidence"] = max(v["confidence"], conf)
        techs = {str(t) for t in as_list(g.get(a, "techniques"))}
        if techs:
            for c in campaigns:
                overlap = techs & ttps[c]
                ratio = len(overlap) / len(techs)
                if len(overlap) >= min_ttp_overlap and ratio >= min_ttp_ratio:
                    conf = round(0.3 + 0.4 * ratio, 3)
                    for target in (c, actor_of(ctx, c)):
                        if not target:
                            continue
                        v = votes.get(target)
                        if v is None:
                            votes[target] = {"basis": "ttp", "confidence": conf, "ttp_overlap": round(ratio, 3)}
                        else:
                            v["basis"] = "ioc+ttp" if v["basis"].startswith("ioc") else "ttp"
                            v["ttp_overlap"] = max(v["ttp_overlap"], round(ratio, 3))
                            v["confidence"] = max(v["confidence"], conf)
        for target, v in votes.items():
            g.add_edge_record({"type": "ATTRIBUTED_TO", "src": a, "dst": target, "source": DERIVED, "first_seen": g.get(a, "detected_at"),
                               "last_seen": g.get(a, "detected_at"), "confidence": v["confidence"],
                               "props": {"basis": v["basis"], "confidence": v["confidence"], "ttp_overlap": v["ttp_overlap"]}})
            n_edges += 1
    return {"attributions": n_edges}


# ---------------------------------------------------------------------- build-time: exposure score


def exposed_assets(ctx: AnalyticsContext) -> list[str]:
    g = ctx.graph
    out: set[str] = set()
    if sem.INTERNET_ID in g:
        for v, _ in g.out_edges(sem.INTERNET_ID, ("EXPOSES",)):
            out.add(v)
    for label in ("VirtualMachine", "Workload", "ServerlessFunction"):
        for n in g.nodes_by_label(label):
            if str(g.get(n, "exposure") or "").lower() == "internet":
                out.add(n)
    return sorted(out)


def exposure_score_of(ctx: AnalyticsContext, asset: str) -> float:
    g = ctx.graph
    best = 0.0
    for cve, _ in g.out_edges(asset, ("VULNERABLE_TO",)):
        status = str(g.get(cve, "exploitation_status") or "none")
        w = STATUS_WEIGHT.get(status, 0.1)
        if status == "none" and g.get(cve, "kev"):
            w = 0.3
        rel = relevance_of(ctx, cve)
        try:
            cvss = float(g.get(cve, "cvss") or 5.0) / 10.0
        except (TypeError, ValueError):
            cvss = 0.5
        best = max(best, w * (0.5 + 0.5 * rel) * cvss)
    return round(min(best, 1.0), 3)


def ti_exposure_scores(ctx: AnalyticsContext) -> dict[str, int]:
    g = ctx.graph
    exposed = set(exposed_assets(ctx))
    n = 0
    for vm in g.nodes_by_label("VirtualMachine"):
        score = exposure_score_of(ctx, vm) if vm in exposed else 0.0
        g.set_node_props(vm, ti_exposure_score=score)
        n += 1
    for asset in exposed:
        if g.label_of(asset) != "VirtualMachine":
            g.set_node_props(asset, ti_exposure_score=exposure_score_of(ctx, asset))
            n += 1
    return {"assets_scored": n, "internet_exposed": len(exposed)}


# ---------------------------------------------------------------------- request-time: TI context


def _match(ctx: AnalyticsContext, ind: str, matched: str, conf: float | None = None) -> TIMatch:
    g = ctx.graph
    return TIMatch(
        indicator_id=ind, ioc_type=str(g.get(ind, "ioc_type") or "unknown"), value=str(g.get(ind, "value") or ""),
        confidence=float(conf if conf is not None else (g.get(ind, "confidence") or 0.5)), matched_node_id=matched,
        matched_label=g.label_of(matched) or "Unknown", actor_id=actor_of(ctx, ind), campaign_id=campaign_of(ctx, ind),
        malware_id=str(g.get(ind, "malware_id")) if g.get(ind, "malware_id") in g else next((t for t, _ in g.out_edges(ind, ("INDICATES",)) if g.label_of(t) == "Malware"), None),
        report_id=str(g.get(ind, "report_id")) if g.get(ind, "report_id") else next((r for r, _ in g.in_edges(ind, ("REPORTS_ON",))), None),
    )


def _matches_of_node(ctx: AnalyticsContext, node_id: str) -> list[TIMatch]:
    g = ctx.graph
    return [_match(ctx, ind, node_id, d.get("confidence")) for ind, d in g.out_edges(node_id, ("MATCHES_IOC",))]


class _Collector:
    def __init__(self, ctx: AnalyticsContext) -> None:
        self.ctx = ctx
        self.matches: dict[str, TIMatch] = {}
        self.actors: dict[str, None] = {}
        self.campaigns: dict[str, None] = {}
        self.malware: dict[str, None] = {}
        self.cves: dict[str, None] = {}
        self.reports: dict[str, None] = {}
        self.techniques: set[str] = set()

    def add_matches(self, matches: list[TIMatch]) -> None:
        g = self.ctx.graph
        for m in matches:
            key = f"{m.indicator_id}|{m.matched_node_id}"
            if key in self.matches:
                continue
            self.matches[key] = m
            if m.actor_id:
                self.actors[m.actor_id] = None
            if m.campaign_id:
                self.campaigns[m.campaign_id] = None
            if m.malware_id and m.malware_id in g:
                self.malware[m.malware_id] = None
            if m.report_id and m.report_id in g:
                self.reports[m.report_id] = None

    def add_ti_node(self, node_id: str) -> None:
        g = self.ctx.graph
        label = g.label_of(node_id)
        if label == "ThreatActor":
            self.actors[node_id] = None
        elif label == "Campaign":
            self.campaigns[node_id] = None
            a = actor_of(self.ctx, node_id)
            if a:
                self.actors[a] = None
        elif label == "Malware":
            self.malware[node_id] = None
        elif label == "IntelReport":
            self.reports[node_id] = None

    def add_cve(self, cve: str) -> None:
        g = self.ctx.graph
        if cve not in g:
            return
        self.cves[cve] = None
        for a in as_list(g.get(cve, "actor_interest")):
            if a in g:
                self.actors[a] = None
        for who, _ in g.in_edges(cve, ("EXPLOITS",)):
            self.add_ti_node(who)
        for r in as_list(g.get(cve, "ti_report_ids")):
            if r in g:
                self.reports[r] = None

    def finish(self, summary_subject: str) -> TIContext:
        g = self.ctx.graph
        for c in list(self.campaigns):
            a = actor_of(self.ctx, c)
            if a:
                self.actors[a] = None
        for who in list(self.actors) + list(self.campaigns) + list(self.malware) + [m.indicator_id for m in self.matches.values()]:
            for r, _ in g.in_edges(who, ("REPORTS_ON",)):
                self.reports[r] = None
        overlap: dict[str, float] = {}
        if self.techniques:
            for who in list(self.actors) + list(self.campaigns):
                ttps = campaign_techniques(self.ctx, who)
                if ttps:
                    overlap[who] = round(len(self.techniques & ttps) / len(self.techniques), 3)
        relevance = max((relevance_of(self.ctx, a) for a in self.actors), default=None)
        exploited = [c for c in self.cves if str(g.get(c, "exploitation_status") or "none") != "none"]
        ctx = self.ctx
        parts = []
        if self.matches:
            parts.append(f"{len(self.matches)} IOC match{'es' if len(self.matches) != 1 else ''}")
        if self.actors:
            parts.append("actors: " + ", ".join(ctx.name(a) for a in list(self.actors)[:3]))
        if exploited:
            parts.append(f"{len(exploited)} exploited vulnerabilit{'ies' if len(exploited) != 1 else 'y'}")
        if overlap:
            best = max(overlap.items(), key=lambda kv: kv[1])
            parts.append(f"TTP overlap {best[1]:.0%} with {ctx.name(best[0])}")
        if relevance is not None:
            parts.append(f"sector relevance {relevance:.2f}")
        summary = f"{summary_subject}: " + ("; ".join(parts) if parts else "no threat-intel context")
        return TIContext(
            matches=sorted(self.matches.values(), key=lambda m: (-m.confidence, m.indicator_id)),
            actors=[g.node_out(a) for a in self.actors],
            campaigns=[g.node_out(c) for c in self.campaigns],
            malware=[g.node_out(m) for m in self.malware],
            exploited_vulnerabilities=[g.node_out(c) for c in exploited],
            reports=[g.node_out(r) for r in self.reports if r in g],
            ttp_overlap=overlap, sector_relevance=relevance, summary=summary,
        )


def threat_intel_context(ctx: AnalyticsContext, node_id: str) -> TIContext:
    g = ctx.graph
    col = _Collector(ctx)
    if node_id not in g:
        return col.finish(node_id)
    label = g.label_of(node_id)
    col.add_matches(_matches_of_node(ctx, node_id))
    if label in ("ThreatActor", "Campaign", "Malware", "IntelReport"):
        return _context_for_ti_node(ctx, node_id)
    if label == "Vulnerability":
        col.add_cve(node_id)
        return col.finish(g.get(node_id, "cve_id") or node_id)
    if label == "Indicator":
        col.add_matches([_match(ctx, node_id, m) for m, _ in g.in_edges(node_id, ("MATCHES_IOC",))] or [_match(ctx, node_id, node_id)])
        return col.finish(str(g.get(node_id, "value") or node_id))
    if label == "Alert":
        col.techniques.update(str(t) for t in as_list(g.get(node_id, "techniques")))
        for ent, _ in g.out_edges(node_id, ("INVOLVES",)):
            col.add_matches(_matches_of_node(ctx, ent))
            if g.label_of(ent) == "Vulnerability":
                col.add_cve(ent)
        for who, _ in g.out_edges(node_id, ("ATTRIBUTED_TO",)):
            col.add_ti_node(who)
        for s, _ in g.out_edges(node_id, ("IN_STORYLINE",)):
            for who, _ in g.out_edges(s, ("ATTRIBUTED_TO",)):
                col.add_ti_node(who)
        asset = ctx.asset_of(node_id)
        if asset:
            for cve, _ in g.out_edges(asset, ("VULNERABLE_TO",)):
                if str(g.get(cve, "exploitation_status") or "none") != "none":
                    col.add_cve(cve)
        return col.finish(str(g.get(node_id, "title") or node_id))
    if label == "Storyline":
        for aid in as_list(g.get(node_id, "alert_ids")):
            if aid in g:
                col.techniques.update(str(t) for t in as_list(g.get(aid, "techniques")))
                col.add_matches(_matches_of_node(ctx, aid))
        for who, _ in g.out_edges(node_id, ("ATTRIBUTED_TO",)):
            col.add_ti_node(who)
        return col.finish(str(g.get(node_id, "title") or node_id))
    # assets, endpoints, identities, processes
    asset = ctx.vm_or_self(node_id)
    for n in {node_id, asset}:
        for cve, _ in g.out_edges(n, ("VULNERABLE_TO",)):
            if str(g.get(cve, "exploitation_status") or "none") != "none":
                col.add_cve(cve)
        for a in ctx.alerts_on(n):
            col.add_matches(_matches_of_node(ctx, a))
            col.techniques.update(str(t) for t in as_list(g.get(a, "techniques")))
            for who, _ in g.out_edges(a, ("ATTRIBUTED_TO",)):
                col.add_ti_node(who)
    if label == "Endpoint":
        for p, _ in g.in_edges(node_id, ("RAN_ON",)):
            col.add_matches(_matches_of_node(ctx, p))
            for nb, _ in g.out_edges(p, ("EXECUTED", "CONNECTED_TO")):
                col.add_matches(_matches_of_node(ctx, nb))
    if label == "Process":
        for nb, _ in g.out_edges(node_id, ("EXECUTED", "CONNECTED_TO")):
            col.add_matches(_matches_of_node(ctx, nb))
    return col.finish(ctx.name(node_id))


def _context_for_ti_node(ctx: AnalyticsContext, node_id: str) -> TIContext:
    g = ctx.graph
    col = _Collector(ctx)
    col.add_ti_node(node_id)
    label = g.label_of(node_id)
    related: list[str] = [node_id]
    if label == "ThreatActor":
        related += [c for c, _ in g.in_edges(node_id, ("ATTRIBUTED_TO",)) if g.label_of(c) == "Campaign"]
        related += [c for c in g.nodes_by_label("Campaign") if g.get(c, "actor_id") == node_id]
        related += [m for m, _ in g.out_edges(node_id, ("USES_MALWARE",))]
    elif label == "Campaign":
        related += [m for m, _ in g.out_edges(node_id, ("USES_MALWARE",))]
    elif label == "IntelReport":
        related += [t for t, _ in g.out_edges(node_id, ("REPORTS_ON",))]
    for r in dict.fromkeys(related):
        rl = g.label_of(r)
        if rl in ("ThreatActor", "Campaign", "Malware", "IntelReport"):
            col.add_ti_node(r)
        elif rl == "Vulnerability":
            col.add_cve(r)
        elif rl == "Indicator":
            col.add_matches([_match(ctx, r, m) for m, _ in g.in_edges(r, ("MATCHES_IOC",))])
    for who in list(col.actors) + list(col.campaigns):
        for cve, _ in g.out_edges(who, ("EXPLOITS",)):
            col.add_cve(cve)
    for ind in indicators_of(ctx, list(col.actors) + list(col.campaigns) + list(col.malware)):
        col.add_matches([_match(ctx, ind, m) for m, _ in g.in_edges(ind, ("MATCHES_IOC",))])
    col.techniques.update(t for who in list(col.actors) + list(col.campaigns) for t in campaign_techniques(ctx, who))
    tic = col.finish(ctx.name(node_id))
    tic.ttp_overlap = {}
    return tic


def indicators_of(ctx: AnalyticsContext, ti_nodes: list[str]) -> list[str]:
    g = ctx.graph
    wanted = set(ti_nodes)
    out: list[str] = []
    for ind in g.nodes_by_label("Indicator"):
        if g.get(ind, "actor_id") in wanted or g.get(ind, "campaign_id") in wanted or g.get(ind, "malware_id") in wanted:
            out.append(ind)
            continue
        if any(t in wanted for t, _ in g.out_edges(ind, ("INDICATES",))):
            out.append(ind)
    return out


def ti_lookup(ctx: AnalyticsContext, value: str) -> TIContext:
    g = ctx.graph
    v = (value or "").strip()
    if not v:
        return TIContext(summary="empty lookup")
    if v in g:
        return threat_intel_context(ctx, v)
    low = v.lower()
    col = _Collector(ctx)
    if _HEX64.match(low):
        for key in (f"file:sha256:{low}",):
            if key in g:
                col.add_matches(_matches_of_node(ctx, key))
        for ind in g.nodes_by_label("Indicator"):
            if str(g.get(ind, "ioc_type")) == "sha256" and _norm("sha256", g.get(ind, "value")) == low:
                hits = [m for m, _ in g.in_edges(ind, ("MATCHES_IOC",))]
                col.add_matches([_match(ctx, ind, m) for m in hits] or [_match(ctx, ind, ind)])
        return col.finish(f"hash {v[:12]}...")
    if _IPV4.match(v):
        node = f"ip:v4:{v}"
        if node in g:
            col.add_matches(_matches_of_node(ctx, node))
        for ind in g.nodes_by_label("Indicator"):
            if str(g.get(ind, "ioc_type")) == "ipv4" and str(g.get(ind, "value")) == v:
                hits = [m for m, _ in g.in_edges(ind, ("MATCHES_IOC",))]
                col.add_matches([_match(ctx, ind, m) for m in hits] or [_match(ctx, ind, ind)])
        return col.finish(f"ip {v}")
    if _CVE.match(v):
        node = f"cve:{v.upper()}"
        col.add_cve(node)
        return col.finish(v.upper())
    if _TECH.match(v):
        tid = v.upper()
        node = f"technique:attack:{tid}"
        col.techniques.add(tid)
        if node in g:
            for who, _ in g.in_edges(node, ("USES_TECHNIQUE",)):
                if g.label_of(who) in ("ThreatActor", "Campaign", "Malware"):
                    col.add_ti_node(who)
        tic = col.finish(f"technique {tid}")
        return tic
    if "." in low and " " not in low:
        node = f"domain:dns:{low}"
        if node in g:
            col.add_matches(_matches_of_node(ctx, node))
        for ind in g.nodes_by_label("Indicator"):
            if str(g.get(ind, "ioc_type")) in ("domain", "url") and low in _norm("domain", g.get(ind, "value")):
                hits = [m for m, _ in g.in_edges(ind, ("MATCHES_IOC",))]
                col.add_matches([_match(ctx, ind, m) for m in hits] or [_match(ctx, ind, ind)])
        if col.matches:
            return col.finish(f"domain {low}")
    # names of actors / campaigns / malware / reports
    for label in ("ThreatActor", "Campaign", "Malware", "IntelReport"):
        for n in g.nodes_by_label(label):
            names = [str(g.get(n, "name") or ""), str(g.get(n, "title") or ""), n.rsplit(":", 1)[-1]] + [str(x) for x in as_list(g.get(n, "aliases"))]
            if any(low == x.lower() or (len(low) >= 4 and low in x.lower()) for x in names if x):
                return _context_for_ti_node(ctx, n)
    return TIContext(summary=f"no threat-intel object matches {v!r}")


# ---------------------------------------------------------------------- request-time: catalog views


def actor_campaigns(ctx: AnalyticsContext, actor_id: str) -> list[str]:
    g = ctx.graph
    out = [c for c, _ in g.in_edges(actor_id, ("ATTRIBUTED_TO",)) if g.label_of(c) == "Campaign"]
    out += [c for c in g.nodes_by_label("Campaign") if g.get(c, "actor_id") == actor_id]
    return sorted(dict.fromkeys(out))


def matched_alerts_for(ctx: AnalyticsContext, ti_nodes: list[str]) -> list[str]:
    """Alerts attributed to any of the given actors/campaigns (or matching their indicators)."""
    g = ctx.graph
    wanted = set(ti_nodes)
    out: set[str] = set()
    for who in wanted:
        for a, _ in g.in_edges(who, ("ATTRIBUTED_TO",)):
            if g.label_of(a) == "Alert":
                out.add(a)
    for ind in indicators_of(ctx, list(wanted)):
        for m, _ in g.in_edges(ind, ("MATCHES_IOC",)):
            if g.label_of(m) == "Alert":
                out.add(m)
    return sorted(out)


def exploited_cves_of(ctx: AnalyticsContext, ti_nodes: list[str]) -> list[str]:
    g = ctx.graph
    out: set[str] = set()
    for who in ti_nodes:
        for cve, _ in g.out_edges(who, ("EXPLOITS",)):
            out.add(cve)
    return sorted(out)


def assets_vulnerable_to(ctx: AnalyticsContext, cves: list[str]) -> list[str]:
    g = ctx.graph
    out: set[str] = set()
    for cve in cves:
        for asset, _ in g.in_edges(cve, ("VULNERABLE_TO",)):
            out.add(asset)
    return sorted(out)


def ti_actors(ctx: AnalyticsContext) -> list[dict[str, Any]]:
    g = ctx.graph
    rows: list[dict[str, Any]] = []
    for actor in g.nodes_by_label("ThreatActor"):
        camps = actor_campaigns(ctx, actor)
        inds = indicators_of(ctx, [actor] + camps)
        ioc_matches = sum(len(g.in_edges(i, ("MATCHES_IOC",))) for i in inds)
        alerts = matched_alerts_for(ctx, [actor] + camps)
        cves = exploited_cves_of(ctx, [actor] + camps)
        present = [c for c in cves if g.in_edges(c, ("VULNERABLE_TO",))]
        affected = set(assets_vulnerable_to(ctx, present))
        for a in alerts:
            anc = ctx.anchor_of(a)
            if anc:
                affected.add(ctx.vm_or_self(anc))
        rows.append({
            "actor": g.node_out(actor), "campaigns": [g.node_out(c) for c in camps],
            "sector_relevance": relevance_of(ctx, actor), "active": bool(g.get(actor, "active")),
            "ioc_matches": ioc_matches, "matched_alerts": len(alerts), "matched_alert_ids": alerts,
            "exploited_cves_present": len(present), "exploited_cve_ids": present, "affected_assets": len(affected),
            "affected_asset_ids": sorted(affected),
        })
    rows.sort(key=lambda r: (-r["sector_relevance"], -(r["ioc_matches"] + r["matched_alerts"]), r["actor"].id))
    return rows


def ti_actor(ctx: AnalyticsContext, actor_id: str) -> dict[str, Any]:
    return _ti_entity(ctx, actor_id, actor_campaigns(ctx, actor_id))


def ti_campaign(ctx: AnalyticsContext, campaign_id: str) -> dict[str, Any]:
    return _ti_entity(ctx, campaign_id, [campaign_id])


def _ti_entity(ctx: AnalyticsContext, node_id: str, campaigns: list[str]) -> dict[str, Any]:
    g = ctx.graph
    if node_id not in g:
        raise KeyError(node_id)
    label = g.label_of(node_id)
    actor = node_id if label == "ThreatActor" else actor_of(ctx, node_id)
    who = list(dict.fromkeys(([actor] if actor and label == "ThreatActor" else []) + campaigns + ([node_id] if node_id not in campaigns else [])))
    malware = sorted({m for w in who for m, _ in g.out_edges(w, ("USES_MALWARE",))})
    techniques = sorted({t for w in who for t, _ in g.out_edges(w, ("USES_TECHNIQUE",))})
    inds = indicators_of(ctx, who + malware)
    reports = sorted({r for w in who + malware + inds for r, _ in g.in_edges(w, ("REPORTS_ON",))})
    alerts = matched_alerts_for(ctx, who)
    cves = exploited_cves_of(ctx, who)
    affected = set(assets_vulnerable_to(ctx, cves))
    anchors = []
    for a in alerts:
        anc = ctx.anchor_of(a)
        if anc:
            anchors.append(anc)
            affected.add(ctx.vm_or_self(anc))
    matched_entities = sorted({m for i in inds for m, _ in g.in_edges(i, ("MATCHES_IOC",))})
    frag_nodes = [node_id] + campaigns + alerts + anchors + sorted(affected) + matched_entities + inds + cves
    affected_frag = g.fragment(frag_nodes, highlight_ids=set(alerts) | affected, focus=[node_id], layout_hint="neighborhood", max_nodes=150)
    return {
        "actor": g.node_out(actor) if actor else None,
        "campaign": g.node_out(node_id) if label == "Campaign" else None,
        "campaigns": [g.node_out(c) for c in campaigns],
        "malware": [g.node_out(m) for m in malware],
        "techniques": [g.node_out(t) for t in techniques],
        "indicators": [g.node_out(i) for i in inds],
        "reports": [g.node_out(r) for r in reports],
        "context": _context_for_ti_node(ctx, node_id),
        "matched_alert_ids": alerts,
        "affected_asset_ids": sorted(affected),
        "exploited_cve_ids": cves,
        "affected": affected_frag,
    }


def ti_reports(ctx: AnalyticsContext) -> list[NodeOut]:
    g = ctx.graph
    reports = sorted(g.nodes_by_label("IntelReport"), key=lambda r: (str(g.get(r, "published") or ""), r), reverse=True)
    return [g.node_out(r) for r in reports]


def ti_report(ctx: AnalyticsContext, report_id: str, summarize: Callable[[str], Any] | None = None) -> dict[str, Any]:
    g = ctx.graph
    if report_id not in g:
        raise KeyError(report_id)
    targets = [t for t, _ in g.out_edges(report_id, ("REPORTS_ON",))]
    by_label: dict[str, list[str]] = defaultdict(list)
    for t in targets:
        by_label[g.label_of(t) or "Unknown"].append(t)
    for key, prop in (("ThreatActor", "actor_ids"), ("Campaign", "campaign_ids")):
        for x in as_list(g.get(report_id, prop)):
            if x in g and x not in by_label[key]:
                by_label[key].append(x)
    for cid in as_list(g.get(report_id, "cve_ids")):
        node = cid if cid in g else f"cve:{cid}"
        if node in g and node not in by_label["Vulnerability"]:
            by_label["Vulnerability"].append(node)
    who = by_label["ThreatActor"] + by_label["Campaign"]
    alerts = matched_alerts_for(ctx, who)
    for ind in by_label["Indicator"]:
        for m, _ in g.in_edges(ind, ("MATCHES_IOC",)):
            if g.label_of(m) == "Alert" and m not in alerts:
                alerts.append(m)
    alerts.sort(key=lambda a: (-(int(g.get(a, "contextual_score") or 0)), a))
    exposed = set(exposed_assets(ctx))
    exposed_vuln = [a for a in assets_vulnerable_to(ctx, by_label["Vulnerability"]) if a in exposed]
    crown_touched: set[str] = set()
    for a in alerts:
        anc = ctx.anchor_of(a)
        if anc:
            crown_touched.update(ctx.reaches_crown_jewel(anc, 4, "access"))
        for s, _ in g.out_edges(a, ("IN_STORYLINE",)):
            crown_touched.update(c for c in as_list(g.get(s, "crown_jewels_reached")) if c in g)
    techs = {str(t) for a in alerts for t in as_list(g.get(a, "techniques"))}
    report_ttps = {str(t) for t in as_list(g.get(report_id, "technique_ids"))} | {str(g.get(t, "technique_id") or "") for t in by_label["AttackTechnique"]}
    for w in who:
        report_ttps |= campaign_techniques(ctx, w)
    overlap = sorted(techs & report_ttps)
    summary = (
        f"{len(alerts)} matched detection{'s' if len(alerts) != 1 else ''}, TTP overlap {len(overlap)} technique{'s' if len(overlap) != 1 else ''}, "
        f"{len(exposed_vuln)} internet-exposed asset{'s' if len(exposed_vuln) != 1 else ''} vulnerable to the reported CVEs"
        + (f"; touches {', '.join(ctx.short(c) for c in sorted(crown_touched)[:4])}" if crown_touched else "")
    )
    return {
        "report": g.node_out(report_id),
        "actors": [g.node_out(a) for a in by_label["ThreatActor"]],
        "campaigns": [g.node_out(c) for c in by_label["Campaign"]],
        "malware": [g.node_out(m) for m in by_label["Malware"]],
        "cves": [g.node_out(c) for c in by_label["Vulnerability"]],
        "indicators": [g.node_out(i) for i in by_label["Indicator"]],
        "techniques": [g.node_out(t) for t in by_label["AttackTechnique"]],
        "impact": {
            "matched_alerts": [summarize(a) for a in alerts] if summarize else [g.node_out(a) for a in alerts],
            "matched_alert_ids": alerts,
            "exposed_assets": [g.node_out(a) for a in exposed_vuln],
            "crown_jewels_touched": sorted(crown_touched),
            "ttp_overlap": overlap,
            "ttp_overlap_count": len(overlap),
            "summary": summary,
        },
    }


def ti_exposure(ctx: AnalyticsContext, sector_only: bool = True, score_asset: Callable[[str], int] | None = None,
                alert_score: Callable[[str], int] | None = None, min_relevance: float = 0.7) -> list[dict[str, Any]]:
    """Question 5: internet-exposed hosts carrying a vulnerability under active / mass exploitation."""
    g = ctx.graph
    rows: list[dict[str, Any]] = []
    for vm in exposed_assets(ctx):
        if g.label_of(vm) not in ("VirtualMachine", "Workload", "ServerlessFunction"):
            continue
        cands = []
        for cve, _ in g.out_edges(vm, ("VULNERABLE_TO",)):
            status = str(g.get(cve, "exploitation_status") or "none")
            if status not in sem.EXPLOITED_STATUSES:
                continue
            rel = relevance_of(ctx, cve)
            if sector_only and rel < min_relevance:
                continue
            cands.append((sem.EXPLOITATION_RANK.get(status, 0), rel, float(g.get(cve, "cvss") or 0), cve, status))
        if not cands:
            continue
        cands.sort(reverse=True)
        _, rel, _, cve, status = cands[0]
        actors = [a for a in as_list(g.get(cve, "actor_interest")) if a in g]
        campaigns = sorted({c for c, _ in g.in_edges(cve, ("EXPLOITS",)) if g.label_of(c) == "Campaign"})
        ep = ctx.endpoint_for(vm)
        alert_ids = sorted(set(ctx.alerts_on(vm)) | (set(ctx.alerts_on(ep)) if ep else set()))
        best_alert: tuple[int, str] | None = None
        if alert_score:
            scored = []
            for a in alert_ids:
                val = alert_score(a)
                if val is None:
                    continue
                tup = tuple(val) if isinstance(val, tuple | list) else (int(val), 0.0)
                scored.append((tup, a))
            if scored:
                best_tup, best_id = max(scored, key=lambda x: (x[0], x[1] < "alert:waf"))
                best_alert = (int(best_tup[0]), best_id)
        host_score = score_asset(vm) if score_asset else 0
        score = max(host_score, best_alert[0] if best_alert else 0)
        crown = ctx.reaches_crown_jewel(vm, 4, "access")
        rows.append({
            "vm": g.node_out(vm), "cve": g.node_out(cve), "cves": [g.node_out(c[3]) for c in cands],
            "exploitation_status": status, "actors": [g.node_out(a) for a in actors], "campaigns": [g.node_out(c) for c in campaigns],
            "sector_relevance": rel, "contextual_score": int(score), "score_source": (best_alert[1] if best_alert and best_alert[0] >= host_score else "asset"),
            "crown_jewels_reachable": [g.node_out(c) for c in crown], "has_edr_sensor": bool(g.get(vm, "has_edr_sensor")) or ep is not None,
            "alert_ids": alert_ids, "ti_exposure_score": float(g.get(vm, "ti_exposure_score") or exposure_score_of(ctx, vm)),
        })
    rows.sort(key=lambda r: (-r["contextual_score"], -r["ti_exposure_score"], -len(r["crown_jewels_reachable"]), r["vm"].id))
    return rows


def exposure_fragment(ctx: AnalyticsContext, rows: list[dict[str, Any]]) -> GraphFragment:
    g = ctx.graph
    ids: list[str] = [sem.INTERNET_ID] if sem.INTERNET_ID in g else []
    hl: set[str] = set()
    for r in rows:
        ids += [r["vm"].id, r["cve"].id] + [a.id for a in r["actors"]] + [c.id for c in r["campaigns"]] + [c.id for c in r["crown_jewels_reachable"]]
        hl.add(r["vm"].id)
    frag = g.fragment(ids, highlight_ids=hl, focus=[r["vm"].id for r in rows[:1]], layout_hint="neighborhood", max_nodes=150)
    for r in rows:
        eid = edge_id(sem.INTERNET_ID, "EXPOSES", r["vm"].id)
        for e in frag.edges:
            if e.id == eid:
                e.highlight = True
    return frag
