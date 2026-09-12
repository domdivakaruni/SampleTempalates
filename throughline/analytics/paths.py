"""Path finding and attack paths over the weighted semantic graph.

* :func:`find_paths` - k shortest simple paths between two nodes on the *undirected* semantic view (layout
  ``path``), so an analyst can ask "how are X and Y connected" without caring about edge direction.
* :func:`attack_paths` - ranked Internet (or alert) -> crown-jewel paths through a node (docs/02 section 4(b)):
  k-shortest simple paths (Yen) on the weighted DiGraph, likelihood = product of step probabilities, every node on
  the path labelled with a kill-chain stage and the techniques observed there.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any

import networkx as nx

from throughline.analytics import semantics as sem
from throughline.analytics.blast import _path_out
from throughline.analytics.context import AnalyticsContext, as_list, fmt_time
from throughline.graph.context_graph import edge_id
from throughline.models import AttackPathOut, GraphFragment, PathOut, StageOut

MAX_TOTAL_HOPS = 8
MAX_YEN_ITERATIONS = 40


# ---------------------------------------------------------------------- find_paths


def find_paths(ctx: AnalyticsContext, src_id: str, dst_id: str, max_hops: int = 6, k: int = 3,
               edge_types: Iterable[str] | None = None) -> GraphFragment:
    g = ctx.graph
    max_hops = max(1, min(int(max_hops), 8))
    k = max(1, min(int(k), 5))
    if src_id not in g or dst_id not in g:
        return GraphFragment(focus=[src_id, dst_id], layout_hint="path", meta={"error": "unknown node"})
    wanted = set(edge_types) if edge_types else None
    U = _undirected_view(ctx, wanted)
    paths: list[list[str]] = []
    if src_id in U and dst_id in U and src_id != dst_id:
        try:
            for i, p in enumerate(nx.shortest_simple_paths(U, src_id, dst_id, weight="weight")):
                if len(p) - 1 <= max_hops:
                    paths.append(p)
                if len(paths) >= k or i >= MAX_YEN_ITERATIONS:
                    break
        except nx.NetworkXNoPath:
            paths = []
    path_outs: list[PathOut] = []
    nodes: list[str] = [src_id, dst_id]
    hl_edges: set[str] = set()
    for p in paths:
        po = _path_out(ctx, p, label=f"{len(p) - 1} hops")
        po.likelihood = round(math.exp(-_path_weight(U, p)), 3)
        po.stages = [sem.stage_label(_stage_for_node(ctx, n, prev_edge(ctx, a, n))) for a, n in zip([None] + p[:-1], p, strict=False)]
        path_outs.append(po)
        hl_edges.update(po.edge_ids)
        for n in p:
            if n not in nodes:
                nodes.append(n)
    frag = g.fragment(nodes, highlight_ids=set(nodes) if paths else {src_id, dst_id}, highlight_edge_ids=hl_edges,
                      focus=[src_id, dst_id], layout_hint="path", paths=path_outs)
    frag.meta = {"paths": len(path_outs), "max_hops": max_hops}
    return frag


def prev_edge(ctx: AnalyticsContext, a: str | None, b: str) -> str | None:
    if a is None:
        return None
    D = ctx.digraph("full")
    if D.has_edge(a, b):
        return D[a][b].get("etype")
    if D.has_edge(b, a):
        return D[b][a].get("etype")
    return None


def _undirected_view(ctx: AnalyticsContext, wanted: set[str] | None) -> nx.Graph:
    D = ctx.digraph("full")
    U = nx.Graph()
    for u, v, d in D.edges(data=True):
        if wanted and d.get("etype") not in wanted:
            continue
        cur = U.get_edge_data(u, v)
        if cur is None or d["weight"] < cur["weight"]:
            U.add_edge(u, v, weight=d["weight"], etype=d.get("etype"))
    if wanted:
        # also allow raw edges of the requested types that carry no attack semantics (e.g. CONTAINS)
        for u, v, d in ctx.graph.G.edges(data=True):
            if d.get("type") in wanted and not U.has_edge(u, v):
                U.add_edge(u, v, weight=1.0, etype=d.get("type"))
    return U


def _path_weight(G: nx.Graph, path: list[str]) -> float:
    total = 0.0
    for a, b in zip(path, path[1:], strict=False):
        d = G.get_edge_data(a, b) or {}
        total += float(d.get("weight", 1.0))
    return total


# ---------------------------------------------------------------------- attack paths


def attack_paths(ctx: AnalyticsContext, through_id: str | None = None, target_id: str | None = None,
                 entry_id: str | None = None, k: int = 5, storyline_scope: str | None = None) -> list[AttackPathOut]:
    g = ctx.graph
    k = max(1, min(int(k), 5))
    D = ctx.digraph("full")
    targets = [target_id] if target_id else list(ctx.crown_jewels)
    targets = [t for t in targets if t in D]
    if not targets:
        return []
    results: list[AttackPathOut] = []
    if through_id and through_id in g:
        if g.label_of(through_id) == "Alert":
            entry = through_id
            results = _paths_from(ctx, D, entry, targets, k, through=through_id, storyline_scope=storyline_scope)
        else:
            entry = entry_id or sem.INTERNET_ID
            results = _paths_through(ctx, D, entry, through_id, targets, k, storyline_scope)
    else:
        entry = entry_id or sem.INTERNET_ID
        if entry not in D:
            return []
        results = _paths_from(ctx, D, entry, targets, k, through=None, storyline_scope=storyline_scope)
    results.sort(key=lambda r: (-r.likelihood * _impact(ctx, r.target_id), r.hops, r.target_id, r.id))
    return results[:k]


def _impact(ctx: AnalyticsContext, target_id: str) -> float:
    a = ctx.graph.node(target_id) or {}
    classes = set(sem.data_classes(a))
    if classes & {"PCI", "PHI"}:
        return 1.0
    if "PII" in classes:
        return 0.95
    if a.get("is_admin"):
        return 0.9
    if "SECRETS" in classes or a.get("label") == "Secret":
        return 0.85
    return 0.8


def _nearest_targets(D: nx.DiGraph, source: str, targets: list[str], limit: int) -> list[str]:
    try:
        dist = nx.single_source_dijkstra_path_length(D, source, weight="weight")
    except nx.NetworkXError:
        return []
    reachable = [(dist[t], t) for t in targets if t in dist and t != source]
    reachable.sort()
    return [t for _, t in reachable[:limit]]


def _yen(D: nx.DiGraph, src: str, dst: str, k: int, max_hops: int) -> list[list[str]]:
    out: list[list[str]] = []
    if src == dst or src not in D or dst not in D:
        return out
    try:
        for i, p in enumerate(nx.shortest_simple_paths(D, src, dst, weight="weight")):
            if len(p) - 1 <= max_hops:
                out.append(p)
            if len(out) >= k or i >= MAX_YEN_ITERATIONS:
                break
    except nx.NetworkXNoPath:
        return out
    return out


def _paths_from(ctx: AnalyticsContext, D: nx.DiGraph, entry: str, targets: list[str], k: int, through: str | None,
                storyline_scope: str | None) -> list[AttackPathOut]:
    out: list[AttackPathOut] = []
    for t in _nearest_targets(D, entry, targets, limit=max(k * 2, 6)):
        for p in _yen(D, entry, t, k, MAX_TOTAL_HOPS):
            out.append(_build(ctx, D, p, entry, t, through, storyline_scope))
    return out


def _paths_through(ctx: AnalyticsContext, D: nx.DiGraph, entry: str, through: str, targets: list[str], k: int,
                   storyline_scope: str | None) -> list[AttackPathOut]:
    out: list[AttackPathOut] = []
    heads = _yen(D, entry, through, k, MAX_TOTAL_HOPS) if entry in D and entry != through else []
    if not heads:
        heads = [[through]]  # the node itself is the compromised entry
        entry = through
    for t in _nearest_targets(D, through, targets, limit=max(k * 2, 6)):
        tails = _yen(D, through, t, k, MAX_TOTAL_HOPS)
        seen: set[tuple[str, ...]] = set()
        for h in heads:
            for tail in tails:
                joined = h + tail[1:]
                if len(joined) - 1 > MAX_TOTAL_HOPS or len(set(joined)) != len(joined):
                    continue
                key = tuple(joined)
                if key in seen:
                    continue
                seen.add(key)
                out.append(_build(ctx, D, joined, entry, t, through, storyline_scope))
    return out


def _build(ctx: AnalyticsContext, D: nx.DiGraph, path: list[str], entry: str, target: str, through: str | None,
           storyline_scope: str | None) -> AttackPathOut:
    g = ctx.graph
    likelihood = 1.0
    for a, b in zip(path, path[1:], strict=False):
        likelihood *= float(D[a][b]["p"]) if D.has_edge(a, b) else 0.5
    stages = build_stages(ctx, path, storyline_scope)
    hops = len(path) - 1
    po = _path_out(ctx, path, label=f"{ctx.short(entry)} -> {ctx.short(target)}", likelihood=round(likelihood, 4), stages=[s.stage for s in stages])
    edge_ids = set(po.edge_ids)
    for s, eid_list in zip(stages, [[]] + [[e] for e in po.edge_ids], strict=False):
        s.edge_ids = list(eid_list)
    extra_nodes: list[str] = []
    for s in stages:
        extra_nodes.extend(a for a in s.alert_ids if a not in path)
    frag = g.fragment(path + extra_nodes, highlight_ids=set(path), highlight_edge_ids=edge_ids, focus=[entry, target],
                      layout_hint="path", paths=[po])
    frag.meta = {"likelihood": round(likelihood, 4), "hops": hops}
    pid = "attackpath:" + ":".join(n.rsplit(":", 1)[-1] for n in (entry, target)) + f":{hops}:{abs(hash(tuple(path))) % 100000:05d}"
    summary = _summary(ctx, path, stages, likelihood, target)
    return AttackPathOut(id=pid, entry_id=entry, target_id=target, through_id=through, likelihood=round(likelihood, 4),
                         hops=hops, stages=stages, summary=summary, fragment=frag)


# ---------------------------------------------------------------------- stages


def storyline_members_on(ctx: AnalyticsContext, node_id: str, storyline_id: str | None) -> tuple[list[str], list[str]]:
    """Alerts and cloud events attached to a node (optionally restricted to one storyline)."""
    g = ctx.graph
    alerts: list[str] = []
    events: list[str] = []
    label = g.label_of(node_id)
    if label == "Alert":
        return [node_id], []
    for a in ctx.alerts_on(node_id):
        alerts.append(a)
    if label in ("IamRole", "IamUser"):
        # AssumeRole events belong to the role that was assumed, not to the performer
        for ev, _ in g.in_edges(node_id, ("PERFORMED_BY",)):
            if not g.out_edges(ev, ("ASSUMED",)):
                events.append(ev)
        for ev, _ in g.in_edges(node_id, ("ASSUMED",)):
            events.append(ev)
    if label in sem.DATA_HOLDER_LABELS:
        for ev, _ in g.in_edges(node_id, ("TARGETED",)):
            events.append(ev)
    if label == "Credential":
        for ev, _ in g.in_edges(node_id, ("USED_CREDENTIAL",)):
            events.append(ev)
        for a, _ in g.out_edges(node_id, ("STOLEN_BY",)):
            if g.label_of(a) == "Alert":
                alerts.append(a)
    if storyline_id:
        def in_story(n: str) -> bool:
            return any(s == storyline_id for s, _ in g.out_edges(n, ("IN_STORYLINE",))) or g.get(n, "storyline_id") == storyline_id

        alerts = [a for a in alerts if in_story(a)]
        events = [e for e in events if in_story(e)]
    return list(dict.fromkeys(alerts)), list(dict.fromkeys(events))


def _step_edge(g: Any, a: str, b: str, etype: str | None) -> dict[str, Any]:
    """Raw edge data for a path step. Parallel LATERAL_MOVEMENT_TO edges between the same hosts (a routine logon
    and the anomalous session) are disambiguated by preferring the edge tied to a lateral-movement detection."""
    cands = [d for d in g.edges_between(a, b) if etype is None or d.get("type") == etype]
    cands += [d for d in g.edges_between(b, a) if etype is None or d.get("type") == etype]
    if not cands:
        return g.first_edge(a, b) or g.first_edge(b, a) or {}
    if etype == "LATERAL_MOVEMENT_TO" and len(cands) > 1:
        def rank(d: dict[str, Any]) -> tuple[bool, bool, str]:
            aid = d.get("alert_id")
            techs = [str(t) for t in as_list(g.get(aid, "techniques"))] if aid and aid in g else []
            lateral = any(t.startswith(("T1021", "T1550")) for t in techs)
            return (not lateral, not bool(aid), str(d.get("time") or ""))

        cands.sort(key=rank)
    return cands[0]


def build_stages(ctx: AnalyticsContext, path: list[str], storyline_id: str | None = None) -> list[StageOut]:
    g = ctx.graph
    D = ctx.digraph("full")
    stages: list[StageOut] = []
    seen_alerts: set[str] = set()
    prev: str | None = None
    for i, nid in enumerate(path):
        etype = None
        edata: dict[str, Any] = {}
        if prev is not None:
            if D.has_edge(prev, nid):
                etype = D[prev][nid].get("etype")
            elif D.has_edge(nid, prev):
                etype = D[nid][prev].get("etype")
            edata = _step_edge(g, prev, nid, etype)
        alerts, events = storyline_members_on(ctx, nid, storyline_id)
        alerts = [a for a in alerts if a not in seen_alerts]
        seen_alerts.update(alerts)
        techniques: list[str] = []
        times: list[str] = []
        for a in alerts:
            techniques.extend(as_list(g.get(a, "techniques")))
            t = g.get(a, "detected_at")
            if t:
                times.append(str(t))
        for ev in events:
            techniques.extend(sem.event_techniques(g.node(ev)))
            t = g.get(ev, "event_time")
            if t:
                times.append(str(t))
        if etype == "LATERAL_MOVEMENT_TO":
            proto = str(edata.get("protocol") or "").lower()
            tech = sem.LATERAL_TECHNIQUES.get(proto)
            if tech:
                techniques.insert(0, tech)
            if edata.get("time"):
                times.append(str(edata["time"]))
            if edata.get("alert_id") and edata["alert_id"] in g and edata["alert_id"] not in seen_alerts:
                alerts.append(str(edata["alert_id"]))
                seen_alerts.add(str(edata["alert_id"]))
        elif etype == "EXPOSES":
            techniques.insert(0, "T1190" if ctx.sem.asset_exploitable(nid) else "T1133")
        techniques = list(dict.fromkeys(techniques))
        prev_stage = stages[-1].stage if stages else None
        stage_no = _stage_for_node(ctx, nid, etype, techniques, alerts, i == 0, events=events, prev_stage=prev_stage)
        stages.append(StageOut(
            order=i + 1, stage=sem.stage_label(stage_no), technique_ids=techniques, node_ids=[nid], edge_ids=[],
            alert_ids=alerts + events, time=min(times) if times else None, summary=_stage_summary(ctx, nid, etype, alerts, events, edata),
        ))
        prev = nid
    # A hop with no telemetry of its own (for example the VM an endpoint resolves to) inherits the time of the
    # stage that led to it, so the timeline never shows a gap in the middle of the chain.
    for idx in range(1, len(stages)):
        if stages[idx].time is None:
            stages[idx].time = stages[idx - 1].time
    return stages


def _stage_for_node(ctx: AnalyticsContext, nid: str, etype: str | None, techniques: list[str] | None = None,
                    alerts: list[str] | None = None, first: bool = False, events: list[str] | None = None,
                    prev_stage: str | None = None) -> int:
    """Kill-chain stage of a path node, driven by how the attacker got there (the transition), then by what was
    observed there (alerts on an anchor host, cloud events on a role or data store)."""
    g = ctx.graph
    label = g.label_of(nid)
    if label == "Alert":
        return sem.alert_stage(g.node(nid)) or 1
    if nid == sem.INTERNET_ID or etype == "EXPOSES":
        return 1
    if etype == "LATERAL_MOVEMENT_TO":
        return 5
    if etype in ("CAN_ASSUME", "MAPS_TO", "DERIVED_FROM"):
        return 5
    if label in sem.DATA_HOLDER_LABELS:
        covered: set[int] = set()
        for e in events or []:
            covered |= sem.stages_covered(sem.event_techniques(g.node(e)))
        return max(covered) if covered else 6
    if etype in ("HAS_ROLE", "CREDENTIAL_FOR", "HAS_ACCESS_KEY") or label in ("IamRole", "IamUser", "Credential", "AccessKey"):
        covered: set[int] = set()
        for e in events or []:
            covered |= sem.stages_covered(sem.event_techniques(g.node(e)))
        return max(covered) if covered else 4
    real_alerts = [a for a in (alerts or []) if g.label_of(a) == "Alert"]
    if real_alerts:
        # the stage the attacker had reached when leaving this host: its latest alert
        latest = max(real_alerts, key=lambda a: (str(g.get(a, "detected_at") or ""), a))
        st = sem.alert_stage(g.node(latest))
        if st:
            return st
    if etype == "SAME_AS" and prev_stage:
        for number, name in sem.KILL_CHAIN_STAGES.items():
            if name == prev_stage:
                return number
    if techniques:
        covered = sem.stages_covered(techniques)
        if covered:
            return max(covered)
    if etype:
        return sem.stage_for_edge(etype)
    return 1 if first else 2


def _stage_summary(ctx: AnalyticsContext, nid: str, etype: str | None, alerts: list[str], events: list[str], edata: dict[str, Any]) -> str:
    g = ctx.graph
    label = g.label_of(nid) or "node"
    name = ctx.short(nid)
    if label == "Alert":
        return f"{g.get(nid, 'vendor_severity') or ''} {g.get(nid, 'source_system') or ''} alert: {g.get(nid, 'title') or name}".strip()
    head = f"{label} {name}"
    if etype == "LATERAL_MOVEMENT_TO":
        head = f"lateral movement to {name} over {edata.get('protocol') or 'network'} as {edata.get('account') or 'unknown account'}"
    elif etype == "SAME_AS":
        head = f"{name} is cloud instance {g.get(nid, 'source_id') or name}" if label == "VirtualMachine" else f"{name} is the endpoint of the VM"
    elif etype == "HAS_ROLE":
        head = f"instance role {name}"
    elif etype == "CAN_ASSUME":
        head = f"assumes role {name}" + (" (cross-account)" if edata.get("cross_account") else "")
    elif etype == "CAN_ACCESS":
        head = f"{edata.get('access_level') or 'read'} access to {name}"
    elif etype == "UNLOCKS":
        head = f"credentials unlock {name}"
    elif etype == "EXPOSES":
        head = f"{name} is internet-exposed"
    elif etype == "ON_ENDPOINT" or etype == "ON_RESOURCE":
        head = f"alert anchored on {name}"
    tail = []
    if alerts:
        tail.append(f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''}")
    if events:
        names = ", ".join(dict.fromkeys(str(g.get(e, 'event_name') or e) for e in events[:3]))
        tail.append(f"{len(events)} cloud event{'s' if len(events) != 1 else ''} ({names})")
    return head + (f" - {'; '.join(tail)}" if tail else "")


def _summary(ctx: AnalyticsContext, path: list[str], stages: list[StageOut], likelihood: float, target: str) -> str:
    g = ctx.graph
    names = " -> ".join(ctx.short(n) for n in path)
    classes = "/".join(sem.data_classes(g.node(target))) or (g.label_of(target) or "target")
    return f"{len(stages)} stages, {len(path) - 1} hops, likelihood {likelihood:.2f} to {ctx.short(target)} ({classes}): {names}"


def stage_edge_ids(path: list[str], etypes: list[str]) -> list[str]:
    return [edge_id(a, t, b) for (a, b), t in zip(zip(path, path[1:], strict=False), etypes, strict=False)]


def stage_time(ctx: AnalyticsContext, node_id: str) -> str | None:
    return fmt_time(ctx.member_time(node_id))
