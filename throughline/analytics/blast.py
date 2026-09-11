"""Blast radius: best-first reachability (Dijkstra on -ln p) from a compromised node.

Depth counts attacker *moves* (docs/02 section 4(a)); entity-resolution edges (alert -> anchor, endpoint -> VM)
are free. Reached nodes are grouped into crown jewels, data stores, secrets and identities, each with the best
path from the root, a reach score ``p * 0.85^hops`` and, for data stores, the access level of the final step.
"""
from __future__ import annotations

from throughline.analytics import semantics as sem
from throughline.analytics.context import AnalyticsContext, Reach
from throughline.graph.context_graph import edge_id
from throughline.models import BlastRadiusResult, GraphFragment, PathOut, ReachedNode

DECAY = 0.85
FRAGMENT_CAP = 150


def blast_radius(ctx: AnalyticsContext, root_id: str, depth: int = 4, max_nodes: int = 500, mode: str = "full",
                 fragment_cap: int = FRAGMENT_CAP) -> BlastRadiusResult:
    g = ctx.graph
    depth = max(0, min(int(depth), 6))
    max_nodes = max(1, min(int(max_nodes), 2000))
    if root_id not in g:
        return BlastRadiusResult(root_id=root_id, depth=depth, reached_count=0, summary="unknown node",
                                 fragment=GraphFragment(focus=[root_id], layout_hint="blast_radius"))
    reach = ctx.reach(root_id, depth, mode, max_nodes)
    return build_result(ctx, reach, fragment_cap=fragment_cap)


def build_result(ctx: AnalyticsContext, reach: Reach, fragment_cap: int = FRAGMENT_CAP) -> BlastRadiusResult:
    g = ctx.graph
    root_id = reach.root
    crown: list[ReachedNode] = []
    data: list[ReachedNode] = []
    secrets: list[ReachedNode] = []
    identities: list[ReachedNode] = []
    accounts: set[str] = set()
    by_hop: dict[int, int] = {}
    for nid in reach.ids():
        info = reach.nodes[nid]
        attrs = g.node(nid) or {}
        by_hop[info.hops] = by_hop.get(info.hops, 0) + 1
        acct = attrs.get("account_id")
        if acct and attrs.get("label") not in ("Alert", "CloudEvent"):
            accounts.add(str(acct))
        rn = ReachedNode(
            node=g.node_out(nid, highlight=sem.is_crown_jewel(attrs)),
            hops=info.hops,
            reach_score=round(info.probability * (DECAY ** info.depth), 4),
            via_path=list(info.path),
            access_level=info.access_level,
        )
        label = attrs.get("label")
        if sem.is_crown_jewel(attrs):
            crown.append(rn)
        if label in ("StorageBucket", "Database"):
            data.append(rn)
        elif label == "Secret":
            secrets.append(rn)
        elif label in sem.IDENTITY_LABELS:
            identities.append(rn)

    def order(items: list[ReachedNode]) -> list[ReachedNode]:
        return sorted(items, key=lambda r: (-r.reach_score, r.hops, r.node.id))

    crown, data, secrets, identities = order(crown), order(data), order(secrets), order(identities)
    fragment = _fragment(ctx, reach, crown, secrets, data, identities, fragment_cap)
    summary = _summary(ctx, root_id, reach, crown, data, secrets, identities, accounts)
    return BlastRadiusResult(
        root_id=root_id, depth=reach.depth, reached_count=len(reach.ids()), crown_jewels=crown, data_stores=data,
        secrets=secrets, identities=identities, accounts_touched=sorted(accounts), by_hop=dict(sorted(by_hop.items())),
        summary=summary, fragment=fragment,
    )


def _fragment(ctx: AnalyticsContext, reach: Reach, crown, secrets, data, identities, cap: int) -> GraphFragment:
    g = ctx.graph
    ordered: list[str] = [reach.root]
    paths: list[PathOut] = []
    highlight: set[str] = {reach.root}
    highlight_edges: set[str] = set()
    priority = [r.node.id for r in crown] + [r.node.id for r in secrets] + [r.node.id for r in data] + [r.node.id for r in identities]
    for nid in priority:
        for p in reach.nodes[nid].path:
            if p not in ordered:
                ordered.append(p)
    for nid in sorted(reach.ids(), key=lambda n: (reach.nodes[n].cost, n)):
        if nid not in ordered:
            ordered.append(nid)
    for r in crown:
        path = reach.nodes[r.node.id].path
        po = _path_out(ctx, path, label=f"to {ctx.short(r.node.id)}", likelihood=round(reach.nodes[r.node.id].probability, 3))
        paths.append(po)
        highlight.update(path)
        highlight_edges.update(po.edge_ids)
    truncated = len(ordered) > cap
    frag = g.fragment(ordered[:cap], highlight_ids=highlight, highlight_edge_ids=highlight_edges, focus=[reach.root],
                      layout_hint="blast_radius", max_nodes=cap, paths=paths)
    frag.truncated = frag.truncated or truncated or reach.truncated
    frag.total_nodes = len(ordered)
    frag.meta = {"reached": len(reach.ids()), "depth": reach.depth, "mode": reach.mode}
    return frag


def _path_out(ctx: AnalyticsContext, path: list[str], label: str | None = None, likelihood: float | None = None, stages: list[str] | None = None) -> PathOut:
    """A PathOut whose edge ids follow the *semantic* move between consecutive nodes (either raw direction)."""
    g = ctx.graph
    eids: list[str] = []
    for a, b in zip(path, path[1:], strict=False):
        d = g.first_edge(a, b)
        if d is not None:
            eids.append(edge_id(a, d["type"], b))
            continue
        d = g.first_edge(b, a)
        if d is not None:
            eids.append(edge_id(b, d["type"], a))
            continue
        attrs = g.node(a) or {}
        implicit = list(attrs.get("contains_credentials_for") or []) + list(attrs.get("grants_access_to") or [])
        if b in implicit:
            eids.append(edge_id(a, "UNLOCKS", b))  # implicit credential move (contains_credentials_for / grants_access_to)
        # any other gap is a multi-edge hop (e.g. alert -> process -> file); it carries no single edge id
    return PathOut(node_ids=list(path), edge_ids=eids, hops=max(len(path) - 1, 0), label=label, likelihood=likelihood, stages=stages or [])


def _summary(ctx: AnalyticsContext, root_id: str, reach: Reach, crown, data, secrets, identities, accounts: set[str]) -> str:
    g = ctx.graph
    root_name = ctx.short(root_id)
    label = g.label_of(root_id) or "node"
    parts = [f"From {label} {root_name}: {len(reach.ids())} nodes reachable within {reach.depth} moves"]
    if crown:
        names = ", ".join(f"{ctx.short(r.node.id)} ({'/'.join(sem.data_classes(g.node(r.node.id))) or r.node.label})" for r in crown[:5])
        parts.append(f"{len(crown)} crown jewel{'s' if len(crown) != 1 else ''}: {names}")
    if secrets:
        parts.append(f"{len(secrets)} secret{'s' if len(secrets) != 1 else ''}: " + ", ".join(ctx.short(r.node.id) for r in secrets[:4]))
    other_data = [r for r in data if not sem.is_crown_jewel(g.node(r.node.id))]
    if other_data:
        parts.append(f"{len(other_data)} other data store{'s' if len(other_data) != 1 else ''}: " + ", ".join(ctx.short(r.node.id) for r in other_data[:4]))
    if identities:
        parts.append(f"{len(identities)} identit{'ies' if len(identities) != 1 else 'y'}: " + ", ".join(ctx.short(r.node.id) for r in identities[:4]))
    if accounts:
        parts.append(f"accounts touched: {', '.join(sorted(accounts))}")
    if reach.truncated:
        parts.append("(node budget reached; result truncated)")
    return "; ".join(parts) + "."
