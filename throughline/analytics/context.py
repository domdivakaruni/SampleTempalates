"""Shared analytics workspace: indexes and caches over a ContextGraph.

Both the build-time enrichment (``materialize.enrich``) and the request-time ``AnalyticsEngine`` work through an
``AnalyticsContext`` so that expensive structures (alerts by anchor, SAME_AS maps, blast radii, the weighted
semantic DiGraph) are built once and shared. Everything here is derived from the graph and can be rebuilt with
:meth:`AnalyticsContext.invalidate` after the graph is mutated.
"""
from __future__ import annotations

import heapq
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import networkx as nx

from throughline.analytics import semantics as sem
from throughline.analytics.semantics import Move, Semantics
from throughline.config import settings
from throughline.graph.context_graph import ContextGraph

# ---------------------------------------------------------------------- time helpers

_TS_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%MZ")


def parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def fmt_time(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


NOW: datetime = parse_time(settings.sim_now) or datetime(2026, 9, 11, 14, 0, tzinfo=UTC)


def hours_between(a: datetime | None, b: datetime | None) -> float | None:
    if a is None or b is None:
        return None
    return abs((a - b).total_seconds()) / 3600.0


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list | tuple | set):
        return list(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
        except (ValueError, TypeError):
            pass
        return [value]
    return [value]


def as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            pass
    return {}


# ---------------------------------------------------------------------- reachability results


@dataclass
class Reached:
    node_id: str
    cost: float
    depth: int  # semantic depth (moves that consumed budget)
    hops: int  # raw edge count on the best path
    path: list[str]
    access_level: str | None = None

    @property
    def probability(self) -> float:
        import math

        return math.exp(-self.cost)


@dataclass
class Reach:
    root: str
    depth: int
    mode: str
    nodes: dict[str, Reached] = field(default_factory=dict)
    truncated: bool = False

    def ids(self) -> list[str]:
        return [n for n in self.nodes if n != self.root]

    def contains(self, node_id: str) -> bool:
        return node_id in self.nodes and node_id != self.root


# ---------------------------------------------------------------------- the context


class AnalyticsContext:
    def __init__(self, graph: ContextGraph) -> None:
        self.graph = graph
        self.sem = Semantics(graph)
        self._reach_cache: dict[tuple[str, int, str, int], Reach] = {}
        self._digraphs: dict[str, nx.DiGraph] = {}
        self._built = False

    # ------------------------------------------------------------------ lifecycle

    def invalidate(self) -> None:
        self.sem = Semantics(self.graph)
        self._reach_cache.clear()
        self._digraphs.clear()
        self._built = False

    def _ensure(self) -> None:
        if self._built:
            return
        g = self.graph
        self.alerts: list[str] = list(g.nodes_by_label("Alert"))
        self.cloud_events: list[str] = list(g.nodes_by_label("CloudEvent"))
        self.vm_of_endpoint: dict[str, str] = {}
        self.endpoint_of_vm: dict[str, str] = {}
        for ep in g.nodes_by_label("Endpoint"):
            best: tuple[float, str] | None = None
            for vm, d in g.out_edges(ep, ("SAME_AS",)):
                conf = float(d.get("confidence") or 1.0)
                if best is None or conf > best[0]:
                    best = (conf, vm)
            if best:
                self.vm_of_endpoint[ep] = best[1]
                self.endpoint_of_vm.setdefault(best[1], ep)
        self.endpoints_by_ip: dict[str, list[str]] = defaultdict(list)
        for ep in g.nodes_by_label("Endpoint"):
            ip = g.get(ep, "private_ip")
            if ip:
                self.endpoints_by_ip[str(ip)].append(ep)
        self.vms_by_ip: dict[str, list[str]] = defaultdict(list)
        for vm in g.nodes_by_label("VirtualMachine"):
            ip = g.get(vm, "private_ip")
            if ip:
                self.vms_by_ip[str(ip)].append(vm)
        self.scanner_ips: set[str] = set()
        self.scanner_hosts: set[str] = set()
        for vm in g.nodes_by_label("VirtualMachine"):
            tags = as_dict(g.get(vm, "tags"))
            name = str(g.get(vm, "name") or "")
            role_tag = str(tags.get("role") or "").lower()
            if "scanner" in role_tag or "vulnscan" in name.lower():
                self.scanner_hosts.add(vm)
                ip = g.get(vm, "private_ip")
                if ip:
                    self.scanner_ips.add(str(ip))
                ep = self.endpoint_of_vm.get(vm)
                if ep:
                    self.scanner_hosts.add(ep)
        self.vpn_ips: set[str] = set()
        self.nat_ips: set[str] = set()
        for ip in g.nodes_by_label("IpAddress"):
            a = g.node(ip) or {}
            text = " ".join(str(a.get(k) or "") for k in ("name", "asn_org", "description", "role")).lower()
            addr = str(a.get("address") or "")
            if a.get("is_vpn") or a.get("vpn_egress") or "vpn" in text:
                self.vpn_ips.add(addr)
            if a.get("is_nat") or "nat" in text.split():
                self.nat_ips.add(addr)
        try:
            from throughline.simulator import storyline_constants as sc

            self.vpn_ips.add(sc.VPN_EGRESS_IP)
            self.scanner_ips.add(sc.SCANNER_IP)
        except Exception:  # pragma: no cover - constants are part of the package
            pass
        self.anchor: dict[str, str | None] = {}
        self.alerts_by_anchor: dict[str, list[str]] = defaultdict(list)
        self.alert_time_cache: dict[str, datetime | None] = {}
        for a in self.alerts:
            anc = self._compute_anchor(a)
            self.anchor[a] = anc
            if anc:
                self.alerts_by_anchor[anc].append(a)
                # alerts on an endpoint are also alerts on its VM and vice versa
                twin = self.vm_of_endpoint.get(anc) or self.endpoint_of_vm.get(anc)
                if twin:
                    self.alerts_by_anchor[twin].append(a)
            self.alert_time_cache[a] = parse_time(g.get(a, "detected_at"))
        for lst in self.alerts_by_anchor.values():
            lst.sort(key=lambda x: (self.alert_time_cache.get(x) or NOW, x))
        self.crown_jewels: list[str] = sorted(
            n for n, attrs in g.G.nodes(data=True) if sem.is_crown_jewel(attrs)
        )
        self.alert_links: dict[str, int] = defaultdict(int)
        for a in self.alerts:
            for v, _ in g.out_edges(a):
                self.alert_links[v] += 1
        self._built = True

    def _compute_anchor(self, alert_id: str) -> str | None:
        g = self.graph
        for v, _ in g.out_edges(alert_id, ("ON_ENDPOINT",)):
            return v
        for v, _ in g.out_edges(alert_id, ("ON_RESOURCE",)):
            return v
        ent = g.get(alert_id, "entity_id")
        if ent and ent in g:
            return str(ent)
        return None

    # ------------------------------------------------------------------ accessors

    def anchor_of(self, alert_id: str) -> str | None:
        self._ensure()
        return self.anchor.get(alert_id)

    def alerts_on(self, node_id: str) -> list[str]:
        self._ensure()
        return list(self.alerts_by_anchor.get(node_id, []))

    def alert_time(self, alert_id: str) -> datetime | None:
        self._ensure()
        if alert_id in self.alert_time_cache:
            return self.alert_time_cache[alert_id]
        t = parse_time(self.graph.get(alert_id, "detected_at"))
        self.alert_time_cache[alert_id] = t
        return t

    def event_time(self, event_id: str) -> datetime | None:
        return parse_time(self.graph.get(event_id, "event_time"))

    def member_time(self, node_id: str) -> datetime | None:
        label = self.graph.label_of(node_id)
        if label == "Alert":
            return self.alert_time(node_id)
        if label == "CloudEvent":
            return self.event_time(node_id)
        return None

    def is_hub(self, node_id: str) -> bool:
        self._ensure()
        if node_id == sem.INTERNET_ID:
            return True
        attrs = self.graph.node(node_id) or {}
        if attrs.get("label") == "IpAddress":
            addr = str(attrs.get("address") or "")
            if addr in self.scanner_ips or addr in self.vpn_ips or addr in self.nat_ips:
                return True
        if node_id in self.scanner_hosts:
            return True
        if attrs.get("hub") is True:
            return True
        return self.alert_links.get(node_id, 0) > 200

    def vm_or_self(self, node_id: str) -> str:
        """Canonical asset for an endpoint (its VM when resolved) or the node itself."""
        self._ensure()
        return self.vm_of_endpoint.get(node_id, node_id)

    def endpoint_for(self, node_id: str) -> str | None:
        self._ensure()
        if self.graph.label_of(node_id) == "Endpoint":
            return node_id
        return self.endpoint_of_vm.get(node_id)

    def asset_of(self, alert_id: str) -> str | None:
        """The cloud asset the alert sits on (VM for endpoint alerts), else the anchor."""
        anc = self.anchor_of(alert_id)
        return self.vm_or_self(anc) if anc else None

    def alert_involves(self, alert_id: str, labels: set[str] | None = None) -> list[str]:
        out = []
        for v, _ in self.graph.out_edges(alert_id, ("INVOLVES",)):
            if labels is None or self.graph.label_of(v) in labels:
                out.append(v)
        return out

    def recent_alert_on(self, node_id: str, before: datetime, hours: float) -> str | None:
        """Most recent alert on the node (or its SAME_AS twin) within ``hours`` before ``before``."""
        best: tuple[datetime, str] | None = None
        for a in self.alerts_on(node_id):
            t = self.alert_time(a)
            if t is None or t > before:
                continue
            if (before - t) <= timedelta(hours=hours) and (best is None or t > best[0]):
                best = (t, a)
        return best[1] if best else None

    # ------------------------------------------------------------------ reachability

    def reach(self, root: str, depth: int = 4, mode: str = "full", max_nodes: int = 500) -> Reach:
        """Best-first (Dijkstra on -ln p) reachability from ``root`` with depth and node budgets."""
        key = (root, depth, mode, max_nodes)
        cached = self._reach_cache.get(key)
        if cached is not None:
            return cached
        result = Reach(root, depth, mode)
        if root not in self.graph:
            self._reach_cache[key] = result
            return result
        result.nodes[root] = Reached(root, 0.0, 0, 0, [root])
        heap: list[tuple[float, int, str]] = [(0.0, 0, root)]
        settled: set[str] = set()
        counter = 0
        while heap:
            cost, _, u = heapq.heappop(heap)
            if u in settled:
                continue
            settled.add(u)
            ru = result.nodes[u]
            if ru.depth >= depth and depth >= 0:
                # can still take zero-cost (resolution) moves
                candidates = [m for m in self.sem.moves(u, mode) if m.depth_cost == 0]
            else:
                candidates = self.sem.moves(u, mode)
            for m in candidates:
                if m.dst == root:
                    continue
                nd = ru.depth + m.depth_cost
                if nd > depth:
                    continue
                ncost = cost + m.cost
                cur = result.nodes.get(m.dst)
                if cur is not None and (cur.cost < ncost or (cur.cost == ncost and cur.depth <= nd)):
                    continue
                if cur is None and len(result.nodes) > max_nodes:
                    result.truncated = True
                    continue
                access_level = None
                if m.etype == "CAN_ACCESS":
                    access_level = str((m.data or {}).get("access_level") or "read")
                elif m.etype == "UNLOCKS":
                    access_level = "credential"
                else:
                    access_level = ru.access_level if ru.access_level and m.depth_cost == 0 else None
                result.nodes[m.dst] = Reached(m.dst, ncost, nd, ru.hops + 1, ru.path + [m.dst], access_level)
                counter += 1
                heapq.heappush(heap, (ncost, counter, m.dst))
        self._reach_cache[key] = result
        return result

    def reaches_crown_jewel(self, root: str, depth: int = 4, mode: str = "access") -> list[str]:
        r = self.reach(root, depth, mode)
        return sorted(n for n in r.ids() if sem.is_crown_jewel(self.graph.node(n)))

    # ------------------------------------------------------------------ weighted digraph view

    def digraph(self, mode: str = "full") -> nx.DiGraph:
        """Weighted DiGraph of semantic moves (weight = -ln p); best move kept per (src, dst)."""
        cached = self._digraphs.get(mode)
        if cached is not None:
            return cached
        D = nx.DiGraph()
        g = self.graph
        for u, v, d in g.G.edges(data=True):
            for m in self.sem.moves_for_edge(u, v, d):
                if mode == "access" and not m.access:
                    continue
                self._add_move(D, m)
        for nid, attrs in g.G.nodes(data=True):
            if attrs.get("label") in ("StorageBucket", "Secret"):
                for m in self.sem.implicit_moves(nid):
                    self._add_move(D, m)
        # the Internet node is never a destination
        for u in list(D.predecessors(sem.INTERNET_ID)) if sem.INTERNET_ID in D else []:
            D.remove_edge(u, sem.INTERNET_ID)
        self._digraphs[mode] = D
        return D

    @staticmethod
    def _add_move(D: nx.DiGraph, m: Move) -> None:
        if m.src == m.dst:
            return
        cur = D.get_edge_data(m.src, m.dst)
        if cur is None or m.p > cur["p"]:
            D.add_edge(m.src, m.dst, p=m.p, weight=m.cost, etype=m.etype, direction=m.direction, depth_cost=m.depth_cost)

    # ------------------------------------------------------------------ misc

    def name(self, node_id: str) -> str:
        attrs = self.graph.node(node_id)
        if not attrs:
            return node_id
        return str(attrs.get("name") or node_id)

    def label(self, node_id: str) -> str:
        return self.graph.label_of(node_id) or "Unknown"

    def short(self, node_id: str) -> str:
        """Human-readable short form (bucket/role/db name without the id prefix)."""
        attrs = self.graph.node(node_id) or {}
        name = attrs.get("name")
        if name:
            return str(name)
        return node_id.rsplit(":", 1)[-1]
