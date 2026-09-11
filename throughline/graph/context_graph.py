"""ContextGraph: the in-process NetworkX projection of the security context graph.

The projection is loaded from the canonical ``nodes.jsonl`` / ``edges.jsonl`` files (docs/03-graph-schema.md)
and is the substrate for analytics that need custom edge semantics (blast radius, attack paths, correlation,
insights). It is immutable after load except for the enrichment pass run by the build pipeline.

Storage conventions
-------------------
* ``G`` is a ``networkx.MultiDiGraph``. Node attributes are the record fields flattened:
  ``id, label, name, source, source_id, first_seen, last_seen, confidence`` plus every key of ``props``.
* Edge key is the relationship type (``HAS_ROLE``); parallel edges of the same type between the same pair get
  keys ``TYPE#2``, ``TYPE#3``... Every edge carries ``type`` (the bare type) plus ``source, first_seen,
  last_seen, confidence`` and the flattened ``props``.
* Edge ids in API output are ``src|TYPE|dst`` (parallel edges are collapsed in output).
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import networkx as nx

from throughline.models import EdgeOut, GraphFragment, NodeOut, PathOut, SearchHit
from throughline.schema import EDGE_TYPES, LABELS, category_of

NODE_META_KEYS = ("id", "label", "name", "source", "source_id", "first_seen", "last_seen", "confidence")
EDGE_META_KEYS = ("type", "source", "first_seen", "last_seen", "confidence")

CROWN_JEWEL_LABELS = {"StorageBucket", "Database", "Secret"}


def edge_id(src: str, etype: str, dst: str) -> str:
    return f"{src}|{etype}|{dst}"


def split_edge_id(eid: str) -> tuple[str, str, str]:
    src, etype, dst = eid.split("|", 2)
    return src, etype, dst


class ContextGraph:
    def __init__(self) -> None:
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self._by_label: dict[str, set[str]] = defaultdict(set)
        self._search_index: dict[str, set[str]] | None = None
        self.build_info: dict[str, Any] = {}

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_jsonl(cls, nodes_path: Path, edges_path: Path, manifest_path: Path | None = None) -> ContextGraph:
        g = cls()
        with Path(nodes_path).open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    g.add_node_record(json.loads(line))
        with Path(edges_path).open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    g.add_edge_record(json.loads(line))
        if manifest_path and Path(manifest_path).exists():
            g.build_info = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        return g

    @classmethod
    def from_records(cls, nodes: Iterable[dict[str, Any]], edges: Iterable[dict[str, Any]]) -> ContextGraph:
        g = cls()
        for n in nodes:
            g.add_node_record(n)
        for e in edges:
            g.add_edge_record(e)
        return g

    def add_node_record(self, rec: dict[str, Any]) -> None:
        attrs = {k: rec.get(k) for k in NODE_META_KEYS}
        props = rec.get("props") or {}
        for k, v in props.items():
            if k not in NODE_META_KEYS:
                attrs[k] = v
        self.G.add_node(rec["id"], **attrs)
        self._by_label[rec["label"]].add(rec["id"])
        self._search_index = None

    def add_edge_record(self, rec: dict[str, Any]) -> str:
        etype = rec["type"]
        src, dst = rec["src"], rec["dst"]
        if src not in self.G or dst not in self.G:
            raise KeyError(f"edge {etype} references unknown node: {src if src not in self.G else dst}")
        attrs = {k: rec.get(k) for k in EDGE_META_KEYS}
        attrs["type"] = etype
        for k, v in (rec.get("props") or {}).items():
            if k not in EDGE_META_KEYS:
                attrs[k] = v
        key = etype
        i = 1
        while self.G.has_edge(src, dst, key=key):
            i += 1
            key = f"{etype}#{i}"
        self.G.add_edge(src, dst, key=key, **attrs)
        return key

    def set_node_props(self, node_id: str, **props: Any) -> None:
        self.G.nodes[node_id].update(props)
        self._search_index = None

    def reload_from(self, other: ContextGraph) -> None:
        """Replace this graph's contents with ``other``'s in place, so references held by other components
        (analytics engine, stores) keep seeing one consistent graph after a rebuild."""
        self.G = other.G
        self._by_label = other._by_label
        self._search_index = None
        self.build_info = other.build_info

    def remove_node_record(self, node_id: str) -> None:
        """Remove a node and its edges (used by the enrichment pass to rebuild derived nodes idempotently)."""
        if node_id not in self.G:
            return
        label = self.G.nodes[node_id].get("label")
        self.G.remove_node(node_id)
        if label in self._by_label:
            self._by_label[label].discard(node_id)
        self._search_index = None

    def remove_edges(self, etype: str, where: Callable[[str, str, dict[str, Any]], bool] | None = None) -> int:
        """Remove every edge of ``etype`` (optionally only those where ``where(src, dst, data)`` is true)."""
        doomed = [
            (u, v, k)
            for u, v, k, d in self.G.edges(keys=True, data=True)
            if d.get("type") == etype and (where is None or where(u, v, d))
        ]
        for u, v, k in doomed:
            self.G.remove_edge(u, v, key=k)
        return len(doomed)

    # ------------------------------------------------------------------ basic access

    def __contains__(self, node_id: str) -> bool:
        return node_id in self.G

    def __len__(self) -> int:
        return self.G.number_of_nodes()

    def node(self, node_id: str) -> dict[str, Any] | None:
        return self.G.nodes[node_id] if node_id in self.G else None

    def label_of(self, node_id: str) -> str | None:
        return self.G.nodes[node_id].get("label") if node_id in self.G else None

    def get(self, node_id: str, key: str, default: Any = None) -> Any:
        return self.G.nodes[node_id].get(key, default) if node_id in self.G else default

    def nodes_by_label(self, label: str) -> Iterator[str]:
        return iter(sorted(self._by_label.get(label, ())))

    def count_by_label(self) -> dict[str, int]:
        return {lbl: len(ids) for lbl, ids in sorted(self._by_label.items())}

    def count_by_edge_type(self) -> dict[str, int]:
        c: Counter[str] = Counter(d["type"] for _, _, d in self.G.edges(data=True))
        return dict(sorted(c.items()))

    def out_edges(self, node_id: str, types: Iterable[str] | None = None) -> list[tuple[str, dict[str, Any]]]:
        if node_id not in self.G:
            return []
        wanted = set(types) if types else None
        return [(v, d) for _, v, d in self.G.out_edges(node_id, data=True) if wanted is None or d["type"] in wanted]

    def in_edges(self, node_id: str, types: Iterable[str] | None = None) -> list[tuple[str, dict[str, Any]]]:
        if node_id not in self.G:
            return []
        wanted = set(types) if types else None
        return [(u, d) for u, _, d in self.G.in_edges(node_id, data=True) if wanted is None or d["type"] in wanted]

    def neighbors(self, node_id: str, types: Iterable[str] | None = None, direction: str = "both") -> list[str]:
        out: list[str] = []
        if direction in ("out", "both"):
            out += [v for v, _ in self.out_edges(node_id, types)]
        if direction in ("in", "both"):
            out += [u for u, _ in self.in_edges(node_id, types)]
        return list(dict.fromkeys(out))

    def edges_between(self, src: str, dst: str) -> list[dict[str, Any]]:
        if not self.G.has_edge(src, dst):
            return []
        return list(self.G.get_edge_data(src, dst).values())

    def first_edge(self, src: str, dst: str, etype: str | None = None) -> dict[str, Any] | None:
        for d in self.edges_between(src, dst):
            if etype is None or d["type"] == etype:
                return d
        return None

    def find(self, label: str, **where: Any) -> list[str]:
        """Nodes of a label whose attributes equal all given values."""
        out = []
        for nid in self.nodes_by_label(label):
            attrs = self.G.nodes[nid]
            if all(attrs.get(k) == v for k, v in where.items()):
                out.append(nid)
        return out

    # ------------------------------------------------------------------ traversal helpers

    def k_hop(
        self,
        start: str | Iterable[str],
        depth: int = 1,
        edge_types: Iterable[str] | None = None,
        direction: str = "both",
        max_nodes: int = 300,
        node_labels: Iterable[str] | None = None,
    ) -> dict[str, int]:
        """Breadth-first expansion; returns {node_id: hop_distance}. Bounded by depth and max_nodes."""
        starts = [start] if isinstance(start, str) else list(start)
        wanted_labels = set(node_labels) if node_labels else None
        dist: dict[str, int] = {s: 0 for s in starts if s in self.G}
        q: deque[str] = deque(dist)
        while q:
            u = q.popleft()
            if dist[u] >= depth:
                continue
            for v in self.neighbors(u, edge_types, direction):
                if v in dist:
                    continue
                if wanted_labels and self.label_of(v) not in wanted_labels:
                    continue
                dist[v] = dist[u] + 1
                if len(dist) >= max_nodes:
                    return dist
                q.append(v)
        return dist

    def shortest_path(self, src: str, dst: str, edge_types: Iterable[str] | None = None, max_hops: int = 6, directed: bool = True) -> list[str] | None:
        if src not in self.G or dst not in self.G:
            return None
        wanted = set(edge_types) if edge_types else None
        # BFS with predecessor tracking on the type-filtered view
        prev: dict[str, str | None] = {src: None}
        q: deque[tuple[str, int]] = deque([(src, 0)])
        while q:
            u, d = q.popleft()
            if u == dst:
                break
            if d >= max_hops:
                continue
            nbrs = [v for v, e in self.out_edges(u) if wanted is None or e["type"] in wanted]
            if not directed:
                nbrs += [v for v, e in self.in_edges(u) if wanted is None or e["type"] in wanted]
            for v in nbrs:
                if v not in prev:
                    prev[v] = u
                    q.append((v, d + 1))
        if dst not in prev:
            return None
        path = [dst]
        while prev[path[-1]] is not None:
            path.append(prev[path[-1]])  # type: ignore[arg-type]
        return list(reversed(path))

    # ------------------------------------------------------------------ search

    def _ensure_search_index(self) -> dict[str, set[str]]:
        if self._search_index is None:
            idx: dict[str, set[str]] = defaultdict(set)
            for nid, attrs in self.G.nodes(data=True):
                tokens: set[str] = set()
                for key in ("name", "hostname", "private_ip", "public_ip", "address", "fqdn", "sha256", "value", "email", "display_name", "cve_id", "technique_id", "title", "arn", "family"):
                    val = attrs.get(key)
                    if isinstance(val, str) and val:
                        tokens.add(val.lower())
                        tokens.update(t for t in _tokenize(val) if len(t) >= 2)
                tokens.add(nid.lower())
                tokens.update(t for t in _tokenize(nid) if len(t) >= 2)
                for t in tokens:
                    idx[t].add(nid)
            self._search_index = idx
        return self._search_index

    def search(self, text: str, labels: Iterable[str] | None = None, limit: int = 50) -> list[SearchHit]:
        text = text.strip().lower()
        if not text:
            return []
        idx = self._ensure_search_index()
        wanted = set(labels) if labels else None
        scored: dict[str, float] = {}
        q_tokens = [t for t in _tokenize(text) if len(t) >= 2] or [text]
        for tok in q_tokens or [text]:
            for key, ids in idx.items():
                if key == tok:
                    s = 3.0
                elif key.startswith(tok):
                    s = 2.0
                elif tok in key and len(tok) >= 3:
                    s = 1.0
                else:
                    continue
                for nid in ids:
                    if wanted and self.label_of(nid) not in wanted:
                        continue
                    scored[nid] = scored.get(nid, 0.0) + s
        ranked = sorted(scored.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
        hits = []
        for nid, s in ranked:
            attrs = self.G.nodes[nid]
            hits.append(SearchHit(id=nid, label=attrs["label"], name=attrs.get("name") or nid, category=category_of(attrs["label"]), snippet=_snippet(attrs), score=s))
        return hits

    # ------------------------------------------------------------------ output conversion

    def node_out(self, node_id: str, highlight: bool = False, extra_tags: Iterable[str] = ()) -> NodeOut:
        attrs = self.G.nodes[node_id]
        label = attrs["label"]
        props = {k: v for k, v in attrs.items() if k not in NODE_META_KEYS and v is not None}
        tags = list(extra_tags)
        if attrs.get("crown_jewel"):
            tags.append("crown_jewel")
        if attrs.get("exposure") == "internet" or attrs.get("public") is True:
            tags.append("internet_exposed")
        if attrs.get("storyline_id"):
            tags.append(f"storyline:{attrs['storyline_id']}")
        if (attrs.get("ioc_match_count") or 0) > 0:
            tags.append("ioc_match")
        severity = attrs.get("vendor_severity") if label == "Alert" else attrs.get("severity")
        score = attrs.get("contextual_score") if label in ("Alert", "Storyline") else None
        return NodeOut(
            id=node_id, label=label, name=attrs.get("name") or node_id, category=category_of(label),
            severity=severity, score=score, highlight=highlight, tags=list(dict.fromkeys(tags)), props=props,
        )

    def edge_out(self, src: str, dst: str, data: dict[str, Any], highlight: bool = False) -> EdgeOut:
        etype = data["type"]
        props = {k: v for k, v in data.items() if k not in EDGE_META_KEYS and v is not None}
        et = EDGE_TYPES.get(etype)
        return EdgeOut(
            id=edge_id(src, etype, dst), type=etype, src=src, dst=dst, derived=bool(et and et.derived) or data.get("source") == "derived",
            confidence=float(data.get("confidence") or 1.0), highlight=highlight, props=props,
        )

    def fragment(
        self,
        node_ids: Iterable[str],
        *,
        highlight_ids: Iterable[str] = (),
        highlight_edge_ids: Iterable[str] = (),
        focus: Iterable[str] = (),
        layout_hint: str = "neighborhood",
        include_edges: bool = True,
        max_nodes: int = 300,
        max_edges: int = 800,
        paths: list[PathOut] | None = None,
    ) -> GraphFragment:
        ids = [n for n in dict.fromkeys(node_ids) if n in self.G]
        truncated = False
        if len(ids) > max_nodes:
            ids, truncated = ids[:max_nodes], True
        hl = set(highlight_ids)
        hle = set(highlight_edge_ids)
        nodes = [self.node_out(n, highlight=n in hl) for n in ids]
        edges: list[EdgeOut] = []
        if include_edges:
            idset = set(ids)
            seen: set[str] = set()
            for u in ids:
                for v, d in self.out_edges(u):
                    if v in idset:
                        eid = edge_id(u, d["type"], v)
                        if eid in seen:
                            continue
                        seen.add(eid)
                        edges.append(self.edge_out(u, v, d, highlight=eid in hle or (u in hl and v in hl)))
            if len(edges) > max_edges:
                edges, truncated = sorted(edges, key=lambda e: not e.highlight)[:max_edges], True
        return GraphFragment(
            nodes=nodes, edges=edges, paths=paths or [], focus=list(focus), layout_hint=layout_hint,  # type: ignore[arg-type]
            truncated=truncated, total_nodes=len(list(dict.fromkeys(node_ids))),
        )

    def path_out(self, node_ids: list[str], label: str | None = None, likelihood: float | None = None, stages: list[str] | None = None) -> PathOut:
        eids = []
        for a, b in zip(node_ids, node_ids[1:], strict=False):
            d = self.first_edge(a, b) or self.first_edge(b, a)
            if d is None:
                continue
            if self.first_edge(a, b) is not None:
                eids.append(edge_id(a, d["type"], b))
            else:
                eids.append(edge_id(b, d["type"], a))
        return PathOut(node_ids=node_ids, edge_ids=eids, hops=max(len(node_ids) - 1, 0), label=label, likelihood=likelihood, stages=stages or [])

    # ------------------------------------------------------------------ export

    def iter_node_records(self) -> Iterator[dict[str, Any]]:
        for _nid, attrs in self.G.nodes(data=True):
            rec = {k: attrs.get(k) for k in NODE_META_KEYS}
            rec["props"] = {k: v for k, v in attrs.items() if k not in NODE_META_KEYS}
            yield rec

    def iter_edge_records(self) -> Iterator[dict[str, Any]]:
        for u, v, d in self.G.edges(data=True):
            rec = {"type": d["type"], "src": u, "dst": v}
            for k in EDGE_META_KEYS[1:]:
                rec[k] = d.get(k)
            rec["props"] = {k: val for k, val in d.items() if k not in EDGE_META_KEYS}
            yield rec

    def validate(self) -> list[str]:
        problems = []
        for nid, attrs in self.G.nodes(data=True):
            if attrs.get("label") not in LABELS:
                problems.append(f"unknown label on {nid}: {attrs.get('label')}")
        for u, v, d in self.G.edges(data=True):
            et = EDGE_TYPES.get(d["type"])
            if et is None:
                problems.append(f"unknown edge type {d['type']} ({u} -> {v})")
                continue
            if not et.allows(self.label_of(u) or "", self.label_of(v) or ""):
                problems.append(f"{d['type']}: ({self.label_of(u)} -> {self.label_of(v)}) not allowed ({u} -> {v})")
        return problems


def _tokenize(text: str) -> list[str]:
    out, cur = [], []
    for ch in text.lower():
        if ch.isalnum():
            cur.append(ch)
        else:
            if cur:
                out.append("".join(cur))
                cur = []
    if cur:
        out.append("".join(cur))
    return out


def _snippet(attrs: dict[str, Any]) -> str | None:
    for key in ("hostname", "title", "email", "address", "fqdn", "cve_id", "arn", "description"):
        val = attrs.get(key)
        if isinstance(val, str) and val and val != attrs.get("name"):
            return val[:120]
    return None
