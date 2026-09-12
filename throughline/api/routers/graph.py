"""Graph endpoints: search, nodes, neighborhood, paths, blast radius, attack paths, Cypher (05 section 3)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Query, Request
from pydantic import BaseModel, Field

from throughline.agent.tools import cap_fragment, merge_fragments, record_to_node_out
from throughline.api.deps import get_graph, get_settings, require_engine, require_registry, require_store
from throughline.api.errors import ApiError, bounded
from throughline.models import GraphFragment
from throughline.schema import EDGE_TYPES, LABELS

router = APIRouter(tags=["graph"])

DIRECTIONS = ("both", "in", "out")


def _csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    return items or None


def _labels(value: str | None) -> list[str] | None:
    labels = _csv(value)
    if labels:
        unknown = [lb for lb in labels if lb not in LABELS]
        if unknown:
            raise ApiError("invalid_argument", f"unknown label(s): {unknown}", details={"param": "labels", "unknown": unknown})
    return labels


def _edge_types(value: str | None) -> list[str] | None:
    types = _csv(value)
    if types:
        unknown = [t for t in types if t not in EDGE_TYPES]
        if unknown:
            raise ApiError("invalid_argument", f"unknown edge type(s): {unknown}", details={"param": "edge_types", "unknown": unknown})
    return types


class BatchIn(BaseModel):
    ids: list[str] = Field(default_factory=list)


class CypherIn(BaseModel):
    query: str
    params: dict[str, Any] | None = None
    row_limit: int | None = None


@router.get("/search")
def search(q: str = Query(""), labels: str | None = None, limit: int = Query(25), store: Any = Depends(require_store)) -> dict[str, Any]:
    if not q.strip():
        raise ApiError("invalid_argument", "q must not be empty", details={"param": "q"})
    limit = bounded(limit, cap=100, name="limit")
    hits = list(store.search(q.strip(), _labels(labels), limit))[:limit]
    return {"hits": hits}


@router.post("/nodes/batch")
def nodes_batch(body: BatchIn, request: Request, store: Any = Depends(require_store)) -> dict[str, Any]:
    ids = [i for i in dict.fromkeys(body.ids) if i]
    if len(ids) > 200:
        raise ApiError("limit_exceeded", f"at most 200 ids per batch (got {len(ids)})", details={"param": "ids", "max": 200, "value": len(ids)})
    graph = get_graph(request)
    nodes = []
    if graph is not None:
        nodes = [graph.node_out(i) for i in ids if i in graph]
    else:
        nodes = [record_to_node_out(rec) for rec in store.get_nodes(ids)]
    return {"nodes": nodes}


@router.get("/nodes/{node_id:path}")
def node_card(node_id: str, engine: Any = Depends(require_engine)) -> Any:
    return engine.node_card(node_id)


@router.get("/graph/neighborhood")
def neighborhood(
    id: str = Query(...),
    depth: int = Query(1),
    edge_types: str | None = None,
    direction: str = Query("both"),
    labels: str | None = None,
    max_nodes: int = Query(150),
    engine: Any = Depends(require_engine),
) -> Any:
    depth = bounded(depth, cap=3, name="depth")
    max_nodes = bounded(max_nodes, cap=300, name="max_nodes")
    if direction not in DIRECTIONS:
        raise ApiError("invalid_argument", f"direction must be one of {DIRECTIONS}", details={"param": "direction", "value": direction})
    frag: GraphFragment = engine.neighborhood(id, depth=depth, edge_types=_edge_types(edge_types), direction=direction, labels=_labels(labels), max_nodes=max_nodes)
    frag = cap_fragment(frag, max_nodes)
    if id not in frag.focus:
        frag = frag.model_copy(update={"focus": [id, *frag.focus]})
    return frag


@router.get("/graph/paths")
def paths(
    src: str = Query(...), dst: str = Query(...), max_hops: int = Query(6), k: int = Query(3), edge_types: str | None = None,
    engine: Any = Depends(require_engine),
) -> Any:
    max_hops = bounded(max_hops, cap=8, name="max_hops")
    k = bounded(k, cap=5, name="k")
    frag: GraphFragment = engine.find_paths(src, dst, max_hops=max_hops, k=k, edge_types=_edge_types(edge_types))
    return frag.model_copy(update={"layout_hint": "path", "focus": list(dict.fromkeys([*frag.focus, src, dst]))})


@router.get("/graph/blast-radius")
def blast_radius(id: str = Query(...), depth: int = Query(4), max_nodes: int = Query(500), engine: Any = Depends(require_engine)) -> Any:
    depth = bounded(depth, cap=6, name="depth")
    max_nodes = bounded(max_nodes, cap=2000, name="max_nodes")
    br = engine.blast_radius(id, depth=depth, max_nodes=max_nodes)
    if br.fragment is not None and br.fragment.layout_hint != "blast_radius":
        br = br.model_copy(update={"fragment": br.fragment.model_copy(update={"layout_hint": "blast_radius"})})
    return br


@router.get("/graph/attack-paths")
def attack_paths(
    through: str | None = None, target: str | None = None, entry: str | None = None, k: int = Query(5), engine: Any = Depends(require_engine),
) -> dict[str, Any]:
    k = bounded(k, cap=5, name="k")
    paths = list(engine.attack_paths(through_id=through, target_id=target, entry_id=entry, k=k))[:k]
    fragment = merge_fragments([p.fragment for p in paths], layout_hint="path")
    focus = [x for x in (through, target, entry) if x]
    fragment = fragment.model_copy(update={"focus": list(dict.fromkeys([*focus, *fragment.focus]))})
    return {"paths": paths, "fragment": fragment}


@router.post("/graph/cypher")
def cypher(
    body: CypherIn = Body(...), request: Request = None, store: Any = Depends(require_store), registry: Any = Depends(require_registry),
) -> dict[str, Any]:
    settings = get_settings(request)
    default_rows = int(getattr(settings, "cypher_row_limit", 200))
    row_limit = bounded(body.row_limit if body.row_limit is not None else default_rows, cap=500, name="row_limit")
    if not body.query.strip():
        raise ApiError("invalid_argument", "query must not be empty", details={"param": "query"})
    try:
        caps = dict(store.capabilities() or {})
    except Exception:
        caps = {}
    if not caps.get("cypher"):
        raise ApiError("not_supported", f"Cypher is not available on the {getattr(store, 'name', 'current')} backend")
    result = store.run_readonly_cypher(body.query, params=body.params, row_limit=row_limit, timeout_ms=int(getattr(settings, "cypher_timeout_ms", 3000)))
    rows = list(getattr(result, "rows", []))
    fragment = registry.cypher_fragment(rows)
    return {
        "columns": list(getattr(result, "columns", [])),
        "rows": rows,
        "elapsed_ms": int(getattr(result, "elapsed_ms", 0)),
        "truncated": bool(getattr(result, "truncated", False)),
        "fragment": fragment if fragment.nodes else None,
    }
