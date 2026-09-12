"""Meta endpoints: health, stats, schema, dashboard (05 section 1)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from throughline import __version__
from throughline.api.deps import get_runtime, get_settings, require_engine, require_store
from throughline.schema import CATEGORIES, COMMON_EDGE_COLUMNS, COMMON_NODE_COLUMNS, EDGE_TYPES, LABELS

router = APIRouter(tags=["meta"])


@router.get("/health")
def health(request: Request) -> dict[str, Any]:
    rt = get_runtime(request)
    settings = get_settings(request)
    total_nodes = total_edges = 0
    if rt.store is not None:
        try:
            stats = rt.store.stats()
            total_nodes, total_edges = int(stats.total_nodes), int(stats.total_edges)
        except Exception:
            pass
    if not total_nodes and rt.graph is not None:
        try:
            total_nodes, total_edges = len(rt.graph), rt.graph.G.number_of_edges()
        except Exception:
            pass
    build: dict[str, Any] = {"version": __version__}
    info = getattr(rt.graph, "build_info", None) or {}
    for key in ("seed", "generated_at", "checksum", "storylines", "storyline_ids"):
        if key in info:
            build[key] = info[key]
    if rt.ready:
        status = "ok"
    elif rt.error:
        status = "degraded"
    else:
        status = "starting"
    analyst_mode = rt.analyst.resolve_mode() if rt.analyst is not None else None
    payload: dict[str, Any] = {
        "status": status,
        "backend": rt.backend,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "agent_mode": getattr(settings, "agent_mode", "auto"),
        "model": rt.analyst.model if rt.analyst is not None else getattr(settings, "anthropic_model", None),
        "build": build,
        "analyst_mode": analyst_mode,
    }
    if rt.error:
        payload["error"] = rt.error
    return payload


@router.get("/stats")
def stats(store: Any = Depends(require_store)) -> Any:
    return store.stats()


@router.get("/schema")
def schema(request: Request) -> dict[str, Any]:
    extras: dict[str, Any] = {}
    store = getattr(getattr(request.app.state, "runtime", None), "store", None)
    if store is not None and hasattr(store, "schema_summary"):
        try:
            summary = store.schema_summary() or {}
            extras = {k: summary[k] for k in ("backend", "dialect", "notes", "key_properties", "example_queries") if k in summary}
        except Exception:  # pragma: no cover - the registry view below is always available
            extras = {}
    return {
        **extras,
        "categories": dict(CATEGORIES),
        "labels": [
            {
                "name": lbl.name, "category": lbl.category, "id_prefix": lbl.id_prefix,
                "columns": [{"name": c.name, "type": c.type} for c in (*COMMON_NODE_COLUMNS, *lbl.columns)],
            }
            for lbl in LABELS.values()
        ],
        "edge_types": [
            {
                "name": et.name, "pairs": [list(p) for p in et.pairs],
                "columns": [{"name": c.name, "type": c.type} for c in (*COMMON_EDGE_COLUMNS, *et.columns)], "derived": et.derived,
            }
            for et in EDGE_TYPES.values()
        ],
    }


@router.get("/dashboard")
def dashboard(engine: Any = Depends(require_engine)) -> Any:
    return engine.dashboard()
