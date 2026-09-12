"""Alerts and storylines (05 section 2)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from throughline.api.deps import require_engine
from throughline.api.errors import ApiError, bounded
from throughline.models import StorylineOut

router = APIRouter(tags=["alerts"])

SORTS = ("contextual", "vendor", "time")
ORDERS = ("desc", "asc")


@router.get("/alerts")
def list_alerts(
    sort: str = Query("contextual"),
    order: str = Query("desc"),
    band: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    storyline: str | None = None,
    reaches_crown_jewel: bool | None = None,
    on_attack_path: bool | None = None,
    q: str | None = None,
    limit: int = Query(50),
    offset: int = Query(0),
    engine: Any = Depends(require_engine),
) -> dict[str, Any]:
    if sort not in SORTS:
        raise ApiError("invalid_argument", f"sort must be one of {SORTS}", details={"param": "sort", "value": sort})
    if order not in ORDERS:
        raise ApiError("invalid_argument", f"order must be one of {ORDERS}", details={"param": "order", "value": order})
    limit = bounded(limit, cap=500, name="limit")
    if offset < 0:
        raise ApiError("invalid_argument", "offset must be >= 0", details={"param": "offset", "value": offset})
    items, total = engine.list_alerts(
        sort=sort, order=order, band=band, severity=severity, source=source, storyline_id=storyline,
        reaches_crown_jewel=reaches_crown_jewel, on_attack_path=on_attack_path, q=q, limit=limit, offset=offset,
    )
    return {"items": list(items), "total": int(total), "limit": limit, "offset": offset}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, engine: Any = Depends(require_engine)) -> dict[str, Any]:
    return {"alert": engine.alert_summary(alert_id), "flat_view": engine.flat_view(alert_id)}


@router.get("/alerts/{alert_id}/context")
def alert_context(alert_id: str, engine: Any = Depends(require_engine)) -> Any:
    return engine.alert_context(alert_id)


@router.get("/alerts/{alert_id}/risk")
def alert_risk(alert_id: str, engine: Any = Depends(require_engine)) -> Any:
    return engine.risk_breakdown(alert_id)


@router.get("/alerts/{alert_id}/insights")
def alert_insights(alert_id: str, engine: Any = Depends(require_engine)) -> dict[str, Any]:
    return {"insights": list(engine.insights(alert_id))}


@router.get("/storylines")
def list_storylines(engine: Any = Depends(require_engine)) -> dict[str, Any]:
    items = []
    for s in engine.list_storylines():
        if isinstance(s, StorylineOut) and s.fragment is not None:
            s = s.model_copy(update={"fragment": None})
        items.append(s)
    return {"items": items}


@router.get("/storylines/{storyline_id}")
def get_storyline(storyline_id: str, engine: Any = Depends(require_engine)) -> Any:
    return engine.storyline(storyline_id, with_fragment=True)
