"""Threat intelligence endpoints (05 section 4)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from throughline.api.deps import require_engine
from throughline.api.errors import ApiError

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.get("/actors")
def actors(engine: Any = Depends(require_engine)) -> dict[str, Any]:
    return {"items": list(engine.ti_actors())}


@router.get("/actors/{actor_id:path}")
def actor(actor_id: str, engine: Any = Depends(require_engine)) -> Any:
    return engine.ti_actor(actor_id)


@router.get("/campaigns/{campaign_id:path}")
def campaign(campaign_id: str, engine: Any = Depends(require_engine)) -> Any:
    return engine.ti_campaign(campaign_id)


@router.get("/reports")
def reports(engine: Any = Depends(require_engine)) -> dict[str, Any]:
    return {"items": list(engine.ti_reports())}


@router.get("/reports/{report_id:path}")
def report(report_id: str, engine: Any = Depends(require_engine)) -> Any:
    return engine.ti_report(report_id)


@router.get("/lookup")
def lookup(value: str = Query(""), engine: Any = Depends(require_engine)) -> Any:
    if not value.strip():
        raise ApiError("invalid_argument", "value must not be empty", details={"param": "value"})
    return engine.ti_lookup(value.strip())


@router.get("/exposure")
def exposure(sector_only: bool = Query(True), engine: Any = Depends(require_engine)) -> dict[str, Any]:
    return {"items": list(engine.ti_exposure(sector_only=sector_only))}
