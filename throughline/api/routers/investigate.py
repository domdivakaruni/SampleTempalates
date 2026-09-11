"""Typed investigations (05 section 5): the demo questions as REST endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from throughline.api.deps import require_engine
from throughline.api.errors import ApiError

router = APIRouter(prefix="/investigate", tags=["investigate"])

CONTAINMENT_ACTIONS = ("isolate_endpoint", "rotate_role_credentials", "tighten_trust_policy", "block_ip", "disable_user", "revoke_sessions")


class ContainmentIn(BaseModel):
    target_ids: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)


@router.get("/credential-joins")
def credential_joins(engine: Any = Depends(require_engine)) -> Any:
    return engine.credential_joins()


@router.get("/alerts-reaching-crown-jewels")
def alerts_reaching_crown_jewels(jewel_id: str | None = None, classification: str | None = None, engine: Any = Depends(require_engine)) -> Any:
    return engine.alerts_reaching_crown_jewels(jewel_id=jewel_id, classification=classification)


@router.get("/identity-footprint")
def identity_footprint(id: str = Query(...), engine: Any = Depends(require_engine)) -> Any:
    return engine.identity_footprint(id)


@router.get("/medium-alerts-with-data-path")
def medium_alerts_with_data_path(severity: str = Query("medium"), source: str | None = Query("falcon"), engine: Any = Depends(require_engine)) -> Any:
    if source in ("", "all", "any", "*"):
        source = None
    return engine.medium_alerts_with_data_path(severity=severity, source=source)


@router.post("/containment")
def containment(body: ContainmentIn, engine: Any = Depends(require_engine)) -> Any:
    targets = [t for t in dict.fromkeys(body.target_ids) if t]
    if not targets:
        raise ApiError("invalid_argument", "target_ids must contain at least one node id", details={"param": "target_ids"})
    if len(targets) > 50:
        raise ApiError("limit_exceeded", f"at most 50 target_ids (got {len(targets)})", details={"param": "target_ids", "max": 50})
    actions = list(dict.fromkeys(body.actions))
    unknown = [a for a in actions if a not in CONTAINMENT_ACTIONS]
    if not actions or unknown:
        raise ApiError("invalid_argument", f"actions must be a non-empty subset of {CONTAINMENT_ACTIONS}", details={"param": "actions", "unknown": unknown})
    return engine.simulate_containment(targets, actions)
