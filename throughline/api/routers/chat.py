"""Analyst chat (05 section 6): sessions, SSE message stream, suggestions."""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Body, Depends, Query
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse, ServerSentEvent

from throughline.agent.prompts import suggestions_for
from throughline.api.deps import require_analyst
from throughline.api.errors import ApiError, not_found
from throughline.models import ChatMessageIn

router = APIRouter(prefix="/chat", tags=["chat"])


class SessionCreateIn(BaseModel):
    context: dict[str, Any] | None = None


@router.post("/sessions")
def create_session(body: SessionCreateIn | None = Body(None), analyst: Any = Depends(require_analyst)) -> Any:
    return analyst.sessions.create(body.context if body else None)


@router.get("/sessions/{session_id}")
def get_session(session_id: str, analyst: Any = Depends(require_analyst)) -> Any:
    session = analyst.sessions.get_optional(session_id)
    if session is None:
        raise not_found("chat session", session_id)
    return session


@router.post("/sessions/{session_id}/messages")
async def post_message(
    session_id: str, body: ChatMessageIn, stream: bool = Query(True), analyst: Any = Depends(require_analyst),
) -> Any:
    if analyst.sessions.get_optional(session_id) is None:
        raise not_found("chat session", session_id)
    if not body.content or not body.content.strip():
        raise ApiError("invalid_argument", "content must not be empty", details={"param": "content"})
    if not stream:
        turn = await asyncio.to_thread(analyst.respond, session_id, body)
        return {"turn": turn}

    async def events() -> AsyncIterator[ServerSentEvent]:
        async for ev in analyst.stream(session_id, body):
            yield ServerSentEvent(event=ev.type, data=json.dumps(ev.data, default=str, ensure_ascii=False))

    return EventSourceResponse(events(), ping=15)


@router.get("/suggestions")
def suggestions(alert_id: str | None = None, node_id: str | None = None, storyline_id: str | None = None) -> dict[str, Any]:
    return {"questions": suggestions_for(alert_id=alert_id, node_id=node_id, storyline_id=storyline_id)}
