"""Agent-facing API (05 section 7): tool manifest, tool invocation, non-streaming answers."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, ValidationError

from throughline.api.deps import require_analyst, require_registry
from throughline.api.errors import ApiError, not_found

router = APIRouter(prefix="/agent", tags=["agent"])


class AnswerIn(BaseModel):
    question: str
    context: dict[str, Any] | None = None
    mode: Literal["auto", "llm", "offline"] | None = None


@router.get("/tools")
def tools(registry: Any = Depends(require_registry)) -> dict[str, Any]:
    return {"tools": registry.anthropic_tools()}


@router.post("/tools/{name}")
def invoke_tool(name: str, arguments: dict[str, Any] | None = Body(None), registry: Any = Depends(require_registry)) -> dict[str, Any]:
    if name not in registry:
        raise not_found("tool", name)
    t0 = time.perf_counter()
    try:
        res = registry.run(name, arguments or {})
    except ValidationError as exc:
        errors = [{"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
        raise ApiError("invalid_argument", f"invalid arguments for tool {name!r}", details={"errors": errors}) from exc
    return {"result": res.result, "evidence": res.evidence, "elapsed_ms": int((time.perf_counter() - t0) * 1000), "summary": res.summary}


@router.post("/answer")
async def answer(body: AnswerIn, analyst: Any = Depends(require_analyst)) -> Any:
    if not body.question.strip():
        raise ApiError("invalid_argument", "question must not be empty", details={"param": "question"})
    return await asyncio.to_thread(analyst.answer, body.question, body.context, body.mode)
