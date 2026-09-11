"""FastAPI dependencies: access to the runtime components stored on ``app.state``."""
from __future__ import annotations

from typing import Any

from fastapi import Request

from throughline.api.errors import ApiError
from throughline.api.runtime import Runtime


def get_runtime(request: Request) -> Runtime:
    return request.app.state.runtime


def get_settings(request: Request) -> Any:
    return request.app.state.settings


def _not_ready(rt: Runtime, what: str) -> ApiError:
    return ApiError("upstream_error", f"{what} is not loaded: {rt.error or 'no graph data'}", details={"error": rt.error})


def require_engine(request: Request) -> Any:
    rt = get_runtime(request)
    if rt.engine is None:
        raise _not_ready(rt, "the analytics engine")
    return rt.engine


def require_store(request: Request) -> Any:
    rt = get_runtime(request)
    if rt.store is None:
        raise _not_ready(rt, "the graph store")
    return rt.store


def require_registry(request: Request) -> Any:
    rt = get_runtime(request)
    if rt.registry is None:
        raise _not_ready(rt, "the tool registry")
    return rt.registry


def require_analyst(request: Request) -> Any:
    rt = get_runtime(request)
    if rt.analyst is None:
        raise _not_ready(rt, "the analyst")
    return rt.analyst


def get_graph(request: Request) -> Any:
    return get_runtime(request).graph
