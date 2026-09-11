"""FastAPI application factory (docs/05-api-contract.md).

``create_app(graph=None, store=None, engine=None, analyst=None)`` wires injected components (tests) or loads them
in the lifespan (production): ``ContextGraph`` via ``throughline.graph.loader``, the store via
``throughline.graph.factory.make_store``, ``AnalyticsEngine`` from ``throughline.analytics.engine``, then the
``ToolRegistry`` and the ``Analyst``. Those packages are imported lazily so this module imports while they are
still being built. The production web bundle (``settings.web_dist``) is served at ``/`` with an SPA fallback.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.staticfiles import StaticFiles

from throughline import __version__
from throughline.api.errors import ApiError, install_error_handlers
from throughline.api.responses import ORJSONResponse
from throughline.api.routers import agent, alerts, chat, investigate, meta, threat_intel
from throughline.api.routers import graph as graph_router
from throughline.api.runtime import Runtime, load_runtime

log = logging.getLogger(__name__)

API_PREFIX = "/api/v1"


def create_app(
    graph: Any = None,
    store: Any = None,
    engine: Any = None,
    analyst: Any = None,
    *,
    registry: Any = None,
    settings: Any = None,
    web_dist: Path | None = None,
) -> FastAPI:
    if settings is None:
        from throughline.config import settings as _settings

        settings = _settings
    dist = Path(web_dist) if web_dist is not None else Path(getattr(settings, "web_dist", "web/dist"))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        rt: Runtime = app.state.runtime
        if not rt.ready:
            app.state.runtime = await asyncio.to_thread(
                load_runtime, settings, graph=rt.graph, store=rt.store, engine=rt.engine, registry=rt.registry, analyst=rt.analyst,
            )
            rt = app.state.runtime
            if rt.ready:
                log.info("Throughline API ready: backend=%s nodes=%s", rt.backend, len(rt.graph) if rt.graph is not None else "?")
            else:
                log.warning("Throughline API started without a loaded graph: %s", rt.error)
        try:
            yield
        finally:
            app.state.runtime.close()

    app = FastAPI(
        title="Throughline API",
        version=__version__,
        description="Security context graph for human and AI analysts (prototype). See docs/05-api-contract.md.",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
        default_response_class=ORJSONResponse,
    )
    app.state.settings = settings
    app.state.runtime = _initial_runtime(settings, graph, store, engine, registry, analyst)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000"],
        allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    install_error_handlers(app)
    for router in (meta.router, alerts.router, graph_router.router, threat_intel.router, investigate.router, chat.router, agent.router):
        app.include_router(router, prefix=API_PREFIX)
    _install_static(app, dist)
    return app


def _initial_runtime(settings: Any, graph: Any, store: Any, engine: Any, registry: Any, analyst: Any) -> Runtime:
    """Wire whatever was injected so the app also works without running the lifespan (bare TestClient)."""
    rt = Runtime(graph=graph, store=store, engine=engine, registry=registry, analyst=analyst)
    if rt.registry is None and rt.analyst is not None:
        rt.registry = getattr(rt.analyst, "registry", None)
    if rt.registry is not None:
        rt.engine = rt.engine or getattr(rt.registry, "engine", None)
        rt.store = rt.store or getattr(rt.registry, "store", None)
    if rt.engine is not None and rt.store is not None:
        if rt.registry is None:
            from throughline.agent.tools import ToolRegistry

            rt.registry = ToolRegistry(rt.engine, rt.store, settings=settings)
        if rt.analyst is None:
            from throughline.agent.analyst import Analyst

            rt.analyst = Analyst(rt.registry, settings)
    return rt


def _install_static(app: FastAPI, dist: Path) -> None:
    index = dist / "index.html"
    if not index.is_file():

        @app.get("/", include_in_schema=False)
        async def root() -> dict[str, Any]:
            return {
                "name": "Throughline API", "version": __version__, "ui": "not built (run `npm run build` in web/)",
                "api": API_PREFIX, "docs": "/api/docs", "health": f"{API_PREFIX}/health",
            }

        return

    root_dir = dist.resolve()
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str) -> Any:
        if full_path == "api" or full_path.startswith("api/"):
            raise ApiError("not_found", f"no API route for /{full_path}")
        if full_path:
            candidate = (root_dir / full_path).resolve()
            if candidate.is_file() and root_dir in candidate.parents:
                return FileResponse(candidate)
        return FileResponse(index)


# uvicorn entry point: `uvicorn throughline.api.app:create_app --factory`
app_factory = create_app
