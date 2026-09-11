"""Runtime assembly shared by the FastAPI lifespan and the CLI: graph -> store -> engine -> tools -> analyst.

The graph, store and analytics packages are built by other engineers; they are imported lazily and every step
degrades gracefully (fallback NetworkX store, ``Runtime.error`` set) so the API process always starts and
``GET /api/v1/health`` can say what is missing.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from throughline.agent.analyst import Analyst
from throughline.agent.session import ChatSessionStore
from throughline.agent.tools import ToolRegistry

log = logging.getLogger(__name__)


@dataclass
class Runtime:
    graph: Any = None
    store: Any = None
    engine: Any = None
    registry: ToolRegistry | None = None
    analyst: Analyst | None = None
    error: str | None = None

    @property
    def ready(self) -> bool:
        return self.engine is not None and self.store is not None and self.analyst is not None

    @property
    def backend(self) -> str:
        return str(getattr(self.store, "name", None) or ("none" if self.store is None else type(self.store).__name__))

    def close(self) -> None:
        close = getattr(self.store, "close", None)
        if callable(close):
            try:
                close()
            except Exception as exc:  # pragma: no cover
                log.warning("store.close failed: %s", exc)


def _load_graph(settings: Any) -> Any:
    data_dir = Path(settings.data_dir)
    try:
        from throughline.graph.loader import load_context_graph  # Agent B
    except ImportError:
        from throughline.api.fallback import load_context_graph_fallback

        log.info("throughline.graph.loader not available; loading the ContextGraph from %s directly", data_dir)
        return load_context_graph_fallback(data_dir)
    return load_context_graph(data_dir)


def _make_store(settings: Any, graph: Any) -> Any:
    from throughline.api.fallback import ContextGraphStore

    try:
        from throughline.graph.factory import make_store  # Agent B
    except ImportError:
        log.info("throughline.graph.factory not available; using the NetworkX fallback store")
        return ContextGraphStore(graph)
    try:
        store = make_store(settings, graph)
        open_ = getattr(store, "open", None)
        if callable(open_):
            try:
                open_()
            except Exception as exc:  # already open, or backend refuses; keep going
                log.debug("store.open(): %s", exc)
        return store
    except Exception as exc:
        log.warning("make_store(%s) failed (%s); using the NetworkX fallback store", getattr(settings, "graph_backend", "?"), exc)
        return ContextGraphStore(graph)


def _make_engine(graph: Any) -> Any:
    try:
        from throughline.analytics.engine import AnalyticsEngine  # Agent C
    except ImportError as exc:
        raise RuntimeError("throughline.analytics.engine is not available yet; analytics endpoints cannot be served") from exc
    return AnalyticsEngine(graph)


def load_runtime(
    settings: Any,
    *,
    graph: Any = None,
    store: Any = None,
    engine: Any = None,
    registry: ToolRegistry | None = None,
    analyst: Analyst | None = None,
    sessions: ChatSessionStore | None = None,
) -> Runtime:
    rt = Runtime(graph=graph, store=store, engine=engine, registry=registry, analyst=analyst)
    if rt.registry is None and rt.analyst is not None:
        rt.registry = rt.analyst.registry
    if rt.registry is not None:
        rt.engine = rt.engine or rt.registry.engine
        rt.store = rt.store or rt.registry.store
    try:
        if rt.graph is None and (rt.engine is None or rt.store is None):
            rt.graph = _load_graph(settings)
        if rt.store is None:
            rt.store = _make_store(settings, rt.graph)
        if rt.engine is None:
            rt.engine = _make_engine(rt.graph)
    except Exception as exc:
        rt.error = f"{type(exc).__name__}: {exc}"
        log.error("runtime not fully loaded: %s", rt.error)
    if rt.engine is not None and rt.store is not None:
        if rt.registry is None:
            rt.registry = ToolRegistry(rt.engine, rt.store, settings=settings)
        if rt.analyst is None:
            rt.analyst = Analyst(rt.registry, settings, sessions=sessions)
    return rt
