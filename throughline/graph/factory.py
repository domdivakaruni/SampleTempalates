"""``make_store(settings, graph)``: pick the GraphStore backend from the settings.

Rules (docs/02-architecture.md section 2.2, docs/06-build-plan.md section 3.1):

* ``graph_backend = "networkx"`` -> ``NetworkXStore`` over the already-loaded ``ContextGraph``;
* ``"ladybug"`` (default) or ``"kuzu"`` -> ``LadybugStore`` opened read-only on ``settings.graph_db_path`` with the
  ``ContextGraph`` attached (search and fragment rendering then match the NetworkX backend exactly);
* ``"neo4j"`` -> ``Neo4jStore`` on ``settings.neo4j_uri``.

The API must start on a fresh checkout that has only the JSONL files, and the data pipeline must be able to create
the embedded database through whatever ``make_store`` returned (``simulator/build.py`` does ``make_store`` then
``loader.build_embedded_db``). So this function never raises for an unavailable backend; it logs one line and
falls back to ``NetworkXStore``:

* engine not importable (package missing, or the other embedded engine is already loaded in this process) ->
  plain ``NetworkXStore`` (nothing can build the database in this process either);
* database file missing, or present but not openable -> ``NetworkXStore`` that *stands in for* the un-opened
  ``LadybugStore`` (``store.embedded``): ``loader.build_embedded_db(store, data_dir)`` then builds the embedded
  database through it, and the next ``make_store`` call returns the real store;
* Neo4j without a URI or unreachable -> plain ``NetworkXStore``.

The fallback is logged at WARNING, or at ERROR when the backend was configured explicitly (``GRAPH_BACKEND`` in the
environment or ``.env``), so a broken deployment stays visible in the logs and in ``stats().backend``.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from throughline.graph.context_graph import ContextGraph
from throughline.graph.networkx_store import NetworkXStore
from throughline.graph.store import GraphStore, NotSupported

log = logging.getLogger(__name__)

BACKENDS = ("ladybug", "kuzu", "networkx", "neo4j")


def _explicit(settings: Any, field: str) -> bool:
    fields_set = getattr(settings, "model_fields_set", None)
    return bool(fields_set) and field in fields_set


def make_store(settings: Any, graph: ContextGraph) -> GraphStore:
    backend = str(getattr(settings, "graph_backend", "ladybug") or "ladybug").lower()
    if backend not in BACKENDS:
        raise ValueError(f"unknown graph backend {backend!r}; expected one of {BACKENDS}")
    fallback_log = log.error if _explicit(settings, "graph_backend") else log.warning

    if backend == "networkx":
        return NetworkXStore(graph)

    if backend == "neo4j":
        return _make_neo4j(settings, graph, fallback_log)
    return _make_embedded(settings, graph, backend, fallback_log)


def _make_neo4j(settings: Any, graph: ContextGraph, fallback_log: Any) -> GraphStore:
    uri = getattr(settings, "neo4j_uri", None)
    if not uri:
        fallback_log("graph_backend=neo4j but neo4j_uri is not set; falling back to the networkx backend")
        return NetworkXStore(graph)
    try:
        from throughline.graph.neo4j_store import Neo4jStore  # noqa: PLC0415 - optional dependency

        store = Neo4jStore(
            uri,
            user=getattr(settings, "neo4j_user", "neo4j"),
            password=getattr(settings, "neo4j_password", None),
            database=getattr(settings, "neo4j_database", "neo4j"),
            graph=graph,
        )
        store.open()
        return store
    except Exception as exc:
        fallback_log("neo4j backend at %s unavailable (%s); falling back to the networkx backend", uri, exc)
        return NetworkXStore(graph)


def _make_embedded(settings: Any, graph: ContextGraph, engine: str, fallback_log: Any) -> GraphStore:
    from throughline.graph.ladybug_store import (  # noqa: PLC0415 - keeps the engine import lazy
        LadybugStore,
        load_engine,
    )

    db_path = Path(settings.graph_db_path)
    try:
        load_engine(engine)
    except NotSupported as exc:
        fallback_log("graph engine %r is not available (%s); falling back to the networkx backend", engine, exc)
        return NetworkXStore(graph)
    store = LadybugStore(db_path, engine=engine, graph=graph)
    if not db_path.exists():
        fallback_log(
            "graph_backend=%s but no database at %s (run `throughline build-data` or `make db`); "
            "serving from the networkx projection until it is built",
            engine, db_path,
        )
        return NetworkXStore(graph, embedded=store)
    try:
        store.open()
        return store
    except Exception as exc:
        fallback_log(
            "%s database at %s cannot be opened (%s); falling back to the networkx backend (rebuild with `make db`)",
            engine, db_path, exc,
        )
        return NetworkXStore(graph, embedded=store)
