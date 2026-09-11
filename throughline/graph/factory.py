"""``make_store(settings, graph)``: pick the GraphStore backend from the settings.

Rules (docs/02-architecture.md section 2.2, docs/06-build-plan.md section 3.1):

* ``graph_backend = "networkx"`` -> ``NetworkXStore`` over the already-loaded ``ContextGraph``;
* ``"ladybug"`` (default) or ``"kuzu"`` -> ``LadybugStore`` opened read-only on ``settings.graph_db_path`` with the
  ``ContextGraph`` attached (search and fragment rendering then match the NetworkX backend exactly). When the
  database file is missing the store falls back to NetworkX with a warning (the API still works, minus Cypher).
  When the database is present but the engine cannot be imported/opened, the fallback happens only if the backend
  was *not* explicitly configured; an explicit ``GRAPH_BACKEND=ladybug|kuzu`` with a database present raises, so a
  broken deployment is visible rather than silently degraded;
* ``"neo4j"`` -> ``Neo4jStore`` when ``neo4j_uri`` is set and reachable; otherwise the same fallback logic.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from throughline.graph.context_graph import ContextGraph
from throughline.graph.networkx_store import NetworkXStore
from throughline.graph.store import GraphStore

log = logging.getLogger(__name__)

BACKENDS = ("ladybug", "kuzu", "networkx", "neo4j")


def _explicit(settings: Any, field: str) -> bool:
    fields_set = getattr(settings, "model_fields_set", None)
    return bool(fields_set) and field in fields_set


def make_store(settings: Any, graph: ContextGraph) -> GraphStore:
    backend = str(getattr(settings, "graph_backend", "ladybug") or "ladybug").lower()
    if backend not in BACKENDS:
        raise ValueError(f"unknown graph backend {backend!r}; expected one of {BACKENDS}")
    explicit = _explicit(settings, "graph_backend")

    if backend == "networkx":
        return NetworkXStore(graph)

    if backend == "neo4j":
        uri = getattr(settings, "neo4j_uri", None)
        if not uri:
            log.warning("graph_backend=neo4j but neo4j_uri is not set; falling back to the networkx backend")
            return NetworkXStore(graph)
        from throughline.graph.neo4j_store import Neo4jStore  # noqa: PLC0415 - optional dependency

        try:
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
            if explicit:
                raise
            log.warning("neo4j backend unavailable (%s); falling back to the networkx backend", exc)
            return NetworkXStore(graph)

    # embedded engines
    from throughline.graph.ladybug_store import LadybugStore  # noqa: PLC0415 - keeps the engine import lazy

    db_path = Path(getattr(settings, "graph_db_path"))
    db_present = db_path.exists()
    if not db_present:
        log.warning(
            "graph_backend=%s but no database at %s (run `throughline build-data`); falling back to the networkx backend",
            backend, db_path,
        )
        return NetworkXStore(graph)
    try:
        store = LadybugStore(db_path, engine=backend, graph=graph)
        store.open()
        return store
    except Exception as exc:
        if explicit:
            raise
        log.warning("%s backend unavailable (%s); falling back to the networkx backend", backend, exc)
        return NetworkXStore(graph)
