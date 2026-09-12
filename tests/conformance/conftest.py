"""Shared fixtures for the GraphStore conformance suite.

Backends are parametrized over what this environment can start:

* ``networkx`` -- always (it is also the *reference* every other backend is compared against);
* ``ladybug`` -- when the ``ladybug`` package imports; the store is built into a session temp dir **without** a
  ``ContextGraph`` attached so the database-only code paths (record conversion, Cypher search, fragment
  rendering) are what gets tested;
* ``kuzu`` -- never in the same process as ladybug (the engines clash at the native level). Run the suite on Kuzu
  in its own process with ``THROUGHLINE_GRAPH_ENGINE=kuzu pytest tests/conformance -q``; ladybug is then skipped;
* ``neo4j`` -- only when ``NEO4J_URI`` (and optionally ``NEO4J_USER`` / ``NEO4J_PASSWORD`` / ``NEO4J_DATABASE``) is set;
  the fixture graph is (re)built into that database.

Slow tests (the 20k-node build) run only with ``THROUGHLINE_RUN_SLOW=1``.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from throughline.graph import loader
from throughline.graph.context_graph import ContextGraph
from throughline.graph.networkx_store import NetworkXStore
from throughline.graph.store import GraphStore

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "data" / "fixtures" / "mini"
EMBEDDED_ENGINE = os.environ.get("THROUGHLINE_GRAPH_ENGINE", "ladybug").lower()
BACKENDS = ("networkx", "ladybug", "kuzu", "neo4j")
RUN_SLOW = os.environ.get("THROUGHLINE_RUN_SLOW") == "1"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "slow: long-running build/scale tests (enable with THROUGHLINE_RUN_SLOW=1)")


def engine_available(engine: str) -> bool:
    return importlib.util.find_spec(engine) is not None


@pytest.fixture(scope="session")
def mini_dir() -> Path:
    return FIXTURE_DIR


@pytest.fixture(scope="session")
def mini_graph(mini_dir: Path) -> ContextGraph:
    return loader.load_context_graph(mini_dir)


@pytest.fixture(scope="session")
def reference(mini_graph: ContextGraph) -> NetworkXStore:
    """The NetworkX backend over the fixture: the semantics every other backend must reproduce."""
    return NetworkXStore(mini_graph)


def make_embedded_store(engine: str, tmp_dir: Path, mini_dir: Path, graph: ContextGraph | None = None):
    from throughline.graph.ladybug_store import LadybugStore

    store = LadybugStore(tmp_dir / f"graph.{engine}", engine=engine, graph=graph, parquet_dir=tmp_dir / "parquet")
    loader.build_embedded_db(store, mini_dir)
    store.open()
    return store


@pytest.fixture(scope="session", params=BACKENDS)
def store(request: pytest.FixtureRequest, mini_dir: Path, mini_graph: ContextGraph, tmp_path_factory: pytest.TempPathFactory) -> Iterator[GraphStore]:
    backend = request.param
    if backend == "networkx":
        yield NetworkXStore(mini_graph)
        return
    if backend in ("ladybug", "kuzu"):
        if backend != EMBEDDED_ENGINE:
            pytest.skip(
                f"{backend} is not run in the same process as {EMBEDDED_ENGINE} (native clash); "
                f"run `THROUGHLINE_GRAPH_ENGINE={backend} pytest tests/conformance` separately"
            )
        if not engine_available(backend):
            pytest.skip(f"{backend} is not installed")
        other = "kuzu" if backend == "ladybug" else "ladybug"
        if other in sys.modules:
            pytest.skip(f"{other} already imported in this process")
        embedded = make_embedded_store(backend, tmp_path_factory.mktemp(f"{backend}-db"), mini_dir)
        yield embedded
        embedded.close()
        return
    if backend == "neo4j":
        uri = os.environ.get("NEO4J_URI")
        if not uri:
            pytest.skip("NEO4J_URI not set")
        from throughline.graph.neo4j_store import Neo4jStore

        neo = Neo4jStore(
            uri,
            user=os.environ.get("NEO4J_USER", "neo4j"),
            password=os.environ.get("NEO4J_PASSWORD"),
            database=os.environ.get("NEO4J_DATABASE", "neo4j"),
        )
        neo.open()
        loader.build_embedded_db(neo, mini_dir, force=True)
        yield neo
        neo.close()
        return
    raise AssertionError(f"unknown backend {backend}")
