"""Shared fixtures for the API / agent tests: the storyline-shaped fixture graph, the fake engine and store, an
offline ``Analyst`` and a FastAPI ``TestClient`` over ``create_app`` with everything injected (no data files, no
graph database, no API key)."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.api.fakes import FakeEngine, FakeStore, build_fixture_graph
from throughline.agent.analyst import Analyst
from throughline.agent.tools import ToolRegistry
from throughline.api.app import create_app
from throughline.config import Settings
from throughline.graph.context_graph import ContextGraph


@pytest.fixture(scope="session")
def fixture_graph() -> ContextGraph:
    return build_fixture_graph()


@pytest.fixture(scope="session")
def engine(fixture_graph: ContextGraph) -> FakeEngine:
    return FakeEngine(fixture_graph)


@pytest.fixture(scope="session")
def store(fixture_graph: ContextGraph) -> FakeStore:
    return FakeStore(fixture_graph, cypher=True)


@pytest.fixture(scope="session")
def settings() -> Settings:
    # never read a developer's .env or key: the suite must be deterministic and offline
    return Settings(_env_file=None, anthropic_api_key=None, agent_mode="auto", agent_max_tool_calls=12, agent_max_rounds=8)


@pytest.fixture(scope="session")
def registry(engine: FakeEngine, store: FakeStore, settings: Settings) -> ToolRegistry:
    return ToolRegistry(engine, store, settings=settings)


@pytest.fixture(scope="session")
def analyst(registry: ToolRegistry, settings: Settings) -> Analyst:
    return Analyst(registry, settings, mode="offline")


@pytest.fixture(scope="session")
def web_dist(tmp_path_factory: pytest.TempPathFactory) -> Path:
    dist = tmp_path_factory.mktemp("web-dist")
    (dist / "index.html").write_text("<!doctype html><html><body><div id='root'>throughline-spa</div></body></html>", encoding="utf-8")
    (dist / "assets").mkdir()
    (dist / "assets" / "app.js").write_text("console.log('throughline');", encoding="utf-8")
    (dist / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")
    return dist


@pytest.fixture(scope="session")
def app(fixture_graph: ContextGraph, store: FakeStore, engine: FakeEngine, analyst: Analyst, settings: Settings, web_dist: Path):
    return create_app(graph=fixture_graph, store=store, engine=engine, analyst=analyst, settings=settings, web_dist=web_dist)


@pytest.fixture(scope="session")
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c
