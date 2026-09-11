"""loader (load, rebuild-skip, exports) and factory (backend selection and fallbacks) tests."""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from throughline.graph import loader
from throughline.graph.context_graph import ContextGraph
from throughline.graph.factory import make_store
from throughline.graph.networkx_store import NetworkXStore
from throughline.graph.store import NotSupported
from throughline.schema import EDGE_TYPES, LABELS

from .conftest import EMBEDDED_ENGINE


def _settings(_explicit: set[str] | None = None, **overrides):
    """A settings stand-in; ``model_fields_set`` mimics pydantic-settings (fields provided via env/.env/kwargs) and
    defaults to every override unless ``_explicit`` narrows it."""
    base = {"graph_backend": "ladybug", "graph_db_path": Path("/nonexistent/graph.lbdb"), "neo4j_uri": None, "neo4j_user": "neo4j", "neo4j_password": None, "neo4j_database": "neo4j"}
    base.update(overrides)
    ns = SimpleNamespace(**base)
    ns.model_fields_set = set(overrides) if _explicit is None else set(_explicit)
    return ns


def test_load_context_graph_reads_manifest(mini_dir: Path, mini_graph: ContextGraph) -> None:
    assert mini_graph.build_info["fixture"] == "mini"
    assert loader.manifest_checksum(mini_dir) == mini_graph.build_info["checksum"]
    with pytest.raises(FileNotFoundError):
        loader.load_context_graph(mini_dir / "nope")


def test_plan_tables_dedupes_and_validates(mini_dir: Path, tmp_path: Path) -> None:
    nodes, edges, _ = loader.graph_paths(mini_dir)
    plan = loader.plan_tables(nodes, edges)
    assert plan.node_count == 59 and plan.edge_count == 97
    # a duplicate edge, a duplicate node, a dangling edge and a disallowed pair are skipped, not fatal
    bad_nodes = tmp_path / "nodes.jsonl"
    bad_edges = tmp_path / "edges.jsonl"
    node_lines = nodes.read_text(encoding="utf-8")
    first_node = node_lines.splitlines()[0]
    bad_nodes.write_text(node_lines + first_node + "\n", encoding="utf-8")
    edge_lines = edges.read_text(encoding="utf-8")
    first_edge = json.loads(edge_lines.splitlines()[0])
    dangling = dict(first_edge, dst="vm:aws:i-missing")
    wrong_pair = dict(first_edge, type="SAME_AS")  # CloudAccount -> X is not an allowed SAME_AS pair
    bad_edges.write_text(edge_lines + json.dumps(first_edge) + "\n" + json.dumps(dangling) + "\n" + json.dumps(wrong_pair) + "\n", encoding="utf-8")
    plan2 = loader.plan_tables(bad_nodes, bad_edges)
    assert plan2.duplicate_nodes == 1 and plan2.duplicate_edges == 1
    assert plan2.skipped_edges["dangling endpoint"] == 1
    assert sum(v for k, v in plan2.skipped_edges.items() if k.startswith("pair not allowed")) == 1
    assert plan2.node_count == 59 and plan2.edge_count == 97


def test_coerce_is_forgiving() -> None:
    assert loader.coerce("true", "BOOLEAN") == (True, False)
    assert loader.coerce(1, "DOUBLE") == (1.0, False)
    assert loader.coerce(2.0, "INT64") == (2, False)
    assert loader.coerce(2.5, "INT64") == (None, True)
    assert loader.coerce("x", "STRING[]") == (["x"], False)
    assert loader.coerce({"a": 1}, "JSON") == ('{"a":1}', False)
    assert loader.coerce("2026-09-10T02:11:45Z", "TIMESTAMP")[0].isoformat() == "2026-09-10T02:11:45"
    assert loader.coerce("not a date", "TIMESTAMP") == (None, True)
    assert loader.coerce(None, "INT64") == (None, False)


def test_build_embedded_db_skips_when_checksum_matches(mini_dir: Path, mini_graph: ContextGraph) -> None:
    store = NetworkXStore(mini_graph)
    assert loader.build_embedded_db(store, mini_dir) is False  # the loaded manifest already carries the checksum
    assert loader.build_embedded_db(store, mini_dir, force=True) is True
    assert len(mini_graph) == 59  # reloaded in place


def test_export_neo4j_import(mini_dir: Path, tmp_path: Path) -> None:
    result = loader.export_neo4j_import(mini_dir, tmp_path / "neo4j")
    out = Path(result["out_dir"])
    assert (out / "import.cypher").exists()
    script = (out / "import.cypher").read_text(encoding="utf-8")
    assert "CREATE CONSTRAINT node_id IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE" in script
    assert "LOAD CSV WITH HEADERS FROM 'file:///nodes_Alert.csv'" in script
    assert "MERGE (a)-[r:CAN_ACCESS]->(b)" in script
    assert "IN TRANSACTIONS OF 5000 ROWS" in script
    alerts = (out / "nodes_Alert.csv").read_text(encoding="utf-8").splitlines()
    assert alerts[0].startswith("id,name,source,source_id,first_seen,last_seen,confidence,")
    assert alerts[0].endswith(",props_json") and len(alerts) == 7
    rels = (out / "rels_SAME_AS.csv").read_text(encoding="utf-8").splitlines()
    assert rels[0].startswith("src,dst,source,first_seen,last_seen,confidence,method")
    assert len(rels) == 4


def test_export_bigquery_tables(mini_dir: Path, tmp_path: Path) -> None:
    result = loader.export_bigquery_tables(mini_dir, tmp_path / "bq", project="p", dataset="d")
    out = Path(result["out_dir"])
    assert set(result["node_tables"]) == set(LABELS)  # every label gets a (possibly empty) table
    sql = (out / "create_property_graph.sql").read_text(encoding="utf-8")
    assert "CREATE OR REPLACE PROPERTY GRAPH `p.d.throughline`" in sql
    for table in result["node_tables"]:
        assert f"`p.d.n_{table}`" in sql
    for table in result["edge_tables"]:
        assert f"`p.d.e_{table}`" in sql
    alerts = pq.read_table(out / result["node_tables"]["Alert"])
    assert alerts.num_rows == 6
    techniques_type = alerts.schema.field("techniques").type
    assert pa.types.is_list(techniques_type) and pa.types.is_string(techniques_type.value_type)
    assert pa.types.is_timestamp(alerts.schema.field("detected_at").type)
    same_as = pq.read_table(out / result["edge_tables"]["SAME_AS__Endpoint__VirtualMachine"])
    assert same_as.num_rows == 3 and same_as.column_names[:2] == ["src", "dst"]
    assert sum(result["edge_counts"].values()) == 97
    assert set(result["edge_counts"]) <= set(EDGE_TYPES)


def _skip_unless_embedded_engine_usable() -> None:
    if importlib.util.find_spec(EMBEDDED_ENGINE) is None:
        pytest.skip(f"{EMBEDDED_ENGINE} not installed")
    other = "kuzu" if EMBEDDED_ENGINE == "ladybug" else "ladybug"
    if other in sys.modules:
        pytest.skip(f"{other} already imported")


def test_factory_networkx_and_fallbacks(mini_graph: ContextGraph, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    plain = make_store(_settings(graph_backend="networkx"), mini_graph)
    assert isinstance(plain, NetworkXStore) and plain.embedded is None and "stands_in_for" not in plain.capabilities()
    # missing database -> networkx fallback even when the backend was explicit, logged at ERROR (explicit) ...
    with caplog.at_level("WARNING", logger="throughline.graph.factory"):
        store = make_store(_settings(graph_backend=EMBEDDED_ENGINE, graph_db_path=tmp_path / "missing.lbdb"), mini_graph)
    assert isinstance(store, NetworkXStore)
    assert any(r.levelname == "ERROR" and "no database" in r.message for r in caplog.records)
    caplog.clear()
    # ... and at WARNING when the backend was left at its default (not in model_fields_set)
    with caplog.at_level("WARNING", logger="throughline.graph.factory"):
        make_store(_settings(graph_backend=EMBEDDED_ENGINE, graph_db_path=tmp_path / "missing.lbdb", _explicit={"graph_db_path"}), mini_graph)
    assert any(r.levelname == "WARNING" and "no database" in r.message for r in caplog.records)
    # neo4j without a URI -> fallback; unreachable neo4j -> fallback, never an exception
    assert isinstance(make_store(_settings(graph_backend="neo4j"), mini_graph), NetworkXStore)
    if importlib.util.find_spec("neo4j") is not None:
        assert isinstance(make_store(_settings(graph_backend="neo4j", neo4j_uri="bolt://127.0.0.1:1"), mini_graph), NetworkXStore)
    with pytest.raises(ValueError):
        make_store(_settings(graph_backend="oracle"), mini_graph)


def test_factory_falls_back_when_engine_cannot_import(mini_graph: ContextGraph, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    from throughline.graph import ladybug_store

    def unavailable(engine: str):
        raise NotSupported(f"simulated: graph engine {engine!r} is not installed")

    monkeypatch.setattr(ladybug_store, "load_engine", unavailable)
    db_path = tmp_path / "graph.lbdb"
    db_path.write_bytes(b"not a database")  # even with a database present, an un-importable engine falls back
    with caplog.at_level("WARNING", logger="throughline.graph.factory"):
        store = make_store(_settings(graph_backend="kuzu", graph_db_path=db_path), mini_graph)
    assert isinstance(store, NetworkXStore) and store.embedded is None
    assert any("not available" in r.message and "simulated" in r.message for r in caplog.records)
    assert store.get_node("alert:falcon:ldt-a009") is not None  # the product keeps working on the projection


def test_factory_fresh_checkout_then_build_embedded_db(mini_dir: Path, mini_graph: ContextGraph, tmp_path: Path) -> None:
    """Fresh checkout: only the JSONL exists. make_store must return a working store and build_embedded_db on that
    store must create the embedded database (this is exactly what simulator/build.py does)."""
    _skip_unless_embedded_engine_usable()
    from throughline.graph.ladybug_store import LadybugStore

    data_dir = tmp_path / "data"
    shutil.copytree(mini_dir, data_dir / "graph")  # the generated layout: <data_dir>/graph/*.jsonl
    db_path = data_dir / "graph.lbdb"
    settings = _settings(graph_backend=EMBEDDED_ENGINE, graph_db_path=db_path)

    store = make_store(settings, mini_graph)
    assert isinstance(store, NetworkXStore)
    assert isinstance(store.embedded, LadybugStore) and store.embedded.db_path == db_path
    assert store.capabilities()["stands_in_for"] == EMBEDDED_ENGINE and store.capabilities()["cypher"] is False
    assert store.stored_manifest() is None  # nothing built yet -> build_embedded_db must build
    assert store.get_node("alert:falcon:ldt-a009")["label"] == "Alert"  # already serving from the projection

    assert loader.build_embedded_db(store, data_dir) is True
    assert db_path.exists() and (data_dir / "parquet" / "nodes" / "Alert.parquet").exists()
    assert store.stored_manifest()["checksum"] == mini_graph.build_info["checksum"]
    assert loader.build_embedded_db(store, data_dir) is False  # sidecar checksum matches now
    assert loader.build_embedded_db(store, data_dir, force=True) is True

    real = make_store(settings, mini_graph)
    assert isinstance(real, LadybugStore) and real.name == EMBEDDED_ENGINE
    assert real.get_node("alert:falcon:ldt-a009") == store.get_node("alert:falcon:ldt-a009")
    assert real.stats().total_nodes == len(mini_graph)
    real.close()

    # a database that exists but cannot be opened also falls back, keeping the embedded target for a rebuild
    db_path.write_bytes(b"garbage")
    broken = make_store(settings, mini_graph)
    assert isinstance(broken, NetworkXStore) and isinstance(broken.embedded, LadybugStore)
    assert loader.build_embedded_db(broken, data_dir, force=True) is True
    fixed = make_store(settings, mini_graph)
    assert isinstance(fixed, LadybugStore)
    fixed.close()


def test_factory_opens_embedded_database(mini_dir: Path, mini_graph: ContextGraph, tmp_path: Path) -> None:
    _skip_unless_embedded_engine_usable()
    from throughline.graph.ladybug_store import LadybugStore

    db_path = tmp_path / "graph.lbdb"
    builder = LadybugStore(db_path, engine=EMBEDDED_ENGINE, parquet_dir=tmp_path / "parquet")
    assert loader.build_embedded_db(builder, mini_dir) is True
    assert loader.build_embedded_db(builder, mini_dir) is False  # sidecar checksum matches
    store = make_store(_settings(graph_backend=EMBEDDED_ENGINE, graph_db_path=db_path), mini_graph)
    assert isinstance(store, LadybugStore) and store.name == EMBEDDED_ENGINE
    assert store.graph is mini_graph  # attached: search/fragments render through the projection
    assert [h.id for h in store.search("bas-01")] == [h.id for h in mini_graph.search("bas-01", limit=25)]
    fragment = store.neighborhood("alert:falcon:ldt-a009", depth=2)
    assert fragment.nodes == NetworkXStore(mini_graph).neighborhood("alert:falcon:ldt-a009", depth=2).nodes
    assert store.stats().build["checksum"] == mini_graph.build_info["checksum"]
    store.close()
