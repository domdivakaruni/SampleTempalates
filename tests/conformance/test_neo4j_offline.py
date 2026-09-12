"""Neo4j store checks that need no server: DDL from the registry, row flattening for UNWIND batches, the shared
read-only gate running before any driver call, and the schema summary. The live conformance run happens in
``test_stores.py`` when ``NEO4J_URI`` is set."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from throughline.graph import loader
from throughline.graph.store import QueryRejected
from throughline.schema import LABELS

pytestmark = pytest.mark.skipif(importlib.util.find_spec("neo4j") is None, reason="neo4j driver not installed")


@pytest.fixture(scope="module")
def store():
    from throughline.graph.neo4j_store import Neo4jStore

    return Neo4jStore("bolt://127.0.0.1:1", user="neo4j", password="x", database="neo4j")


def test_constraints_cover_every_label(store) -> None:
    statements = store.constraint_statements()
    assert "CREATE CONSTRAINT node_id IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE" in statements
    for lbl in LABELS.values():
        assert any(f"FOR (n:{lbl.name}) REQUIRE n.id IS UNIQUE" in s for s in statements)


def test_row_flattening_keeps_everything_storable(store, mini_dir: Path) -> None:
    nodes_path, edges_path, _ = loader.graph_paths(mini_dir)
    plan = loader.plan_tables(nodes_path, edges_path)
    for label, rows in plan.node_rows.items():
        for rec in rows:
            row = store._node_row(label, rec)
            assert row["id"] == rec["id"] and row["props"]["label"] == label
            assert json.loads(row["props"]["props_json"]) == (rec.get("props") or {})
            for key, value in row["props"].items():
                assert value is not None, key
                if isinstance(value, list):
                    assert all(isinstance(v, str) for v in value) or all(isinstance(v, int | float) for v in value)
                else:
                    assert isinstance(value, str | int | float | bool) or hasattr(value, "isoformat"), key
    alert = next(r for r in plan.node_rows["Alert"] if r["id"] == "alert:falcon:ldt-a009")
    props = store._node_row("Alert", alert)["props"]
    assert props["techniques"] == ["T1552.005"] and props["detected_at"].isoformat().startswith("2026-09-10T02:11:45")
    assert isinstance(props["raw"], str) and json.loads(props["raw"])["severity"] == "medium"
    (etype, _, _), rows = next(iter(sorted(plan.edge_rows.items())))
    edge_row = store._edge_row(etype, rows[0])
    assert {"src", "dst", "props"} == set(edge_row) and "props_json" in edge_row["props"]


def test_gate_runs_before_the_driver(store) -> None:
    with pytest.raises(QueryRejected):
        store.run_readonly_cypher("CREATE (n:Alert {id: 'x'})")
    with pytest.raises(QueryRejected):
        store.run_readonly_cypher("MATCH (a)-[*]->(b) RETURN a")
    with pytest.raises(RuntimeError, match="not open"):
        store.get_node("alert:falcon:ldt-a009")


def test_capabilities_and_schema(store) -> None:
    caps = store.capabilities()
    assert caps["cypher"] is True and caps["multi_label_patterns"] is True and caps["dialect"] == "neo4j"
    summary = store.schema_summary()
    assert summary["dialect"] == "neo4j" and 6 <= len(summary["example_queries"]) <= 8
    assert any("toLower" in ex["query"] for ex in summary["example_queries"])
