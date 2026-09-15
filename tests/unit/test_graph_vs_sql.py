"""Smoke test for scripts/graph_vs_sql.py (docs/11-graph-benefits.md): the graph tier and the SQL-over-graph tier
must agree on the bastion alert's blast radius, and the benchmark traversal must match the product's reach."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("duckdb")

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA = REPO_ROOT / "data" / "generated"
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

pytestmark = pytest.mark.skipif(not (DATA / "graph" / "nodes.jsonl").exists(), reason="run the simulator build first")


@pytest.fixture(scope="module")
def tiers():
    import graph_vs_sql as b

    nodes, edges = b.load_records(DATA)
    return b, b.GraphTier(nodes, edges), b.NormSQLTier(nodes, edges, threads=2)


def test_graph_and_sql_agree_on_blast_radius(tiers) -> None:
    b, gt, nt = tiers
    graph_reach, settled = gt.reach(b.ALERT_A009, b.DEPTH, "full")
    sql_reach = nt.reach(b.ALERT_A009)
    assert set(graph_reach) == set(sql_reach)
    assert graph_reach and settled <= 50  # a local neighbourhood, not the estate
    product = gt.ctx.reach(b.ALERT_A009, b.DEPTH, "full", max_nodes=100_000)
    assert set(graph_reach) == set(product.ids())


def test_reverse_reach_finds_the_bastion_alert(tiers) -> None:
    b, gt, nt = tiers
    graph_alerts = {n for n in gt.reach(b.C.CARDHOLDER_VAULT, b.DEPTH, "full", reverse=True)[0] if gt.label(n) == "Alert"}
    sql_alerts = {n for n in nt.reach(b.C.CARDHOLDER_VAULT, reverse=True) if n.startswith("alert:")}
    assert b.ALERT_A009 in graph_alerts
    assert graph_alerts == sql_alerts


def test_shortest_path_agrees(tiers) -> None:
    b, gt, nt = tiers
    regulated = {n for n in gt.g.G.nodes if gt.is_regulated_data(n)}
    path, _ = gt.shortest(b.ALERT_A001, lambda n: n in regulated)
    sql_path = nt.shortest(b.ALERT_A001, "n.label IN ('StorageBucket','Database','Secret') AND list_has_any(CAST(json_extract(n.props, '$.data_classifications') AS VARCHAR[]), ['PCI','PHI','PII','SECRETS'])")
    assert path and sql_path and len(path) == len(sql_path)
    assert path[0] == sql_path[0] == b.ALERT_A001
