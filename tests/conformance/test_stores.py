"""GraphStore conformance: every available backend must give the NetworkX reference's answers on the mini fixture."""
from __future__ import annotations

import time

import pytest

from throughline.graph.context_graph import ContextGraph
from throughline.graph.networkx_store import NetworkXStore
from throughline.graph.store import (
    BaseStore,
    CypherResult,
    GraphStore,
    NotSupported,
    QueryRejected,
    QueryTimeout,
    edge_record_from_flat,
    record_from_flat,
)
from throughline.schema import validate_node
from throughline.simulator import storyline_constants as sc

A009 = sc.ALERT_A["a009"][0]
STORYLINE_PATH_QUERY = (
    "MATCH (a:Alert)-[:ON_ENDPOINT]->(e:Endpoint)-[:SAME_AS]->(v:VirtualMachine)-[:HAS_ROLE]->(r:IamRole)"
    "-[:CAN_ASSUME*0..2]->(r2:IamRole)-[:CAN_ACCESS]->(b:StorageBucket) WHERE b.crown_jewel RETURN a.id, b.name LIMIT 20"
)
NEIGHBORHOOD_CASES = [
    pytest.param(A009, 1, None, "both", None, id="a009-depth1"),
    pytest.param(A009, 2, None, "both", None, id="a009-depth2"),
    pytest.param(A009, 3, None, "both", None, id="a009-depth3"),
    pytest.param(A009, 3, ["ON_ENDPOINT", "SAME_AS", "HAS_ROLE", "CAN_ASSUME", "CAN_ACCESS"], "out", None, id="a009-attack-path-out"),
    pytest.param(sc.CARDHOLDER_VAULT, 2, None, "in", None, id="vault-in"),
    pytest.param(sc.CARDHOLDER_VAULT, 2, None, "in", ["IamRole", "CloudEvent", "IamPolicy"], id="vault-in-labels"),
    pytest.param(sc.BASTION_VM, 2, None, "both", ["Endpoint", "IamRole", "Alert"], id="bastion-labels"),
    pytest.param(sc.EDGE_VM, 2, ["VULNERABLE_TO", "EXPLOITS", "HAS_VULNERABILITY"], "both", None, id="edge-vuln-types"),
]


def _cypher(store: GraphStore) -> bool:
    return bool(store.capabilities().get("cypher"))


# ----------------------------------------------------------------------------- fixture sanity


def test_fixture_is_valid(mini_graph: ContextGraph) -> None:
    problems = [p for rec in mini_graph.iter_node_records() for p in validate_node(rec)]
    assert problems == []
    assert mini_graph.validate() == []
    counts = mini_graph.build_info["counts"]
    assert counts["total_nodes"] == len(mini_graph) >= 50
    assert counts["total_edges"] == mini_graph.G.number_of_edges() >= 70
    assert mini_graph.count_by_label() == counts["nodes"]
    assert mini_graph.count_by_edge_type() == counts["edges"]


def test_base_store_rendering_mirrors_context_graph(mini_graph: ContextGraph) -> None:
    """The record -> NodeOut/EdgeOut helpers used by database-only backends must match ContextGraph exactly."""
    for nid, attrs in mini_graph.G.nodes(data=True):
        assert BaseStore.record_to_node_out(record_from_flat(attrs)) == mini_graph.node_out(nid)
    for u, v, data in mini_graph.G.edges(data=True):
        assert BaseStore.edge_record_to_out(edge_record_from_flat(u, v, data)) == mini_graph.edge_out(u, v, data)


# ----------------------------------------------------------------------------- protocol surface


def test_store_satisfies_protocol(store: GraphStore) -> None:
    assert isinstance(store, GraphStore)
    caps = store.capabilities()
    for key in ("cypher", "multi_label_patterns", "shortest_path", "read_only"):
        assert key in caps
    assert isinstance(store.name, str) and store.name


def test_get_node_matches_reference(store: GraphStore, reference: NetworkXStore, mini_graph: ContextGraph) -> None:
    for nid in sorted(mini_graph.G.nodes):
        assert store.get_node(nid) == reference.get_node(nid), nid
    assert store.get_node("vm:aws:does-not-exist") is None
    assert store.get_node("nonsense-without-prefix") is None


def test_get_nodes_matches_reference(store: GraphStore, reference: NetworkXStore) -> None:
    ids = [A009, sc.BASTION_VM, "group:okta:missing", sc.CARDHOLDER_VAULT, "bogus", A009]
    got = store.get_nodes(ids)
    assert got == reference.get_nodes(ids)
    assert [r["id"] for r in got] == [A009, sc.BASTION_VM, sc.CARDHOLDER_VAULT]
    assert store.get_nodes([]) == []


def test_search_finds_bastion_endpoint_and_vm(store: GraphStore) -> None:
    hits = store.search("bas-01")
    ids = [h.id for h in hits]
    assert sc.EP_BASTION in ids and sc.BASTION_VM in ids
    assert all(h.category for h in hits)
    only_endpoints = store.search("bas-01", labels=["Endpoint"])
    assert [h.id for h in only_endpoints] == [sc.EP_BASTION]
    assert store.search("   ") == []


@pytest.mark.parametrize(("node_id", "depth", "edge_types", "direction", "labels"), NEIGHBORHOOD_CASES)
def test_neighborhood_matches_k_hop_and_reference(
    store: GraphStore, reference: NetworkXStore, mini_graph: ContextGraph, node_id: str, depth: int, edge_types, direction: str, labels
) -> None:
    fragment = store.neighborhood(node_id, depth=depth, edge_types=edge_types, direction=direction, labels=labels)
    expected = mini_graph.k_hop(node_id, depth=depth, edge_types=edge_types, direction=direction, node_labels=labels)
    assert set(fragment.node_ids()) == set(expected)
    assert fragment.focus == [node_id]
    assert fragment.nodes[0].id == node_id
    ref = reference.neighborhood(node_id, depth=depth, edge_types=edge_types, direction=direction, labels=labels)
    assert fragment.node_ids() == ref.node_ids()  # start first, then (hop, id)
    assert [n.model_dump() for n in fragment.nodes] == [n.model_dump() for n in ref.nodes]
    assert {e.id for e in fragment.edges} == {e.id for e in ref.edges}
    assert sorted((e.model_dump() for e in fragment.edges), key=lambda e: e["id"]) == sorted((e.model_dump() for e in ref.edges), key=lambda e: e["id"])
    assert fragment.truncated is False and fragment.total_nodes == len(fragment.nodes)


def test_neighborhood_depth2_equals_k_hop_set(store: GraphStore, mini_graph: ContextGraph) -> None:
    fragment = store.neighborhood(A009, depth=2)
    assert set(fragment.node_ids()) == set(mini_graph.k_hop(A009, depth=2))
    # the storyline core is within two hops of the pivotal alert
    for nid in (sc.EP_BASTION, sc.BASTION_VM, sc.CRED_BASTION_KEY, sc.INCIDENT_BASTION):
        assert nid in fragment.node_ids()


def test_neighborhood_truncation_is_deterministic(store: GraphStore, reference: NetworkXStore) -> None:
    fragment = store.neighborhood(A009, depth=3, max_nodes=5)
    ref = reference.neighborhood(A009, depth=3, max_nodes=5)
    assert fragment.truncated is True and ref.truncated is True
    assert fragment.node_ids() == ref.node_ids() and len(fragment.nodes) == 5
    assert fragment.total_nodes == ref.total_nodes
    assert all(e.src in set(fragment.node_ids()) and e.dst in set(fragment.node_ids()) for e in fragment.edges)


def test_neighborhood_missing_node_and_bad_arguments(store: GraphStore) -> None:
    empty = store.neighborhood("vm:aws:i-nope", depth=1)
    assert empty.nodes == [] and empty.edges == [] and empty.focus == ["vm:aws:i-nope"]
    with pytest.raises(ValueError):
        store.neighborhood(A009, depth=0)
    with pytest.raises(ValueError):
        store.neighborhood(A009, direction="sideways")
    with pytest.raises(ValueError):
        store.neighborhood(A009, edge_types=["NOT_AN_EDGE"])
    with pytest.raises(ValueError):
        store.neighborhood(A009, labels=["NotALabel"])


def test_stats_match_fixture_counts(store: GraphStore, mini_graph: ContextGraph) -> None:
    stats = store.stats()
    counts = mini_graph.build_info["counts"]
    assert stats.node_counts == counts["nodes"]
    assert stats.edge_counts == counts["edges"]
    assert stats.total_nodes == counts["total_nodes"] and stats.total_edges == counts["total_edges"]
    assert stats.backend == store.name
    assert stats.capabilities == store.capabilities()


def test_schema_summary_lists_registry(store: GraphStore) -> None:
    summary = store.schema_summary()
    labels = {lbl["name"]: lbl for lbl in summary["labels"]}
    assert {"Alert", "VirtualMachine", "StorageBucket", "Group"} <= set(labels)
    assert {"name", "type"} <= set(labels["Alert"]["columns"][0])
    assert any(c["name"] == "techniques" and c["type"] == "STRING[]" for c in labels["Alert"]["columns"])
    edge_types = {et["name"]: et for et in summary["edge_types"]}
    assert ["Endpoint", "VirtualMachine"] in edge_types["SAME_AS"]["pairs"]
    assert edge_types["CAN_ACCESS"]["derived"] is True
    assert summary["backend"] == store.name and "dialect" in summary and "example_queries" in summary
    if _cypher(store):
        assert 6 <= len(summary["example_queries"]) <= 8
        assert all("query" in ex and "title" in ex for ex in summary["example_queries"])


# ----------------------------------------------------------------------------- Cypher


def test_networkx_has_no_cypher(reference: NetworkXStore) -> None:
    assert reference.capabilities()["cypher"] is False
    with pytest.raises(NotSupported):
        reference.run_readonly_cypher("MATCH (n) RETURN n LIMIT 1")


def test_storyline_path_query(store: GraphStore) -> None:
    if not _cypher(store):
        pytest.skip("backend has no Cypher")
    result = store.run_readonly_cypher(STORYLINE_PATH_QUERY)
    assert isinstance(result, CypherResult)
    assert result.columns == ["a.id", "b.name"]
    pairs = {tuple(row) for row in result.rows}
    assert (A009, "larkspur-cardholder-vault") in pairs
    assert (A009, "larkspur-kyc-documents") in pairs
    assert result.truncated is False and result.elapsed_ms >= 0


def test_cypher_rejects_writes_and_unbounded_patterns(store: GraphStore) -> None:
    if not _cypher(store):
        pytest.skip("backend has no Cypher")
    with pytest.raises(QueryRejected):
        store.run_readonly_cypher("CREATE (n:Alert {id:'x'})")
    with pytest.raises(QueryRejected):
        store.run_readonly_cypher("MATCH (a:Alert) SET a.title = 'x' RETURN a")
    with pytest.raises(QueryRejected):
        store.run_readonly_cypher("MATCH (a)-[*]->(b) RETURN a.id LIMIT 5")
    with pytest.raises(QueryRejected):
        store.run_readonly_cypher("MATCH (a)-[*1..9]->(b) RETURN a.id LIMIT 5")
    with pytest.raises(QueryRejected):  # engine-level error surfaces as a rejection the agent can fix
        store.run_readonly_cypher("MATCH (a:Alert) RETURN a.no_such_property")


def test_cypher_limit_is_clamped(store: GraphStore, mini_graph: ContextGraph) -> None:
    if not _cypher(store):
        pytest.skip("backend has no Cypher")
    result = store.run_readonly_cypher("MATCH (n) RETURN n.id LIMIT 100000", row_limit=10)
    assert len(result.rows) == 10 and result.truncated is True
    everything = store.run_readonly_cypher("MATCH (n) RETURN n.id ORDER BY n.id", row_limit=500)
    assert len(everything.rows) == len(mini_graph) and everything.truncated is False
    assert everything.rows[0] == [sorted(mini_graph.G.nodes)[0]]


def test_cypher_renders_graph_values(store: GraphStore) -> None:
    if not _cypher(store):
        pytest.skip("backend has no Cypher")
    result = store.run_readonly_cypher(
        "MATCH (a:Alert {id: $id})-[e:ON_ENDPOINT]->(m) RETURN a, e, m, a.detected_at, a.techniques, a.confidence LIMIT 5", {"id": A009}
    )
    assert len(result.rows) == 1
    node, rel, other, detected, techniques, confidence = result.rows[0]
    assert node == {"id": A009, "label": "Alert", "name": "Cloud instance metadata service credential access from interactive shell"}
    assert rel == {"src": A009, "type": "ON_ENDPOINT", "dst": sc.EP_BASTION}
    assert other == {"id": sc.EP_BASTION, "label": "Endpoint", "name": "bas-01"}
    assert detected == sc.ALERT_A["a009"][1]  # ISO-8601 Z string
    assert techniques == ["T1552.005"]
    assert confidence == 1.0


def test_cypher_slow_query_completes_or_times_out(store: GraphStore) -> None:
    if not _cypher(store):
        pytest.skip("backend has no Cypher")
    t0 = time.perf_counter()
    try:
        result = store.run_readonly_cypher("MATCH (a)-[*1..5]-(b) RETURN count(*)", timeout_ms=1000)
        assert result.rows and result.rows[0][0] >= 0
    except QueryTimeout:
        pass
    assert time.perf_counter() - t0 < 6.0


def test_example_queries_run(store: GraphStore) -> None:
    if not _cypher(store):
        pytest.skip("backend has no Cypher")
    for example in store.schema_summary()["example_queries"]:
        result = store.run_readonly_cypher(example["query"], example.get("params"), row_limit=50)
        assert isinstance(result.columns, list)
