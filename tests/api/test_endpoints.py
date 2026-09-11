"""Every endpoint of docs/05-api-contract.md: status codes, response shapes (re-validated through the pydantic
models), limits, the error envelope, the SPA fallback, the chat SSE stream and the agent surface. Runs on the fixture
graph with ``FakeEngine`` / ``FakeStore`` injected into ``create_app`` - no data files, no database, no API key."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.api.fakes import FakeStore
from throughline.agent.analyst import Analyst
from throughline.agent.prompts import DEMO_QUESTIONS
from throughline.agent.tools import ToolRegistry
from throughline.api.app import create_app
from throughline.models import (
    AlertContext,
    AlertSummary,
    AnalystAnswer,
    AttackPathOut,
    BlastRadiusResult,
    ChatSession,
    ChatTurn,
    ContainmentSimulation,
    GraphFragment,
    Insight,
    NodeOut,
    RiskBreakdown,
    SearchHit,
    StatsOut,
    StorylineOut,
    TIContext,
)
from throughline.simulator import storyline_constants as C

API = "/api/v1"
A009 = "alert:falcon:ldt-a009"
A001 = "alert:falcon:ldt-a001"
N002 = "alert:cspm:iss-n002"
CROWN_JEWELS = {C.CARDHOLDER_VAULT, C.KYC_DOCS, C.CARDHOLDER_DB}
CONTRACT_TOOLS = {
    "search_entities", "get_entity", "get_neighborhood", "find_paths", "blast_radius", "attack_paths", "list_alerts", "get_alert",
    "get_alert_context", "explain_risk", "get_storyline", "list_storylines", "threat_intel_lookup", "exposed_hosts_with_exploited_vulns",
    "credential_joins", "alerts_reaching_crown_jewels", "identity_footprint", "simulate_containment", "run_cypher", "get_schema",
    "submit_answer",
}


# ----------------------------------------------------------------------------- helpers


def _error(resp, status: int, code: str) -> dict[str, Any]:
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert set(body) == {"error"}, body
    err = body["error"]
    assert err["code"] == code, err
    assert isinstance(err["message"], str) and err["message"]
    assert isinstance(err["details"], dict)
    return err


def _ok(resp) -> Any:
    assert resp.status_code == 200, resp.text
    return resp.json()


def parse_sse(text: str) -> list[tuple[str, Any]]:
    """``event: <type>`` + ``data: <json>`` blocks separated by blank lines (comments/pings start with ':')."""
    events: list[tuple[str, Any]] = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        etype, data = None, []
        for line in block.split("\n"):
            if line.startswith(":"):
                continue
            if line.startswith("event:"):
                etype = line[len("event:"):].strip()
            elif line.startswith("data:"):
                data.append(line[len("data:"):].strip())
        if etype:
            events.append((etype, json.loads("\n".join(data)) if data else {}))
    return events


def _walk_schemas(node: Any):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk_schemas(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_schemas(v)


# ----------------------------------------------------------------------------- meta


def test_health(client: TestClient, fixture_graph) -> None:
    body = _ok(client.get(f"{API}/health"))
    assert {"status", "backend", "total_nodes", "total_edges", "agent_mode", "model", "build"} <= set(body)
    assert body["status"] == "ok"
    assert body["backend"] == "fake-cypher"
    assert body["total_nodes"] == len(fixture_graph) and body["total_edges"] == fixture_graph.G.number_of_edges()
    assert body["analyst_mode"] == "offline"
    assert body["build"]["version"] and body["build"]["checksum"] == "fixture"


def test_stats(client: TestClient) -> None:
    stats = StatsOut.model_validate(_ok(client.get(f"{API}/stats")))
    assert stats.total_nodes > 0 and stats.node_counts["Alert"] == 17
    assert stats.capabilities["cypher"] is True and stats.backend == "fake-cypher"


def test_schema(client: TestClient) -> None:
    body = _ok(client.get(f"{API}/schema"))
    assert set(body) == {"categories", "labels", "edge_types"}
    labels = {lbl["name"]: lbl for lbl in body["labels"]}
    assert {"Alert", "Endpoint", "VirtualMachine", "IamRole", "StorageBucket", "ThreatActor"} <= set(labels)
    for lbl in labels.values():
        assert {"name", "category", "id_prefix", "columns"} <= set(lbl)
        assert lbl["category"] in body["categories"]
        assert all({"name", "type"} <= set(c) for c in lbl["columns"])
    edge_types = {et["name"]: et for et in body["edge_types"]}
    assert {"SAME_AS", "HAS_ROLE", "CAN_ASSUME", "CAN_ACCESS", "MATCHES_IOC"} <= set(edge_types)
    assert edge_types["SAME_AS"]["derived"] is True
    assert all(len(p) == 2 for p in edge_types["HAS_ROLE"]["pairs"])
    assert all({"name", "type"} <= set(c) for c in edge_types["CAN_ACCESS"]["columns"])


def test_dashboard(client: TestClient) -> None:
    body = _ok(client.get(f"{API}/dashboard"))
    assert {"kpis", "leaderboard_contextual", "leaderboard_vendor", "storylines", "alerts_by_band", "alerts_by_source", "coverage", "ti_pressure", "rerank_examples"} <= set(body)
    assert {"open_alerts", "critical_contextual", "storylines", "crown_jewels", "crown_jewels_at_risk", "internet_exposed_exploited", "endpoints", "endpoint_coverage_pct", "ioc_matches"} <= set(body["kpis"])
    top = [AlertSummary.model_validate(a) for a in body["leaderboard_contextual"]]
    assert 0 < len(top) <= 10 and top[0].id == A009
    assert [a.contextual_score for a in top] == sorted((a.contextual_score for a in top), reverse=True)
    vendor = [AlertSummary.model_validate(a) for a in body["leaderboard_vendor"]]
    assert [a.vendor_severity_rank for a in vendor] == sorted((a.vendor_severity_rank for a in vendor), reverse=True)
    for s in body["storylines"]:
        assert StorylineOut.model_validate(s).fragment is None
    assert set(body["alerts_by_band"]) == {"critical", "high", "medium", "low", "noise"}
    assert {"falcon", "cspm", "waf", "ids", "cloud-anomaly", "okta"} <= set(body["alerts_by_source"])
    assert {"vms_total", "vms_with_sensor", "vms_without_sensor_prod", "endpoints_total", "endpoints_resolved_to_vm"} <= set(body["coverage"])
    assert body["ti_pressure"] and {"actor_id", "actor_name", "sector_relevance", "campaigns", "ioc_matches", "exploited_cves_present", "alerts"} <= set(body["ti_pressure"][0])
    assert body["rerank_examples"] and {"alert_id", "title", "vendor_severity", "contextual_score", "vendor_rank_position", "contextual_rank_position"} <= set(body["rerank_examples"][0])


def test_openapi_and_docs_are_served(client: TestClient) -> None:
    spec = _ok(client.get("/api/openapi.json"))
    assert f"{API}/alerts" in spec["paths"] and f"{API}/chat/sessions/{{session_id}}/messages" in spec["paths"]
    assert client.get("/api/docs").status_code == 200


# ----------------------------------------------------------------------------- alerts & storylines


def test_list_alerts_default_ordering(client: TestClient) -> None:
    body = _ok(client.get(f"{API}/alerts"))
    assert set(body) == {"items", "total", "limit", "offset"}
    items = [AlertSummary.model_validate(a) for a in body["items"]]
    assert body["total"] == 17 == len(items) and body["limit"] == 50 and body["offset"] == 0
    assert items[0].id == A009 and items[0].contextual_rank_position == 1
    assert [a.contextual_score for a in items] == sorted((a.contextual_score for a in items), reverse=True)


def test_list_alerts_filters_sorts_and_paging(client: TestClient) -> None:
    medium = [AlertSummary.model_validate(a) for a in _ok(client.get(f"{API}/alerts", params={"severity": "medium", "source": "falcon"}))["items"]]
    assert medium and all(a.vendor_severity == "medium" and a.source_system == "falcon" for a in medium)
    noise = _ok(client.get(f"{API}/alerts", params={"band": "noise"}))["items"]
    assert noise and all(a["contextual_band"] == "noise" for a in noise)
    story = _ok(client.get(f"{API}/alerts", params={"storyline": C.STORYLINE_A}))["items"]
    assert story and all(a["storyline_id"] == C.STORYLINE_A for a in story)
    reach = _ok(client.get(f"{API}/alerts", params={"reaches_crown_jewel": "true"}))["items"]
    assert reach and all(a["reaches_crown_jewel"] for a in reach)
    on_path = _ok(client.get(f"{API}/alerts", params={"on_attack_path": "true"}))["items"]
    assert on_path and all(a["on_attack_path"] for a in on_path)
    by_host = _ok(client.get(f"{API}/alerts", params={"q": "bas-01"}))["items"]
    assert {a["id"] for a in by_host} == {A009, "alert:falcon:ldt-a007", "alert:falcon:ldt-a008x"}
    vendor = _ok(client.get(f"{API}/alerts", params={"sort": "vendor"}))["items"]
    ranks = [a["vendor_severity_rank"] for a in vendor]
    assert ranks == sorted(ranks, reverse=True) and vendor[0]["id"] == N002
    by_time = _ok(client.get(f"{API}/alerts", params={"sort": "time", "order": "asc"}))["items"]
    times = [a["detected_at"] for a in by_time]
    assert times == sorted(times)
    page = _ok(client.get(f"{API}/alerts", params={"limit": 2, "offset": 1}))
    full = _ok(client.get(f"{API}/alerts"))["items"]
    assert page["limit"] == 2 and page["offset"] == 1 and [a["id"] for a in page["items"]] == [a["id"] for a in full[1:3]]


def test_list_alerts_limits_and_argument_errors(client: TestClient) -> None:
    err = _error(client.get(f"{API}/alerts", params={"limit": 501}), 400, "limit_exceeded")
    assert err["details"] == {"param": "limit", "max": 500, "value": 501}
    _error(client.get(f"{API}/alerts", params={"limit": 0}), 400, "invalid_argument")
    _error(client.get(f"{API}/alerts", params={"offset": -1}), 400, "invalid_argument")
    _error(client.get(f"{API}/alerts", params={"sort": "bogus"}), 400, "invalid_argument")
    _error(client.get(f"{API}/alerts", params={"order": "sideways"}), 400, "invalid_argument")
    err = _error(client.get(f"{API}/alerts", params={"limit": "abc"}), 400, "invalid_argument")
    assert err["details"]["errors"] and err["details"]["errors"][0]["loc"][-1] == "limit"


def test_alert_detail_and_not_found(client: TestClient) -> None:
    body = _ok(client.get(f"{API}/alerts/{A009}"))
    assert set(body) == {"alert", "flat_view"}
    alert = AlertSummary.model_validate(body["alert"])
    assert alert.id == A009 and alert.vendor_severity == "medium" and alert.contextual_score == 92
    assert body["flat_view"]["Severity"] == "Medium" and body["flat_view"]["Hostname"] == "bas-01"
    err = _error(client.get(f"{API}/alerts/alert:falcon:does-not-exist"), 404, "not_found")
    assert "does-not-exist" in err["message"]


def test_alert_context_risk_and_insights(client: TestClient) -> None:
    ctx = AlertContext.model_validate(_ok(client.get(f"{API}/alerts/{A009}/context")))
    assert ctx.alert.id == A009 and ctx.storyline is not None and ctx.storyline.id == C.STORYLINE_A
    assert ctx.blast_radius is not None and {r.node.id for r in ctx.blast_radius.crown_jewels} >= CROWN_JEWELS
    assert ctx.attack_paths and ctx.evidence.layout_hint == "path"
    assert ctx.evidence.nodes and A009 in ctx.evidence.node_ids()
    risk = RiskBreakdown.model_validate(_ok(client.get(f"{API}/alerts/{A009}/risk")))
    assert risk.subject_id == A009 and risk.contextual_score == 92 and risk.band == "critical"
    assert {f.key for f in risk.factors} == {"severity", "exposure", "privilege", "data", "threat_intel", "correlation"}
    assert any(r.startswith("attack_path_floor") for r in risk.rails)
    body = _ok(client.get(f"{API}/alerts/{A009}/insights"))
    insights = [Insight.model_validate(i) for i in body["insights"]]
    assert {i.kind for i in insights} >= {"blast_radius", "credential_join"}
    _error(client.get(f"{API}/alerts/alert:nope/context"), 404, "not_found")
    _error(client.get(f"{API}/alerts/alert:nope/risk"), 404, "not_found")
    _error(client.get(f"{API}/alerts/alert:nope/insights"), 404, "not_found")


def test_storylines(client: TestClient) -> None:
    items = [StorylineOut.model_validate(s) for s in _ok(client.get(f"{API}/storylines"))["items"]]
    assert [s.id for s in items] == [C.STORYLINE_A, C.STORYLINE_B]
    assert all(s.fragment is None for s in items)
    detail = StorylineOut.model_validate(_ok(client.get(f"{API}/storylines/{C.STORYLINE_A}")))
    assert detail.fragment is not None and detail.fragment.layout_hint == "storyline" and detail.fragment.paths
    assert [s.order for s in detail.stages] == sorted(s.order for s in detail.stages) and detail.stage_count == 7
    assert set(detail.crown_jewels_reached) == CROWN_JEWELS and A009 in detail.alert_ids
    _error(client.get(f"{API}/storylines/storyline:derived:nope"), 404, "not_found")


# ----------------------------------------------------------------------------- graph


def test_search(client: TestClient) -> None:
    hits = [SearchHit.model_validate(h) for h in _ok(client.get(f"{API}/search", params={"q": "bas-01"}))["hits"]]
    assert {C.EP_BASTION, C.BASTION_VM} <= {h.id for h in hits}
    vms = _ok(client.get(f"{API}/search", params={"q": "bas-01", "labels": "VirtualMachine", "limit": 5}))["hits"]
    assert vms and all(h["label"] == "VirtualMachine" for h in vms) and len(vms) <= 5
    _error(client.get(f"{API}/search", params={"q": "   "}), 400, "invalid_argument")
    _error(client.get(f"{API}/search", params={"q": "x", "limit": 101}), 400, "limit_exceeded")
    _error(client.get(f"{API}/search", params={"q": "x", "labels": "NotALabel"}), 400, "invalid_argument")


def test_node_card_and_batch(client: TestClient) -> None:
    body = _ok(client.get(f"{API}/nodes/{C.EP_BASTION}"))
    assert set(body) == {"node", "degree", "edge_type_counts", "alerts", "threat_intel"}
    node = NodeOut.model_validate(body["node"])
    assert node.id == C.EP_BASTION and node.label == "Endpoint"
    assert set(body["degree"]) == {"in", "out"} and body["edge_type_counts"]["SAME_AS"] == 1
    assert {AlertSummary.model_validate(a).id for a in body["alerts"]} >= {A009}
    slashed = _ok(client.get(f"{API}/nodes/{C.DB_READER_SECRET}"))  # ids may contain '/'
    assert slashed["node"]["id"] == C.DB_READER_SECRET
    with_ti = _ok(client.get(f"{API}/nodes/{A001}"))
    assert TIContext.model_validate(with_ti["threat_intel"]).matches
    _error(client.get(f"{API}/nodes/vm:aws:i-nope"), 404, "not_found")
    batch = _ok(client.post(f"{API}/nodes/batch", json={"ids": [C.BASTION_VM, C.CARDHOLDER_VAULT, "vm:aws:i-nope", C.BASTION_VM]}))
    nodes = [NodeOut.model_validate(n) for n in batch["nodes"]]
    assert [n.id for n in nodes] == [C.BASTION_VM, C.CARDHOLDER_VAULT]
    assert "crown_jewel" in nodes[1].tags
    err = _error(client.post(f"{API}/nodes/batch", json={"ids": [f"vm:aws:i-{i}" for i in range(201)]}), 400, "limit_exceeded")
    assert err["details"]["max"] == 200


def test_neighborhood(client: TestClient) -> None:
    frag = GraphFragment.model_validate(_ok(client.get(f"{API}/graph/neighborhood", params={"id": C.BASTION_VM, "depth": 1})))
    assert frag.focus[0] == C.BASTION_VM and frag.layout_hint == "neighborhood"
    assert {C.EP_BASTION, C.BASTION_ROLE} <= set(frag.node_ids())
    assert all(e.src in set(frag.node_ids()) and e.dst in set(frag.node_ids()) for e in frag.edges)
    roles = GraphFragment.model_validate(_ok(client.get(f"{API}/graph/neighborhood", params={"id": C.BASTION_VM, "labels": "IamRole"})))
    assert all(n.label == "IamRole" for n in roles.nodes if n.id != C.BASTION_VM) and C.BASTION_ROLE in roles.node_ids()
    capped = GraphFragment.model_validate(_ok(client.get(f"{API}/graph/neighborhood", params={"id": C.BASTION_ROLE, "depth": 2, "max_nodes": 3})))
    assert len(capped.nodes) <= 3 and C.BASTION_ROLE in capped.node_ids()
    _error(client.get(f"{API}/graph/neighborhood", params={"id": C.BASTION_VM, "depth": 4}), 400, "limit_exceeded")
    _error(client.get(f"{API}/graph/neighborhood", params={"id": C.BASTION_VM, "max_nodes": 301}), 400, "limit_exceeded")
    _error(client.get(f"{API}/graph/neighborhood", params={"id": C.BASTION_VM, "direction": "sideways"}), 400, "invalid_argument")
    _error(client.get(f"{API}/graph/neighborhood", params={"id": C.BASTION_VM, "edge_types": "NOT_AN_EDGE"}), 400, "invalid_argument")
    _error(client.get(f"{API}/graph/neighborhood", params={"id": "vm:aws:i-nope"}), 404, "not_found")
    _error(client.get(f"{API}/graph/neighborhood"), 400, "invalid_argument")


def test_paths(client: TestClient) -> None:
    frag = GraphFragment.model_validate(_ok(client.get(f"{API}/graph/paths", params={"src": A009, "dst": C.CARDHOLDER_VAULT})))
    assert frag.layout_hint == "path" and frag.paths and {A009, C.CARDHOLDER_VAULT} <= set(frag.focus)
    path = frag.paths[0]
    assert path.node_ids[0] == A009 and path.node_ids[-1] == C.CARDHOLDER_VAULT and path.hops == len(path.node_ids) - 1
    assert set(path.node_ids) <= set(frag.node_ids())
    _error(client.get(f"{API}/graph/paths", params={"src": A009, "dst": C.CARDHOLDER_VAULT, "max_hops": 9}), 400, "limit_exceeded")
    _error(client.get(f"{API}/graph/paths", params={"src": A009, "dst": C.CARDHOLDER_VAULT, "k": 6}), 400, "limit_exceeded")
    _error(client.get(f"{API}/graph/paths", params={"src": "alert:nope", "dst": C.CARDHOLDER_VAULT}), 404, "not_found")


def test_blast_radius(client: TestClient) -> None:
    br = BlastRadiusResult.model_validate(_ok(client.get(f"{API}/graph/blast-radius", params={"id": A009, "depth": 5})))
    assert br.root_id == A009 and br.depth == 5 and br.reached_count > 0
    assert {r.node.id for r in br.crown_jewels} == CROWN_JEWELS and {r.node.id for r in br.secrets} == {C.DB_READER_SECRET, C.HSM_SECRET}
    assert br.fragment.layout_hint == "blast_radius" and A009 in br.fragment.node_ids()
    assert C.MARKETING_BUCKET not in br.fragment.node_ids()
    _error(client.get(f"{API}/graph/blast-radius", params={"id": A009, "depth": 7}), 400, "limit_exceeded")
    _error(client.get(f"{API}/graph/blast-radius", params={"id": A009, "max_nodes": 2001}), 400, "limit_exceeded")
    _error(client.get(f"{API}/graph/blast-radius", params={"id": "vm:aws:i-nope"}), 404, "not_found")


def test_attack_paths(client: TestClient) -> None:
    body = _ok(client.get(f"{API}/graph/attack-paths", params={"through": A001, "target": C.CARDHOLDER_VAULT, "k": 3}))
    assert set(body) == {"paths", "fragment"}
    paths = [AttackPathOut.model_validate(p) for p in body["paths"]]
    assert paths and paths[0].entry_id == A001 and paths[0].target_id == C.CARDHOLDER_VAULT and len(paths[0].stages) == 7
    frag = GraphFragment.model_validate(body["fragment"])
    assert frag.layout_hint == "path" and frag.focus[:2] == [A001, C.CARDHOLDER_VAULT] and {C.WKS_DANA, C.EP_BASTION, C.BASTION_ROLE} <= set(frag.node_ids())
    empty = _ok(client.get(f"{API}/graph/attack-paths", params={"through": N002}))
    assert empty["paths"] == [] and GraphFragment.model_validate(empty["fragment"]).nodes == []
    _error(client.get(f"{API}/graph/attack-paths", params={"k": 6}), 400, "limit_exceeded")


def test_cypher(client: TestClient, store: FakeStore) -> None:
    body = _ok(client.post(f"{API}/graph/cypher", json={"query": "MATCH (v:VirtualMachine)-[r:HAS_ROLE]->(x) RETURN v, r, x"}))
    assert set(body) == {"columns", "rows", "elapsed_ms", "truncated", "fragment"}
    assert body["columns"] == ["vm", "r", "role"] and len(body["rows"]) == 2 and body["truncated"] is False
    frag = GraphFragment.model_validate(body["fragment"])
    assert {C.BASTION_VM, C.BASTION_ROLE, C.EDGE_VM, C.EDGE_ROLE} == set(frag.node_ids())
    assert {e.id for e in frag.edges} == {f"{C.BASTION_VM}|HAS_ROLE|{C.BASTION_ROLE}", f"{C.EDGE_VM}|HAS_ROLE|{C.EDGE_ROLE}"}
    one = _ok(client.post(f"{API}/graph/cypher", json={"query": "MATCH (n) RETURN n", "row_limit": 1}))
    assert len(one["rows"]) == 1 and one["truncated"] is True
    assert store.calls[-1] == ("cypher", {"query": "MATCH (n) RETURN n", "row_limit": 1})
    _error(client.post(f"{API}/graph/cypher", json={"query": "MATCH (n) DELETE n"}), 400, "query_rejected")
    _error(client.post(f"{API}/graph/cypher", json={"query": "MATCH (n) RETURN SLEEP(n)"}), 504, "timeout")
    _error(client.post(f"{API}/graph/cypher", json={"query": "   "}), 400, "invalid_argument")
    _error(client.post(f"{API}/graph/cypher", json={"query": "MATCH (n) RETURN n", "row_limit": 501}), 400, "limit_exceeded")
    _error(client.post(f"{API}/graph/cypher", json={}), 400, "invalid_argument")


def test_cypher_not_supported_on_networkx_backend(fixture_graph, engine, settings, tmp_path: Path) -> None:
    plain = FakeStore(fixture_graph, cypher=False)
    analyst = Analyst(ToolRegistry(engine, plain, settings=settings), settings, mode="offline")
    app = create_app(graph=fixture_graph, store=plain, engine=engine, analyst=analyst, settings=settings, web_dist=tmp_path / "missing")
    with TestClient(app) as c:
        _error(c.post(f"{API}/graph/cypher", json={"query": "MATCH (n) RETURN n"}), 501, "not_supported")
        assert c.get(f"{API}/health").json()["backend"] == "fake"
        # the agent tool degrades cleanly instead of failing
        body = _ok(c.post(f"{API}/agent/tools/run_cypher", json={"query": "MATCH (n) RETURN n"}))
        assert body["result"]["status"] == "not_supported" and body["evidence"] is None


# ----------------------------------------------------------------------------- threat intel


def test_ti_actors_and_details(client: TestClient) -> None:
    items = _ok(client.get(f"{API}/threat-intel/actors"))["items"]
    assert [NodeOut.model_validate(i["actor"]).id for i in items][:2] == [C.ACTOR_CJ, C.ACTOR_HT]
    assert {"actor", "campaigns", "sector_relevance", "active", "ioc_matches", "matched_alerts", "exploited_cves_present", "affected_assets"} <= set(items[0])
    assert A001 in items[0]["matched_alerts"] and items[0]["ioc_matches"] > 0
    rel = [i["sector_relevance"] for i in items]
    assert rel == sorted(rel, reverse=True)
    actor = _ok(client.get(f"{API}/threat-intel/actors/{C.ACTOR_CJ}"))
    assert {"actor", "campaigns", "malware", "techniques", "indicators", "reports", "context", "affected"} <= set(actor)
    assert NodeOut.model_validate(actor["actor"]).id == C.ACTOR_CJ and TIContext.model_validate(actor["context"]).matches
    assert GraphFragment.model_validate(actor["affected"]).nodes and {NodeOut.model_validate(c).id for c in actor["campaigns"]} == {C.CAMPAIGN_EMBERCAST}
    campaign = _ok(client.get(f"{API}/threat-intel/campaigns/{C.CAMPAIGN_SALTWORKS}"))
    assert NodeOut.model_validate(campaign["actor"]).id == C.ACTOR_HT and TIContext.model_validate(campaign["context"])
    _error(client.get(f"{API}/threat-intel/actors/actor:ti:nobody"), 404, "not_found")
    _error(client.get(f"{API}/threat-intel/campaigns/campaign:ti:nothing"), 404, "not_found")


def test_ti_reports_lookup_and_exposure(client: TestClient) -> None:
    reports = [NodeOut.model_validate(r) for r in _ok(client.get(f"{API}/threat-intel/reports"))["items"]]
    assert [r.id for r in reports] == [C.REPORT_SALTWORKS, C.REPORT_EMBERCAST]  # newest first
    report = _ok(client.get(f"{API}/threat-intel/reports/{C.REPORT_EMBERCAST}"))
    assert {"report", "actors", "campaigns", "malware", "cves", "indicators", "techniques", "impact"} <= set(report)
    assert {"matched_alerts", "exposed_assets", "summary"} <= set(report["impact"])
    assert {AlertSummary.model_validate(a).id for a in report["impact"]["matched_alerts"]} >= {A001, "alert:cloud-anomaly:ca-a017"}
    _error(client.get(f"{API}/threat-intel/reports/report:ti:TL-0000-0000"), 404, "not_found")
    by_name = TIContext.model_validate(_ok(client.get(f"{API}/threat-intel/lookup", params={"value": "Cinder Jackal"})))
    assert {a.id for a in by_name.actors} == {C.ACTOR_CJ} and by_name.matches and by_name.sector_relevance == 0.9
    by_hash = TIContext.model_validate(_ok(client.get(f"{API}/threat-intel/lookup", params={"value": C.HASH_MAPLELOADER})))
    assert {m.matched_node_id for m in by_hash.matches} == {A001}
    by_cve = TIContext.model_validate(_ok(client.get(f"{API}/threat-intel/lookup", params={"value": "CVE-2021-44228"})))
    assert {v.id for v in by_cve.exploited_vulnerabilities} == {C.LOG4SHELL}
    _error(client.get(f"{API}/threat-intel/lookup", params={"value": ""}), 400, "invalid_argument")
    rows = _ok(client.get(f"{API}/threat-intel/exposure"))["items"]
    assert {"vm", "cve", "exploitation_status", "actors", "campaigns", "sector_relevance", "contextual_score", "crown_jewels_reachable", "has_edr_sensor", "alert_ids"} <= set(rows[0])
    vm_ids = [NodeOut.model_validate(r["vm"]).id for r in rows]
    assert vm_ids[0] == C.EDGE_VM and {C.STG_EDGE_VM, C.DEV_LOG4J_VM} <= set(vm_ids) and C.BASTION_VM not in vm_ids
    assert [r["contextual_score"] for r in rows] == sorted((r["contextual_score"] for r in rows), reverse=True)
    assert rows[0]["exploitation_status"] == "mass_exploitation" and {a["id"] for a in rows[0]["actors"]} == {C.ACTOR_HT}
    assert len(_ok(client.get(f"{API}/threat-intel/exposure", params={"sector_only": "false"}))["items"]) >= len(rows)


# ----------------------------------------------------------------------------- investigations


def test_credential_joins(client: TestClient) -> None:
    body = _ok(client.get(f"{API}/investigate/credential-joins"))
    assert {"items", "fragment"} <= set(body)
    item = body["items"][0]
    assert {"credential", "stolen_by_alert", "endpoint", "principal", "used_in_events", "derived_credentials", "first_use", "source_ips"} <= set(item)
    assert NodeOut.model_validate(item["credential"]).id == C.CRED_BASTION_KEY
    assert AlertSummary.model_validate(item["stolen_by_alert"]).id == A009 and NodeOut.model_validate(item["endpoint"]).id == C.EP_BASTION
    assert {NodeOut.model_validate(e).id for e in item["used_in_events"]} >= {C.CLOUDEVENTS_A["a010"][0], C.CLOUDEVENTS_A["a012"][0]}
    assert item["source_ips"] == [C.ATTACKER_EGRESS_IP]
    frag = GraphFragment.model_validate(body["fragment"])
    assert C.CRED_BASTION_KEY in frag.focus and frag.layout_hint == "path"


def test_alerts_reaching_crown_jewels(client: TestClient) -> None:
    body = _ok(client.get(f"{API}/investigate/alerts-reaching-crown-jewels"))
    assert set(body) == {"items", "jewels", "fragment"}
    ids = {AlertSummary.model_validate(a).id for a in body["items"]}
    assert {"alert:falcon:ldt-a007", "alert:falcon:ldt-a008x", A009, "alert:cloud-anomaly:ca-a017", "alert:falcon:ldt-b002", "alert:falcon:ldt-b003", "alert:waf:waf-b001"} <= ids
    assert not ({"alert:falcon:ldt-n001", N002, "alert:falcon:ldt-n003"} & ids)
    assert {NodeOut.model_validate(j).id for j in body["jewels"]} == CROWN_JEWELS
    GraphFragment.model_validate(body["fragment"])
    one = _ok(client.get(f"{API}/investigate/alerts-reaching-crown-jewels", params={"jewel_id": C.CARDHOLDER_VAULT}))
    assert [j["id"] for j in one["jewels"]] == [C.CARDHOLDER_VAULT] and "alert:waf:waf-b001" not in {a["id"] for a in one["items"]}
    pci = _ok(client.get(f"{API}/investigate/alerts-reaching-crown-jewels", params={"classification": "PCI"}))
    assert {j["id"] for j in pci["jewels"]} == {C.CARDHOLDER_VAULT, C.CARDHOLDER_DB}


def test_identity_footprint_and_data_path(client: TestClient) -> None:
    br = BlastRadiusResult.model_validate(_ok(client.get(f"{API}/investigate/identity-footprint", params={"id": C.BASTION_ROLE})))
    assert br.root_id == C.BASTION_ROLE and {r.node.id for r in br.crown_jewels} == CROWN_JEWELS
    assert {r.node.id for r in br.identities} == {C.PROD_READER_ROLE} and C.SHARED_LOGS_BUCKET in {r.node.id for r in br.data_stores}
    _error(client.get(f"{API}/investigate/identity-footprint"), 400, "invalid_argument")
    _error(client.get(f"{API}/investigate/identity-footprint", params={"id": "role:aws:1:Nope"}), 404, "not_found")
    body = _ok(client.get(f"{API}/investigate/medium-alerts-with-data-path"))
    items = [AlertSummary.model_validate(a) for a in body["items"]]
    assert [a.id for a in items] == [A009, "alert:falcon:ldt-a007", "alert:falcon:ldt-b002"]
    assert all(a.vendor_severity == "medium" and a.source_system == "falcon" for a in items)
    GraphFragment.model_validate(body["fragment"])
    any_source = _ok(client.get(f"{API}/investigate/medium-alerts-with-data-path", params={"source": "all"}))
    assert "alert:waf:waf-b001" in {a["id"] for a in any_source["items"]}
    low = _ok(client.get(f"{API}/investigate/medium-alerts-with-data-path", params={"severity": "low"}))
    assert {a["id"] for a in low["items"]} == {"alert:falcon:ldt-a008x", "alert:falcon:ldt-b003"}


def test_containment(client: TestClient) -> None:
    body = {"target_ids": [C.EP_BASTION, C.BASTION_ROLE], "actions": ["isolate_endpoint", "rotate_role_credentials"]}
    sim = ContainmentSimulation.model_validate(_ok(client.post(f"{API}/investigate/containment", json=body)))
    assert sim.paths_cut >= 1 and C.STORYLINE_A in sim.storylines_contained and set(sim.crown_jewels_protected) == CROWN_JEWELS
    breaks = " ".join(f"{b.node_id} {b.name} {b.impact}" for b in sim.breaks).lower()
    assert "settlement" in breaks and "ssm" in breaks
    assert any("trust policy" in r.lower() for r in sim.recommendations) and any("expired" in r for r in sim.residual_risks)
    _error(client.post(f"{API}/investigate/containment", json={"target_ids": [], "actions": ["isolate_endpoint"]}), 400, "invalid_argument")
    _error(client.post(f"{API}/investigate/containment", json={"target_ids": [C.EP_BASTION], "actions": ["format_disk"]}), 400, "invalid_argument")
    _error(client.post(f"{API}/investigate/containment", json={"target_ids": [C.EP_BASTION], "actions": []}), 400, "invalid_argument")
    _error(client.post(f"{API}/investigate/containment", json={"target_ids": [f"vm:aws:i-{i}" for i in range(51)], "actions": ["block_ip"]}), 400, "limit_exceeded")
    _error(client.post(f"{API}/investigate/containment", json={"target_ids": ["vm:aws:i-nope"], "actions": ["isolate_endpoint"]}), 404, "not_found")


# ----------------------------------------------------------------------------- chat


def test_chat_sessions(client: TestClient) -> None:
    created = ChatSession.model_validate(_ok(client.post(f"{API}/chat/sessions", json={"context": {"alert_id": A009, "selected_node_ids": [C.BASTION_VM], "empty": None}})))
    assert created.turns == [] and created.context == {"alert_id": A009, "selected_node_ids": [C.BASTION_VM]}
    fetched = ChatSession.model_validate(_ok(client.get(f"{API}/chat/sessions/{created.id}")))
    assert fetched.id == created.id and fetched.created_at == created.created_at
    bare = ChatSession.model_validate(_ok(client.post(f"{API}/chat/sessions")))
    assert bare.context == {}
    _error(client.get(f"{API}/chat/sessions/nope"), 404, "not_found")
    _error(client.post(f"{API}/chat/sessions/nope/messages", json={"content": "hi"}), 404, "not_found")
    _error(client.post(f"{API}/chat/sessions/{created.id}/messages", json={"content": "   "}), 400, "invalid_argument")
    _error(client.post(f"{API}/chat/sessions/{created.id}/messages", json={"content": "hi", "mode": "turbo"}), 400, "invalid_argument")


def test_chat_suggestions(client: TestClient) -> None:
    assert _ok(client.get(f"{API}/chat/suggestions"))["questions"] == DEMO_QUESTIONS
    with_alert = _ok(client.get(f"{API}/chat/suggestions", params={"alert_id": A009}))["questions"]
    assert A009 in with_alert[0] and set(DEMO_QUESTIONS) <= set(with_alert)
    with_node = _ok(client.get(f"{API}/chat/suggestions", params={"node_id": C.BASTION_VM, "storyline_id": C.STORYLINE_A}))["questions"]
    assert any(C.BASTION_VM in q for q in with_node) and any(C.STORYLINE_A in q for q in with_node)
    assert len(with_node) == len(set(with_node))


def test_chat_message_sse_stream(client: TestClient) -> None:
    session = _ok(client.post(f"{API}/chat/sessions", json={}))
    question = DEMO_QUESTIONS[0]
    with client.stream("POST", f"{API}/chat/sessions/{session['id']}/messages", json={"content": question}) as resp:
        assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/event-stream")
        events = parse_sse(resp.read().decode("utf-8"))
    types = [t for t, _ in events]
    assert types[0] == "session" and types[-1] == "done" and types.count("answer") == 1
    assert types.count("tool_call") >= 1 and types.count("tool_result") >= 1 and types.count("evidence") >= 1 and "text_delta" in types
    session_ev = events[0][1]
    assert session_ev == {"session_id": session["id"], "mode": "offline", "model": None}
    calls = [d for t, d in events if t == "tool_call"]
    results = [d for t, d in events if t == "tool_result"]
    assert all({"id", "name", "arguments"} <= set(c) for c in calls) and all({"id", "name", "summary", "duration_ms"} <= set(r) for r in results)
    assert {c["id"] for c in calls} == {r["id"] for r in results}
    assert "blast_radius" in {c["name"] for c in calls}
    for _, frag in [(t, d) for t, d in events if t == "evidence"]:
        GraphFragment.model_validate(frag)
    answer = AnalystAnswer.model_validate(next(d for t, d in events if t == "answer"))
    assert answer.mode == "offline" and answer.intent == "blast_radius_of_alert" and answer.findings
    assert {A009, C.CARDHOLDER_VAULT} <= set(answer.evidence.node_ids())
    assert "".join(d["text"] for t, d in events if t == "text_delta").strip() == answer.narrative_md.strip()
    done = events[-1][1]
    assert done["mode"] == "offline" and done["model"] is None and done["tool_calls"] == len(answer.tool_calls) and done["elapsed_ms"] >= 0
    recorded = ChatSession.model_validate(_ok(client.get(f"{API}/chat/sessions/{session['id']}")))
    assert [t.role for t in recorded.turns] == ["user", "assistant"] and recorded.turns[0].content == question
    assert recorded.turns[1].answer is not None and recorded.turns[1].answer.intent == "blast_radius_of_alert"


def test_chat_message_non_streaming_with_context(client: TestClient) -> None:
    session = _ok(client.post(f"{API}/chat/sessions", json={"context": {"alert_id": A009}}))
    body = _ok(client.post(f"{API}/chat/sessions/{session['id']}/messages", params={"stream": "false"}, json={"content": "Why is this alert risky?"}))
    assert set(body) == {"turn"}
    turn = ChatTurn.model_validate(body["turn"])
    assert turn.role == "assistant" and turn.answer is not None and turn.content == turn.answer.narrative_md
    assert turn.answer.mode == "offline" and turn.answer.intent == "why_is_alert_risky" and A009 in turn.answer.evidence.node_ids()
    # a later message can update the canvas context
    body = _ok(client.post(f"{API}/chat/sessions/{session['id']}/messages", params={"stream": "false"}, json={"content": "Summarize this storyline", "context": {"storyline_id": C.STORYLINE_B}}))
    assert ChatTurn.model_validate(body["turn"]).answer.intent == "summarize_storyline"
    recorded = ChatSession.model_validate(_ok(client.get(f"{API}/chat/sessions/{session['id']}")))
    assert len(recorded.turns) == 4 and recorded.context["storyline_id"] == C.STORYLINE_B


# ----------------------------------------------------------------------------- agent surface


def test_agent_tools_manifest(client: TestClient) -> None:
    tools = _ok(client.get(f"{API}/agent/tools"))["tools"]
    names = {t["name"] for t in tools}
    assert CONTRACT_TOOLS <= names and len(names) == len(tools)
    for tool in tools:
        assert {"name", "description", "input_schema"} <= set(tool) and tool["strict"] is True and len(tool["description"]) > 20
        schema = tool["input_schema"]
        assert schema["type"] == "object" and schema["additionalProperties"] is False and isinstance(schema["required"], list)
        assert set(schema["required"]) <= set(schema["properties"])
        for sub in _walk_schemas(schema):
            if sub.get("type") == "object":
                assert sub.get("additionalProperties") is False and isinstance(sub.get("required"), list), tool["name"]
            assert not ({"minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems"} & set(sub)), tool["name"]
    limit = next(t for t in tools if t["name"] == "search_entities")["input_schema"]["properties"]["limit"]
    assert limit["type"] == "integer" and "25" in limit["description"]


def test_agent_invoke_tool(client: TestClient) -> None:
    body = _ok(client.post(f"{API}/agent/tools/blast_radius", json={"id": A009, "depth": 5}))
    assert {"result", "evidence", "elapsed_ms"} <= set(body) and body["elapsed_ms"] >= 0
    frag = GraphFragment.model_validate(body["evidence"])
    assert frag.layout_hint == "blast_radius" and len(frag.nodes) <= 100 and frag.focus[0] == A009
    assert {j["node"]["id"] for j in body["result"]["crown_jewels"]} == CROWN_JEWELS and "fragment" not in body["result"]
    hits = _ok(client.post(f"{API}/agent/tools/search_entities", json={"query": "LarkspurBastionSSMRole", "labels": ["IamRole"]}))
    assert hits["result"]["hits"][0]["id"] == C.BASTION_ROLE and hits["evidence"] is None
    storylines = _ok(client.post(f"{API}/agent/tools/list_storylines"))
    assert storylines["result"]["count"] == 2 and GraphFragment.model_validate(storylines["evidence"]).nodes
    clamped = _ok(client.post(f"{API}/agent/tools/list_alerts", json={"limit": 500}))
    assert clamped["result"]["returned"] == 17 and clamped["result"]["total"] == 17
    _error(client.post(f"{API}/agent/tools/not_a_tool", json={}), 404, "not_found")
    err = _error(client.post(f"{API}/agent/tools/search_entities", json={"query": "x", "bogus": 1}), 400, "invalid_argument")
    assert err["details"]["errors"]
    _error(client.post(f"{API}/agent/tools/get_neighborhood", json={"id": C.BASTION_VM, "labels": ["Nope"]}), 400, "invalid_argument")
    _error(client.post(f"{API}/agent/tools/get_alert", json={"alert_id": "alert:falcon:nope"}), 404, "not_found")
    submitted = _ok(client.post(f"{API}/agent/tools/submit_answer", json={"narrative_md": "## Findings\n- x", "findings": [], "evidence_ids": [A009], "confidence": 0.4}))
    assert submitted["result"]["accepted"] is True and submitted["result"]["answer"]["mode"] == "llm"


def test_agent_answer(client: TestClient) -> None:
    answer = AnalystAnswer.model_validate(_ok(client.post(f"{API}/agent/answer", json={"question": DEMO_QUESTIONS[7], "mode": "offline"})))
    assert answer.mode == "offline" and answer.intent == "credential_joins" and answer.findings and answer.tool_calls
    assert {C.CRED_BASTION_KEY, C.CRED_PROD_KEY} <= set(answer.evidence.node_ids())
    with_ctx = AnalystAnswer.model_validate(_ok(client.post(f"{API}/agent/answer", json={"question": "What can an attacker reach from here?", "context": {"alert_id": A009}})))
    assert with_ctx.intent == "blast_radius_of_alert" and A009 in with_ctx.evidence.focus
    _error(client.post(f"{API}/agent/answer", json={"question": "  "}), 400, "invalid_argument")
    _error(client.post(f"{API}/agent/answer", json={"question": "x", "mode": "turbo"}), 400, "invalid_argument")


# ----------------------------------------------------------------------------- static UI / SPA


def test_spa_fallback_and_static_files(client: TestClient) -> None:
    root = client.get("/")
    assert root.status_code == 200 and root.headers["content-type"].startswith("text/html") and "throughline-spa" in root.text
    deep = client.get("/alerts/alert:falcon:ldt-a009/context")
    assert deep.status_code == 200 and "throughline-spa" in deep.text  # client-side route -> index.html
    asset = client.get("/assets/app.js")
    assert asset.status_code == 200 and "throughline" in asset.text
    assert client.get("/favicon.svg").status_code == 200
    _error(client.get(f"{API}/does-not-exist"), 404, "not_found")  # API misses never fall back to the SPA
    _error(client.get("/api/nothing-here"), 404, "not_found")


def test_root_without_web_dist(fixture_graph, store, engine, analyst, settings, tmp_path: Path) -> None:
    app = create_app(graph=fixture_graph, store=store, engine=engine, analyst=analyst, settings=settings, web_dist=tmp_path / "missing")
    with TestClient(app) as c:
        body = _ok(c.get("/"))
        assert body["api"] == API and body["health"] == f"{API}/health" and "ui" in body
        _error(c.get("/alerts"), 404, "not_found")
        assert c.get(f"{API}/health").json()["status"] == "ok"


@pytest.mark.parametrize(
    "method,path,status,code",
    [
        ("GET", f"{API}/alerts/alert:falcon:nope", 404, "not_found"),
        ("GET", f"{API}/alerts?limit=9999", 400, "limit_exceeded"),
        ("GET", f"{API}/graph/neighborhood?id=vm:aws:i-0b4571e2c9a8f3d01&direction=up", 400, "invalid_argument"),
        ("POST", f"{API}/graph/cypher", 400, "query_rejected"),
        ("PUT", f"{API}/alerts", 405, "invalid_argument"),
    ],
)
def test_error_envelope(client: TestClient, method: str, path: str, status: int, code: str) -> None:
    kwargs = {"json": {"query": "CREATE (n:Thing) RETURN n"}} if method == "POST" else {}
    _error(client.request(method, path, **kwargs), status, code)
