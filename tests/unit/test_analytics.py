"""Unit tests for the analytics library (Agent C) on the miniature storyline fixture.

The fixture (``tests/fixtures/analytics_fixture.py``) is docs/04-storyline.md in about 300 nodes; ``enrich()`` runs
once per module and the ``AnalyticsEngine`` is exercised against the ground truth of docs/04 section 2.2, 3, 4 and 6
and the API shapes of docs/05 and docs/06 section 3.2.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.fixtures import analytics_fixture as fx  # noqa: E402
from throughline.analytics import semantics as sem  # noqa: E402
from throughline.analytics.engine import AnalyticsEngine  # noqa: E402
from throughline.analytics.materialize import enrich  # noqa: E402
from throughline.analytics.semantics import RULES, Semantics  # noqa: E402
from throughline.graph.context_graph import ContextGraph, split_edge_id  # noqa: E402
from throughline.models import (  # noqa: E402
    AlertContext,
    AlertSummary,
    AttackPathOut,
    BlastRadiusResult,
    ContainmentSimulation,
    GraphFragment,
    Insight,
    ReachedNode,
    RiskBreakdown,
    StorylineOut,
    TIContext,
)
from throughline.simulator import storyline_constants as C  # noqa: E402

A = {k: v[0] for k, v in C.ALERT_A.items()}
B = {k: v[0] for k, v in C.ALERT_B.items()}
N = {k: v[0] for k, v in C.ALERT_N.items()}
CROWN_JEWELS = {C.CARDHOLDER_VAULT, C.KYC_DOCS, C.CARDHOLDER_DB}
SECRETS = {C.DB_READER_SECRET, C.HSM_SECRET}
STORYLINE_A_ALERTS = {A[k] for k in ("a001", "a002", "a003", "a004", "a005", "a006", "a007", "a008x", "a009", "a017")}
STORYLINE_B_ALERTS = {B["b001"], B["b002"], B["b003"]}
DASHBOARD_KEYS = {"kpis", "leaderboard_contextual", "leaderboard_vendor", "storylines", "alerts_by_band", "alerts_by_source", "coverage", "ti_pressure", "rerank_examples"}
KPI_KEYS = {"open_alerts", "critical_contextual", "storylines", "crown_jewels", "crown_jewels_at_risk", "internet_exposed_exploited", "endpoints", "endpoint_coverage_pct", "ioc_matches"}
COVERAGE_KEYS = {"vms_total", "vms_with_sensor", "vms_without_sensor_prod", "endpoints_total", "endpoints_resolved_to_vm"}
TI_PRESSURE_KEYS = {"actor_id", "actor_name", "sector_relevance", "campaigns", "ioc_matches", "exploited_cves_present", "alerts"}
RERANK_KEYS = {"alert_id", "title", "vendor_severity", "contextual_score", "vendor_rank_position", "contextual_rank_position"}


# ----------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def enriched() -> dict[str, Any]:
    graph = fx.build_fixture_graph()
    assert graph.validate() == []
    t0 = time.perf_counter()
    report = enrich(graph)
    elapsed = time.perf_counter() - t0
    assert graph.validate() == []
    return {"graph": graph, "report": report, "elapsed": elapsed}


@pytest.fixture(scope="module")
def graph(enriched: dict[str, Any]) -> ContextGraph:
    return enriched["graph"]


@pytest.fixture(scope="module")
def engine(graph: ContextGraph) -> AnalyticsEngine:
    return AnalyticsEngine(graph)


def _snapshot(g: ContextGraph) -> tuple[list[str], list[str]]:
    nodes = sorted(json.dumps(r, sort_keys=True, default=str) for r in g.iter_node_records())
    edges = sorted(json.dumps(r, sort_keys=True, default=str) for r in g.iter_edge_records())
    return nodes, edges


def _edge_exists(g: ContextGraph, eid: str) -> bool:
    src, etype, dst = split_edge_id(eid)
    if src not in g or dst not in g:
        return False
    if g.first_edge(src, dst, etype) is not None:
        return True
    # implicit credential move (StorageBucket.contains_credentials_for / Secret.grants_access_to)
    attrs = g.node(src) or {}
    implicit = list(attrs.get("contains_credentials_for") or []) + list(attrs.get("grants_access_to") or [])
    return etype == "UNLOCKS" and dst in implicit


def _check_ids(g: ContextGraph, ids: list[str], where: str) -> None:
    missing = [i for i in ids if i not in g]
    assert not missing, f"{where}: unknown node ids {missing[:5]}"


def _check_edge_ids(g: ContextGraph, ids: list[str], where: str) -> None:
    missing = [i for i in ids if not _edge_exists(g, i)]
    assert not missing, f"{where}: unknown edge ids {missing[:5]}"


def _check_fragment(g: ContextGraph, frag: GraphFragment, where: str) -> None:
    _check_ids(g, frag.node_ids(), where)
    _check_edge_ids(g, [e.id for e in frag.edges], where)
    _check_ids(g, frag.focus, where)
    for p in frag.paths:
        _check_ids(g, p.node_ids, where)
        _check_edge_ids(g, p.edge_ids, where)


# ----------------------------------------------------------------------------- enrichment


def test_enrich_is_fast_and_reports(enriched: dict[str, Any]) -> None:
    assert enriched["elapsed"] < 2.0, f"enrich took {enriched['elapsed']:.2f}s on the fixture"
    report = enriched["report"]
    assert report["storylines"] == [C.STORYLINE_A, C.STORYLINE_B]
    assert report["ioc_matching"]["alert_matches"] >= 8
    assert report["attribution"]["attributions"] >= 8
    assert report["lateral_movement"]["lateral_movement_edges"] >= 1
    assert report["alerts_scored"] == len(list(enriched["graph"].nodes_by_label("Alert")))


def test_enrich_is_idempotent() -> None:
    g = fx.build_fixture_graph()
    enrich(g)
    first = _snapshot(g)
    report = enrich(g)
    second = _snapshot(g)
    assert first == second
    assert report["removed"]["Storyline"] == 2 and report["removed"]["MATCHES_IOC"] > 0
    assert set(g.nodes_by_label("Storyline")) == {C.STORYLINE_A, C.STORYLINE_B}


def test_vulnerability_overlay_and_exposure_scores(graph: ContextGraph) -> None:
    assert graph.get(C.LOG4SHELL, "exploitation_status") == "mass_exploitation"
    assert C.ACTOR_HT in graph.get(C.LOG4SHELL, "actor_interest")
    assert graph.get(C.LOG4SHELL, "sector_targeting_relevance") == pytest.approx(0.8)
    assert C.REPORT_SALTWORKS in graph.get(C.LOG4SHELL, "ti_report_ids")
    assert graph.get(C.EDGE_VM, "ti_exposure_score") > graph.get(C.STG_EDGE_VM, "ti_exposure_score") >= 0
    assert graph.get(C.BASTION_VM, "ti_exposure_score") == 0.0  # not internet-exposed
    assert graph.get(C.BASTION_VM, "crown_jewel_reach") == 3
    assert graph.get(C.DEV_SANDBOX_VM, "crown_jewel_reach") == 0


def test_ioc_matching_and_attribution_edges(graph: ContextGraph) -> None:
    matched = {ind for ind, _ in graph.out_edges(A["a003"], ("MATCHES_IOC",))}
    assert {C.IOC_C2_DOMAIN, C.IOC_C2_IP, C.IOC_HASH_NIGHTFERRY} <= matched
    assert {ind for ind, _ in graph.out_edges(A["a001"], ("MATCHES_IOC",))} == {C.IOC_HASH_MAPLELOADER}
    assert {ind for ind, _ in graph.out_edges(A["a017"], ("MATCHES_IOC",))} == {C.IOC_EGRESS_IP}
    assert graph.get(A["a003"], "ioc_match_count") == len(matched)
    attributed = {who for who, _ in graph.out_edges(A["a001"], ("ATTRIBUTED_TO",))}
    assert {C.CAMPAIGN_EMBERCAST, C.ACTOR_CJ} <= attributed
    # low-confidence, historical indicator on the wiki host matches but never attributes a storyline
    assert graph.out_edges("alert:falcon:ldt-g005", ("MATCHES_IOC",))
    assert graph.get("alert:falcon:ldt-g005", "storyline_id") is None


def test_lateral_movement_is_the_anomalous_ssh_session_only(graph: ContextGraph) -> None:
    edges = [d for u, v, d in graph.G.edges(data=True) if d.get("type") == "LATERAL_MOVEMENT_TO" and u == C.WKS_DANA and v == C.EP_BASTION]
    assert len(edges) == 1, edges
    assert edges[0]["protocol"] == "ssh" and edges[0]["account"] == "svc-finops-sftp"
    assert edges[0]["time"] == C.ALERT_A["a007"][1] and edges[0]["alert_id"] == A["a007"]


# ----------------------------------------------------------------------------- semantics


def test_edge_semantics_follow_the_architecture_table(graph: ContextGraph) -> None:
    s = Semantics(graph)
    from_ep = {m.dst: m for m in s.moves(C.EP_BASTION)}
    same = from_ep[C.BASTION_VM]
    assert same.etype == "SAME_AS" and same.p == pytest.approx(0.95 * 0.99) and same.depth_cost == 0
    assert {m.dst: m for m in s.moves(C.BASTION_VM)}[C.EP_BASTION].etype == "SAME_AS"  # both directions
    from_vm = {m.dst: m for m in s.moves(C.BASTION_VM)}
    assert from_vm[C.BASTION_ROLE].etype == "HAS_ROLE" and from_vm[C.BASTION_ROLE].p == 0.9
    assert C.CARDHOLDER_VAULT not in from_vm  # the transitive CAN_ACCESS shortcut is not traversed
    from_role = {m.dst: m for m in s.moves(C.BASTION_ROLE, "access")}
    assert from_role[C.PROD_READER_ROLE].etype == "CAN_ASSUME" and from_role[C.PROD_READER_ROLE].p == 0.8
    assert from_role[C.SHARED_LOGS_BUCKET].p == 0.9  # write
    assert {m.dst: m for m in s.moves(C.PROD_READER_ROLE)}[C.CARDHOLDER_VAULT].p == 0.7  # read
    assert {m.dst: m for m in s.moves(C.DB_READER_SECRET)}[C.CARDHOLDER_DB].p == 0.8  # UNLOCKS
    implicit = {m.dst: m for m in s.moves(C.APP_CONFIG_BUCKET)}[C.CARDHOLDER_DB]
    assert implicit.p == 0.7 and implicit.direction == "implicit"  # contains_credentials_for
    from_cred = {m.dst: m for m in s.moves(C.CRED_BASTION_KEY)}
    assert from_cred[C.BASTION_ROLE].etype == "CREDENTIAL_FOR" and from_cred[C.BASTION_ROLE].p == 0.9
    assert from_cred[C.CRED_PROD_KEY].etype == "DERIVED_FROM" and from_cred[C.CRED_PROD_KEY].direction == "reverse" and from_cred[C.CRED_PROD_KEY].p == 0.9
    assert {m.dst: m for m in s.moves(C.WKS_DANA)}[C.EP_BASTION].etype == "LATERAL_MOVEMENT_TO"
    assert s.moves(C.ACCOUNTS["shared"]["id"]) == []  # CONTAINS is context only
    assert s.moves(sem.INTERNET_ID) == [] and s.moves(sem.INTERNET_ID, allow_internet=True)
    assert RULES["MAPS_TO"].p_forward == 0.8 and RULES["HAS_ACCESS_KEY"].p_forward == 0.7 and RULES["ROUTES_TO"].p_forward == 0.5
    assert RULES["HAS_NODE"].direction == "reverse" and RULES["HAS_NODE"].p_reverse == 0.6
    assert RULES["RUNS_IMAGE"].direction == "reverse" and RULES["RUNS_IMAGE"].p_reverse == 0.7
    assert RULES["LOGGED_ON"].p_reverse == 0.6 and RULES["LOGGED_ON"].p_forward == 0.5
    assert RULES["PRIMARY_USER"].direction == "both" and RULES["PRIMARY_USER"].p_forward == 0.6
    assert "VULNERABLE_TO" not in RULES and "INVOLVES" not in RULES and "CONTAINS" not in RULES


def test_crown_jewel_predicate_sources_and_kill_chain(graph: ContextGraph) -> None:
    assert sem.is_crown_jewel(graph.node(C.CARDHOLDER_VAULT)) and sem.is_crown_jewel(graph.node(C.KYC_DOCS)) and sem.is_crown_jewel(graph.node(C.CARDHOLDER_DB))
    assert sem.is_crown_jewel(graph.node(C.CORP_IT_ADMIN_ROLE))  # admin role
    assert not sem.is_crown_jewel(graph.node(C.MARKETING_BUCKET)) and not sem.is_crown_jewel(graph.node(C.SHARED_LOGS_BUCKET))
    assert sem.source_of(graph.node(C.EP_BASTION)) == "falcon" and sem.source_of(graph.node(C.BASTION_VM)) == "wiz"
    assert sem.source_of(graph.node(C.CLOUDEVENTS_A["a010"][0])) == "cloudtrail" and sem.source_of(graph.node(N["n002"])) == "wiz"
    assert sem.source_of(graph.node(C.USER_DANA)) == "okta" and sem.source_of(graph.node(C.IOC_C2_DOMAIN)) == "ti"
    assert sem.stage_number(["T1552.005"]) == 4 and sem.stage_number(["T1021.004"]) == 5
    assert sem.stage_label(7) == "Exfiltration & Impact"
    assert "T1548.005" in sem.event_techniques({"event_name": "AssumeRole"})
    assert sem.stages_covered(["T1566.001", "T1530"]) == {1, 6}


# ----------------------------------------------------------------------------- scoring and ranking


def test_ground_truth_scores(engine: AnalyticsEngine) -> None:
    score = {k: engine.alert_summary(aid).contextual_score for k, aid in {**A, **B, **N}.items()}
    assert score["a009"] >= 90 and engine.alert_summary(A["a009"]).contextual_rank_position == 1
    assert score["a001"] >= 85 and score["a017"] >= 85
    assert 78 <= score["b002"] <= 89
    assert score["n001"] <= 25 and score["n002"] <= 25 and score["n003"] <= 35 and score["n004"] <= 30
    for aid in C.QUARANTINE_ALERT_IDS:
        assert engine.alert_summary(aid).contextual_score <= 20
    for aid in (a for a in engine.graph.nodes_by_label("Alert") if a.startswith("alert:ids:")):
        assert engine.alert_summary(aid).contextual_score <= 25


def test_contextual_ranking(engine: AnalyticsEngine) -> None:
    items, total = engine.list_alerts(sort="contextual", limit=25)
    assert isinstance(items, list) and isinstance(total, int) and total == len(list(engine.graph.nodes_by_label("Alert")))
    assert len(items) == 25 and all(isinstance(i, AlertSummary) for i in items)
    assert items[0].id == A["a009"]
    scores = [i.contextual_score for i in items]
    assert scores == sorted(scores, reverse=True)
    top10 = {i.id for i in items[:10]}
    assert top10 == STORYLINE_A_ALERTS
    non_a = [i for i in items if i.storyline_id != C.STORYLINE_A]
    assert non_a[0].id == B["b002"]
    assert N["n002"] not in {i.id for i in items} and N["n001"] not in {i.id for i in items}
    positions = {i.id: i.contextual_rank_position for i in items}
    assert positions[A["a009"]] == 1 and positions[B["b002"]] == 11
    vendor_first, _ = engine.list_alerts(sort="vendor", limit=3)
    assert vendor_first[0].vendor_severity == "critical" and vendor_first[0].vendor_rank_position == 1
    assert engine.alert_summary(A["a009"]).vendor_rank_position > 10  # a medium alert buried by vendor severity
    page1, _ = engine.list_alerts(limit=5, offset=0)
    page2, _ = engine.list_alerts(limit=5, offset=5)
    assert [i.id for i in page1] == [i.id for i in items[:5]] and [i.id for i in page2] == [i.id for i in items[5:10]]


def test_list_alert_filters(engine: AnalyticsEngine) -> None:
    items, total = engine.list_alerts(severity="medium", source="falcon", limit=100)
    assert total == len(items) and all(i.vendor_severity == "medium" and i.source_system == "falcon" for i in items)
    items, total = engine.list_alerts(storyline_id=C.STORYLINE_A, limit=100)
    assert {i.id for i in items} == STORYLINE_A_ALERTS
    items, _ = engine.list_alerts(band="critical", limit=100)
    assert {i.id for i in items} == STORYLINE_A_ALERTS
    items, _ = engine.list_alerts(reaches_crown_jewel=True, limit=100)
    assert {A["a009"], B["b002"]} <= {i.id for i in items} and N["n002"] not in {i.id for i in items}
    items, _ = engine.list_alerts(q="bas-01", limit=100)
    assert A["a009"] in {i.id for i in items}
    items, _ = engine.list_alerts(sort="time", limit=1)
    assert items[0].detected_at >= engine.alert_summary(A["a009"]).detected_at


def test_risk_breakdown_shapes_and_rails(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    rb = engine.risk_breakdown(A["a009"])
    assert isinstance(rb, RiskBreakdown) and rb.contextual_score >= 90 and rb.band == "critical"
    assert [f.key for f in rb.factors] == ["severity", "exposure", "privilege", "data", "threat_intel", "correlation"]
    assert "attack_path_floor:90" in rb.rails and any(r.startswith("credential_pivot_bonus") for r in rb.rails)
    assert rb.delta_vs_vendor < 0
    by_key = {f.key: f for f in rb.factors}
    assert by_key["privilege"].value == 1.0 and by_key["data"].value == 1.0 and by_key["correlation"].value == 1.0
    assert by_key["data"].contribution == pytest.approx(100 * 0.70 * 0.25 * 1.0, abs=0.11)
    assert by_key["severity"].contribution == pytest.approx(100 * 0.30 * 0.5, abs=0.11)
    for f in rb.factors:
        assert f.reason and 0.0 <= f.value <= 1.0
        if f.key in ("privilege", "data", "correlation", "threat_intel"):
            assert f.evidence_ids, f.key
    assert any("PCI" in r for r in rb.reasons) and any("credential" in r for r in rb.reasons)

    b002 = engine.risk_breakdown(B["b002"])
    assert "ti_booster_floor:80" in b002.rails and {f.key: f.value for f in b002.factors}["threat_intel"] == 1.0
    n002 = engine.risk_breakdown(N["n002"])
    assert "no_context_ceiling:25" in n002.rails and "public data only" in n002.reasons
    assert any(r.startswith("benign_ceiling:test_file") for r in engine.risk_breakdown(N["n001"]).rails)
    assert any(r.startswith("benign_ceiling:change_ticket:35") for r in engine.risk_breakdown(N["n003"]).rails)
    assert any(r.startswith("benign_ceiling:vpn_egress") for r in engine.risk_breakdown(N["n004"]).rails)
    assert any(r.startswith("benign_ceiling:known_scanner") for r in engine.risk_breakdown("alert:ids:ids-n101").rails)


def test_posture_probes_and_explained_anomalies_rank_below_live_exploitation(engine: AnalyticsEngine) -> None:
    b002 = engine.alert_summary(B["b002"]).contextual_score
    toxic = engine.risk_breakdown(fx.TOXIC_ISSUE_ON_EDGE)
    assert toxic.contextual_score <= 80 < b002 and "posture_ceiling:80" in toxic.rails
    assert 60 <= engine.alert_summary("alert:cspm:iss-g004").contextual_score <= 80  # toxic combination band
    probe = engine.risk_breakdown(fx.WAF_NOISE_ON_EDGE)
    assert probe.contextual_score < 80 and not any(r.startswith("ti_booster") for r in probe.rails)
    assert engine.alert_summary(fx.WAF_NOISE_ON_EDGE).storyline_id is None
    explained = engine.alert_summary(fx.EXPLAINED_CLOUD_ANOMALY)
    assert explained.contextual_score <= 30 and explained.storyline_id is None
    assert any(r.startswith("benign_ceiling:explained_baseline") for r in engine.risk_breakdown(fx.EXPLAINED_CLOUD_ANOMALY).rails)
    waf_b001 = engine.risk_breakdown(B["b001"])
    assert "ti_booster_floor:80" in waf_b001.rails  # a probe from the exploiting actor's infrastructure does qualify
    assert waf_b001.contextual_score <= b002


def test_alert_summary_fields(engine: AnalyticsEngine) -> None:
    s = engine.alert_summary(A["a009"])
    assert s.entity_id == C.EP_BASTION and s.entity_label == "Endpoint" and s.hostname == C.BASTION_NAME
    assert s.storyline_id == C.STORYLINE_A and s.reaches_crown_jewel and s.on_attack_path
    assert C.ACTOR_CJ in s.ti_actor_ids and s.contextual_band == "critical" and s.techniques == ["T1552.005"]
    assert engine.alert_summary(A["a003"]).ioc_match_count >= 3
    assert engine.flat_view(A["a009"])["command_line"].startswith("curl")
    with pytest.raises(KeyError):
        engine.alert_summary("alert:falcon:does-not-exist")


# ----------------------------------------------------------------------------- storylines


def test_storylines_exact(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    assert set(graph.nodes_by_label("Storyline")) == {C.STORYLINE_A, C.STORYLINE_B}
    a = engine.storyline(C.STORYLINE_A, with_fragment=False)
    assert isinstance(a, StorylineOut) and a.fragment is None
    assert set(a.alert_ids) == STORYLINE_A_ALERTS
    assert a.actor_id == C.ACTOR_CJ and a.campaign_id == C.CAMPAIGN_EMBERCAST and a.actor_name == "Cinder Jackal"
    assert CROWN_JEWELS | SECRETS <= set(a.crown_jewels_reached)
    assert a.stage_count == 7 and len(a.stages) == 7 and a.contextual_score >= 90
    assert a.first_event == C.ALERT_A["a001"][1] and a.last_event == C.ALERT_A["a017"][1]
    stage_techs = {t for s in a.stages for t in s.technique_ids}
    assert {"T1566.001", "T1552.005", "T1021.004", "T1548.005", "T1530"} <= stage_techs
    assert graph.get(C.STORYLINE_A, "confirmed_reach") is True and graph.get(C.STORYLINE_A, "attribution_basis") == "ioc"
    b = engine.storyline(C.STORYLINE_B, with_fragment=False)
    assert set(b.alert_ids) == STORYLINE_B_ALERTS
    assert b.actor_id == C.ACTOR_HT and b.campaign_id == C.CAMPAIGN_SALTWORKS and b.stage_count == 3
    assert {C.APP_CONFIG_BUCKET, C.CARDHOLDER_DB} <= set(b.crown_jewels_reached)
    assert 78 <= b.contextual_score <= 89
    assert [s.id for s in engine.list_storylines()] == [C.STORYLINE_A, C.STORYLINE_B]
    with pytest.raises(KeyError):
        engine.storyline("storyline:derived:nope")


def test_storyline_graph_artifacts(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    members = {m for m, _ in graph.in_edges(C.STORYLINE_A, ("IN_STORYLINE",)) if graph.label_of(m) in ("Alert", "CloudEvent")}
    assert STORYLINE_A_ALERTS | {v[0] for v in C.CLOUDEVENTS_A.values()} == members
    supporting = {m for m, _ in graph.in_edges(C.STORYLINE_A, ("IN_STORYLINE",))}
    assert {C.CRED_BASTION_KEY, C.CRED_PROD_KEY, C.CARDHOLDER_VAULT, C.EP_BASTION, C.BASTION_VM} <= supporting
    nxt = [(u, v) for u, v, d in graph.G.edges(data=True) if d.get("type") == "NEXT_STAGE" and d.get("storyline_id") == C.STORYLINE_A]
    assert len(nxt) == len(members) - 1
    assert (A["a009"], C.CLOUDEVENTS_A["a010"][0]) in nxt
    attributed = {who for who, _ in graph.out_edges(C.STORYLINE_A, ("ATTRIBUTED_TO",))}
    assert attributed == {C.CAMPAIGN_EMBERCAST, C.ACTOR_CJ}
    for m in members:
        assert graph.get(m, "storyline_id") == C.STORYLINE_A
    full = engine.storyline(C.STORYLINE_A, with_fragment=True)
    assert full.fragment is not None and full.fragment.layout_hint == "storyline" and full.fragment.paths
    _check_fragment(graph, full.fragment, "storyline fragment")
    # the background incident that grouped unrelated workstation detections did not become a storyline
    for aid in ("alert:falcon:ldt-g001", "alert:falcon:ldt-g002", "alert:falcon:ldt-g004"):
        assert graph.get(aid, "storyline_id") is None


# ----------------------------------------------------------------------------- blast radius and paths


def test_blast_radius_from_pivotal_alert(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    br = engine.blast_radius(A["a009"], depth=5)
    assert isinstance(br, BlastRadiusResult) and br.root_id == A["a009"] and br.depth == 5
    assert all(isinstance(r, ReachedNode) for r in br.crown_jewels + br.secrets + br.data_stores + br.identities)
    assert {r.node.id for r in br.crown_jewels} == CROWN_JEWELS
    assert {r.node.id for r in br.secrets} == SECRETS
    data = {r.node.id for r in br.data_stores}
    assert CROWN_JEWELS <= data and C.SHARED_LOGS_BUCKET in data and C.MARKETING_BUCKET not in data
    assert {r.node.id for r in br.identities} >= {C.BASTION_ROLE, C.PROD_READER_ROLE}
    vault = next(r for r in br.crown_jewels if r.node.id == C.CARDHOLDER_VAULT)
    assert vault.hops == 5 and vault.access_level == "read"
    assert vault.via_path == [A["a009"], C.EP_BASTION, C.BASTION_VM, C.BASTION_ROLE, C.PROD_READER_ROLE, C.CARDHOLDER_VAULT]
    db = next(r for r in br.crown_jewels if r.node.id == C.CARDHOLDER_DB)
    assert db.hops == 6 and db.via_path[-2] == C.DB_READER_SECRET and db.access_level == "credential"
    assert 0 < vault.reach_score <= 1 and set(br.accounts_touched) == {"111111111111", "222222222222"}
    assert br.fragment.layout_hint == "blast_radius" and br.fragment.focus == [A["a009"]] and len(br.fragment.nodes) <= 150
    assert br.reached_count == sum(br.by_hop.values())
    assert "crown jewel" in br.summary
    _check_fragment(graph, br.fragment, "blast radius fragment")
    for r in br.crown_jewels + br.secrets:
        _check_ids(graph, r.via_path, "via_path")


def test_identity_footprint_and_find_paths(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    fp = engine.identity_footprint(C.BASTION_ROLE)
    reached = {r.node.id for r in fp.crown_jewels} | {r.node.id for r in fp.secrets} | {r.node.id for r in fp.data_stores}
    assert CROWN_JEWELS | SECRETS | {C.SHARED_LOGS_BUCKET} <= reached
    assert C.PROD_READER_ROLE in {r.node.id for r in fp.identities}
    frag = engine.find_paths(A["a009"], C.CARDHOLDER_VAULT, max_hops=6, k=3)
    assert frag.layout_hint == "path" and frag.paths and frag.paths[0].hops == 5
    assert frag.paths[0].node_ids[0] == A["a009"] and frag.paths[0].node_ids[-1] == C.CARDHOLDER_VAULT
    _check_fragment(graph, frag, "find_paths")


def test_attack_path_from_phishing_to_vault(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    paths = engine.attack_paths(through_id=A["a001"], target_id=C.CARDHOLDER_VAULT, k=3)
    assert paths and all(isinstance(p, AttackPathOut) for p in paths)
    best = paths[0]
    assert best.entry_id == A["a001"] and best.target_id == C.CARDHOLDER_VAULT and 0 < best.likelihood <= 1
    node_ids = {n for s in best.stages for n in s.node_ids} | set(best.fragment.node_ids())
    assert {C.WKS_DANA, C.EP_BASTION, C.BASTION_VM, C.BASTION_ROLE, C.PROD_READER_ROLE, C.CARDHOLDER_VAULT} <= node_ids
    assert len(best.stages) >= 5
    techniques = {t for s in best.stages for t in s.technique_ids}
    assert {"T1021.004", "T1552.005", "T1566.001", "T1548.005"} <= techniques
    labels = [s.stage for s in best.stages]
    assert labels[0] == "Initial Access" and labels[-1] == "Exfiltration & Impact"
    assert "Lateral Movement & Privilege Escalation" in labels
    alerts_on_path = {a for s in best.stages for a in s.alert_ids}
    assert {A["a001"], A["a007"], A["a009"], C.CLOUDEVENTS_A["a014"][0]} <= alerts_on_path
    assert [s.order for s in best.stages] == list(range(1, len(best.stages) + 1))
    assert best.fragment.layout_hint == "path" and best.fragment.paths
    _check_fragment(graph, best.fragment, "attack path fragment")
    for s in best.stages:
        _check_ids(graph, s.node_ids + s.alert_ids, "stage ids")
        _check_edge_ids(graph, s.edge_ids, "stage edges")
    internet = engine.attack_paths(through_id=C.EDGE_VM, target_id=C.CARDHOLDER_DB, k=2)
    assert internet and internet[0].entry_id == sem.INTERNET_ID and internet[0].stages[0].stage == "Initial Access"
    assert "T1190" in internet[0].stages[0].technique_ids


# ----------------------------------------------------------------------------- threat intel


def test_ti_exposure_table(engine: AnalyticsEngine) -> None:
    rows = engine.ti_exposure(sector_only=True)
    vm_ids = [r["vm"].id for r in rows]
    assert vm_ids[0] == C.EDGE_VM and C.BASTION_VM not in vm_ids
    assert C.STG_EDGE_VM in vm_ids and C.DEV_LOG4J_VM in vm_ids and len(vm_ids) >= 5
    first = rows[0]
    assert first["cve"].id == C.LOG4SHELL and first["exploitation_status"] == "mass_exploitation"
    assert {a.id for a in first["actors"]} == {C.ACTOR_HT} and {c.id for c in first["campaigns"]} == {C.CAMPAIGN_SALTWORKS}
    assert first["sector_relevance"] >= 0.7 and first["has_edr_sensor"] is True and B["b002"] in first["alert_ids"]
    assert C.CARDHOLDER_DB in {c.id for c in first["crown_jewels_reachable"]}
    scores = [r["contextual_score"] for r in rows]
    assert scores == sorted(scores, reverse=True)
    for r in rows:
        assert r["sector_relevance"] >= 0.7
    everything = engine.ti_exposure(sector_only=False)
    assert fx.CANARY_VM in {r["vm"].id for r in everything} and fx.CANARY_VM not in vm_ids


def test_ti_actor_campaign_context_and_lookup(engine: AnalyticsEngine) -> None:
    actor = engine.ti_actor(C.ACTOR_CJ)
    assert actor["actor"].id == C.ACTOR_CJ and {c.id for c in actor["campaigns"]} == {C.CAMPAIGN_EMBERCAST}
    matched = {a.id for a in actor["matched_alerts"]}
    assert {A["a001"], A["a002"], A["a003"], A["a004"], A["a017"]} <= matched and B["b002"] not in matched
    assert all(isinstance(a, AlertSummary) for a in actor["matched_alerts"])
    assert {m.id for m in actor["malware"]} == {C.MALWARE_MAPLELOADER, C.MALWARE_QUILLDROP, C.MALWARE_NIGHTFERRY}
    assert C.REPORT_EMBERCAST in {r.id for r in actor["reports"]} and isinstance(actor["context"], TIContext)
    assert isinstance(actor["affected"], GraphFragment) and C.WKS_DANA in actor["affected"].node_ids()
    ctx = engine.threat_intel_context(C.ACTOR_CJ)
    assert ctx.matches and ctx.sector_relevance == pytest.approx(0.9)
    camp = engine.ti_campaign(C.CAMPAIGN_SALTWORKS)
    assert {a.id for a in camp["matched_alerts"]} == STORYLINE_B_ALERTS and C.LOG4SHELL in camp["exploited_cve_ids"]
    a003 = engine.threat_intel_context(A["a003"])
    assert {m.indicator_id for m in a003.matches} >= {C.IOC_C2_DOMAIN, C.IOC_C2_IP}
    assert {a.id for a in a003.actors} == {C.ACTOR_CJ} and a003.ttp_overlap.get(C.ACTOR_CJ) == 1.0
    lookup = engine.ti_lookup(C.C2_DOMAIN)
    assert lookup.matches and {a.id for a in lookup.actors} == {C.ACTOR_CJ}
    assert engine.ti_lookup(C.HASH_MAPLELOADER).matches
    cve = engine.ti_lookup("CVE-2021-44228")
    assert C.LOG4SHELL in {v.id for v in cve.exploited_vulnerabilities} and C.ACTOR_HT in {a.id for a in cve.actors}
    assert {a.id for a in engine.ti_lookup("Hollow Tide").actors} == {C.ACTOR_HT}
    assert engine.ti_lookup("nothing-like-this-exists").matches == []
    actors = engine.ti_actors()
    assert actors[0]["actor"].id == C.ACTOR_CJ and actors[0]["matched_alerts"] >= 5
    reports = engine.ti_reports()
    assert reports[0].id == C.REPORT_SALTWORKS  # newest first
    report = engine.ti_report(C.REPORT_EMBERCAST)
    assert {a.id for a in report["impact"]["matched_alerts"]} >= {A["a001"], A["a003"]}
    assert C.CARDHOLDER_VAULT in report["impact"]["crown_jewels_touched"] and report["impact"]["ttp_overlap_count"] >= 10


# ----------------------------------------------------------------------------- typed investigations


def test_credential_joins_exact(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    res = engine.credential_joins()
    items = res["items"]
    assert {it["credential"].id for it in items} == {C.CRED_BASTION_KEY, C.CRED_PROD_KEY}
    by_id = {it["credential"].id: it for it in items}
    bastion = by_id[C.CRED_BASTION_KEY]
    assert bastion["stolen_by_alert"].id == A["a009"] and isinstance(bastion["stolen_by_alert"], AlertSummary)
    assert [e.id for e in bastion["used_in_events"]] == [C.CLOUDEVENTS_A[k][0] for k in ("a010", "a011", "a012")]
    assert bastion["endpoint"].id == C.EP_BASTION and bastion["principal"].id == C.BASTION_ROLE
    assert [c.id for c in bastion["derived_credentials"]] == [C.CRED_PROD_KEY] and bastion["source_ips"] == [C.ATTACKER_EGRESS_IP]
    prod = by_id[C.CRED_PROD_KEY]
    assert prod["stolen_by_alert"].id == A["a009"] and prod["derived_from"].id == C.CRED_BASTION_KEY
    assert [e.id for e in prod["used_in_events"]] == [C.CLOUDEVENTS_A[k][0] for k in ("a013", "a014", "a015", "a016")]
    assert prod["principal"].id == C.PROD_READER_ROLE
    _check_fragment(graph, res["fragment"], "credential joins fragment")


def test_alerts_reaching_crown_jewels(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    res = engine.alerts_reaching_crown_jewels()
    ids = [i.id for i in res["items"]]
    assert {A["a007"], A["a008x"], A["a009"], A["a017"], B["b002"], B["b003"], B["b001"]} <= set(ids)
    assert not ({N["n001"], N["n002"], N["n003"], N["n004"]} & set(ids))
    assert ids[0] == A["a009"]
    scores = [i.contextual_score for i in res["items"]]
    assert scores == sorted(scores, reverse=True)
    assert CROWN_JEWELS <= {j.id for j in res["jewels"]}
    only_vault = engine.alerts_reaching_crown_jewels(jewel_id=C.CARDHOLDER_VAULT)
    assert A["a009"] in {i.id for i in only_vault["items"]} and B["b002"] not in {i.id for i in only_vault["items"]}
    pci = engine.alerts_reaching_crown_jewels(classification="PCI")
    assert {A["a009"], B["b002"]} <= {i.id for i in pci["items"]}
    _check_fragment(graph, res["fragment"], "crown jewel fragment")


def test_medium_alerts_with_data_path(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    res = engine.medium_alerts_with_data_path(severity="medium", source="falcon")
    ids = [i.id for i in res["items"]]
    assert ids[0] == A["a009"] and A["a007"] in ids and B["b002"] in ids
    assert N["n003"] not in ids and N["n001"] not in ids and fx.WAF_NOISE_ON_EDGE not in ids
    assert all(i.vendor_severity == "medium" and i.source_system == "falcon" for i in res["items"])
    assert C.CARDHOLDER_VAULT in res["data_reached"][A["a009"]]
    any_source = engine.medium_alerts_with_data_path(severity="medium", source=None)
    assert B["b001"] in {i.id for i in any_source["items"]}
    _check_fragment(graph, res["fragment"], "medium alerts fragment")


def test_containment_simulation(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    sim = engine.simulate_containment([C.EP_BASTION, C.BASTION_ROLE], ["isolate_endpoint", "rotate_role_credentials"])
    assert isinstance(sim, ContainmentSimulation)
    assert sim.storylines_contained == [C.STORYLINE_A] and sim.paths_cut >= 1
    assert CROWN_JEWELS | SECRETS <= set(sim.crown_jewels_protected)
    breaks = " ".join(f"{b.node_id} {b.name} {b.impact}" for b in sim.breaks).lower()
    assert "settlement" in breaks and ("ssm" in breaks or "platform" in breaks)
    assert {b.owner_team_id for b in sim.breaks} >= {C.TEAM_TREASURY, C.TEAM_PLATFORM}
    assert C.APP_SETTLEMENT_SFTP in {b.node_id for b in sim.breaks}
    assert any(C.CRED_PROD_KEY_ID in r and "expired" in r for r in sim.residual_risks)
    assert any("trust policy" in r.lower() for r in sim.residual_risks)
    assert any("tighten_trust_policy" in r for r in sim.recommendations)
    assert any("exfiltrated" in r for r in sim.recommendations)
    assert sim.fragment.meta["cut_edges"] and set(sim.fragment.focus) == {C.EP_BASTION, C.BASTION_ROLE}
    _check_ids(graph, sim.crown_jewels_protected + [b.node_id for b in sim.breaks] + sim.target_ids, "containment ids")
    _check_fragment(graph, sim.fragment, "containment fragment")
    trust = engine.simulate_containment([C.BASTION_ROLE], ["tighten_trust_policy"])
    assert trust.storylines_contained == [C.STORYLINE_A] and C.CARDHOLDER_VAULT in trust.crown_jewels_protected
    nothing = engine.simulate_containment([f"ip:v4:{C.ATTACKER_EGRESS_IP}"], ["block_ip"])
    assert nothing.storylines_contained == [] and any("rotate infrastructure" in r for r in nothing.residual_risks)


# ----------------------------------------------------------------------------- insights, context, dashboard


def test_insights_cross_sources_and_cite_real_evidence(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    total = 0
    for aid in graph.nodes_by_label("Alert"):
        for ins in engine.insights(aid):
            total += 1
            assert isinstance(ins, Insight) and ins.hops >= 2 and len(ins.sources) >= 2, (aid, ins.statement)
            assert ins.statement.endswith(".") and 0 < ins.importance <= 1
            _check_ids(graph, ins.evidence_node_ids, f"insight on {aid}")
            _check_edge_ids(graph, ins.evidence_edge_ids, f"insight on {aid}")
    assert total >= 60
    kinds = {i.kind for i in engine.insights(A["a009"])}
    assert {"blast_radius", "credential_join", "correlation", "lateral"} <= kinds
    assert "ti_match" in {i.kind for i in engine.insights(A["a003"])}
    assert "noise" in {i.kind for i in engine.insights(N["n002"])}
    assert "noise" in {i.kind for i in engine.insights(N["n003"])}


def test_alert_context_assembly(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    ctx = engine.alert_context(A["a009"])
    assert isinstance(ctx, AlertContext) and ctx.alert.id == A["a009"]
    assert ctx.risk.contextual_score == ctx.alert.contextual_score and ctx.flat_view
    assert ctx.blast_radius is not None and {r.node.id for r in ctx.blast_radius.crown_jewels} == CROWN_JEWELS
    assert ctx.attack_paths and ctx.storyline is not None and ctx.storyline.id == C.STORYLINE_A
    assert ctx.threat_intel is not None and C.ACTOR_CJ in {a.id for a in ctx.threat_intel.actors}
    assert {A["a007"], A["a001"]} <= {r.id for r in ctx.related_alerts}
    assert ctx.evidence.layout_hint == "path" and ctx.evidence.paths
    _check_fragment(graph, ctx.evidence, "alert context evidence")
    plain = engine.alert_context(N["n002"])
    assert plain.storyline is None and plain.evidence.layout_hint == "neighborhood" and plain.blast_radius is not None
    card = engine.node_card(C.BASTION_VM)
    assert set(card) == {"node", "degree", "edge_type_counts", "alerts", "threat_intel"}
    assert A["a009"] in {a.id for a in card["alerts"]} and card["degree"]["out"] > 0
    hood = engine.neighborhood(C.BASTION_VM, depth=1)
    assert hood.focus == [C.BASTION_VM] and {C.EP_BASTION, C.BASTION_ROLE} <= set(hood.node_ids())
    _check_fragment(graph, hood, "neighborhood")


def test_dashboard_payload(engine: AnalyticsEngine, graph: ContextGraph) -> None:
    d = engine.dashboard()
    assert set(d) == DASHBOARD_KEYS
    assert set(d["kpis"]) == KPI_KEYS and set(d["coverage"]) == COVERAGE_KEYS
    assert d["kpis"]["storylines"] == 2 and d["kpis"]["crown_jewels"] >= 3 and d["kpis"]["ioc_matches"] > 0
    assert d["kpis"]["open_alerts"] == len(list(graph.nodes_by_label("Alert")))
    assert 0 < d["kpis"]["endpoint_coverage_pct"] <= 100
    assert len(d["leaderboard_contextual"]) == 10 and d["leaderboard_contextual"][0].id == A["a009"]
    assert len(d["leaderboard_vendor"]) == 10 and d["leaderboard_vendor"][0].vendor_severity == "critical"
    assert [s.id for s in d["storylines"]] == [C.STORYLINE_A, C.STORYLINE_B] and all(s.fragment is None for s in d["storylines"])
    assert set(d["alerts_by_band"]) == {"critical", "high", "medium", "low", "noise"}
    assert sum(d["alerts_by_band"].values()) == d["kpis"]["open_alerts"]
    assert {"falcon", "cspm", "waf", "ids", "cloud-anomaly", "okta"} <= set(d["alerts_by_source"])
    assert d["ti_pressure"] and set(d["ti_pressure"][0]) >= TI_PRESSURE_KEYS and d["ti_pressure"][0]["actor_id"] == C.ACTOR_CJ
    assert d["rerank_examples"] and all(RERANK_KEYS <= set(r) for r in d["rerank_examples"])
    assert d["rerank_examples"][0]["alert_id"] == A["a009"] and d["rerank_examples"][0]["contextual_rank_position"] == 1
    assert any(r["alert_id"] in (N["n001"], N["n002"]) for r in d["rerank_examples"])
    _check_ids(graph, [r["alert_id"] for r in d["rerank_examples"]] + [r["actor_id"] for r in d["ti_pressure"]], "dashboard ids")
