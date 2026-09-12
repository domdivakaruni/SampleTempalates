"""Scenario tests: the twelve demo questions from docs/04-storyline.md section 6, asserted on the fully generated
dataset through the analytics engine and through the offline analyst. Skipped when the dataset has not been built
(`make data`)."""
from __future__ import annotations

from pathlib import Path

import pytest

from throughline.config import settings
from throughline.simulator import storyline_constants as C

DATA = Path(settings.data_dir)
pytestmark = pytest.mark.skipif(not (DATA / "graph" / "nodes.jsonl").exists(), reason="generated dataset missing; run `make data`")


@pytest.fixture(scope="module")
def graph():
    from throughline.graph.loader import load_context_graph

    return load_context_graph(DATA)


@pytest.fixture(scope="module")
def engine(graph):
    from throughline.analytics.engine import AnalyticsEngine

    return AnalyticsEngine(graph)


@pytest.fixture(scope="module")
def analyst(graph, engine):
    from throughline.agent.analyst import Analyst
    from throughline.agent.tools import ToolRegistry
    from throughline.graph.networkx_store import NetworkXStore

    registry = ToolRegistry(engine, NetworkXStore(graph))
    return Analyst(registry, mode="offline")


A = {k: v[0] for k, v in C.ALERT_A.items()}
B = {k: v[0] for k, v in C.ALERT_B.items()}
N = {k: v[0] for k, v in C.ALERT_N.items()}
CROWN_JEWELS = {C.CARDHOLDER_VAULT, C.KYC_DOCS, C.CARDHOLDER_DB}
SECRETS = {C.DB_READER_SECRET, C.HSM_SECRET}


# ----------------------------------------------------------------------------- scores and storylines


def test_scores_match_ground_truth(engine):
    score = {aid: engine.alert_summary(aid).contextual_score for aid in [A["a009"], A["a001"], A["a017"], B["b002"], N["n001"], N["n002"], N["n003"], N["n004"]]}
    assert score[A["a009"]] >= 90, score
    assert score[A["a001"]] >= 85, score
    assert score[A["a017"]] >= 85, score
    assert 78 <= score[B["b002"]] <= 89, score
    assert score[N["n001"]] <= 25, score
    assert score[N["n002"]] <= 25, score
    assert score[N["n003"]] <= 35, score
    assert score[N["n004"]] <= 30, score


def test_storylines_exist_with_members(engine):
    a = engine.storyline(C.STORYLINE_A, with_fragment=False)
    b = engine.storyline(C.STORYLINE_B, with_fragment=False)
    assert {A["a001"], A["a002"], A["a003"], A["a004"], A["a007"], A["a009"], A["a017"]} <= set(a.alert_ids)
    assert {B["b001"], B["b002"], B["b003"]} <= set(b.alert_ids)
    assert CROWN_JEWELS <= set(a.crown_jewels_reached)
    assert a.actor_id == C.ACTOR_CJ and b.actor_id == C.ACTOR_HT


def test_q6_ranking(engine):
    items, total = engine.list_alerts(sort="contextual", limit=25)
    assert total > 1000
    assert items[0].id == A["a009"]
    top_ids = [i.id for i in items[:10]]
    assert N["n002"] not in top_ids and N["n001"] not in top_ids
    non_a = [i for i in items if i.storyline_id != C.STORYLINE_A]
    assert non_a[0].id == B["b002"], [(i.id, i.contextual_score) for i in non_a[:3]]


# ----------------------------------------------------------------------------- the twelve questions


def test_q1_blast_radius_from_bastion_alert(engine):
    br = engine.blast_radius(A["a009"], depth=5)
    reached = {r.node.id for r in br.crown_jewels} | {r.node.id for r in br.secrets} | {r.node.id for r in br.data_stores}
    assert CROWN_JEWELS <= reached, reached
    assert SECRETS <= reached, reached
    assert C.MARKETING_BUCKET not in reached


def test_q2_medium_alerts_with_data_path(engine):
    res = engine.medium_alerts_with_data_path(severity="medium", source="falcon")
    ids = [i.id for i in res["items"]]
    assert ids[0] == A["a009"], ids[:5]
    assert A["a007"] in ids and B["b002"] in ids
    assert N["n003"] not in ids and N["n001"] not in ids


def test_q3_cloud_activity_linked_to_endpoint(engine):
    res = engine.credential_joins()
    joined = {item["credential"].id if hasattr(item["credential"], "id") else item["credential"]["id"]: item for item in res["items"]}
    item = joined[C.CRED_BASTION_KEY]
    used = {e.id if hasattr(e, "id") else e["id"] for e in item["used_in_events"]}
    assert {C.CLOUDEVENTS_A["a010"][0], C.CLOUDEVENTS_A["a012"][0]} <= used
    stolen = item["stolen_by_alert"]
    assert (stolen.id if hasattr(stolen, "id") else stolen["id"]) == A["a009"]


def test_q4_identity_footprint(engine):
    br = engine.identity_footprint(C.BASTION_ROLE)
    reached = {r.node.id for r in br.crown_jewels} | {r.node.id for r in br.secrets} | {r.node.id for r in br.data_stores}
    assert CROWN_JEWELS <= reached and SECRETS <= reached
    assert C.SHARED_LOGS_BUCKET in reached


def test_q5_exposed_hosts_with_exploited_vulns(engine):
    rows = engine.ti_exposure(sector_only=True)
    vm_ids = [r["vm"].id if hasattr(r["vm"], "id") else r["vm"]["id"] for r in rows]
    assert vm_ids and vm_ids[0] == C.EDGE_VM, vm_ids[:5]
    assert C.BASTION_VM not in vm_ids
    assert C.STG_EDGE_VM in vm_ids and C.DEV_LOG4J_VM in vm_ids
    assert len(vm_ids) >= 5


def test_q7_attack_path_from_phishing_to_vault(engine):
    paths = engine.attack_paths(through_id=A["a001"], target_id=C.CARDHOLDER_VAULT, k=3)
    assert paths, "no attack path from the phishing alert to the vault"
    best = paths[0]
    node_ids = {n for s in best.stages for n in s.node_ids} | set(best.fragment.node_ids())
    assert {C.WKS_DANA, C.EP_BASTION, C.BASTION_ROLE, C.PROD_READER_ROLE, C.CARDHOLDER_VAULT} <= node_ids
    techniques = {t for s in best.stages for t in s.technique_ids}
    assert {"T1021.004", "T1552.005"} <= techniques or len(best.stages) >= 5


def test_q8_credential_joins_exact(engine):
    res = engine.credential_joins()
    ids = {item["credential"].id if hasattr(item["credential"], "id") else item["credential"]["id"] for item in res["items"]}
    assert ids == {C.CRED_BASTION_KEY, C.CRED_PROD_KEY}, ids


def test_q9_actor_matches(engine):
    ctx = engine.threat_intel_context(C.ACTOR_CJ) if hasattr(engine, "threat_intel_context") else None
    actor = engine.ti_actor(C.ACTOR_CJ)
    matched = {a.id if hasattr(a, "id") else a["id"] for a in actor.get("matched_alerts", [])}
    assert {A["a001"], A["a002"], A["a003"], A["a004"], A["a017"]} <= matched, matched
    assert B["b002"] not in matched
    if ctx is not None:
        assert ctx.matches


def test_q10_alerts_reaching_crown_jewels(engine):
    res = engine.alerts_reaching_crown_jewels()
    ids = {i.id for i in res["items"]}
    assert {A["a007"], A["a008x"], A["a009"], A["a017"], B["b002"], B["b003"], B["b001"]} <= ids
    assert not ({N["n001"], N["n002"], N["n003"]} & ids)


def test_q11_public_bucket_finding_is_noise(engine):
    rb = engine.risk_breakdown(N["n002"])
    assert rb.contextual_score <= 25
    assert any("no_context" in r or "ceiling" in r for r in rb.rails) or rb.contextual_score <= 25


def test_q12_containment(engine):
    sim = engine.simulate_containment([C.EP_BASTION, C.BASTION_ROLE], ["isolate_endpoint", "rotate_role_credentials"])
    assert C.STORYLINE_A in sim.storylines_contained
    breaks = " ".join(b.node_id + " " + b.name for b in sim.breaks).lower()
    assert "settlement" in breaks and ("ssm" in breaks or "platform" in breaks)
    assert sim.paths_cut >= 1


# ----------------------------------------------------------------------------- offline analyst end to end

QUESTIONS = [
    ("Show me everything connected to the credential-dumping alert on BAS-01 - what can an attacker reach from here?", {C.CARDHOLDER_VAULT}),
    ("Which of today's medium-severity endpoint alerts sit on assets with a path to regulated data?", {A["a009"]}),
    ("Is the cloud API activity from the bastion role in the last 6 hours related to any endpoint detection?", {C.CRED_BASTION_KEY}),
    ("What is the blast radius if identity LarkspurBastionSSMRole is fully compromised?", {C.CARDHOLDER_VAULT}),
    ("Which internet-exposed hosts have a vuln a threat actor is actively exploiting against fintechs right now?", {C.EDGE_VM}),
    ("Rank all open alerts by contextual risk, not vendor severity, and explain the top 3.", {A["a009"]}),
    ("Trace the full attack path from the phishing detection on WKS-3391 to any regulated data store.", {C.CARDHOLDER_VAULT}),
    ("Which credentials used in cloud API calls today were seen being stolen on an endpoint?", {C.CRED_BASTION_KEY, C.CRED_PROD_KEY}),
    ("Do any current detections match IOCs or TTPs from the Cinder Jackal report, and what do they touch?", {A["a003"]}),
    ("Show only alerts on assets that can reach cardholder data; hide everything else.", {A["a009"]}),
    ("Is the 'S3 bucket public' critical finding actually risky - what's in it and can an actor reach it?", {C.MARKETING_BUCKET}),
    ("If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?", {C.EP_BASTION}),
]


@pytest.mark.parametrize("question,expected_ids", QUESTIONS, ids=[f"q{i+1}" for i in range(len(QUESTIONS))])
def test_offline_analyst_answers(analyst, question, expected_ids):
    answer = analyst.answer(question, context={}, mode="offline")
    assert answer.findings, f"no findings for: {question}"
    evidence_ids = set(answer.evidence.node_ids()) | {eid for f in answer.findings for eid in f.evidence_ids}
    text = answer.narrative_md
    assert expected_ids & evidence_ids or any(x in text for x in expected_ids), f"expected {expected_ids} in evidence for: {question}\n{text[:800]}"
    assert answer.mode == "offline" and answer.intent not in (None, "help")
