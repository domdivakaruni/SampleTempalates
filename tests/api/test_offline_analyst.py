"""The deterministic offline analyst: intent classification, entity linking, playbooks and cited evidence for the
twelve demo questions (docs/04-storyline.md section 6) plus the generic intents, on the fixture graph."""
from __future__ import annotations

import pytest

from throughline.agent.analyst import Analyst
from throughline.agent.offline import INTENTS, OfflineAnalyst
from throughline.agent.prompts import DEMO_QUESTIONS
from throughline.agent.tools import ToolRegistry
from throughline.models import AnalystAnswer, ChatEvent
from throughline.simulator import storyline_constants as C

A = {k: v[0] for k, v in C.ALERT_A.items()}
B = {k: v[0] for k, v in C.ALERT_B.items()}
N = {k: v[0] for k, v in C.ALERT_N.items()}
EVT = {k: v[0] for k, v in C.CLOUDEVENTS_A.items()}
CROWN_JEWELS = {C.CARDHOLDER_VAULT, C.KYC_DOCS, C.CARDHOLDER_DB}
SECTIONS = ("## Findings", "## Evidence", "## Impact", "## Recommended actions")

# question -> (intent, ids that must appear as evidence, ids that must NOT appear, phrases the narrative must contain)
DEMO: list[tuple[str, str, set[str], set[str], tuple[str, ...]]] = [
    (DEMO_QUESTIONS[0], "blast_radius_of_alert", {A["a009"], C.EP_BASTION, C.BASTION_VM, C.BASTION_ROLE, C.PROD_READER_ROLE, *CROWN_JEWELS, C.DB_READER_SECRET, C.HSM_SECRET}, {C.MARKETING_BUCKET}, ("3 crown jewel", "PCI")),
    (DEMO_QUESTIONS[1], "medium_alerts_with_data_path", {A["a009"], A["a007"], B["b002"]}, {N["n003"], N["n001"]}, ("ldt-a009",)),
    (DEMO_QUESTIONS[2], "cloud_activity_related_to_endpoint", {C.CRED_BASTION_KEY, A["a009"], EVT["a010"], EVT["a012"], C.BASTION_ROLE}, set(), ("**Yes.**", "ASIA5LARKBASTION01Q7")),
    (DEMO_QUESTIONS[3], "identity_footprint", {C.BASTION_ROLE, C.PROD_READER_ROLE, *CROWN_JEWELS, C.DB_READER_SECRET, C.HSM_SECRET, C.SHARED_LOGS_BUCKET}, set(), ("LarkspurProdDataReader", "cardholder-vault", "kyc-documents")),
    (DEMO_QUESTIONS[4], "exposed_exploited_hosts", {C.EDGE_VM, C.STG_EDGE_VM, C.DEV_LOG4J_VM, C.LOG4SHELL, C.ACTOR_HT}, {C.BASTION_VM}, ("stmt-render-2a", "CVE-2021-44228", "mass_exploitation", "Hollow Tide")),
    (DEMO_QUESTIONS[5], "rank_alerts_explain_top", {A["a009"], A["a001"], B["b002"]}, set(), ("| 1 | `alert:falcon:ldt-a009`", "ldt-b002")),
    (DEMO_QUESTIONS[6], "attack_path_from_alert", {A["a001"], C.WKS_DANA, C.EP_BASTION, C.BASTION_VM, C.BASTION_ROLE, C.PROD_READER_ROLE, C.CARDHOLDER_VAULT}, set(), ("T1552.005", "T1021.004", "7 stages")),
    (DEMO_QUESTIONS[7], "credential_joins", {C.CRED_BASTION_KEY, C.CRED_PROD_KEY, A["a009"], EVT["a010"], EVT["a012"]}, set(), ("ASIA5LARKBASTION01Q7", "ASIA5LARKPRODREADER1")),
    (DEMO_QUESTIONS[8], "ioc_ttp_matches_for_actor_or_report", {A["a001"], A["a002"], A["a003"], A["a004"], A["a017"], C.ACTOR_CJ, C.CARDHOLDER_VAULT}, {C.IOC_SALTWORKS_IP, C.IOC_HASH_BRACKISH}, ("Cinder Jackal", "IOC match")),
    (DEMO_QUESTIONS[9], "alerts_reaching_crown_jewels", {A["a007"], A["a008x"], A["a009"], A["a017"], B["b002"], B["b003"], B["b001"]}, {N["n001"], N["n002"], N["n003"]}, ("hidden",)),
    (DEMO_QUESTIONS[10], "is_alert_actually_risky", {N["n002"], C.MARKETING_BUCKET}, set(), ("PUBLIC", "noise / low priority", "24", "Low priority")),
    (DEMO_QUESTIONS[11], "containment_simulation", {C.EP_BASTION, C.BASTION_ROLE, C.STORYLINE_A, C.APP_SETTLEMENT_SFTP}, set(), ("settlement", "trust polic", "expired")),
]


@pytest.fixture(scope="module")
def offline(registry: ToolRegistry) -> OfflineAnalyst:
    return OfflineAnalyst(registry)


def _check_answer(answer: AnalystAnswer) -> None:
    """Invariants every offline answer must satisfy."""
    assert answer.mode == "offline" and answer.model is None
    assert answer.intent in INTENTS
    assert 0.0 < answer.confidence <= 1.0
    assert 2 <= len(answer.followups) <= 3
    for section in SECTIONS:
        assert section in answer.narrative_md, section
    node_ids = set(answer.evidence.node_ids())
    edge_ids = {e.id for e in answer.evidence.edges}
    for f in answer.findings:
        assert f.statement.strip()
        for eid in f.evidence_ids:
            if "|" in eid:
                src, _, dst = eid.split("|", 2)
                if src in node_ids and dst in node_ids:
                    assert eid in edge_ids, eid
            else:
                assert eid in node_ids, f"cited node {eid} missing from the evidence fragment"
    assert all(n.id in node_ids for n in answer.evidence.nodes)
    assert all(e.src in node_ids and e.dst in node_ids for e in answer.evidence.edges)


@pytest.mark.parametrize("question,intent,expected,forbidden,phrases", DEMO, ids=[f"q{i + 1}" for i in range(len(DEMO))])
def test_demo_questions(offline: OfflineAnalyst, question: str, intent: str, expected: set[str], forbidden: set[str], phrases: tuple[str, ...]) -> None:
    answer = offline.answer(question, {})
    _check_answer(answer)
    assert answer.intent == intent
    assert answer.findings and answer.tool_calls
    assert all(c.error is None for c in answer.tool_calls), [(c.name, c.error) for c in answer.tool_calls]
    cited = set(answer.evidence.node_ids()) | {eid for f in answer.findings for eid in f.evidence_ids}
    assert expected <= cited, f"missing {expected - cited}"
    assert not (forbidden & cited), forbidden & cited
    assert not any(x.split(":")[-1] in answer.narrative_md for x in forbidden)
    for phrase in phrases:
        assert phrase in answer.narrative_md, phrase
    assert answer.evidence.focus and answer.confidence >= 0.6
    assert any(f.evidence_ids for f in answer.findings)


def test_classifier_maps_every_demo_question(offline: OfflineAnalyst) -> None:
    expected = [row[1] for row in DEMO]
    for question, intent in zip(DEMO_QUESTIONS, expected, strict=True):
        got, scores = offline.classify(question)
        # q4 is refined from blast_radius/identity by entity linking; the raw classifier may pick either
        if intent == "identity_footprint":
            assert got in ("identity_footprint", "blast_radius_of_alert"), (question, scores)
        else:
            assert got == intent, (question, scores)


@pytest.mark.parametrize("question", ["What is the weather like on Mars?", "hello there", "asdf qwerty zxcv", "help", "what can you do?"])
def test_unknown_questions_fall_back_to_help(offline: OfflineAnalyst, question: str) -> None:
    answer = offline.answer(question, {})
    assert answer.intent == "help" and answer.confidence <= 0.3 and answer.mode == "offline"
    assert answer.findings and all(f.statement.startswith("Try:") for f in answer.findings)
    assert answer.evidence.nodes == [] and answer.followups


def test_canvas_context_resolves_this_alert_host_and_storyline(offline: OfflineAnalyst) -> None:
    a = offline.answer("Why is this alert risky?", {"alert_id": B["b002"]})
    _check_answer(a)
    assert a.intent == "why_is_alert_risky" and B["b002"] in a.evidence.focus and "ti_booster_floor" in a.narrative_md
    b = offline.answer("What can an attacker reach from this host?", {"selected_node_ids": [C.EDGE_VM]})
    _check_answer(b)
    assert b.intent == "blast_radius_of_alert" and b.evidence.focus[0] == C.EDGE_VM and C.CARDHOLDER_DB in b.evidence.node_ids()
    c = offline.answer("Summarize this storyline", {"storyline_id": C.STORYLINE_B})
    _check_answer(c)
    assert c.intent == "summarize_storyline" and C.STORYLINE_B in c.evidence.node_ids() and "SALTWORKS" in c.narrative_md
    d = offline.answer("What can an attacker reach from here?", {"alert_id": A["a009"]})
    assert d.intent == "blast_radius_of_alert" and d.evidence.focus[0] == A["a009"]


@pytest.mark.parametrize(
    "question,intent,expected",
    [
        ("What is bas-01?", "what_is_entity", {C.EP_BASTION}),
        (f"Tell me about {C.CARDHOLDER_VAULT}", "what_is_entity", {C.CARDHOLDER_VAULT}),
        ("Tell me about Dana Whitfield", "what_is_entity", {C.USER_DANA}),
        (f"Show me the neighborhood of {C.BASTION_ROLE}", "neighborhood_of_entity", {C.BASTION_ROLE, C.PROD_READER_ROLE, C.BASTION_VM}),
        ("What is connected to the cardholder vault?", "neighborhood_of_entity", {C.CARDHOLDER_VAULT}),
        ("Which alerts sit on stmt-render-2a?", "alerts_on_entity", {C.EP_EDGE, B["b002"], B["b003"]}),
        ("Any detections on WKS-3391?", "alerts_on_entity", {C.WKS_DANA, A["a001"], A["a004"]}),
        ("Which alerts are related to Cinder Jackal?", "ioc_ttp_matches_for_actor_or_report", {C.ACTOR_CJ, A["a001"]}),
        (f"Why is {A['a009']} risky?", "why_is_alert_risky", {A["a009"], C.STORYLINE_A}),
        ("Why was ldt-a001 ranked so high?", "why_is_alert_risky", {A["a001"]}),
        ("Summarize the EMBERCAST storyline", "summarize_storyline", {C.STORYLINE_A, A["a001"], C.CARDHOLDER_VAULT}),
        ("Which storylines are active?", "list_storylines", {C.STORYLINE_A, C.STORYLINE_B}),
        ("What is the blast radius of LarkspurBastionSSMRole?", "identity_footprint", {C.BASTION_ROLE, C.CARDHOLDER_VAULT}),
        ("What is the blast radius of bas-01?", "blast_radius_of_alert", {C.EP_BASTION, C.CARDHOLDER_VAULT}),
        ("Trace the attack path from bas-01 to the cardholder vault", "attack_path_from_alert", {C.CARDHOLDER_VAULT, C.BASTION_ROLE}),
        ("Is the EICAR detection on dev-sandbox-runner-03 actually a problem?", "is_alert_actually_risky", {N["n001"], C.EP_DEV_SANDBOX}),
        ("Is the impossible travel alert for pkaur a false positive?", "is_alert_actually_risky", {N["n004"]}),
        ("Is the S3 bucket public critical finding actually risky?", "is_alert_actually_risky", {N["n002"], C.MARKETING_BUCKET}),
        ("Quarantine stmt-render-2a and rotate LarkspurStmtRenderRole - what breaks?", "containment_simulation", {C.EP_EDGE, C.EDGE_ROLE}),
        ("Which credentials were stolen and then used in the cloud?", "credential_joins", {C.CRED_BASTION_KEY}),
        ("Prioritize the alert queue by contextual risk", "rank_alerts_explain_top", {A["a009"]}),
        ("Which internet-facing hosts have an exploited vulnerability?", "exposed_exploited_hosts", {C.EDGE_VM}),
        ("Which low-severity endpoint alerts sit on assets with a path to PCI data?", "medium_alerts_with_data_path", {A["a008x"], B["b003"]}),
    ],
)
def test_generic_intents_and_entity_linking(offline: OfflineAnalyst, question: str, intent: str, expected: set[str]) -> None:
    answer = offline.answer(question, {})
    _check_answer(answer)
    assert answer.intent == intent, (answer.intent, answer.narrative_md[:200])
    cited = set(answer.evidence.node_ids()) | {eid for f in answer.findings for eid in f.evidence_ids}
    assert expected <= cited, f"missing {expected - cited}"
    assert answer.tool_calls and all(c.error is None for c in answer.tool_calls)


def test_low_severity_variant_uses_the_severity_slot(offline: OfflineAnalyst) -> None:
    answer = offline.answer("Which low-severity endpoint alerts sit on assets with a path to PCI data?", {})
    call = next(c for c in answer.tool_calls if c.name == "alerts_with_data_path")
    assert call.arguments == {"severity": "low", "source": "falcon"}


def test_events_are_emitted_in_order(offline: OfflineAnalyst) -> None:
    events: list[ChatEvent] = []
    answer = offline.answer(DEMO_QUESTIONS[7], {}, events.append)
    types = [e.type for e in events]
    assert types[0] == "tool_call" and "tool_result" in types and "evidence" in types and types[-1] == "text_delta"
    assert "answer" not in types and "done" not in types  # the facade adds those
    calls = [e.data for e in events if e.type == "tool_call"]
    results = [e.data for e in events if e.type == "tool_result"]
    assert [c["id"] for c in calls] == [r["id"] for r in results] == [f"offline-{i}" for i in range(1, len(calls) + 1)]
    assert [c["name"] for c in calls] == [t.name for t in answer.tool_calls]
    assert "".join(e.data["text"] for e in events if e.type == "text_delta").strip() == answer.narrative_md.strip()
    merged = set()
    for e in events:
        if e.type == "evidence":
            merged |= {n["id"] for n in e.data["nodes"]}
    assert merged == set(answer.evidence.node_ids())


def test_tool_budget_degrades_gracefully(registry: ToolRegistry) -> None:
    tight = OfflineAnalyst(registry, max_tool_calls=1)
    answer = tight.answer(DEMO_QUESTIONS[0], {})
    assert answer.mode == "offline" and len(answer.tool_calls) == 1 and answer.narrative_md
    for section in SECTIONS:
        assert section in answer.narrative_md


def test_playbook_failure_is_reported_not_raised(registry: ToolRegistry, monkeypatch: pytest.MonkeyPatch) -> None:
    analyst = OfflineAnalyst(registry)

    def boom(*_args, **_kwargs):
        raise RuntimeError("engine exploded")

    monkeypatch.setitem(analyst._playbooks, "credential_joins", boom)
    answer = analyst.answer(DEMO_QUESTIONS[7], {})
    assert answer.mode == "offline" and answer.intent == "credential_joins" and answer.confidence <= 0.3
    assert "engine exploded" in answer.narrative_md and answer.followups


def test_analyst_facade_offline_mode(registry: ToolRegistry, settings) -> None:
    analyst = Analyst(registry, mode="offline")  # the exact construction used by tests/scenarios and scripts/demo_questions.py
    assert analyst.resolve_mode() == "offline" and analyst.configured_mode() == "offline"
    answer = analyst.answer(DEMO_QUESTIONS[3], context={}, mode="offline")
    assert isinstance(answer, AnalystAnswer) and answer.mode == "offline" and answer.intent == "identity_footprint" and answer.findings
    assert C.CARDHOLDER_VAULT in answer.evidence.node_ids()
    auto = Analyst(registry, settings)  # no key, no client: auto resolves to offline
    assert auto.has_llm() is False and auto.resolve_mode() == "offline" and auto.resolve_mode("llm") == "offline"
    events: list[ChatEvent] = []
    forced = auto.answer(DEMO_QUESTIONS[7], {}, "llm", on_event=events.append)
    assert forced.mode == "offline" and events[0].type == "error" and events[0].data["code"] == "no_api_key"
    with pytest.raises(ValueError):
        Analyst(registry, settings, mode="turbo")
