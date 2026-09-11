"""The Claude tool-use loop against the scripted fake client (``tests/api/fake_anthropic.py``): request shape
(streaming, server-side fallbacks, adaptive thinking, strict tools, prompt caching), parallel tool results returned in
one user message, ``submit_answer`` evidence validation, stop reasons (``end_turn``, ``max_tokens``, ``pause_turn``,
``refusal``), SDK errors falling back to the offline analyst in ``auto`` mode, and the budgets."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import anthropic
import pytest

from tests.api import fake_anthropic as fa
from throughline.agent.analyst import Analyst
from throughline.agent.llm import BETA_FALLBACKS, BUDGET_NOTE, CONTINUE_NOTE, LLMAnalyst, LLMUnavailable
from throughline.agent.prompts import SYSTEM_PROMPT
from throughline.agent.tools import EvidenceSet, SubmitAnswerArgs, ToolRegistry, ToolResult
from throughline.models import ChatEvent, ChatMessageIn, GraphFragment, NodeOut
from throughline.simulator import storyline_constants as C

A009 = "alert:falcon:ldt-a009"
QUESTION = "Show me everything connected to the credential-dumping alert on BAS-01 - what can an attacker reach from here?"


def _llm(registry: ToolRegistry, settings, script: list[Any], **overrides: Any) -> tuple[LLMAnalyst, fa.FakeAnthropicClient]:
    client = fa.FakeAnthropicClient(script)
    cfg = settings.model_copy(update=overrides) if overrides else settings
    return LLMAnalyst(registry, cfg, client_factory=lambda: client), client


def _analyst(registry: ToolRegistry, settings, script: list[Any], **overrides: Any) -> tuple[Analyst, fa.FakeAnthropicClient]:
    client = fa.FakeAnthropicClient(script)
    cfg = settings.model_copy(update=overrides) if overrides else settings
    return Analyst(registry, cfg, client_factory=lambda: client), client


def _submit(block_id: str = "toolu_final", **kwargs: Any) -> Any:
    args = {"narrative_md": "## Findings\n- done\n\n## Evidence\n- none\n\n## Impact\n- none\n\n## Recommended actions\n1. none", "findings": [], "evidence_ids": [], "confidence": 0.5, "followups": ["next?"]}
    args.update(kwargs)
    return fa.tool_use(block_id, "submit_answer", args)


# ----------------------------------------------------------------------------- the happy path


def test_two_turn_tool_loop_merges_evidence_and_validates_citations(registry: ToolRegistry, settings) -> None:
    llm, client = _llm(registry, settings, fa.two_turn_script(A009)())
    events: list[ChatEvent] = []
    answer = llm.run_sync(QUESTION, {"alert_id": A009}, events.append)
    assert answer.mode == "llm" and answer.model == "claude-opus-5" and answer.intent is None
    assert [c.name for c in answer.tool_calls] == ["get_alert", "blast_radius", "submit_answer"] and all(c.error is None for c in answer.tool_calls)
    # evidence merged from both tool results: the alert card and the blast radius
    node_ids = set(answer.evidence.node_ids())
    assert {A009, C.EP_BASTION, C.CARDHOLDER_VAULT, C.KYC_DOCS, C.BASTION_ROLE} <= node_ids
    assert answer.evidence.layout_hint == "blast_radius" and answer.evidence.focus[0] == A009
    # submit_answer: cited ids that no tool returned are dropped, the rest kept in order
    assert len(answer.findings) == 1
    cited = answer.findings[0].evidence_ids
    assert cited[0] == A009 and C.CARDHOLDER_VAULT in cited and "vm:aws:i-does-not-exist" not in cited
    assert set(cited) <= node_ids | {e.id for e in answer.evidence.edges}
    assert "vm:aws:i-does-not-exist" in answer.narrative_md and "dropped" in answer.narrative_md
    assert answer.narrative_md.startswith("## Findings") and answer.confidence == 0.9 and len(answer.followups) == 2
    # events: thinking + text from turn 1, parallel tool calls, evidence per fragment-bearing tool, narrative chunks
    types = [e.type for e in events]
    assert types[0] == "thinking" and types.count("tool_call") == 3 and types.count("tool_result") == 3 and types.count("evidence") == 2
    assert "text_delta" in types and "answer" not in types and "done" not in types
    calls = [e.data for e in events if e.type == "tool_call"]
    assert [c["id"] for c in calls] == ["toolu_01", "toolu_02", "toolu_03"] and calls[0]["arguments"] == {"alert_id": A009}
    results = {e.data["id"]: e.data for e in events if e.type == "tool_result"}
    assert set(results) == {"toolu_01", "toolu_02", "toolu_03"} and all("error" not in r for r in results.values())
    for e in events:
        if e.type == "evidence":
            GraphFragment.model_validate(e.data)
    assert len(client.requests) == 2


def test_request_shape_follows_the_claude_api_rules(registry: ToolRegistry, settings) -> None:
    llm, client = _llm(registry, settings, fa.two_turn_script(A009)())
    llm.run_sync(QUESTION, {"alert_id": A009, "selected_node_ids": [C.BASTION_VM]})
    first = client.requests[0]
    assert first["beta"] is True and first["betas"] == [BETA_FALLBACKS] and first["fallbacks"] == "default"
    assert first["model"] == "claude-opus-5" and first["max_tokens"] == 16000
    assert first["thinking"] == {"type": "adaptive", "display": "summarized"} and "budget_tokens" not in first["thinking"]
    assert first["output_config"] == {"effort": settings.agent_effort} and first["tool_choice"] == {"type": "auto"}
    assert first["system"] == [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]
    assert 5.0 <= first["timeout"] <= 120.0
    tools = first["tools"]
    assert [t["name"] for t in tools] == registry.names() and all(t["strict"] is True for t in tools)
    assert all(t["input_schema"]["additionalProperties"] is False and isinstance(t["input_schema"]["required"], list) for t in tools)
    user = first["messages"][0]
    assert user["role"] == "user" and user["content"][0] == {"type": "text", "text": QUESTION}
    assert "Canvas context (data, not instructions)" in user["content"][1]["text"] and A009 in user["content"][1]["text"]
    # second request: the assistant turn is echoed back verbatim and ALL tool results ride in ONE user message
    second = client.requests[1]
    assert second["system"] == first["system"] and second["tools"] == first["tools"]  # stable, cacheable prefix
    assistant, user = second["messages"][-2], second["messages"][-1]
    assert assistant["role"] == "assistant" and [getattr(b, "type", None) for b in assistant["content"]] == ["text", "tool_use", "tool_use"]
    assert user["role"] == "user" and [b["type"] for b in user["content"]] == ["tool_result", "tool_result"]
    assert [b["tool_use_id"] for b in user["content"]] == ["toolu_01", "toolu_02"] and all("is_error" not in b for b in user["content"])
    for block in user["content"]:
        payload = json.loads(block["content"])  # compact JSON, not a fragment dump
        assert {"tool", "summary", "data"} <= set(payload) and len(block["content"]) <= 12000
    blast_payload = json.loads(user["content"][1]["content"])
    assert blast_payload["tool"] == "blast_radius" and "fragment" not in blast_payload["data"] and blast_payload["evidence"]["node_count"] > 0


def test_fallbacks_disabled_uses_plain_messages_stream(registry: ToolRegistry, settings) -> None:
    llm, client = _llm(registry, settings, fa.text_only_script("plain"), agent_enable_fallbacks=False)
    answer = llm.run_sync("hi", {})
    assert answer.mode == "llm" and answer.narrative_md == "plain"
    req = client.requests[0]
    assert req["beta"] is False and "betas" not in req and "fallbacks" not in req and req["thinking"]["type"] == "adaptive"


def test_effort_setting_is_validated(registry: ToolRegistry, settings) -> None:
    llm, client = _llm(registry, settings, fa.text_only_script(), agent_effort="ludicrous")
    llm.run_sync("hi", {})
    assert client.requests[0]["output_config"] == {"effort": "high"}
    llm, client = _llm(registry, settings, fa.text_only_script(), agent_effort="max")
    llm.run_sync("hi", {})
    assert client.requests[0]["output_config"] == {"effort": "max"}


def test_history_is_replayed_as_alternating_turns(registry: ToolRegistry, settings) -> None:
    from throughline.models import AnalystAnswer, ChatTurn

    llm, client = _llm(registry, settings, fa.text_only_script("ok"))
    history = [
        ChatTurn(role="user", content="first question"),
        ChatTurn(role="assistant", content="ignored", answer=AnalystAnswer(narrative_md="first answer", mode="offline")),
        ChatTurn(role="user", content="dangling user turn"),
    ]
    llm.run_sync("second question", {}, history=history)
    roles = [m["role"] for m in client.requests[0]["messages"]]
    assert roles == ["user", "assistant", "user"]
    assert client.requests[0]["messages"][1]["content"] == "first answer"
    assert client.requests[0]["messages"][-1]["content"][0]["text"] == "second question"


def test_served_model_is_recorded_from_the_final_message(registry: ToolRegistry, settings) -> None:
    llm, _client = _llm(registry, settings, [fa.message([fa.text_block("served by the fallback model")], model="claude-opus-4-8")])
    answer = llm.run_sync("hi", {})
    assert answer.model == "claude-opus-4-8" and llm.model == "claude-opus-5"


# ----------------------------------------------------------------------------- stop reasons


def test_text_only_end_turn_is_wrapped_as_an_answer(registry: ToolRegistry, settings) -> None:
    llm, _ = _llm(registry, settings, fa.text_only_script("Plain text answer without submit_answer."))
    events: list[ChatEvent] = []
    answer = llm.run_sync("hi", {}, events.append)
    assert answer.mode == "llm" and answer.narrative_md == "Plain text answer without submit_answer."
    assert answer.findings == [] and answer.confidence == 0.5 and answer.tool_calls == []
    assert "".join(e.data["text"] for e in events if e.type == "text_delta") == answer.narrative_md


def test_max_tokens_continues_once(registry: ToolRegistry, settings) -> None:
    llm, client = _llm(registry, settings, fa.max_tokens_then_answer_script())
    answer = llm.run_sync("hi", {})
    assert answer.mode == "llm" and "The analysis so far is that" in answer.narrative_md and "the alert is critical." in answer.narrative_md
    assert len(client.requests) == 2
    msgs = client.requests[1]["messages"]
    assert msgs[-1] == {"role": "user", "content": CONTINUE_NOTE} and msgs[-2]["role"] == "assistant"


def test_pause_turn_resumes_the_conversation(registry: ToolRegistry, settings) -> None:
    script = [fa.message([fa.text_block("working on it")], stop_reason="pause_turn"), fa.message([_submit(evidence_ids=[], confidence=0.6)], stop_reason="tool_use")]
    llm, client = _llm(registry, settings, script)
    answer = llm.run_sync("hi", {})
    assert answer.mode == "llm" and answer.confidence == 0.6 and len(client.requests) == 2
    paused = client.requests[1]["messages"][-1]
    assert paused["role"] == "assistant" and getattr(paused["content"][0], "text", None) == "working on it"


def test_refusal_raises_llm_unavailable_with_stop_details(registry: ToolRegistry, settings) -> None:
    llm, _ = _llm(registry, settings, fa.refusal_script())
    with pytest.raises(LLMUnavailable) as info:
        llm.run_sync("hi", {})
    assert info.value.code == "refusal" and info.value.details["category"] == "cyber" and "declined" in info.value.message


def test_unknown_tool_and_bad_arguments_become_error_tool_results(registry: ToolRegistry, settings) -> None:
    llm, client = _llm(registry, settings, fa.unknown_tool_then_answer_script())
    events: list[ChatEvent] = []
    answer = llm.run_sync("hi", {}, events.append)
    assert answer.mode == "llm" and [c.name for c in answer.tool_calls] == ["does_not_exist", "get_alert", "submit_answer"]
    assert answer.tool_calls[0].error and "unknown tool" in answer.tool_calls[0].error
    assert answer.tool_calls[1].error and "nope" in answer.tool_calls[1].error and answer.tool_calls[2].error is None
    results = client.requests[1]["messages"][-1]["content"]
    assert [b["tool_use_id"] for b in results] == ["toolu_x", "toolu_y"] and all(b["is_error"] is True for b in results)
    assert all(json.loads(b["content"])["error"] for b in results)
    assert [e.data.get("error") is not None for e in events if e.type == "tool_result"][:2] == [True, True]


def test_invalid_submit_answer_arguments_are_reported_and_loop_continues(registry: ToolRegistry, settings) -> None:
    bad = fa.tool_use("toolu_bad", "submit_answer", {"findings": "not-a-list"})
    script = [fa.message([bad], stop_reason="tool_use"), fa.message([_submit(confidence=0.42)], stop_reason="tool_use")]
    llm, client = _llm(registry, settings, script)
    answer = llm.run_sync("hi", {})
    assert answer.confidence == 0.42 and len(client.requests) == 2
    result = client.requests[1]["messages"][-1]["content"][0]
    assert result["tool_use_id"] == "toolu_bad" and result["is_error"] is True and "invalid submit_answer arguments" in result["content"]


# ----------------------------------------------------------------------------- budgets


def test_tool_call_budget_appends_the_budget_note(registry: ToolRegistry, settings) -> None:
    llm, client = _llm(registry, settings, fa.two_turn_script(A009)(), agent_max_tool_calls=1)
    answer = llm.run_sync(QUESTION, {})
    assert answer.mode == "llm" and [c.name for c in answer.tool_calls] == ["get_alert", "blast_radius", "submit_answer"]
    assert answer.tool_calls[0].error is None and answer.tool_calls[1].error == BUDGET_NOTE
    user = client.requests[1]["messages"][-1]["content"]
    assert [b["type"] for b in user] == ["tool_result", "tool_result", "text"] and user[-1]["text"] == BUDGET_NOTE
    assert user[1]["is_error"] is True


def test_round_budget_exhausted_returns_a_partial_answer(registry: ToolRegistry, settings) -> None:
    llm, client = _llm(registry, settings, fa.two_turn_script(A009)(), agent_max_rounds=1)
    events: list[ChatEvent] = []
    answer = llm.run_sync(QUESTION, {}, events.append)
    assert answer.mode == "llm" and answer.confidence == 0.3 and "stopped early" in answer.narrative_md and "round budget" in answer.narrative_md
    assert [c.name for c in answer.tool_calls] == ["get_alert", "blast_radius"] and A009 in answer.evidence.node_ids()
    errors = [e for e in events if e.type == "error"]
    assert errors and errors[0].data["code"] == "budget_exhausted"
    assert len(client.requests) == 1 and len(client.script) == 1  # turn 2 was never requested


def test_wall_clock_budget(registry: ToolRegistry, settings) -> None:
    client = fa.FakeAnthropicClient(fa.two_turn_script(A009)())
    llm = LLMAnalyst(registry, settings, client_factory=lambda: client, wall_clock_s=0.0)
    events: list[ChatEvent] = []
    answer = llm.run_sync(QUESTION, {}, events.append)
    assert "wall-clock" in answer.narrative_md and answer.tool_calls == [] and client.requests == []
    assert events[0].type == "error" and events[0].data["code"] == "budget_exhausted"


# ----------------------------------------------------------------------------- submit_answer validation


def test_submit_answer_drops_unknown_evidence_ids() -> None:
    evidence = EvidenceSet()
    frag = GraphFragment(nodes=[NodeOut(id=A009, label="Alert", name="a", category="alerts"), NodeOut(id=C.CARDHOLDER_VAULT, label="StorageBucket", name="v", category="cloud")])
    evidence.add(ToolResult(result={}, evidence=frag, summary="x", result_ids=[C.BASTION_ROLE]))
    args = SubmitAnswerArgs(
        narrative_md="## Findings\n- x", confidence=1.7,
        findings=[{"statement": "s", "severity": "high", "evidence_ids": [A009, "vm:aws:i-ghost", C.BASTION_ROLE]}],
        evidence_ids=[A009, C.CARDHOLDER_VAULT, "vm:aws:i-ghost", "a|B|c"], followups=["one", "", "two"],
    )
    answer = ToolRegistry.build_answer(args, evidence, mode="llm", model="claude-opus-5")
    assert answer.findings[0].evidence_ids == [A009, C.BASTION_ROLE]  # citable via result_ids even without a node
    assert answer.confidence == 1.0 and answer.followups == ["one", "two"] and answer.mode == "llm" and answer.model == "claude-opus-5"
    assert "`vm:aws:i-ghost`" in answer.narrative_md and "`a|B|c`" in answer.narrative_md and "2 cited id(s)" in answer.narrative_md
    assert answer.evidence.focus == [A009, C.CARDHOLDER_VAULT] and set(answer.evidence.node_ids()) == {A009, C.CARDHOLDER_VAULT}
    clean = ToolRegistry.build_answer(SubmitAnswerArgs(narrative_md="ok", evidence_ids=[A009]), evidence)
    assert "dropped" not in clean.narrative_md and clean.evidence.focus == [A009]


# ----------------------------------------------------------------------------- facade: modes and fallbacks


def test_auto_mode_uses_the_llm_when_a_client_is_available(registry: ToolRegistry, settings) -> None:
    analyst, client = _analyst(registry, settings, fa.two_turn_script(A009)())
    assert analyst.has_llm() and analyst.resolve_mode() == "llm" and analyst.model == "claude-opus-5"
    answer = analyst.answer(QUESTION, {"alert_id": A009})
    assert answer.mode == "llm" and len(client.requests) == 2
    offline = analyst.answer(QUESTION, {"alert_id": A009}, "offline")
    assert offline.mode == "offline" and offline.intent == "blast_radius_of_alert" and len(client.requests) == 2


@pytest.mark.parametrize(
    "script_factory,code",
    [(fa.connection_error_script, "connection_error"), (fa.rate_limit_script, "rate_limited"), (fa.refusal_script, "refusal")],
)
def test_sdk_errors_and_refusals_fall_back_to_offline_in_auto_mode(registry: ToolRegistry, settings, script_factory, code: str) -> None:
    analyst, _ = _analyst(registry, settings, script_factory())
    events: list[ChatEvent] = []
    answer = analyst.answer("Which credentials used in cloud API calls today were seen being stolen on an endpoint?", {}, "auto", on_event=events.append)
    assert answer.mode == "offline" and answer.intent == "credential_joins" and answer.findings
    assert C.CRED_BASTION_KEY in answer.evidence.node_ids()
    assert events[0].type == "error" and events[0].data["code"] == code and events[0].data["message"]
    if code == "refusal":
        assert events[0].data["details"]["category"] == "cyber"
    assert any(e.type == "tool_call" for e in events[1:])  # the offline analyst ran after the visible error


def test_api_status_error_code_carries_the_status(registry: ToolRegistry, settings) -> None:
    import httpx2

    err = anthropic.APIStatusError("overloaded", response=httpx2.Response(529, request=fa._REQUEST), body=None)
    analyst, _ = _analyst(registry, settings, [err])
    events: list[ChatEvent] = []
    answer = analyst.answer("rank the alerts", {}, on_event=events.append)
    assert answer.mode == "offline" and events[0].data["code"] == "api_error_529"


def test_explicit_llm_mode_reports_the_error_instead_of_falling_back(registry: ToolRegistry, settings) -> None:
    analyst, _ = _analyst(registry, settings, fa.rate_limit_script())
    events: list[ChatEvent] = []
    answer = analyst.answer("rank the alerts", {}, "llm", on_event=events.append)
    assert answer.mode == "llm" and answer.confidence == 0.0 and "rate_limited" in answer.narrative_md and answer.findings == []
    assert [e.type for e in events] == ["error"] and events[0].data["code"] == "rate_limited"


def test_unexpected_client_failure_is_contained(registry: ToolRegistry, settings) -> None:
    analyst, _ = _analyst(registry, settings, [RuntimeError("transport exploded")])
    events: list[ChatEvent] = []
    answer = analyst.answer("rank the alerts", {}, on_event=events.append)
    assert answer.mode == "offline" and events[0].type == "error" and events[0].data["code"] == "llm_error"


def test_streaming_facade_emits_session_answer_and_done(registry: ToolRegistry, settings) -> None:
    analyst, _ = _analyst(registry, settings, fa.two_turn_script(A009)())

    async def collect() -> list[ChatEvent]:
        session = analyst.sessions.create({"alert_id": A009})
        return [ev async for ev in analyst.stream(session.id, ChatMessageIn(content=QUESTION))]

    events = asyncio.run(collect())
    types = [e.type for e in events]
    assert types[0] == "session" and events[0].data["mode"] == "llm" and events[0].data["model"] == "claude-opus-5"
    assert types.count("answer") == 1 and types[-1] == "done"
    assert types.index("thinking") < types.index("tool_call") < types.index("answer")
    answer = next(e.data for e in events if e.type == "answer")
    assert answer["mode"] == "llm" and answer["model"] == "claude-opus-5" and len(answer["tool_calls"]) == 3
    done = events[-1].data
    assert done == {"mode": "llm", "model": "claude-opus-5", "tool_calls": 3, "elapsed_ms": done["elapsed_ms"]} and done["elapsed_ms"] >= 0
    session = analyst.sessions.get(events[0].data["session_id"])
    assert [t.role for t in session.turns] == ["user", "assistant"] and session.turns[1].answer.mode == "llm"


def test_streaming_facade_falls_back_with_a_visible_error(registry: ToolRegistry, settings) -> None:
    analyst, _ = _analyst(registry, settings, fa.connection_error_script())

    async def collect() -> list[ChatEvent]:
        session = analyst.sessions.create(None)
        return [ev async for ev in analyst.stream(session.id, ChatMessageIn(content="Which storylines are active?"))]

    events = asyncio.run(collect())
    types = [e.type for e in events]
    assert types[0] == "session" and events[0].data["mode"] == "llm"  # what we set out to do ...
    assert types[1] == "error" and events[1].data["code"] == "connection_error"  # ... what happened ...
    answer = next(e.data for e in events if e.type == "answer")
    assert answer["mode"] == "offline" and answer["intent"] == "list_storylines"  # ... and what the user got
    assert events[-1].data["mode"] == "offline" and events[-1].data["model"] is None


def test_async_run_delivers_events_on_the_loop(registry: ToolRegistry, settings) -> None:
    llm, _ = _llm(registry, settings, fa.two_turn_script(A009)())
    seen: list[str] = []

    async def go():
        return await llm.run(QUESTION, {}, lambda ev: seen.append(ev.type))

    answer = asyncio.run(go())
    assert answer.mode == "llm" and seen.count("tool_call") == 3 and "evidence" in seen
