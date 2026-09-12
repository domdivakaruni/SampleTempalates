"""A scripted stand-in for ``anthropic.Anthropic`` used to test the tool-use loop without an API key.

The fake mirrors the surface ``LLMAnalyst`` touches: ``client.messages.stream(**kwargs)`` and
``client.beta.messages.stream(**kwargs)`` return a context manager whose ``__enter__`` yields an iterable of
stream events and exposes ``get_final_message()``. Messages and events are real ``anthropic.types.beta`` objects so
the loop handles the SDK's shapes, and error variants raise the SDK's real exception classes.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator
from typing import Any

import anthropic
import anthropic.types.beta as tb
import httpx2

_REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def tool_use(block_id: str, name: str, arguments: dict[str, Any]) -> tb.BetaToolUseBlock:
    return tb.BetaToolUseBlock(type="tool_use", id=block_id, name=name, input=arguments)


def text_block(text: str) -> tb.BetaTextBlock:
    return tb.BetaTextBlock(type="text", text=text)


def message(content: list[Any], stop_reason: str = "end_turn", *, model: str = "claude-opus-5", stop_details: Any = None) -> tb.BetaMessage:
    return tb.BetaMessage(
        id="msg_fake", type="message", role="assistant", model=model, content=content, stop_reason=stop_reason,  # type: ignore[arg-type]
        stop_sequence=None, usage=tb.BetaUsage(input_tokens=100, output_tokens=50), stop_details=stop_details,
    )


def events_for(msg: tb.BetaMessage, *, thinking: str | None = None) -> list[Any]:
    """Approximate the raw stream for a message: thinking/text deltas plus tool_use block starts."""
    out: list[Any] = [tb.BetaRawMessageStartEvent(type="message_start", message=msg.model_copy(update={"content": []}))]
    index = 0
    if thinking:
        out.append(tb.BetaRawContentBlockStartEvent(type="content_block_start", index=index, content_block=tb.BetaThinkingBlock(type="thinking", thinking="", signature="sig")))
        out.append(tb.BetaRawContentBlockDeltaEvent(type="content_block_delta", index=index, delta=tb.BetaThinkingDelta(type="thinking_delta", thinking=thinking)))
        out.append(tb.BetaRawContentBlockStopEvent(type="content_block_stop", index=index))
        index += 1
    for block in msg.content:
        if block.type == "text":
            out.append(tb.BetaRawContentBlockStartEvent(type="content_block_start", index=index, content_block=tb.BetaTextBlock(type="text", text="")))
            for i in range(0, len(block.text), 20):
                out.append(tb.BetaRawContentBlockDeltaEvent(type="content_block_delta", index=index, delta=tb.BetaTextDelta(type="text_delta", text=block.text[i : i + 20])))
        elif block.type == "tool_use":
            out.append(tb.BetaRawContentBlockStartEvent(type="content_block_start", index=index, content_block=tb.BetaToolUseBlock(type="tool_use", id=block.id, name=block.name, input={})))
            out.append(tb.BetaRawContentBlockDeltaEvent(type="content_block_delta", index=index, delta=tb.BetaInputJSONDelta(type="input_json_delta", partial_json=json.dumps(block.input))))
        out.append(tb.BetaRawContentBlockStopEvent(type="content_block_stop", index=index))
        index += 1
    out.append(tb.BetaRawMessageDeltaEvent(type="message_delta", delta={"stop_reason": msg.stop_reason, "stop_sequence": None}, usage=tb.BetaMessageDeltaUsage(output_tokens=50)))  # type: ignore[arg-type]
    out.append(tb.BetaRawMessageStopEvent(type="message_stop"))
    return out


class FakeStream:
    def __init__(self, final: tb.BetaMessage, events: Iterable[Any]) -> None:
        self._final = final
        self._events = list(events)

    def __iter__(self) -> Iterator[Any]:
        yield from self._events

    def get_final_message(self) -> tb.BetaMessage:
        return self._final

    def close(self) -> None:
        pass


class FakeStreamManager:
    def __init__(self, turn: Any, kwargs: dict[str, Any]) -> None:
        self._turn = turn
        self.kwargs = kwargs

    def __enter__(self) -> FakeStream:
        turn = self._turn
        if isinstance(turn, BaseException):
            raise turn
        if callable(turn):
            turn = turn(self.kwargs)
            if isinstance(turn, BaseException):
                raise turn
        if isinstance(turn, tuple):
            final, thinking = turn
        else:
            final, thinking = turn, None
        return FakeStream(final, events_for(final, thinking=thinking))

    def __exit__(self, *exc: Any) -> None:
        return None


class _Messages:
    def __init__(self, client: FakeAnthropicClient, beta: bool) -> None:
        self._client = client
        self._beta = beta

    def stream(self, **kwargs: Any) -> FakeStreamManager:
        # snapshot: the loop keeps appending to the live ``messages`` list after the request was issued
        self._client.requests.append({"beta": self._beta, **kwargs, "messages": list(kwargs.get("messages") or [])})
        if not self._client.script:
            raise AssertionError("fake client script exhausted: the loop asked for one more model round than scripted")
        turn = self._client.script.pop(0)
        return FakeStreamManager(turn, kwargs)


class _Beta:
    def __init__(self, client: FakeAnthropicClient) -> None:
        self.messages = _Messages(client, beta=True)


class FakeAnthropicClient:
    """``script`` is a list of turns: a ``BetaMessage``, ``(BetaMessage, thinking_text)``, an exception instance
    (raised when the stream is opened) or a callable ``kwargs -> turn``."""

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.requests: list[dict[str, Any]] = []
        self.messages = _Messages(self, beta=False)
        self.beta = _Beta(self)


# ----------------------------------------------------------------------------- ready-made scripts


def two_turn_script(alert_id: str, *, extra_bogus_id: str = "vm:aws:i-does-not-exist") -> Callable[[], list[Any]]:
    """Turn 1: get_alert + blast_radius in parallel; turn 2: submit_answer citing evidence plus one unknown id."""

    def build() -> list[Any]:
        turn1 = (
            message(
                [
                    text_block("Let me look at the alert and its blast radius."),
                    tool_use("toolu_01", "get_alert", {"alert_id": alert_id}),
                    tool_use("toolu_02", "blast_radius", {"id": alert_id, "depth": 5}),
                ],
                stop_reason="tool_use",
            ),
            "Plan: fetch the alert, then compute reach.",
        )

        def turn2(kwargs: dict[str, Any]) -> tb.BetaMessage:
            # cite ids that really came back in the tool results of the previous user message
            last_user = kwargs["messages"][-1]
            seen: list[str] = []
            for block in last_user["content"]:
                if block.get("type") == "tool_result":
                    payload = json.loads(block["content"])
                    for candidate in _walk_ids(payload):
                        if candidate not in seen:
                            seen.append(candidate)
            cited = [alert_id] + [s for s in seen if s.startswith(("bucket:", "role:", "secret:", "database:"))][:6]
            return message(
                [
                    tool_use(
                        "toolu_03",
                        "submit_answer",
                        {
                            "narrative_md": "## Findings\n- The alert reaches the cardholder vault.\n\n## Evidence\n- `" + alert_id + "`\n\n## Impact\n- PCI data at risk.\n\n## Recommended actions\n1. Isolate the host.",
                            "findings": [
                                {"statement": f"`{alert_id}` reaches crown jewels", "severity": "critical", "evidence_ids": cited + [extra_bogus_id]},
                            ],
                            "evidence_ids": cited + [extra_bogus_id],
                            "confidence": 0.9,
                            "followups": ["Trace the attack path from WKS-3391.", "Simulate isolating BAS-01."],
                        },
                    )
                ],
                stop_reason="tool_use",
            )

        return [turn1, turn2]

    return build


def _walk_ids(obj: Any) -> Iterator[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "id" and isinstance(v, str) and ":" in v:
                yield v
            else:
                yield from _walk_ids(v)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, str) and ":" in v and " " not in v and "|" not in v:
                yield v
            else:
                yield from _walk_ids(v)


def connection_error_script() -> list[Any]:
    return [anthropic.APIConnectionError(request=_REQUEST)]


def rate_limit_script() -> list[Any]:
    return [anthropic.RateLimitError("rate limited", response=httpx2.Response(429, request=_REQUEST), body=None)]


def refusal_script() -> list[Any]:
    return [message([], stop_reason="refusal", stop_details=tb.BetaRefusalStopDetails(type="refusal", category="cyber", explanation="declined"))]


def text_only_script(text: str = "Plain text answer without submit_answer.") -> list[Any]:
    return [message([text_block(text)], stop_reason="end_turn")]


def unknown_tool_then_answer_script() -> list[Any]:
    return [
        message([tool_use("toolu_x", "does_not_exist", {"foo": 1}), tool_use("toolu_y", "get_alert", {"alert_id": "alert:falcon:nope"})], stop_reason="tool_use"),
        message([tool_use("toolu_z", "submit_answer", {"narrative_md": "## Findings\n- nothing", "findings": [], "evidence_ids": [], "confidence": 0.3, "followups": []})], stop_reason="tool_use"),
    ]


def max_tokens_then_answer_script() -> list[Any]:
    return [
        message([text_block("The analysis so far is that")], stop_reason="max_tokens"),
        message([text_block(" the alert is critical.")], stop_reason="end_turn"),
    ]
