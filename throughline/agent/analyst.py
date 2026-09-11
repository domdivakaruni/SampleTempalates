"""Analyst facade: picks the LLM or the offline analyst per ``settings.agent_mode`` and key presence, streams
``ChatEvent``s for the chat API and records turns in the session store.

Mode resolution (``resolve_mode``):

* ``offline``            -> offline analyst.
* ``llm``                -> Claude; on failure an ``error`` event is emitted and an error answer (mode ``llm``) is
                            returned, unless no key/client is available at all (then offline with an ``error``).
* ``auto`` (default)     -> Claude when an API key (or an injected client factory) is present, otherwise offline;
                            API errors, refusals and budget failures fall back to the offline analyst after a
                            visible ``error`` event (``AnalystAnswer.mode == "offline"``).
"""
from __future__ import annotations

import asyncio
import functools
import logging
import os
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from typing import Any

from throughline.agent.llm import LLMAnalyst, LLMUnavailable
from throughline.agent.offline import OfflineAnalyst
from throughline.agent.session import ChatSessionStore, now_iso
from throughline.agent.tools import ToolRegistry
from throughline.models import AnalystAnswer, ChatEvent, ChatMessageIn, ChatTurn

log = logging.getLogger(__name__)

EventSink = Callable[[ChatEvent], None]
_DONE = object()


class Analyst:
    def __init__(
        self,
        registry: ToolRegistry,
        settings: Any | None = None,
        *,
        sessions: ChatSessionStore | None = None,
        llm: LLMAnalyst | None = None,
        offline: OfflineAnalyst | None = None,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        if settings is None:
            from throughline.config import settings as _settings

            settings = _settings
        self.registry = registry
        self.settings = settings
        self.sessions = sessions or ChatSessionStore()
        self.offline = offline or OfflineAnalyst(registry)
        self._client_factory = client_factory
        self.llm = llm or LLMAnalyst(registry, settings, client_factory=client_factory)

    # -------------------------------------------------------------- mode

    def has_llm(self) -> bool:
        if self._client_factory is not None or getattr(self.llm, "_client_factory", None) is not None:
            return True
        return bool(getattr(self.settings, "anthropic_api_key", None) or os.environ.get("ANTHROPIC_API_KEY"))

    def resolve_mode(self, requested: str | None = None) -> str:
        """Effective mode for a turn: ``"llm"`` or ``"offline"``."""
        mode = (requested or getattr(self.settings, "agent_mode", "auto") or "auto").lower()
        if mode == "offline":
            return "offline"
        if mode == "llm":
            return "llm" if self.has_llm() else "offline"
        return "llm" if self.has_llm() else "offline"

    @property
    def model(self) -> str:
        return self.llm.model

    def model_for(self, mode: str) -> str | None:
        return self.model if mode == "llm" else None

    # -------------------------------------------------------------- core

    def _run(
        self,
        question: str,
        context: Mapping[str, Any] | None,
        requested_mode: str | None,
        emit: EventSink,
        history: Sequence[ChatTurn] | None,
    ) -> AnalystAnswer:
        explicit = (requested_mode or getattr(self.settings, "agent_mode", "auto") or "auto").lower()
        mode = self.resolve_mode(requested_mode)
        if explicit == "llm" and mode == "offline":
            emit(ChatEvent(type="error", data={"code": "no_api_key", "message": "LLM mode requested but no Anthropic API key is configured; answering offline."}))
        if mode == "llm":
            try:
                return self.llm.run_sync(question, context, emit, history)
            except LLMUnavailable as exc:
                emit(ChatEvent(type="error", data={"code": exc.code, "message": exc.message, "details": exc.details}))
                if explicit == "llm":
                    return AnalystAnswer(
                        narrative_md=f"The LLM analyst could not answer ({exc.code}): {exc.message}", findings=[], confidence=0.0,
                        followups=[], mode="llm", model=self.llm.model,
                    )
                log.info("LLM analyst unavailable (%s); falling back to the offline analyst", exc.code)
        try:
            return self.offline.answer(question, context, emit, history)
        except Exception as exc:  # the offline analyst guards its playbooks; this is the last line of defence
            log.exception("offline analyst failed")
            emit(ChatEvent(type="error", data={"code": "internal_error", "message": f"{type(exc).__name__}: {exc}"}))
            return AnalystAnswer(narrative_md=f"The analyst failed: {type(exc).__name__}: {exc}", confidence=0.0, mode="offline")

    def answer(
        self,
        question: str,
        context: Mapping[str, Any] | None = None,
        mode: str | None = None,
        *,
        on_event: EventSink | None = None,
        history: Sequence[ChatTurn] | None = None,
    ) -> AnalystAnswer:
        """Non-streaming answer (POST /agent/answer, CLI ``ask``)."""
        return self._run(question, context, mode, on_event or (lambda ev: None), history)

    async def answer_async(self, question: str, context: Mapping[str, Any] | None = None, mode: str | None = None) -> AnalystAnswer:
        return await asyncio.to_thread(self.answer, question, context, mode)

    # -------------------------------------------------------------- chat sessions

    def respond(self, session_id: str, message: ChatMessageIn) -> ChatTurn:
        """Non-streaming chat turn: runs the analyst and records both turns in the session."""
        session = self.sessions.get(session_id)
        if message.context:
            self.sessions.update_context(session_id, message.context)
            session = self.sessions.get(session_id)
        history = self.sessions.history(session_id)
        self.sessions.append_turn(session_id, ChatTurn(role="user", content=message.content, created_at=now_iso()))
        answer = self.answer(message.content, session.context, message.mode, history=history)
        turn = ChatTurn(role="assistant", content=answer.narrative_md, answer=answer, created_at=now_iso())
        self.sessions.append_turn(session_id, turn)
        return turn

    async def stream(self, session_id: str, message: ChatMessageIn) -> AsyncIterator[ChatEvent]:
        """SSE event stream for one chat turn (05 section 6): session, ..., answer, done."""
        session = self.sessions.get(session_id)
        if message.context:
            self.sessions.update_context(session_id, message.context)
            session = self.sessions.get(session_id)
        mode = self.resolve_mode(message.mode)
        model = self.model_for(mode)
        started = time.perf_counter()
        yield ChatEvent(type="session", data={"session_id": session.id, "mode": mode, "model": model})
        history = self.sessions.history(session_id)
        self.sessions.append_turn(session_id, ChatTurn(role="user", content=message.content, created_at=now_iso()))

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[Any] = asyncio.Queue()

        def emit(ev: ChatEvent) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, ev)

        future = loop.run_in_executor(None, functools.partial(self._run, message.content, dict(session.context), message.mode, emit, history))
        future.add_done_callback(lambda _f: queue.put_nowait(_DONE))
        while True:
            item = await queue.get()
            if item is _DONE:
                break
            yield item
        try:
            answer: AnalystAnswer = future.result()
        except Exception as exc:  # pragma: no cover - _run guards everything; keep the stream well-formed anyway
            log.exception("analyst stream failed")
            yield ChatEvent(type="error", data={"code": "internal_error", "message": f"{type(exc).__name__}: {exc}"})
            answer = AnalystAnswer(narrative_md=f"The analyst failed: {exc}", confidence=0.0, mode="offline")
        self.sessions.append_turn(session_id, ChatTurn(role="assistant", content=answer.narrative_md, answer=answer, created_at=now_iso()))
        yield ChatEvent(type="answer", data=answer.model_dump(mode="json"))
        yield ChatEvent(
            type="done",
            data={"mode": answer.mode, "model": answer.model, "tool_calls": len(answer.tool_calls), "elapsed_ms": int((time.perf_counter() - started) * 1000)},
        )
