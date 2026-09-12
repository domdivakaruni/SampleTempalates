"""In-memory chat sessions for the analyst (docs/05-api-contract.md section 6).

A session holds the canvas context the UI sends (``alert_id``, ``storyline_id``, ``selected_node_ids``) and the
append-only list of turns. Sessions live in process memory; the store is thread-safe and bounded (LRU eviction).
"""
from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from throughline.models import ChatSession, ChatTurn

CONTEXT_KEYS = ("alert_id", "storyline_id", "selected_node_ids", "node_id", "screen")


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_context(context: Mapping[str, Any] | None) -> dict[str, Any]:
    """Keep only well-formed, JSON-friendly context values (drop Nones and empties)."""
    out: dict[str, Any] = {}
    for key, value in (context or {}).items():
        if value is None or value == "" or value == []:
            continue
        if key == "selected_node_ids":
            if isinstance(value, str):
                value = [value]
            value = [str(v) for v in value if v][:200]
            if not value:
                continue
        elif isinstance(value, (dict, list)):
            pass
        else:
            value = str(value)
        out[str(key)] = value
    return out


class ChatSessionStore:
    def __init__(self, max_sessions: int = 500) -> None:
        self._sessions: OrderedDict[str, ChatSession] = OrderedDict()
        self._lock = threading.Lock()
        self.max_sessions = max_sessions

    def create(self, context: Mapping[str, Any] | None = None) -> ChatSession:
        session = ChatSession(id=uuid.uuid4().hex[:16], created_at=now_iso(), turns=[], context=clean_context(context))
        with self._lock:
            self._sessions[session.id] = session
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        return session

    def get(self, session_id: str) -> ChatSession:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(f"chat session {session_id!r} not found")
            self._sessions.move_to_end(session_id)
            return session

    def get_optional(self, session_id: str) -> ChatSession | None:
        try:
            return self.get(session_id)
        except KeyError:
            return None

    def append_turn(self, session_id: str, turn: ChatTurn) -> ChatSession:
        session = self.get(session_id)
        if turn.created_at is None:
            turn = turn.model_copy(update={"created_at": now_iso()})
        with self._lock:
            session.turns.append(turn)
        return session

    def update_context(self, session_id: str, context: Mapping[str, Any] | None) -> ChatSession:
        session = self.get(session_id)
        extra = clean_context(context)
        if extra:
            with self._lock:
                session.context.update(extra)
        return session

    def history(self, session_id: str, limit: int = 6) -> list[ChatTurn]:
        session = self.get(session_id)
        return list(session.turns)[-limit:] if limit else list(session.turns)

    def __len__(self) -> int:
        return len(self._sessions)

    def __contains__(self, session_id: str) -> bool:
        return session_id in self._sessions
