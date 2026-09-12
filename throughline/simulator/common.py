"""Shared utilities for all simulator generators: deterministic RNG, clock, ids, JSONL writing.

Every generator must obtain randomness through ``rng(namespace)`` so that adding a generator never
perturbs another generator's output for the same seed.
"""
from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from throughline.config import settings

SEED = settings.sim_seed
NOW = datetime.strptime(settings.sim_now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def rng(namespace: str) -> random.Random:
    """A Random instance seeded from the global seed and a namespace (stable across runs)."""
    h = hashlib.sha256(f"{SEED}:{namespace}".encode()).hexdigest()
    return random.Random(int(h[:16], 16))


def ts(dt: datetime) -> str:
    """ISO-8601 UTC string with a trailing Z (the only timestamp format in the JSONL files)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def ago(**kwargs: float) -> str:
    return ts(NOW - timedelta(**kwargs))


def at(text: str) -> str:
    """Normalize a storyline timestamp like '2026-09-10 02:11:45' or '2026-09-10T02:11:45Z'."""
    text = text.strip().replace(" ", "T")
    if not text.endswith("Z"):
        text += "Z"
    if len(text) == len("2026-09-10T02:11Z"):
        text = text[:-1] + ":00Z"
    return ts(parse_ts(text))


def stable_hex(*parts: Any, length: int = 16) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:length]


def fake_sha256(*parts: Any) -> str:
    return hashlib.sha256(("sha256|" + "|".join(str(p) for p in parts)).encode()).hexdigest()


def node(
    id: str,
    label: str,
    name: str,
    props: dict[str, Any] | None = None,
    *,
    source: str,
    source_id: str | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
    confidence: float = 1.0,
) -> dict[str, Any]:
    return {
        "id": id,
        "label": label,
        "name": name,
        "source": source,
        "source_id": source_id if source_id is not None else id.split(":")[-1],
        "first_seen": first_seen or ago(days=120),
        "last_seen": last_seen or ts(NOW - timedelta(minutes=5)),
        "confidence": confidence,
        "props": props or {},
    }


def edge(
    type: str,
    src: str,
    dst: str,
    props: dict[str, Any] | None = None,
    *,
    source: str,
    first_seen: str | None = None,
    last_seen: str | None = None,
    confidence: float = 1.0,
) -> dict[str, Any]:
    return {
        "type": type,
        "src": src,
        "dst": dst,
        "source": source,
        "first_seen": first_seen or ago(days=120),
        "last_seen": last_seen or ts(NOW - timedelta(minutes=5)),
        "confidence": confidence,
        "props": props or {},
    }


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":"), ensure_ascii=False))
            f.write("\n")
            n += 1
    return n


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def pick(r: random.Random, weighted: dict[str, float]) -> str:
    """Weighted choice from a {value: weight} mapping."""
    values = list(weighted.keys())
    weights = list(weighted.values())
    return r.choices(values, weights=weights, k=1)[0]
