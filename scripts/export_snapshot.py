#!/usr/bin/env python3
"""Export the static-snapshot edition of the Throughline UI (docs/10-static-snapshot.md, sections 1 and 2).

The exporter starts the real API in-process (``fastapi.testclient.TestClient`` over ``create_app`` with the NetworkX
store and the offline analyst) and records the JSON every endpoint returns, so the payload shapes are exactly the
ones the routers serve (``web/src/api/types.ts``). Only ``graph/nodes.json``, the compact edge shards and
``search.json`` are built straight from the ``ContextGraph``.

Files written into ``--out`` (default ``web/snapshot-out``)::

    manifest.json  meta.json  alerts.json  alert_details/<NN>.json  storylines.json  ti.json  investigate.json
    graph/nodes.json  graph/edges-<NN>.json  graph/blast_radius.json  graph/attack_paths.json
    node_cards.json  search.json  chat.json

Output is deterministic (sorted keys, compact separators, stable ordering; analyst ``tool_calls[].duration_ms`` is
zeroed; ``manifest.generated_at`` honours ``SOURCE_DATE_EPOCH``). Size budget: every file must stay under 15 MB and
the tree should stay under ``--budget-mb`` (default 60, see ``DEFAULT_BUDGET_MB``; the contract's 50 MB target is
reported as well). When the tree is over budget the exporter trims in the contract's order - node ``props`` to the
typed columns (extended by blanking props on GraphFragment nodes, which no screen reads: the inspector uses the node
card), chat answers (node-level first), then fewer top contexts - and, if that is still not enough, continues with
the documented extra steps in ``LADDER``. Every step keeps the payload shapes valid and is recorded in
``manifest.trim_steps``.

Usage::

    .venv/bin/python scripts/export_snapshot.py [--out web/snapshot-out] [--data data/generated]
        [--top-contexts 400] [--max-chat-answers 320] [--budget-mb 60] [--alert-shard-chars 1] [--verbose]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from throughline.agent.prompts import DEMO_QUESTIONS  # noqa: E402
from throughline.analytics import semantics as sem  # noqa: E402
from throughline.schema import EDGE_TYPES, LABELS, category_of  # noqa: E402
from throughline.simulator import storyline_constants as C  # noqa: E402

API = "/api/v1"
MB = 1_000_000
FILE_CAP_BYTES = 15 * MB
# docs/10 asks for <= 50 MB in total. The contract's mandatory coverage alone (every alert's details, all crown-jewel
# tables, 60 identity footprints, TI details, nodes, edges, search) measures ~51 MB after every shape-preserving trim,
# so 50 MB cannot be met without dropping mandated coverage; the default fit budget is the hosting ceiling instead
# (a private artifact allows 64 MB per version including the ~1.5 MB web bundle). Both numbers are reported.
CONTRACT_TARGET_MB = 50
DEFAULT_BUDGET_MB = 60
DEFAULT_OUT = REPO_ROOT / "web" / "snapshot-out"
DEFAULT_DATA = REPO_ROOT / "data" / "generated"
DEFAULT_TOP_CONTEXTS = 400
DEFAULT_MAX_CHAT_ANSWERS = 320
EDGES_PER_SHARD = 40_000
BLAST_FRAGMENT_CAP = 100
CHAT_EVIDENCE_CAP = (120, 300)
CHAT_EVIDENCE_CAP_TIGHT = (60, 150)
NODE_CARDS_CAP = 400
IDENTITY_CAP = 60
CHAT_TOP_ALERTS = 60
LONG_STRING = 200
PROP_BLOCKLIST = frozenset({"raw", "score_breakdown", "stages", "statements", "inbound_rules", "body"})
NAMED_JEWELS = (C.CARDHOLDER_VAULT, C.KYC_DOCS, C.CARDHOLDER_DB, C.DB_READER_SECRET, C.HSM_SECRET)
NAMED_EXPOSED_VMS = (C.EDGE_VM, C.STG_EDGE_VM, C.DEV_LOG4J_VM)
IDENTITY_LABELS = ("IamRole", "IamUser", "HumanUser", "Credential")
PRINCIPAL_LABELS = ("IamRole", "IamUser", "HumanUser")
ACCESS_RANK = {"admin": 3, "write": 2, "read": 1, "list": 0}
STORYLINE_INDICATOR_TYPES = ("sha256", "ipv4", "domain", "url")
CONTAINMENT_ACTION_SETS: tuple[tuple[str, ...], ...] = (
    ("isolate_endpoint", "rotate_role_credentials"),
    ("isolate_endpoint", "rotate_role_credentials", "tighten_trust_policy"),
    ("isolate_endpoint",),
    ("rotate_role_credentials",),
)
CONTAINMENT_TARGET_SETS: tuple[tuple[str, ...], ...] = (
    (C.EP_BASTION, C.BASTION_ROLE),
    (C.EP_BASTION, C.BASTION_VM, C.BASTION_ROLE),
    (C.EP_EDGE, C.EDGE_ROLE),
    (C.EP_EDGE, C.EDGE_VM, C.EDGE_ROLE),
)
GENERIC_ALERT_QUESTIONS = ("Why is this alert risky?", "What can an attacker reach from this alert?")
GENERIC_STORYLINE_QUESTIONS = ("Summarize this storyline", "If we contain this storyline now, what breaks?")
GENERIC_NODE_QUESTIONS = ("What is this?", "What is connected to this node?")
# search.json extra tokens: the attribute keys ContextGraph's search index tokenizes (minus ``name``, its own column)
SEARCH_TOKEN_KEYS = ("hostname", "private_ip", "public_ip", "address", "fqdn", "sha256", "value", "email", "display_name", "cve_id", "technique_id", "title", "arn", "family")
SNIPPET_KEYS = ("hostname", "title", "email", "address", "fqdn", "cve_id", "arn", "description")  # mirror of ContextGraph._snippet

_NORMALIZE_RE = re.compile(r"[^\w\s:/.\-]")
_WS_RE = re.compile(r"\s+")
NORMALIZATION_NOTE = (
    "Chat question normalisation (mirror it exactly on the adapter side): lower-case the question; delete every "
    "character that is not a letter, a digit, an underscore, whitespace or one of ':' '/' '.' '-' "
    "(JavaScript: s.toLowerCase().replace(/[^\\p{L}\\p{N}_\\s:/.-]/gu, '')); collapse whitespace runs to one space; "
    "trim. Match a typed question by exact normalised string in the context key, then in the global key '', then by "
    "the highest Jaccard token overlap >= 0.55 (same context key, then global). Context keys: '' (global), "
    "'alert:<alert id>', 'node:<node id>', 'storyline:<storyline id>'."
)


def normalize_question(text: str) -> str:
    """lower-case, strip punctuation except ``:/.-`` (and ``_``), collapse whitespace, trim."""
    return _WS_RE.sub(" ", _NORMALIZE_RE.sub("", text.lower())).strip()


def dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")


def shard_key(alert_id: str, chars: int = 2) -> str:
    return hashlib.sha1(alert_id.encode("utf-8")).hexdigest()[:chars]


def utc_now_iso() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = datetime.fromtimestamp(int(epoch), tz=UTC) if epoch else datetime.now(tz=UTC)
    return when.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def uniq(items: Iterable[str | None]) -> list[str]:
    return [x for x in dict.fromkeys(items) if x]


# ----------------------------------------------------------------------------- payload surgery (shape-preserving)

_TYPED_COLUMNS: dict[str, frozenset[str]] = {name: frozenset(c.name for c in lbl.columns) for name, lbl in LABELS.items()}


def is_node_out(obj: Any) -> bool:
    return isinstance(obj, dict) and "id" in obj and "label" in obj and "category" in obj and "name" in obj and isinstance(obj.get("props"), dict)


def is_fragment(obj: Any) -> bool:
    return isinstance(obj, dict) and "layout_hint" in obj and isinstance(obj.get("nodes"), list) and isinstance(obj.get("edges"), list)


def trim_node_props(label: str, props: dict[str, Any]) -> dict[str, Any]:
    """Keep the typed columns of the label, minus the JSON blobs and strings longer than 200 chars (docs/10 section 1)."""
    cols = _TYPED_COLUMNS.get(label)
    out: dict[str, Any] = {}
    for key, value in props.items():
        if cols is not None and key not in cols:
            continue
        if key in PROP_BLOCKLIST:
            continue
        if isinstance(value, str) and len(value) > LONG_STRING:
            continue
        out[key] = value
    return out


def walk(obj: Any, on_dict: Callable[[dict[str, Any]], bool]) -> None:
    """Depth-first over dicts/lists; ``on_dict`` returns True when the dict was handled and must not be descended."""
    stack: list[Any] = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if on_dict(cur):
                continue
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def trim_all_node_props(obj: Any) -> None:
    """Apply ``trim_node_props`` to every NodeOut inside ``obj`` (in place)."""

    def visit(d: dict[str, Any]) -> bool:
        if is_node_out(d):
            d["props"] = trim_node_props(str(d["label"]), d["props"])
            return True
        return False

    walk(obj, visit)


def blank_fragment_node_props(obj: Any) -> None:
    """Set ``props`` to ``{}`` on the nodes of every GraphFragment inside ``obj`` (tables and cards keep theirs)."""

    def visit(d: dict[str, Any]) -> bool:
        if is_fragment(d):
            for n in d["nodes"]:
                if isinstance(n, dict) and isinstance(n.get("props"), dict):
                    n["props"] = {}
            return True
        return False

    walk(obj, visit)


def cap_fragment(frag: dict[str, Any], max_nodes: int, max_edges: int | None = None) -> dict[str, Any]:
    """Keep at most ``max_nodes`` nodes (focus, then highlighted, then original order) and ``max_edges`` edges
    (highlighted first); drop dangling edges and paths. Same semantics as ``throughline.agent.tools.cap_fragment``."""
    nodes = frag.get("nodes") or []
    edges = frag.get("edges") or []
    if len(nodes) <= max_nodes and (max_edges is None or len(edges) <= max_edges):
        return frag
    focus = set(frag.get("focus") or [])
    order = sorted(range(len(nodes)), key=lambda i: (nodes[i].get("id") not in focus, not nodes[i].get("highlight"), i))
    keep = set(order[:max_nodes])
    kept_nodes = [n for i, n in enumerate(nodes) if i in keep]
    keep_ids = {n["id"] for n in kept_nodes}
    kept_edges = [e for e in edges if e.get("src") in keep_ids and e.get("dst") in keep_ids]
    if max_edges is not None and len(kept_edges) > max_edges:
        eorder = sorted(range(len(kept_edges)), key=lambda i: (not kept_edges[i].get("highlight"), i))
        ekeep = set(eorder[:max_edges])
        kept_edges = [e for i, e in enumerate(kept_edges) if i in ekeep]
    paths = [p for p in (frag.get("paths") or []) if all(n in keep_ids for n in (p.get("node_ids") or []))]
    out = dict(frag)
    out.update(nodes=kept_nodes, edges=kept_edges, paths=paths, truncated=True, total_nodes=frag.get("total_nodes") or len(nodes))
    return out


def finalize_answer(answer: dict[str, Any], cap: tuple[int, int]) -> dict[str, Any]:
    """Deterministic, capped copy of an ``AnalystAnswer`` payload."""
    out = dict(answer)
    out["tool_calls"] = [{**tc, "duration_ms": 0} for tc in (answer.get("tool_calls") or [])]
    if isinstance(answer.get("evidence"), dict):
        out["evidence"] = cap_fragment(answer["evidence"], cap[0], cap[1])
    return out


def answer_fingerprint(answer: dict[str, Any]) -> str:
    ev = answer.get("evidence") or {}
    return json.dumps(
        [answer.get("intent"), answer.get("narrative_md"), answer.get("findings"), answer.get("followups"),
         sorted(n.get("id", "") for n in ev.get("nodes") or [])],
        sort_keys=True, default=str,
    )


# ----------------------------------------------------------------------------- chat bookkeeping


@dataclass
class ChatEntry:
    question: str
    normalized: str
    context_key: str
    answer: dict[str, Any]
    tier: int  # 0 global, 1 storyline, 2 alert, 3 node, 4-6 demo-question variants that differ from the global answer
    group: str  # the alert / storyline / node id the entry belongs to ("" for global)
    group_rank: int  # position of the group within its tier (lower = more important)
    seq: int
    floor: bool  # part of the contract's minimum (never dropped by the contract's chat step)
    size: int = 0

    def payload(self) -> dict[str, Any]:
        return {"question": self.question, "normalized": self.normalized, "context_key": self.context_key, "answer": self.answer}

    def priority(self) -> tuple[int, int, int]:
        return (self.tier, self.group_rank, self.seq)


@dataclass
class TrimState:
    props_typed: bool = False
    chat_cap: tuple[int, int] = CHAT_EVIDENCE_CAP
    blast_alert_roots: bool = True
    blast_principal_roots: bool = True
    fragment_props_blank: bool = False
    log: list[dict[str, Any]] = field(default_factory=list)


# ----------------------------------------------------------------------------- the exporter


class SnapshotExporter:
    def __init__(
        self,
        client: Any,
        *,
        out_dir: Path,
        top_contexts: int,
        max_chat_answers: int,
        budget_bytes: int,
        shard_chars: int,
        verbose: bool,
    ) -> None:
        self.client = client
        self.rt = client.app.state.runtime
        self.graph = self.rt.graph
        self.engine = self.rt.engine
        self.out_dir = out_dir
        self.top_contexts = max(0, int(top_contexts))
        self.requested_top_contexts = self.top_contexts
        self.max_chat_answers = max(0, int(max_chat_answers))
        self.budget = int(budget_bytes)
        self.shard_chars = shard_chars
        self.verbose = verbose
        self.t0 = time.perf_counter()
        self.trim = TrimState()

        self.meta: dict[str, Any] = {}
        self.alerts: list[dict[str, Any]] = []
        self.alert_ids: list[str] = []
        self.details: dict[str, dict[str, Any]] = {}
        self.contexts: dict[str, dict[str, Any]] = {}
        self.mandatory_ctx: list[str] = []
        self.storylines: dict[str, Any] = {}
        self.storyline_ids: list[str] = []
        self.storyline_alert_ids: list[str] = []
        self.storyline_member_nodes: list[str] = []
        self.crown_jewels: list[str] = []
        self.exposed_vms: list[str] = []
        self.identities: list[str] = []
        self.rerank_alerts: list[str] = []
        self.ti: dict[str, Any] = {}
        self.investigate: dict[str, Any] = {}
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[list[Any]] = []
        self.search: list[list[Any]] = []
        self.blast: dict[str, dict[str, Any]] = {}
        self.blast_reasons: dict[str, set[str]] = {}
        self.anchor_alerts: dict[str, set[str]] = {}
        self.attack_paths: dict[str, dict[str, Any]] = {}
        self.node_cards: dict[str, dict[str, Any]] = {}
        self.suggestions: dict[str, list[str]] = {}
        self.chat_entries: list[ChatEntry] = []
        self.chat_dropped: set[int] = set()
        self.chat_stats: Counter[str] = Counter()
        self._sizes: dict[str, int] = {}
        self._ctx_sizes: dict[str, int] = {}
        self._blast_sizes: dict[str, int] = {}
        self.total_bytes = 0

    # ------------------------------------------------------------------ plumbing

    def log(self, msg: str, *, verbose_only: bool = False) -> None:
        if verbose_only and not self.verbose:
            return
        print(f"[{time.perf_counter() - self.t0:7.1f}s] {msg}", flush=True)

    def get(self, path: str, **params: Any) -> Any:
        r = self.client.get(API + path, params={k: v for k, v in params.items() if v is not None})
        if r.status_code != 200:
            raise RuntimeError(f"GET {path} {params} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def get_optional(self, path: str, **params: Any) -> Any | None:
        r = self.client.get(API + path, params={k: v for k, v in params.items() if v is not None})
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise RuntimeError(f"GET {path} {params} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def post(self, path: str, body: dict[str, Any]) -> Any:
        r = self.client.post(API + path, json=body)
        if r.status_code != 200:
            raise RuntimeError(f"POST {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def anchor_of(self, alert_id: str) -> str | None:
        try:
            return self.engine.ctx.anchor_of(alert_id)
        except Exception:
            return None

    # ------------------------------------------------------------------ collection phases

    def run(self) -> int:
        self.collect_meta()
        self.collect_alerts()
        self.collect_storylines()
        self.collect_contexts()
        self.collect_ti()
        self.collect_investigate()
        self.collect_graph()
        self.collect_attack_paths()
        self.collect_blast_radius()
        self.collect_node_cards()
        self.collect_chat()
        self.fit_budget()
        return self.write()

    def collect_meta(self) -> None:
        health = self.get("/health")
        health.update(backend="snapshot", agent_mode="offline", analyst_mode="precomputed", model=None)
        health.pop("error", None)
        stats = self.get("/stats")
        stats["backend"] = "snapshot"
        caps = dict(stats.get("capabilities") or {})
        caps.update(cypher=False, engine="snapshot")
        caps.pop("stands_in_for", None)
        stats["capabilities"] = caps
        schema = self.get("/schema")
        if "backend" in schema:
            schema["backend"] = "snapshot"
        dashboard = self.get("/dashboard")
        self.meta = {"health": health, "stats": stats, "schema": schema, "dashboard": dashboard}
        self.rerank_alerts = uniq(r.get("alert_id") for r in dashboard.get("rerank_examples") or [])
        self.crown_jewels = [n.id for n in self.engine.crown_jewels()]
        self.log(f"meta: {health['total_nodes']} nodes / {health['total_edges']} edges, {len(self.crown_jewels)} crown jewels, {len(self.rerank_alerts)} rerank examples")

    def collect_alerts(self) -> None:
        items: list[dict[str, Any]] = []
        offset = 0
        while True:
            page = self.get("/alerts", sort="contextual", order="desc", limit=500, offset=offset)
            items.extend(page["items"])
            offset += 500
            if offset >= int(page["total"]) or not page["items"]:
                break
        self.alerts = items
        self.alert_ids = [a["id"] for a in items]
        for i, aid in enumerate(self.alert_ids):
            detail = self.get(f"/alerts/{aid}")
            risk = self.get(f"/alerts/{aid}/risk")
            insights = self.get(f"/alerts/{aid}/insights")
            self.details[aid] = {"alert": detail["alert"], "flat_view": detail["flat_view"], "risk": risk, "insights": insights["insights"]}
            if self.verbose and (i + 1) % 400 == 0:
                self.log(f"  alert details {i + 1}/{len(self.alert_ids)}", verbose_only=True)
        self.log(f"alerts: {len(self.alerts)} summaries and details")

    def collect_storylines(self) -> None:
        items = self.get("/storylines")["items"]
        details = {s["id"]: self.get(f"/storylines/{s['id']}") for s in items}
        self.storylines = {"items": items, "details": details}
        self.storyline_ids = [s["id"] for s in items]
        present = set(self.alert_ids)
        alert_rank = {a: i for i, a in enumerate(self.alert_ids)}
        story_alerts = [a for s in items for a in details[s["id"]].get("alert_ids") or [] if a in present]
        self.storyline_alert_ids = sorted(dict.fromkeys(story_alerts), key=lambda a: alert_rank[a])
        members: list[str] = []
        for sid in self.storyline_ids:
            members.extend(sorted(u for u, _ in self.graph.in_edges(sid, ("IN_STORYLINE",))))
        self.storyline_member_nodes = uniq(m for m in members if self.graph.label_of(m) != "Alert")
        self.log(f"storylines: {len(items)} ({len(self.storyline_alert_ids)} member alerts, {len(self.storyline_member_nodes)} member nodes)")

    def context_alert_ids(self) -> list[str]:
        top = set(self.alert_ids[: self.top_contexts])
        mandatory = set(self.mandatory_ctx)
        return [a for a in self.alert_ids if a in top or a in mandatory]

    def collect_contexts(self) -> None:
        present = set(self.alert_ids)
        noise = [v[0] for v in C.ALERT_N.values()] + list(C.QUARANTINE_ALERT_IDS)
        self.mandatory_ctx = uniq(a for a in [*self.storyline_alert_ids, *noise, *self.rerank_alerts] if a in present)
        wanted = self.context_alert_ids()
        for i, aid in enumerate(wanted):
            self.contexts[aid] = self.get(f"/alerts/{aid}/context")
            if self.verbose and (i + 1) % 100 == 0:
                self.log(f"  contexts {i + 1}/{len(wanted)}", verbose_only=True)
        self.log(f"contexts: {len(self.contexts)} full alert contexts ({len(self.mandatory_ctx)} mandatory + top {self.top_contexts})")

    def collect_ti(self) -> None:
        g = self.graph
        actors = self.get("/threat-intel/actors")
        actor_ids = [it["actor"]["id"] for it in actors["items"]]
        campaign_ids = list(g.nodes_by_label("Campaign"))
        reports = self.get("/threat-intel/reports")
        report_ids = [r["id"] for r in reports["items"]]
        exposure_all = self.get("/threat-intel/exposure", sector_only="false")
        exposure_sector = self.get("/threat-intel/exposure", sector_only="true")
        self.exposed_vms = uniq([*(row["vm"]["id"] for row in exposure_all["items"]), *(vm for vm in NAMED_EXPOSED_VMS if vm in g)])

        values: list[str] = []
        story_actors = {C.ACTOR_CJ, C.ACTOR_HT}
        story_campaigns = {C.CAMPAIGN_EMBERCAST, C.CAMPAIGN_SALTWORKS}
        for ind in g.nodes_by_label("Indicator"):
            if (g.get(ind, "actor_id") in story_actors or g.get(ind, "campaign_id") in story_campaigns) and str(g.get(ind, "ioc_type")) in STORYLINE_INDICATOR_TYPES:
                values.append(str(g.get(ind, "value") or ""))
        values += [C.HASH_MAPLELOADER, C.HASH_QUILLDROP, C.HASH_NIGHTFERRY, C.C2_DOMAIN, C.C2_IP, C.ATTACKER_EGRESS_IP, C.SALTWORKS_IP, C.HASH_BRACKISH, C.BRACKISH_URL]
        exploited = sorted({v for _, v, d in g.G.edges(data=True) if d.get("type") == "EXPLOITS"})
        values += [str(g.get(cve, "cve_id") or cve.split(":", 1)[-1]) for cve in exploited]
        for nid in [*actor_ids, *campaign_ids, *report_ids]:
            values += [nid, str(g.get(nid, "name") or "")]
            if g.label_of(nid) == "IntelReport":
                values += [nid.rsplit(":", 1)[-1], str(g.get(nid, "title") or "")]
        techniques = set(C.CJ_TECHNIQUES) | set(C.HT_TECHNIQUES)
        for sid in self.storyline_ids:
            for stage in self.storylines["details"][sid].get("stages") or []:
                techniques.update(str(t) for t in stage.get("technique_ids") or [])
        values += sorted(techniques)
        lookups: dict[str, Any] = {}
        for value in values:
            key = value.strip().lower()
            if key and key not in lookups:
                lookups[key] = self.get("/threat-intel/lookup", value=value.strip())
        self.ti = {
            "actors": actors,
            "actor_details": {a: self.get(f"/threat-intel/actors/{a}") for a in actor_ids},
            "campaign_details": {c: self.get(f"/threat-intel/campaigns/{c}") for c in campaign_ids},
            "reports": reports,
            "report_details": {r: self.get(f"/threat-intel/reports/{r}") for r in report_ids},
            "exposure": {"sector_only": exposure_sector, "all": exposure_all},
            "lookups": lookups,
        }
        self.log(f"threat intel: {len(actor_ids)} actors, {len(campaign_ids)} campaigns, {len(report_ids)} reports, {len(lookups)} lookups, {len(self.exposed_vms)} exposed hosts")

    def _identity_candidates(self) -> list[str]:
        g = self.graph
        story = [n for n in self.storyline_member_nodes if g.label_of(n) in IDENTITY_LABELS]
        privileged = []
        for label in IDENTITY_LABELS:
            for n in g.nodes_by_label(label):
                if g.get(n, "is_admin") is True or float(g.get(n, "privilege_score") or 0.0) >= 0.7:
                    privileged.append(n)
        privileged.sort(key=lambda n: (-float(g.get(n, "privilege_score") or 0.0), g.get(n, "is_admin") is not True, n))
        return uniq([*story, *privileged])[:IDENTITY_CAP]

    def collect_investigate(self) -> None:
        reaching = {"": self.get("/investigate/alerts-reaching-crown-jewels")}
        for jewel in self.crown_jewels:
            reaching[jewel] = self.get("/investigate/alerts-reaching-crown-jewels", jewel_id=jewel)
        medium = {}
        for severity, source in (("medium", "falcon"), ("medium", ""), ("high", "falcon"), ("low", "falcon")):
            medium[f"{severity}|{source}"] = self.get("/investigate/medium-alerts-with-data-path", severity=severity, source=source)
        self.identities = self._identity_candidates()
        footprints = {i: self.get("/investigate/identity-footprint", id=i) for i in self.identities}
        containment: list[dict[str, Any]] = []
        for targets in CONTAINMENT_TARGET_SETS:
            for actions in CONTAINMENT_ACTION_SETS:
                result = self.post("/investigate/containment", {"target_ids": list(targets), "actions": list(actions)})
                containment.append({"targets": list(targets), "actions": list(actions), "result": result})
        result = self.post("/investigate/containment", {"target_ids": [C.EP_EDGE], "actions": ["isolate_endpoint"]})
        containment.append({"targets": [C.EP_EDGE], "actions": ["isolate_endpoint"], "result": result})
        self.investigate = {
            "credential_joins": self.get("/investigate/credential-joins"),
            "alerts_reaching_crown_jewels": reaching,
            "medium_alerts_with_data_path": medium,
            "identity_footprint": footprints,
            "containment": containment,
        }
        self.log(f"investigate: {len(reaching)} crown-jewel tables, {len(footprints)} identity footprints, {len(containment)} containment simulations")

    def collect_graph(self) -> None:
        g = self.graph
        nodes: list[dict[str, Any]] = []
        entries: list[list[Any]] = []
        for nid in sorted(g.G.nodes):
            attrs = g.G.nodes[nid]
            node = g.node_out(nid).model_dump(mode="json")
            node["props"] = trim_node_props(node["label"], node["props"])
            nodes.append(node)
            tokens: list[str] = []
            for key in SEARCH_TOKEN_KEYS:
                val = attrs.get(key)
                if isinstance(val, str) and val and val != attrs.get("name"):
                    tokens.append(val.lower())
            snippet = None
            for key in SNIPPET_KEYS:
                val = attrs.get(key)
                if isinstance(val, str) and val and val != attrs.get("name"):
                    snippet = val[:120]
                    break
            entries.append([nid, attrs["label"], attrs.get("name") or nid, category_of(attrs["label"]), snippet or "", " ".join(uniq(tokens))])
        self.nodes = nodes
        self.search = entries
        edges: list[list[Any]] = []
        for u, v, d in g.G.edges(data=True):
            etype = d["type"]
            et = EDGE_TYPES.get(etype)
            derived = bool(et and et.derived) or d.get("source") == "derived"
            edges.append([u, etype, v, 1 if derived else 0, float(d.get("confidence") or 1.0)])
        edges.sort(key=lambda e: (e[0], e[1], e[2], -e[4]))
        self.edges = edges
        self.log(f"graph: {len(nodes)} nodes, {len(edges)} edges, {len(entries)} search entries")

    def collect_attack_paths(self) -> None:
        keys: list[str] = []
        for aid in self.storyline_alert_ids:
            keys.append(aid)
            keys.append(self.anchor_of(aid) or "")
        out: dict[str, Any] = {}
        for through in uniq(keys):
            out[through] = self.get("/graph/attack-paths", through=through)
        for jewel in NAMED_JEWELS:
            if jewel in self.graph and sem.INTERNET_ID in self.graph:
                out[f"internet->{jewel}"] = self.get("/graph/attack-paths", entry=sem.INTERNET_ID, target=jewel)
        self.attack_paths = out
        self.log(f"attack paths: {len(out)} entries")

    def _jewel_principals(self, jewel: str, top: int = 3) -> list[str]:
        g = self.graph
        cands = []
        for u, d in g.in_edges(jewel, ("CAN_ACCESS",)):
            if g.label_of(u) in PRINCIPAL_LABELS:
                cands.append((-ACCESS_RANK.get(str(d.get("access_level") or ""), 0), -float(g.get(u, "privilege_score") or 0.0), g.get(u, "is_admin") is not True, u))
        cands.sort()
        return uniq(c[3] for c in cands)[:top]

    def collect_blast_radius(self) -> None:
        reasons: dict[str, set[str]] = {}

        def add(root: str | None, reason: str) -> None:
            if root and root in self.graph:
                reasons.setdefault(root, set()).add(reason)

        for aid in self.contexts:
            add(aid, "alert")
            anchor = self.anchor_of(aid)
            if anchor:
                add(anchor, "anchor")
                self.anchor_alerts.setdefault(anchor, set()).add(aid)
        for n in self.storyline_member_nodes:
            add(n, "storyline_member")
        for jewel in self.crown_jewels:
            for p in self._jewel_principals(jewel):
                add(p, "jewel_principal")
        for i in self.identities:
            add(i, "identity")
        self.blast_reasons = reasons
        for i, root in enumerate(sorted(reasons)):
            result = self.get_optional("/graph/blast-radius", id=root)
            if result is None:
                continue
            if isinstance(result.get("fragment"), dict):
                result["fragment"] = cap_fragment(result["fragment"], BLAST_FRAGMENT_CAP)
            self.blast[root] = result
            if self.verbose and (i + 1) % 250 == 0:
                self.log(f"  blast radius {i + 1}/{len(reasons)}", verbose_only=True)
        self.log(f"blast radius: {len(self.blast)} roots computed")

    def blast_root_ids(self) -> list[str]:
        ctx = set(self.contexts) & set(self.context_alert_ids())
        out = []
        for root, reasons in sorted(self.blast_reasons.items()):
            if root not in self.blast:
                continue
            keep = "storyline_member" in reasons or "identity" in reasons
            keep = keep or ("jewel_principal" in reasons and self.trim.blast_principal_roots)
            keep = keep or ("alert" in reasons and root in ctx and self.trim.blast_alert_roots)
            keep = keep or ("anchor" in reasons and any(a in ctx for a in self.anchor_alerts.get(root, ())))
            if keep:
                out.append(root)
        return out

    def _exposed_endpoints(self) -> list[str]:
        return uniq(self.engine.ctx.endpoint_for(vm) for vm in self.exposed_vms)

    def collect_node_cards(self) -> None:
        g = self.graph
        cands: list[str] = list(self.storyline_member_nodes)
        cands += [j for j in NAMED_JEWELS if j in g]
        cands += self.crown_jewels
        for label in ("ThreatActor", "Campaign", "IntelReport", "Malware"):
            cands += list(g.nodes_by_label(label))
        cands += self.exposed_vms
        cands += self._exposed_endpoints()
        for aid in self.rerank_alerts:
            cands.append(aid)
            cands.append(self.anchor_of(aid) or "")
            ctx = self.contexts.get(aid) or {}
            cands += [n.get("id", "") for n in (ctx.get("evidence") or {}).get("nodes") or []]
        wanted = [n for n in uniq(cands) if n in g][:NODE_CARDS_CAP]
        for nid in wanted:
            card = self.get_optional(f"/nodes/{nid}")
            if card is not None:
                self.node_cards[nid] = card
        self.log(f"node cards: {len(self.node_cards)}")

    # ------------------------------------------------------------------ chat

    def _suggestions(self, **ctx: str) -> list[str]:
        key = self._context_key(ctx)
        if key not in self.suggestions:
            self.suggestions[key] = list(self.get("/chat/suggestions", **ctx)["questions"])
        return self.suggestions[key]

    @staticmethod
    def _context_key(ctx: dict[str, Any]) -> str:
        if ctx.get("alert_id"):
            return f"alert:{ctx['alert_id']}"
        if ctx.get("storyline_id"):
            return f"storyline:{ctx['storyline_id']}"
        if ctx.get("node_id"):
            return f"node:{ctx['node_id']}"
        ids = ctx.get("selected_node_ids") or []
        return f"node:{ids[0]}" if ids else ""

    def _answer(self, question: str, context: dict[str, Any]) -> dict[str, Any]:
        raw = self.post("/agent/answer", {"question": question, "context": context, "mode": "offline"})
        return finalize_answer(raw, self.trim.chat_cap)

    def _chat_alert_order(self) -> list[str]:
        present = set(self.alert_ids)
        noise = [v[0] for v in C.ALERT_N.values() if v[0] in present]
        quarantine = [a for a in C.QUARANTINE_ALERT_IDS if a in present]
        return uniq([*self.storyline_alert_ids, *noise, *self.alert_ids[:CHAT_TOP_ALERTS], *quarantine])

    def _chat_node_order(self) -> list[str]:
        g = self.graph
        actors = [it["actor"]["id"] for it in (self.ti.get("actors") or {}).get("items") or []]
        return [n for n in uniq([*self.storyline_member_nodes, *NAMED_JEWELS, *self.crown_jewels, *self.exposed_vms, *actors]) if n in g]

    def collect_chat(self) -> None:
        demo = set(DEMO_QUESTIONS)
        seq = 0
        cap = self.max_chat_answers
        global_answers: dict[str, dict[str, Any]] = {}

        def room(n: int = 1) -> bool:
            return len(self.chat_entries) + n <= cap

        def add(question: str, context: dict[str, Any], tier: int, group: str, rank: int, floor: bool) -> ChatEntry | None:
            nonlocal seq
            key = self._context_key(context)
            norm = normalize_question(question)
            if any(e.context_key == key and e.normalized == norm for e in self.chat_entries):
                return None
            answer = self._answer(question, context)
            if tier >= 4 and answer_fingerprint(answer) == answer_fingerprint(global_answers.get(question, {})):
                self.chat_stats["variants_identical_to_global"] += 1
                return None
            seq += 1
            entry = ChatEntry(question, norm, key, answer, tier, group, rank, seq, floor)
            entry.size = len(dumps(entry.payload()))
            self.chat_entries.append(entry)
            return entry

        # tier 0: the demo questions (plus suggestions_for() without context, which are the same list) in the global context
        for q in uniq([*DEMO_QUESTIONS, *self._suggestions()]):
            if not room():
                break
            entry = add(q, {}, 0, "", 0, True)
            if entry is not None:
                global_answers[q] = entry.answer
        # tier 1: per storyline, the storyline-specific suggestions and the two generic phrasings
        story_questions: dict[str, list[str]] = {}
        for rank, sid in enumerate(self.storyline_ids):
            specific = [q for q in self._suggestions(storyline_id=sid) if q not in demo] + list(GENERIC_STORYLINE_QUESTIONS)
            story_questions[sid] = specific
            if not room(len(specific)):
                break
            for q in specific:
                add(q, {"storyline_id": sid}, 1, sid, rank, True)
        # tier 2: per alert (storyline members, named noise, top-60, quarantine), specific suggestions + generic phrasings
        alert_order = self._chat_alert_order()
        floor_alerts = set(self.storyline_alert_ids) | {v[0] for v in C.ALERT_N.values()}
        alert_questions: dict[str, list[str]] = {}
        for rank, aid in enumerate(alert_order):
            specific = [q for q in self._suggestions(alert_id=aid) if q not in demo] + list(GENERIC_ALERT_QUESTIONS)
            alert_questions[aid] = specific
            if not room(len(specific)):
                break
            for q in specific:
                add(q, {"alert_id": aid}, 2, aid, rank, aid in floor_alerts)
        # tier 3: per node (storyline members, crown jewels, exposed hosts, actors)
        node_order = self._chat_node_order()
        node_questions: dict[str, list[str]] = {}
        for rank, nid in enumerate(node_order):
            specific = [q for q in self._suggestions(node_id=nid) if q not in demo] + list(GENERIC_NODE_QUESTIONS)
            node_questions[nid] = specific
            if not room(len(specific)):
                break
            for q in specific:
                add(q, {"selected_node_ids": [nid]}, 3, nid, rank, False)
        # tiers 4-6: the demo questions asked inside a context, kept only when the offline analyst answers them
        # differently from the global answer (the adapter falls back to the global key otherwise)
        for tier, keys, make_ctx in (
            (4, self.storyline_ids, lambda k: {"storyline_id": k}),
            (5, alert_order, lambda k: {"alert_id": k}),
            (6, node_order, lambda k: {"selected_node_ids": [k]}),
        ):
            for rank, key in enumerate(keys):
                if not room():
                    break
                for q in DEMO_QUESTIONS:
                    if not room():
                        break
                    add(q, make_ctx(key), tier, key, rank, False)
        # suggestion lists for every precomputed context key
        for aid in self.context_alert_ids():
            self._suggestions(alert_id=aid)
        for nid in self.node_cards:
            self._suggestions(node_id=nid)
        for sid in self.storyline_ids:
            self._suggestions(storyline_id=sid)
        self._suggestions()
        tiers = Counter(e.tier for e in self.chat_entries)
        self.log(f"chat: {len(self.chat_entries)} answers (global {tiers[0]}, storyline {tiers[1]}, alert {tiers[2]}, node {tiers[3]}, context variants {tiers[4] + tiers[5] + tiers[6]}), {len(self.suggestions)} suggestion keys")

    def kept_chat_entries(self) -> list[ChatEntry]:
        return sorted((e for e in self.chat_entries if e.seq not in self.chat_dropped), key=ChatEntry.priority)

    # ------------------------------------------------------------------ assembly

    def context_alert_set(self) -> set[str]:
        return set(self.context_alert_ids()) & set(self.contexts)

    def alert_shards(self) -> dict[str, dict[str, Any]]:
        with_ctx = self.context_alert_set()
        shards: dict[str, dict[str, Any]] = {}
        for aid in self.alert_ids:
            entry = dict(self.details[aid])
            if aid in with_ctx:
                entry["context"] = self.contexts[aid]
            shards.setdefault(shard_key(aid, self.shard_chars), {})[aid] = entry
        return shards

    def edge_shards(self) -> list[list[list[Any]]]:
        return [self.edges[i : i + EDGES_PER_SHARD] for i in range(0, len(self.edges), EDGES_PER_SHARD)] or [[]]

    def chat_payload(self) -> dict[str, Any]:
        keys = {"", *(f"storyline:{s}" for s in self.storyline_ids), *(f"alert:{a}" for a in self.context_alert_ids()), *(f"node:{n}" for n in self.node_cards)}
        entries = self.kept_chat_entries()
        keys.update(e.context_key for e in entries)
        suggestions = {k: v for k, v in self.suggestions.items() if k in keys}
        return {"suggestions": suggestions, "answers": [e.payload() for e in entries]}

    def files(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "meta.json": self.meta,
            "alerts.json": {"items": self.alerts},
            "storylines.json": self.storylines,
            "ti.json": self.ti,
            "investigate.json": self.investigate,
            "graph/nodes.json": {"nodes": self.nodes},
            "graph/blast_radius.json": {root: self.blast[root] for root in self.blast_root_ids()},
            "graph/attack_paths.json": self.attack_paths,
            "node_cards.json": self.node_cards,
            "search.json": {"entries": self.search},
            "chat.json": self.chat_payload(),
        }
        for key, shard in self.alert_shards().items():
            out[f"alert_details/{key}.json"] = shard
        for i, shard in enumerate(self.edge_shards()):
            out[f"graph/edges-{i:02d}.json"] = {"edges": shard}
        return out

    # ------------------------------------------------------------------ size budget

    def measure(self, only_prefixes: Sequence[str] | None = None) -> int:
        files = self.files()
        for path in list(self._sizes):
            if path not in files:
                del self._sizes[path]
        for path, obj in files.items():
            if only_prefixes is None or path not in self._sizes or any(path.startswith(p) for p in only_prefixes):
                self._sizes[path] = len(dumps(obj))
        return sum(self._sizes.values())

    def _ctx_size(self, aid: str) -> int:
        if aid not in self._ctx_sizes:
            self._ctx_sizes[aid] = len(dumps(self.contexts[aid]))
        return self._ctx_sizes[aid]

    def _blast_size(self, root: str) -> int:
        if root not in self._blast_sizes:
            self._blast_sizes[root] = len(dumps(self.blast[root]))
        return self._blast_sizes[root]

    def _invalidate_estimates(self) -> None:
        self._ctx_sizes.clear()
        self._blast_sizes.clear()
        for e in self.chat_entries:
            e.size = len(dumps(e.payload()))

    def fit_budget(self) -> None:
        if self.budget <= 0:
            self.total_bytes = self.measure()
            return
        total = self.measure()
        self.log(f"size: {total / MB:.1f} MB before trimming (budget {self.budget / MB:.0f} MB)")
        for name, step, kind in LADDER:
            if total <= self.budget:
                break
            detail = step(self, total)
            if not detail:
                continue
            total = self.measure(only_prefixes=DIRTY_PREFIXES.get(name))
            self.trim.log.append({"step": name, "kind": kind, "detail": detail, "total_bytes": total})
            self.log(f"trim [{name}] {detail} -> {total / MB:.1f} MB")
        self.total_bytes = total
        if total > self.budget:
            self.log(f"WARNING: {total / MB:.1f} MB exceeds the {self.budget / MB:.0f} MB budget after every trim step; see the report")

    # --- ladder steps (each returns a description when it changed something)

    def step_props_typed(self, total: int) -> str | None:
        if self.trim.props_typed:
            return None
        self.trim.props_typed = True
        for obj in (self.meta, self.details, self.contexts, self.storylines, self.ti, self.investigate, self.blast, self.attack_paths, self.node_cards):
            trim_all_node_props(obj)
        for e in self.chat_entries:
            trim_all_node_props(e.answer)
        self._invalidate_estimates()
        return "node props trimmed to the typed columns of each label (JSON blobs and strings > 200 chars dropped) in every payload"

    def _drop_chat_groups(self, total: int, *, allow_floor: bool) -> str | None:
        kept = self.kept_chat_entries()
        groups: dict[tuple[int, str], list[ChatEntry]] = {}
        for e in kept:
            if e.tier == 0 or (e.floor and not allow_floor):
                continue
            groups.setdefault((e.tier, e.group), []).append(e)
        if not groups:
            return None
        order = sorted(groups, key=lambda k: (-k[0], -groups[k][0].group_rank))
        dropped: Counter[int] = Counter()
        over = total - self.budget
        for key in order:
            if over <= 0:
                break
            for e in groups[key]:
                self.chat_dropped.add(e.seq)
                over -= e.size
                dropped[e.tier] += 1
        if not dropped:
            return None
        labels = {1: "storyline", 2: "alert", 3: "node", 4: "storyline variant", 5: "alert variant", 6: "node variant"}
        return "dropped chat answers: " + ", ".join(f"{n} {labels.get(t, t)}-level" for t, n in sorted(dropped.items(), reverse=True))

    def step_chat_drop(self, total: int) -> str | None:
        return self._drop_chat_groups(total, allow_floor=False)

    def step_chat_drop_floor(self, total: int) -> str | None:
        return self._drop_chat_groups(total, allow_floor=True)

    def step_top_contexts(self, total: int) -> str | None:
        """Drop top-N contexts one alert at a time (lowest contextual rank first), together with the blast-radius
        entries only they justified, until the estimate fits; mandatory alerts keep their context."""
        if self.top_contexts <= 0:
            return None
        start = self.top_contexts
        mandatory = set(self.mandatory_ctx)
        estimate = total
        roots_before = set(self.blast_root_ids())
        while estimate > self.budget and self.top_contexts > 0:
            self.top_contexts -= 1
            aid = self.alert_ids[self.top_contexts] if self.top_contexts < len(self.alert_ids) else None
            if aid is None or aid in mandatory:
                continue
            if aid in self.contexts:
                estimate -= self._ctx_size(aid)
            roots_after = set(self.blast_root_ids())
            estimate -= sum(self._blast_size(r) for r in roots_before - roots_after)
            roots_before = roots_after
        return f"top contexts {start} -> {self.top_contexts} ({len(self.context_alert_set())} alerts keep a full context)"

    def step_chat_evidence_tight(self, total: int) -> str | None:
        if self.trim.chat_cap == CHAT_EVIDENCE_CAP_TIGHT:
            return None
        self.trim.chat_cap = CHAT_EVIDENCE_CAP_TIGHT
        for e in self.chat_entries:
            e.answer = finalize_answer(e.answer, self.trim.chat_cap)
            e.size = len(dumps(e.payload()))
        return f"chat evidence fragments capped at {CHAT_EVIDENCE_CAP_TIGHT[0]} nodes / {CHAT_EVIDENCE_CAP_TIGHT[1]} edges"

    def step_blast_alert_roots(self, total: int) -> str | None:
        if not self.trim.blast_alert_roots:
            return None
        before = len(self.blast_root_ids())
        self.trim.blast_alert_roots = False
        return f"blast radius: dropped {before - len(self.blast_root_ids())} alert-rooted entries (their anchors stay; the adapter approximates alert roots)"

    def step_blast_principal_roots(self, total: int) -> str | None:
        if not self.trim.blast_principal_roots:
            return None
        before = len(self.blast_root_ids())
        self.trim.blast_principal_roots = False
        return f"blast radius: dropped {before - len(self.blast_root_ids())} crown-jewel principal roots"

    def step_fragment_props_blank(self, total: int) -> str | None:
        if self.trim.fragment_props_blank:
            return None
        self.trim.fragment_props_blank = True
        for obj in (self.contexts, self.storylines, self.ti, self.investigate, self.blast, self.attack_paths):
            blank_fragment_node_props(obj)
        for e in self.chat_entries:
            blank_fragment_node_props(e.answer)
        self._invalidate_estimates()
        return "props blanked on GraphFragment nodes inside analytics payloads (graph/nodes.json, node_cards.json and every table/list keep typed props; hydrate fragment nodes from graph/nodes.json)"

    # ------------------------------------------------------------------ output

    def manifest(self, files: dict[str, bytes]) -> dict[str, Any]:
        build = (self.meta.get("health") or {}).get("build") or {}
        with_ctx = self.context_alert_set()
        kept = self.kept_chat_entries()
        tiers = Counter(e.tier for e in kept)
        notes = (
            f"Throughline static snapshot v1 (docs/10-static-snapshot.md). {NORMALIZATION_NOTE} "
            f"Alert details are sharded by the first {self.shard_chars} hex chars of sha1(alert id) into alert_details/<NN>.json; "
            f"'context' is present for {len(with_ctx)} alerts (storyline members, named noise, rerank examples, top {self.top_contexts} by "
            f"contextual score); the adapter synthesises a lite context for the others. Compact edges are [src, type, dst, derived 0|1, "
            f"confidence] in shards of {EDGES_PER_SHARD}. graph/nodes.json props are trimmed to the typed columns of each label."
        )
        if self.trim.fragment_props_blank:
            notes += " GraphFragment nodes inside analytics payloads carry props {} (budget trim); node_cards.json and graph/nodes.json hold the typed props."
        return {
            "version": 1,
            "generated_at": utc_now_iso(),
            "seed": build.get("seed", C.SEED),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "alert_count": len(self.alerts),
            "shards": {
                "alert_details": sorted(p for p in files if p.startswith("alert_details/")),
                "edges": sorted(p for p in files if p.startswith("graph/edges-")),
            },
            "notes": notes,
            "normalization": {
                "rule": "lower-case; delete [^\\p{L}\\p{N}_\\s:/.-]; collapse whitespace; trim",
                "examples": [[q, normalize_question(q)] for q in (DEMO_QUESTIONS[0], DEMO_QUESTIONS[10], "Why is `alert:falcon:ldt-a009` risky? Explain its contextual score.")],
            },
            "dataset": {k: build[k] for k in ("seed", "generated_at", "checksum", "storylines") if k in build},
            "alert_shard_prefix_len": self.shard_chars,
            "coverage": {
                "alerts_with_context": len(with_ctx),
                "top_contexts_requested": self.requested_top_contexts,
                "top_contexts_exported": self.top_contexts,
                "blast_radius_roots": len(self.blast_root_ids()),
                "attack_path_keys": len(self.attack_paths),
                "node_cards": len(self.node_cards),
                "identity_footprints": len(self.investigate.get("identity_footprint") or {}),
                "containment_simulations": len(self.investigate.get("containment") or []),
                "ti_lookups": len(self.ti.get("lookups") or {}),
                "chat_answers": {"total": len(kept), "global": tiers[0], "storyline": tiers[1], "alert": tiers[2], "node": tiers[3], "context_variants": tiers[4] + tiers[5] + tiers[6]},
                "chat_suggestion_keys": len(self.chat_payload()["suggestions"]),
                "chat_evidence_cap": list(self.trim.chat_cap),
            },
            "trim_steps": self.trim.log,
            "budget": {"contract_target_bytes": CONTRACT_TARGET_MB * MB, "fit_budget_bytes": self.budget, "total_bytes": sum(files.values())},
            "files": dict(sorted(files.items())),
        }

    def write(self) -> int:
        out = self.out_dir
        if out.exists():
            if (out / "manifest.json").exists() or not any(out.iterdir()):
                shutil.rmtree(out)
            else:
                raise SystemExit(f"refusing to overwrite {out}: it exists and does not look like a snapshot (no manifest.json)")
        out.mkdir(parents=True)
        payloads = self.files()
        sizes: dict[str, int] = {}
        for path, obj in sorted(payloads.items()):
            data = dumps(obj)
            target = out / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            sizes[path] = len(data)
        manifest = dumps(self.manifest(sizes))
        (out / "manifest.json").write_bytes(manifest)
        sizes["manifest.json"] = len(manifest)
        return self.report(sizes)

    def report(self, sizes: dict[str, int]) -> int:
        total = sum(sizes.values())
        elapsed = time.perf_counter() - self.t0
        print()
        print(f"{'file':<44} {'bytes':>12} {'MB':>7}")
        print("-" * 66)
        families = {"alert_details/": "alert_details/<NN>.json", "graph/edges-": "graph/edges-<NN>.json"}
        shown: set[str] = set()
        for prefix, label in families.items():
            members = sorted(p for p in sizes if p.startswith(prefix))
            if not members:
                continue
            shown.update(members)
            if self.verbose:
                for p in members:
                    print(f"{p:<44} {sizes[p]:>12,} {sizes[p] / MB:>7.2f}")
            fam_total = sum(sizes[p] for p in members)
            biggest = max(members, key=lambda p: sizes[p])
            print(f"{label + f' ({len(members)} files)':<44} {fam_total:>12,} {fam_total / MB:>7.2f}   largest {biggest} {sizes[biggest] / MB:.2f} MB")
        for p in sorted(sizes):
            if p in shown:
                continue
            flag = "  OVER 15 MB" if sizes[p] > FILE_CAP_BYTES else ""
            print(f"{p:<44} {sizes[p]:>12,} {sizes[p] / MB:>7.2f}{flag}")
        print("-" * 66)
        fit = "disabled" if self.budget <= 0 else ("OK" if total <= self.budget else "OVER")
        contract = "OK" if total <= CONTRACT_TARGET_MB * MB else "OVER"
        print(f"{'total (' + str(len(sizes)) + ' files)':<44} {total:>12,} {total / MB:>7.2f}   fit budget {self.budget / MB:.0f} MB -> {fit}; contract target {CONTRACT_TARGET_MB} MB -> {contract}")
        print()
        kept = self.kept_chat_entries()
        tiers = Counter(e.tier for e in kept)
        with_ctx = self.context_alert_set()
        print(f"alerts: {len(self.alerts)} total, {len(with_ctx)} with full context (mandatory {len(self.mandatory_ctx)}, top {self.top_contexts} of the requested {self.requested_top_contexts})")
        print(f"chat: {len(kept)} answers (global {tiers[0]}, storyline {tiers[1]}, alert {tiers[2]}, node {tiers[3]}, context variants {tiers[4] + tiers[5] + tiers[6]}; "
              f"{len(self.chat_entries) - len(kept)} dropped by the budget, {self.chat_stats['variants_identical_to_global']} context variants identical to the global answer); "
              f"{len(self.chat_payload()['suggestions'])} suggestion keys; evidence cap {self.trim.chat_cap[0]}/{self.trim.chat_cap[1]}")
        print(f"graph: {len(self.nodes)} nodes, {len(self.edges)} edges in {len(self.edge_shards())} shards; blast radius roots {len(self.blast_root_ids())}; attack path keys {len(self.attack_paths)}; node cards {len(self.node_cards)}")
        print(f"ti: {len(self.ti.get('lookups') or {})} lookups; investigate: {len(self.investigate.get('identity_footprint') or {})} identity footprints, {len(self.investigate.get('containment') or [])} containment simulations, {len(self.investigate.get('alerts_reaching_crown_jewels') or {})} crown-jewel tables")
        if self.trim.log:
            print("trim steps applied:")
            for step in self.trim.log:
                print(f"  - [{step['kind']}] {step['step']}: {step['detail']} -> {step['total_bytes'] / MB:.1f} MB")
        else:
            print("trim steps applied: none")
        print(f"written to {self.out_dir} in {elapsed:.1f}s")
        over = [p for p, s in sizes.items() if s > FILE_CAP_BYTES]
        if over:
            print(f"ERROR: files over the 15 MB cap: {over}")
            return 2
        return 0


# (name, step, kind): the contract's three steps in order (kind "contract"; "contract-extension" = blanking props on
# GraphFragment nodes, an extension of the node-props step that no screen can observe), then the extra steps.
LADDER: tuple[tuple[str, Callable[[SnapshotExporter, int], str | None], str], ...] = (
    ("props_typed", SnapshotExporter.step_props_typed, "contract"),
    ("fragment_props_blank", SnapshotExporter.step_fragment_props_blank, "contract-extension"),
    ("chat_drop", SnapshotExporter.step_chat_drop, "contract"),
    ("top_contexts", SnapshotExporter.step_top_contexts, "contract"),
    ("chat_evidence_tight", SnapshotExporter.step_chat_evidence_tight, "extra"),
    ("blast_alert_roots", SnapshotExporter.step_blast_alert_roots, "extra"),
    ("blast_principal_roots", SnapshotExporter.step_blast_principal_roots, "extra"),
    ("chat_drop_floor", SnapshotExporter.step_chat_drop_floor, "extra"),
)
# files a step can change (others keep their cached size); steps not listed dirty everything
DIRTY_PREFIXES: dict[str, tuple[str, ...]] = {
    "chat_drop": ("chat.json",),
    "chat_drop_floor": ("chat.json",),
    "chat_evidence_tight": ("chat.json",),
    "top_contexts": ("alert_details/", "graph/blast_radius.json", "chat.json"),
    "blast_alert_roots": ("graph/blast_radius.json",),
    "blast_principal_roots": ("graph/blast_radius.json",),
}


# ----------------------------------------------------------------------------- entry point


def ensure_dataset(data_dir: Path) -> None:
    if (data_dir / "graph" / "nodes.jsonl").exists():
        return
    print(f"[export_snapshot] no dataset at {data_dir}; building it with throughline.simulator.build", flush=True)
    subprocess.run([sys.executable, "-m", "throughline.simulator.build", "--out", str(data_dir)], check=True, cwd=str(REPO_ROOT))


def build_app(data_dir: Path) -> Any:
    from throughline.api.app import create_app
    from throughline.config import Settings

    settings = Settings(
        _env_file=None, data_dir=data_dir, graph_backend="networkx", graph_db_path=data_dir / "graph.lbdb",
        agent_mode="offline", anthropic_api_key=None,
    )
    return create_app(settings=settings, web_dist=data_dir / "__no_web_dist__")


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory (default web/snapshot-out)")
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA, help="generated dataset (default data/generated; built when missing)")
    ap.add_argument("--top-contexts", type=int, default=DEFAULT_TOP_CONTEXTS, help="full contexts for the top N alerts by contextual score (default 400)")
    ap.add_argument("--max-chat-answers", type=int, default=DEFAULT_MAX_CHAT_ANSWERS, help="cap on precomputed analyst answers (default 320)")
    ap.add_argument("--budget-mb", type=float, default=DEFAULT_BUDGET_MB, help=f"total size to fit in MB; 0 disables trimming (default {DEFAULT_BUDGET_MB}; the contract's {CONTRACT_TARGET_MB} MB target is reported too)")
    ap.add_argument("--alert-shard-chars", type=int, choices=(1, 2), default=1, help="hex chars of sha1(alert id) naming alert_details shards: 1 = 16 shards (default; keeps the tree under the artifact publisher's 255-file limit), 2 = 256 shards")
    ap.add_argument("--verbose", action="store_true", help="progress per phase and per shard sizes")
    return ap.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    data_dir = args.data.resolve()
    ensure_dataset(data_dir)
    from fastapi.testclient import TestClient

    t0 = time.perf_counter()
    with TestClient(build_app(data_dir)) as client:
        rt = client.app.state.runtime
        if not rt.ready:
            print(f"ERROR: runtime not ready: {rt.error}", file=sys.stderr)
            return 1
        print(f"[export_snapshot] runtime ready in {time.perf_counter() - t0:.1f}s (backend {rt.backend}, {len(rt.graph)} nodes)", flush=True)
        exporter = SnapshotExporter(
            client, out_dir=args.out.resolve(), top_contexts=args.top_contexts, max_chat_answers=args.max_chat_answers,
            budget_bytes=int(args.budget_mb * MB), shard_chars=args.alert_shard_chars, verbose=args.verbose,
        )
        return exporter.run()


if __name__ == "__main__":
    raise SystemExit(main())
