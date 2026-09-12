"""ToolRegistry: the typed, bounded, read-only tools shared by the LLM analyst, the offline analyst and the REST
agent surface (docs/05-api-contract.md section 7.1).

Each ``Tool`` has a pydantic argument model (turned into a strict JSON schema with ``additionalProperties: false``),
a handler over ``AnalyticsEngine`` + ``GraphStore`` and returns a ``ToolResult``:

* ``result``    JSON-serialisable payload (fragments are *not* duplicated here; they travel in ``evidence``)
* ``evidence``  a ``GraphFragment`` the UI can merge into the canvas and whose ids become citable
* ``summary``   one line for the ``tool_result`` SSE event and the tool-call record
* ``result_ids`` extra ids that appeared in the result without a fragment (search hits) and are therefore citable

Bounds from the contract are enforced by clamping (``limit<=25`` etc.); unknown arguments are rejected.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from throughline.agent.prompts import TOOL_DESCRIPTIONS
from throughline.models import (
    AlertSummary,
    AnalystAnswer,
    EdgeOut,
    Finding,
    GraphFragment,
    NodeOut,
    PathOut,
    SearchHit,
    StorylineOut,
    TIContext,
)
from throughline.schema import EDGE_TYPES, LABELS, category_of, label_for_id

log = logging.getLogger(__name__)

NODE_META_KEYS = ("id", "label", "name", "source", "source_id", "first_seen", "last_seen", "confidence")
BULKY_PROP_KEYS = {"raw", "statements", "body", "inbound_rules", "score_breakdown", "stages"}

Severity = Literal["informational", "low", "medium", "high", "critical"]
BandLit = Literal["noise", "low", "medium", "high", "critical"]
SourceLit = Literal["falcon", "cspm", "waf", "ids", "cloud-anomaly", "okta"]
ContainmentAction = Literal[
    "isolate_endpoint", "rotate_role_credentials", "tighten_trust_policy", "block_ip", "disable_user", "revoke_sessions"
]

# ----------------------------------------------------------------------------- conversions


def record_to_node_out(rec: Mapping[str, Any], *, highlight: bool = False) -> NodeOut:
    """Build a ``NodeOut`` from a store record (nodes.jsonl shape, flattened or with ``props``)."""
    node_id = str(rec.get("id"))
    label = str(rec.get("label") or label_for_id(node_id) or "Unknown")
    props = rec.get("props")
    if not isinstance(props, Mapping):
        props = {k: v for k, v in rec.items() if k not in NODE_META_KEYS and v is not None}
    elif isinstance(props, str):
        try:
            props = json.loads(props)
        except ValueError:
            props = {}
    props = dict(props)
    tags: list[str] = []
    if props.get("crown_jewel"):
        tags.append("crown_jewel")
    if props.get("exposure") == "internet" or props.get("public") is True:
        tags.append("internet_exposed")
    if props.get("storyline_id"):
        tags.append(f"storyline:{props['storyline_id']}")
    if (props.get("ioc_match_count") or 0) > 0:
        tags.append("ioc_match")
    severity = props.get("vendor_severity") if label == "Alert" else props.get("severity")
    score = props.get("contextual_score") if label in ("Alert", "Storyline") else None
    return NodeOut(
        id=node_id, label=label, name=str(rec.get("name") or node_id), category=category_of(label),
        severity=severity, score=score, highlight=highlight, tags=tags, props=props,
    )


def edge_out_from_id(edge_id: str, *, highlight: bool = False, props: Mapping[str, Any] | None = None) -> EdgeOut | None:
    parts = edge_id.split("|")
    if len(parts) != 3 or not all(parts):
        return None
    src, etype, dst = parts
    et = EDGE_TYPES.get(etype)
    return EdgeOut(id=edge_id, type=etype, src=src, dst=dst, derived=bool(et and et.derived), highlight=highlight, props=dict(props or {}))


def alert_node_out(a: AlertSummary, *, highlight: bool = False) -> NodeOut:
    tags = []
    if a.reaches_crown_jewel:
        tags.append("reaches_crown_jewel")
    if a.on_attack_path:
        tags.append("on_attack_path")
    if a.storyline_id:
        tags.append(f"storyline:{a.storyline_id}")
    if a.ioc_match_count:
        tags.append("ioc_match")
    return NodeOut(
        id=a.id, label="Alert", name=a.title, category="alerts", severity=a.vendor_severity, score=a.contextual_score,
        highlight=highlight, tags=tags,
        props={
            "source_system": a.source_system, "alert_type": a.alert_type, "vendor_severity": a.vendor_severity,
            "contextual_score": a.contextual_score, "contextual_band": a.contextual_band, "detected_at": a.detected_at,
            "hostname": a.hostname, "entity_id": a.entity_id, "storyline_id": a.storyline_id, "techniques": a.techniques,
            "graph_reasons": a.graph_reasons, "reaches_crown_jewel": a.reaches_crown_jewel, "on_attack_path": a.on_attack_path,
        },
    )


def storyline_node_out(s: StorylineOut, *, highlight: bool = False) -> NodeOut:
    return NodeOut(
        id=s.id, label="Storyline", name=s.title, category="alerts", score=s.contextual_score, highlight=highlight,
        props={
            "actor_id": s.actor_id, "campaign_id": s.campaign_id, "stage_count": s.stage_count, "alert_ids": s.alert_ids,
            "crown_jewels_reached": s.crown_jewels_reached, "first_event": s.first_event, "last_event": s.last_event,
        },
    )


def fragment_from_nodes(
    nodes: Iterable[NodeOut], edges: Iterable[EdgeOut] = (), *, focus: Iterable[str] = (), layout_hint: str = "neighborhood",
) -> GraphFragment:
    uniq_n: dict[str, NodeOut] = {}
    for n in nodes:
        uniq_n.setdefault(n.id, n)
    uniq_e: dict[str, EdgeOut] = {}
    for e in edges:
        uniq_e.setdefault(e.id, e)
    return GraphFragment(nodes=list(uniq_n.values()), edges=list(uniq_e.values()), focus=list(dict.fromkeys(focus)), layout_hint=layout_hint)  # type: ignore[arg-type]


def cap_fragment(frag: GraphFragment, max_nodes: int, *, layout_hint: str | None = None) -> GraphFragment:
    """Keep at most ``max_nodes`` nodes (focus and highlighted first), drop dangling edges and paths."""
    if frag is None:
        return GraphFragment(layout_hint=layout_hint or "neighborhood")  # type: ignore[arg-type]
    if len(frag.nodes) <= max_nodes:
        if layout_hint and frag.layout_hint != layout_hint:
            return frag.model_copy(update={"layout_hint": layout_hint})
        return frag
    focus = set(frag.focus)
    ordered = sorted(frag.nodes, key=lambda n: (n.id not in focus, not n.highlight))
    keep = ordered[:max_nodes]
    keep_ids = {n.id for n in keep}
    # preserve the original order for readability
    nodes = [n for n in frag.nodes if n.id in keep_ids]
    edges = [e for e in frag.edges if e.src in keep_ids and e.dst in keep_ids]
    paths = [p for p in frag.paths if all(nid in keep_ids for nid in p.node_ids)]
    return GraphFragment(
        nodes=nodes, edges=edges, paths=paths, focus=frag.focus, layout_hint=layout_hint or frag.layout_hint,  # type: ignore[arg-type]
        truncated=True, total_nodes=frag.total_nodes or len(frag.nodes), meta=dict(frag.meta),
    )


def merge_fragments(frags: Iterable[GraphFragment | None], *, layout_hint: str | None = None) -> GraphFragment:
    out: GraphFragment | None = None
    for f in frags:
        if f is None:
            continue
        out = f if out is None else out.merge(f)
    out = out or GraphFragment()
    if layout_hint:
        out = out.model_copy(update={"layout_hint": layout_hint})
    return out


# ----------------------------------------------------------------------------- compaction for the model


def _dump(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, Mapping):
        return {str(k): _dump(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_dump(v) for v in obj]
    return obj


def _node_brief(n: Mapping[str, Any]) -> str:
    bits = [str(n.get("id"))]
    label, name = n.get("label"), n.get("name")
    if label or name:
        bits.append(f"({label}: {name})" if label else f"({name})")
    tags = n.get("tags") or []
    if tags:
        bits.append("[" + ",".join(str(t) for t in tags[:4]) + "]")
    if n.get("score") is not None:
        bits.append(f"score={n['score']}")
    return " ".join(bits)


def _is_fragment(d: Mapping[str, Any]) -> bool:
    return isinstance(d.get("nodes"), list) and isinstance(d.get("edges"), list) and "layout_hint" in d


def _trim(node: Any, max_list: int, max_str: int, *, in_props: bool = False) -> Any:
    if isinstance(node, Mapping):
        if _is_fragment(node):
            nodes = node.get("nodes") or []
            summary: dict[str, Any] = {
                "node_count": len(nodes), "edge_count": len(node.get("edges") or []), "truncated": node.get("truncated", False),
                "layout_hint": node.get("layout_hint"), "focus": node.get("focus"),
                "nodes": [_node_brief(n) for n in nodes[:max_list]],
            }
            if len(nodes) > max_list:
                summary["nodes"].append(f"... +{len(nodes) - max_list} more nodes")
            paths = node.get("paths") or []
            if paths:
                summary["paths"] = [{"hops": p.get("hops"), "node_ids": p.get("node_ids")} for p in paths[:3]]
            return summary
        out: dict[str, Any] = {}
        for k, v in node.items():
            if in_props and k in BULKY_PROP_KEYS:
                out[k] = "<omitted>"
                continue
            out[k] = _trim(v, max_list, max_str, in_props=(k == "props"))
        return out
    if isinstance(node, list):
        items = [_trim(v, max_list, max_str, in_props=in_props) for v in node[:max_list]]
        if len(node) > max_list:
            items.append(f"... +{len(node) - max_list} more")
        return items
    if isinstance(node, str) and len(node) > max_str:
        return node[: max_str - 1] + "…"
    return node


def compact_for_model(obj: Any, *, max_list: int = 40, max_str: int = 300, max_chars: int = 12000) -> str:
    """JSON for the model context: fragments -> counts + ids, long lists/strings truncated, bounded size."""
    data = _dump(obj)
    text = ""
    for lst, s in ((max_list, max_str), (15, 120), (6, 80)):
        text = json.dumps(_trim(data, lst, s), separators=(",", ":"), ensure_ascii=False, default=str)
        if len(text) <= max_chars:
            return text
    return json.dumps(
        {"truncated": True, "note": "result too large for the model context; ask a narrower question", "preview": text[: max_chars - 200]},
        separators=(",", ":"), ensure_ascii=False,
    )


# ----------------------------------------------------------------------------- tool plumbing


class ToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolResult(BaseModel):
    result: Any = None
    evidence: GraphFragment | None = None
    summary: str = ""
    result_ids: list[str] = Field(default_factory=list)

    def citable_ids(self) -> set[str]:
        ids: set[str] = set(self.result_ids)
        if self.evidence is not None:
            ids.update(n.id for n in self.evidence.nodes)
            ids.update(e.id for e in self.evidence.edges)
        return ids


class EvidenceSet:
    """Merged evidence of one analyst turn plus the set of ids the answer may cite."""

    def __init__(self) -> None:
        self.fragment = GraphFragment()
        self.ids: set[str] = set()

    def add(self, result: ToolResult) -> GraphFragment | None:
        frag = result.evidence
        if frag is not None and (frag.nodes or frag.edges or frag.paths):
            if not self.fragment.nodes and not self.fragment.edges:
                self.fragment = frag.model_copy(deep=True)
            else:
                merged = self.fragment.merge(frag)
                if self.fragment.layout_hint == "neighborhood" and frag.layout_hint != "neighborhood":
                    merged = merged.model_copy(update={"layout_hint": frag.layout_hint})
                self.fragment = merged
        self.ids.update(result.citable_ids())
        return frag if frag is not None and (frag.nodes or frag.edges) else None

    def validate_ids(self, ids: Iterable[str]) -> tuple[list[str], list[str]]:
        kept, dropped = [], []
        for i in dict.fromkeys(ids):
            (kept if i in self.ids else dropped).append(i)
        return kept, dropped


_STRIP_KEYS = {"title", "default", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems", "multipleOf", "pattern"}


def strict_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Pydantic JSON schema -> Anthropic strict tool schema (refs inlined, numeric/string constraints removed)."""
    raw = model.model_json_schema()
    defs = raw.pop("$defs", {})

    def clean(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                ref = node["$ref"].split("/")[-1]
                merged = {**defs.get(ref, {}), **{k: v for k, v in node.items() if k != "$ref"}}
                return clean(merged)
            out: dict[str, Any] = {}
            for k, v in node.items():
                if k in _STRIP_KEYS:
                    continue
                out[k] = clean(v)
            if out.get("type") == "object":
                out.setdefault("properties", {})
                out["additionalProperties"] = False
                out["required"] = list(out.get("required") or [])
            return out
        if isinstance(node, list):
            return [clean(v) for v in node]
        return node

    schema = clean(raw)
    schema["type"] = "object"
    return schema


@dataclass
class Tool:
    name: str
    description: str
    args_model: type[ToolArgs]
    handler: Callable[[Any], ToolResult]

    def definition(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": strict_schema(self.args_model), "strict": True}

    def run(self, arguments: Mapping[str, Any] | None = None) -> ToolResult:
        args = self.args_model.model_validate(dict(arguments or {}))
        return self.handler(args)


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(int(v), hi))


def _validate_labels(labels: list[str] | None) -> list[str] | None:
    if not labels:
        return None
    unknown = [lb for lb in labels if lb not in LABELS]
    if unknown:
        raise ValueError(f"unknown label(s) {unknown}; known labels: {sorted(LABELS)}")
    return labels


def _validate_edge_types(types: list[str] | None) -> list[str] | None:
    if not types:
        return None
    unknown = [t for t in types if t not in EDGE_TYPES]
    if unknown:
        raise ValueError(f"unknown edge type(s) {unknown}; known types: {sorted(EDGE_TYPES)}")
    return types


# ----------------------------------------------------------------------------- argument models


class SearchEntitiesArgs(ToolArgs):
    query: str = Field(description="Free text: hostname, IP, hash, domain, login, role/bucket name, CVE id, alert id or title, actor name.")
    labels: list[str] | None = Field(default=None, description="Optional node labels to restrict to, e.g. ['Endpoint','VirtualMachine'].")
    limit: int = Field(default=10, description="Maximum hits, 1-25 (default 10).")

    @field_validator("limit")
    @classmethod
    def _lim(cls, v: int) -> int:
        return _clamp(v, 1, 25)

    @field_validator("labels")
    @classmethod
    def _labels(cls, v: list[str] | None) -> list[str] | None:
        return _validate_labels(v)


class GetEntityArgs(ToolArgs):
    id: str = Field(description="Canonical node id, e.g. 'vm:aws:i-0b4571e2c9a8f3d01'.")


class GetNeighborhoodArgs(ToolArgs):
    id: str = Field(description="Centre node id.")
    depth: int = Field(default=1, description="Hops, 1-2 (default 1).")
    edge_types: list[str] | None = Field(default=None, description="Optional edge types to follow, e.g. ['HAS_ROLE','CAN_ASSUME'].")
    labels: list[str] | None = Field(default=None, description="Optional node labels to keep.")
    max_nodes: int = Field(default=60, description="Node cap, 1-100 (default 60).")

    @field_validator("depth")
    @classmethod
    def _depth(cls, v: int) -> int:
        return _clamp(v, 1, 2)

    @field_validator("max_nodes")
    @classmethod
    def _max_nodes(cls, v: int) -> int:
        return _clamp(v, 1, 100)

    @field_validator("labels")
    @classmethod
    def _labels(cls, v: list[str] | None) -> list[str] | None:
        return _validate_labels(v)

    @field_validator("edge_types")
    @classmethod
    def _types(cls, v: list[str] | None) -> list[str] | None:
        return _validate_edge_types(v)


class FindPathsArgs(ToolArgs):
    src_id: str = Field(description="Start node id (e.g. an alert or endpoint).")
    dst_id: str = Field(description="Target node id (e.g. a bucket, database or secret).")
    max_hops: int = Field(default=6, description="Maximum hops, 1-6 (default 6).")
    k: int = Field(default=3, description="Number of paths, 1-3 (default 3).")

    @field_validator("max_hops")
    @classmethod
    def _hops(cls, v: int) -> int:
        return _clamp(v, 1, 6)

    @field_validator("k")
    @classmethod
    def _k(cls, v: int) -> int:
        return _clamp(v, 1, 3)


class BlastRadiusArgs(ToolArgs):
    id: str = Field(description="Root node id: alert, endpoint, VM, workload, role or user.")
    depth: int = Field(default=4, description="Traversal depth, 1-5 (default 4).")

    @field_validator("depth")
    @classmethod
    def _depth(cls, v: int) -> int:
        return _clamp(v, 1, 5)


class AttackPathsArgs(ToolArgs):
    through_id: str | None = Field(default=None, description="Node the path must pass through (alert, endpoint, VM, role).")
    target_id: str | None = Field(default=None, description="Data store the path must end at (bucket, database, secret).")
    k: int = Field(default=3, description="Number of paths, 1-5 (default 3).")

    @field_validator("k")
    @classmethod
    def _k(cls, v: int) -> int:
        return _clamp(v, 1, 5)


class ListAlertsArgs(ToolArgs):
    sort: Literal["contextual", "vendor", "time"] = Field(default="contextual", description="Ordering (descending).")
    band: BandLit | None = Field(default=None, description="Contextual band filter.")
    severity: Severity | None = Field(default=None, description="Vendor severity filter.")
    source: SourceLit | None = Field(default=None, description="Source system filter.")
    storyline_id: str | None = Field(default=None, description="Only alerts in this storyline.")
    reaches_crown_jewel: bool | None = Field(default=None, description="Only alerts whose asset reaches a crown jewel.")
    q: str | None = Field(default=None, description="Text filter on title / hostname / entity (e.g. a hostname).")
    limit: int = Field(default=20, description="Maximum rows, 1-50 (default 20).")

    @field_validator("limit")
    @classmethod
    def _lim(cls, v: int) -> int:
        return _clamp(v, 1, 50)


class AlertIdArgs(ToolArgs):
    alert_id: str = Field(description="Alert id, e.g. 'alert:falcon:ldt-a009'.")


class StorylineIdArgs(ToolArgs):
    storyline_id: str = Field(description="Storyline id, e.g. 'storyline:derived:embercast-larkspur'.")


class NoArgs(ToolArgs):
    pass


class ThreatIntelLookupArgs(ToolArgs):
    value: str = Field(description="sha256, IP, domain, CVE id, technique id, or actor/campaign/report/malware id or name.")


class ExposedHostsArgs(ToolArgs):
    sector_only: bool = Field(default=True, description="Keep only actors targeting financial services (relevance >= 0.7). Default true.")


class AlertsReachingCrownJewelsArgs(ToolArgs):
    jewel_id: str | None = Field(default=None, description="Restrict to alerts that can reach this crown jewel id.")
    classification: str | None = Field(default=None, description="Restrict to jewels holding this classification (PCI, PII, SECRETS, PHI, FINANCIAL).")


class AlertsWithDataPathArgs(ToolArgs):
    severity: Severity = Field(default="medium", description="Vendor severity (default medium).")
    source: SourceLit | None = Field(default="falcon", description="Source system (default falcon = endpoint detections); null for all.")


class IdentityFootprintArgs(ToolArgs):
    identity_id: str = Field(description="Identity id: IamRole, IamUser, HumanUser or ServiceAccount.")


class SimulateContainmentArgs(ToolArgs):
    target_ids: list[str] = Field(description="Endpoints, VMs, roles, users or IPs to act on.")
    actions: list[ContainmentAction] = Field(description="Containment actions to simulate.")

    @field_validator("target_ids")
    @classmethod
    def _targets(cls, v: list[str]) -> list[str]:
        v = [t for t in dict.fromkeys(v) if t]
        if not v:
            raise ValueError("target_ids must contain at least one id")
        return v[:20]

    @field_validator("actions")
    @classmethod
    def _actions(cls, v: list[str]) -> list[str]:
        v = list(dict.fromkeys(v))
        if not v:
            raise ValueError("actions must contain at least one action")
        return v


class RunCypherArgs(ToolArgs):
    query: str = Field(description="Read-only Cypher (MATCH ... RETURN ...). Bound variable-length patterns to <= 5 hops.")
    row_limit: int = Field(default=50, description="Maximum rows, 1-200 (default 50).")

    @field_validator("row_limit")
    @classmethod
    def _rows(cls, v: int) -> int:
        return _clamp(v, 1, 200)


class FindingArgs(ToolArgs):
    statement: str = Field(description="One concrete, cited sentence.")
    severity: Severity | None = Field(default=None, description="Severity of this finding.")
    evidence_ids: list[str] = Field(default_factory=list, description="Node/edge ids from tool results that support it.")


class SubmitAnswerArgs(ToolArgs):
    narrative_md: str = Field(description="Markdown with sections ## Findings, ## Evidence, ## Impact, ## Recommended actions.")
    findings: list[FindingArgs] = Field(default_factory=list, description="Key findings with severity and evidence ids.")
    evidence_ids: list[str] = Field(default_factory=list, description="All node/edge ids relied upon.")
    confidence: float = Field(default=0.7, description="0-1 confidence in the answer.")
    followups: list[str] = Field(default_factory=list, description="2-3 next questions.")

    @field_validator("confidence")
    @classmethod
    def _conf(cls, v: float) -> float:
        return max(0.0, min(float(v), 1.0))


# ----------------------------------------------------------------------------- registry


class ToolRegistry:
    """Typed tools over ``AnalyticsEngine`` (Agent C) and ``GraphStore`` (Agent B)."""

    BLAST_FRAGMENT_CAP = 100
    PATH_FRAGMENT_CAP = 60

    def __init__(self, engine: Any, store: Any, *, settings: Any | None = None) -> None:
        self.engine = engine
        self.store = store
        if settings is None:
            from throughline.config import settings as _settings

            settings = _settings
        self.settings = settings
        self._tools: dict[str, Tool] = {}
        self._register_all()

    # -------------------------------------------------------------- public API

    def names(self) -> list[str]:
        return list(self._tools)

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError:
            raise KeyError(f"unknown tool {name!r}") from None

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def anthropic_tools(self) -> list[dict[str, Any]]:
        return [t.definition() for t in self._tools.values()]

    def run(self, name: str, arguments: Mapping[str, Any] | None = None) -> ToolResult:
        return self.get(name).run(arguments)

    def timed_run(self, name: str, arguments: Mapping[str, Any] | None = None) -> tuple[ToolResult, int]:
        t0 = time.perf_counter()
        res = self.run(name, arguments)
        return res, int((time.perf_counter() - t0) * 1000)

    # -------------------------------------------------------------- helpers

    def node_outs(self, ids: Iterable[str], *, highlight: Iterable[str] = ()) -> list[NodeOut]:
        wanted = [i for i in dict.fromkeys(ids) if isinstance(i, str) and i]
        if not wanted:
            return []
        try:
            recs = self.store.get_nodes(wanted)
        except Exception as exc:  # pragma: no cover - defensive against partial stores
            log.warning("store.get_nodes failed: %s", exc)
            recs = []
        by_id = {str(r.get("id")): r for r in recs if isinstance(r, Mapping) and r.get("id")}
        hl = set(highlight)
        return [record_to_node_out(by_id[i], highlight=i in hl) for i in wanted if i in by_id]

    def fragment_for_ids(
        self, node_ids: Iterable[str], edge_ids: Iterable[str] = (), *, focus: Iterable[str] = (), layout_hint: str = "neighborhood",
        highlight: Iterable[str] = (),
    ) -> GraphFragment:
        nodes = self.node_outs(node_ids, highlight=highlight)
        present = {n.id for n in nodes}
        edges = []
        for eid in dict.fromkeys(edge_ids):
            e = edge_out_from_id(eid)
            if e is not None and e.src in present and e.dst in present:
                edges.append(e)
        return fragment_from_nodes(nodes, edges, focus=focus, layout_hint=layout_hint)

    # -------------------------------------------------------------- registration

    def _add(self, name: str, args_model: type[ToolArgs], handler: Callable[[Any], ToolResult]) -> None:
        self._tools[name] = Tool(name=name, description=TOOL_DESCRIPTIONS[name], args_model=args_model, handler=handler)

    def _register_all(self) -> None:
        self._add("search_entities", SearchEntitiesArgs, self._search_entities)
        self._add("get_entity", GetEntityArgs, self._get_entity)
        self._add("get_neighborhood", GetNeighborhoodArgs, self._get_neighborhood)
        self._add("find_paths", FindPathsArgs, self._find_paths)
        self._add("blast_radius", BlastRadiusArgs, self._blast_radius)
        self._add("attack_paths", AttackPathsArgs, self._attack_paths)
        self._add("list_alerts", ListAlertsArgs, self._list_alerts)
        self._add("get_alert", AlertIdArgs, self._get_alert)
        self._add("get_alert_context", AlertIdArgs, self._get_alert_context)
        self._add("explain_risk", AlertIdArgs, self._explain_risk)
        self._add("get_storyline", StorylineIdArgs, self._get_storyline)
        self._add("list_storylines", NoArgs, self._list_storylines)
        self._add("threat_intel_lookup", ThreatIntelLookupArgs, self._threat_intel_lookup)
        self._add("exposed_hosts_with_exploited_vulns", ExposedHostsArgs, self._exposed_hosts)
        self._add("credential_joins", NoArgs, self._credential_joins)
        self._add("alerts_reaching_crown_jewels", AlertsReachingCrownJewelsArgs, self._alerts_reaching_crown_jewels)
        self._add("alerts_with_data_path", AlertsWithDataPathArgs, self._alerts_with_data_path)
        self._add("identity_footprint", IdentityFootprintArgs, self._identity_footprint)
        self._add("simulate_containment", SimulateContainmentArgs, self._simulate_containment)
        self._add("run_cypher", RunCypherArgs, self._run_cypher)
        self._add("get_schema", NoArgs, self._get_schema)
        self._add("submit_answer", SubmitAnswerArgs, self._submit_answer)

    # -------------------------------------------------------------- handlers

    def _search_entities(self, a: SearchEntitiesArgs) -> ToolResult:
        hits: list[SearchHit] = list(self.store.search(a.query, a.labels, a.limit))[: a.limit]
        return ToolResult(
            result={"query": a.query, "labels": a.labels, "count": len(hits), "hits": [h.model_dump(mode="json") for h in hits]},
            summary=f"{len(hits)} hit(s) for {a.query!r}" + (f" in {a.labels}" if a.labels else ""),
            result_ids=[h.id for h in hits],
        )

    def _get_entity(self, a: GetEntityArgs) -> ToolResult:
        card = dict(self.engine.node_card(a.id))
        node = card.get("node")
        node_out = node if isinstance(node, NodeOut) else NodeOut.model_validate(node) if isinstance(node, Mapping) else None
        alerts = list(card.get("alerts") or [])[:10]
        card["alerts"] = alerts
        result = _dump(card)
        nodes: list[NodeOut] = []
        if node_out is not None:
            nodes.append(node_out.model_copy(update={"highlight": True}))
        for al in alerts:
            if isinstance(al, AlertSummary):
                nodes.append(alert_node_out(al))
            elif isinstance(al, Mapping) and al.get("id"):
                nodes.append(alert_node_out(AlertSummary.model_validate(al)))
        degree = card.get("degree") or {}
        summary = f"{node_out.label} {node_out.name}" if node_out else a.id
        summary += f": in={degree.get('in', 0)} out={degree.get('out', 0)}, {len(alerts)} alert(s)"
        return ToolResult(result=result, evidence=fragment_from_nodes(nodes, focus=[a.id]), summary=summary)

    def _get_neighborhood(self, a: GetNeighborhoodArgs) -> ToolResult:
        frag: GraphFragment = self.engine.neighborhood(a.id, depth=a.depth, edge_types=a.edge_types, direction="both", labels=a.labels, max_nodes=a.max_nodes)
        frag = cap_fragment(frag, a.max_nodes)
        if a.id not in frag.focus:
            frag = frag.model_copy(update={"focus": [a.id, *frag.focus]})
        by_label: dict[str, int] = {}
        for n in frag.nodes:
            by_label[n.label] = by_label.get(n.label, 0) + 1
        result = {
            "id": a.id, "depth": a.depth, "node_count": len(frag.nodes), "edge_count": len(frag.edges), "truncated": frag.truncated,
            "nodes_by_label": by_label,
            "nodes": [{"id": n.id, "label": n.label, "name": n.name, "tags": n.tags} for n in frag.nodes],
            "edges": [{"id": e.id, "type": e.type} for e in frag.edges],
        }
        return ToolResult(result=result, evidence=frag, summary=f"{len(frag.nodes)} nodes / {len(frag.edges)} edges within {a.depth} hop(s) of {a.id}")

    def _find_paths(self, a: FindPathsArgs) -> ToolResult:
        frag: GraphFragment = self.engine.find_paths(a.src_id, a.dst_id, max_hops=a.max_hops, k=a.k)
        frag = frag.model_copy(update={"layout_hint": "path", "focus": list(dict.fromkeys([*frag.focus, a.src_id, a.dst_id]))})
        paths: list[PathOut] = list(frag.paths)[: a.k]
        result = {
            "src_id": a.src_id, "dst_id": a.dst_id, "found": bool(paths), "path_count": len(paths),
            "paths": [p.model_dump(mode="json") for p in paths], "node_count": len(frag.nodes),
        }
        summary = f"{len(paths)} path(s) {a.src_id} -> {a.dst_id}" + (f", shortest {min(p.hops for p in paths)} hops" if paths else " (none within bounds)")
        return ToolResult(result=result, evidence=frag, summary=summary)

    def _blast_radius(self, a: BlastRadiusArgs) -> ToolResult:
        br = self.engine.blast_radius(a.id, depth=a.depth, max_nodes=500)
        return self._blast_result(br, root=a.id)

    def _identity_footprint(self, a: IdentityFootprintArgs) -> ToolResult:
        br = self.engine.identity_footprint(a.identity_id)
        return self._blast_result(br, root=a.identity_id)

    def _blast_result(self, br: Any, *, root: str) -> ToolResult:
        frag = cap_fragment(br.fragment, self.BLAST_FRAGMENT_CAP, layout_hint="blast_radius")
        if root not in frag.focus:
            frag = frag.model_copy(update={"focus": [root, *frag.focus]})
        result = br.model_dump(mode="json", exclude={"fragment"})
        result["fragment_node_count"] = len(frag.nodes)
        summary = (
            f"{br.reached_count} nodes reached from {root} (depth {br.depth}): {len(br.crown_jewels)} crown jewel(s), "
            f"{len(br.data_stores)} data store(s), {len(br.secrets)} secret(s), {len(br.identities)} identit(ies)"
        )
        return ToolResult(result=result, evidence=frag, summary=summary)

    def _attack_paths(self, a: AttackPathsArgs) -> ToolResult:
        paths = list(self.engine.attack_paths(through_id=a.through_id, target_id=a.target_id, entry_id=None, k=a.k))[: a.k]
        frags = [cap_fragment(p.fragment, self.PATH_FRAGMENT_CAP) for p in paths if p.fragment is not None]
        focus = [x for x in (a.through_id, a.target_id) if x]
        evidence = merge_fragments(frags, layout_hint="path")
        evidence = evidence.model_copy(update={"focus": list(dict.fromkeys([*focus, *evidence.focus]))})
        result = {"count": len(paths), "through_id": a.through_id, "target_id": a.target_id, "paths": [p.model_dump(mode="json", exclude={"fragment"}) for p in paths]}
        summary = f"{len(paths)} attack path(s)" + (f" through {a.through_id}" if a.through_id else "") + (f" to {a.target_id}" if a.target_id else "")
        if paths:
            summary += f"; best likelihood {max(p.likelihood for p in paths):.2f}, {paths[0].hops} hops, {len(paths[0].stages)} stages"
        return ToolResult(result=result, evidence=evidence, summary=summary)

    def _list_alerts(self, a: ListAlertsArgs) -> ToolResult:
        items, total = self.engine.list_alerts(
            sort=a.sort, order="desc", band=a.band, severity=a.severity, source=a.source, storyline_id=a.storyline_id,
            reaches_crown_jewel=a.reaches_crown_jewel, on_attack_path=None, q=a.q, limit=a.limit, offset=0,
        )
        items = list(items)[: a.limit]
        frag = fragment_from_nodes([alert_node_out(x) for x in items])
        result = {"total": total, "returned": len(items), "sort": a.sort, "filters": a.model_dump(exclude={"sort", "limit"}, exclude_none=True), "items": [x.model_dump(mode="json") for x in items]}
        ids = [x.id for x in items] + [x.entity_id for x in items if x.entity_id]
        return ToolResult(result=result, evidence=frag, summary=f"{len(items)} of {total} alert(s), sorted by {a.sort}", result_ids=ids)

    def _storyline_summary(self, storyline_id: str | None) -> dict[str, Any] | None:
        if not storyline_id:
            return None
        try:
            s: StorylineOut = self.engine.storyline(storyline_id, with_fragment=False)
        except Exception:
            return None
        return s.model_dump(mode="json", exclude={"fragment": True, "stages": {"__all__": {"edge_ids", "node_ids"}}})

    def _get_alert(self, a: AlertIdArgs) -> ToolResult:
        alert: AlertSummary = self.engine.alert_summary(a.alert_id)
        flat = self.engine.flat_view(a.alert_id)
        risk = self.engine.risk_breakdown(a.alert_id)
        insights = list(self.engine.insights(a.alert_id))
        story = self._storyline_summary(alert.storyline_id)
        result = {"alert": alert.model_dump(mode="json"), "flat_view": flat, "risk": risk.model_dump(mode="json"), "insights": [i.model_dump(mode="json") for i in insights], "storyline": story}
        # evidence: the alert, its entity, factor and insight evidence
        ev_ids: list[str] = []
        if alert.entity_id:
            ev_ids.append(alert.entity_id)
        for f in risk.factors:
            ev_ids.extend(f.evidence_ids)
        edge_ids: list[str] = []
        for ins in insights:
            ev_ids.extend(ins.evidence_node_ids)
            edge_ids.extend(ins.evidence_edge_ids)
        node_ids = [i for i in dict.fromkeys(ev_ids) if "|" not in i][:60]
        edge_ids += [i for i in ev_ids if "|" in i]
        frag = self.fragment_for_ids(node_ids, edge_ids, focus=[a.alert_id], highlight=[alert.entity_id] if alert.entity_id else ())
        frag = fragment_from_nodes([alert_node_out(alert, highlight=True), *frag.nodes], frag.edges, focus=[a.alert_id])
        summary = f"{alert.id}: {alert.title} | vendor {alert.vendor_severity} -> contextual {alert.contextual_score} ({alert.contextual_band})"
        if alert.storyline_id:
            summary += f", storyline {alert.storyline_id}"
        return ToolResult(result=result, evidence=frag, summary=summary, result_ids=[a.alert_id])

    def _get_alert_context(self, a: AlertIdArgs) -> ToolResult:
        ctx = self.engine.alert_context(a.alert_id)
        result = ctx.model_dump(
            mode="json",
            exclude={"evidence": True, "blast_radius": {"fragment"}, "storyline": {"fragment"}, "attack_paths": {"__all__": {"fragment"}}},
        )
        frags: list[GraphFragment | None] = [ctx.evidence]
        if ctx.blast_radius is not None:
            frags.append(cap_fragment(ctx.blast_radius.fragment, self.PATH_FRAGMENT_CAP))
        for p in ctx.attack_paths[:3]:
            frags.append(cap_fragment(p.fragment, self.PATH_FRAGMENT_CAP))
        evidence = merge_fragments(frags, layout_hint=ctx.evidence.layout_hint if ctx.evidence is not None else "path")
        if a.alert_id not in evidence.focus:
            evidence = evidence.model_copy(update={"focus": [a.alert_id, *evidence.focus]})
        cj = len(ctx.blast_radius.crown_jewels) if ctx.blast_radius else 0
        summary = f"{ctx.alert.id} context: score {ctx.alert.contextual_score}, {cj} crown jewel(s) reachable, {len(ctx.attack_paths)} attack path(s), {len(ctx.insights)} insight(s)"
        if ctx.storyline:
            summary += f", storyline {ctx.storyline.id}"
        return ToolResult(result=result, evidence=evidence, summary=summary, result_ids=[a.alert_id])

    def _explain_risk(self, a: AlertIdArgs) -> ToolResult:
        risk = self.engine.risk_breakdown(a.alert_id)
        ev_ids: list[str] = [a.alert_id]
        for f in risk.factors:
            ev_ids.extend(f.evidence_ids)
        node_ids = [i for i in dict.fromkeys(ev_ids) if "|" not in i][:60]
        edge_ids = [i for i in ev_ids if "|" in i]
        frag = self.fragment_for_ids(node_ids, edge_ids, focus=[a.alert_id], layout_hint="neighborhood", highlight=[a.alert_id])
        top = sorted(risk.factors, key=lambda f: -f.contribution)[:3]
        summary = f"{a.alert_id}: {risk.contextual_score} ({risk.band}); top factors " + ", ".join(f"{f.key}={f.value:.2f}" for f in top)
        if risk.rails:
            summary += f"; rails {risk.rails}"
        return ToolResult(result=risk.model_dump(mode="json"), evidence=frag, summary=summary, result_ids=[a.alert_id])

    def _get_storyline(self, a: StorylineIdArgs) -> ToolResult:
        s: StorylineOut = self.engine.storyline(a.storyline_id, with_fragment=True)
        frag = s.fragment or GraphFragment()
        frag = cap_fragment(frag, 150, layout_hint="storyline")
        frag = fragment_from_nodes([storyline_node_out(s, highlight=True), *frag.nodes], frag.edges, focus=[a.storyline_id, *frag.focus], layout_hint="storyline")
        frag = frag.model_copy(update={"paths": (s.fragment.paths if s.fragment else [])})
        result = s.model_dump(mode="json", exclude={"fragment"})
        summary = f"{s.title}: {s.stage_count} stages, {len(s.alert_ids)} alerts, score {s.contextual_score}, {len(s.crown_jewels_reached)} crown jewel(s) reached"
        return ToolResult(result=result, evidence=frag, summary=summary, result_ids=[*s.alert_ids, *s.crown_jewels_reached])

    def _list_storylines(self, _: NoArgs) -> ToolResult:
        items: list[StorylineOut] = list(self.engine.list_storylines())
        frag = fragment_from_nodes([storyline_node_out(s) for s in items])
        result = {"count": len(items), "items": [s.model_dump(mode="json", exclude={"fragment": True, "stages": {"__all__": {"edge_ids", "node_ids"}}}) for s in items]}
        ids: list[str] = []
        for s in items:
            ids.extend(s.alert_ids)
            ids.extend(s.crown_jewels_reached)
        return ToolResult(result=result, evidence=frag, summary=f"{len(items)} storyline(s)", result_ids=ids)

    def _threat_intel_lookup(self, a: ThreatIntelLookupArgs) -> ToolResult:
        ti: TIContext = self.engine.ti_lookup(a.value)
        nodes: list[NodeOut] = [*ti.actors, *ti.campaigns, *ti.malware, *ti.exploited_vulnerabilities, *ti.reports]
        indicator_ids = [m.indicator_id for m in ti.matches]
        matched_ids = [m.matched_node_id for m in ti.matches]
        nodes += self.node_outs([*indicator_ids, *matched_ids][:120], highlight=matched_ids)
        present = {n.id for n in nodes}
        edges = []
        for m in ti.matches:
            if m.matched_node_id in present and m.indicator_id in present:
                e = edge_out_from_id(f"{m.matched_node_id}|MATCHES_IOC|{m.indicator_id}", props={"confidence": m.confidence})
                if e is not None:
                    edges.append(e)
        focus = [n.id for n in [*ti.actors, *ti.campaigns][:3]]
        frag = fragment_from_nodes(nodes, edges, focus=focus)
        summary = f"TI for {a.value!r}: {len(ti.matches)} IOC match(es), {len(ti.actors)} actor(s), {len(ti.campaigns)} campaign(s), {len(ti.exploited_vulnerabilities)} exploited CVE(s)"
        if ti.sector_relevance is not None:
            summary += f", sector relevance {ti.sector_relevance:.2f}"
        return ToolResult(result=ti.model_dump(mode="json"), evidence=frag, summary=summary, result_ids=[*indicator_ids, *matched_ids])

    def _exposed_hosts(self, a: ExposedHostsArgs) -> ToolResult:
        rows = list(self.engine.ti_exposure(sector_only=a.sector_only))
        nodes: list[NodeOut] = []
        edges: list[EdgeOut] = []
        for r in rows:
            vm, cve = _as_node(r.get("vm")), _as_node(r.get("cve"))
            for n in (vm, cve):
                if n is not None:
                    nodes.append(n)
            for key in ("actors", "campaigns", "crown_jewels_reachable"):
                for x in r.get(key) or []:
                    n = _as_node(x)
                    if n is not None:
                        nodes.append(n)
                        if key == "campaigns" and cve is not None:
                            e = edge_out_from_id(f"{n.id}|EXPLOITS|{cve.id}", props={"status": r.get("exploitation_status")})
                            if e:
                                edges.append(e)
            if vm is not None and cve is not None:
                e = edge_out_from_id(f"{vm.id}|VULNERABLE_TO|{cve.id}")
                if e:
                    edges.append(e)
        focus = [n.id for n in nodes[:1]]
        frag = fragment_from_nodes([n.model_copy(update={"highlight": n.label == "VirtualMachine"}) for n in nodes], edges, focus=focus)
        result = {"sector_only": a.sector_only, "count": len(rows), "items": _dump(rows)}
        top = rows[0] if rows else None
        summary = f"{len(rows)} internet-exposed host(s) with actively exploited vulnerabilities"
        if top is not None:
            tv, tc = _as_node(top.get("vm")), _as_node(top.get("cve"))
            summary += f"; #1 {tv.name if tv else '?'} ({tc.name if tc else '?'}, {top.get('exploitation_status')}, score {top.get('contextual_score')})"
        return ToolResult(result=result, evidence=frag, summary=summary)

    def _credential_joins(self, _: NoArgs) -> ToolResult:
        data = dict(self.engine.credential_joins())
        frag = data.pop("fragment", None)
        frag = frag if isinstance(frag, GraphFragment) else (GraphFragment.model_validate(frag) if frag else GraphFragment())
        items = list(data.get("items") or [])
        creds = [_as_node(i.get("credential")) for i in items if isinstance(i, Mapping)]
        cred_ids = [c.id for c in creds if c]
        frag = frag.model_copy(update={"focus": list(dict.fromkeys([*frag.focus, *cred_ids])), "layout_hint": frag.layout_hint if frag.layout_hint != "neighborhood" else "path"})
        result = {"count": len(items), "items": _dump(items)}
        summary = f"{len(items)} credential(s) stolen on an endpoint and used in cloud API calls" + (f": {', '.join(c.name for c in creds if c)}" if creds else "")
        return ToolResult(result=result, evidence=frag, summary=summary, result_ids=cred_ids)

    def _alerts_reaching_crown_jewels(self, a: AlertsReachingCrownJewelsArgs) -> ToolResult:
        data = dict(self.engine.alerts_reaching_crown_jewels(jewel_id=a.jewel_id, classification=a.classification))
        frag = data.pop("fragment", None)
        frag = frag if isinstance(frag, GraphFragment) else (GraphFragment.model_validate(frag) if frag else GraphFragment())
        items = [x if isinstance(x, AlertSummary) else AlertSummary.model_validate(x) for x in data.get("items") or []]
        jewels = [n for n in (_as_node(j) for j in data.get("jewels") or []) if n]
        frag = fragment_from_nodes([*frag.nodes, *[alert_node_out(x) for x in items], *jewels], frag.edges, focus=[j.id for j in jewels], layout_hint=frag.layout_hint if frag.nodes else "neighborhood")
        result = {"count": len(items), "jewel_id": a.jewel_id, "classification": a.classification, "items": [x.model_dump(mode="json") for x in items], "jewels": [j.model_dump(mode="json") for j in jewels]}
        summary = f"{len(items)} alert(s) on assets that can reach {len(jewels)} crown jewel(s)"
        return ToolResult(result=result, evidence=frag, summary=summary, result_ids=[x.id for x in items] + [j.id for j in jewels])

    def _alerts_with_data_path(self, a: AlertsWithDataPathArgs) -> ToolResult:
        data = dict(self.engine.medium_alerts_with_data_path(severity=a.severity, source=a.source))
        frag = data.pop("fragment", None)
        frag = frag if isinstance(frag, GraphFragment) else (GraphFragment.model_validate(frag) if frag else GraphFragment())
        items = [x if isinstance(x, AlertSummary) else AlertSummary.model_validate(x) for x in data.get("items") or []]
        frag = fragment_from_nodes([*frag.nodes, *[alert_node_out(x) for x in items]], frag.edges, focus=[x.id for x in items[:1]], layout_hint=frag.layout_hint if frag.nodes else "neighborhood")
        result = {"severity": a.severity, "source": a.source, "count": len(items), "items": [x.model_dump(mode="json") for x in items]}
        summary = f"{len(items)} {a.severity} {a.source or 'any-source'} alert(s) on assets with a path to regulated data"
        if items:
            summary += f"; #1 {items[0].id} (score {items[0].contextual_score})"
        return ToolResult(result=result, evidence=frag, summary=summary, result_ids=[x.id for x in items])

    def _simulate_containment(self, a: SimulateContainmentArgs) -> ToolResult:
        sim = self.engine.simulate_containment(list(a.target_ids), list(a.actions))
        frag = cap_fragment(sim.fragment, 150)
        frag = frag.model_copy(update={"focus": list(dict.fromkeys([*a.target_ids, *frag.focus]))})
        result = sim.model_dump(mode="json", exclude={"fragment"})
        summary = f"containment of {len(a.target_ids)} target(s) with {a.actions}: {sim.paths_cut} path(s) cut, {len(sim.storylines_contained)} storyline(s) contained, {len(sim.crown_jewels_protected)} crown jewel(s) protected, {len(sim.breaks)} thing(s) break"
        citable = [*sim.target_ids, *sim.storylines_contained, *sim.crown_jewels_protected, *(b.node_id for b in sim.breaks), *(b.owner_team_id for b in sim.breaks if b.owner_team_id)]
        return ToolResult(result=result, evidence=frag, summary=summary, result_ids=list(dict.fromkeys(citable)))

    def _store_capabilities(self) -> dict[str, Any]:
        try:
            return dict(self.store.capabilities() or {})
        except Exception:  # pragma: no cover
            return {}

    def _run_cypher(self, a: RunCypherArgs) -> ToolResult:
        caps = self._store_capabilities()
        backend = getattr(self.store, "name", type(self.store).__name__)
        if not caps.get("cypher"):
            return ToolResult(
                result={
                    "status": "not_supported", "backend": backend,
                    "message": f"The active graph backend ({backend}) has no Cypher engine.",
                    "hint": "Use get_neighborhood, find_paths, blast_radius or the typed investigation tools instead.",
                },
                summary=f"run_cypher not supported on backend {backend}",
            )
        timeout_ms = int(getattr(self.settings, "cypher_timeout_ms", 3000))
        res = self.store.run_readonly_cypher(a.query, params=None, row_limit=a.row_limit, timeout_ms=timeout_ms)
        columns = list(getattr(res, "columns", []))
        rows = list(getattr(res, "rows", []))[: a.row_limit]
        frag = self.cypher_fragment(rows)
        result = {
            "status": "ok", "columns": columns, "rows": rows, "row_count": len(rows),
            "elapsed_ms": getattr(res, "elapsed_ms", 0), "truncated": bool(getattr(res, "truncated", False)),
        }
        return ToolResult(result=result, evidence=frag if frag.nodes else None, summary=f"{len(rows)} row(s), {len(columns)} column(s) in {getattr(res, 'elapsed_ms', 0)} ms")

    def cypher_fragment(self, rows: Sequence[Sequence[Any]]) -> GraphFragment:
        node_ids: list[str] = []
        edge_ids: list[str] = []

        def visit(v: Any) -> None:
            if isinstance(v, Mapping):
                if "id" in v and "label" in v:
                    node_ids.append(str(v["id"]))
                elif {"src", "type", "dst"} <= set(v):
                    node_ids.extend([str(v["src"]), str(v["dst"])])
                    edge_ids.append(f"{v['src']}|{v['type']}|{v['dst']}")
                else:
                    for x in v.values():
                        visit(x)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    visit(x)

        for row in rows:
            visit(row)
        return self.fragment_for_ids(node_ids[:150], edge_ids)

    def _get_schema(self, _: NoArgs) -> ToolResult:
        labels = [
            {"name": lbl.name, "category": lbl.category, "id_prefix": lbl.id_prefix, "key_properties": [c.name for c in lbl.columns[:8]]}
            for lbl in LABELS.values()
        ]
        edge_types = [
            {"name": et.name, "pairs": [list(p) for p in et.pairs[:12]], "properties": [c.name for c in et.columns], "derived": et.derived}
            for et in EDGE_TYPES.values()
        ]
        try:
            store_schema = self.store.schema_summary()
        except Exception as exc:  # pragma: no cover
            store_schema = {"error": str(exc)}
        result = {
            "id_conventions": {
                "node_id": "<type>:<namespace>:<natural-key>, lowercase type prefix from the label table",
                "examples": ["alert:falcon:ldt-a009", "endpoint:falcon:aid-bas01", "vm:aws:i-0b4571e2c9a8f3d01", "role:aws:222222222222:LarkspurBastionSSMRole", "bucket:aws:larkspur-cardholder-vault", "cve:CVE-2021-44228", "technique:attack:T1552.005"],
                "edge_id": "src|TYPE|dst",
                "timestamps": "ISO-8601 UTC strings; simulation clock NOW = 2026-09-11T14:00:00Z",
            },
            "capabilities": self._store_capabilities(),
            "labels": labels,
            "edge_types": edge_types,
            "example_queries": [
                "MATCH (a:Alert)-[:ON_ENDPOINT]->(e:Endpoint)-[:SAME_AS]->(v:VirtualMachine)-[:HAS_ROLE]->(r:IamRole) RETURN a.id, e.hostname, v.name, r.name LIMIT 20",
                "MATCH (r:IamRole)-[:CAN_ASSUME]->(p:IamRole)-[:CAN_ACCESS]->(b:StorageBucket) WHERE b.crown_jewel = true RETURN r.name, p.name, b.name",
                "MATCH (c:Credential)-[:STOLEN_BY]->(a:Alert), (ev:CloudEvent)-[:USED_CREDENTIAL]->(c) RETURN c.id, a.id, ev.event_name, ev.event_time ORDER BY ev.event_time",
                "MATCH (n)-[:MATCHES_IOC]->(i:Indicator)-[:INDICATES]->(m) RETURN n.id, i.value, m.name LIMIT 50",
            ],
            "store_schema": store_schema,
        }
        return ToolResult(result=result, summary=f"{len(labels)} labels, {len(edge_types)} edge types; cypher={bool(result['capabilities'].get('cypher'))}")

    def _submit_answer(self, a: SubmitAnswerArgs) -> ToolResult:
        answer = self.build_answer(a)
        return ToolResult(
            result={"accepted": True, "answer": answer.model_dump(mode="json", exclude={"evidence"}), "note": "evidence ids are validated against the turn's evidence set inside an analyst turn"},
            summary=f"answer submitted: {len(answer.findings)} finding(s), {len(a.evidence_ids)} evidence id(s), confidence {answer.confidence:.2f}",
        )

    @staticmethod
    def build_answer(a: SubmitAnswerArgs, evidence: EvidenceSet | None = None, *, mode: str = "llm", model: str | None = None) -> AnalystAnswer:
        """Turn ``submit_answer`` arguments into an ``AnalystAnswer``; with an ``EvidenceSet`` unknown ids are dropped."""
        dropped_all: list[str] = []
        findings: list[Finding] = []
        for f in a.findings:
            ids = list(dict.fromkeys(f.evidence_ids))
            if evidence is not None:
                ids, dropped = evidence.validate_ids(ids)
                dropped_all += dropped
            findings.append(Finding(statement=f.statement, severity=f.severity, evidence_ids=ids))
        ev_ids = list(dict.fromkeys(a.evidence_ids))
        if evidence is not None:
            ev_ids, dropped = evidence.validate_ids(ev_ids)
            dropped_all += dropped
        narrative = a.narrative_md.strip()
        if dropped_all:
            uniq = list(dict.fromkeys(dropped_all))
            narrative += (
                "\n\n> Note: " + f"{len(uniq)} cited id(s) were not returned by any tool in this turn and were dropped from the evidence: "
                + ", ".join(f"`{i}`" for i in uniq[:10]) + (" ..." if len(uniq) > 10 else "")
            )
        frag = evidence.fragment if evidence is not None else GraphFragment()
        if ev_ids:
            frag = frag.model_copy(update={"focus": list(dict.fromkeys([*frag.focus, *[i for i in ev_ids if "|" not in i]]))[:50]})
        return AnalystAnswer(
            narrative_md=narrative, findings=findings, evidence=frag, confidence=a.confidence,
            followups=[s for s in a.followups if s][:5], mode=mode, model=model,  # type: ignore[arg-type]
        )


def _as_node(x: Any) -> NodeOut | None:
    if x is None:
        return None
    if isinstance(x, NodeOut):
        return x
    if isinstance(x, Mapping) and x.get("id"):
        try:
            return NodeOut.model_validate(x)
        except Exception:
            return record_to_node_out(x)
    return None
