"""Pydantic models shared by analytics, the API, the analyst agent and (mirrored in TypeScript) the web UI.

Rules: every graph-returning operation returns a ``GraphFragment``; every score is explainable through a
``RiskBreakdown``; every analyst answer carries evidence ids that exist in the graph.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]
Band = Literal["noise", "low", "medium", "high", "critical"]
LayoutHint = Literal["neighborhood", "path", "blast_radius", "storyline", "tree"]

SEVERITY_RANK: dict[str, int] = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def band_for_score(score: int) -> Band:
    if score >= 90:
        return "critical"
    if score >= 76:
        return "high"
    if score >= 51:
        return "medium"
    if score >= 26:
        return "low"
    return "noise"


# ----------------------------------------------------------------------------- graph fragments


class NodeOut(BaseModel):
    id: str
    label: str
    name: str
    category: str = "unknown"
    severity: str | None = None  # vendor severity for alerts, or derived severity for assets
    score: int | None = None  # contextual score for alerts/storylines
    highlight: bool = False
    tags: list[str] = Field(default_factory=list)  # e.g. crown_jewel, internet_exposed, storyline:<id>, ioc_match
    props: dict[str, Any] = Field(default_factory=dict)


class EdgeOut(BaseModel):
    id: str  # "src|TYPE|dst"
    type: str
    src: str
    dst: str
    derived: bool = False
    confidence: float = 1.0
    highlight: bool = False
    props: dict[str, Any] = Field(default_factory=dict)


class PathOut(BaseModel):
    node_ids: list[str]
    edge_ids: list[str]
    hops: int
    label: str | None = None
    likelihood: float | None = None
    stages: list[str] = Field(default_factory=list)


class GraphFragment(BaseModel):
    nodes: list[NodeOut] = Field(default_factory=list)
    edges: list[EdgeOut] = Field(default_factory=list)
    paths: list[PathOut] = Field(default_factory=list)
    focus: list[str] = Field(default_factory=list)
    layout_hint: LayoutHint = "neighborhood"
    truncated: bool = False
    total_nodes: int | None = None
    meta: dict[str, Any] = Field(default_factory=dict)

    def node_ids(self) -> list[str]:
        return [n.id for n in self.nodes]

    def merge(self, other: GraphFragment) -> GraphFragment:
        seen_n = {n.id for n in self.nodes}
        seen_e = {e.id for e in self.edges}
        nodes = self.nodes + [n for n in other.nodes if n.id not in seen_n]
        edges = self.edges + [e for e in other.edges if e.id not in seen_e]
        return GraphFragment(
            nodes=nodes, edges=edges, paths=self.paths + other.paths,
            focus=list(dict.fromkeys(self.focus + other.focus)), layout_hint=self.layout_hint,
            truncated=self.truncated or other.truncated, meta={**self.meta, **other.meta},
        )


# ----------------------------------------------------------------------------- risk


class RiskFactor(BaseModel):
    key: str  # severity | exposure | privilege | data | threat_intel | correlation
    label: str
    value: float  # normalized 0..1 input
    weight: float
    contribution: float  # points contributed to the 0..100 score
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class RiskBreakdown(BaseModel):
    subject_id: str
    vendor_severity: str | None = None
    vendor_severity_rank: int | None = None
    contextual_score: int
    band: Band
    raw_score: float
    factors: list[RiskFactor]
    rails: list[str] = Field(default_factory=list)  # e.g. "attack_path_floor:90", "no_context_ceiling:25"
    reasons: list[str] = Field(default_factory=list)  # short "why" chips: "reaches PCI", "active TI", "on attack path"
    delta_vs_vendor: int = 0  # contextual rank position minus vendor rank position (negative = moved up)


# ----------------------------------------------------------------------------- analytics results


class Insight(BaseModel):
    kind: str  # blast_radius | ti_match | credential_join | exposure | lateral | correlation | noise | ownership
    statement: str
    hops: int
    sources: list[str]  # data sources crossed, e.g. ["falcon", "wiz", "cloudtrail", "ti"]
    importance: float = 0.5
    evidence_node_ids: list[str] = Field(default_factory=list)
    evidence_edge_ids: list[str] = Field(default_factory=list)


class ReachedNode(BaseModel):
    node: NodeOut
    hops: int
    reach_score: float
    via_path: list[str]  # node ids from root to node
    access_level: str | None = None


class BlastRadiusResult(BaseModel):
    root_id: str
    depth: int
    reached_count: int
    crown_jewels: list[ReachedNode] = Field(default_factory=list)
    data_stores: list[ReachedNode] = Field(default_factory=list)
    secrets: list[ReachedNode] = Field(default_factory=list)
    identities: list[ReachedNode] = Field(default_factory=list)
    accounts_touched: list[str] = Field(default_factory=list)
    by_hop: dict[int, int] = Field(default_factory=dict)
    summary: str = ""
    fragment: GraphFragment


class StageOut(BaseModel):
    order: int
    stage: str  # kill-chain stage label
    technique_ids: list[str] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    time: str | None = None
    summary: str = ""


class AttackPathOut(BaseModel):
    id: str
    entry_id: str
    target_id: str
    through_id: str | None = None
    likelihood: float
    hops: int
    stages: list[StageOut]
    summary: str = ""
    fragment: GraphFragment


class StorylineOut(BaseModel):
    id: str
    title: str
    summary: str
    actor_id: str | None = None
    actor_name: str | None = None
    campaign_id: str | None = None
    campaign_name: str | None = None
    contextual_score: int
    stage_count: int
    alert_ids: list[str]
    crown_jewels_reached: list[str]
    first_event: str | None = None
    last_event: str | None = None
    stages: list[StageOut] = Field(default_factory=list)
    fragment: GraphFragment | None = None


class TIMatch(BaseModel):
    indicator_id: str
    ioc_type: str
    value: str
    confidence: float
    matched_node_id: str
    matched_label: str
    actor_id: str | None = None
    campaign_id: str | None = None
    malware_id: str | None = None
    report_id: str | None = None


class TIContext(BaseModel):
    matches: list[TIMatch] = Field(default_factory=list)
    actors: list[NodeOut] = Field(default_factory=list)
    campaigns: list[NodeOut] = Field(default_factory=list)
    malware: list[NodeOut] = Field(default_factory=list)
    exploited_vulnerabilities: list[NodeOut] = Field(default_factory=list)
    reports: list[NodeOut] = Field(default_factory=list)
    ttp_overlap: dict[str, float] = Field(default_factory=dict)  # actor/campaign id -> overlap ratio
    sector_relevance: float | None = None
    summary: str = ""


class AlertSummary(BaseModel):
    id: str
    title: str
    source_system: str
    alert_type: str
    vendor_severity: str
    vendor_severity_rank: int
    contextual_score: int
    contextual_band: Band
    detected_at: str | None = None
    status: str = "new"
    entity_id: str | None = None
    entity_name: str | None = None
    entity_label: str | None = None
    hostname: str | None = None
    user: str | None = None
    techniques: list[str] = Field(default_factory=list)
    storyline_id: str | None = None
    graph_reasons: list[str] = Field(default_factory=list)
    reaches_crown_jewel: bool = False
    on_attack_path: bool = False
    ioc_match_count: int = 0
    ti_actor_ids: list[str] = Field(default_factory=list)
    vendor_rank_position: int | None = None  # 1-based position in the vendor-severity ordering
    contextual_rank_position: int | None = None  # 1-based position in the contextual ordering


class AlertContext(BaseModel):
    alert: AlertSummary
    flat_view: dict[str, Any]  # exactly what the source console shows
    risk: RiskBreakdown
    insights: list[Insight]
    blast_radius: BlastRadiusResult | None = None
    attack_paths: list[AttackPathOut] = Field(default_factory=list)
    storyline: StorylineOut | None = None
    threat_intel: TIContext | None = None
    related_alerts: list[AlertSummary] = Field(default_factory=list)
    evidence: GraphFragment


class BreakItem(BaseModel):
    node_id: str
    name: str
    label: str
    impact: str
    owner_team_id: str | None = None


class ContainmentSimulation(BaseModel):
    target_ids: list[str]
    actions: list[str]
    paths_cut: int
    storylines_contained: list[str]
    crown_jewels_protected: list[str]
    breaks: list[BreakItem]
    residual_risks: list[str]
    recommendations: list[str]
    fragment: GraphFragment


class SearchHit(BaseModel):
    id: str
    label: str
    name: str
    category: str
    snippet: str | None = None
    score: float = 1.0


class StatsOut(BaseModel):
    node_counts: dict[str, int]
    edge_counts: dict[str, int]
    total_nodes: int
    total_edges: int
    backend: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    build: dict[str, Any] = Field(default_factory=dict)


# ----------------------------------------------------------------------------- analyst agent


class Finding(BaseModel):
    statement: str
    severity: Severity | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class ToolCallRecord(BaseModel):
    name: str
    arguments: dict[str, Any]
    summary: str
    duration_ms: int = 0
    error: str | None = None


class AnalystAnswer(BaseModel):
    narrative_md: str
    findings: list[Finding] = Field(default_factory=list)
    evidence: GraphFragment = Field(default_factory=GraphFragment)
    confidence: float = 0.5
    followups: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    mode: Literal["llm", "offline"] = "offline"
    intent: str | None = None
    model: str | None = None


class ChatMessageIn(BaseModel):
    content: str
    context: dict[str, Any] | None = None  # {"alert_id": ..., "selected_node_ids": [...], "storyline_id": ...}
    mode: Literal["auto", "llm", "offline"] | None = None


class ChatEvent(BaseModel):
    """One server-sent event in a streaming chat turn."""

    type: Literal["session", "text_delta", "thinking", "tool_call", "tool_result", "evidence", "answer", "error", "done"]
    data: dict[str, Any] = Field(default_factory=dict)


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str
    answer: AnalystAnswer | None = None
    created_at: str | None = None


class ChatSession(BaseModel):
    id: str
    created_at: str
    turns: list[ChatTurn] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
