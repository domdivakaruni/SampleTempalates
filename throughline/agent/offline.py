"""OfflineAnalyst: deterministic intent -> playbook -> templated ``AnalystAnswer`` (no LLM required).

The offline analyst is a first-class product path (docs/02 section 11.7): it must answer all twelve demo
questions (docs/04 section 6) with cited evidence, using the *same* ``ToolRegistry`` as the LLM analyst so the UI
cannot tell the two modes apart.

Pipeline for one question:

1. ``classify``: weighted regex rules over the question -> intent (falls back to ``help``).
2. entity linking: explicit node ids, hostnames (BAS-01, WKS-3391, stmt-render-2a), alert ids (ldt-a009), role
   names, bucket names, actor/report names, CVEs, IPs, hashes, domains and quoted strings are resolved through
   ``search_entities``; ``context.alert_id`` / ``selected_node_ids`` are used for "this alert" / "this host".
3. playbook: an ordered sequence of tool calls with argument templates; every fragment is merged into the
   answer's evidence and every id cited in a finding is validated against that evidence set.
4. narrative: markdown with ``## Findings``, ``## Evidence``, ``## Impact``, ``## Recommended actions`` citing
   node ids in backticks, plus findings, confidence, follow-up questions and the tool-call records.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from throughline.agent.prompts import DEMO_QUESTIONS, PLAYBOOK_HINTS
from throughline.agent.tools import EvidenceSet, ToolRegistry, ToolResult, edge_out_from_id
from throughline.models import AnalystAnswer, ChatEvent, ChatTurn, Finding, ToolCallRecord
from throughline.schema import label_for_id

log = logging.getLogger(__name__)

EventSink = Callable[[ChatEvent], None]

# ----------------------------------------------------------------------------- intents

INTENTS: tuple[str, ...] = (
    "blast_radius_of_alert",
    "medium_alerts_with_data_path",
    "cloud_activity_related_to_endpoint",
    "identity_footprint",
    "exposed_exploited_hosts",
    "rank_alerts_explain_top",
    "attack_path_from_alert",
    "credential_joins",
    "ioc_ttp_matches_for_actor_or_report",
    "alerts_reaching_crown_jewels",
    "is_alert_actually_risky",
    "containment_simulation",
    "alerts_on_entity",
    "what_is_entity",
    "neighborhood_of_entity",
    "why_is_alert_risky",
    "summarize_storyline",
    "list_storylines",
    "help",
)

# (intent, [(regex, weight), ...]); scores are summed, the highest intent wins, < 2 -> help
_RULES: list[tuple[str, list[tuple[str, float]]]] = [
    ("containment_simulation", [
        (r"\bisolat", 3), (r"\brotat(e|ing|ion)\b", 2), (r"\bcontain(ed|ment|s)?\b", 2), (r"what (would |will |do we |does )?break", 3),
        (r"\bquarantin", 3), (r"\brevoke\b", 2), (r"\bblock (the |this )?ip\b", 2), (r"\bdisable (the |this )?(user|account)\b", 2),
        (r"\bwhat if we\b", 1), (r"\btighten\b", 1),
    ]),
    ("credential_joins", [
        (r"\bcredentials?\b", 2), (r"\bstolen\b|\bstealing\b|\btheft\b|\bbeing stolen\b", 3), (r"\bcloud api\b", 1.5),
        (r"\bused in cloud\b", 2), (r"\baccess keys?\b", 1), (r"\bimds\b", 1), (r"\bkeys? .* (used|seen)\b", 1),
    ]),
    ("cloud_activity_related_to_endpoint", [
        (r"\bcloud api\b", 3), (r"\bapi (activity|calls?)\b", 2), (r"\bactivity\b", 1), (r"\brelated to\b", 1),
        (r"\bendpoint detection", 2), (r"\bcloudtrail\b", 2), (r"\bfrom the \w+ role\b", 1),
    ]),
    ("blast_radius_of_alert", [
        (r"\bblast radius\b", 4), (r"what can an attacker reach", 4), (r"\breach from (here|this|it)\b", 3),
        (r"everything connected to", 3), (r"\balert\b|\bdetection\b", 1), (r"\battacker\b", 1),
    ]),
    ("identity_footprint", [
        (r"\bblast radius\b", 2), (r"\bidentity\b", 2), (r"\bcompromised\b", 2), (r"\b\w+Role\b", 2), (r"\brole\b", 1),
        (r"\bfootprint\b", 4), (r"\bwhat can (this|the) (identity|role|user) (access|reach)\b", 4), (r"\bservice account\b", 1),
    ]),
    ("exposed_exploited_hosts", [
        (r"internet[- ]exposed|internet[- ]facing|public[- ]facing|exposed hosts", 4), (r"\bexploit", 3), (r"\bvuln", 1),
        (r"\bactively\b", 1), (r"\bthreat actor\b|\bactor\b", 1), (r"\bcve\b", 1), (r"\bfintech", 1),
    ]),
    ("rank_alerts_explain_top", [
        (r"\brank", 4), (r"\btop (\d+|three|five|ten)\b", 3), (r"\bcontextual\b", 2), (r"\bprioriti[sz]", 3),
        (r"\bexplain the top\b", 2), (r"\bnot vendor severity\b", 2), (r"\bleaderboard\b", 3), (r"\bmost (risky|critical|important) alerts\b", 3),
    ]),
    ("attack_path_from_alert", [
        (r"\battack path", 4), (r"\btrace\b", 3), (r"\bpath from\b", 2), (r"\bkill chain\b", 2), (r"\bfull path\b", 2), (r"\bhow (did|could) .* (reach|get to)\b", 2),
    ]),
    ("ioc_ttp_matches_for_actor_or_report", [
        (r"\biocs?\b", 4), (r"\bttps?\b", 3), (r"\bindicators?\b", 3), (r"\bmatch", 2), (r"\breport\b", 2), (r"\bactor\b", 1),
        (r"\bcampaign\b", 1), (r"\bwhat do they touch\b", 2), (r"\bthreat intel", 2),
    ]),
    ("alerts_reaching_crown_jewels", [
        (r"\balerts?\b.*\b(reach|access)\b.*\b(cardholder|crown|regulated|sensitive|pci|pii|phi|data)\b", 4), (r"hide everything else", 3),
        (r"\bonly (the )?alerts\b", 2), (r"\bcrown[- ]jewels?\b", 2), (r"\bcardholder data\b", 1),
    ]),
    ("medium_alerts_with_data_path", [
        (r"\b(medium|low|high|critical|informational)[- ]severity\b", 3), (r"\bpath to (regulated|sensitive|pci|pii|customer|cardholder) data\b", 3),
        (r"\bendpoint alerts?\b", 2), (r"\bsit on assets\b", 2), (r"\bregulated data\b", 1),
    ]),
    ("is_alert_actually_risky", [
        (r"\bactually (risky|dangerous|a problem|matter|bad|real)\b", 5), (r"\bfalse positive\b|\bnoise\b|\bbenign\b", 4), (r"\bis (this|that|the|it)\b.*\b(real|legit|legitimate|a concern|worth)\b", 3),
        (r"\bis (this|that|the|it) .*\brisky\b", 3), (r"\bshould (i|we) (care|worry|escalate)\b", 3), (r"what'?s in it", 2),
        (r"\bfinding\b", 1), (r"\bcan an actor reach it\b", 2),
    ]),
    ("why_is_alert_risky", [
        (r"\bwhy (is|does|did|was)\b.*\b(risk|score|rank|critical|high|flagged|prioriti)", 4), (r"\bexplain (the |its |this )?(score|risk|ranking|breakdown)\b", 3),
        (r"\bscore breakdown\b", 3), (r"\bfactor", 1), (r"\bwhy .* (flagged|prioriti|ranked)", 2),
    ]),
    ("summarize_storyline", [
        (r"\bsummari[sz]e\b", 3), (r"\bstoryline\b", 2), (r"\bincident\b", 1), (r"\bwhat happened\b", 3), (r"\btimeline\b", 2), (r"\bstages\b", 1),
    ]),
    ("list_storylines", [
        (r"\b(list|which|what|show|any)\b.*\b(storylines|incidents|intrusions|campaigns are)\b", 3), (r"\bactive (incidents|storylines|intrusions)\b", 3),
        (r"\bhow many (storylines|incidents)\b", 3),
    ]),
    ("alerts_on_entity", [
        (r"\balerts?\b.*\b(on|against|affecting|hitting|involving)\b", 3), (r"\b(which|what|any|list|show|how many)\b.*\b(alerts?|detections?|findings?)\b", 2),
        (r"\b(detections?|findings?)\b.*\b(on|against)\b", 2), (r"\bsit(s|ting)? on\b", 1), (r"\balerts? (are )?(there )?on\b", 2),
    ]),
    ("neighborhood_of_entity", [
        (r"\bneighbou?rhood\b", 4), (r"\b(what is|what'?s|show( me)?( what is)?) connected to\b", 3), (r"\bexpand\b", 2), (r"\bconnections? (of|to|from)\b", 2),
        (r"\b(graph|nodes|edges) around\b", 3), (r"\bconnected to\b", 1),
    ]),
    ("what_is_entity", [
        (r"^\s*(what|who) is\b", 3), (r"\btell me about\b", 3), (r"\bdescribe\b", 2), (r"\bdetails? (of|about|on)\b", 2), (r"\bwhat do (we|you) know about\b", 3),
    ]),
    ("help", [(r"\bhelp\b", 3), (r"what can you (do|answer)", 4), (r"^\s*(hi|hello|hey)\b", 2)]),
]
_COMPILED: list[tuple[str, list[tuple[re.Pattern[str], float]]]] = [(intent, [(re.compile(p, re.I), w) for p, w in rules]) for intent, rules in _RULES]

# ----------------------------------------------------------------------------- entity linking regexes

_ID_RE = re.compile(
    r"\b(?:alert|vm|endpoint|role|bucket|secret|database|user|identity|credential|cloudevent|storyline|actor|campaign|malware|report|ioc|cve|technique|app|team|account|incident|policy|ip|domain|process|file|image|package|workload|k8s|function|sg|lb|vpc|subnet|group|iamuser|accesskey|logon|internet):[A-Za-z0-9][^\s`'\",;)?]*"
)
_HOST_RE = re.compile(r"\b([A-Za-z]{2,5}-\d{2,5}|[a-z][a-z0-9]*(?:-[a-z0-9]+){1,4})\b")
_ALERT_REF_RE = re.compile(r"\b((?:ldt|ca|iss|waf|ids|idp|inc)-[a-z]?\d{3,4}x?)\b", re.I)
_ROLE_NAME_RE = re.compile(r"\b([A-Z][A-Za-z0-9]{3,}Role)\b")
_ROLE_PHRASE_RE = re.compile(r"\b(?:the |that |this )?([a-z0-9-]+(?: [a-z0-9-]+)?) role\b", re.I)
_BUCKET_RE = re.compile(r"\b(larkspur-[a-z0-9-]+)\b", re.I)
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I)
_HASH_RE = re.compile(r"\b([a-f0-9]{64})\b", re.I)
_IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:net|com|org|io|example|internal|xyz|info))\b", re.I)
_TECH_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
_REPORT_RE = re.compile(r"\b(TL-\d{4}-\d{4})\b", re.I)
_CAPS_BIGRAM_RE = re.compile(r"\b([A-Z][a-z]{2,} [A-Z][a-z]{2,})\b")
_UPPER_WORD_RE = re.compile(r"\b([A-Z]{5,})\b")
_QUOTED_RE = re.compile(r"['\"“‘]([^'\"”’]{3,80})['\"”’]")
_USER_RE = re.compile(r"\b(?:user|login|account|employee) ([a-z][a-z0-9._-]{2,})\b", re.I)
_SEVERITY_RE = re.compile(r"\b(informational|low|medium|high|critical)\b", re.I)
_STOP_BIGRAMS = {"Show Me", "Trace The", "Which Of", "Larkspur Financial", "Is The", "What Is", "Rank All", "If We", "Do Any"}
_DATA_HINTS: dict[str, str] = {"cardholder": "PCI", "pci": "PCI", "card data": "PCI", "kyc": "PII", "pii": "PII", "customer data": "PII", "secrets": "SECRETS", "phi": "PHI", "financial data": "FINANCIAL"}
_ACTION_RULES: list[tuple[str, str]] = [
    (r"\bisolat|\bquarantin|\bnetwork contain", "isolate_endpoint"),
    (r"\brotat", "rotate_role_credentials"),
    (r"\btighten|\btrust polic", "tighten_trust_policy"),
    (r"\bblock", "block_ip"),
    (r"\bdisable (the |this )?(user|account)|\bsuspend", "disable_user"),
    (r"\brevoke|\bsessions?\b", "revoke_sessions"),
]
_THIS_RE = re.compile(r"\b(this|that|the selected|current|here|it)\b", re.I)
_STOPWORDS = {
    "a", "an", "and", "any", "are", "about", "actually", "alert", "alerts", "all", "as", "at", "be", "by", "can", "critical",
    "describe", "details", "detection", "do", "does", "finding", "for", "from", "give", "has", "have", "how", "i", "in",
    "into", "is", "it", "its", "know", "like", "me", "of", "on", "or", "our", "risky", "show", "tell", "that", "the",
    "there", "these", "this", "those", "to", "us", "was", "we", "what", "what's", "whats", "which", "who", "why", "with",
    "you", "your", "high", "medium", "low", "informational", "severity", "please", "now", "today", "really", "still",
}


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", str(text).lower()) if t]


def _notable_words(text: str) -> list[str]:
    """Words worth searching for: not stopwords, at least three characters (or containing a digit)."""
    out: list[str] = []
    for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", text):
        lw = w.lower().strip(".:/-")
        if not lw or lw in _STOPWORDS or (len(lw) < 3 and not any(ch.isdigit() for ch in lw)):
            continue
        if lw not in out:
            out.append(lw)
    return out


def _hit_overlap(hit: Mapping[str, Any], words: Iterable[str]) -> int:
    """How many query tokens occur verbatim (or as a >= 4 char prefix) in a search hit's name / snippet / id tail."""
    hay = set(_tokens(str(hit.get("name", "")))) | set(_tokens(str(hit.get("snippet") or ""))) | set(_tokens(str(hit.get("id", "")).split(":")[-1]))
    qtoks = {t for w in words for t in _tokens(w) if t not in _STOPWORDS}
    return sum(1 for t in qtoks if t in hay or (len(t) >= 4 and any(h.startswith(t) for h in hay)) or (len(t) >= 5 and any(t in h for h in hay)))

IDENTITY_LABELS = {"IamRole", "IamUser", "HumanUser", "ServiceAccount", "Group"}
_LINKABLE_LABELS = ["Endpoint", "VirtualMachine", "Workload", "IamRole", "IamUser", "HumanUser", "ServiceAccount", "StorageBucket", "Database", "Secret", "Application"]
_LABEL_HINTS: dict[str, tuple[str, ...]] = {
    "bucket": ("StorageBucket",), "database": ("Database",), "db": ("Database",), "secret": ("Secret",), "role": ("IamRole",),
    "user": ("HumanUser", "IamUser"), "account": ("ServiceAccount", "IamUser", "HumanUser"), "host": ("VirtualMachine", "Endpoint"),
    "vm": ("VirtualMachine",), "instance": ("VirtualMachine",), "server": ("VirtualMachine", "Endpoint"), "workstation": ("Endpoint",),
    "laptop": ("Endpoint",), "endpoint": ("Endpoint",), "app": ("Application",), "application": ("Application",),
}
ENTITY_INTENTS = {"alerts_on_entity", "what_is_entity", "neighborhood_of_entity", "blast_radius_of_alert", "identity_footprint", "containment_simulation", "attack_path_from_alert"}
_QUESTION_VOCAB = {
    "attacker", "reach", "reached", "reaches", "blast", "radius", "footprint", "host", "hosts", "identity", "identities", "role",
    "roles", "user", "users", "bucket", "buckets", "storyline", "storylines", "incident", "incidents", "many", "sit", "sits",
    "connected", "everything", "neighborhood", "neighbourhood", "path", "paths", "attack", "risk", "data", "regulated",
    "sensitive", "crown", "jewel", "jewels", "cloud", "api", "activity", "endpoint", "endpoints", "related", "hours", "last",
    "open", "rank", "vendor", "contextual", "explain", "top", "trace", "full", "credential", "credentials", "stolen", "calls",
    "seen", "current", "match", "matches", "iocs", "ttps", "report", "touch", "only", "assets", "asset", "hide", "else",
    "public", "actor", "actors", "isolate", "rotate", "contain", "breaks", "break", "internet", "exposed", "vuln",
    "vulnerability", "exploiting", "fintechs", "fintech", "right", "compromised", "fully", "around", "expand", "connections",
    "nodes", "edges", "graph", "server", "machine", "instance", "workstation", "laptop", "resource", "entity", "node",
}
HOST_LABELS = {"Endpoint", "VirtualMachine", "Workload", "ServerlessFunction", "KubernetesCluster"}
DATA_LABELS = {"StorageBucket", "Database", "Secret"}
TI_LABELS = {"ThreatActor", "Campaign", "IntelReport", "Malware", "Indicator"}
_ALERT_WORDS = re.compile(r"\balert|\bdetection|\bisolat|\bsensor|\bedr\b|\bendpoint\b", re.I)

# ----------------------------------------------------------------------------- data classes


@dataclass
class Slots:
    explicit_ids: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    vms: list[str] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)
    data_stores: list[str] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    reports: list[str] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)
    storylines: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    ioc_values: list[str] = field(default_factory=list)
    quoted: list[str] = field(default_factory=list)
    host_tokens: list[str] = field(default_factory=list)
    classification: str | None = None
    severity: str | None = None
    actions: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)  # id -> label

    def hosts(self) -> list[str]:
        return list(dict.fromkeys(self.endpoints + self.vms))

    def primary(self) -> str | None:
        for group in (self.alerts, self.endpoints, self.vms, self.identities, self.data_stores, self.actors, self.campaigns, self.reports, self.storylines, self.explicit_ids):
            if group:
                return group[0]
        return None

    def add(self, node_id: str, label: str | None = None) -> None:
        label = label or label_for_id(node_id) or "Unknown"
        self.labels[node_id] = label
        target = {
            "Alert": self.alerts, "Endpoint": self.endpoints, "VirtualMachine": self.vms, "Workload": self.vms,
            "ServerlessFunction": self.vms, "KubernetesCluster": self.vms, "IamRole": self.identities, "IamUser": self.identities,
            "HumanUser": self.identities, "ServiceAccount": self.identities, "Group": self.identities, "StorageBucket": self.data_stores,
            "Database": self.data_stores, "Secret": self.data_stores, "ThreatActor": self.actors, "Campaign": self.campaigns,
            "IntelReport": self.reports, "Malware": self.malware, "Storyline": self.storylines, "Vulnerability": self.cves,
            "AttackTechnique": self.techniques,
        }.get(label)
        if target is not None and node_id not in target:
            target.append(node_id)
        if node_id not in self.explicit_ids:
            self.explicit_ids.append(node_id)


@dataclass
class Draft:
    summary: str
    findings: list[Finding] = field(default_factory=list)
    evidence_lines: list[str] = field(default_factory=list)
    impact_lines: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    followups: list[str] = field(default_factory=list)
    confidence: float = 0.7
    focus: list[str] = field(default_factory=list)
    intent: str | None = None  # set by playbooks that degrade to another intent (e.g. ``help``)


# ----------------------------------------------------------------------------- formatting helpers


def _b(x: Any) -> str:
    return f"`{x}`"


def _g(d: Mapping[str, Any] | None, *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, Mapping):
            return default
        cur = cur.get(k)
    return default if cur is None else cur


def _node_ref(n: Mapping[str, Any] | None) -> str:
    if not n:
        return "(unknown node)"
    label, name = n.get("label", ""), n.get("name", "")
    extra = []
    props = n.get("props") or {}
    if props.get("data_classifications"):
        extra.append("/".join(str(c) for c in props["data_classifications"]))
    if props.get("sensitivity"):
        extra.append(f"sensitivity {props['sensitivity']}")
    if "crown_jewel" in (n.get("tags") or []):
        extra.append("crown jewel")
    tail = f"; {', '.join(extra)}" if extra else ""
    return f"{_b(n.get('id'))} - {name} ({label}{tail})"


def _alert_ref(a: Mapping[str, Any] | None) -> str:
    if not a:
        return "(unknown alert)"
    host = f" on {a['hostname']}" if a.get("hostname") else ""
    return f"{_b(a.get('id'))} - {a.get('title', '')}{host} (vendor {a.get('vendor_severity')} -> contextual {a.get('contextual_score')} {a.get('contextual_band')})"


def _reached_lines(items: Iterable[Mapping[str, Any]], limit: int = 8) -> list[str]:
    out = []
    for r in list(items)[:limit]:
        n = r.get("node") or {}
        via = f", {r.get('hops')} hop(s)" if r.get("hops") is not None else ""
        acc = f", access {r['access_level']}" if r.get("access_level") else ""
        out.append(f"- {_node_ref(n)}{via}{acc}")
    return out


def _ids_of_reached(items: Iterable[Mapping[str, Any]]) -> list[str]:
    return [str(_g(r, "node", "id")) for r in items if _g(r, "node", "id")]


def _fmt_time(ts: Any) -> str:
    return str(ts).replace("T", " ").replace("Z", " UTC") if ts else "unknown time"


def _compose(draft: Draft) -> str:
    lines = [draft.summary.strip(), "", "## Findings"]
    lines += [f"- {f.statement}" for f in draft.findings] or ["- No findings could be established from the graph."]
    lines += ["", "## Evidence"]
    lines += draft.evidence_lines or ["- No evidence returned by the tools."]
    lines += ["", "## Impact"]
    lines += draft.impact_lines or ["- No impact assessment available."]
    lines += ["", "## Recommended actions"]
    lines += [f"{i}. {a}" for i, a in enumerate(draft.actions, start=1)] or ["1. Investigate further with the follow-up questions below."]
    return "\n".join(lines).strip() + "\n"


def _chunks(text: str, size: int = 400) -> list[str]:
    parts: list[str] = []
    for para in text.split("\n\n"):
        if not para:
            continue
        while len(para) > size:
            parts.append(para[:size])
            para = para[size:]
        parts.append(para + "\n\n")
    return parts


# ----------------------------------------------------------------------------- run state


class _Run:
    """One offline turn: executes tools, records calls, merges evidence, emits events."""

    def __init__(self, registry: ToolRegistry, emit: EventSink, max_tool_calls: int) -> None:
        self.registry = registry
        self.emit = emit
        self.max_tool_calls = max_tool_calls
        self.evidence = EvidenceSet()
        self.tool_calls: list[ToolCallRecord] = []
        self._n = 0

    def call(self, name: str, **arguments: Any) -> ToolResult | None:
        if self._n >= self.max_tool_calls:
            log.info("offline analyst: tool budget reached, skipping %s", name)
            return None
        self._n += 1
        call_id = f"offline-{self._n}"
        arguments = {k: v for k, v in arguments.items() if v is not None}
        self.emit(ChatEvent(type="tool_call", data={"id": call_id, "name": name, "arguments": arguments}))
        try:
            res, ms = self.registry.timed_run(name, arguments)
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            log.info("offline analyst: %s(%s) failed: %s", name, arguments, msg)
            self.tool_calls.append(ToolCallRecord(name=name, arguments=arguments, summary=msg, error=msg))
            self.emit(ChatEvent(type="tool_result", data={"id": call_id, "name": name, "summary": msg, "duration_ms": 0, "error": msg}))
            return None
        frag = self.evidence.add(res)
        if frag is not None:
            self.emit(ChatEvent(type="evidence", data=frag.model_dump(mode="json")))
        self.tool_calls.append(ToolCallRecord(name=name, arguments=arguments, summary=res.summary, duration_ms=ms))
        self.emit(ChatEvent(type="tool_result", data={"id": call_id, "name": name, "summary": res.summary, "duration_ms": ms}))
        return res

    def result(self, name: str, **arguments: Any) -> dict[str, Any]:
        res = self.call(name, **arguments)
        return dict(res.result) if res is not None and isinstance(res.result, Mapping) else {}

    # entity linking helpers -------------------------------------------------

    def search(self, query: str, labels: Sequence[str] | None = None, *, prefer: Sequence[str] = ()) -> dict[str, Any] | None:
        data = self.result("search_entities", query=query, labels=list(labels) if labels else None, limit=8)
        hits = [h for h in data.get("hits") or [] if isinstance(h, Mapping)]
        if not hits:
            return None
        q = query.lower()

        def rank(h: Mapping[str, Any]) -> tuple[int, int, float]:
            name = str(h.get("name", "")).lower()
            snippet = str(h.get("snippet") or "").lower()
            exact = 0 if name == q or h.get("id", "").lower().endswith(":" + q) else 1
            starts = 0 if name.startswith(q) or snippet.startswith(q) else 1
            pref = prefer.index(h["label"]) if h.get("label") in prefer else len(prefer)
            return (exact, pref if exact == 0 else pref + starts, -float(h.get("score", 0)))

        hits.sort(key=rank)
        return dict(hits[0])

    def search_all(self, query: str, labels: Sequence[str] | None = None, limit: int = 8) -> list[dict[str, Any]]:
        data = self.result("search_entities", query=query, labels=list(labels) if labels else None, limit=limit)
        return [dict(h) for h in data.get("hits") or [] if isinstance(h, Mapping)]

    def alert_by_text(self, phrase: str, *, min_overlap: int = 1) -> dict[str, Any] | None:
        """Find the alert a free-text phrase refers to ("S3 bucket public", "EICAR test file", "impossible travel").

        ``list_alerts(q=...)`` is a substring filter, so it is tried first with the phrase and then the token search
        (``search_entities`` over Alert nodes) whose best hit must share at least ``min_overlap`` notable words with
        the phrase - guarding against a random alert winning on a single common token.
        """
        phrase = phrase.strip()
        if not phrase:
            return None
        words = _notable_words(phrase)
        data = self.result("list_alerts", q=phrase, sort="time", limit=25)
        items = [a for a in data.get("items") or [] if isinstance(a, Mapping)]
        if items:
            return self._latest_of(items)
        hits = self.search_all(" ".join(words) or phrase, ["Alert"], limit=8)
        if not hits:
            return None
        qtoks = {t for w in words for t in _tokens(w) if t not in _STOPWORDS}
        need = max(min_overlap, min(2, len(qtoks))) if qtoks else 1
        scored = sorted(((_hit_overlap(h, words), float(h.get("score") or 0), h) for h in hits), key=lambda t: (-t[0], -t[1]))
        overlap, _score, best = scored[0]
        if overlap < need:
            return None
        # the same finding usually exists on several assets ("S3 bucket allows public read" x5): "the finding" is the
        # most recent one; the others are reported as siblings so the analyst can pivot
        title = str(best.get("name") or "")
        if title:
            data = self.result("list_alerts", q=title, sort="time", limit=25)
            same = [a for a in data.get("items") or [] if isinstance(a, Mapping) and str(a.get("title") or "").lower() == title.lower()]
            if same:
                return self._latest_of(same)
        return {"id": best["id"], "title": best.get("name"), "label": best.get("label"), "siblings": []}

    @staticmethod
    def _latest_of(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        ordered = sorted(items, key=lambda a: (str(a.get("detected_at") or ""), int(a.get("contextual_score") or 0)), reverse=True)
        top = dict(ordered[0])
        top["siblings"] = [dict(a) for a in ordered[1:]]
        return top


# ----------------------------------------------------------------------------- the analyst


class OfflineAnalyst:
    def __init__(self, registry: ToolRegistry, *, max_tool_calls: int = 14) -> None:
        self.registry = registry
        self.max_tool_calls = max_tool_calls
        self._playbooks: dict[str, Callable[[_Run, str, Slots, Mapping[str, Any]], Draft]] = {
            "blast_radius_of_alert": self._pb_blast_radius,
            "medium_alerts_with_data_path": self._pb_medium_alerts,
            "cloud_activity_related_to_endpoint": self._pb_cloud_activity,
            "identity_footprint": self._pb_identity_footprint,
            "exposed_exploited_hosts": self._pb_exposed_hosts,
            "rank_alerts_explain_top": self._pb_rank_alerts,
            "attack_path_from_alert": self._pb_attack_path,
            "credential_joins": self._pb_credential_joins,
            "ioc_ttp_matches_for_actor_or_report": self._pb_ioc_ttp,
            "alerts_reaching_crown_jewels": self._pb_alerts_reaching_crown_jewels,
            "is_alert_actually_risky": self._pb_is_alert_risky,
            "containment_simulation": self._pb_containment,
            "alerts_on_entity": self._pb_alerts_on_entity,
            "what_is_entity": self._pb_what_is,
            "neighborhood_of_entity": self._pb_neighborhood,
            "why_is_alert_risky": self._pb_why_risky,
            "summarize_storyline": self._pb_summarize_storyline,
            "list_storylines": self._pb_list_storylines,
            "help": self._pb_help,
        }

    # -------------------------------------------------------------- classification

    def classify(self, question: str, context: Mapping[str, Any] | None = None) -> tuple[str, dict[str, float]]:
        scores: dict[str, float] = {}
        for intent, rules in _COMPILED:
            s = sum(w for rx, w in rules if rx.search(question))
            if s:
                scores[intent] = s
        if not scores:
            return "help", scores
        best = max(scores.items(), key=lambda kv: (kv[1], -INTENTS.index(kv[0])))
        if best[1] < 2:
            return "help", scores
        return best[0], scores

    def _refine_intent(self, intent: str, slots: Slots, question: str, context: Mapping[str, Any]) -> str:
        primary = slots.primary()
        label = slots.labels.get(primary or "", "")
        if intent in ("blast_radius_of_alert", "identity_footprint"):
            if slots.identities and not slots.alerts and not slots.hosts():
                return "identity_footprint"
            if slots.alerts or slots.hosts():
                return "blast_radius_of_alert"
            if label in IDENTITY_LABELS:
                return "identity_footprint"
        if intent == "what_is_entity":
            if label == "Alert" and re.search(r"\brisk", question, re.I):
                return "why_is_alert_risky"
            if label == "Storyline":
                return "summarize_storyline"
        if intent == "alerts_on_entity":
            if label in TI_LABELS or (not primary and _CAPS_BIGRAM_RE.search(question)):
                return "ioc_ttp_matches_for_actor_or_report"
            if label == "Storyline":
                return "summarize_storyline"
            if label == "Alert" and not slots.hosts():
                return "why_is_alert_risky"
        if intent == "summarize_storyline" and not slots.storylines and not context.get("storyline_id"):
            if slots.alerts:
                return "why_is_alert_risky"
            if re.search(r"\b(storylines|incidents)\b", question, re.I):
                return "list_storylines"
        return intent

    # -------------------------------------------------------------- entity linking

    def _link(self, run: _Run, question: str, intent: str, context: Mapping[str, Any]) -> Slots:
        slots = Slots()
        q = question
        alert_oriented = bool(_ALERT_WORDS.search(q)) or intent in ("blast_radius_of_alert", "attack_path_from_alert", "containment_simulation", "is_alert_actually_risky", "why_is_alert_risky")

        for m in _ID_RE.findall(q):
            node_id = m.rstrip(".,:;!?`'\")")
            slots.add(node_id)
        for m in _CVE_RE.findall(q):
            slots.add(f"cve:{m.upper()}", "Vulnerability")
        for m in _TECH_RE.findall(q):
            slots.add(f"technique:attack:{m}", "AttackTechnique")
        slots.ioc_values += _HASH_RE.findall(q) + _IP_RE.findall(q) + [d for d in _DOMAIN_RE.findall(q) if not d.lower().endswith(".internal")]
        slots.quoted = [s.strip() for s in _QUOTED_RE.findall(q)]
        sev = _SEVERITY_RE.search(q)
        if sev and intent not in ("is_alert_actually_risky",):
            slots.severity = sev.group(1).lower()
        for hint, cls in _DATA_HINTS.items():
            if hint in q.lower():
                slots.classification = cls
                break
        for rx, action in _ACTION_RULES:
            if re.search(rx, q, re.I) and action not in slots.actions:
                slots.actions.append(action)

        # hosts (BAS-01, WKS-3391, stmt-render-2a ...)
        for tok in _HOST_RE.findall(q):
            if not re.search(r"\d", tok) or _ALERT_REF_RE.fullmatch(tok) or _CVE_RE.fullmatch(tok) or _REPORT_RE.fullmatch(tok) or _TECH_RE.fullmatch(tok):
                continue
            if tok.lower() in {t.lower() for t in slots.host_tokens}:
                continue
            slots.host_tokens.append(tok)
        for tok in slots.host_tokens[:3]:
            prefer = ("Endpoint", "VirtualMachine") if alert_oriented else ("VirtualMachine", "Endpoint")
            hits = run.search_all(tok, ["Endpoint", "VirtualMachine", "Workload"])
            exact = [h for h in hits if str(h.get("name", "")).lower() == tok.lower() or str(h.get("snippet") or "").lower().startswith(tok.lower())] or hits
            exact.sort(key=lambda h: prefer.index(h["label"]) if h.get("label") in prefer else 9)
            for h in exact[:2]:
                slots.add(h["id"], h["label"])

        # alert references like ldt-a009
        for ref in _ALERT_REF_RE.findall(q):
            hit = run.search(ref, ["Alert", "Incident"])
            if hit:
                slots.add(hit["id"], hit["label"])

        # roles
        role_queries: list[str] = list(dict.fromkeys(_ROLE_NAME_RE.findall(q)))
        for phrase in _ROLE_PHRASE_RE.findall(q):
            words = [w for w in phrase.lower().split() if w not in {"the", "a", "an", "this", "that", "instance", "iam", "its", "compromised", "and", "rotate", "if", "we"}]
            if words:
                role_queries.append(words[-1])
        for rq in role_queries[:3]:
            hit = run.search(rq, ["IamRole", "IamUser", "ServiceAccount"])
            if hit:
                slots.add(hit["id"], hit["label"])

        # users / identities named in prose
        for login in _USER_RE.findall(q):
            hit = run.search(login, ["HumanUser", "ServiceAccount", "IamUser"])
            if hit:
                slots.add(hit["id"], hit["label"])

        # buckets / databases
        for name in _BUCKET_RE.findall(q):
            hit = run.search(name, ["StorageBucket", "Database", "Secret"])
            if hit:
                slots.add(hit["id"], hit["label"])
        if not slots.data_stores and intent in ("alerts_reaching_crown_jewels", "attack_path_from_alert") and re.search(r"\b(cardholder vault|kyc documents|app config|statements)\b", q, re.I):
            m = re.search(r"\b(cardholder vault|kyc documents|app config|statements)\b", q, re.I)
            hit = run.search(m.group(1).split()[0], ["StorageBucket", "Database"]) if m else None
            if hit:
                slots.add(hit["id"], hit["label"])

        # threat intel: report ids, capitalized names, upper-case malware names
        for rep in _REPORT_RE.findall(q):
            hit = run.search(rep, ["IntelReport"])
            if hit:
                slots.add(hit["id"], hit["label"])
        for bigram in _CAPS_BIGRAM_RE.findall(q)[:4]:
            if bigram in _STOP_BIGRAMS:
                continue
            hit = run.search(bigram, ["ThreatActor", "Campaign", "Malware", "IntelReport", "HumanUser"])
            if hit and str(hit.get("name", "")).lower() == bigram.lower():
                slots.add(hit["id"], hit["label"])
        for word in _UPPER_WORD_RE.findall(q)[:2]:
            if _CVE_RE.fullmatch(word):
                continue
            hit = run.search(word, ["Malware", "Campaign", "ThreatActor"])
            if hit and str(hit.get("name", "")).lower() == word.lower():
                slots.add(hit["id"], hit["label"])

        # last resort for entity-centric questions: plain words that name something ("the bastion", "cardholder vault")
        if not slots.primary() and intent in ENTITY_INTENTS:
            words = [w for w in _notable_words(q) if w not in _QUESTION_VOCAB and not _ALERT_REF_RE.fullmatch(w)]
            preferred = {lbl for hint, lbls in _LABEL_HINTS.items() if re.search(rf"\b{hint}s?\b", q, re.I) for lbl in lbls}
            candidates: dict[str, dict[str, Any]] = {}
            for word in words[:3]:
                for h in run.search_all(word, sorted(preferred) if preferred else _LINKABLE_LABELS, limit=6):
                    candidates.setdefault(h["id"], h)
            ranked = sorted(
                ((_hit_overlap(h, words), 0 if h.get("label") in preferred else 1, float(h.get("score") or 0), h) for h in candidates.values()),
                key=lambda t: (-t[0], t[1], -t[2]),
            )
            if ranked and ranked[0][0] >= 1:
                best = ranked[0][3]
                slots.add(best["id"], best.get("label"))

        # canvas context
        ctx_alert = context.get("alert_id")
        if ctx_alert and (not slots.alerts or _THIS_RE.search(q)):
            slots.add(str(ctx_alert), "Alert")
        if context.get("storyline_id") and not slots.storylines:
            slots.add(str(context["storyline_id"]), "Storyline")
        if context.get("node_id") and not slots.explicit_ids:
            slots.add(str(context["node_id"]))
        for nid in context.get("selected_node_ids") or []:
            if not slots.primary() or (_THIS_RE.search(q) and not slots.hosts() and not slots.alerts):
                slots.add(str(nid))
        return slots

    # -------------------------------------------------------------- answer

    def answer(
        self,
        question: str,
        context: Mapping[str, Any] | None = None,
        on_event: EventSink | None = None,
        history: Sequence[ChatTurn] | None = None,
    ) -> AnalystAnswer:
        emit: EventSink = on_event or (lambda ev: None)
        context = dict(context or {})
        run = _Run(self.registry, emit, self.max_tool_calls)
        intent, _scores = self.classify(question, context)
        slots = self._link(run, question, intent, context) if intent != "help" else Slots()
        intent = self._refine_intent(intent, slots, question, context)
        playbook = self._playbooks[intent]
        try:
            draft = playbook(run, question, slots, context)
        except Exception as exc:  # a playbook must never crash the chat; degrade to a cited partial answer
            log.exception("offline playbook %s failed", intent)
            draft = Draft(summary=f"The `{intent}` playbook failed while querying the graph ({type(exc).__name__}: {exc}).", confidence=0.2, followups=DEMO_QUESTIONS[:3])
        intent = draft.intent or intent
        # validate cited ids against the evidence set (ids returned by the tools of this turn)
        findings: list[Finding] = []
        for f in draft.findings:
            kept, _dropped = run.evidence.validate_ids(f.evidence_ids)
            findings.append(Finding(statement=f.statement, severity=f.severity, evidence_ids=kept))
        narrative = _compose(draft)
        frag = self._complete_evidence(run, findings, draft.focus, emit)
        focus = [i for i in dict.fromkeys(draft.focus) if i in run.evidence.ids and "|" not in i]
        if focus:
            frag = frag.model_copy(update={"focus": list(dict.fromkeys([*focus, *frag.focus]))[:50]})
        for chunk in _chunks(narrative):
            emit(ChatEvent(type="text_delta", data={"text": chunk}))
        return AnalystAnswer(
            narrative_md=narrative, findings=findings, evidence=frag, confidence=max(0.0, min(1.0, draft.confidence)),
            followups=draft.followups[:3], tool_calls=list(run.tool_calls), mode="offline", intent=intent, model=None,
        )

    def _complete_evidence(self, run: _Run, findings: Sequence[Finding], focus: Sequence[str], emit: EventSink) -> Any:
        """Make sure every cited node is present in the evidence fragment.

        Tool results such as ``list_alerts`` or ``list_storylines`` expose citable ids (alert ids, entity ids) without
        returning the node itself; the UI highlights evidence by node id, so the missing nodes are looked up in the
        store (not a tool call) and merged in, together with cited edges whose endpoints are present.
        """
        frag = run.evidence.fragment
        present = {n.id for n in frag.nodes}
        cited = [i for f in findings for i in f.evidence_ids] + [i for i in focus if i in run.evidence.ids]
        missing_nodes = [i for i in dict.fromkeys(cited) if "|" not in i and i not in present][:80]
        if missing_nodes:
            try:
                extra = self.registry.node_outs(missing_nodes)
            except Exception as exc:  # pragma: no cover - defensive: evidence completion must never break an answer
                log.debug("evidence completion failed: %s", exc)
                extra = []
            if extra:
                frag = frag.model_copy(update={"nodes": [*frag.nodes, *extra]})
                present.update(n.id for n in extra)
        present_edges = {e.id for e in frag.edges}
        new_edges = []
        for eid in dict.fromkeys(i for i in cited if "|" in i and i not in present_edges):
            e = edge_out_from_id(eid)
            if e is not None and e.src in present and e.dst in present:
                new_edges.append(e)
        if new_edges:
            frag = frag.model_copy(update={"edges": [*frag.edges, *new_edges]})
        if (missing_nodes and len(frag.nodes) > len(run.evidence.fragment.nodes)) or new_edges:
            added = frag.model_copy(update={"nodes": frag.nodes[len(run.evidence.fragment.nodes):], "edges": new_edges, "paths": [], "focus": []})
            if added.nodes or added.edges:
                emit(ChatEvent(type="evidence", data=added.model_dump(mode="json")))
        run.evidence.fragment = frag
        return frag

    # -------------------------------------------------------------- shared steps

    def _pick_alert_on_host(self, run: _Run, host_id: str, host_name: str | None, question: str, keywords: Sequence[tuple[str, Sequence[str]]]) -> dict[str, Any] | None:
        """Alerts on a host via list_alerts(q=hostname); prefer those matching the question's keyword family."""
        data = run.result("list_alerts", q=host_name or host_id, sort="contextual", limit=50)
        items = [a for a in data.get("items") or [] if isinstance(a, Mapping)]
        items = [a for a in items if a.get("entity_id") == host_id or (host_name and str(a.get("hostname", "")).lower() == host_name.lower())] or items
        if not items:
            return None

        def score(a: Mapping[str, Any]) -> tuple[int, int]:
            s = 0
            title = str(a.get("title", "")).lower()
            techs = [str(t) for t in a.get("techniques") or []]
            for rx, tech_prefixes in keywords:
                if re.search(rx, question, re.I):
                    if re.search(rx, title):
                        s += 3
                    if any(t.startswith(p) for t in techs for p in tech_prefixes):
                        s += 2
            return (s, int(a.get("contextual_score") or 0))

        items.sort(key=score, reverse=True)
        return dict(items[0])

    _CRED_KEYWORDS = [
        (r"credential|dump|lsass|imds|metadata|shadow", ("T1003", "T1552", "T1555")),
        (r"phish|lnk|iso|malicious file|initial", ("T1566", "T1204", "T1059")),
        (r"beacon|c2|command and control|outbound", ("T1071", "T1573")),
        (r"lateral|ssh|rdp|psexec", ("T1021", "T1570", "T1569")),
        (r"web ?shell|jndi|log4", ("T1505", "T1190")),
        (r"persist|run key", ("T1547",)),
        (r"public|bucket|s3", ()),
    ]

    def _resolve_alert(self, run: _Run, slots: Slots, question: str, context: Mapping[str, Any]) -> dict[str, Any] | None:
        """Return an AlertSummary dict for the alert the question is about (or None)."""
        if slots.alerts:
            data = run.result("get_alert", alert_id=slots.alerts[0])
            if data.get("alert"):
                return dict(data)
        for host in slots.hosts():
            name = None
            hit = None
            for h in run.search_all(host.split(":")[-1], ["Endpoint", "VirtualMachine"], limit=3):
                if h.get("id") == host:
                    hit = h
            name = str(hit.get("name")) if hit else (slots.host_tokens[0] if slots.host_tokens else None)
            alert = self._pick_alert_on_host(run, host, name, question, self._CRED_KEYWORDS)
            if alert:
                data = run.result("get_alert", alert_id=alert["id"])
                if data.get("alert"):
                    return dict(data)
        for quoted in slots.quoted[:2]:
            hit = run.alert_by_text(quoted)
            if hit:
                full = run.result("get_alert", alert_id=hit["id"])
                if full.get("alert"):
                    return {**full, "siblings": hit.get("siblings") or []}
        return None

    @staticmethod
    def _alert_of(data: Mapping[str, Any]) -> dict[str, Any]:
        return dict(data.get("alert") or {})

    # -------------------------------------------------------------- playbooks (demo questions 1-12)

    def _pb_blast_radius(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        # "the credential-dumping alert on BAS-01" is about an alert; "from WKS-3391" / "from this host" is about the host
        wants_alert = bool(slots.alerts) or bool(re.search(r"\b(alert|detection|finding|incident)s?\b", question, re.I))
        if not slots.hosts() and not slots.alerts and context.get("alert_id"):
            wants_alert = True
        alert_data = self._resolve_alert(run, slots, question, context) if wants_alert else None
        root_id: str | None = None
        root_desc = ""
        alert: dict[str, Any] = {}
        if alert_data:
            alert = self._alert_of(alert_data)
            root_id = alert.get("id")
            root_desc = _alert_ref(alert)
        elif slots.hosts():
            root_id = slots.hosts()[0]
            card = run.result("get_entity", id=root_id)
            root_desc = _node_ref(card.get("node"))
        elif slots.primary():
            root_id = slots.primary()
            card = run.result("get_entity", id=root_id)
            root_desc = _node_ref(card.get("node"))
        if not root_id:
            return self._pb_help(run, question, slots, context, note="I could not resolve which alert or host you mean. Name a host (e.g. BAS-01), an alert id (e.g. ldt-a009) or select one on the canvas.")

        br = run.result("blast_radius", id=root_id, depth=5)
        jewels = br.get("crown_jewels") or []
        stores = br.get("data_stores") or []
        secrets = br.get("secrets") or []
        idents = br.get("identities") or []
        reached = int(br.get("reached_count") or 0)
        accounts = br.get("accounts_touched") or []
        risk = alert_data.get("risk") if alert_data else None
        story = alert_data.get("storyline") if alert_data else None

        draft = Draft(summary=f"**Blast radius of {root_desc}** - an attacker controlling this node can reach **{reached} nodes**, including **{len(jewels)} crown jewel(s)**, {len(secrets)} secret(s) and {len(idents)} identit(ies) across {len(accounts) or 'no'} cloud account(s).", focus=[root_id])
        draft.findings.append(Finding(statement=f"Root {root_desc}.", severity=alert.get("vendor_severity") if alert else None, evidence_ids=[root_id]))
        if alert.get("entity_id"):
            draft.findings.append(Finding(statement=f"The alert sits on {_b(alert['entity_id'])} ({alert.get('hostname') or alert.get('entity_label')}), which resolves to cloud infrastructure with an instance role - the endpoint-to-cloud bridge.", evidence_ids=[root_id, alert["entity_id"]]))
        role_ids = [i for i in _ids_of_reached(idents) if i.startswith("role:")]
        if role_ids:
            draft.findings.append(Finding(statement="Reachable identities (role chain): " + ", ".join(_b(i) for i in role_ids[:4]) + ".", severity="high", evidence_ids=role_ids[:4]))
        if jewels:
            draft.findings.append(Finding(statement=f"{len(jewels)} crown jewel(s) reachable: " + ", ".join(_node_ref(j.get('node')) for j in jewels[:5]) + ".", severity="critical", evidence_ids=_ids_of_reached(jewels)[:6]))
        else:
            draft.findings.append(Finding(statement="No crown jewel (PCI/PII/SECRETS store) is reachable from this node within 5 hops.", severity="low", evidence_ids=[root_id]))
        if secrets:
            draft.findings.append(Finding(statement=f"{len(secrets)} secret(s) reachable: " + ", ".join(_b(i) for i in _ids_of_reached(secrets)[:4]) + ".", severity="high", evidence_ids=_ids_of_reached(secrets)[:4]))
        if risk:
            rails = ", ".join(risk.get("rails") or []) or "none"
            draft.findings.append(Finding(statement=f"Contextual score {risk.get('contextual_score')} ({risk.get('band')}) vs vendor severity {risk.get('vendor_severity')}; rails: {rails}.", evidence_ids=[root_id]))
        if story:
            draft.findings.append(Finding(statement=f"Part of storyline {_b(story.get('id'))} \"{story.get('title')}\" ({story.get('stage_count')} stages, score {story.get('contextual_score')}).", evidence_ids=[story.get("id"), root_id]))
        # a concrete path to the most sensitive jewel
        if jewels:
            target = str(_g(jewels[0], "node", "id"))
            paths = run.result("find_paths", src_id=root_id, dst_id=target, max_hops=6, k=1)
            if paths.get("found"):
                p = paths["paths"][0]
                draft.findings.append(Finding(statement=f"Shortest path to {_b(target)} is {p.get('hops')} hops: " + " -> ".join(_b(n) for n in p.get("node_ids", [])) + ".", severity="critical", evidence_ids=list(p.get("node_ids", [])) + list(p.get("edge_ids", []))))
                draft.focus += list(p.get("node_ids", []))
        draft.evidence_lines += [f"- Root: {root_desc}"]
        draft.evidence_lines += _reached_lines(jewels, 6) + _reached_lines(secrets, 4) + _reached_lines(idents, 6)
        other = [s for s in stores if _g(s, "node", "id") not in set(_ids_of_reached(jewels))]
        draft.evidence_lines += _reached_lines(other, 4)
        by_hop = br.get("by_hop") or {}
        if by_hop:
            draft.evidence_lines.append("- Reached nodes by hop: " + ", ".join(f"{h}: {c}" for h, c in sorted(by_hop.items(), key=lambda kv: int(kv[0]))))
        classes: set[str] = set()
        for j in jewels + stores:
            for c in _g(j, "node", "props", "data_classifications", default=[]) or []:
                classes.add(str(c))
        draft.impact_lines.append(f"- Data classifications reachable: {', '.join(sorted(classes)) or 'none'}; accounts touched: {', '.join(_b(a) for a in accounts) or 'none'}.")
        if jewels:
            draft.impact_lines.append(f"- A {alert.get('vendor_severity', 'vendor')}-severity endpoint alert therefore has a direct line to regulated data - it should be treated as {risk.get('band') if risk else 'critical'} regardless of the vendor label.")
        draft.actions = [
            f"Isolate the host behind {_b(alert.get('entity_id') or root_id)} and preserve the process/logon evidence.",
            *(f"Rotate credentials for {_b(r)} and review its CloudTrail activity for the last 24 h." for r in role_ids[:1]),
            *(f"Tighten the trust policy of {_b(r)} to the exact principals that need it." for r in role_ids[1:2]),
            "Check access logs on the reachable crown jewels for reads by the involved principals.",
        ]
        draft.followups = [
            DEMO_QUESTIONS[6], DEMO_QUESTIONS[7], DEMO_QUESTIONS[11],
        ]
        draft.confidence = 0.9 if jewels else 0.7
        return draft

    def _pb_medium_alerts(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        severity = slots.severity or "medium"
        source = "falcon" if re.search(r"\bendpoint|\bedr\b|\bfalcon", question, re.I) or not re.search(r"\b(cspm|waf|ids|okta|cloud)\b", question, re.I) else None
        data = run.result("alerts_with_data_path", severity=severity, source=source)
        items = [a for a in data.get("items") or [] if isinstance(a, Mapping)]
        draft = Draft(summary=f"**{len(items)} {severity}-severity {'endpoint ' if source == 'falcon' else ''}alert(s)** sit on assets with a path to regulated data (sorted by contextual score).", focus=[a["id"] for a in items[:3]])
        if not items:
            draft.findings.append(Finding(statement=f"No {severity} alerts from {source or 'any source'} currently sit on an asset that can reach regulated data.", severity="low"))
            draft.confidence = 0.6
        for a in items[:8]:
            reasons = ", ".join(a.get("graph_reasons") or []) or "path to regulated data"
            draft.findings.append(Finding(statement=f"{_alert_ref(a)} - {reasons}.", severity=a.get("contextual_band") if a.get("contextual_band") in ("low", "medium", "high", "critical") else None, evidence_ids=[a["id"]] + ([a["entity_id"]] if a.get("entity_id") else [])))
        if items:
            top = items[0]
            ctx = run.result("get_alert_context", alert_id=top["id"])
            br = ctx.get("blast_radius") or {}
            jewels = br.get("crown_jewels") or []
            if jewels:
                draft.findings.append(Finding(statement=f"The top alert {_b(top['id'])} reaches {len(jewels)} crown jewel(s): " + ", ".join(_node_ref(j.get('node')) for j in jewels[:4]) + ".", severity="critical", evidence_ids=[top["id"]] + _ids_of_reached(jewels)[:4]))
            paths = ctx.get("attack_paths") or []
            if paths:
                p = paths[0]
                draft.findings.append(Finding(statement=f"It lies on an attack path of {p.get('hops')} hops / {len(p.get('stages') or [])} stages ending at {_b(p.get('target_id'))} (likelihood {p.get('likelihood', 0):.2f}).", severity="critical", evidence_ids=[top["id"], p.get("target_id")]))
            story = ctx.get("storyline")
            if story:
                draft.findings.append(Finding(statement=f"It is stage material of storyline {_b(story.get('id'))} \"{story.get('title')}\" (score {story.get('contextual_score')}).", evidence_ids=[story.get("id"), top["id"]]))
        draft.evidence_lines = [f"- {_alert_ref(a)}" for a in items[:10]]
        draft.impact_lines = [
            f"- Vendor severity '{severity}' hides the difference between these alerts and the rest of the {severity} queue; the contextual score separates them by data reachability.",
            "- Alerts without a data path (e.g. isolated dev hosts, file servers without regulated data) are excluded from this list by construction.",
        ]
        draft.actions = [
            f"Triage {_b(items[0]['id'])} first; open its graph context to see the path to data." if items else "Widen the search: try other severities or sources.",
            "Escalate every alert in this list to incident response regardless of the vendor label.",
            "Review why the vendor ranked them medium: the EDR has no cloud visibility.",
        ]
        draft.followups = [DEMO_QUESTIONS[0], DEMO_QUESTIONS[6], DEMO_QUESTIONS[5]]
        draft.confidence = 0.9 if items else 0.6
        return draft

    def _pb_cloud_activity(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        role_ids = [i for i in slots.identities if slots.labels.get(i) == "IamRole"] or slots.identities
        if not role_ids:
            hit = run.search("bastion", ["IamRole"]) if re.search(r"\bbastion\b", question, re.I) else None
            if hit:
                role_ids = [hit["id"]]
                slots.add(hit["id"], hit["label"])
        role_id = role_ids[0] if role_ids else None
        role_card = run.result("get_entity", id=role_id) if role_id else {}
        joins = run.result("credential_joins")
        items = [i for i in joins.get("items") or [] if isinstance(i, Mapping)]

        def involves_role(item: Mapping[str, Any]) -> bool:
            if not role_id:
                return True
            ids = {str(_g(item, "principal", "id")), str(_g(item, "credential", "props", "principal_id"))}
            ids |= {str(_g(d, "props", "principal_id")) for d in item.get("derived_credentials") or []}
            return role_id in ids

        related = [i for i in items if involves_role(i)]
        role_desc = _node_ref(role_card.get("node")) if role_card.get("node") else (_b(role_id) if role_id else "the role")
        if related:
            draft = Draft(summary=f"**Yes.** Cloud API activity by {role_desc} used **{len(related)} credential(s) that were stolen on an endpoint** - the cloud events are the continuation of an endpoint detection.", focus=[role_id] if role_id else [])
            for it in related:
                cred, alert, ep = it.get("credential") or {}, it.get("stolen_by_alert") or {}, it.get("endpoint") or {}
                events = [e for e in it.get("used_in_events") or [] if isinstance(e, Mapping)]
                ev_desc = ", ".join(f"{_b(e.get('id'))} {_g(e, 'props', 'event_name', default=e.get('name'))}" for e in events[:6])
                draft.findings.append(Finding(statement=f"Credential {_node_ref(cred)} was stolen by {_alert_ref(alert)} on {_node_ref(ep)} and then used in {len(events)} cloud event(s): {ev_desc}.", severity="critical", evidence_ids=[cred.get("id"), alert.get("id"), ep.get("id")] + [e.get("id") for e in events[:6]]))
                ips = it.get("source_ips") or []
                if ips:
                    draft.findings.append(Finding(statement=f"The calls came from {', '.join(_b(ip) for ip in ips[:3])}, i.e. from outside the VPC although the credential belongs to an instance role.", severity="high", evidence_ids=[cred.get("id")]))
                for d in it.get("derived_credentials") or []:
                    draft.findings.append(Finding(statement=f"A derived credential {_node_ref(d)} was minted from it via AssumeRole (privilege escalation into another account).", severity="critical", evidence_ids=[d.get("id"), cred.get("id")]))
                if it.get("first_use"):
                    draft.evidence_lines.append(f"- First cloud use of {_b(cred.get('id'))}: {_fmt_time(it.get('first_use'))}; theft detected at {_fmt_time(alert.get('detected_at'))}.")
                draft.evidence_lines += [f"- {_b(e.get('id'))} {_g(e, 'props', 'event_name', default='')} at {_fmt_time(_g(e, 'props', 'event_time'))} -> target {_g(e, 'props', 'target_id', default='n/a')}" for e in events[:8]]
            draft.impact_lines = [
                "- The EDR incident and the cloud audit trail describe one intrusion; the credential node is the join key neither tool has.",
                "- Any resource the role (and roles it can assume) can access must be considered read by the attacker.",
            ]
            draft.actions = [
                f"Revoke active sessions and rotate credentials for {_b(role_id) if role_id else 'the role'}; invalidate derived sessions by updating the downstream roles' trust policies.",
                "Block the source IPs at the edge and add them to the watchlist.",
                "Pull object-level access logs for the targets of the listed events.",
            ]
            draft.confidence = 0.9
        else:
            draft = Draft(summary=f"**No endpoint detection is linked to the cloud API activity of {role_desc}** through a stolen credential.", focus=[role_id] if role_id else [])
            if role_id:
                nb = run.result("get_neighborhood", id=role_id, depth=1, edge_types=["PERFORMED_BY", "ASSUMED", "CREDENTIAL_FOR"], max_nodes=60)
                events = [n for n in nb.get("nodes") or [] if n.get("label") == "CloudEvent"]
                draft.findings.append(Finding(statement=f"{len(events)} cloud event(s) were performed by or assumed {_b(role_id)}; none used a credential with a STOLEN_BY link to an alert.", severity="low", evidence_ids=[role_id] + [e["id"] for e in events[:10]]))
                draft.evidence_lines = [f"- {_b(e['id'])} {e.get('name')}" for e in events[:10]]
            else:
                draft.findings.append(Finding(statement="No role could be resolved from the question; name the role (e.g. LarkspurBastionSSMRole).", severity="low"))
            draft.impact_lines = ["- Absence of a credential join is not proof of benign activity; anomalous geolocation or new ASN would still warrant a look."]
            draft.actions = ["Run `credential_joins` again after the next EDR sync.", "Inspect the role's recent CloudEvents for new source ASNs."]
            draft.confidence = 0.6 if role_id else 0.3
        draft.followups = [DEMO_QUESTIONS[7], DEMO_QUESTIONS[3], DEMO_QUESTIONS[11]]
        return draft

    def _pb_identity_footprint(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        identity = slots.identities[0] if slots.identities else None
        if not identity:
            hit = run.search("bastion", ["IamRole"]) if re.search(r"\bbastion\b", question, re.I) else None
            identity = hit["id"] if hit else slots.primary()
        if not identity:
            return self._pb_help(run, question, slots, context, note="Name the identity (an IAM role, user or service account) whose footprint you want.")
        card = run.result("get_entity", id=identity)
        fp = run.result("identity_footprint", identity_id=identity)
        jewels, stores, secrets, idents = (fp.get(k) or [] for k in ("crown_jewels", "data_stores", "secrets", "identities"))
        accounts = fp.get("accounts_touched") or []
        desc = _node_ref(card.get("node")) if card.get("node") else _b(identity)
        draft = Draft(summary=f"**If {desc} is fully compromised** the attacker reaches **{fp.get('reached_count', 0)} nodes**: {len(idents)} further identit(ies), {len(jewels)} crown jewel(s), {len(secrets)} secret(s) across {len(accounts)} account(s).", focus=[identity])
        draft.findings.append(Finding(statement=f"Identity {desc}.", evidence_ids=[identity]))
        role_ids = [i for i in _ids_of_reached(idents) if i != identity]
        if role_ids:
            draft.findings.append(Finding(statement="It can assume / map to: " + ", ".join(_b(i) for i in role_ids[:5]) + (" (cross-account chain)" if any(i.split(":")[2] != identity.split(":")[2] for i in role_ids if i.count(":") >= 3 and identity.count(":") >= 3) else "") + ".", severity="high", evidence_ids=role_ids[:5]))
        if jewels:
            draft.findings.append(Finding(statement=f"Crown jewels reachable ({len(jewels)}): " + "; ".join(f"{_node_ref(j.get('node'))}{' [' + j['access_level'] + ']' if j.get('access_level') else ''}" for j in jewels[:5]) + ".", severity="critical", evidence_ids=_ids_of_reached(jewels)[:6]))
        if secrets:
            draft.findings.append(Finding(statement="Secrets reachable: " + ", ".join(_b(i) for i in _ids_of_reached(secrets)[:4]) + " - a database reader secret extends the reach to the database it unlocks.", severity="critical", evidence_ids=_ids_of_reached(secrets)[:4]))
        writable = [s for s in stores if str(s.get("access_level") or "").lower() in ("write", "admin")]
        if writable:
            draft.findings.append(Finding(statement="Write access to: " + ", ".join(_node_ref(s.get("node")) for s in writable[:3]) + " (e.g. log tampering).", severity="medium", evidence_ids=_ids_of_reached(writable)[:3]))
        if not jewels and not secrets:
            draft.findings.append(Finding(statement="No PCI/PII/SECRETS store is reachable from this identity within the transitive permission graph.", severity="low", evidence_ids=[identity]))
        draft.evidence_lines = _reached_lines(idents, 5) + _reached_lines(jewels, 5) + _reached_lines(secrets, 4) + _reached_lines([s for s in stores if _g(s, "node", "id") not in set(_ids_of_reached(jewels))], 4)
        by_hop = fp.get("by_hop") or {}
        if by_hop:
            draft.evidence_lines.append("- Reached by hop: " + ", ".join(f"{h}: {c}" for h, c in sorted(by_hop.items(), key=lambda kv: int(kv[0]))))
        draft.impact_lines = [
            f"- Accounts touched: {', '.join(_b(a) for a in accounts) or 'only its own'}; the transitive reach (CAN_ASSUME -> CAN_ACCESS -> UNLOCKS) is what an IAM console does not show.",
            "- Treat every listed data store as exposed if this identity's credentials are ever seen used from an unexpected network location.",
        ]
        draft.actions = [
            f"Remove or scope the AssumeRole grant from {_b(identity)} to the downstream roles; require an external-id / source-VPC condition.",
            "Tighten the trust policies of the assumable roles to exactly this principal.",
            "Alert on use of this identity's credentials from outside the VPC (instance roles should never call from the internet).",
        ]
        draft.followups = [DEMO_QUESTIONS[2], DEMO_QUESTIONS[11], DEMO_QUESTIONS[0]]
        draft.confidence = 0.9 if (jewels or idents) else 0.6
        return draft

    def _pb_exposed_hosts(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        sector_only = not re.search(r"\b(all sectors|any sector|regardless of sector|not just fintech)\b", question, re.I)
        data = run.result("exposed_hosts_with_exploited_vulns", sector_only=sector_only)
        rows = [r for r in data.get("items") or [] if isinstance(r, Mapping)]
        draft = Draft(summary=f"**{len(rows)} internet-exposed host(s)** carry a vulnerability that a threat actor is actively exploiting{' against financial services' if sector_only else ''}, ranked by contextual score.", focus=[str(_g(r, 'vm', 'id')) for r in rows[:3]])
        header = "| # | Host | CVE | Exploitation | Actor / campaign | Sector rel. | Score | Crown jewels reachable | EDR |\n|---|---|---|---|---|---|---|---|---|"
        table = [header]
        for i, r in enumerate(rows[:12], start=1):
            vm, cve = r.get("vm") or {}, r.get("cve") or {}
            actors = ", ".join(a.get("name", "") for a in r.get("actors") or [])
            camps = ", ".join(c.get("name", "") for c in r.get("campaigns") or [])
            jewels = r.get("crown_jewels_reachable") or []
            table.append(f"| {i} | {_b(vm.get('id'))} {vm.get('name', '')} | {cve.get('name') or cve.get('id')} | {r.get('exploitation_status')} | {actors}{' / ' + camps if camps else ''} | {r.get('sector_relevance')} | {r.get('contextual_score')} | {len(jewels)} | {'yes' if r.get('has_edr_sensor') else 'NO'} |")
            ids = [vm.get("id"), cve.get("id")] + [a.get("id") for a in r.get("actors") or []] + [c.get("id") for c in r.get("campaigns") or []]
            if i <= 4:
                sev = "critical" if jewels else ("high" if i == 1 else "medium")
                draft.findings.append(Finding(statement=f"#{i} {_node_ref(vm)} is exposed to the internet and vulnerable to {_b(cve.get('id'))} ({r.get('exploitation_status')}, exploited by {actors or 'unknown actor'}{' in ' + camps if camps else ''}; sector relevance {r.get('sector_relevance')}); contextual score {r.get('contextual_score')}; {len(jewels)} crown jewel(s) reachable; alerts on host: {', '.join(_b(a) for a in (r.get('alert_ids') or [])[:3]) or 'none'}.", severity=sev, evidence_ids=[x for x in ids if x] + list(r.get("alert_ids") or [])[:3]))
        if not rows:
            draft.findings.append(Finding(statement="No internet-exposed host currently carries an actively exploited vulnerability from a sector-relevant actor.", severity="low"))
        draft.evidence_lines = table if rows else []
        no_edr = [str(_g(r, "vm", "name")) for r in rows if not r.get("has_edr_sensor")]
        draft.impact_lines = [
            "- Exposure x active exploitation x sector targeting is what lifts these hosts above the rest of the CSPM backlog; the ranking is by blast radius, not CVSS.",
            *(["- Hosts without an EDR sensor (" + ", ".join(no_edr[:4]) + ") give no runtime signal if exploitation succeeds."] if no_edr else []),
        ]
        top_vm = _g(rows[0], "vm", "id") if rows else None
        draft.actions = [
            f"Patch or virtual-patch (WAF rule) {_b(top_vm)} first; it has the highest contextual score." if top_vm else "Nothing to patch on the exposed perimeter right now.",
            "Restrict the offending security groups to the load balancer / VPN CIDR instead of 0.0.0.0/0.",
            "Hunt for post-exploitation on the top hosts (web-root writes, shells spawned by the Java process).",
        ]
        draft.followups = [f"What alerts sit on {_b(top_vm)} and are they related?" if top_vm else DEMO_QUESTIONS[5], DEMO_QUESTIONS[9], DEMO_QUESTIONS[8]]
        draft.confidence = 0.9 if rows else 0.6
        return draft

    def _pb_rank_alerts(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        m = re.search(r"\btop (\d+|three|five|ten)\b", question, re.I)
        words = {"three": 3, "five": 5, "ten": 10}
        n_explain = min(int(words.get(m.group(1).lower(), m.group(1)) if m else 3), 5) if m else 3
        data = run.result("list_alerts", sort="contextual", limit=10)
        items = [a for a in data.get("items") or [] if isinstance(a, Mapping)]
        total = data.get("total", len(items))
        draft = Draft(summary=f"**Top {min(len(items), 10)} of {total} alerts by contextual risk** (vendor severity shown for contrast).", focus=[a["id"] for a in items[:3]])
        table = ["| # | Alert | Vendor | Contextual | Storyline | Why |", "|---|---|---|---|---|---|"]
        for i, a in enumerate(items, start=1):
            table.append(f"| {i} | {_b(a['id'])} {a.get('title', '')} | {a.get('vendor_severity')} (#{a.get('vendor_rank_position') or '?'}) | {a.get('contextual_score')} {a.get('contextual_band')} | {a.get('storyline_id') or '-'} | {', '.join(a.get('graph_reasons') or [])} |")
        draft.evidence_lines = table
        first_story = items[0].get("storyline_id") if items else None
        for i, a in enumerate(items[:n_explain], start=1):
            risk = run.result("explain_risk", alert_id=a["id"])
            factors = sorted(risk.get("factors") or [], key=lambda f: -float(f.get("contribution") or 0))
            fac = "; ".join(f"{f.get('label') or f.get('key')} {float(f.get('value') or 0):.2f} (+{float(f.get('contribution') or 0):.0f}): {f.get('reason')}" for f in factors[:4])
            rails = ", ".join(risk.get("rails") or []) or "none"
            ev = [a["id"]] + [e for f in factors for e in (f.get("evidence_ids") or [])[:2]]
            draft.findings.append(Finding(statement=f"#{i} {_alert_ref(a)}: raw {float(risk.get('raw_score') or 0):.0f}, rails {rails}; factors - {fac}.", severity=a.get("contextual_band") if a.get("contextual_band") in ("low", "medium", "high", "critical") else "medium", evidence_ids=ev[:10]))
        top_other = next((a for a in items if first_story and a.get("storyline_id") != first_story), None)
        if top_other:
            draft.findings.append(Finding(statement=f"Highest-scoring alert outside storyline {_b(first_story)}: {_alert_ref(top_other)}.", severity="high", evidence_ids=[top_other["id"]]))
        promoted = [a for a in items if (a.get("vendor_rank_position") or 0) > 20]
        if promoted:
            draft.findings.append(Finding(statement="Re-ranked up from deep in the vendor queue: " + ", ".join(f"{_b(a['id'])} (vendor #{a.get('vendor_rank_position')} -> contextual #{a.get('contextual_rank_position')})" for a in promoted[:3]) + ".", evidence_ids=[a["id"] for a in promoted[:3]]))
        bands = {}
        for a in items:
            bands[a.get("contextual_band")] = bands.get(a.get("contextual_band"), 0) + 1
        draft.impact_lines = [
            f"- Bands in the top {len(items)}: " + ", ".join(f"{k}: {v}" for k, v in bands.items()) + ".",
            "- Vendor-critical findings with no data path, no privilege reach and no threat-intel relevance are capped at 25 (noise ceiling) and do not appear here.",
        ]
        draft.actions = [
            f"Open {_b(items[0]['id'])} and its storyline first." if items else "No alerts to rank.",
            "Work the list top-down; the factor breakdown is the justification for each escalation.",
            "Suppress or auto-close alerts in the noise band after review.",
        ]
        draft.followups = [DEMO_QUESTIONS[0], DEMO_QUESTIONS[10], DEMO_QUESTIONS[1]]
        draft.confidence = 0.9 if items else 0.5
        return draft

    def _pb_attack_path(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        alert_data = self._resolve_alert(run, slots, question, context)
        alert = self._alert_of(alert_data) if alert_data else {}
        through = alert.get("id") or (slots.hosts()[0] if slots.hosts() else slots.primary())
        target = slots.data_stores[0] if slots.data_stores else None
        if not through and not target:
            return self._pb_help(run, question, slots, context, note="Name the starting detection or host (e.g. 'the phishing detection on WKS-3391').")
        data = run.result("attack_paths", through_id=through, target_id=target, k=3)
        paths = [p for p in data.get("paths") or [] if isinstance(p, Mapping)]
        if not paths and alert.get("entity_id"):
            data = run.result("attack_paths", through_id=alert["entity_id"], target_id=target, k=3)
            paths = [p for p in data.get("paths") or [] if isinstance(p, Mapping)]
        story = alert_data.get("storyline") if alert_data else None
        if not paths and story and story.get("id"):
            sdata = run.result("get_storyline", storyline_id=story["id"])
            stages = sdata.get("stages") or []
            if stages:
                paths = [{"id": sdata.get("id"), "entry_id": (stages[0].get("alert_ids") or [None])[0], "target_id": (sdata.get("crown_jewels_reached") or [None])[0], "likelihood": 1.0, "hops": len(stages), "stages": stages, "summary": sdata.get("summary")}]
        start_desc = _alert_ref(alert) if alert else _b(through)
        if not paths:
            draft = Draft(summary=f"**No attack path** was reconstructed through {start_desc}{' to ' + _b(target) if target else ''}.", focus=[x for x in (through, target) if x])
            draft.findings.append(Finding(statement=f"The attack-graph search found no multi-stage path through {_b(through)}; the node may not be on a storyline.", severity="low", evidence_ids=[x for x in (through,) if x]))
            draft.actions = ["Check the blast radius of the host instead.", "Verify the entity resolution (SAME_AS) of the endpoint."]
            draft.followups = [DEMO_QUESTIONS[0], DEMO_QUESTIONS[5], DEMO_QUESTIONS[3]]
            draft.confidence = 0.4
            return draft
        p = paths[0]
        stages = [s for s in p.get("stages") or [] if isinstance(s, Mapping)]
        chain = list(dict.fromkeys(n for s in stages for n in (s.get("node_ids") or [])))
        draft = Draft(summary=f"**Attack path from {start_desc} to {_b(p.get('target_id'))}**: {len(stages)} stages, {p.get('hops')} hops, likelihood {float(p.get('likelihood') or 0):.2f}.", focus=[x for x in (through, p.get("target_id")) if x] + chain)
        for s in stages:
            techs = ", ".join(s.get("technique_ids") or []) or "-"
            alerts = ", ".join(_b(a) for a in (s.get("alert_ids") or [])[:2]) or "no alert (cloud audit only)"
            nodes = " -> ".join(_b(n) for n in (s.get("node_ids") or [])[:3])
            draft.findings.append(Finding(statement=f"Stage {s.get('order')} {s.get('stage')} ({techs}) at {_fmt_time(s.get('time'))}: {s.get('summary') or ''} [{alerts}] {nodes}".strip(), severity="high", evidence_ids=list(s.get("alert_ids") or []) + list(s.get("node_ids") or [])[:4] + list(s.get("edge_ids") or [])[:4]))
        draft.findings.append(Finding(statement=f"Terminal target {_b(p.get('target_id'))}; entry {_b(p.get('entry_id'))}. " + (p.get("summary") or ""), severity="critical", evidence_ids=[x for x in (p.get("entry_id"), p.get("target_id")) if x]))
        if len(paths) > 1:
            draft.findings.append(Finding(statement=f"{len(paths) - 1} alternative path(s) exist with likelihood " + ", ".join(f"{float(q.get('likelihood') or 0):.2f}" for q in paths[1:]) + ".", evidence_ids=[q.get("target_id") for q in paths[1:] if q.get("target_id")]))
        draft.evidence_lines = ["- Chain: " + " -> ".join(_b(n) for n in chain[:12])] + [f"- Stage {s.get('order')}: {s.get('stage')} - alerts {', '.join(s.get('alert_ids') or []) or 'none'}" for s in stages]
        if story:
            draft.evidence_lines.append(f"- Storyline {_b(story.get('id'))} \"{story.get('title')}\" score {story.get('contextual_score')}, crown jewels reached: {', '.join(_b(c) for c in story.get('crown_jewels_reached') or [])}")
        draft.impact_lines = [
            "- The path crosses endpoint lateral movement (SSH) and cloud privilege escalation (AssumeRole); no single console sees both halves.",
            f"- Terminal blast radius: {_b(p.get('target_id'))}" + (f" plus {len(story.get('crown_jewels_reached') or []) - 1} other crown jewel(s) in the storyline" if story and len(story.get('crown_jewels_reached') or []) > 1 else "") + ".",
        ]
        draft.actions = [
            "Contain the pivot host (bastion) and the initial workstation; revoke the compromised SSH key and the instance-role credentials.",
            "Rotate the downstream role trust policy and audit object access on the terminal data store.",
            "Feed the technique chain to detection engineering: the medium-severity middle stages are where this should have been caught.",
        ]
        draft.followups = [DEMO_QUESTIONS[7], DEMO_QUESTIONS[11], DEMO_QUESTIONS[8]]
        draft.confidence = 0.9
        return draft

    def _pb_credential_joins(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        data = run.result("credential_joins")
        items = [i for i in data.get("items") or [] if isinstance(i, Mapping)]
        draft = Draft(summary=f"**{len(items)} credential(s)** used in cloud API calls were first seen being stolen on an endpoint." if items else "**No credential** used in cloud API calls has a STOLEN_BY link to an endpoint detection.", focus=[str(_g(i, 'credential', 'id')) for i in items])
        for it in items:
            cred, alert, ep, principal = it.get("credential") or {}, it.get("stolen_by_alert") or {}, it.get("endpoint") or {}, it.get("principal") or {}
            events = [e for e in it.get("used_in_events") or [] if isinstance(e, Mapping)]
            ev_names = ", ".join(f"{_g(e, 'props', 'event_name', default=e.get('name'))} ({_b(e.get('id'))})" for e in events[:6])
            draft.findings.append(Finding(statement=f"{_node_ref(cred)} for {_node_ref(principal)}: stolen by {_alert_ref(alert)} on {_node_ref(ep)} at {_fmt_time(alert.get('detected_at'))}; first cloud use {_fmt_time(it.get('first_use'))} from {', '.join(it.get('source_ips') or []) or 'unknown IP'}; events: {ev_names or 'none'}.", severity="critical", evidence_ids=[cred.get("id"), alert.get("id"), ep.get("id"), principal.get("id")] + [e.get("id") for e in events[:6]]))
            for d in it.get("derived_credentials") or []:
                draft.findings.append(Finding(statement=f"Derived credential {_node_ref(d)} (via AssumeRole) - its use is attributable to the same theft.", severity="critical", evidence_ids=[d.get("id"), cred.get("id")]))
            draft.evidence_lines += [f"- {_b(e.get('id'))} {_g(e, 'props', 'event_name', default='')} {_fmt_time(_g(e, 'props', 'event_time'))} -> {_g(e, 'props', 'target_id', default='')}" for e in events[:8]]
        draft.impact_lines = [
            "- These credentials prove the endpoint compromise progressed into the cloud control plane; every target of the listed events must be treated as accessed.",
            "- Session credentials minted through AssumeRole are not revoked by rotating the source role; the downstream roles' trust policies must change too.",
        ] if items else ["- No cross-domain credential reuse is visible; keep monitoring IMDS/LSASS access alerts."]
        draft.actions = [
            "Revoke all sessions for the affected principals and rotate them.",
            "Block the source IPs and search CloudTrail for other keys used from them.",
            "Review the objects and secrets targeted by the events for exposure notification obligations.",
        ] if items else ["No action required from this angle."]
        draft.followups = [DEMO_QUESTIONS[2], DEMO_QUESTIONS[11], DEMO_QUESTIONS[6]]
        draft.confidence = 0.95 if items else 0.6
        return draft

    def _pb_ioc_ttp(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        subject = (slots.actors + slots.campaigns + slots.reports + slots.malware + slots.ioc_values + slots.cves)
        if not subject:
            for bigram in _CAPS_BIGRAM_RE.findall(question):
                if bigram not in _STOP_BIGRAMS:
                    subject.append(bigram)
                    break
        if not subject:
            return self._pb_help(run, question, slots, context, note="Name the actor, campaign, report or indicator (e.g. 'Cinder Jackal', 'TL-2026-0142', a hash or IP).")
        value = subject[0]
        ti = run.result("threat_intel_lookup", value=value)
        actors = [a for a in ti.get("actors") or [] if isinstance(a, Mapping)]
        campaigns = [c for c in ti.get("campaigns") or [] if isinstance(c, Mapping)]
        reports = [r for r in ti.get("reports") or [] if isinstance(r, Mapping)]
        matches = [m for m in ti.get("matches") or [] if isinstance(m, Mapping)]
        actor_id = actors[0]["id"] if actors else (value if value.startswith("actor:") else None)
        actor_name = actors[0].get("name") if actors else value
        # attributed alerts and their techniques
        alerts_data = run.result("list_alerts", sort="contextual", limit=50)
        all_alerts = [a for a in alerts_data.get("items") or [] if isinstance(a, Mapping)]
        matched_alert_ids = {m.get("matched_node_id") for m in matches if m.get("matched_label") == "Alert"}
        attributed = [a for a in all_alerts if (actor_id and actor_id in (a.get("ti_actor_ids") or [])) or a["id"] in matched_alert_ids]
        matched_events = [m for m in matches if m.get("matched_label") == "CloudEvent"]
        # TTP overlap from the actor's technique neighbourhood
        actor_techs: set[str] = set()
        if actor_id:
            nb = run.result("get_neighborhood", id=actor_id, depth=1, edge_types=["USES_TECHNIQUE"], labels=["AttackTechnique"], max_nodes=100)
            actor_techs = {str(_g(n, "props", "technique_id") or str(n.get("id", "")).split(":")[-1]) for n in nb.get("nodes") or [] if n.get("label") == "AttackTechnique"}
        alert_techs = {str(t) for a in attributed for t in a.get("techniques") or []}
        overlap = sorted(actor_techs & alert_techs)
        storyline_id = next((a.get("storyline_id") for a in attributed if a.get("storyline_id")), None)
        story = run.result("get_storyline", storyline_id=storyline_id) if storyline_id else {}
        subject_desc = f"{actor_name} ({_b(actor_id)})" if actor_id else _b(value)
        draft = Draft(summary=f"**Yes - {len(matches)} IOC match(es) and {len(overlap)} overlapping TTP(s)** link current telemetry to {subject_desc}" + (f"; the matched activity forms storyline {_b(storyline_id)} which reaches {len(story.get('crown_jewels_reached') or [])} crown jewel(s)." if storyline_id else "."), focus=[x for x in ([actor_id] if actor_id else []) + [a["id"] for a in attributed[:5]]])
        if not matches and not attributed:
            draft.summary = f"**No IOC or TTP match** links current detections to {subject_desc}."
        by_type: dict[str, list[Mapping[str, Any]]] = {}
        for m in matches:
            by_type.setdefault(str(m.get("ioc_type")), []).append(m)
        for t, ms in by_type.items():
            draft.findings.append(Finding(statement=f"{len(ms)} {t} indicator match(es): " + "; ".join(f"{_b(m.get('indicator_id'))} = {m.get('value')} -> {_b(m.get('matched_node_id'))} ({m.get('matched_label')}, conf {float(m.get('confidence') or 0):.2f})" for m in ms[:5]) + ".", severity="high", evidence_ids=[m.get("indicator_id") for m in ms[:5]] + [m.get("matched_node_id") for m in ms[:5]]))
        if attributed:
            draft.findings.append(Finding(statement=f"{len(attributed)} alert(s) attributed to {actor_name}: " + ", ".join(_b(a["id"]) for a in attributed[:10]) + ".", severity="critical", evidence_ids=[a["id"] for a in attributed[:10]]))
        if matched_events:
            draft.findings.append(Finding(statement=f"{len(matched_events)} cloud event(s) match actor infrastructure: " + ", ".join(_b(m.get("matched_node_id")) for m in matched_events[:8]) + ".", severity="critical", evidence_ids=[m.get("matched_node_id") for m in matched_events[:8]]))
        if actor_techs:
            draft.findings.append(Finding(statement=f"TTP overlap: {len(overlap)} of {len(actor_techs)} actor techniques observed in the attributed alerts ({', '.join(overlap[:12])}{'...' if len(overlap) > 12 else ''}).", severity="high" if len(overlap) >= 5 else "medium", evidence_ids=[actor_id] + [f"technique:attack:{t}" for t in overlap[:10]]))
        if story:
            draft.findings.append(Finding(statement=f"What they touch: storyline {_b(story.get('id'))} \"{story.get('title')}\" ({story.get('stage_count')} stages, score {story.get('contextual_score')}) reaches " + ", ".join(_b(c) for c in story.get("crown_jewels_reached") or []) + ".", severity="critical", evidence_ids=[story.get("id")] + list(story.get("crown_jewels_reached") or [])))
        rel = ti.get("sector_relevance")
        draft.evidence_lines = [f"- Actor: {_node_ref(a)}{f' - sector relevance {rel}' if rel is not None else ''}" for a in actors] + [f"- Campaign: {_node_ref(c)}" for c in campaigns] + [f"- Report: {_node_ref(r)}" for r in reports[:3]] + [f"- {_alert_ref(a)}" for a in attributed[:8]]
        draft.impact_lines = [
            f"- {ti.get('summary') or 'Threat-intel context attached.'}",
            "- Matched telemetry that reaches crown jewels turns a PDF report into a live incident with data at risk.",
        ]
        draft.actions = [
            "Block the matched C2 domain/IPs and hash-ban the matched files fleet-wide.",
            "Sweep all endpoints for the remaining IOCs of the report (hash, domain, filename).",
            "Map the un-observed actor TTPs to detection gaps.",
        ]
        draft.followups = [DEMO_QUESTIONS[6], DEMO_QUESTIONS[7], DEMO_QUESTIONS[4]]
        draft.confidence = 0.9 if (matches or attributed) else 0.5
        return draft

    def _pb_alerts_reaching_crown_jewels(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        jewel_id = slots.data_stores[0] if slots.data_stores and not re.search(r"\bcardholder data\b|\bregulated data\b", question, re.I) else None
        classification = slots.classification if not jewel_id else None
        data = run.result("alerts_reaching_crown_jewels", jewel_id=jewel_id, classification=classification)
        items = [a for a in data.get("items") or [] if isinstance(a, Mapping)]
        jewels = [j for j in data.get("jewels") or [] if isinstance(j, Mapping)]
        totals = run.result("list_alerts", sort="contextual", limit=1)
        total = totals.get("total")
        scope = f"{_b(jewel_id)}" if jewel_id else (f"{classification} data" if classification else "any crown jewel")
        draft = Draft(summary=f"**{len(items)} alert(s)** sit on assets that can reach {scope}" + (f" - the other {int(total) - len(items)} of {total} alerts are hidden." if isinstance(total, int) and total >= len(items) else "."), focus=[j["id"] for j in jewels[:3]] + [a["id"] for a in items[:5]])
        for a in items[:12]:
            draft.findings.append(Finding(statement=f"{_alert_ref(a)}" + (f" - {', '.join(a.get('graph_reasons') or [])}" if a.get("graph_reasons") else "") + ".", severity=a.get("contextual_band") if a.get("contextual_band") in ("low", "medium", "high", "critical") else None, evidence_ids=[a["id"]] + ([a["entity_id"]] if a.get("entity_id") else [])))
        if not items:
            draft.findings.append(Finding(statement=f"No alert currently sits on an asset with a path to {scope}.", severity="low"))
        draft.evidence_lines = [f"- Jewel: {_node_ref(j)}" for j in jewels[:6]] + [f"- {_alert_ref(a)}" for a in items[:12]]
        storylines = sorted({a.get("storyline_id") for a in items if a.get("storyline_id")})
        draft.impact_lines = [
            f"- Storylines represented: {', '.join(_b(s) for s in storylines) or 'none'}; vendor severities range from {min((a.get('vendor_severity') for a in items), default='n/a')} to {max((a.get('vendor_severity') for a in items), default='n/a')} - the filter is data reachability, not severity.",
            "- Excluded by construction: alerts on isolated dev hosts, public marketing assets and file servers without a data path.",
        ]
        draft.actions = [
            f"Work {_b(items[0]['id'])} first (highest contextual score)." if items else "Nothing to triage under this filter.",
            "Pin this filter as the SOC's default queue view.",
            "Review the CAN_ACCESS / CAN_ASSUME edges that create each path: least-privilege fixes shrink this list.",
        ]
        draft.followups = [DEMO_QUESTIONS[0], DEMO_QUESTIONS[5], DEMO_QUESTIONS[1]]
        draft.confidence = 0.9 if items else 0.6
        return draft

    def _pb_is_alert_risky(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        alert_data = self._resolve_alert(run, slots, question, context)
        if not alert_data:
            # free-text fallbacks: quoted phrases, well-known finding families, then the question's notable words
            candidates: list[str] = list(slots.quoted[:2])
            candidates += re.findall(r"\b(public (?:read|bucket|s3)|s3 bucket|eicar|psexec|impossible travel|beacon|web ?shell|lsass|imds|metadata)\b", question, re.I)
            candidates.append(" ".join(_notable_words(question)[:6]))
            for phrase in dict.fromkeys(c for c in candidates if c.strip()):
                hit = run.alert_by_text(phrase, min_overlap=2 if len(_notable_words(phrase)) > 1 else 1)
                if hit:
                    alert_data = run.result("get_alert", alert_id=hit["id"])
                    if alert_data.get("alert"):
                        alert_data = {**alert_data, "siblings": hit.get("siblings") or []}
                        break
                    alert_data = None
        if not alert_data:
            return self._pb_help(run, question, slots, context, note="Quote the finding's title or give its alert id (e.g. 'S3 bucket allows public read' or iss-n002).")
        alert = self._alert_of(alert_data)
        risk = alert_data.get("risk") or {}
        score = int(alert.get("contextual_score") or 0)
        band = alert.get("contextual_band")
        entity_id = alert.get("entity_id")
        card = run.result("get_entity", id=entity_id) if entity_id else {}
        node = card.get("node") or {}
        props = node.get("props") or {}
        ti = run.result("threat_intel_lookup", value=entity_id) if entity_id else {}
        actors = ti.get("actors") or []
        factors = {f.get("key"): f for f in risk.get("factors") or [] if isinstance(f, Mapping)}
        data_f, ti_f, priv_f, exp_f = factors.get("data", {}), factors.get("threat_intel", {}), factors.get("privilege", {}), factors.get("exposure", {})
        verdict = "**noise / low priority**" if score <= 25 else ("**low**" if score <= 50 else ("**moderate**" if score <= 75 else "**genuinely risky**"))
        draft = Draft(summary=f"{_alert_ref(alert)} is {verdict}: contextual score **{score}** ({band}) versus vendor severity **{alert.get('vendor_severity')}**.", focus=[alert["id"]] + ([entity_id] if entity_id else []))
        draft.findings.append(Finding(statement=f"The finding is on {_node_ref(node) if node else _b(entity_id)}.", evidence_ids=[alert["id"]] + ([entity_id] if entity_id else [])))
        classes = props.get("data_classifications") or []
        if node:
            draft.findings.append(Finding(statement=f"What's in it: data classifications {', '.join(str(c) for c in classes) or 'none recorded'}, sensitivity {props.get('sensitivity', 'unknown')}, crown jewel: {'yes' if props.get('crown_jewel') else 'no'}, public: {props.get('public', 'n/a')}.", severity="low" if not classes or set(map(str, classes)) <= {"PUBLIC", "INTERNAL"} else "high", evidence_ids=[entity_id] if entity_id else []))
        draft.findings.append(Finding(statement=f"Actor interest: {len(actors)} actor(s) linked to this asset" + (" (" + ", ".join(a.get("name", "") for a in actors[:3]) + ")" if actors else " - no IOC match, no campaign targeting it") + f"; threat-intel factor {float(ti_f.get('value') or 0):.2f}.", severity="high" if actors else "low", evidence_ids=[entity_id] + [a.get("id") for a in actors[:3]] if entity_id else [a.get("id") for a in actors[:3]]))
        draft.findings.append(Finding(statement=f"Privilege reach {float(priv_f.get('value') or 0):.2f} ({priv_f.get('reason') or 'no identity attached'}); exposure {float(exp_f.get('value') or 0):.2f} ({exp_f.get('reason') or 'n/a'}); data factor {float(data_f.get('value') or 0):.2f} ({data_f.get('reason') or 'n/a'}).", evidence_ids=[alert["id"]] + [e for f in (priv_f, exp_f, data_f) for e in (f.get("evidence_ids") or [])[:2]]))
        rails = risk.get("rails") or []
        if rails:
            draft.findings.append(Finding(statement=f"Rails applied: {', '.join(rails)}" + (" - capped as noise because there is no data, no threat-intel relevance and no privilege behind the exposure." if any('ceiling' in r for r in rails) else "."), evidence_ids=[alert["id"]]))
        siblings = [s for s in alert_data.get("siblings") or [] if isinstance(s, Mapping) and s.get("id")]
        if siblings:
            draft.findings.append(Finding(
                statement=f"{len(siblings)} other finding(s) carry the same title; this answer covers the most recent one. The others: "
                + ", ".join(f"{_b(s['id'])} on {s.get('entity_name') or s.get('hostname') or s.get('entity_id')} (score {s.get('contextual_score')})" for s in siblings[:5])
                + (" ..." if len(siblings) > 5 else "") + " - the contextual score separates the ones that matter.",
                severity="medium" if any(int(s.get("contextual_score") or 0) > 25 for s in siblings) else "low",
                evidence_ids=[s["id"] for s in siblings[:5]],
            ))
        insights = alert_data.get("insights") or []
        draft.evidence_lines = ["- Flat view: " + "; ".join(f"{k}={v}" for k, v in list((alert_data.get("flat_view") or {}).items())[:6])] + [f"- Insight: {i.get('statement')}" for i in insights[:4]]
        draft.impact_lines = [
            f"- Contextual score {score}: {'a vendor-critical finding that is operationally noise - fix it during normal hygiene work.' if score <= 25 else 'warrants attention proportional to its band.'}",
            f"- {'No sensitive data, no actor interest and no privilege reach means an attacker gains nothing from this misconfiguration.' if score <= 25 else 'See the factor breakdown for what drives the score.'}",
        ]
        draft.actions = [
            "Low priority: track as a hygiene ticket; do not page on it." if score <= 25 else "Prioritize according to the contextual band and the factor breakdown.",
            f"Confirm the asset's classification ({', '.join(str(c) for c in classes) or 'none'}) is still accurate - a misclassified bucket would change this verdict.",
            "Suppress vendor-critical alerts with the no-context rail from the on-call queue.",
        ]
        draft.followups = [DEMO_QUESTIONS[5], DEMO_QUESTIONS[9], DEMO_QUESTIONS[1]]
        draft.confidence = 0.9
        return draft

    def _pb_containment(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        targets: list[str] = []
        actions = list(slots.actions)
        hosts = slots.hosts()
        roles = [i for i in slots.identities if slots.labels.get(i) == "IamRole"]
        users = [i for i in slots.identities if slots.labels.get(i) in ("HumanUser", "IamUser", "ServiceAccount")]
        if not hosts and slots.alerts:
            data = run.result("get_alert", alert_id=slots.alerts[0])
            ent = _g(data, "alert", "entity_id")
            if ent:
                hosts = [ent]
        if not roles and re.search(r"\bbastion role\b|\brotate\b", question, re.I):
            hit = run.search("bastion", ["IamRole"])
            if hit:
                roles = [hit["id"]]
        if "isolate_endpoint" in actions or not actions:
            targets += hosts[:2]
        if "rotate_role_credentials" in actions or "tighten_trust_policy" in actions:
            targets += roles[:2]
        if "disable_user" in actions or "revoke_sessions" in actions:
            targets += users[:2]
        if "block_ip" in actions:
            targets += [f"ip:v4:{ip}" for ip in slots.ioc_values if _IP_RE.fullmatch(ip)]
        targets = list(dict.fromkeys(targets)) or list(dict.fromkeys(hosts + roles + users))
        if not actions:
            actions = ["isolate_endpoint"] if hosts else (["rotate_role_credentials"] if roles else ["revoke_sessions"])
        if roles and "rotate_role_credentials" in actions and "tighten_trust_policy" not in actions:
            actions.append("tighten_trust_policy")
        if not targets:
            return self._pb_help(run, question, slots, context, note="Name what to contain (a host such as BAS-01, a role, a user or an IP).")
        sim = run.result("simulate_containment", target_ids=targets, actions=actions)
        breaks = [b for b in sim.get("breaks") or [] if isinstance(b, Mapping)]
        contained = sim.get("storylines_contained") or []
        protected = sim.get("crown_jewels_protected") or []
        residual = sim.get("residual_risks") or []
        recs = sim.get("recommendations") or []
        draft = Draft(summary=f"**Simulating {', '.join(actions)} on {', '.join(_b(t) for t in targets)}**: cuts **{sim.get('paths_cut', 0)} attack path(s)**, contains **{len(contained)} storyline(s)**, protects **{len(protected)} crown jewel(s)** - and breaks **{len(breaks)} dependency(ies)**.", focus=targets + [b.get("node_id") for b in breaks[:5]])
        if contained:
            draft.findings.append(Finding(statement="Contained: " + ", ".join(_b(s) for s in contained) + f"; crown jewels no longer reachable through the targets: {', '.join(_b(c) for c in protected) or 'none'}.", severity="critical", evidence_ids=list(contained) + list(protected)))
        else:
            draft.findings.append(Finding(statement="No storyline is fully contained by these actions alone.", severity="medium", evidence_ids=targets))
        for b in breaks[:8]:
            draft.findings.append(Finding(statement=f"Breaks: {_b(b.get('node_id'))} {b.get('name')} ({b.get('label')}) - {b.get('impact')}" + (f"; owner {_b(b.get('owner_team_id'))}" if b.get("owner_team_id") else "") + ".", severity="medium", evidence_ids=[b.get("node_id")] + ([b.get("owner_team_id")] if b.get("owner_team_id") else [])))
        for r in residual[:5]:
            draft.findings.append(Finding(statement=f"Residual risk: {r}", severity="high", evidence_ids=targets[:1]))
        if roles and "rotate_role_credentials" in actions and not any("trust" in r.lower() for r in residual + recs):
            draft.findings.append(Finding(statement="Rotating the source role does not invalidate sessions already minted via AssumeRole; the downstream roles' trust policies must be tightened as well.", severity="high", evidence_ids=roles[:1]))
        draft.evidence_lines = [f"- Targets: {', '.join(_b(t) for t in targets)}; actions: {', '.join(actions)}"] + [f"- Break: {_b(b.get('node_id'))} {b.get('name')} - {b.get('impact')}" for b in breaks[:8]] + [f"- Residual: {r}" for r in residual[:5]]
        draft.impact_lines = [
            f"- Operational impact: {len(breaks)} dependent application(s)/team(s) lose service" + (" (" + ", ".join(str(b.get("name")) for b in breaks[:4]) + ")" if breaks else "") + ".",
            f"- Security gain: {sim.get('paths_cut', 0)} path(s) cut; {len(protected)} crown jewel(s) protected.",
        ]
        draft.actions = [*recs[:4]] or ["Proceed with the simulated actions and notify the owning teams."]
        if roles and not any("trust" in r.lower() for r in draft.actions):
            draft.actions.append("Tighten the trust policy of the downstream (assumed) roles so the rotated role cannot be re-abused.")
        draft.actions.append("Notify the owning teams listed under Breaks before executing; prepare the SFTP/SSM fallback.")
        draft.followups = [DEMO_QUESTIONS[7], DEMO_QUESTIONS[3], "Draft an incident summary for this storyline with cited evidence."]
        draft.confidence = 0.85
        return draft

    # -------------------------------------------------------------- generic playbooks

    def _pb_alerts_on_entity(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        targets = slots.hosts() or slots.identities or slots.data_stores or ([slots.primary()] if slots.primary() else [])
        if not targets:
            return self._pb_help(run, question, slots, context, note="Name the host, identity or resource whose alerts you want (e.g. 'which alerts sit on stmt-render-2a?').")
        alerts: dict[str, dict[str, Any]] = {}
        primary_card: dict[str, Any] = {}
        for t in targets[:3]:
            card = run.result("get_entity", id=t)
            if not primary_card and card.get("node"):
                primary_card = card
            for a in card.get("alerts") or []:
                if isinstance(a, Mapping) and a.get("id"):
                    alerts.setdefault(str(a["id"]), dict(a))
        node = primary_card.get("node") or {}
        query = slots.host_tokens[0] if slots.host_tokens else str(node.get("name") or "")
        if query:
            listed = run.result("list_alerts", q=query, sort="contextual", limit=25)
            for a in listed.get("items") or []:
                if not isinstance(a, Mapping) or not a.get("id"):
                    continue
                if a.get("entity_id") in targets or str(a.get("hostname") or "").lower() == query.lower() or str(a.get("entity_name") or "").lower() == query.lower():
                    alerts.setdefault(str(a["id"]), dict(a))
        items = sorted(alerts.values(), key=lambda a: (-int(a.get("contextual_score") or 0), str(a.get("detected_at") or "")))
        desc = _node_ref(node) if node else ", ".join(_b(t) for t in targets)
        draft = Draft(summary=f"**{len(items)} alert(s)** on {desc}" + (f" (highest contextual score {items[0].get('contextual_score')})." if items else "."), focus=[*targets, *[a["id"] for a in items[:5]]])
        for a in items[:10]:
            reasons = ", ".join(a.get("graph_reasons") or [])
            draft.findings.append(Finding(statement=f"{_alert_ref(a)}" + (f" - {reasons}" if reasons else "") + ".", severity=a.get("contextual_band") if a.get("contextual_band") in ("low", "medium", "high", "critical") else None, evidence_ids=[a["id"]] + ([a["entity_id"]] if a.get("entity_id") else [])))
        if not items:
            draft.findings.append(Finding(statement=f"No alert is currently attached to {desc}.", severity="low", evidence_ids=[t for t in targets if t in run.evidence.ids]))
        storylines = sorted({a.get("storyline_id") for a in items if a.get("storyline_id")})
        if storylines:
            draft.findings.append(Finding(statement="Storylines these alerts belong to: " + ", ".join(_b(sid) for sid in storylines) + ".", severity="high", evidence_ids=list(storylines)))
        draft.evidence_lines = [f"- Target: {desc}"] + [f"- {_alert_ref(a)}" for a in items[:10]]
        techs = sorted({str(t) for a in items for t in a.get("techniques") or []})
        draft.impact_lines = [
            f"- Techniques observed: {', '.join(techs[:12]) or 'none'}." + (" The alerts are correlated into a storyline - treat them as one incident." if storylines else ""),
            f"- {sum(1 for a in items if a.get('reaches_crown_jewel'))} of {len(items)} alert(s) sit on an asset with a path to a crown jewel.",
        ]
        draft.actions = [f"Open {_b(items[0]['id'])} first; it carries the highest contextual score." if items else f"Nothing to triage on {desc} right now.", f"Run the blast radius of {_b(targets[0])} to see what the alerts put at risk."]
        draft.followups = [f"What can an attacker reach from `{targets[0]}`?", f"Why is `{items[0]['id']}` risky?" if items else DEMO_QUESTIONS[5], DEMO_QUESTIONS[11]]
        draft.confidence = 0.85 if items else 0.6
        return draft

    def _pb_what_is(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        node_id = slots.primary()
        if not node_id:
            words = _notable_words(question)
            hits = run.search_all(" ".join(words[:4]), limit=8) if words else []
            # only accept a hit that shares a real word with the question (never bind "what is the weather" to a node
            # that merely contains "the")
            ranked = sorted(((_hit_overlap(h, words), float(h.get("score") or 0), h) for h in hits), key=lambda t: (-t[0], -t[1]))
            if ranked and ranked[0][0] >= 1:
                node_id = ranked[0][2]["id"]
        if not node_id:
            return self._pb_help(run, question, slots, context, note="I could not resolve that entity; try a node id or an exact hostname.")
        card = run.result("get_entity", id=node_id)
        node = card.get("node") or {}
        props = node.get("props") or {}
        alerts = [a for a in card.get("alerts") or [] if isinstance(a, Mapping)]
        ti = card.get("threat_intel") or {}
        draft = Draft(summary=f"{_node_ref(node)} - category {node.get('category')}, degree in {_g(card, 'degree', 'in', default=0)} / out {_g(card, 'degree', 'out', default=0)}, {len(alerts)} alert(s) on it.", focus=[node_id])
        keyprops = {k: v for k, v in props.items() if k not in ("raw", "statements", "body", "score_breakdown", "stages") and v not in (None, "", [], {})}
        draft.findings.append(Finding(statement="Key properties: " + "; ".join(f"{k}={v}" for k, v in list(keyprops.items())[:12]) + ".", evidence_ids=[node_id]))
        etc = card.get("edge_type_counts") or {}
        if etc:
            draft.findings.append(Finding(statement="Relationships: " + ", ".join(f"{k} x{v}" for k, v in sorted(etc.items(), key=lambda kv: -int(kv[1]))[:10]) + ".", evidence_ids=[node_id]))
        for a in alerts[:5]:
            draft.findings.append(Finding(statement=_alert_ref(a) + ".", severity=a.get("contextual_band") if a.get("contextual_band") in ("low", "medium", "high", "critical") else None, evidence_ids=[a["id"], node_id]))
        if ti and (ti.get("matches") or ti.get("actors")):
            draft.findings.append(Finding(statement=f"Threat intel: {ti.get('summary') or str(len(ti.get('matches') or [])) + ' IOC match(es)'}.", severity="high", evidence_ids=[node_id] + [a.get("id") for a in ti.get("actors") or []][:3]))
        draft.evidence_lines = [f"- {_node_ref(node)}"] + [f"- {_alert_ref(a)}" for a in alerts[:5]]
        tags = node.get("tags") or []
        draft.impact_lines = [f"- Tags: {', '.join(tags) or 'none'}." + (" This is a crown jewel." if "crown_jewel" in tags else "") + (" Internet exposed." if "internet_exposed" in tags else "")]
        draft.actions = [f"Expand the neighborhood of {_b(node_id)} to see its connections.", f"Run the blast radius of {_b(node_id)} to see what an attacker could reach."]
        draft.followups = [f"Show me the neighborhood of `{node_id}`.", f"What is the blast radius of `{node_id}`?", DEMO_QUESTIONS[5]]
        draft.confidence = 0.85
        return draft

    def _pb_neighborhood(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        node_id = slots.primary()
        if not node_id:
            return self._pb_help(run, question, slots, context, note="Name the node to expand (id or hostname).")
        depth = 2 if re.search(r"\b(2|two) hops?\b", question, re.I) else 1
        card = run.result("get_entity", id=node_id)
        nb = run.result("get_neighborhood", id=node_id, depth=depth, max_nodes=80)
        nodes = [n for n in nb.get("nodes") or [] if isinstance(n, Mapping) and n.get("id") != node_id]
        by_label = nb.get("nodes_by_label") or {}
        draft = Draft(summary=f"**{len(nodes)} node(s) within {depth} hop(s) of {_node_ref(card.get('node')) if card.get('node') else _b(node_id)}** ({nb.get('edge_count', 0)} edges" + (", truncated" if nb.get("truncated") else "") + ").", focus=[node_id])
        draft.findings.append(Finding(statement="By label: " + ", ".join(f"{k} x{v}" for k, v in sorted(by_label.items(), key=lambda kv: -int(kv[1]))) + ".", evidence_ids=[node_id]))
        notable = [n for n in nodes if set(n.get("tags") or []) & {"crown_jewel", "internet_exposed", "ioc_match"} or n.get("label") in ("Alert", "IamRole", "Credential", "Storyline")]
        if notable:
            draft.findings.append(Finding(statement="Notable neighbours: " + ", ".join(f"{_b(n['id'])} ({n.get('label')}{', ' + ','.join(n.get('tags') or []) if n.get('tags') else ''})" for n in notable[:10]) + ".", severity="medium", evidence_ids=[n["id"] for n in notable[:10]]))
        draft.evidence_lines = [f"- {_b(n['id'])} {n.get('name')} ({n.get('label')})" for n in nodes[:20]]
        edge_types: dict[str, int] = {}
        for e in nb.get("edges") or []:
            edge_types[e.get("type")] = edge_types.get(e.get("type"), 0) + 1
        draft.impact_lines = ["- Edge types: " + ", ".join(f"{k} x{v}" for k, v in sorted(edge_types.items(), key=lambda kv: -kv[1])[:12]) + "."]
        draft.actions = [f"Follow HAS_ROLE / CAN_ASSUME / CAN_ACCESS edges from {_b(node_id)} with the blast radius tool.", "Filter the neighborhood by edge type to isolate identity or telemetry links."]
        draft.followups = [f"What is the blast radius of `{node_id}`?", f"Which alerts sit on `{node_id}`?", DEMO_QUESTIONS[0]]
        draft.confidence = 0.85
        return draft

    def _pb_why_risky(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        alert_data = self._resolve_alert(run, slots, question, context)
        if not alert_data:
            return self._pb_help(run, question, slots, context, note="Which alert? Give its id or select it on the canvas.")
        alert = self._alert_of(alert_data)
        risk = alert_data.get("risk") or run.result("explain_risk", alert_id=alert["id"])
        factors = sorted([f for f in risk.get("factors") or [] if isinstance(f, Mapping)], key=lambda f: -float(f.get("contribution") or 0))
        story = alert_data.get("storyline")
        insights = [i for i in alert_data.get("insights") or [] if isinstance(i, Mapping)]
        draft = Draft(summary=f"{_alert_ref(alert)} scores **{risk.get('contextual_score')}** ({risk.get('band')}) - raw {float(risk.get('raw_score') or 0):.0f}, rails {', '.join(risk.get('rails') or []) or 'none'}; vendor ranked it #{alert.get('vendor_rank_position') or '?'} but it is #{alert.get('contextual_rank_position') or '?'} contextually.", focus=[alert["id"]])
        for f in factors:
            draft.findings.append(Finding(statement=f"{f.get('label') or f.get('key')}: value {float(f.get('value') or 0):.2f} x weight {float(f.get('weight') or 0):.2f} -> +{float(f.get('contribution') or 0):.1f} points - {f.get('reason')}", severity=None, evidence_ids=[alert["id"]] + list(f.get("evidence_ids") or [])[:6]))
        for i in insights[:4]:
            draft.findings.append(Finding(statement=f"Insight ({i.get('kind')}, {i.get('hops')} hops across {', '.join(i.get('sources') or [])}): {i.get('statement')}", severity="high" if float(i.get("importance") or 0) >= 0.7 else "medium", evidence_ids=list(i.get("evidence_node_ids") or [])[:8] + list(i.get("evidence_edge_ids") or [])[:4]))
        if story:
            draft.findings.append(Finding(statement=f"Correlated into storyline {_b(story.get('id'))} \"{story.get('title')}\" (score {story.get('contextual_score')}, {story.get('stage_count')} stages).", severity="critical", evidence_ids=[story.get("id"), alert["id"]]))
        draft.evidence_lines = [f"- Reasons: {', '.join(risk.get('reasons') or alert.get('graph_reasons') or []) or 'none'}", "- Flat view: " + "; ".join(f"{k}={v}" for k, v in list((alert_data.get("flat_view") or {}).items())[:6])]
        draft.impact_lines = [f"- The vendor label ({alert.get('vendor_severity')}) is only 30% of the score; 70% is graph context (exposure, privilege, data, threat intel, correlation)."]
        draft.actions = ["Follow the highest-contributing factor's evidence on the canvas.", "If a rail applied, check the storyline / TI edge that triggered it."]
        draft.followups = [f"What can an attacker reach from `{alert['id']}`?", DEMO_QUESTIONS[6], DEMO_QUESTIONS[11]]
        draft.confidence = 0.9
        return draft

    def _pb_summarize_storyline(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        storyline_id = slots.storylines[0] if slots.storylines else context.get("storyline_id")
        if not storyline_id:
            listing = run.result("list_storylines")
            items = [s for s in listing.get("items") or [] if isinstance(s, Mapping)]
            ql = question.lower()
            pick = next((s for s in items if any(tok and tok in ql for tok in [str(s.get("actor_name") or "").lower(), str(s.get("campaign_name") or "").lower(), str(s.get("id", "")).split(":")[-1].split("-")[0]])), items[0] if items else None)
            storyline_id = pick.get("id") if pick else None
        if not storyline_id:
            return self._pb_help(run, question, slots, context, note="There is no storyline to summarize.")
        s = run.result("get_storyline", storyline_id=storyline_id)
        stages = [st for st in s.get("stages") or [] if isinstance(st, Mapping)]
        draft = Draft(summary=f"**{s.get('title')}** ({_b(s.get('id'))}) - {s.get('stage_count')} stages from {_fmt_time(s.get('first_event'))} to {_fmt_time(s.get('last_event'))}, contextual score {s.get('contextual_score')}, attributed to {s.get('actor_name') or 'unknown actor'}{' / ' + s['campaign_name'] if s.get('campaign_name') else ''}.", focus=[storyline_id])
        draft.findings.append(Finding(statement=s.get("summary") or "Storyline summary unavailable.", severity="critical", evidence_ids=[storyline_id] + list(s.get("alert_ids") or [])[:6]))
        for st in stages:
            draft.findings.append(Finding(statement=f"Stage {st.get('order')} {st.get('stage')} ({', '.join(st.get('technique_ids') or []) or '-'}) {_fmt_time(st.get('time'))}: {st.get('summary') or ''} [{', '.join(_b(a) for a in (st.get('alert_ids') or [])[:2]) or 'cloud audit only'}]", severity="high", evidence_ids=list(st.get("alert_ids") or []) + list(st.get("node_ids") or [])[:4]))
        draft.evidence_lines = [f"- Alerts: {', '.join(_b(a) for a in (s.get('alert_ids') or [])[:12])}", f"- Crown jewels reached: {', '.join(_b(c) for c in s.get('crown_jewels_reached') or []) or 'none'}"] + ([f"- Actor {_b(s.get('actor_id'))}, campaign {_b(s.get('campaign_id'))}"] if s.get("actor_id") else [])
        draft.impact_lines = [f"- {len(s.get('crown_jewels_reached') or [])} crown jewel(s) reached; {len(s.get('alert_ids') or [])} alerts across the kill chain, most of them medium/low in the vendor console."]
        draft.actions = ["Contain the pivot host and rotate the involved roles (see the containment simulation).", "Draft the incident report from the stage list; every stage carries its alert and node ids."]
        draft.followups = [DEMO_QUESTIONS[11], DEMO_QUESTIONS[6], DEMO_QUESTIONS[8]]
        draft.confidence = 0.9
        return draft

    def _pb_list_storylines(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any]) -> Draft:
        listing = run.result("list_storylines")
        items = [s for s in listing.get("items") or [] if isinstance(s, Mapping)]
        draft = Draft(summary=f"**{len(items)} correlated storyline(s)** in the estate.", focus=[s["id"] for s in items[:3]])
        for s in items:
            draft.findings.append(Finding(statement=f"{_b(s.get('id'))} \"{s.get('title')}\" - score {s.get('contextual_score')}, {s.get('stage_count')} stages, {len(s.get('alert_ids') or [])} alerts, actor {s.get('actor_name') or 'unknown'}, crown jewels reached {len(s.get('crown_jewels_reached') or [])}.", severity="critical" if int(s.get("contextual_score") or 0) >= 90 else "high", evidence_ids=[s["id"]] + list(s.get("alert_ids") or [])[:5]))
        if not items:
            draft.findings.append(Finding(statement="No storyline has been correlated.", severity="low"))
        draft.evidence_lines = [f"- {_b(s['id'])}: {', '.join(s.get('alert_ids') or [])[:200]}" for s in items]
        draft.impact_lines = ["- Storylines chain alerts and cloud events by shared hosts, credentials, IPs and IOC/campaign links across the EDR/cloud boundary."]
        draft.actions = [f"Summarize `{items[0]['id']}` and run the containment simulation." if items else "Nothing to do."]
        draft.followups = [f"Summarize storyline `{items[0]['id']}`." if items else DEMO_QUESTIONS[5], DEMO_QUESTIONS[5], DEMO_QUESTIONS[11]]
        draft.confidence = 0.9
        return draft

    def _pb_help(self, run: _Run, question: str, slots: Slots, context: Mapping[str, Any], note: str | None = None) -> Draft:
        draft = Draft(summary=(note + " " if note else "") + "I am the Throughline analyst (offline mode). I answer graph questions about Larkspur's alerts, assets, identities, data and threat intel with cited node ids.", confidence=0.2, intent="help")
        draft.findings = [Finding(statement=f"Try: {q}") for q in DEMO_QUESTIONS[:6]]
        draft.evidence_lines = ["- Intents I understand: " + ", ".join(f"`{intent}`" for intent, _q, _t in PLAYBOOK_HINTS) + ", `alerts_on_entity`, `what_is_entity`, `neighborhood_of_entity`, `why_is_alert_risky`, `summarize_storyline`, `list_storylines`."]
        draft.impact_lines = ["- Name hosts (BAS-01, WKS-3391), alert ids (ldt-a009), roles (LarkspurBastionSSMRole), buckets, actors (Cinder Jackal) or select something on the canvas and say 'this alert'."]
        draft.actions = ["Ask one of the questions above, or select an alert and ask 'why is this alert risky?'."]
        draft.followups = [DEMO_QUESTIONS[1], DEMO_QUESTIONS[4], DEMO_QUESTIONS[5]]
        return draft
