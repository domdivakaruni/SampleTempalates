"""Attack-graph semantics: how a compromise propagates along each edge type.

This module is the single place where security meaning is attached to the schema. Every traversal engine
(blast radius, attack paths, containment, questions) asks :func:`moves` for the *semantic moves* available from
a compromised node instead of looking at raw edges.

Conventions
-----------
* ``direction`` is relative to the raw edge: ``forward`` follows src -> dst, ``reverse`` follows dst -> src.
* ``p`` is the probability that control of the source of the move gives control of its target.
* ``depth_cost`` is how much of a depth budget a move consumes. Entity-resolution moves (an alert onto its anchor,
  an endpoint onto the VM it *is*) cost nothing: they do not represent attacker movement. Reported ``hops`` in
  paths still count every edge.
* ``access`` marks moves that follow identity / access rights (role chains, effective access, credentials). The
  ``access`` mode is used for privilege and data factors and for "assets that can reach X" questions; the ``full``
  mode adds observed movement (lateral movement, cached logons, network routing, image sharing).
"""
from __future__ import annotations

import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from throughline.graph.context_graph import ContextGraph
from throughline.simulator.catalog.techniques import KILL_CHAIN_STAGES, TACTIC_STAGE, TECHNIQUES

Mode = str  # "full" | "access"

HUB_OUT_DEGREE = 300
INTERNET_ID = "internet:global:internet"
REGULATED_CLASSES = {"PCI", "PII", "PHI", "SECRETS"}
EXPLOITED_STATUSES = {"active", "mass_exploitation"}
EXPLOITATION_RANK = {"none": 0, "poc_public": 1, "active": 2, "mass_exploitation": 3}

DATA_HOLDER_LABELS = {"StorageBucket", "Database", "Secret"}
IDENTITY_LABELS = {"IamRole", "IamUser", "HumanUser", "ServiceAccount", "Credential", "AccessKey", "Group"}
COMPUTE_LABELS = {"VirtualMachine", "Workload", "ServerlessFunction", "KubernetesCluster", "Endpoint"}


@dataclass(frozen=True)
class Move:
    """One semantic step from ``src`` to ``dst`` along a raw edge of type ``etype``."""

    src: str
    dst: str
    p: float
    etype: str
    direction: str  # forward | reverse | implicit
    depth_cost: int = 1
    access: bool = True
    data: dict[str, Any] | None = None

    @property
    def cost(self) -> float:
        return -math.log(max(min(self.p, 0.999), 1e-6))


PFunc = Callable[[dict[str, Any]], float]


@dataclass(frozen=True)
class Rule:
    direction: str  # forward | reverse | both | none
    p_forward: float | PFunc = 0.0
    p_reverse: float | PFunc = 0.0
    depth_cost: int = 1
    access: bool = True
    skip_if: Callable[[dict[str, Any]], bool] | None = None
    access_reverse: bool | None = None  # defaults to ``access``; lets a direction count as movement only

    def is_access(self, direction: str) -> bool:
        if direction == "reverse" and self.access_reverse is not None:
            return self.access_reverse
        return self.access


def _p_can_access(data: dict[str, Any]) -> float:
    level = str(data.get("access_level") or "read").lower()
    if level in ("write", "admin"):
        return 0.9
    if level == "list":
        return 0.6
    return 0.7


def _p_same_as(data: dict[str, Any]) -> float:
    conf = data.get("confidence")
    try:
        conf_f = float(conf) if conf is not None else 1.0
    except (TypeError, ValueError):
        conf_f = 1.0
    return 0.95 * max(0.0, min(conf_f, 1.0))


def _is_transitive(data: dict[str, Any]) -> bool:
    return bool(data.get("transitive"))


RULES: dict[str, Rule] = {
    "SAME_AS": Rule("both", _p_same_as, _p_same_as, depth_cost=0),
    "HAS_ROLE": Rule("forward", 0.9),
    "CAN_ASSUME": Rule("forward", 0.8),
    "CAN_ACCESS": Rule("forward", _p_can_access, skip_if=_is_transitive),
    "UNLOCKS": Rule("forward", 0.8),
    "MAPS_TO": Rule("forward", 0.8),
    "HAS_ACCESS_KEY": Rule("forward", 0.7),
    "CREDENTIAL_FOR": Rule("forward", 0.9),
    "DERIVED_FROM": Rule("reverse", p_reverse=0.9),
    "LOGGED_ON": Rule("both", 0.5, 0.6, access=False),
    # endpoint -> its primary user counts as access (SSO sessions live on the device); user -> endpoint is movement
    "PRIMARY_USER": Rule("both", 0.6, 0.6, access=True, access_reverse=False),
    "LATERAL_MOVEMENT_TO": Rule("forward", 0.8, access=False),
    "ROUTES_TO": Rule("forward", 0.5, access=False),
    "HAS_NODE": Rule("reverse", p_reverse=0.6, access=False),
    "RUNS_IMAGE": Rule("reverse", p_reverse=0.7, access=False),
    "ON_ENDPOINT": Rule("forward", 1.0, depth_cost=0),
    "ON_RESOURCE": Rule("forward", 1.0, depth_cost=0),
    # EXPOSES is only ever followed *from* the Internet node; its probability depends on the exposed asset.
    "EXPOSES": Rule("forward", 0.5, access=False),
}

ACCESS_EDGE_TYPES = frozenset(t for t, r in RULES.items() if r.access)
TRAVERSED_EDGE_TYPES = frozenset(RULES)

# Probability of the Internet -> asset step (docs/02 section 4(b)).
P_EXPOSED_EXPLOITABLE = 0.9
P_EXPOSED_DEFAULT = 0.5
P_IMPLICIT_UNLOCKS = 0.7


def _p_of(spec: float | PFunc, data: dict[str, Any]) -> float:
    return float(spec(data)) if callable(spec) else float(spec)


class Semantics:
    """Semantic moves over a ContextGraph with small per-node caches (exploitability, hub detection)."""

    def __init__(self, graph: ContextGraph) -> None:
        self.graph = graph
        self._exploitable: dict[str, bool] = {}

    # ------------------------------------------------------------------ exposure

    def asset_exploitable(self, asset_id: str) -> bool:
        """True when the asset carries a vulnerability that is exploitable or under active exploitation."""
        cached = self._exploitable.get(asset_id)
        if cached is not None:
            return cached
        result = False
        for cve, d in self.graph.out_edges(asset_id, ("VULNERABLE_TO",)):
            if d.get("exploitable"):
                result = True
                break
            status = self.graph.get(cve, "exploitation_status") or "none"
            if status in EXPLOITED_STATUSES:
                result = True
                break
        self._exploitable[asset_id] = result
        return result

    def p_exposes(self, asset_id: str) -> float:
        return P_EXPOSED_EXPLOITABLE if self.asset_exploitable(asset_id) else P_EXPOSED_DEFAULT

    # ------------------------------------------------------------------ moves

    def moves_for_edge(self, u: str, v: str, data: dict[str, Any]) -> list[Move]:
        etype = data.get("type")
        rule = RULES.get(etype or "")
        if rule is None or rule.direction == "none":
            return []
        if rule.skip_if is not None and rule.skip_if(data):
            return []
        out: list[Move] = []
        if rule.direction in ("forward", "both"):
            if etype == "EXPOSES":
                p = self.p_exposes(v)
            else:
                p = _p_of(rule.p_forward, data)
            if p > 0:
                out.append(Move(u, v, p, etype, "forward", rule.depth_cost, rule.is_access("forward"), data))
        if rule.direction in ("reverse", "both"):
            p = _p_of(rule.p_reverse, data)
            if p > 0:
                out.append(Move(v, u, p, etype, "reverse", rule.depth_cost, rule.is_access("reverse"), data))
        return out

    def implicit_moves(self, node_id: str) -> list[Move]:
        """Moves that exist because of node properties rather than edges.

        * ``StorageBucket.contains_credentials_for`` (a config bucket holding DB credentials) acts as an implicit
          UNLOCKS with p 0.7.
        * ``Secret.grants_access_to`` behaves the same way when no explicit UNLOCKS edge exists.
        """
        attrs = self.graph.node(node_id)
        if not attrs:
            return []
        targets: list[str] = []
        label = attrs.get("label")
        if label == "StorageBucket":
            targets = list(attrs.get("contains_credentials_for") or [])
        elif label == "Secret":
            targets = list(attrs.get("grants_access_to") or [])
        if not targets:
            return []
        explicit = {v for v, _ in self.graph.out_edges(node_id, ("UNLOCKS",))}
        return [
            Move(node_id, t, P_IMPLICIT_UNLOCKS, "UNLOCKS", "implicit", 1, True, {"type": "UNLOCKS", "implicit": True})
            for t in targets
            if t in self.graph and t not in explicit and t != node_id
        ]

    def moves(self, node_id: str, mode: Mode = "full", *, allow_internet: bool = False) -> list[Move]:
        """All semantic moves out of ``node_id`` (deduplicated to the best p per target)."""
        if node_id == INTERNET_ID and not allow_internet:
            return []
        g = self.graph
        found: list[Move] = []
        for v, d in g.out_edges(node_id):
            for m in self.moves_for_edge(node_id, v, d):
                if m.src == node_id:
                    found.append(m)
        for u, d in g.in_edges(node_id):
            for m in self.moves_for_edge(u, node_id, d):
                if m.src == node_id:
                    found.append(m)
        found.extend(self.implicit_moves(node_id))
        if mode == "access":
            found = [m for m in found if m.access]
        elif len(found) > HUB_OUT_DEGREE:
            # hub cap: very connected nodes are only expanded through access rights
            found = [m for m in found if m.access]
        best: dict[str, Move] = {}
        for m in found:
            if m.dst == node_id:
                continue
            cur = best.get(m.dst)
            if cur is None or m.p > cur.p or (m.p == cur.p and m.depth_cost < cur.depth_cost):
                best[m.dst] = m
        return sorted(best.values(), key=lambda m: (m.cost, m.dst))


# ---------------------------------------------------------------------- predicates on nodes


def _classes(attrs: dict[str, Any]) -> set[str]:
    vals = attrs.get("data_classifications") or []
    if isinstance(vals, str):
        vals = [vals]
    return {str(v).upper() for v in vals}


def is_crown_jewel(attrs: dict[str, Any] | None) -> bool:
    """Crown jewel: flagged as such, or a regulated data holder of high/critical sensitivity, or an admin role."""
    if not attrs:
        return False
    if attrs.get("crown_jewel") is True:
        return True
    label = attrs.get("label")
    if label in ("StorageBucket", "Database"):
        sens = str(attrs.get("sensitivity") or "").lower()
        if sens in ("critical", "high") and _classes(attrs) & REGULATED_CLASSES:
            return True
    if label == "IamRole" and attrs.get("is_admin") is True:
        return True
    return False


def is_data_holder(attrs: dict[str, Any] | None) -> bool:
    return bool(attrs) and attrs.get("label") in DATA_HOLDER_LABELS


def is_identity(attrs: dict[str, Any] | None) -> bool:
    return bool(attrs) and attrs.get("label") in IDENTITY_LABELS


def is_regulated(attrs: dict[str, Any] | None) -> bool:
    return bool(attrs) and bool(_classes(attrs) & REGULATED_CLASSES)


def data_classes(attrs: dict[str, Any] | None) -> list[str]:
    return sorted(_classes(attrs or {}))


def sensitivity_rank(attrs: dict[str, Any] | None) -> int:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(str((attrs or {}).get("sensitivity") or "none").lower(), 0)


# ---------------------------------------------------------------------- data sources


SOURCE_OF_LABEL: dict[str, str] = {
    "Endpoint": "falcon", "Process": "falcon", "File": "falcon", "LogonSession": "falcon", "Incident": "falcon",
    "CloudAccount": "wiz", "VPC": "wiz", "Subnet": "wiz", "SecurityGroup": "wiz", "LoadBalancer": "wiz",
    "VirtualMachine": "wiz", "KubernetesCluster": "wiz", "Workload": "wiz", "ContainerImage": "wiz",
    "ServerlessFunction": "wiz", "StorageBucket": "wiz", "Database": "wiz", "Secret": "wiz", "Internet": "wiz",
    "IpAddress": "wiz", "Domain": "wiz", "IamRole": "wiz", "IamUser": "wiz", "IamPolicy": "wiz", "AccessKey": "wiz",
    "Package": "wiz", "Vulnerability": "wiz", "ServiceAccount": "falcon", "Credential": "falcon",
    "HumanUser": "okta", "Group": "okta",
    "Application": "business", "Team": "business",
    "CloudEvent": "cloudtrail",
    "ThreatActor": "ti", "Campaign": "ti", "Malware": "ti", "AttackTechnique": "ti", "Indicator": "ti", "IntelReport": "ti",
    "Alert": "falcon", "Storyline": "derived",
}

ALERT_SOURCE_SYSTEM: dict[str, str] = {
    "falcon": "falcon", "cspm": "wiz", "waf": "waf", "ids": "ids", "cloud-anomaly": "cloudtrail", "okta": "okta",
}


def source_of(attrs: dict[str, Any] | None) -> str:
    """Which data source a node comes from (falcon / wiz / cloudtrail / ti / okta / business / waf / ids)."""
    if not attrs:
        return "unknown"
    label = attrs.get("label") or ""
    if label == "Alert":
        return ALERT_SOURCE_SYSTEM.get(str(attrs.get("source_system") or ""), "falcon")
    src = str(attrs.get("source") or "")
    if src and src != "derived":
        base = src.removesuffix("-sim")
        if base in ("wiz", "falcon", "cloudtrail", "waf", "ids", "okta", "ti", "business"):
            return base
    return SOURCE_OF_LABEL.get(label, "unknown")


def sources_crossed(graph: ContextGraph, node_ids: Iterable[str]) -> list[str]:
    out: list[str] = []
    for nid in node_ids:
        s = source_of(graph.node(nid))
        if s not in ("unknown", "derived") and s not in out:
            out.append(s)
    return out


# ---------------------------------------------------------------------- kill-chain helpers


CLOUD_EVENT_TECHNIQUES: dict[str, list[str]] = {
    "GetCallerIdentity": ["T1580", "T1078.004"],
    "ListAllMyBuckets": ["T1580", "T1078.004"],
    "ListRoles": ["T1580"],
    "ListUsers": ["T1580"],
    "DescribeInstances": ["T1580"],
    "DescribeDBInstances": ["T1580"],
    "AssumeRole": ["T1548.005", "T1078.004"],
    "ListBucket": ["T1530", "T1580"],
    "ListObjects": ["T1530"],
    "ListObjectsV2": ["T1530"],
    "GetObject": ["T1530", "T1567.002"],
    "GetSecretValue": ["T1555.006"],
    "CreateAccessKey": ["T1098.001"],
    "CreateUser": ["T1136.003"],
    "PutObject": ["T1567.002"],
}


def event_techniques(attrs: dict[str, Any] | None) -> list[str]:
    if not attrs:
        return []
    name = str(attrs.get("event_name") or "")
    return list(CLOUD_EVENT_TECHNIQUES.get(name, []))


def stage_number(technique_ids: Iterable[str], tactic: str | None = None) -> int:
    """Primary kill-chain stage (1-7) of an alert: its tactic if known, else its first known technique."""
    if tactic and tactic in TACTIC_STAGE:
        return TACTIC_STAGE[tactic]
    for t in technique_ids:
        info = TECHNIQUES.get(t)
        if info:
            return int(info["kill_chain_stage"])
    return 0


def stage_label(stage: int) -> str:
    return KILL_CHAIN_STAGES.get(stage, "Unknown")


def stages_covered(technique_ids: Iterable[str]) -> set[int]:
    out: set[int] = set()
    for t in technique_ids:
        info = TECHNIQUES.get(t)
        if info:
            out.add(int(info["kill_chain_stage"]))
    return out


def alert_stage(attrs: dict[str, Any] | None) -> int:
    if not attrs:
        return 0
    return stage_number(list(attrs.get("techniques") or []), attrs.get("tactic"))


def event_stage(attrs: dict[str, Any] | None) -> int:
    return stage_number(event_techniques(attrs))


LATERAL_TECHNIQUES: dict[str, str] = {
    "ssh": "T1021.004", "rdp": "T1021.001", "smb": "T1021.002", "psexec": "T1021.002", "winrm": "T1021.006",
}

EDGE_STAGE: dict[str, int] = {
    "EXPOSES": 1, "LATERAL_MOVEMENT_TO": 5, "LOGGED_ON": 5, "HAS_ROLE": 4, "CAN_ASSUME": 5, "MAPS_TO": 5,
    "CREDENTIAL_FOR": 4, "DERIVED_FROM": 5, "HAS_ACCESS_KEY": 4, "CAN_ACCESS": 6, "UNLOCKS": 6, "ROUTES_TO": 5,
    "HAS_NODE": 5, "RUNS_IMAGE": 5, "SAME_AS": 2, "ON_ENDPOINT": 2, "ON_RESOURCE": 2, "PRIMARY_USER": 4,
}


def stage_for_edge(etype: str, default: int = 2) -> int:
    return EDGE_STAGE.get(etype, default)

