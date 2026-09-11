"""Shared accumulator and constructors for the events stage.

``Ctx`` collects the graph nodes and edges every event generator emits (deduplicating nodes by id, keeping
edges as-is so parallel telemetry edges survive) and holds the :class:`Inventory` index the generators
target. The id/severity helpers and :func:`add_alert` keep every generator emitting the exact id shapes and
typed columns docs/03-graph-schema.md section 3.6 requires.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from throughline.simulator.catalog.techniques import TECHNIQUES, tactic_of, technique_node_id
from throughline.simulator.common import at, edge, node
from throughline.simulator.common import parse_ts as _parse_ts
from throughline.simulator.events.inventory_stub import Inventory

# vendor severity -> rank (0..4) as in docs/03 section 3.6
SEV_RANK: dict[str, int] = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Falcon numeric severity (0..100) shown in the flat view
FALCON_SEV_NUM: dict[str, int] = {"informational": 10, "low": 30, "medium": 50, "high": 70, "critical": 90}

# alert source_system -> provenance feed (docs/03 section 1 source enum)
SOURCE_FEED: dict[str, str] = {
    "falcon": "falcon-sim", "waf": "waf-sim", "ids": "ids-sim", "okta": "okta-sim",
    "cloud-anomaly": "cloudtrail-sim", "cspm": "wiz-sim",
}

PLATFORM_NAME: dict[str, str] = {"windows": "Windows", "linux": "Linux", "mac": "Mac"}


@dataclass
class Ctx:
    inv: Inventory
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    _seen: set[str] = field(default_factory=set, repr=False)

    # ------------------------------------------------------------------ accumulation
    def add_node(self, rec: dict[str, Any]) -> str:
        nid = rec["id"]
        if nid not in self._seen:
            self._seen.add(nid)
            self.nodes.append(rec)
        return nid

    def add_edge(self, rec: dict[str, Any]) -> dict[str, Any]:
        self.edges.append(rec)
        return rec

    def has_node(self, node_id: str) -> bool:
        return node_id in self._seen

    def node_ids(self) -> set[str]:
        return set(self._seen)

    # ------------------------------------------------------------------ typed constructors
    def n(self, node_id: str, label: str, name: str, props: dict[str, Any], *, source: str,
          source_id: str | None = None, first_seen: str | None = None, last_seen: str | None = None,
          confidence: float = 1.0) -> str:
        return self.add_node(node(node_id, label, name, props, source=source, source_id=source_id,
                                  first_seen=first_seen, last_seen=last_seen, confidence=confidence))

    def e(self, etype: str, src: str, dst: str, props: dict[str, Any] | None = None, *, source: str,
          first_seen: str | None = None, last_seen: str | None = None, confidence: float = 1.0) -> None:
        self.add_edge(edge(etype, src, dst, props or {}, source=source, first_seen=first_seen,
                           last_seen=last_seen, confidence=confidence))


# --------------------------------------------------------------------- id helpers


def aid_of(endpoint_id: str) -> str:
    """``endpoint:falcon:aid-wks3391`` -> ``aid-wks3391``."""
    return endpoint_id.split(":")[-1]


def epoch(ts_str: str) -> int:
    return int(_parse_ts(at(ts_str)).timestamp())


def process_id(aid: str, pid: int, start_ts: str) -> str:
    return f"process:falcon:{aid}:{pid}:{epoch(start_ts)}"


def file_id(sha256: str) -> str:
    return f"file:sha256:{sha256}"


def ip_id(addr: str) -> str:
    return f"ip:v4:{addr}"


def domain_id(fqdn: str) -> str:
    return f"domain:dns:{fqdn}"


# --------------------------------------------------------------------- alert constructor


def add_alert(
    ctx: Ctx,
    *,
    alert_id: str,
    source_system: str,
    alert_type: str,
    title: str,
    description: str,
    severity: str,
    detected_at: str,
    techniques: list[str],
    entity_id: str,
    entity_label: str,
    raw: dict[str, Any],
    tactic: str | None = None,
    hostname: str | None = None,
    user: str | None = None,
    on_endpoint: str | None = None,
    on_resource: str | None = None,
    vendor_incident_id: str | None = None,
    change_ticket: str | None = None,
    status: str = "new",
) -> str:
    """Create an Alert node with every typed column the schema fills at generation time.

    Leaves the analytics-owned columns (``contextual_score``, ``storyline_id``, ...) unset. Adds the
    ``ON_ENDPOINT`` / ``ON_RESOURCE`` anchor and one ``USES_TECHNIQUE`` edge per referenced technique id.
    ``INVOLVES`` edges are added by the caller (it knows the process/file/ip/credential roles).
    """
    feed = SOURCE_FEED.get(source_system, f"{source_system}-sim")
    detected = at(detected_at)
    tac = tactic if tactic is not None else (tactic_of(techniques) or "")
    props = {
        "source_system": source_system,
        "alert_type": alert_type,
        "title": title,
        "description": description,
        "vendor_severity": severity,
        "vendor_severity_rank": SEV_RANK[severity],
        "status": status,
        "detected_at": detected,
        "techniques": list(techniques),
        "tactic": tac,
        "entity_id": entity_id,
        "entity_label": entity_label,
        "hostname": hostname,
        "user": user,
        "vendor_incident_id": vendor_incident_id,
        "change_ticket": change_ticket,
        "raw": raw,
    }
    ctx.n(alert_id, "Alert", title, props, source=feed, source_id=alert_id.split(":")[-1],
          first_seen=detected, last_seen=detected)
    if on_endpoint:
        ctx.e("ON_ENDPOINT", alert_id, on_endpoint, source=feed, first_seen=detected, last_seen=detected)
    if on_resource:
        ctx.e("ON_RESOURCE", alert_id, on_resource, source=feed, first_seen=detected, last_seen=detected)
    for tid in techniques:
        if tid in TECHNIQUES:
            ctx.e("USES_TECHNIQUE", alert_id, technique_node_id(tid), source=feed,
                  first_seen=detected, last_seen=detected)
    return alert_id


def involves(ctx: Ctx, alert_id: str, target_id: str, role: str, *, source: str = "falcon-sim",
             when: str | None = None) -> None:
    ctx.e("INVOLVES", alert_id, target_id, {"role": role}, source=source, first_seen=when, last_seen=when)


def falcon_raw(
    *,
    alert_id: str,
    endpoint: dict[str, Any],
    severity: str,
    techniques: list[str],
    display_name: str,
    description: str,
    disposition: str,
    filename: str,
    filepath: str,
    cmdline: str,
    sha256: str,
    user_name: str,
    timestamp: str,
    incident_id: str | None = None,
    parent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The Falcon *alerts-v2* flat view exactly as a Falcon analyst sees it (no cloud context)."""
    tid = techniques[0] if techniques else None
    tech = TECHNIQUES.get(tid or "", {})
    aid = endpoint["id"].split(":")[-1]
    return {
        "composite_id": f"ldt:{aid}:{epoch(timestamp)}",
        "device": {
            "device_id": aid,
            "hostname": endpoint.get("hostname"),
            "local_ip": endpoint.get("private_ip"),
            "platform_name": PLATFORM_NAME.get(endpoint.get("os_family", ""), "Unknown"),
        },
        "severity": FALCON_SEV_NUM[severity],
        "severity_name": severity.capitalize(),
        "tactic": tech.get("tactic"),
        "technique": tech.get("name"),
        "technique_id": tid,
        "display_name": display_name,
        "description": description,
        "pattern_disposition": disposition,
        "filename": filename,
        "filepath": filepath,
        "cmdline": cmdline,
        "sha256": sha256,
        "parent_details": parent or {},
        "user_name": user_name,
        "timestamp": at(timestamp),
        "incident_id": incident_id,
    }
