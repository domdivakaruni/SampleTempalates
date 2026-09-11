"""STIX-2.1-like raw threat-intel feeds written under ``raw/ti/``.

These loosely mimic real feed objects (intrusion sets, campaigns, malware, indicators with STIX pattern
strings, reports, a CISA-KEV-like exploited-CVE list, and ATT&CK attack patterns). They are *not* loaded into
the graph; the graph fragments come from ``generate.py``. Everything is deterministic and fictional.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from throughline.simulator.catalog.cves import CVES
from throughline.simulator.catalog.techniques import TECHNIQUES
from throughline.simulator.common import stable_hex, write_jsonl
from throughline.simulator.threat_intel import catalog as cat

if TYPE_CHECKING:
    from throughline.simulator.threat_intel.generate import Model


def _stix_id(kind: str, key: str) -> str:
    h = stable_hex("stix", kind, key, length=32)
    return f"{kind}--{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _stixts(iso: str) -> str:
    """Convert an ``...Z`` timestamp to STIX millisecond form ``...000Z``."""
    return iso[:-1] + ".000Z" if iso.endswith("Z") else iso


_BASELINE = "2025-01-01T00:00:00.000Z"

_STIX_PATTERN = {
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "ipv4": "[ipv4-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "filename": "[file:name = '{v}']",
}


def _write_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, sort_keys=False)
        f.write("\n")
    return path


def _intrusion_sets() -> list[dict[str, Any]]:
    out = []
    for a in cat.ACTORS:
        out.append({
            "type": "intrusion-set", "spec_version": "2.1", "id": _stix_id("intrusion-set", a.id),
            "created": _BASELINE, "modified": _BASELINE, "name": a.name, "aliases": list(a.aliases),
            "description": a.description, "primary_motivation": a.motivation,
            "resource_level": "organization" if a.sophistication in ("high", "advanced") else "group",
            "goals": [f"target {s}" for s in a.targeted_sectors],
            "x_throughline_id": a.id, "x_origin": a.origin, "x_sophistication": a.sophistication,
            "x_targeted_regions": list(a.targeted_regions), "x_sector_targeting_relevance": a.relevance,
            "x_active": a.active,
        })
    return out


def _campaigns() -> list[dict[str, Any]]:
    out = []
    for c in cat.CAMPAIGNS:
        created = _stixts(f"{c.started}T00:00:00Z")
        out.append({
            "type": "campaign", "spec_version": "2.1", "id": _stix_id("campaign", c.id),
            "created": created, "modified": created, "name": c.name, "description": c.description,
            "first_seen": created, "objective": c.objective,
            "x_throughline_id": c.id, "x_attributed_to": c.actor_id, "x_status": c.status,
            "x_targeted_sectors": list(c.targeted_sectors), "x_sector_targeting_relevance": c.relevance,
        })
    return out


def _malware() -> list[dict[str, Any]]:
    out = []
    for mw in cat.MALWARE:
        out.append({
            "type": "malware", "spec_version": "2.1", "id": _stix_id("malware", mw.id),
            "created": _BASELINE, "modified": _BASELINE, "name": mw.name, "is_family": True,
            "malware_types": [mw.malware_type], "description": mw.description,
            "x_throughline_id": mw.id, "x_platforms": list(mw.platforms),
        })
    return out


def _indicators(m: Model) -> list[dict[str, Any]]:
    out = []
    for ind in m.indicators:
        pattern = _STIX_PATTERN[ind["ioc_type"]].format(v=ind["value"])
        valid_from = _stixts(ind["first_seen"])
        out.append({
            "type": "indicator", "spec_version": "2.1", "id": _stix_id("indicator", ind["id"]),
            "created": valid_from, "modified": _stixts(ind["last_seen"]), "name": ind["value"],
            "indicator_types": ["malicious-activity"], "pattern": pattern, "pattern_type": "stix",
            "valid_from": valid_from, "confidence": int(round(ind["confidence"] * 100)),
            "x_throughline_id": ind["id"], "x_ioc_type": ind["ioc_type"], "x_report_id": ind["report_id"],
            "x_actor_id": ind["actor_id"], "x_campaign_id": ind["campaign_id"],
            "x_malware_id": ind["malware_id"], "x_kill_chain_stage": ind["kill_chain_stage"],
            "x_active": ind["active"],
        })
    return out


def _reports(m: Model) -> list[dict[str, Any]]:
    from throughline.simulator.catalog.techniques import technique_node_id

    out = []
    for rr in m.reports:
        published = _stixts(rr["published"])
        object_refs = (list(rr["actor_ids"]) + list(rr["campaign_ids"]) + list(rr["malware_ids"])
                       + [f"cve:{c}" for c in rr["cve_ids"]]
                       + [technique_node_id(t) for t in rr["technique_ids"]])
        out.append({
            "type": "report", "spec_version": "2.1", "id": _stix_id("report", rr["id"]),
            "created": published, "modified": published, "name": rr["title"], "published": published,
            "report_types": ["threat-report"], "description": rr["summary"], "object_refs": object_refs,
            "x_throughline_id": rr["id"], "x_publisher": rr["publisher"], "x_confidence": rr["report_confidence"],
            "x_tlp": rr["tlp"], "x_indicator_count": rr["indicator_count"],
            "x_targeted_sectors": list(rr["targeted_sectors"]), "x_body": rr["body"],
        })
    return out


def _exploited_cves(m: Model) -> list[dict[str, Any]]:
    out = []
    for row in m.exploited:
        cve = CVES[row["cve_id"]]
        added = row["date_added"]
        due = (datetime.strptime(added, "%Y-%m-%d").replace(tzinfo=UTC) + timedelta(days=21)).strftime("%Y-%m-%d")
        ransomware = "Known" if row["status"] == "mass_exploitation" else "Unknown"
        names = ", ".join(sorted({a["name"] for a in row["attributions"]}))
        out.append({
            "cveID": cve.cve_id, "vendorProject": cve.component, "product": cve.component,
            "vulnerabilityName": cve.description[:80], "dateAdded": added, "shortDescription": cve.description,
            "requiredAction": "Apply vendor mitigations or discontinue use of the affected product.",
            "dueDate": due, "knownRansomwareCampaignUse": ransomware,
            "notes": f"Fictional attribution (Throughline prototype): observed use by {names}.",
            "x_exploitation_status": row["status"], "x_synthetic": cve.synthetic,
            "x_attributions": row["attributions"],
        })
    return out


def _attack_patterns() -> list[dict[str, Any]]:
    out = []
    for tid, meta in TECHNIQUES.items():
        base = tid.split(".")[0]
        phase = str(meta["tactic"]).lower().replace(" ", "-")
        out.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": _stix_id("attack-pattern", tid),
            "created": _BASELINE, "modified": _BASELINE, "name": str(meta["name"]),
            "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                     "url": f"https://attack.mitre.org/techniques/{base.replace('.', '/')}/"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": phase}],
            "x_throughline_id": f"technique:attack:{tid}", "x_tactic": str(meta["tactic"]),
            "x_kill_chain_stage": int(meta["kill_chain_stage"]),
        })
    return out


def write_all(raw_dir: Path, m: Model) -> list[Path]:
    raw_dir = Path(raw_dir)
    paths: list[Path] = []
    paths.append(_write_json(raw_dir / "intrusion_sets.json", _intrusion_sets()))
    paths.append(_write_json(raw_dir / "actors.json", _intrusion_sets()))  # doc-03 alias
    paths.append(_write_json(raw_dir / "campaigns.json", _campaigns()))
    paths.append(_write_json(raw_dir / "malware.json", _malware()))
    write_jsonl(raw_dir / "indicators.jsonl", _indicators(m))
    paths.append(raw_dir / "indicators.jsonl")
    paths.append(_write_json(raw_dir / "reports.json", _reports(m)))
    paths.append(_write_json(raw_dir / "exploited_cves.json", _exploited_cves(m)))
    paths.append(_write_json(raw_dir / "attack_patterns.json", _attack_patterns()))
    paths.append(_write_json(raw_dir / "low_confidence_plants.json", m.plants))
    return paths
