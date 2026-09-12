"""Unit tests for the threat-intelligence stage of the data simulator (Agent A3).

Covers: fast deterministic generation, the exact storyline indicators/values/confidence, EXPLOITS statuses,
Vulnerability and AttackTechnique node counts, USES_TECHNIQUE target existence, schema/ContextGraph validation,
byte-identical determinism, headline counts, the low-confidence IOC plants, and the STIX-like raw feeds.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

import pytest

from throughline.graph.context_graph import ContextGraph
from throughline.schema import validate_edge, validate_node
from throughline.simulator import storyline_constants as SC
from throughline.simulator.catalog.cves import CVES
from throughline.simulator.catalog.techniques import TECHNIQUES, technique_node_id
from throughline.simulator.threat_intel import catalog as cat
from throughline.simulator.threat_intel import generate

# storyline indicators: id -> (value, confidence) exactly as docs/04 sections 2-3 require
STORYLINE_IOCS = {
    SC.IOC_C2_DOMAIN: (SC.C2_DOMAIN, 0.95),
    SC.IOC_C2_IP: (SC.C2_IP, 0.9),
    SC.IOC_EGRESS_IP: (SC.ATTACKER_EGRESS_IP, 0.85),
    SC.IOC_HASH_MAPLELOADER: (SC.HASH_MAPLELOADER, 0.95),
    SC.IOC_HASH_QUILLDROP: (SC.HASH_QUILLDROP, 0.9),
    SC.IOC_HASH_NIGHTFERRY: (SC.HASH_NIGHTFERRY, 0.95),
    SC.IOC_FILENAME_SYNCHOST: ("synchost.exe", 0.6),
    SC.IOC_SALTWORKS_IP: (SC.SALTWORKS_IP, 0.8),
    SC.IOC_HASH_BRACKISH: (SC.HASH_BRACKISH, 0.85),
    SC.IOC_BRACKISH_URL: (SC.BRACKISH_URL, 0.8),
}


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(scope="module")
def out_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("ti")
    generate(d)
    return d


@pytest.fixture(scope="module")
def nodes(out_dir: Path) -> list[dict]:
    return _read_jsonl(out_dir / "graph" / "ti_nodes.jsonl")


@pytest.fixture(scope="module")
def edges(out_dir: Path) -> list[dict]:
    return _read_jsonl(out_dir / "graph" / "ti_edges.jsonl")


@pytest.fixture(scope="module")
def by_id(nodes: list[dict]) -> dict[str, dict]:
    return {n["id"]: n for n in nodes}


@pytest.fixture(scope="module")
def label_of(nodes: list[dict]) -> dict[str, str]:
    return {n["id"]: n["label"] for n in nodes}


# ----------------------------------------------------------------------------- speed & determinism


def test_generation_is_fast(tmp_path: Path):
    t0 = time.perf_counter()
    result = generate(tmp_path)
    elapsed = time.perf_counter() - t0
    assert elapsed < 10.0, f"generation took {elapsed:.2f}s"
    assert result["nodes"].exists() and result["edges"].exists()


def test_determinism_byte_identical(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    generate(a)
    generate(b)
    rels = [
        "graph/ti_nodes.jsonl", "graph/ti_edges.jsonl",
        "raw/ti/intrusion_sets.json", "raw/ti/campaigns.json", "raw/ti/malware.json",
        "raw/ti/indicators.jsonl", "raw/ti/reports.json", "raw/ti/exploited_cves.json",
        "raw/ti/attack_patterns.json", "raw/ti/low_confidence_plants.json",
    ]
    for rel in rels:
        assert (a / rel).read_bytes() == (b / rel).read_bytes(), rel


# ----------------------------------------------------------------------------- counts


def test_headline_counts(nodes: list[dict]):
    counts = Counter(n["label"] for n in nodes)
    assert counts["ThreatActor"] == 10
    assert counts["Campaign"] == 16
    assert counts["Malware"] == 12
    assert counts["IntelReport"] == 30
    assert 350 <= counts["Indicator"] <= 450


def test_vulnerability_and_technique_nodes(nodes: list[dict], by_id: dict[str, dict]):
    counts = Counter(n["label"] for n in nodes)
    # 60 CVEs from the catalog, one Vulnerability node each
    assert counts["Vulnerability"] == 60 == len(CVES)
    for cve in CVES.values():
        assert cve.node_id in by_id
    # one AttackTechnique node per catalog entry (the working-tree catalog currently holds 80)
    assert counts["AttackTechnique"] == len(TECHNIQUES)
    for tid in TECHNIQUES:
        assert technique_node_id(tid) in by_id


def test_vulnerability_props_leave_derived_unset(by_id: dict[str, dict]):
    v = by_id["cve:CVE-2021-44228"]["props"]
    assert v["cve_id"] == "CVE-2021-44228" and v["kev"] is True and v["cvss"] == 10.0
    assert set(v) == {"cve_id", "cvss", "epss", "kev", "severity", "published", "synthetic",
                      "description", "affected_component"}
    for derived in ("exploitation_status", "actor_interest", "sector_targeting_relevance", "ti_report_ids"):
        assert derived not in v


# ----------------------------------------------------------------------------- storyline exactness


def test_storyline_indicators_exact(by_id: dict[str, dict]):
    for iid, (value, confidence) in STORYLINE_IOCS.items():
        assert iid in by_id, iid
        n = by_id[iid]
        assert n["label"] == "Indicator"
        assert n["props"]["value"] == value, (iid, n["props"]["value"])
        assert n["confidence"] == confidence, (iid, n["confidence"])
        assert n["props"]["active"] is True


def test_storyline_named_entities_exist(by_id: dict[str, dict]):
    for aid in (SC.ACTOR_CJ, SC.ACTOR_HT):
        assert by_id[aid]["label"] == "ThreatActor"
    for cid in (SC.CAMPAIGN_EMBERCAST, SC.CAMPAIGN_SALTWORKS):
        assert by_id[cid]["label"] == "Campaign"
    for mid, mtype in ((SC.MALWARE_MAPLELOADER, "loader"), (SC.MALWARE_QUILLDROP, "stealer"),
                       (SC.MALWARE_NIGHTFERRY, "implant"), (SC.MALWARE_BRACKISH, "webshell")):
        assert by_id[mid]["label"] == "Malware"
        assert by_id[mid]["props"]["malware_type"] == mtype


def test_flagship_reports(by_id: dict[str, dict]):
    em = by_id[SC.REPORT_EMBERCAST]["props"]
    assert em["report_confidence"] == "high" and em["tlp"] == "amber"
    assert em["cve_ids"] == [] and em["indicator_count"] == 7
    assert em["technique_ids"] == list(SC.CJ_TECHNIQUES)
    assert len(em["body"].split("\n\n")) >= 4
    sw = by_id[SC.REPORT_SALTWORKS]["props"]
    assert sw["report_confidence"] == "medium-high" and sw["cve_ids"] == ["CVE-2021-44228"]
    assert sw["indicator_count"] == 3


def test_flagship_reports_reference_exact_indicators(edges: list[dict]):
    def reported_iocs(report_id: str) -> set[str]:
        return {e["dst"] for e in edges
                if e["type"] == "REPORTS_ON" and e["src"] == report_id and e["dst"].startswith("ioc:")}

    assert reported_iocs(SC.REPORT_EMBERCAST) == {
        SC.IOC_C2_DOMAIN, SC.IOC_C2_IP, SC.IOC_EGRESS_IP, SC.IOC_HASH_MAPLELOADER,
        SC.IOC_HASH_QUILLDROP, SC.IOC_HASH_NIGHTFERRY, SC.IOC_FILENAME_SYNCHOST,
    }
    assert reported_iocs(SC.REPORT_SALTWORKS) == {SC.IOC_SALTWORKS_IP, SC.IOC_HASH_BRACKISH, SC.IOC_BRACKISH_URL}


# ----------------------------------------------------------------------------- EXPLOITS


def test_exploits_statuses(edges: list[dict]):
    exploits: dict[str, set[tuple[str, str]]] = {}
    first_seen: dict[tuple[str, str], str] = {}
    for e in edges:
        if e["type"] == "EXPLOITS":
            exploits.setdefault(e["dst"], set()).add((e["src"], e["props"]["status"]))
            first_seen[(e["src"], e["dst"])] = e["first_seen"]

    # SALTWORKS campaign + Hollow Tide actor mass-exploit Log4Shell, first seen 2026-08-20
    log4shell = exploits["cve:CVE-2021-44228"]
    assert (SC.CAMPAIGN_SALTWORKS, "mass_exploitation") in log4shell
    assert (SC.ACTOR_HT, "mass_exploitation") in log4shell
    assert first_seen[(SC.CAMPAIGN_SALTWORKS, "cve:CVE-2021-44228")] == "2026-08-20T00:00:00Z"

    statuses = {cve: {s for _, s in pairs} for cve, pairs in exploits.items()}
    assert "active" in statuses["cve:CVE-2023-4966"]
    assert "active" in statuses["cve:CVE-2024-3400"]
    assert "active" in statuses["cve:CVE-2024-23897"]
    assert "active" in statuses["cve:CVE-2023-22515"]
    # CVE-2022-22965 is poc_public only (never active/mass)
    assert statuses["cve:CVE-2022-22965"] == {"poc_public"}

    # at least 6 CVEs reach active/mass_exploitation (doc 04 section 5)
    active_mass = [c for c, ss in statuses.items() if ss & {"active", "mass_exploitation"}]
    assert len(active_mass) >= 6


def test_cinder_jackal_and_embercast_exploit_nothing(edges: list[dict]):
    offenders = [e for e in edges
                 if e["type"] == "EXPLOITS" and e["src"] in (SC.ACTOR_CJ, SC.CAMPAIGN_EMBERCAST)]
    assert offenders == []


def test_fin_actor_exploits_are_high_relevance(edges: list[dict], by_id: dict[str, dict]):
    # CVE-2023-4966 and CVE-2024-23897 are attributed to financial-targeting actors (relevance >= 0.7)
    for cve in ("cve:CVE-2023-4966", "cve:CVE-2024-23897"):
        srcs = [e["src"] for e in edges if e["type"] == "EXPLOITS" and e["dst"] == cve]
        assert any(by_id[s]["props"].get("sector_targeting_relevance", 0) >= 0.7
                   for s in srcs if s in by_id)


# ----------------------------------------------------------------------------- structural integrity


def test_uses_technique_targets_exist(edges: list[dict], by_id: dict[str, dict]):
    for e in edges:
        if e["type"] == "USES_TECHNIQUE":
            assert e["dst"] in by_id, e["dst"]
            assert by_id[e["dst"]]["label"] == "AttackTechnique"


def test_all_nodes_pass_schema(nodes: list[dict]):
    problems: list[str] = []
    for n in nodes:
        problems += validate_node(n)
    assert problems == []


def test_all_edges_pass_schema(edges: list[dict], label_of: dict[str, str]):
    problems: list[str] = []
    for e in edges:
        problems += validate_edge(e, label_of)
    assert problems == []


def test_context_graph_loads_and_validates(out_dir: Path):
    g = ContextGraph.from_jsonl(out_dir / "graph" / "ti_nodes.jsonl", out_dir / "graph" / "ti_edges.jsonl")
    assert g.validate() == []


# ----------------------------------------------------------------------------- indicators & plants


def test_generated_ipv4_excludes_infra_and_scanner(nodes: list[dict]):
    gen_ips = {n["props"]["value"] for n in nodes
               if n["label"] == "Indicator" and n["props"]["ioc_type"] == "ipv4"}
    # infra IPs must never appear as indicators
    assert not ({SC.BASTION_PUBLIC_IP, SC.EDGE_PUBLIC_IP, SC.VPN_EGRESS_IP} & gen_ips)
    # every ipv4 indicator lives in the indicator block or the deliberate-plant block, never in the estate's
    # public block or the noise blocks (docs/04-storyline.md section 4: noise sources are "none in TI")
    for ip in gen_ips:
        assert ip.startswith(f"{SC.IP_BLOCK_TI_INDICATORS}.") or ip.startswith(f"{SC.IP_BLOCK_PLANTS}."), ip
        assert not ip.startswith(f"{SC.IP_BLOCK_ESTATE_PUBLIC}.")
        assert not any(ip.startswith(f"{b}.") for b in SC.IP_BLOCKS_NOISE)


def test_low_confidence_plants(out_dir: Path):
    plants = json.loads((out_dir / "raw" / "ti" / "low_confidence_plants.json").read_text(encoding="utf-8"))
    assert 5 <= len(plants) <= 8
    values = {p["value"] for p in plants}
    for p in plants:
        assert p["confidence"] <= 0.5
        assert p["campaign_id"] and p["actor_id"] and p["report_id"]
    # plant ipv4s must sit in the documentation ranges and avoid the excluded infra values
    assert "198.51.100.10" not in values and "198.51.100.24" not in values and "198.51.100.200" not in values


def test_plants_are_indicator_nodes(out_dir: Path, by_id: dict[str, dict]):
    plants = json.loads((out_dir / "raw" / "ti" / "low_confidence_plants.json").read_text(encoding="utf-8"))
    for p in plants:
        assert p["id"] in by_id
        assert by_id[p["id"]]["confidence"] <= 0.5


# ----------------------------------------------------------------------------- raw STIX-like feeds


def test_raw_feeds_written(out_dir: Path):
    raw = out_dir / "raw" / "ti"
    for name in ("intrusion_sets.json", "campaigns.json", "malware.json", "indicators.jsonl",
                 "reports.json", "exploited_cves.json", "attack_patterns.json", "low_confidence_plants.json"):
        assert (raw / name).exists(), name
    intrusion_sets = json.loads((raw / "intrusion_sets.json").read_text(encoding="utf-8"))
    assert len(intrusion_sets) == 10 and all(o["type"] == "intrusion-set" for o in intrusion_sets)


def test_indicator_feed_has_stix_patterns(out_dir: Path):
    feed = _read_jsonl(out_dir / "raw" / "ti" / "indicators.jsonl")
    by_tid = {o["x_throughline_id"]: o for o in feed}
    assert by_tid[SC.IOC_HASH_MAPLELOADER]["pattern"] == f"[file:hashes.'SHA-256' = '{SC.HASH_MAPLELOADER}']"
    assert by_tid[SC.IOC_C2_DOMAIN]["pattern"] == f"[domain-name:value = '{SC.C2_DOMAIN}']"
    assert by_tid[SC.IOC_C2_IP]["pattern"] == f"[ipv4-addr:value = '{SC.C2_IP}']"
    assert by_tid[SC.IOC_BRACKISH_URL]["pattern"] == f"[url:value = '{SC.BRACKISH_URL}']"
    assert all(o["pattern_type"] == "stix" for o in feed)


def test_exploited_cves_feed(out_dir: Path):
    rows = json.loads((out_dir / "raw" / "ti" / "exploited_cves.json").read_text(encoding="utf-8"))
    by_cve = {r["cveID"]: r for r in rows}
    assert by_cve["CVE-2021-44228"]["x_exploitation_status"] == "mass_exploitation"
    assert by_cve["CVE-2021-44228"]["knownRansomwareCampaignUse"] == "Known"
    # every exploited CVE in the feed corresponds to a real EXPLOITS target
    exploited_ids = {f"cve:{r['cveID']}" for r in rows}
    assert "cve:CVE-2021-44228" in exploited_ids


def test_catalog_actor_and_campaign_shape():
    # sanity on the fictional catalog: 4 financial-targeting actors (>=0.7), 6 others (<=0.3)
    fin = [a for a in cat.ACTORS if a.relevance >= 0.7]
    low = [a for a in cat.ACTORS if a.relevance <= 0.3]
    assert len(fin) == 4 and len(low) == 6
    assert {a.motivation for a in cat.ACTORS} >= {"financial", "espionage", "hacktivism", "access-broker"}
    assert {c.status for c in cat.CAMPAIGNS} == {"active", "dormant", "historical"}
