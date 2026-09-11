"""Threat-intelligence stage of the data simulator.

Builds the fictional threat-intel graph for the estate - actors, campaigns, malware, ATT&CK technique nodes,
indicators, intel reports, ``EXPLOITS`` relationships and the ``Vulnerability`` (CVE) nodes - and writes the
canonical graph fragments (``ti_nodes.jsonl`` / ``ti_edges.jsonl``) plus STIX-2.1-like raw feeds under
``raw/ti/``. Everything is deterministic from ``simulator.common`` seed; all randomness goes through
``rng(namespace)`` so adding or reordering generators never perturbs another's output.

Entry point: ``generate(out_dir: Path) -> dict`` (see docs/06-build-plan.md section 2).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from throughline.simulator import storyline_constants as SC
from throughline.simulator.catalog.cves import CVES
from throughline.simulator.catalog.techniques import TECHNIQUES, technique_node_id
from throughline.simulator.common import NOW, edge, fake_sha256, node, rng, ts, write_jsonl
from throughline.simulator.threat_intel import catalog as cat
from throughline.simulator.threat_intel import feeds

SOURCE = "ti-sim"

# addresses that must never be emitted as generated indicators (storyline / infra values + plants)
_STORYLINE_IPS = {SC.C2_IP, SC.ATTACKER_EGRESS_IP, SC.SALTWORKS_IP}
_INFRA_IPS = {SC.BASTION_PUBLIC_IP, SC.EDGE_PUBLIC_IP, SC.VPN_EGRESS_IP}  # 198.51.100.10/.24/.200

_DOMAIN_WORDS = (
    "cdn", "metrics", "telemetry", "sync", "update", "cache", "assets", "edge", "cloud", "static",
    "portal", "gateway", "mail", "relay", "proxy", "node", "vault", "ledger", "beacon", "signal",
    "harbor", "delta", "orbit", "quartz", "cobalt", "saffron", "basalt", "verdant", "amber", "slate",
)
_FILE_WORDS = (
    "svchost", "winupd", "helper", "runtime", "sysmon", "netcfg", "printcfg", "taskhost", "backup",
    "installer", "updater", "monitor", "agent", "loader", "report", "invoice", "statement", "config",
)
_FILE_EXTS = ("exe", "dll", "jsp", "sh", "ps1", "bin")
_URL_SEGS = ("s", "d", "static", "cdn", "api", "files", "img", "u", "get", "load")


@dataclass
class Model:
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    indicators: list[dict[str, Any]] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)
    plants: list[dict[str, Any]] = field(default_factory=list)
    exploited: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


_ACTOR_BY_ID = {a.id: a for a in cat.ACTORS}
_CAMPAIGN_BY_ID = {c.id: c for c in cat.CAMPAIGNS}


def _day(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=UTC)


def _campaign_techniques(c: cat.CampaignSpec) -> tuple[str, ...]:
    return c.techniques or _ACTOR_BY_ID[c.actor_id].techniques


def _campaign_malware(c: cat.CampaignSpec) -> tuple[str, ...]:
    return c.malware or _ACTOR_BY_ID[c.actor_id].malware


# ----------------------------------------------------------------------------- node builders


def _build_techniques(m: Model) -> None:
    for tid, meta in TECHNIQUES.items():
        m.nodes.append(node(
            technique_node_id(tid), "AttackTechnique", str(meta["name"]),
            {"technique_id": tid, "tactic": str(meta["tactic"]),
             "kill_chain_stage": int(meta["kill_chain_stage"]), "description": str(meta["name"])},
            source=SOURCE, source_id=tid,
        ))


def _build_vulnerabilities(m: Model) -> None:
    for cve in CVES.values():
        # Typed props only; exploitation_status/actor_interest/sector_targeting_relevance/ti_report_ids
        # are intentionally UNSET - analytics derives them from EXPLOITS edges and reports.
        m.nodes.append(node(
            cve.node_id, "Vulnerability", cve.cve_id,
            {"cve_id": cve.cve_id, "cvss": cve.cvss, "epss": cve.epss, "kev": cve.kev,
             "severity": cve.severity, "published": cve.published, "synthetic": cve.synthetic,
             "description": cve.description, "affected_component": cve.component},
            source=SOURCE, source_id=cve.cve_id, first_seen=cve.published, last_seen=ts(NOW),
        ))


def _build_actors(m: Model) -> None:
    for a in cat.ACTORS:
        m.nodes.append(node(
            a.id, "ThreatActor", a.name,
            {"aliases": list(a.aliases), "motivation": a.motivation, "origin": a.origin,
             "sophistication": a.sophistication, "targeted_sectors": list(a.targeted_sectors),
             "targeted_regions": list(a.targeted_regions), "sector_targeting_relevance": a.relevance,
             "active": a.active, "description": a.description},
            source=SOURCE, source_id=a.id.split(":")[-1],
        ))
        for tid in a.techniques:
            m.edges.append(edge("USES_TECHNIQUE", a.id, technique_node_id(tid), source=SOURCE))
        for mid in a.malware:
            m.edges.append(edge("USES_MALWARE", a.id, mid, source=SOURCE))


def _build_malware(m: Model) -> None:
    for mw in cat.MALWARE:
        m.nodes.append(node(
            mw.id, "Malware", mw.name,
            {"family": mw.name, "malware_type": mw.malware_type, "platforms": list(mw.platforms),
             "description": mw.description},
            source=SOURCE, source_id=mw.id.split(":")[-1],
        ))
        for tid in mw.techniques:
            m.edges.append(edge("USES_TECHNIQUE", mw.id, technique_node_id(tid), source=SOURCE))


def _build_campaigns(m: Model) -> None:
    for c in cat.CAMPAIGNS:
        started = ts(_day(c.started))
        m.nodes.append(node(
            c.id, "Campaign", c.name,
            {"actor_id": c.actor_id, "status": c.status, "started": started, "objective": c.objective,
             "targeted_sectors": list(c.targeted_sectors), "sector_targeting_relevance": c.relevance,
             "description": c.description},
            source=SOURCE, source_id=c.id.split(":")[-1], first_seen=started,
        ))
        m.edges.append(edge("ATTRIBUTED_TO", c.id, c.actor_id, {"basis": "report"}, source=SOURCE, first_seen=started))
        for tid in _campaign_techniques(c):
            m.edges.append(edge("USES_TECHNIQUE", c.id, technique_node_id(tid), source=SOURCE))
        for mid in _campaign_malware(c):
            m.edges.append(edge("USES_MALWARE", c.id, mid, source=SOURCE))


def _build_exploits(m: Model) -> None:
    # graph edges
    for ex in cat.EXPLOITS:
        m.edges.append(edge(
            "EXPLOITS", ex.source_id, f"cve:{ex.cve_id}", {"status": ex.status},
            source=SOURCE, first_seen=ts(_day(ex.first_seen)),
        ))
    # KEV-like aggregation per CVE
    order = {"poc_public": 1, "active": 2, "mass_exploitation": 3}
    agg: dict[str, dict[str, Any]] = {}
    for ex in cat.EXPLOITS:
        row = agg.setdefault(ex.cve_id, {"cve_id": ex.cve_id, "status": ex.status, "date_added": ex.first_seen,
                                         "attributions": []})
        if order[ex.status] > order[row["status"]]:
            row["status"] = ex.status
        if ex.first_seen < row["date_added"]:
            row["date_added"] = ex.first_seen
        name = (_ACTOR_BY_ID[ex.source_id].name if ex.kind == "actor" else _CAMPAIGN_BY_ID[ex.source_id].name)
        row["attributions"].append({"kind": ex.kind, "id": ex.source_id, "name": name,
                                    "status": ex.status, "first_seen": ex.first_seen})
    for cve_id in sorted(agg):
        m.exploited.append(agg[cve_id])


# ----------------------------------------------------------------------------- reports


def _report_confidence(r) -> str:  # r: a seeded random.Random
    return r.choice(["low", "medium", "medium-high", "high"])


def _tlp(r) -> str:
    return r.choice(["clear", "green", "amber", "amber"])


def _generic_body(c: cat.CampaignSpec, a: cat.ActorSpec, cve_ids: list[str], rid: str) -> str:
    r = rng(f"ti:report-body:{rid}")
    sectors = ", ".join(c.targeted_sectors)
    p1 = (
        f"Throughline Labs tracks the {c.name} campaign, attributed with {_report_confidence(r)} confidence to "
        f"the {a.motivation} actor {a.name}. The campaign, first observed in {c.started[:7]}, is currently "
        f"assessed as {c.status} and focuses on {c.objective.lower()} against {sectors} targets."
    )
    tech = ", ".join(_campaign_techniques(c)[:4])
    p2 = (
        f"{a.name} favours a repeatable tradecraft profile; observed techniques for this campaign include "
        f"{tech}. {a.description}"
    )
    parts = [p1, p2]
    if cve_ids:
        cnames = ", ".join(cve_ids)
        p3 = (
            f"Where opportunistic access is required, the actor has been observed exploiting {cnames}. "
            f"Defenders in the affected sectors should prioritise patching these components on internet-facing "
            f"systems and hunt for the indicators enumerated with this report."
        )
        parts.append(p3)
    else:
        parts.append(
            "No specific vulnerability exploitation is attributed to this campaign; initial access relies on "
            "social engineering and valid accounts. Detection should centre on the behavioural techniques above "
            "and on the indicators enumerated with this report."
        )
    return "\n\n".join(parts)


def _build_reports(m: Model) -> dict[str, list[str]]:
    """Create report records and return {campaign_id: [report_id, ...]} for indicator attribution."""
    campaign_reports: dict[str, list[str]] = {c.id: [] for c in cat.CAMPAIGNS}

    def resolved_cves(campaign_id: str) -> list[str]:
        actor_id = _CAMPAIGN_BY_ID[campaign_id].actor_id
        out: list[str] = []
        for ex in cat.EXPLOITS:
            if (ex.kind == "campaign" and ex.source_id == campaign_id) or (
                ex.kind == "actor" and ex.source_id == actor_id
            ):
                if ex.cve_id not in out:
                    out.append(ex.cve_id)
        return out

    # --- flagship reports (full bodies) ---
    cj = _ACTOR_BY_ID[SC.ACTOR_CJ]
    m.reports.append({
        "id": SC.REPORT_EMBERCAST,
        "title": "EMBERCAST: Cinder Jackal shifts to bastion-host pivoting against fintech cloud estates",
        "published": ts(_day("2026-09-02")), "publisher": cat.PUBLISHER, "report_confidence": "high", "tlp": "amber",
        "summary": cat.EMBERCAST_SUMMARY, "body": cat.EMBERCAST_BODY,
        "actor_ids": [SC.ACTOR_CJ], "campaign_ids": [SC.CAMPAIGN_EMBERCAST], "cve_ids": [],
        "technique_ids": list(SC.CJ_TECHNIQUES),
        "malware_ids": list(_campaign_malware(_CAMPAIGN_BY_ID[SC.CAMPAIGN_EMBERCAST])),
        "targeted_sectors": list(cj.targeted_sectors),
    })
    campaign_reports[SC.CAMPAIGN_EMBERCAST].append(SC.REPORT_EMBERCAST)

    ht = _ACTOR_BY_ID[SC.ACTOR_HT]
    m.reports.append({
        "id": SC.REPORT_SALTWORKS,
        "title": "SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services",
        "published": ts(_day("2026-09-08")), "publisher": cat.PUBLISHER, "report_confidence": "medium-high",
        "tlp": "amber", "summary": cat.SALTWORKS_SUMMARY, "body": cat.SALTWORKS_BODY,
        "actor_ids": [SC.ACTOR_HT], "campaign_ids": [SC.CAMPAIGN_SALTWORKS], "cve_ids": ["CVE-2021-44228"],
        "technique_ids": list(SC.HT_TECHNIQUES),
        "malware_ids": list(_campaign_malware(_CAMPAIGN_BY_ID[SC.CAMPAIGN_SALTWORKS])),
        "targeted_sectors": list(ht.targeted_sectors),
    })
    campaign_reports[SC.CAMPAIGN_SALTWORKS].append(SC.REPORT_SALTWORKS)

    # --- 28 generic reports: two per non-storyline campaign ---
    storyline_campaigns = {SC.CAMPAIGN_EMBERCAST, SC.CAMPAIGN_SALTWORKS}
    drafts: list[tuple[datetime, str, int]] = []
    for c in cat.CAMPAIGNS:
        if c.id in storyline_campaigns:
            continue
        for idx, off in enumerate((30, 120)):
            drafts.append((_day(c.started) + timedelta(days=off), c.id, idx))
    drafts.sort(key=lambda d: (d[0], d[1], d[2]))

    year_counter: dict[int, int] = {}

    def next_number(year: int) -> int:
        n = year_counter.get(year, 0) + 1
        while n in (142, 147):
            n += 1
        year_counter[year] = n
        return n

    for published_dt, campaign_id, idx in drafts:
        c = _CAMPAIGN_BY_ID[campaign_id]
        a = _ACTOR_BY_ID[c.actor_id]
        year = published_dt.year
        rid = f"report:ti:TL-{year}-{next_number(year):04d}"
        cve_ids = resolved_cves(campaign_id)
        cve_ids = cve_ids[:2] if idx == 0 else cve_ids[2:4]
        techs = list(_campaign_techniques(c))[: (12 if idx == 0 else 8)]
        rr = rng(f"ti:report-meta:{rid}")
        kind = "activity update" if idx == 0 else "technical analysis"
        title = f"{c.name}: {kind} on {a.name} operations against {c.targeted_sectors[0]}"
        m.reports.append({
            "id": rid, "title": title, "published": ts(published_dt), "publisher": cat.PUBLISHER,
            "report_confidence": _report_confidence(rr), "tlp": _tlp(rr),
            "summary": (f"{a.name} {c.status} campaign {c.name}: {c.objective.lower()}. "
                        f"Sector focus: {', '.join(c.targeted_sectors)}."),
            "body": _generic_body(c, a, cve_ids, rid),
            "actor_ids": [a.id], "campaign_ids": [c.id], "cve_ids": cve_ids, "technique_ids": techs,
            "malware_ids": list(_campaign_malware(c)), "targeted_sectors": list(c.targeted_sectors),
        })
        campaign_reports[campaign_id].append(rid)

    # nodes get their indicator_count / REPORTS_ON edges filled in after indicators are built
    return campaign_reports


# ----------------------------------------------------------------------------- indicators


def _slug_url(url: str) -> str:
    return "ioc:url:" + url.replace("://", "-").replace(":", "-").replace("/", "-")


def _ind_id(ioc_type: str, value: str) -> str:
    if ioc_type == "url":
        return _slug_url(value)
    return f"ioc:{ioc_type}:{value}"


def _add_indicator(m: Model, *, ind_id: str, ioc_type: str, value: str, confidence: float,
                   first_seen: str, last_seen: str, report_id: str, actor_id: str, campaign_id: str,
                   malware_id: str, kill_chain_stage: int, active: bool) -> None:
    m.indicators.append({
        "id": ind_id, "ioc_type": ioc_type, "value": value, "confidence": round(confidence, 2),
        "first_seen": first_seen, "last_seen": last_seen, "report_id": report_id, "actor_id": actor_id,
        "campaign_id": campaign_id, "malware_id": malware_id, "kill_chain_stage": kill_chain_stage,
        "active": active,
    })


def _build_storyline_indicators(m: Model) -> None:
    cj, em, r_em = SC.ACTOR_CJ, SC.CAMPAIGN_EMBERCAST, SC.REPORT_EMBERCAST
    ht, sw, r_sw = SC.ACTOR_HT, SC.CAMPAIGN_SALTWORKS, SC.REPORT_SALTWORKS
    em_fs, em_ls = ts(_day("2026-08-15")), ts(NOW - timedelta(hours=1))
    sw_fs, sw_ls = ts(_day("2026-08-20")), ts(NOW - timedelta(hours=1))

    # EMBERCAST / Cinder Jackal (exact ids/values/confidence per storyline)
    specs = [
        (SC.IOC_C2_DOMAIN, "domain", SC.C2_DOMAIN, 0.95, SC.MALWARE_NIGHTFERRY, 6),
        (SC.IOC_C2_IP, "ipv4", SC.C2_IP, 0.9, SC.MALWARE_NIGHTFERRY, 6),
        (SC.IOC_EGRESS_IP, "ipv4", SC.ATTACKER_EGRESS_IP, 0.85, "", 7),
        (SC.IOC_HASH_MAPLELOADER, "sha256", SC.HASH_MAPLELOADER, 0.95, SC.MALWARE_MAPLELOADER, 2),
        (SC.IOC_HASH_QUILLDROP, "sha256", SC.HASH_QUILLDROP, 0.9, SC.MALWARE_QUILLDROP, 4),
        (SC.IOC_HASH_NIGHTFERRY, "sha256", SC.HASH_NIGHTFERRY, 0.95, SC.MALWARE_NIGHTFERRY, 6),
        (SC.IOC_FILENAME_SYNCHOST, "filename", "synchost.exe", 0.6, SC.MALWARE_NIGHTFERRY, 3),
    ]
    for ind_id, ioc_type, value, conf, mal, kcs in specs:
        _add_indicator(m, ind_id=ind_id, ioc_type=ioc_type, value=value, confidence=conf,
                       first_seen=em_fs, last_seen=em_ls, report_id=r_em, actor_id=cj, campaign_id=em,
                       malware_id=mal, kill_chain_stage=kcs, active=True)

    # SALTWORKS / Hollow Tide
    sw_specs = [
        (SC.IOC_SALTWORKS_IP, "ipv4", SC.SALTWORKS_IP, 0.8, SC.MALWARE_BRACKISH, 1),
        (SC.IOC_HASH_BRACKISH, "sha256", SC.HASH_BRACKISH, 0.85, SC.MALWARE_BRACKISH, 3),
        (SC.IOC_BRACKISH_URL, "url", SC.BRACKISH_URL, 0.8, SC.MALWARE_BRACKISH, 6),
    ]
    for ind_id, ioc_type, value, conf, mal, kcs in sw_specs:
        _add_indicator(m, ind_id=ind_id, ioc_type=ioc_type, value=value, confidence=conf,
                       first_seen=sw_fs, last_seen=sw_ls, report_id=r_sw, actor_id=ht, campaign_id=sw,
                       malware_id=mal, kill_chain_stage=kcs, active=True)


def _build_plants(m: Model, campaign_reports: dict[str, list[str]]) -> None:
    for p in cat.PLANTS:
        c = _CAMPAIGN_BY_ID[p.campaign_id]
        report_id = campaign_reports[p.campaign_id][0]
        ind_id = _ind_id(p.ioc_type, p.value)
        _add_indicator(m, ind_id=ind_id, ioc_type=p.ioc_type, value=p.value, confidence=p.confidence,
                       first_seen=ts(_day(p.first_seen)), last_seen=ts(_day(p.last_seen)), report_id=report_id,
                       actor_id=c.actor_id, campaign_id=p.campaign_id, malware_id="",
                       kill_chain_stage=p.kill_chain_stage, active=True)
        m.plants.append({"id": ind_id, "ioc_type": p.ioc_type, "value": p.value, "confidence": p.confidence,
                         "campaign_id": p.campaign_id, "actor_id": c.actor_id, "report_id": report_id})


def _window(c: cat.CampaignSpec) -> tuple[datetime, datetime]:
    start = _day(c.started)
    if c.status == "active":
        end = NOW
    elif c.status == "dormant":
        end = min(start + timedelta(days=210), NOW)
    else:  # historical
        end = min(start + timedelta(days=150), NOW)
    if end <= start:
        end = start + timedelta(days=30)
    return start, end


def _build_generated_indicators(m: Model, campaign_reports: dict[str, list[str]], count: int) -> None:
    r = rng("ti:indicators")
    # deterministic ipv4 pool
    pool_rng = rng("ti:ipv4-pool")
    excluded = _STORYLINE_IPS | _INFRA_IPS | {p.value for p in cat.PLANTS if p.ioc_type == "ipv4"}
    pool = [f"203.0.113.{o}" for o in range(1, 255)] + [f"198.51.100.{o}" for o in range(1, 255)]
    pool = [ip for ip in pool if ip not in excluded]
    pool_rng.shuffle(pool)

    # campaigns eligible for generated indicators (exclude the two flagship campaigns so their reports keep
    # exactly their storyline indicator counts)
    pool_campaigns = [c for c in cat.CAMPAIGNS if c.id not in (SC.CAMPAIGN_EMBERCAST, SC.CAMPAIGN_SALTWORKS)]
    weights = [{"active": 3.0, "dormant": 2.0, "historical": 1.0}[c.status] for c in pool_campaigns]

    used = {ind["id"] for ind in m.indicators}
    types = ["ipv4", "domain", "sha256", "url", "filename"]
    type_weights = [0.39, 0.28, 0.20, 0.07, 0.06]

    made = 0
    i = 0
    while made < count:
        i += 1
        c = r.choices(pool_campaigns, weights=weights, k=1)[0]
        a = _ACTOR_BY_ID[c.actor_id]
        ioc_type = r.choices(types, weights=type_weights, k=1)[0]
        if ioc_type == "ipv4" and not pool:
            ioc_type = "sha256"
        value = _gen_value(r, ioc_type, i)
        ind_id = _ind_id(ioc_type, value) if ioc_type != "ipv4" else f"ioc:ipv4:{value}"
        if ioc_type == "ipv4":
            value = pool.pop()
            ind_id = f"ioc:ipv4:{value}"
        if ind_id in used:
            continue
        used.add(ind_id)
        report_id = r.choice(campaign_reports[c.id])
        malware_id = r.choice(list(a.malware)) if (a.malware and r.random() < 0.8) else ""
        conf = r.uniform(0.3, 0.95)
        start, end = _window(c)
        span = (end - start).total_seconds()
        fs = start + timedelta(seconds=r.uniform(0, span * 0.6))
        ls = fs + timedelta(seconds=r.uniform(0, (end - fs).total_seconds()))
        if c.status == "active":
            active = r.random() < 0.9
        elif c.status == "dormant":
            active = r.random() < 0.4
        else:
            active = r.random() < 0.15
        _add_indicator(m, ind_id=ind_id, ioc_type=ioc_type, value=value, confidence=conf,
                       first_seen=ts(fs), last_seen=ts(ls), report_id=report_id, actor_id=c.actor_id,
                       campaign_id=c.id, malware_id=malware_id, kill_chain_stage=r.randint(1, 7), active=active)
        made += 1


def _gen_value(r, ioc_type: str, i: int) -> str:
    if ioc_type == "domain":
        w1 = r.choice(_DOMAIN_WORDS)
        w2 = r.choice(_DOMAIN_WORDS)
        tld = r.choice(("example", "test", "invalid"))
        style = r.randint(0, 2)
        if style == 0:
            return f"{w1}-{w2}-{i}.{tld}"
        if style == 1:
            return f"{w1}{i}.{tld}"
        return f"cdn-{w1}-{i}.{w2}-sync.net"
    if ioc_type == "sha256":
        return fake_sha256("ti-ioc", i, r.random())
    if ioc_type == "filename":
        return f"{r.choice(_FILE_WORDS)}{i}.{r.choice(_FILE_EXTS)}"
    if ioc_type == "url":
        host = r.choice(_DOMAIN_WORDS) + str(i) + "." + r.choice(("example", "test", "invalid"))
        seg = r.choice(_URL_SEGS)
        return f"http://{host}/{seg}/{r.choice(_FILE_WORDS)}{i}.{r.choice(_FILE_EXTS)}"
    return f"ioc-{i}"  # pragma: no cover (ipv4 handled by pool)


# ----------------------------------------------------------------------------- indicator nodes/edges + reports finalize


def _finalize(m: Model, campaign_reports: dict[str, list[str]]) -> None:
    report_indicators: dict[str, list[str]] = {rr["id"]: [] for rr in m.reports}
    # indicator nodes + INDICATES edges
    for ind in m.indicators:
        m.nodes.append(node(
            ind["id"], "Indicator", ind["value"],
            {"ioc_type": ind["ioc_type"], "value": ind["value"], "report_id": ind["report_id"],
             "actor_id": ind["actor_id"], "campaign_id": ind["campaign_id"], "malware_id": ind["malware_id"],
             "kill_chain_stage": ind["kill_chain_stage"], "active": ind["active"]},
            source=SOURCE, source_id=ind["id"].split(":", 2)[-1], first_seen=ind["first_seen"],
            last_seen=ind["last_seen"], confidence=ind["confidence"],
        ))
        if ind["malware_id"]:
            m.edges.append(edge("INDICATES", ind["id"], ind["malware_id"], source=SOURCE, first_seen=ind["first_seen"]))
        m.edges.append(edge("INDICATES", ind["id"], ind["campaign_id"], source=SOURCE, first_seen=ind["first_seen"]))
        m.edges.append(edge("INDICATES", ind["id"], ind["actor_id"], source=SOURCE, first_seen=ind["first_seen"]))
        if ind["report_id"] in report_indicators:
            report_indicators[ind["report_id"]].append(ind["id"])

    # report nodes + REPORTS_ON edges
    for rr in m.reports:
        rid = rr["id"]
        ind_ids = report_indicators.get(rid, [])
        rr["indicator_count"] = len(ind_ids)
        m.nodes.append(node(
            rid, "IntelReport", rr["title"],
            {"title": rr["title"], "published": rr["published"], "publisher": rr["publisher"],
             "report_confidence": rr["report_confidence"], "tlp": rr["tlp"], "summary": rr["summary"],
             "actor_ids": rr["actor_ids"], "campaign_ids": rr["campaign_ids"], "cve_ids": rr["cve_ids"],
             "technique_ids": rr["technique_ids"], "indicator_count": len(ind_ids),
             "targeted_sectors": rr["targeted_sectors"], "body": rr["body"]},
            source=SOURCE, source_id=rid.split(":")[-1], first_seen=rr["published"], last_seen=rr["published"],
        ))
        for aid in rr["actor_ids"]:
            m.edges.append(edge("REPORTS_ON", rid, aid, source=SOURCE, first_seen=rr["published"]))
        for cid in rr["campaign_ids"]:
            m.edges.append(edge("REPORTS_ON", rid, cid, source=SOURCE, first_seen=rr["published"]))
        for mid in rr["malware_ids"]:
            m.edges.append(edge("REPORTS_ON", rid, mid, source=SOURCE, first_seen=rr["published"]))
        for cve_id in rr["cve_ids"]:
            m.edges.append(edge("REPORTS_ON", rid, f"cve:{cve_id}", source=SOURCE, first_seen=rr["published"]))
        for tid in rr["technique_ids"]:
            m.edges.append(edge("REPORTS_ON", rid, technique_node_id(tid), source=SOURCE, first_seen=rr["published"]))
        for iid in ind_ids:
            m.edges.append(edge("REPORTS_ON", rid, iid, source=SOURCE, first_seen=rr["published"]))


# ----------------------------------------------------------------------------- orchestration


def build_model(indicator_target: int = 400) -> Model:
    m = Model()
    _build_techniques(m)
    _build_vulnerabilities(m)
    _build_actors(m)
    _build_malware(m)
    _build_campaigns(m)
    _build_exploits(m)
    campaign_reports = _build_reports(m)
    _build_storyline_indicators(m)
    _build_plants(m, campaign_reports)
    generated = indicator_target - len(m.indicators)
    _build_generated_indicators(m, campaign_reports, generated)
    _finalize(m, campaign_reports)

    m.counts = {
        "actors": len(cat.ACTORS), "campaigns": len(cat.CAMPAIGNS), "malware": len(cat.MALWARE),
        "techniques": len(TECHNIQUES), "vulnerabilities": len(CVES), "indicators": len(m.indicators),
        "reports": len(m.reports), "exploits": len(cat.EXPLOITS), "low_confidence_plants": len(m.plants),
        "nodes": len(m.nodes), "edges": len(m.edges),
    }
    return m


def generate(out_dir: Path) -> dict[str, Any]:
    """Generate the threat-intel stage into ``out_dir``. Returns the GenerateResult dict (06 section 2)."""
    out_dir = Path(out_dir)
    m = build_model()

    nodes_path = out_dir / "graph" / "ti_nodes.jsonl"
    edges_path = out_dir / "graph" / "ti_edges.jsonl"
    write_jsonl(nodes_path, m.nodes)
    write_jsonl(edges_path, m.edges)

    raw_dir = out_dir / "raw" / "ti"
    raw_paths = feeds.write_all(raw_dir, m)

    return {"nodes": nodes_path, "edges": edges_path, "raw": raw_paths, "counts": m.counts}
