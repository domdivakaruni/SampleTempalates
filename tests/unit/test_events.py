"""Unit tests for the events stage of the data simulator.

Covers: generation against the hand-written stub inventory in < 30 s, exact storyline/noise ids with their
canonical timestamps and severities, the a001 process chain, the anomalous A7 SSH logon, edge-endpoint
integrity (every endpoint resolves to events output, the inventory, or an externally-provided
``technique:attack:*`` / ``cve:*`` id), schema node validation, determinism (two byte-identical runs) and
scale counts within +-30% of docs/04 section 7.
"""
from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path

import pytest

from throughline.graph.context_graph import ContextGraph
from throughline.schema.registry import validate_edge, validate_node
from throughline.simulator import storyline_constants as S
from throughline.simulator.common import at, read_jsonl
from throughline.simulator.events import generate, resolve_inventory

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "mini_inventory.json"

# externally-provided id prefixes (threat-intel stage creates AttackTechnique; inventory/TI create Vulnerability)
_EXTERNAL_PREFIX = re.compile(r"^(technique:attack:|cve:)")
_PREFIX_LABEL = {
    "technique:attack:": "AttackTechnique", "cve:": "Vulnerability", "endpoint:": "Endpoint",
    "vm:": "VirtualMachine", "user:okta:": "HumanUser", "identity:": "ServiceAccount", "role:": "IamRole",
    "bucket:": "StorageBucket", "secret:": "Secret", "database:": "Database", "app:": "Application",
    "team:": "Team", "account:": "CloudAccount", "iamuser:": "IamUser", "group:": "Group",
}


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict:
    out = tmp_path_factory.mktemp("events-out")
    t0 = time.time()
    result = generate(out, inventory_path=FIXTURE)
    elapsed = time.time() - t0
    nodes = read_jsonl(result["nodes"])
    edges = read_jsonl(result["edges"])
    inv = resolve_inventory(FIXTURE, out)
    return {"out": out, "result": result, "nodes": nodes, "edges": edges, "inv": inv,
            "by_id": {n["id"]: n for n in nodes}, "elapsed": elapsed}


def test_generation_is_fast(built: dict) -> None:
    assert built["elapsed"] < 30, f"generation took {built['elapsed']:.1f}s"


def test_fixture_exists() -> None:
    assert FIXTURE.exists(), "run inventory_stub.write_mini_fixture to (re)create the fixture"


# --------------------------------------------------------------------- exact ids / timestamps / severity


def test_storyline_and_noise_alert_ids_exact(built: dict) -> None:
    by_id = built["by_id"]
    expected = {**S.ALERT_A, **S.ALERT_B}
    for _, (nid, ts_, sev) in expected.items():
        assert nid in by_id, f"missing alert {nid}"
        assert by_id[nid]["props"]["detected_at"] == at(ts_), nid
        assert by_id[nid]["props"]["vendor_severity"] == sev, nid
    for _, (nid, ts_, sev) in S.ALERT_N.items():
        if nid == "alert:cspm:iss-n002":
            assert nid not in by_id, "iss-n002 is owned by the inventory stage, not events"
            continue
        assert nid in by_id, f"missing noise alert {nid}"
        assert by_id[nid]["props"]["detected_at"] == at(ts_), nid
        assert by_id[nid]["props"]["vendor_severity"] == sev, nid
    for qid in S.QUARANTINE_ALERT_IDS:
        assert qid in by_id, f"missing quarantine alert {qid}"
    assert len(S.QUARANTINE_ALERT_IDS) == 12


def test_cloud_events_exact(built: dict) -> None:
    by_id = built["by_id"]
    for _, (eid, etime, ename, esrc, akid, success, err, count) in S.CLOUDEVENTS_A.items():
        assert eid in by_id, f"missing cloud event {eid}"
        p = by_id[eid]["props"]
        assert p["event_time"] == at(etime), eid
        assert p["event_name"] == ename and p["event_source"] == esrc, eid
        assert p["access_key_id"] == akid and p["success"] == success, eid
        assert p["error_code"] == err and p["count"] == count, eid
    assert by_id["cloudevent:aws:evt-a014"]["props"]["bytes"] == S.EXFIL_BYTES


def test_credentials_exact(built: dict) -> None:
    by_id = built["by_id"]
    ssh = by_id[S.CRED_SSH_KEY]["props"]
    assert ssh["credential_type"] == "ssh_private_key" and ssh["principal_id"] == S.SVC_FINOPS_SFTP
    bastion = by_id[S.CRED_BASTION_KEY]["props"]
    assert bastion["credential_type"] == "aws_temporary_key" and bastion["status"] == "expired"
    assert bastion["issued_at"] == at("2026-09-10T02:11:45Z")
    assert bastion["expires_at"] == at("2026-09-10T08:11:45Z")
    prod = by_id[S.CRED_PROD_KEY]["props"]
    assert prod["derived_from"] == S.CRED_BASTION_KEY and prod["status"] == "expired"


def test_c2_domain_and_ips_reputation_unknown(built: dict) -> None:
    by_id = built["by_id"]
    for nid in (f"domain:dns:{S.C2_DOMAIN}", f"ip:v4:{S.C2_IP}",
                f"ip:v4:{S.ATTACKER_EGRESS_IP}", f"ip:v4:{S.SALTWORKS_IP}"):
        assert nid in by_id, f"missing {nid}"
        assert by_id[nid]["props"]["reputation"] == "unknown", nid


def test_ca_a017_and_waf_b001_anchors(built: dict) -> None:
    edges = built["edges"]

    def has(t: str, s: str, d: str) -> bool:
        return any(e["type"] == t and e["src"] == s and e["dst"] == d for e in edges)

    assert has("ON_RESOURCE", "alert:cloud-anomaly:ca-a017", S.PROD_READER_ROLE)
    assert has("INVOLVES", "alert:cloud-anomaly:ca-a017", S.CRED_PROD_KEY)
    assert has("INVOLVES", "alert:cloud-anomaly:ca-a017", f"ip:v4:{S.ATTACKER_EGRESS_IP}")
    for key in ("a013", "a014", "a015", "a016"):
        assert has("INVOLVES", "alert:cloud-anomaly:ca-a017", S.CLOUDEVENTS_A[key][0])
    assert has("ON_RESOURCE", "alert:waf:waf-b001", S.EDGE_VM)
    assert has("INVOLVES", "alert:waf:waf-b001", f"ip:v4:{S.SALTWORKS_IP}")


# --------------------------------------------------------------------- process chain / logon / joins


def test_a001_process_chain(built: dict) -> None:
    nodes, edges = built["nodes"], built["edges"]
    procs = [n for n in nodes if n["label"] == "Process" and n["props"]["endpoint_id"] == S.WKS_DANA]
    by_img: dict[str, list[str]] = {}
    for p in procs:
        base = p["props"]["image_path"].replace("\\", "/").rsplit("/", 1)[-1].lower()
        by_img.setdefault(base, []).append(p["id"])
    spawned = {(e["src"], e["dst"]) for e in edges if e["type"] == "SPAWNED"}
    explorer = by_img["explorer.exe"][0]
    powershell = by_img["powershell.exe"][0]
    rundll = by_img["rundll32.exe"][0]
    assert (explorer, powershell) in spawned
    assert (powershell, rundll) in spawned


def test_a7_ssh_logon(built: dict) -> None:
    edges = built["edges"]
    ssh = [e for e in edges if e["type"] == "LOGGED_ON" and e["props"].get("logon_type") == "ssh"
           and e["src"] == S.SVC_FINOPS_SFTP and e["dst"] == S.EP_BASTION]
    assert ssh, "anomalous A7 SSH logon missing"
    assert ssh[0]["props"]["logon_time"] == at("2026-09-10T02:05:17Z")
    assert ssh[0]["props"]["source_ip"] == S.WKS_DANA_IP


def test_credential_join_edges(built: dict) -> None:
    edges = built["edges"]
    stolen = {(e["src"], e["dst"]) for e in edges if e["type"] == "STOLEN_BY"}
    used = {(e["src"], e["dst"]) for e in edges if e["type"] == "USED_CREDENTIAL"}
    derived = {(e["src"], e["dst"]) for e in edges if e["type"] == "DERIVED_FROM"}
    assert (S.CRED_SSH_KEY, "alert:falcon:ldt-a005") in stolen
    assert (S.CRED_BASTION_KEY, "alert:falcon:ldt-a009") in stolen
    assert (S.CRED_PROD_KEY, S.CRED_BASTION_KEY) in derived
    assert ("cloudevent:aws:evt-a010", S.CRED_BASTION_KEY) in used
    assert ("cloudevent:aws:evt-a014", S.CRED_PROD_KEY) in used


def test_verdicts_no_malware_family(built: dict) -> None:
    by_id = built["by_id"]
    brackish = by_id[f"file:sha256:{S.HASH_BRACKISH}"]["props"]
    assert brackish["verdict"] == "suspicious" and brackish["malware_family"] == ""
    for h in (S.HASH_MAPLELOADER, S.HASH_NIGHTFERRY, S.HASH_QUILLDROP):
        f = by_id[f"file:sha256:{h}"]["props"]
        assert f["verdict"] == "malicious" and f["malware_family"] == ""


# --------------------------------------------------------------------- schema / integrity


def test_node_validation_passes(built: dict) -> None:
    problems: list[str] = []
    for n in built["nodes"]:
        problems += validate_node(n)
    assert not problems, problems[:20]


def test_no_duplicate_node_ids(built: dict) -> None:
    ids = [n["id"] for n in built["nodes"]]
    assert len(ids) == len(set(ids))


def _label_map(nodes: list[dict], edges: list[dict]) -> dict[str, str]:
    label_of = {n["id"]: n["label"] for n in nodes}
    for e in edges:
        for endp in (e["src"], e["dst"]):
            if endp not in label_of:
                for prefix, lbl in _PREFIX_LABEL.items():
                    if endp.startswith(prefix):
                        label_of[endp] = lbl
                        break
    return label_of


def test_every_edge_endpoint_resolves(built: dict) -> None:
    nodes, edges, inv = built["nodes"], built["edges"], built["inv"]
    known = {n["id"] for n in nodes} | inv.all_node_ids()
    dangling = [(e["type"], endp) for e in edges for endp in (e["src"], e["dst"])
                if endp not in known and not _EXTERNAL_PREFIX.match(endp)]
    assert not dangling, dangling[:20]


def test_all_edge_pairs_allowed(built: dict) -> None:
    nodes, edges = built["nodes"], built["edges"]
    label_of = _label_map(nodes, edges)
    problems: list[str] = []
    for e in edges:
        problems += validate_edge(e, label_of)
    assert not problems, problems[:20]


def test_loads_into_context_graph(built: dict) -> None:
    nodes, edges = built["nodes"], built["edges"]
    label_of = _label_map(nodes, edges)
    have = {n["id"] for n in nodes}
    referenced = {endp for e in edges for endp in (e["src"], e["dst"])}
    stub = [{"id": nid, "label": label_of[nid], "name": nid.split(":")[-1], "source": "stub",
             "source_id": nid.split(":")[-1], "first_seen": None, "last_seen": None, "confidence": 1.0,
             "props": {}} for nid in referenced - have if nid in label_of]
    g = ContextGraph.from_records(nodes + stub, edges)
    assert not g.validate()


# --------------------------------------------------------------------- determinism


def test_deterministic_byte_identical(tmp_path_factory: pytest.TempPathFactory) -> None:
    def digest(dir_name: str) -> tuple[str, str]:
        out = tmp_path_factory.mktemp(dir_name)
        res = generate(out, inventory_path=FIXTURE)
        n = hashlib.sha256(Path(res["nodes"]).read_bytes()).hexdigest()
        e = hashlib.sha256(Path(res["edges"]).read_bytes()).hexdigest()
        return n, e

    assert digest("det-a") == digest("det-b")


# --------------------------------------------------------------------- scale (docs/04 section 7, +-30%)


def _band(target: int) -> tuple[int, int]:
    return int(target * 0.7), int(target * 1.3)


def test_scale_counts_within_30pct(built: dict) -> None:
    nodes = built["nodes"]
    by_label: dict[str, int] = {}
    for n in nodes:
        by_label[n["label"]] = by_label.get(n["label"], 0) + 1
    alerts_by_source: dict[str, int] = {}
    for n in nodes:
        if n["label"] == "Alert":
            src = n["props"]["source_system"]
            alerts_by_source[src] = alerts_by_source.get(src, 0) + 1
    external = by_label.get("IpAddress", 0) + by_label.get("Domain", 0)

    checks = {
        "EDR detections (falcon)": (alerts_by_source.get("falcon", 0), 600),
        "WAF alerts": (alerts_by_source.get("waf", 0), 400),
        "IDS alerts": (alerts_by_source.get("ids", 0), 120),
        "cloud-anomaly alerts": (alerts_by_source.get("cloud-anomaly", 0), 10),
        "okta alerts": (alerts_by_source.get("okta", 0), 10),
        "incidents": (by_label.get("Incident", 0), 45),
        "cloud events": (by_label.get("CloudEvent", 0), 2500),
        "process nodes": (by_label.get("Process", 0), 6000),
        "file nodes": (by_label.get("File", 0), 1500),
        "external ip/domain nodes": (external, 800),
    }
    failures = []
    for name, (value, target) in checks.items():
        lo, hi = _band(target)
        if not (lo <= value <= hi):
            failures.append(f"{name}: {value} not in [{lo},{hi}] (target {target})")
    assert not failures, failures


# --------------------------------------------------------------------- stub fallback


def test_stub_fallback_when_no_inventory(tmp_path: Path) -> None:
    # no inventory_path and no <out>/inventory.json -> synthesized stub, still produces the storyline
    result = generate(tmp_path)
    assert result["counts"]["inventory_source"] == "stub"
    by_id = {n["id"]: n for n in read_jsonl(result["nodes"])}
    assert "alert:falcon:ldt-a009" in by_id
    assert S.CRED_BASTION_KEY in by_id
