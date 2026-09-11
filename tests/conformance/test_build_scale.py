"""Slow: build a synthetic ~20k-node / ~100k-edge graph through the Parquet COPY path and check the time budget.

Run with ``THROUGHLINE_RUN_SLOW=1 pytest tests/conformance/test_build_scale.py -q`` (skipped by default).
"""
from __future__ import annotations

import importlib.util
import random
import sys
import time
from pathlib import Path

import pytest

from throughline.graph import loader
from throughline.simulator.common import edge, node, write_jsonl

from .conftest import EMBEDDED_ENGINE, RUN_SLOW

pytestmark = pytest.mark.slow

BUDGET_S = 90.0


def synthesize(out_dir: Path, n_vms: int = 4000, seed: int = 7) -> tuple[int, int]:
    """A registry-valid estate: VMs with endpoints, roles, buckets, alerts, users, CVEs, cloud events, processes."""
    rng = random.Random(seed)
    nodes: list[dict] = []
    edges: list[dict] = []
    account = "account:aws:111111111111"
    nodes.append(node(account, "CloudAccount", "prod", {"provider": "aws", "account_id": "111111111111", "environment": "prod"}, source="wiz-sim"))
    internet = "internet:global:internet"
    nodes.append(node(internet, "Internet", "internet", {}, source="derived"))
    roles = [f"role:aws:111111111111:Role{i}" for i in range(1500)]
    buckets = [f"bucket:aws:bucket-{i}" for i in range(800)]
    secrets = [f"secret:aws:111111111111:prod/secret-{i}" for i in range(300)]
    users = [f"user:okta:user{i}" for i in range(3000)]
    cves = [f"cve:CVE-2026-{90000 + i}" for i in range(60)]
    ips = [f"ip:v4:203.0.113.{i % 250}-{i}" for i in range(600)]
    for i, rid in enumerate(roles):
        nodes.append(node(rid, "IamRole", f"Role{i}", {"provider": "aws", "account_id": "111111111111", "arn": f"arn:aws:iam::111111111111:role/Role{i}", "role_type": "instance", "is_admin": i % 97 == 0, "privilege_score": rng.random(), "trust_principals": ["ec2.amazonaws.com"]}, source="wiz-sim"))
        edges.append(edge("CONTAINS", account, rid, source="wiz-sim"))
        for _ in range(4):
            edges.append(edge("CAN_ACCESS", rid, rng.choice(buckets), {"access_level": "read", "path_length": 1, "transitive": False}, source="derived"))
        if i % 3 == 0:
            edges.append(edge("CAN_ASSUME", rid, rng.choice(roles), {"via": "trust_policy", "cross_account": False}, source="wiz-sim"))
            edges.append(edge("CAN_ACCESS", rid, rng.choice(secrets), {"access_level": "read", "path_length": 2, "transitive": True}, source="derived"))
    for i, bid in enumerate(buckets):
        nodes.append(node(bid, "StorageBucket", f"bucket-{i}", {"provider": "aws", "account_id": "111111111111", "public": i % 50 == 0, "encrypted": True, "data_classifications": ["PCI"] if i % 40 == 0 else ["INTERNAL"], "sensitivity": "critical" if i % 40 == 0 else "low", "crown_jewel": i % 40 == 0, "size_gb": rng.random() * 1000}, source="wiz-sim"))
        edges.append(edge("CONTAINS", account, bid, source="wiz-sim"))
    for i, sid in enumerate(secrets):
        nodes.append(node(sid, "Secret", f"secret-{i}", {"provider": "aws", "account_id": "111111111111", "secret_type": "api_key", "sensitivity": "high", "rotated_days_ago": i}, source="wiz-sim"))
        edges.append(edge("CONTAINS", account, sid, source="wiz-sim"))
    for i, cid in enumerate(cves):
        nodes.append(node(cid, "Vulnerability", cid.split(":")[-1], {"cve_id": cid.split(":")[-1], "cvss": 5 + 5 * rng.random(), "kev": i % 5 == 0, "exploitation_status": "active" if i % 5 == 0 else "none", "synthetic": True}, source="ti-sim"))
    for i, uid in enumerate(users):
        nodes.append(node(uid, "HumanUser", f"User {i}", {"email": f"user{i}@corp.larkspur.example", "display_name": f"User {i}", "department": "Engineering", "is_privileged": i % 100 == 0, "mfa_enabled": True, "status": "active"}, source="okta-sim"))
    for ip in ips:
        nodes.append(node(ip, "IpAddress", ip.split(":")[-1], {"address": ip.split(":")[-1], "is_private": False, "reputation": "unknown"}, source="falcon-sim"))
    alert_no = 0
    for i in range(n_vms):
        vid = f"vm:aws:i-{i:016x}"
        nodes.append(node(vid, "VirtualMachine", f"host-{i}", {"provider": "aws", "account_id": "111111111111", "hostname": f"host-{i}.prod.larkspur.internal", "private_ip": f"10.{(i >> 8) & 255}.{i & 255}.10", "os_family": "linux", "environment": "prod", "exposure": "internet" if i % 20 == 0 else "internal", "has_edr_sensor": i % 10 != 0, "is_k8s_node": False, "tags": {"env": "prod", "n": i}, "criticality": "tier-2"}, source="wiz-sim"))
        edges.append(edge("CONTAINS", account, vid, source="wiz-sim"))
        edges.append(edge("HAS_ROLE", vid, roles[i % len(roles)], {"via": "instance_profile"}, source="wiz-sim"))
        for cid in rng.sample(cves, 10):
            edges.append(edge("VULNERABLE_TO", vid, cid, {"exploitable": True}, source="derived"))
        if i % 20 == 0:
            edges.append(edge("EXPOSES", internet, vid, {"ports": ["443/tcp"], "via": "security_group"}, source="derived"))
        if i % 10 != 0:
            eid = f"endpoint:falcon:aid-{i:08x}"
            nodes.append(node(eid, "Endpoint", f"host-{i}", {"hostname": f"host-{i}", "device_type": "server", "os_family": "linux", "private_ip": f"10.{(i >> 8) & 255}.{i & 255}.10", "cloud_instance_id": f"i-{i:016x}", "containment_status": "normal"}, source="falcon-sim"))
            edges.append(edge("SAME_AS", eid, vid, {"method": "instance_id"}, source="derived", confidence=0.99))
            edges.append(edge("PRIMARY_USER", eid, users[i % len(users)], source="falcon-sim"))
            edges.append(edge("LOGGED_ON", users[(i * 7) % len(users)], eid, {"logon_type": "ssh"}, source="falcon-sim"))
            for _ in range(3):
                alert_no += 1
                aid = f"alert:falcon:ldt-s{alert_no:06d}"
                nodes.append(node(aid, "Alert", f"Detection {alert_no}", {"source_system": "falcon", "alert_type": "detection", "title": f"Detection {alert_no}", "vendor_severity": rng.choice(["low", "medium", "high"]), "vendor_severity_rank": 2, "status": "new", "detected_at": "2026-09-10T02:11:45Z", "techniques": ["T1059.004", "T1552.005"], "contextual_score": rng.randint(0, 100), "raw": {"k": alert_no}, "reaches_crown_jewel": False, "on_attack_path": False}, source="falcon-sim"))
                edges.append(edge("ON_ENDPOINT", aid, eid, source="falcon-sim"))
                edges.append(edge("INVOLVES", aid, rng.choice(ips), {"role": "destination"}, source="falcon-sim"))
            pid = f"process:falcon:aid-{i:08x}:{1000 + i}:1757470305"
            nodes.append(node(pid, "Process", "bash", {"endpoint_id": eid, "pid": 1000 + i, "image_path": "/bin/bash", "signed": True}, source="falcon-sim"))
            edges.append(edge("RAN_ON", pid, eid, source="falcon-sim"))
            for ip in rng.sample(ips, 3):
                edges.append(edge("CONNECTED_TO", pid, ip, {"port": 443, "protocol": "tcp", "direction": "outbound", "count": 3}, source="falcon-sim"))
        if i % 2 == 0:
            evid = f"cloudevent:aws:evt-s{i:07d}"
            nodes.append(node(evid, "CloudEvent", "GetObject", {"provider": "aws", "account_id": "111111111111", "event_name": "GetObject", "event_source": "s3.amazonaws.com", "event_time": "2026-09-10T02:26:00Z", "success": True, "count": 1, "anomalous": False}, source="cloudtrail-sim"))
            edges.append(edge("PERFORMED_BY", evid, roles[i % len(roles)], source="cloudtrail-sim"))
            edges.append(edge("TARGETED", evid, rng.choice(buckets), source="cloudtrail-sim"))
            edges.append(edge("FROM_IP", evid, rng.choice(ips), source="cloudtrail-sim"))
    graph_dir = out_dir / "graph"
    write_jsonl(graph_dir / "nodes.jsonl", nodes)
    write_jsonl(graph_dir / "edges.jsonl", edges)
    (graph_dir / "manifest.json").write_text('{"seed": 7, "synthetic": true}', encoding="utf-8")
    return len(nodes), len(edges)


@pytest.mark.skipif(not RUN_SLOW, reason="set THROUGHLINE_RUN_SLOW=1 to run the 20k-node build benchmark")
def test_build_20k_nodes_within_budget(tmp_path: Path) -> None:
    if importlib.util.find_spec(EMBEDDED_ENGINE) is None:
        pytest.skip(f"{EMBEDDED_ENGINE} not installed")
    other = "kuzu" if EMBEDDED_ENGINE == "ladybug" else "ladybug"
    if other in sys.modules:
        pytest.skip(f"{other} already imported")
    from throughline.graph.ladybug_store import LadybugStore

    n_nodes, n_edges = synthesize(tmp_path)
    assert n_nodes >= 20000 and n_edges >= 100000
    store = LadybugStore(tmp_path / "graph.lbdb", engine=EMBEDDED_ENGINE)
    t0 = time.perf_counter()
    assert loader.build_embedded_db(store, tmp_path) is True
    elapsed = time.perf_counter() - t0
    store.open()
    stats = store.stats()
    sidecar = store.stored_manifest()
    assert stats.total_nodes == n_nodes
    assert stats.total_edges == n_edges - sidecar["duplicate_edges"]  # same-type parallel edges collapse (first wins)
    assert set(sidecar["load_method"].values()) == {"copy"}
    fragment = store.neighborhood("vm:aws:i-0000000000000000", depth=2)
    assert fragment.nodes[0].id == "vm:aws:i-0000000000000000" and len(fragment.nodes) > 1
    result = store.run_readonly_cypher("MATCH (a:Alert)-[:ON_ENDPOINT]->(e:Endpoint)-[:SAME_AS]->(v:VirtualMachine)-[:HAS_ROLE]->(r:IamRole)-[:CAN_ACCESS]->(b:StorageBucket) WHERE b.crown_jewel RETURN a.id, b.name LIMIT 20")
    assert result.rows
    store.close()
    print(f"\nbuilt {n_nodes} nodes / {n_edges} edges on {EMBEDDED_ENGINE} in {elapsed:.1f}s; timings {store.stored_manifest()['timings_s']}")
    assert elapsed < BUDGET_S, f"build took {elapsed:.1f}s (> {BUDGET_S}s)"
