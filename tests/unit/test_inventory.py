"""Unit tests for the inventory simulator stage (Agent A1).

The generator runs once per test session into a temporary directory; a second run checks determinism.
"""
from __future__ import annotations

import filecmp
import json
import time
from pathlib import Path

import pytest

from throughline.graph.context_graph import ContextGraph
from throughline.schema import validate_node
from throughline.simulator import storyline_constants as sc
from throughline.simulator.catalog.cves import CVES
from throughline.simulator.common import read_jsonl
from throughline.simulator.inventory import generate

TARGETS = {
    "VPC": 30, "Subnet": 90, "SecurityGroup": 150, "LoadBalancer": 25, "VirtualMachine": 650, "Workload": 260, "ServerlessFunction": 120,
    "StorageBucket": 180, "Database": 40, "Secret": 60, "IamRole": 400, "IamUser": 80, "AccessKey": 100, "IamPolicy": 300, "ContainerImage": 400,
    "Package": 2500, "Application": 45, "Team": 18, "HumanUser": 1400, "Group": 60, "Endpoint": 2000, "Alert": 600,
}
EDGE_TARGETS = {"VULNERABLE_TO": 3000, "SAME_AS": 560}


@pytest.fixture(scope="session")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict:
    out = tmp_path_factory.mktemp("inventory")
    started = time.perf_counter()
    result = generate(out)
    elapsed = time.perf_counter() - started
    nodes = read_jsonl(result["nodes"])
    edges = read_jsonl(result["edges"])
    return {"out": out, "result": result, "elapsed": elapsed, "nodes": nodes, "edges": edges, "by_id": {n["id"]: n for n in nodes}}


def _edges(gen: dict, etype: str, src: str | None = None, dst: str | None = None) -> list[dict]:
    return [e for e in gen["edges"] if e["type"] == etype and (src is None or e["src"] == src) and (dst is None or e["dst"] == dst)]


def _one(gen: dict, etype: str, src: str, dst: str) -> dict:
    found = _edges(gen, etype, src, dst)
    assert len(found) == 1, f"expected exactly one {etype} {src} -> {dst}, got {len(found)}"
    return found[0]


# ---------------------------------------------------------------------------- shape and scale


def test_runs_fast_and_writes_outputs(generated: dict) -> None:
    assert generated["elapsed"] < 40
    out: Path = generated["out"]
    assert (out / "graph" / "inventory_nodes.jsonl").exists()
    assert (out / "graph" / "inventory_edges.jsonl").exists()
    assert (out / "inventory.json").exists()
    for rel in ("wiz/cloud_resources.jsonl", "wiz/iam.jsonl", "wiz/network.jsonl", "wiz/vulnerabilities.jsonl", "wiz/issues.jsonl", "wiz/business_context.jsonl", "falcon/devices.jsonl", "okta/users.jsonl"):
        path = out / "raw" / rel
        assert path.exists() and path.stat().st_size > 0, rel
    result = generated["result"]
    assert set(result) >= {"nodes", "edges", "raw", "counts"}


def test_counts_within_targets(generated: dict) -> None:
    counts = generated["result"]["counts"]["nodes"]
    for label, target in TARGETS.items():
        assert target * 0.7 <= counts.get(label, 0) <= target * 1.3, f"{label}: {counts.get(label)} vs target {target}"
    ecounts = generated["result"]["counts"]["edges"]
    for etype, target in EDGE_TARGETS.items():
        assert target * 0.7 <= ecounts.get(etype, 0) <= target * 1.3, f"{etype}: {ecounts.get(etype)} vs target {target}"
    k8s_nodes = sum(1 for n in generated["nodes"] if n["label"] == "VirtualMachine" and n["props"]["is_k8s_node"])
    assert 84 <= k8s_nodes <= 156
    assert counts["KubernetesCluster"] == 3
    assert counts["CloudAccount"] == 8
    assert counts["Internet"] == 1


def test_every_node_valid_and_ids_unique(generated: dict) -> None:
    ids = [n["id"] for n in generated["nodes"]]
    assert len(ids) == len(set(ids))
    for n in generated["nodes"]:
        assert validate_node(n) == [], n["id"]
        assert n["first_seen"] <= n["last_seen"] <= "2026-09-11T14:00:00Z", n["id"]
        assert n["source"] in ("wiz-sim", "falcon-sim", "okta-sim", "derived")


def test_edges_reference_existing_nodes_and_allowed_pairs(generated: dict) -> None:
    by_id = generated["by_id"]
    dangling = [e for e in generated["edges"] if e["src"] not in by_id or (e["dst"] not in by_id and not e["dst"].startswith("cve:"))]
    assert dangling == []
    cve_refs = {e["dst"] for e in generated["edges"] if e["dst"].startswith("cve:")}
    assert cve_refs <= {c.node_id for c in CVES.values()}
    stubs = [{"id": c, "label": "Vulnerability", "name": c, "source": "ti-sim", "source_id": c, "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-01-01T00:00:00Z", "confidence": 1.0, "props": {}} for c in sorted(cve_refs)]
    graph = ContextGraph.from_records(generated["nodes"] + stubs, generated["edges"])
    assert graph.validate() == []
    keys = [(e["type"], e["src"], e["dst"]) for e in generated["edges"]]
    assert len(keys) == len(set(keys)), "duplicate (type, src, dst) edges"


def test_derived_edges_marked_derived(generated: dict) -> None:
    for e in generated["edges"]:
        if e["type"] in ("EXPOSES", "VULNERABLE_TO", "CAN_ACCESS", "SAME_AS"):
            assert e["source"] == "derived", e


# ---------------------------------------------------------------------------- storyline: bastion path


def test_bastion_vm_properties(generated: dict) -> None:
    vm = generated["by_id"][sc.BASTION_VM]
    p = vm["props"]
    assert vm["name"] == "bas-01" and p["hostname"] == sc.BASTION_HOSTNAME
    assert p["private_ip"] == sc.BASTION_PRIVATE_IP and p["public_ip"] == sc.BASTION_PUBLIC_IP
    assert p["os"] == "Amazon Linux 2023" and p["account_id"] == "222222222222" and p["exposure"] == "internal"
    assert p["tags"]["role"] == "bastion" and p["tags"]["owner"] == "platform-eng" and p["tags"]["env"] == "prod"
    assert p["has_edr_sensor"] is True
    _one(generated, "IN_SUBNET", sc.BASTION_VM, sc.BASTION_SUBNET)
    assert _one(generated, "HAS_ROLE", sc.BASTION_VM, sc.BASTION_ROLE)["props"]["via"] == "instance_profile"
    assert _edges(generated, "EXPOSES", dst=sc.BASTION_VM) == []
    sgs = [e["dst"] for e in _edges(generated, "HAS_SECURITY_GROUP", src=sc.BASTION_VM)]
    rules = [r for sg in sgs for r in generated["by_id"][sg]["props"]["inbound_rules"]]
    assert any(r["cidr"] == "10.99.0.0/16" and r["port_from"] == 22 for r in rules)
    assert not any(r["cidr"] == "0.0.0.0/0" for r in rules)


def test_bastion_role_chain(generated: dict) -> None:
    policies = {e["dst"] for e in _edges(generated, "HAS_POLICY", src=sc.BASTION_ROLE)}
    assert {sc.BASTION_ASSUME_POLICY, sc.BASTION_LOGS_POLICY} <= policies
    assert any("SSMManagedInstanceCore" in p for p in policies)
    assume = _one(generated, "GRANTS", sc.BASTION_ASSUME_POLICY, sc.PROD_READER_ROLE)
    assert assume["props"]["access_level"] == "assume" and "sts:AssumeRole" in assume["props"]["actions"]
    assert _one(generated, "GRANTS", sc.BASTION_LOGS_POLICY, sc.SHARED_LOGS_BUCKET)["props"]["access_level"] == "write"
    ca = _one(generated, "CAN_ASSUME", sc.BASTION_ROLE, sc.PROD_READER_ROLE)
    assert ca["props"] == {"via": "trust_policy", "cross_account": True}
    reader = generated["by_id"][sc.PROD_READER_ROLE]["props"]
    assert reader["trust_principals"] == [sc.BASTION_ROLE_ARN]
    grants = {e["dst"]: e["props"] for e in _edges(generated, "GRANTS", src=sc.PROD_READER_POLICY)}
    assert set(grants) == {sc.CARDHOLDER_VAULT, sc.KYC_DOCS, sc.DB_READER_SECRET, sc.HSM_SECRET, sc.CARDHOLDER_DB}
    assert set(grants[sc.CARDHOLDER_VAULT]["actions"]) == {"s3:GetObject", "s3:ListBucket"} and grants[sc.CARDHOLDER_VAULT]["access_level"] == "read"
    assert grants[sc.DB_READER_SECRET]["actions"] == ["secretsmanager:GetSecretValue"]
    assert grants[sc.CARDHOLDER_DB]["actions"] == ["rds:DescribeDBInstances"]
    assert _one(generated, "UNLOCKS", sc.DB_READER_SECRET, sc.CARDHOLDER_DB)["props"]["credential_type"] == "db_credentials"


def test_bastion_effective_access(generated: dict) -> None:
    targets = [sc.CARDHOLDER_VAULT, sc.KYC_DOCS, sc.DB_READER_SECRET, sc.HSM_SECRET]
    for t in targets:
        direct = _one(generated, "CAN_ACCESS", sc.PROD_READER_ROLE, t)["props"]
        assert direct["path_length"] == 1 and direct["transitive"] is False and direct["access_level"] == "read"
        via_role = _one(generated, "CAN_ACCESS", sc.BASTION_ROLE, t)["props"]
        assert via_role["path_length"] == 2 and via_role["transitive"] is True
        assert sc.PROD_READER_ROLE in via_role["via"].split(",")
        via_vm = _one(generated, "CAN_ACCESS", sc.BASTION_VM, t)["props"]
        assert via_vm["transitive"] is True and via_vm["path_length"] == 3
        assert via_vm["via"].split(",")[:2] == [sc.BASTION_ROLE, sc.PROD_READER_ROLE]
    assert _one(generated, "CAN_ACCESS", sc.BASTION_ROLE, sc.SHARED_LOGS_BUCKET)["props"]["access_level"] == "write"
    assert generated["by_id"][sc.BASTION_VM]["props"]["crown_jewel_reach"] >= 3


def test_crown_jewels(generated: dict) -> None:
    vault = generated["by_id"][sc.CARDHOLDER_VAULT]["props"]
    assert vault["data_classifications"] == ["PCI"] and vault["sensitivity"] == "critical" and vault["crown_jewel"] is True
    assert vault["encrypted"] is True and vault["public"] is False and vault["account_id"] == "111111111111" and 3000 < vault["size_gb"] < 5000
    kyc = generated["by_id"][sc.KYC_DOCS]["props"]
    assert kyc["data_classifications"] == ["PII"] and kyc["sensitivity"] == "high" and kyc["crown_jewel"] is True
    db = generated["by_id"][sc.CARDHOLDER_DB]["props"]
    assert db["data_classifications"] == ["PCI"] and db["sensitivity"] == "critical" and db["crown_jewel"] is True and db["public"] is False
    assert "postgres" in db["engine"]
    assert generated["by_id"][sc.HSM_SECRET]["props"]["sensitivity"] == "critical"
    for rid in (sc.CARDHOLDER_VAULT, sc.KYC_DOCS, sc.CARDHOLDER_DB, sc.DB_READER_SECRET, sc.HSM_SECRET):
        _one(generated, "PART_OF", rid, sc.APP_CARD_ISSUING)
    deps = {e["dst"] for e in _edges(generated, "DEPENDS_ON", src=sc.APP_CARD_ISSUING)}
    assert {sc.CARDHOLDER_DB, sc.CARDHOLDER_VAULT} <= deps
    assert generated["by_id"][sc.APP_CARD_ISSUING]["props"]["criticality"] == "tier-0"
    _one(generated, "OWNED_BY", sc.APP_CARD_ISSUING, sc.TEAM_PAYMENTS)


# ---------------------------------------------------------------------------- storyline: statement-render


def test_edge_vm_exposure_and_vulnerability(generated: dict) -> None:
    vm = generated["by_id"][sc.EDGE_VM]
    p = vm["props"]
    assert vm["name"] == sc.EDGE_NAME and p["hostname"] == sc.EDGE_HOSTNAME and p["private_ip"] == sc.EDGE_PRIVATE_IP and p["public_ip"] == sc.EDGE_PUBLIC_IP
    assert p["os"] == "Ubuntu 22.04" and p["account_id"] == "111111111111" and p["exposure"] == "internet"
    _one(generated, "HAS_SECURITY_GROUP", sc.EDGE_VM, sc.EDGE_SG)
    sg = generated["by_id"][sc.EDGE_SG]["props"]
    assert sg["open_to_internet"] is True and sg["internet_ports"] == ["8080"]
    assert any(r["cidr"] == "0.0.0.0/0" and r["port_from"] == 8080 and r["protocol"] == "tcp" for r in sg["inbound_rules"])
    exp = _one(generated, "EXPOSES", "internet:global:internet", sc.EDGE_VM)["props"]
    assert exp["ports"] == ["8080"] and exp["via"] == "security_group"
    _one(generated, "RUNS_IMAGE", sc.EDGE_VM, sc.EDGE_IMAGE)
    _one(generated, "HAS_PACKAGE", sc.EDGE_VM, sc.EDGE_LOG4J_PACKAGE)
    pkg = generated["by_id"][sc.EDGE_LOG4J_PACKAGE]["props"]
    assert pkg["package_name"] == "log4j-core" and pkg["version"] == "2.14.1" and pkg["ecosystem"] == "maven"
    _one(generated, "HAS_VULNERABILITY", sc.EDGE_LOG4J_PACKAGE, sc.LOG4SHELL)
    image_pkgs = [e["dst"] for e in _edges(generated, "HAS_PACKAGE", src=sc.EDGE_IMAGE)]
    assert any(generated["by_id"][x]["props"]["package_name"] == "log4j-core" for x in image_pkgs)
    vuln = _one(generated, "VULNERABLE_TO", sc.EDGE_VM, sc.LOG4SHELL)["props"]
    assert vuln["exploitable"] is True and vuln["via_package"] == sc.EDGE_LOG4J_PACKAGE
    assert _one(generated, "HAS_ROLE", sc.EDGE_VM, sc.EDGE_ROLE)["props"]["via"] == "instance_profile"
    grants = {e["dst"]: e["props"]["access_level"] for e in _edges(generated, "GRANTS", src=sc.EDGE_POLICY)}
    assert grants == {sc.APP_CONFIG_BUCKET: "read", sc.STATEMENTS_OUT_BUCKET: "write"}
    cfg = generated["by_id"][sc.APP_CONFIG_BUCKET]["props"]
    assert cfg["data_classifications"] == ["SECRETS"] and cfg["contains_credentials_for"] == [sc.CARDHOLDER_DB] and cfg["sensitivity"] == "high"
    _one(generated, "PART_OF", sc.EDGE_VM, sc.APP_STMT_RENDER)
    _one(generated, "OWNED_BY", sc.EDGE_VM, sc.TEAM_PAYMENTS)
    app = generated["by_id"][sc.APP_STMT_RENDER]["props"]
    assert app["criticality"] == "tier-1" and app["owner_team_id"] == sc.TEAM_PAYMENTS and app["service_owner_id"] == sc.USER_LCHEN
    assert _one(generated, "CAN_ACCESS", sc.EDGE_VM, sc.APP_CONFIG_BUCKET)["props"]["access_level"] == "read"


def test_other_exposed_hosts(generated: dict) -> None:
    expected = {
        sc.STG_EDGE_VM: (sc.STG_EDGE_NAME, "333333333333", "8080", sc.LOG4SHELL),
        sc.DEV_LOG4J_VM: (sc.DEV_LOG4J_NAME, "444444444444", "8080", sc.LOG4SHELL),
        "vm:aws:i-0ns1c3d5e7f9a1b3c5": ("ns-gw-01", "222222222222", "443", "cve:CVE-2023-4966"),
        "vm:aws:i-0pan2d4f6a8c0e2a4b": ("vpn-pa-01", "666666666666", "443", "cve:CVE-2024-3400"),
        "vm:aws:i-0spr3e5a7c9b1d3f5e": ("partner-api-3", "111111111111", "443", "cve:CVE-2022-22965"),
        "vm:aws:i-0jnk4f6b8d0c2e4a6c": ("ci-jenkins-01", "222222222222", "8443", "cve:CVE-2024-23897"),
        "vm:aws:i-0cnf5a7c9e1d3b5f7a": ("wiki-confluence-01", "666666666666", "443", "cve:CVE-2023-22515"),
    }
    for vm_id, (name, acct, port, cve) in expected.items():
        vm = generated["by_id"][vm_id]
        assert vm["name"] == name and vm["props"]["account_id"] == acct and vm["props"]["exposure"] == "internet", name
        exp = _one(generated, "EXPOSES", "internet:global:internet", vm_id)["props"]
        assert port in exp["ports"], (name, exp)
        assert _one(generated, "VULNERABLE_TO", vm_id, cve)["props"]["exploitable"] is True
    # role reach: staging edge reads only a staging config bucket; dev testbed, vpn and wiki have no role
    stg_targets = {e["dst"] for e in _edges(generated, "CAN_ACCESS", src=sc.STG_EDGE_VM)}
    assert stg_targets and all(generated["by_id"][t]["props"]["crown_jewel"] is False and generated["by_id"][t]["props"]["account_id"] == "333333333333" for t in stg_targets)
    for vm_id in (sc.DEV_LOG4J_VM, "vm:aws:i-0pan2d4f6a8c0e2a4b", "vm:aws:i-0cnf5a7c9e1d3b5f7a"):
        assert _edges(generated, "HAS_ROLE", src=vm_id) == []
    partner_targets = {e["dst"] for e in _edges(generated, "CAN_ACCESS", src="vm:aws:i-0spr3e5a7c9b1d3f5e")}
    assert any("PII" in generated["by_id"][t]["props"]["data_classifications"] for t in partner_targets)
    jenkins_role = _edges(generated, "HAS_ROLE", src="vm:aws:i-0jnk4f6b8d0c2e4a6c")[0]["dst"]
    assert any(generated["by_id"][e["dst"]]["props"]["account_id"] == "111111111111" for e in _edges(generated, "CAN_ASSUME", src=jenkins_role))
    # the log4j component never leaks onto other hosts
    log4j_hosts = {e["src"] for e in _edges(generated, "VULNERABLE_TO", dst=sc.LOG4SHELL) if e["src"].startswith("vm:")}
    assert log4j_hosts == {sc.EDGE_VM, sc.STG_EDGE_VM, sc.DEV_LOG4J_VM}


def test_noise_resources(generated: dict) -> None:
    mk = generated["by_id"][sc.MARKETING_BUCKET]["props"]
    assert mk["public"] is True and mk["data_classifications"] == ["PUBLIC"] and mk["sensitivity"] == "none" and mk["account_id"] == "666666666666"
    _one(generated, "PART_OF", sc.MARKETING_BUCKET, sc.APP_MARKETING)
    assert generated["by_id"][sc.APP_MARKETING]["props"]["criticality"] == "tier-3"
    assert _one(generated, "EXPOSES", "internet:global:internet", sc.MARKETING_BUCKET)["props"]["via"] == "public_acl"
    dev = generated["by_id"][sc.DEV_SANDBOX_VM]
    assert dev["name"] == sc.DEV_SANDBOX_NAME and dev["props"]["account_id"] == "444444444444" and dev["props"]["exposure"] == "isolated"
    assert _edges(generated, "HAS_ROLE", src=sc.DEV_SANDBOX_VM) == [] and _edges(generated, "CAN_ACCESS", src=sc.DEV_SANDBOX_VM) == []
    scanner = generated["by_id"][sc.SCANNER_VM]
    assert scanner["name"] == sc.SCANNER_NAME and scanner["props"]["private_ip"] == sc.SCANNER_IP and scanner["props"]["tags"]["role"] == "vulnerability-scanner"
    fs = generated["by_id"][sc.FILESHARE_VM]
    assert fs["name"] == sc.FILESHARE_NAME and fs["props"]["os"] == "Windows Server 2022" and fs["props"]["account_id"] == "666666666666"


def test_cspm_issue_n002(generated: dict) -> None:
    alert = generated["by_id"]["alert:cspm:iss-n002"]
    p = alert["props"]
    assert p["source_system"] == "cspm" and p["alert_type"] == "issue" and p["title"] == "S3 bucket allows public read"
    assert p["vendor_severity"] == "critical" and p["vendor_severity_rank"] == 4 and p["detected_at"] == "2026-09-11T06:00:00Z"
    assert p["entity_id"] == sc.MARKETING_BUCKET and p["raw"]["severity"] == "CRITICAL" and p["raw"]["entitySnapshot"]["name"] == "larkspur-marketing-assets"
    _one(generated, "ON_RESOURCE", "alert:cspm:iss-n002", sc.MARKETING_BUCKET)
    alerts = [n for n in generated["nodes"] if n["label"] == "Alert"]
    assert all(a["props"]["source_system"] == "cspm" and a["props"]["alert_type"] == "issue" for a in alerts)
    assert len({a["props"]["title"] for a in alerts}) >= 25
    toxic = [a for a in alerts if a["props"]["title"].startswith("Toxic combination")]
    assert any(e["dst"] == sc.EDGE_VM for a in toxic for e in _edges(generated, "ON_RESOURCE", src=a["id"]))
    assert all(len(_edges(generated, "ON_RESOURCE", src=a["id"])) == 1 for a in alerts)


# ---------------------------------------------------------------------------- endpoints and people


def test_named_endpoints_and_resolution(generated: dict) -> None:
    dana = generated["by_id"][sc.WKS_DANA]["props"]
    assert dana["hostname"] == "WKS-3391" and dana["os"].startswith("Windows 11") and dana["private_ip"] == sc.WKS_DANA_IP
    assert dana["site"] == "Boston office" and dana["primary_user_id"] == sc.USER_DANA and dana["device_type"] == "workstation"
    _one(generated, "PRIMARY_USER", sc.WKS_DANA, sc.USER_DANA)
    bas = generated["by_id"][sc.EP_BASTION]["props"]
    assert bas["hostname"] == "bas-01" and bas["cloud_provider"] == "aws" and bas["cloud_instance_id"] == sc.BASTION_INSTANCE_ID and bas["cloud_account_id"] == "222222222222"
    same = _one(generated, "SAME_AS", sc.EP_BASTION, sc.BASTION_VM)
    assert same["props"]["method"] == "instance_id" and same["props"]["confidence"] == 0.99 and same["confidence"] == 0.99
    for ep, vm in ((sc.EP_EDGE, sc.EDGE_VM), (sc.EP_DEV_SANDBOX, sc.DEV_SANDBOX_VM), (sc.EP_FILESHARE, sc.FILESHARE_VM)):
        assert _one(generated, "SAME_AS", ep, vm)["props"]["method"] == "instance_id"
    assert generated["by_id"][sc.EP_EDGE]["props"]["hostname"] == "stmt-render-2a"
    mreyes = generated["by_id"][sc.EP_MREYES]["props"]
    assert mreyes["hostname"] == sc.EP_MREYES_HOSTNAME and mreyes["primary_user_id"] == sc.USER_MREYES
    pkaur = generated["by_id"][sc.EP_PKAUR]["props"]
    assert pkaur["hostname"] == sc.EP_PKAUR_HOSTNAME and pkaur["os"].startswith("macOS") and pkaur["primary_user_id"] == sc.USER_PKAUR
    methods = {e["props"]["method"] for e in _edges(generated, "SAME_AS")}
    assert methods == {"instance_id", "hostname_ip", "hostname_only"}
    for e in _edges(generated, "SAME_AS"):
        if e["props"]["method"] == "hostname_only":
            assert e["props"]["needs_review"] is True and e["props"]["confidence"] == 0.6
    vms = [n for n in generated["nodes"] if n["label"] == "VirtualMachine"]
    with_sensor = [v for v in vms if v["props"]["has_edr_sensor"]]
    assert 0.8 <= len(with_sensor) / len(vms) <= 0.97
    assert len(_edges(generated, "SAME_AS")) == len(with_sensor)
    prod_gaps = [v for v in vms if not v["props"]["has_edr_sensor"] and v["props"]["environment"] == "prod"]
    assert prod_gaps
    workstations = [n for n in generated["nodes"] if n["label"] == "Endpoint" and n["props"]["device_type"] == "workstation"]
    assert 1200 <= len(workstations) <= 1400 and all(n["props"]["primary_user_id"] for n in workstations)
    assert len({n["props"]["hostname"] for n in workstations}) == len(workstations)


def test_people_and_identities(generated: dict) -> None:
    dana = generated["by_id"][sc.USER_DANA]["props"]
    assert dana["display_name"] == "Dana Whitfield" and dana["department"] == "Finance" and dana["location"] == "Boston" and dana["team_id"] == sc.TEAM_TREASURY
    assert "Treasury" in dana["title"] and dana["is_privileged"] is False and dana["email"] == "dwhitfield@corp.larkspur.example"
    groups = {e["dst"] for e in _edges(generated, "MEMBER_OF", src=sc.USER_DANA)}
    assert {sc.GROUP_TREASURY, sc.GROUP_ALL, sc.TEAM_TREASURY} <= groups
    mreyes = generated["by_id"][sc.USER_MREYES]["props"]
    assert mreyes["display_name"] == "Marcus Reyes" and mreyes["is_privileged"] is True and mreyes["team_id"] == sc.TEAM_CORP_IT
    assert _one(generated, "MAPS_TO", sc.USER_MREYES, sc.CORP_IT_ADMIN_ROLE)["props"]["via"] == "sso"
    assert generated["by_id"][sc.CORP_IT_ADMIN_ROLE]["props"]["is_admin"] is True
    pkaur = generated["by_id"][sc.USER_PKAUR]["props"]
    assert pkaur["display_name"] == "Priya Kaur" and pkaur["is_executive"] is True and "Chief Financial Officer" in pkaur["title"]
    _one(generated, "LEADS", sc.USER_JOKAFOR, sc.TEAM_PLATFORM)
    assert generated["by_id"][sc.TEAM_PLATFORM]["props"]["lead_user_id"] == sc.USER_JOKAFOR
    assert generated["by_id"][sc.USER_LCHEN]["props"]["team_id"] == sc.TEAM_PAYMENTS
    svc = generated["by_id"][sc.SVC_FINOPS_SFTP]["props"]
    assert svc == {**svc, "system": "linux", "host_id": sc.BASTION_VM, "privileged": False} and "SFTP" in svc["purpose"]
    users = [n for n in generated["nodes"] if n["label"] == "HumanUser"]
    assert len({u["props"]["email"] for u in users}) == len(users)
    depts = {u["props"]["department"] for u in users}
    assert {"Engineering", "Finance", "Support"} <= depts
    for tid in (sc.TEAM_PLATFORM, sc.TEAM_PAYMENTS, sc.TEAM_TREASURY, sc.TEAM_CORP_IT):
        assert tid in generated["by_id"]
        assert _edges(generated, "LEADS", dst=tid)
    for aid in (sc.APP_SETTLEMENT_SFTP, "app:larkspur:platform-ssm-access"):
        assert generated["by_id"][aid]["props"]["criticality"] == "tier-2"
        _one(generated, "DEPENDS_ON", aid, sc.BASTION_VM)
    _one(generated, "OWNED_BY", sc.APP_SETTLEMENT_SFTP, sc.TEAM_TREASURY)
    _one(generated, "OWNED_BY", "app:larkspur:platform-ssm-access", sc.TEAM_PLATFORM)


def test_iam_realism(generated: dict) -> None:
    keys = [n for n in generated["nodes"] if n["label"] == "AccessKey"]
    assert any(k["props"]["age_days"] > 90 and k["props"]["status"] == "active" for k in keys)
    assert all(k["props"]["owner_id"] in generated["by_id"] for k in keys)
    roles = [n for n in generated["nodes"] if n["label"] == "IamRole"]
    assert {r["props"]["role_type"] for r in roles} >= {"instance", "service", "cross-account", "sso", "human"}
    assert all(0 <= r["props"]["privilege_score"] <= 1 for r in roles)
    chains = [e for e in _edges(generated, "CAN_ACCESS") if e["props"]["path_length"] >= 3 and e["src"].startswith("role:")]
    assert chains, "expected multi-hop role chains"
    assert all(e["props"]["path_length"] <= 5 for e in _edges(generated, "CAN_ACCESS"))
    exposed = [n for n in generated["nodes"] if n["label"] == "VirtualMachine" and n["props"]["exposure"] == "internet"]
    assert 20 <= len(exposed) <= 120
    assert all(n["props"]["public_ip"] or n["props"].get("public_ports") for n in exposed)


# ---------------------------------------------------------------------------- posture realism


def test_question5_result_set_is_exactly_the_eight_scripted_hosts(generated: dict) -> None:
    """Internet-exposed compute carrying a CVE the TI stage tracks (active / mass exploitation / public PoC)."""
    from throughline.simulator.inventory.vulns import TI_TRACKED_COMPONENTS
    from throughline.simulator.threat_intel.catalog import EXPLOITS

    assert {CVES[e.cve_id].component for e in EXPLOITS} <= TI_TRACKED_COMPONENTS, "TI catalog drifted; extend TI_TRACKED_COMPONENTS"
    exposed = {e["dst"] for e in _edges(generated, "EXPOSES")}
    tracked = {c.node_id for c in CVES.values() if c.component in TI_TRACKED_COMPONENTS}
    hits = {e["src"] for e in _edges(generated, "VULNERABLE_TO") if e["src"] in exposed and e["dst"] in tracked}
    assert hits == {
        sc.EDGE_VM, sc.STG_EDGE_VM, sc.DEV_LOG4J_VM, "vm:aws:i-0ns1c3d5e7f9a1b3c5", "vm:aws:i-0pan2d4f6a8c0e2a4b",
        "vm:aws:i-0spr3e5a7c9b1d3f5e", "vm:aws:i-0jnk4f6b8d0c2e4a6c", "vm:aws:i-0cnf5a7c9e1d3b5f7a",
    }
    # the tracked components still show up on internal assets (TI exposure panel at lower exposure)
    assert any(e["src"] not in exposed and e["dst"] in tracked for e in _edges(generated, "VULNERABLE_TO"))


def test_toxic_combinations(generated: dict) -> None:
    by_id = generated["by_id"]
    exposed = {e["dst"] for e in _edges(generated, "EXPOSES") if by_id[e["dst"]]["label"] in ("VirtualMachine", "Workload", "ServerlessFunction")}
    crit: dict[str, list[str]] = {}
    for e in _edges(generated, "VULNERABLE_TO"):
        if CVES[e["dst"].split(":", 1)[1]].cvss >= 9.0:
            crit.setdefault(e["src"], []).append(e["dst"])
    sensitive = {e["src"] for e in _edges(generated, "CAN_ACCESS") if by_id[e["dst"]]["props"].get("sensitivity") in ("high", "critical")}
    toxic = sorted(a for a in exposed if a in crit and a in sensitive)
    prod_staging = [a for a in toxic if by_id[a]["props"].get("environment") in ("prod", "staging")]
    assert 15 <= len(prod_staging) <= 60, len(prod_staging)
    assert sc.EDGE_VM in prod_staging and sc.LOG4SHELL in crit[sc.EDGE_VM]
    assert all(sc.LOG4SHELL not in crit[a] for a in toxic if a != sc.EDGE_VM), "only stmt-render-2a combines exposure, Log4Shell and sensitive reach"
    assert sc.APP_CONFIG_BUCKET in {e["dst"] for e in _edges(generated, "CAN_ACCESS", src=sc.EDGE_VM)}
    # every toxic combination surfaces as a critical CSPM issue on that asset, and only those do
    toxic_alerts = {a["props"]["entity_id"]: a for a in generated["nodes"] if a["label"] == "Alert" and a["props"]["title"].startswith("Toxic combination")}
    assert set(toxic_alerts) == set(toxic)
    assert all(a["props"]["vendor_severity"] == "critical" and a["props"]["raw"]["type"] == "TOXIC_COMBINATION" for a in toxic_alerts.values())
    assert len({by_id[a]["label"] for a in toxic}) >= 2 or len(toxic) >= 20


def test_every_inventory_owned_storyline_constant_exists_once(generated: dict) -> None:
    prefixes = ("vm:", "role:", "policy:", "bucket:", "secret:", "database:", "sg:", "subnet:", "image:", "package:", "endpoint:", "user:", "identity:", "team:", "app:", "group:", "account:", "alert:cspm:")
    named = {k: v for k, v in vars(sc).items() if isinstance(v, str) and v.startswith(prefixes)}
    named.update({f"account_{k}": v["id"] for k, v in sc.ACCOUNTS.items()})
    named["alert_n002"] = sc.ALERT_N["n002"][0]
    assert len(named) >= 50
    ids = [n["id"] for n in generated["nodes"]]
    story = json.loads((generated["out"] / "inventory.json").read_text())["storyline"]
    story_values = set(story.values())
    for key, nid in named.items():
        assert ids.count(nid) == 1, (key, nid)
        assert nid in story_values, (key, nid)
    foreign = ("cve:", "technique:", "actor:", "campaign:", "malware:", "ioc:", "report:", "process:", "file:", "logon:", "credential:", "cloudevent:", "incident:", "storyline:", "ip:", "domain:")
    assert not any(n["id"].startswith(foreign) for n in generated["nodes"]), "inventory emitted a node another stage owns"
    assert not any(n["label"] == "Alert" and n["props"]["source_system"] != "cspm" for n in generated["nodes"])


# ---------------------------------------------------------------------------- consumers and feeds


def test_index_loads_through_events_stage_loader(generated: dict) -> None:
    from throughline.simulator.events import resolve_inventory
    from throughline.simulator.events.inventory_stub import FLEET_ENDPOINT_FLOOR

    out: Path = generated["out"]
    inv = resolve_inventory(out / "inventory.json", out)
    assert inv.source == str(out / "inventory.json")
    n_endpoints = sum(1 for n in generated["nodes"] if n["label"] == "Endpoint")
    assert len(inv.endpoints) == n_endpoints >= FLEET_ENDPOINT_FLOOR, "a full inventory must not be padded with a synthetic fleet"
    assert inv.get(sc.BASTION_VM)["endpoint_id"] == sc.EP_BASTION and inv.get(sc.BASTION_VM)["role_ids"] == [sc.BASTION_ROLE]
    assert inv.endpoint(sc.WKS_DANA)["primary_user_id"] == sc.USER_DANA
    assert inv.user(sc.USER_DANA)["endpoint_id"] == sc.WKS_DANA and inv.user(sc.USER_DANA)["login"] == "dwhitfield"
    internet = {v["id"] for v in inv.internet_vms()}
    assert sc.EDGE_VM in internet and sc.BASTION_VM not in internet
    assert {e["id"] for e in inv.workstations()} >= {sc.WKS_DANA, sc.EP_MREYES, sc.EP_PKAUR}
    assert {e["id"] for e in inv.servers()} >= {sc.EP_BASTION, sc.EP_EDGE, sc.EP_DEV_SANDBOX, sc.EP_FILESHARE}
    assert {s["id"] for s in inv.service_accounts} >= {sc.SVC_FINOPS_SFTP}
    assert set(inv.account_ids) == {a["id"] for a in sc.ACCOUNTS.values()}
    # every id the index declares resolves to a node this stage emitted, so events edges targeting them survive the merge
    assert inv.all_node_ids() <= set(generated["by_id"]) | {sc.LOG4SHELL}


def test_raw_feed_shapes(generated: dict) -> None:
    out: Path = generated["out"]
    devices = read_jsonl(out / "raw" / "falcon" / "devices.jsonl")
    required = {"device_id", "hostname", "local_ip", "external_ip", "os_version", "platform_name", "agent_version", "last_seen", "service_provider", "service_provider_account_id", "instance_id", "site_name", "ou", "tags"}
    assert all(required <= set(d) for d in devices)
    assert len(devices) == sum(1 for n in generated["nodes"] if n["label"] == "Endpoint")
    bas = next(d for d in devices if d["device_id"] == "aid-bas01")
    assert bas["instance_id"] == sc.BASTION_INSTANCE_ID and bas["service_provider"] == "AWS_EC2_V2" and bas["service_provider_account_id"] == "222222222222"
    assert bas["platform_name"] == "Linux" and bas["local_ip"] == sc.BASTION_PRIVATE_IP and bas["hostname"] == "bas-01"
    dana = next(d for d in devices if d["device_id"] == "aid-wks3391")
    assert dana["platform_name"] == "Windows" and dana["site_name"] == "Boston office" and dana["ou"].startswith("OU=Workstations")
    users = read_jsonl(out / "raw" / "okta" / "users.jsonl")
    assert len(users) == sum(1 for n in generated["nodes"] if n["label"] == "HumanUser")
    okta_dana = next(u for u in users if u["profile"]["login"] == "dwhitfield")
    assert okta_dana["profile"]["email"] == "dwhitfield@corp.larkspur.example" and okta_dana["status"] == "ACTIVE" and "finance-treasury" in okta_dana["groups"]
    issues = read_jsonl(out / "raw" / "wiz" / "issues.jsonl")
    assert len(issues) == sum(1 for n in generated["nodes"] if n["label"] == "Alert")
    n002 = next(i for i in issues if i["id"] == "iss-n002")
    assert n002["severity"] == "CRITICAL" and n002["sourceRule"]["name"] == "S3 bucket allows public read" and n002["entitySnapshot"]["graphEntityId"] == sc.MARKETING_BUCKET
    resources = read_jsonl(out / "raw" / "wiz" / "cloud_resources.jsonl")
    assert any(r["graphEntityId"] == sc.BASTION_VM and r["type"] == "VIRTUAL_MACHINE" and sc.BASTION_ROLE_ARN in r["properties"]["instanceProfileRoles"] for r in resources)
    vulns = read_jsonl(out / "raw" / "wiz" / "vulnerabilities.jsonl")
    assert any(v["name"] == "CVE-2021-44228" and v["vulnerableAsset"]["graphEntityId"] == sc.EDGE_VM and v["vulnerableAsset"]["isInternetFacing"] for v in vulns)
    iam = read_jsonl(out / "raw" / "wiz" / "iam.jsonl")
    reader = next(r for r in iam if r["graphEntityId"] == sc.PROD_READER_ROLE)
    assert reader["trustPolicy"]["Statement"][0]["Principal"] == {"AWS": sc.BASTION_ROLE_ARN}
    network = read_jsonl(out / "raw" / "wiz" / "network.jsonl")
    assert any(r.get("type") == "NETWORK_EXPOSURE" and r["resource"]["graphEntityId"] == sc.EDGE_VM and r["ports"] == ["8080"] for r in network)


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from throughline.simulator.inventory.__main__ import main

    assert main(["--out", str(tmp_path), "-q"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["out"] == str(tmp_path) and summary["counts"]["nodes"]["VirtualMachine"] > 0
    assert (tmp_path / "graph" / "inventory_nodes.jsonl").exists() and (tmp_path / "inventory.json").exists()


# ---------------------------------------------------------------------------- index and determinism


def test_inventory_index(generated: dict) -> None:
    index = json.loads((generated["out"] / "inventory.json").read_text())
    for key in ("vms", "endpoints", "users", "roles", "buckets", "secrets", "databases", "apps", "teams", "service_accounts", "storyline"):
        assert key in index and index[key], key
    vm = next(v for v in index["vms"] if v["id"] == sc.BASTION_VM)
    assert vm["endpoint_id"] == sc.EP_BASTION and vm["role_ids"] == [sc.BASTION_ROLE] and vm["exposure"] == "internal" and vm["app_id"] == "app:larkspur:platform-ssm-access"
    assert set(vm) >= {"id", "name", "hostname", "private_ip", "public_ip", "os", "os_family", "account_id", "environment", "exposure", "has_edr_sensor", "endpoint_id", "role_ids", "app_id"}
    ep = next(e for e in index["endpoints"] if e["id"] == sc.WKS_DANA)
    assert ep["primary_user_id"] == sc.USER_DANA and ep["vm_id"] is None and ep["site"] == "Boston office"
    user = next(u for u in index["users"] if u["id"] == sc.USER_DANA)
    assert user["endpoint_id"] == sc.WKS_DANA and user["team_id"] == sc.TEAM_TREASURY and user["login"] == "dwhitfield"
    role = next(r for r in index["roles"] if r["id"] == sc.BASTION_ROLE)
    assert role["attached_vm_ids"] == [sc.BASTION_VM] and role["arn"] == sc.BASTION_ROLE_ARN
    story = index["storyline"]
    assert story["bastion_vm"] == sc.BASTION_VM and story["edge_vm"] == sc.EDGE_VM and story["wks_dana"] == sc.WKS_DANA
    assert set(story.values()) <= set(generated["by_id"]) | {sc.LOG4SHELL}
    for value in story.values():
        assert value == sc.LOG4SHELL or value in generated["by_id"]


def test_deterministic(generated: dict, tmp_path: Path) -> None:
    generate(tmp_path)
    for rel in ("graph/inventory_nodes.jsonl", "graph/inventory_edges.jsonl", "inventory.json", "raw/wiz/issues.jsonl", "raw/falcon/devices.jsonl", "raw/okta/users.jsonl"):
        assert filecmp.cmp(generated["out"] / rel, tmp_path / rel, shallow=False), rel
