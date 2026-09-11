"""Fakes for the API and agent tests.

* ``build_fixture_graph()`` - a small ``ContextGraph`` shaped like docs/04-storyline.md: campaign A (EMBERCAST,
  pivotal alert ``alert:falcon:ldt-a009``), campaign B (SALTWORKS / Log4Shell), the noise alerts, threat intel,
  credentials, cloud events, storylines, business context.
* ``FakeStore`` - the GraphStore protocol over that graph (optionally with scripted Cypher).
* ``FakeEngine`` - the ``AnalyticsEngine`` API (docs/06 section 3.2) with simple but shape-correct logic, built
  from ``throughline.models``. It is NOT the real analytics; it exists so the API and both analysts can be tested
  end-to-end without Agent C's package.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import BaseModel

from throughline.api.errors import NotSupported, QueryRejected, QueryTimeout
from throughline.api.fallback import ContextGraphStore
from throughline.graph.context_graph import ContextGraph, edge_id
from throughline.models import (
    AlertContext,
    AlertSummary,
    AttackPathOut,
    BlastRadiusResult,
    BreakItem,
    ContainmentSimulation,
    GraphFragment,
    Insight,
    NodeOut,
    ReachedNode,
    RiskBreakdown,
    RiskFactor,
    StageOut,
    StorylineOut,
    TIContext,
    TIMatch,
    band_for_score,
)
from throughline.simulator import storyline_constants as C
from throughline.simulator.common import edge as mk_edge
from throughline.simulator.common import node as mk_node

SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FIX = "fixture"

# ----------------------------------------------------------------------------- fixture data

IP_EGRESS = f"ip:v4:{C.ATTACKER_EGRESS_IP}"
IP_C2 = f"ip:v4:{C.C2_IP}"
IP_SALT = f"ip:v4:{C.SALTWORKS_IP}"
DOMAIN_C2 = f"domain:dns:{C.C2_DOMAIN}"
INTERNET = "internet:global:internet"
TECH = "technique:attack:{}"

# alert id -> (title, entity_id, entity_label, hostname, techniques, score, storyline, source, alert_type, reaches_cj, on_path, ioc_count, actors, user)
ALERT_ROWS: dict[str, tuple[Any, ...]] = {
    "alert:falcon:ldt-a001": ("Malicious file execution via LNK in mounted ISO", C.WKS_DANA, "Endpoint", "WKS-3391", ["T1566.001", "T1204.002", "T1059.001", "T1218.011"], 88, C.STORYLINE_A, "falcon", "detection", True, True, 1, [C.ACTOR_CJ], "dwhitfield"),
    "alert:falcon:ldt-a002": ("Run-key persistence by recently written binary", C.WKS_DANA, "Endpoint", "WKS-3391", ["T1547.001", "T1055"], 80, C.STORYLINE_A, "falcon", "detection", True, True, 1, [C.ACTOR_CJ], "dwhitfield"),
    "alert:falcon:ldt-a003": ("Periodic outbound connections to rare domain", C.WKS_DANA, "Endpoint", "WKS-3391", ["T1071.001", "T1573.002"], 79, C.STORYLINE_A, "falcon", "detection", True, True, 1, [C.ACTOR_CJ], "dwhitfield"),
    "alert:falcon:ldt-a004": ("Credential dumping technique observed (LSASS memory read)", C.WKS_DANA, "Endpoint", "WKS-3391", ["T1003.001"], 78, C.STORYLINE_A, "falcon", "detection", True, True, 1, [C.ACTOR_CJ], "dwhitfield"),
    "alert:falcon:ldt-a005": ("Access to SSH private key by unsigned process", C.WKS_DANA, "Endpoint", "WKS-3391", ["T1552.001"], 76, C.STORYLINE_A, "falcon", "detection", True, True, 0, [C.ACTOR_CJ], "dwhitfield"),
    "alert:falcon:ldt-a006": ("Account and remote-system discovery", C.WKS_DANA, "Endpoint", "WKS-3391", ["T1087.002", "T1018"], 70, C.STORYLINE_A, "falcon", "detection", True, True, 0, [C.ACTOR_CJ], "dwhitfield"),
    "alert:falcon:ldt-a007": ("Interactive SSH session from user workstation to bastion outside business hours", C.EP_BASTION, "Endpoint", "bas-01", ["T1021.004", "T1078"], 84, C.STORYLINE_A, "falcon", "detection", True, True, 0, [C.ACTOR_CJ], "svc-finops-sftp"),
    "alert:falcon:ldt-a008x": ("Read of /etc/shadow via sudo", C.EP_BASTION, "Endpoint", "bas-01", ["T1003.008"], 75, C.STORYLINE_A, "falcon", "detection", True, True, 0, [C.ACTOR_CJ], "svc-finops-sftp"),
    "alert:falcon:ldt-a009": ("Cloud instance metadata service credential access from interactive shell", C.EP_BASTION, "Endpoint", "bas-01", ["T1552.005"], 92, C.STORYLINE_A, "falcon", "detection", True, True, 0, [C.ACTOR_CJ], "svc-finops-sftp"),
    "alert:cloud-anomaly:ca-a017": ("API calls for role LarkspurProdDataReader from a new geolocation/ASN", C.PROD_READER_ROLE, "IamRole", None, ["T1078.004"], 86, C.STORYLINE_A, "cloud-anomaly", "cloud", True, True, 1, [C.ACTOR_CJ], None),
    "alert:waf:waf-b001": ("JNDI injection pattern in request header", C.EDGE_VM, "VirtualMachine", "stmt-render-2a", ["T1190"], 70, C.STORYLINE_B, "waf", "network", True, True, 1, [C.ACTOR_HT], None),
    "alert:falcon:ldt-b002": ("Shell spawned by Java application server process", C.EP_EDGE, "Endpoint", "stmt-render-2a", ["T1190", "T1059.004"], 82, C.STORYLINE_B, "falcon", "detection", True, True, 1, [C.ACTOR_HT], "statement-render"),
    "alert:falcon:ldt-b003": ("Web shell-like file written to web root", C.EP_EDGE, "Endpoint", "stmt-render-2a", ["T1505.003"], 68, C.STORYLINE_B, "falcon", "detection", True, True, 1, [C.ACTOR_HT], "statement-render"),
    "alert:falcon:ldt-n001": ("EICAR test file detected and quarantined", C.EP_DEV_SANDBOX, "Endpoint", "dev-sandbox-runner-03", ["T1204.002"], 22, None, "falcon", "detection", False, False, 0, [], "ubuntu"),
    "alert:cspm:iss-n002": ("S3 bucket allows public read", C.MARKETING_BUCKET, "StorageBucket", None, [], 24, None, "cspm", "issue", False, False, 0, [], None),
    "alert:falcon:ldt-n003": ("PsExec service execution", C.EP_FILESHARE, "Endpoint", "srv-fileshare-01", ["T1569.002"], 33, None, "falcon", "detection", False, False, 0, [], "mreyes"),
    "alert:okta:idp-n004": ("Impossible travel: London then New York", C.USER_PKAUR, "HumanUser", None, ["T1078"], 28, None, "okta", "identity", False, False, 0, [], "pkaur"),
}
ALERT_TIMES: dict[str, tuple[str, str]] = {aid: (t, sev) for aid, t, sev in C.ALERT_A.values()}
ALERT_TIMES.update({aid: (t, sev) for aid, t, sev in C.ALERT_B.values()})
ALERT_TIMES.update({aid: (t, sev) for aid, t, sev in C.ALERT_N.values()})

FACTORS: dict[str, tuple[dict[str, float], list[str]]] = {
    "alert:falcon:ldt-a009": ({"severity": 0.5, "exposure": 0.6, "privilege": 1.0, "data": 1.0, "threat_intel": 0.8, "correlation": 1.0}, ["attack_path_floor:90"]),
    "alert:falcon:ldt-a001": ({"severity": 0.75, "exposure": 0.4, "privilege": 0.6, "data": 1.0, "threat_intel": 1.0, "correlation": 1.0}, ["attack_path_floor:90"]),
    "alert:cloud-anomaly:ca-a017": ({"severity": 0.25, "exposure": 0.4, "privilege": 1.0, "data": 1.0, "threat_intel": 0.9, "correlation": 1.0}, ["attack_path_floor:90"]),
    "alert:falcon:ldt-b002": ({"severity": 0.5, "exposure": 1.0, "privilege": 0.7, "data": 0.8, "threat_intel": 1.0, "correlation": 0.3}, ["ti_booster_floor:80"]),
    "alert:falcon:ldt-n001": ({"severity": 0.75, "exposure": 0.1, "privilege": 0.1, "data": 0.0, "threat_intel": 0.0, "correlation": 0.0}, ["no_context_ceiling:25"]),
    "alert:cspm:iss-n002": ({"severity": 1.0, "exposure": 1.0, "privilege": 0.0, "data": 0.0, "threat_intel": 0.0, "correlation": 0.0}, ["no_context_ceiling:25"]),
    "alert:falcon:ldt-n003": ({"severity": 0.5, "exposure": 0.4, "privilege": 0.3, "data": 0.2, "threat_intel": 0.0, "correlation": 0.0}, ["benign_context_ceiling:35"]),
    "alert:okta:idp-n004": ({"severity": 0.5, "exposure": 0.4, "privilege": 0.2, "data": 0.1, "threat_intel": 0.0, "correlation": 0.0}, ["benign_context_ceiling:35"]),
}
WEIGHTS = {"severity": 0.30, "exposure": 0.15 * 0.7, "privilege": 0.20 * 0.7, "data": 0.25 * 0.7, "threat_intel": 0.20 * 0.7, "correlation": 0.20 * 0.7}
FACTOR_LABELS = {"severity": "Vendor severity", "exposure": "Exposure", "privilege": "Privilege reach", "data": "Data sensitivity reachable", "threat_intel": "Threat-intel relevance", "correlation": "Incident correlation"}

STORYLINE_A_STAGES = [
    {"order": 1, "stage": "Initial Access", "technique_ids": ["T1566.001", "T1204.002", "T1059.001", "T1218.011"], "alert_ids": ["alert:falcon:ldt-a001"], "node_ids": ["alert:falcon:ldt-a001", C.WKS_DANA, C.USER_DANA], "time": "2026-09-09T09:12:04Z", "summary": "ISO/LNK phishing runs MAPLELOADER on WKS-3391"},
    {"order": 2, "stage": "Persistence & C2", "technique_ids": ["T1547.001", "T1071.001", "T1573.002"], "alert_ids": ["alert:falcon:ldt-a002", "alert:falcon:ldt-a003"], "node_ids": ["alert:falcon:ldt-a002", "alert:falcon:ldt-a003", DOMAIN_C2], "time": "2026-09-09T09:14:30Z", "summary": "NIGHTFERRY persists and beacons to cdn-metrics.telemetry-sync.net"},
    {"order": 3, "stage": "Credential Access", "technique_ids": ["T1003.001", "T1552.001"], "alert_ids": ["alert:falcon:ldt-a004", "alert:falcon:ldt-a005"], "node_ids": ["alert:falcon:ldt-a004", "alert:falcon:ldt-a005", C.CRED_SSH_KEY], "time": "2026-09-09T15:22:41Z", "summary": "QUILLDROP dumps LSASS and steals Dana's SSH key"},
    {"order": 4, "stage": "Lateral Movement", "technique_ids": ["T1021.004", "T1078"], "alert_ids": ["alert:falcon:ldt-a007"], "node_ids": ["alert:falcon:ldt-a007", C.WKS_DANA, C.EP_BASTION], "time": "2026-09-10T02:05:17Z", "summary": "SSH from WKS-3391 to bas-01 as svc-finops-sftp"},
    {"order": 5, "stage": "Credential Access (cloud)", "technique_ids": ["T1552.005"], "alert_ids": ["alert:falcon:ldt-a009"], "node_ids": ["alert:falcon:ldt-a009", C.EP_BASTION, C.BASTION_VM, C.CRED_BASTION_KEY], "time": "2026-09-10T02:11:45Z", "summary": "IMDS credentials of LarkspurBastionSSMRole stolen from the interactive shell"},
    {"order": 6, "stage": "Privilege Escalation", "technique_ids": ["T1078.004", "T1548.005"], "alert_ids": [], "node_ids": ["cloudevent:aws:evt-a012", C.BASTION_ROLE, C.PROD_READER_ROLE, C.CRED_PROD_KEY], "time": "2026-09-10T02:24:15Z", "summary": "AssumeRole into LarkspurProdDataReader from 203.0.113.77"},
    {"order": 7, "stage": "Collection / Exfiltration", "technique_ids": ["T1530", "T1567.002"], "alert_ids": ["alert:cloud-anomaly:ca-a017"], "node_ids": ["cloudevent:aws:evt-a014", C.CARDHOLDER_VAULT, "alert:cloud-anomaly:ca-a017"], "time": "2026-09-10T02:27:10Z", "summary": "1,247 GetObject calls on larkspur-cardholder-vault (~38 GB)"},
]
STORYLINE_B_STAGES = [
    {"order": 1, "stage": "Initial Access", "technique_ids": ["T1190"], "alert_ids": ["alert:waf:waf-b001"], "node_ids": ["alert:waf:waf-b001", C.EDGE_VM, IP_SALT], "time": "2026-09-10T21:13:02Z", "summary": "JNDI injection against stmt-render-2a:8080"},
    {"order": 2, "stage": "Execution", "technique_ids": ["T1059.004"], "alert_ids": ["alert:falcon:ldt-b002"], "node_ids": ["alert:falcon:ldt-b002", C.EP_EDGE], "time": "2026-09-10T21:13:07Z", "summary": "Java spawns bash to fetch brackish.sh"},
    {"order": 3, "stage": "Persistence", "technique_ids": ["T1505.003"], "alert_ids": ["alert:falcon:ldt-b003"], "node_ids": ["alert:falcon:ldt-b003", C.EDGE_ROLE, C.APP_CONFIG_BUCKET], "time": "2026-09-10T21:13:19Z", "summary": "BRACKISH web shell written to the web root"},
]

PATH_A = ["alert:falcon:ldt-a001", C.WKS_DANA, C.EP_BASTION, C.BASTION_VM, C.BASTION_ROLE, C.PROD_READER_ROLE, C.CARDHOLDER_VAULT]
PATH_B = ["alert:waf:waf-b001", C.EDGE_VM, C.EDGE_ROLE, C.APP_CONFIG_BUCKET, C.CARDHOLDER_DB]


def _n(id: str, label: str, name: str, source: str = FIX, **props: Any) -> dict[str, Any]:
    return mk_node(id, label, name, props, source=source)


def _e(type: str, src: str, dst: str, **props: Any) -> dict[str, Any]:
    return mk_edge(type, src, dst, props, source="derived" if type in ("SAME_AS", "CAN_ACCESS", "STOLEN_BY", "DERIVED_FROM", "MATCHES_IOC", "IN_STORYLINE", "NEXT_STAGE", "LATERAL_MOVEMENT_TO", "EXPOSES", "VULNERABLE_TO", "ATTRIBUTED_TO") else FIX)


def _alert_node(aid: str) -> dict[str, Any]:
    title, entity_id, entity_label, hostname, techniques, score, storyline, source, alert_type, reaches, on_path, ioc_count, actors, user = ALERT_ROWS[aid]
    detected_at, severity = ALERT_TIMES[aid]
    factors, rails = FACTORS.get(aid, ({}, []))
    reasons = []
    if reaches:
        reasons.append("reaches PCI")
    if on_path:
        reasons.append("on attack path")
    if ioc_count:
        reasons.append("IOC match")
    if actors:
        reasons.append("active TI")
    if score <= 25:
        reasons.append("no context")
    raw = {"DetectId": aid.split(":")[-1], "Severity": severity.capitalize(), "Tactic": techniques[0] if techniques else "", "Hostname": hostname or entity_id, "Title": title, "Status": "new"}
    return _n(
        aid, "Alert", title, source=f"{source}-sim", source_system=source, alert_type=alert_type, title=title, description=title,
        vendor_severity=severity, vendor_severity_rank=SEV_RANK[severity], status="new", detected_at=detected_at, techniques=techniques,
        tactic=techniques[0] if techniques else None, entity_id=entity_id, entity_label=entity_label, hostname=hostname, user=user,
        raw=json.dumps(raw), contextual_score=score, contextual_band=band_for_score(score), storyline_id=storyline, graph_reasons=reasons,
        ti_actor_ids=actors, ioc_match_count=ioc_count, reaches_crown_jewel=reaches, on_attack_path=on_path,
        score_breakdown=json.dumps({"factors": factors, "rails": rails}), change_ticket=C.CHANGE_TICKET if aid.endswith("n003") else None,
    )


def build_fixture_graph() -> ContextGraph:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    A = C.ACCOUNTS
    nodes += [
        _n(A["prod"]["id"], "CloudAccount", "larkspur-prod", provider="aws", account_id="111111111111", environment="prod"),
        _n(A["shared"]["id"], "CloudAccount", "larkspur-shared-services", provider="aws", account_id="222222222222", environment="prod"),
        _n(INTERNET, "Internet", "internet"),
        # VMs
        _n(C.BASTION_VM, "VirtualMachine", C.BASTION_NAME, provider="aws", account_id="222222222222", hostname=C.BASTION_HOSTNAME, private_ip=C.BASTION_PRIVATE_IP, public_ip=C.BASTION_PUBLIC_IP, os="Amazon Linux 2023", os_family="linux", environment="prod", exposure="internal", has_edr_sensor=True, tags=json.dumps({"role": "bastion", "owner": "platform-eng"}), criticality="tier-1", crown_jewel_reach=3),
        _n(C.EDGE_VM, "VirtualMachine", C.EDGE_NAME, provider="aws", account_id="111111111111", hostname=C.EDGE_HOSTNAME, private_ip=C.EDGE_PRIVATE_IP, public_ip=C.EDGE_PUBLIC_IP, os="Ubuntu 22.04", os_family="linux", environment="prod", exposure="internet", has_edr_sensor=True, criticality="tier-1", ti_exposure_score=0.95, crown_jewel_reach=1),
        _n(C.STG_EDGE_VM, "VirtualMachine", C.STG_EDGE_NAME, provider="aws", account_id="333333333333", hostname="stmt-render-stg-1.staging.larkspur.internal", environment="staging", exposure="internet", has_edr_sensor=True, ti_exposure_score=0.5),
        _n(C.DEV_LOG4J_VM, "VirtualMachine", C.DEV_LOG4J_NAME, provider="aws", account_id="444444444444", hostname="log4j-testbed.dev.larkspur.internal", environment="dev", exposure="internet", has_edr_sensor=False, ti_exposure_score=0.3),
        _n(C.DEV_SANDBOX_VM, "VirtualMachine", C.DEV_SANDBOX_NAME, provider="aws", account_id="444444444444", hostname="dev-sandbox-runner-03.dev.larkspur.internal", environment="dev", exposure="isolated", has_edr_sensor=True),
        _n(C.FILESHARE_VM, "VirtualMachine", C.FILESHARE_NAME, provider="aws", account_id="666666666666", hostname="srv-fileshare-01.corp.larkspur.internal", os_family="windows", environment="corp", exposure="internal", has_edr_sensor=True),
        # endpoints
        _n(C.WKS_DANA, "Endpoint", C.WKS_DANA_HOSTNAME, source="falcon-sim", hostname=C.WKS_DANA_HOSTNAME, device_type="workstation", os="Windows 11", os_family="windows", private_ip=C.WKS_DANA_IP, site="Boston office", primary_user_id=C.USER_DANA),
        _n(C.EP_BASTION, "Endpoint", "bas-01", source="falcon-sim", hostname="bas-01", device_type="server", os_family="linux", private_ip=C.BASTION_PRIVATE_IP, cloud_provider="aws", cloud_instance_id=C.BASTION_INSTANCE_ID, cloud_account_id="222222222222"),
        _n(C.EP_EDGE, "Endpoint", "stmt-render-2a", source="falcon-sim", hostname="stmt-render-2a", device_type="server", os_family="linux", private_ip=C.EDGE_PRIVATE_IP, cloud_instance_id=C.EDGE_INSTANCE_ID),
        _n(C.EP_DEV_SANDBOX, "Endpoint", "dev-sandbox-runner-03", source="falcon-sim", hostname="dev-sandbox-runner-03", device_type="server", os_family="linux"),
        _n(C.EP_FILESHARE, "Endpoint", "srv-fileshare-01", source="falcon-sim", hostname="srv-fileshare-01", device_type="server", os_family="windows"),
        _n(C.EP_MREYES, "Endpoint", C.EP_MREYES_HOSTNAME, source="falcon-sim", hostname=C.EP_MREYES_HOSTNAME, device_type="workstation", primary_user_id=C.USER_MREYES),
        # people / identities
        _n(C.USER_DANA, "HumanUser", "Dana Whitfield", source="okta-sim", email="dwhitfield@corp.larkspur.example", display_name="Dana Whitfield", title="Treasury Operations analyst", department="Finance", team_id=C.TEAM_TREASURY, location="Boston"),
        _n(C.USER_MREYES, "HumanUser", "Marcus Reyes", source="okta-sim", email="mreyes@corp.larkspur.example", display_name="Marcus Reyes", title="IT systems administrator", department="Corp IT", is_privileged=True),
        _n(C.USER_PKAUR, "HumanUser", "Priya Kaur", source="okta-sim", email="pkaur@corp.larkspur.example", display_name="Priya Kaur", title="CFO", is_executive=True),
        _n(C.USER_JOKAFOR, "HumanUser", "Jide Okafor", source="okta-sim", email="jokafor@corp.larkspur.example", display_name="Jide Okafor", title="Platform engineering lead"),
        _n(C.SVC_FINOPS_SFTP, "ServiceAccount", "svc-finops-sftp", system="linux", host_id=C.BASTION_VM, purpose="settlement-file SFTP"),
        _n(C.BASTION_ROLE, "IamRole", "LarkspurBastionSSMRole", provider="aws", account_id="222222222222", arn=C.BASTION_ROLE_ARN, role_type="instance", is_admin=False, privilege_score=0.7, environment="prod"),
        _n(C.PROD_READER_ROLE, "IamRole", "LarkspurProdDataReader", provider="aws", account_id="111111111111", arn=C.PROD_READER_ROLE_ARN, role_type="cross-account", is_admin=False, privilege_score=0.9, trust_principals=[C.BASTION_ROLE_ARN], environment="prod"),
        _n(C.EDGE_ROLE, "IamRole", "LarkspurStmtRenderRole", provider="aws", account_id="111111111111", arn=C.EDGE_ROLE_ARN, role_type="instance", privilege_score=0.5, environment="prod"),
        _n(C.BASTION_ASSUME_POLICY, "IamPolicy", "LarkspurBastionAssumeProdReader", provider="aws", account_id="222222222222", access_levels=["admin"]),
        _n(C.PROD_READER_POLICY, "IamPolicy", "LarkspurProdDataReaderAccess", provider="aws", account_id="111111111111", access_levels=["read", "list"]),
        # data
        _n(C.CARDHOLDER_VAULT, "StorageBucket", "larkspur-cardholder-vault", provider="aws", account_id="111111111111", public=False, encrypted=True, data_classifications=["PCI"], sensitivity="critical", crown_jewel=True, size_gb=4100.0, environment="prod"),
        _n(C.KYC_DOCS, "StorageBucket", "larkspur-kyc-documents", provider="aws", account_id="111111111111", public=False, encrypted=True, data_classifications=["PII"], sensitivity="high", crown_jewel=True, environment="prod"),
        _n(C.APP_CONFIG_BUCKET, "StorageBucket", "larkspur-prod-app-config", provider="aws", account_id="111111111111", public=False, data_classifications=["SECRETS"], sensitivity="high", crown_jewel=False, contains_credentials_for=[C.CARDHOLDER_DB], environment="prod"),
        _n(C.STATEMENTS_OUT_BUCKET, "StorageBucket", "larkspur-statements-out", provider="aws", account_id="111111111111", data_classifications=["PII"], sensitivity="medium", environment="prod"),
        _n(C.SHARED_LOGS_BUCKET, "StorageBucket", "larkspur-shared-logs", provider="aws", account_id="222222222222", data_classifications=["INTERNAL"], sensitivity="low", environment="prod"),
        _n(C.MARKETING_BUCKET, "StorageBucket", "larkspur-marketing-assets", provider="aws", account_id="666666666666", public=True, data_classifications=["PUBLIC"], sensitivity="none", crown_jewel=False, environment="corp"),
        _n(C.DB_READER_SECRET, "Secret", "prod/cardholder-db/reader", provider="aws", account_id="111111111111", secret_type="db_credentials", sensitivity="critical", grants_access_to=[C.CARDHOLDER_DB]),
        _n(C.HSM_SECRET, "Secret", "prod/hsm/partner-signing-key", provider="aws", account_id="111111111111", secret_type="signing_key", sensitivity="critical"),
        _n(C.CARDHOLDER_DB, "Database", "cardholder-db", provider="aws", account_id="111111111111", engine="postgres", public=False, data_classifications=["PCI"], sensitivity="critical", crown_jewel=True, environment="prod", exposure="internal"),
        # business
        _n(C.APP_CARD_ISSUING, "Application", "card-issuing", criticality="tier-0", environment="prod", owner_team_id=C.TEAM_PAYMENTS, data_classifications=["PCI"]),
        _n(C.APP_STMT_RENDER, "Application", "statement-render", criticality="tier-1", environment="prod", owner_team_id=C.TEAM_PAYMENTS),
        _n(C.APP_MARKETING, "Application", "marketing-site", criticality="tier-3", environment="corp"),
        _n(C.APP_SETTLEMENT_SFTP, "Application", "settlement-sftp", criticality="tier-2", environment="prod", owner_team_id=C.TEAM_TREASURY),
        _n(C.TEAM_PLATFORM, "Team", "platform-eng", department="Engineering"),
        _n(C.TEAM_PAYMENTS, "Team", "payments-platform", department="Engineering"),
        _n(C.TEAM_TREASURY, "Team", "finance-treasury", department="Finance"),
        _n(C.TEAM_CORP_IT, "Team", "corp-it", department="IT"),
        # credentials
        _n(C.CRED_SSH_KEY, "Credential", "dwhitfield id_ed25519", credential_type="ssh_private_key", principal_id=C.SVC_FINOPS_SFTP, status="valid"),
        _n(C.CRED_BASTION_KEY, "Credential", C.CRED_BASTION_KEY_ID, credential_type="aws_temporary_key", principal_id=C.BASTION_ROLE, issued_at="2026-09-10T02:11:00Z", expires_at="2026-09-10T08:11:00Z", status="expired"),
        _n(C.CRED_PROD_KEY, "Credential", C.CRED_PROD_KEY_ID, credential_type="aws_temporary_key", principal_id=C.PROD_READER_ROLE, issued_at="2026-09-10T02:24:15Z", expires_at="2026-09-10T03:24:15Z", status="expired", derived_from=C.CRED_BASTION_KEY),
        # network
        _n(IP_EGRESS, "IpAddress", C.ATTACKER_EGRESS_IP, address=C.ATTACKER_EGRESS_IP, is_private=False, asn=C.ATTACKER_ASN, asn_org=C.ATTACKER_ASN_ORG, reputation="malicious"),
        _n(IP_C2, "IpAddress", C.C2_IP, address=C.C2_IP, is_private=False, reputation="malicious"),
        _n(IP_SALT, "IpAddress", C.SALTWORKS_IP, address=C.SALTWORKS_IP, is_private=False, reputation="malicious"),
        _n(DOMAIN_C2, "Domain", C.C2_DOMAIN, fqdn=C.C2_DOMAIN, registered_days_ago=40, reputation="suspicious"),
        # incidents
        _n(C.INCIDENT_WKS, "Incident", "inc-0091", source="falcon-sim", vendor_severity="high", alert_count=6, hosts=["WKS-3391"]),
        _n(C.INCIDENT_BASTION, "Incident", "inc-0094", source="falcon-sim", vendor_severity="medium", alert_count=3, hosts=["bas-01"]),
        _n(C.INCIDENT_EDGE, "Incident", "inc-0096", source="falcon-sim", vendor_severity="medium", alert_count=2, hosts=["stmt-render-2a"]),
        # storylines
        _n(C.STORYLINE_A, "Storyline", "EMBERCAST intrusion: WKS-3391 -> bas-01 -> LarkspurProdDataReader -> cardholder vault", source="derived", title="EMBERCAST intrusion: WKS-3391 -> bas-01 -> LarkspurProdDataReader -> cardholder vault", summary="Phishing on WKS-3391 led to SSH lateral movement to bas-01, IMDS credential theft, cross-account AssumeRole and mass GetObject on the PCI cardholder vault.", actor_id=C.ACTOR_CJ, campaign_id=C.CAMPAIGN_EMBERCAST, stage_count=7, alert_ids=[a for a in ALERT_ROWS if ALERT_ROWS[a][6] == C.STORYLINE_A], crown_jewels_reached=[C.CARDHOLDER_VAULT, C.KYC_DOCS, C.CARDHOLDER_DB], first_event="2026-09-09T09:12:04Z", last_event="2026-09-10T03:55:00Z", contextual_score=92, stages=json.dumps(STORYLINE_A_STAGES)),
        _n(C.STORYLINE_B, "Storyline", "SALTWORKS: Log4Shell exploitation of stmt-render-2a", source="derived", title="SALTWORKS: Log4Shell exploitation of stmt-render-2a", summary="Mass exploitation of CVE-2021-44228 on the internet-facing statement renderer dropped the BRACKISH web shell; the instance role reaches a config bucket holding cardholder-db credentials.", actor_id=C.ACTOR_HT, campaign_id=C.CAMPAIGN_SALTWORKS, stage_count=3, alert_ids=[a for a in ALERT_ROWS if ALERT_ROWS[a][6] == C.STORYLINE_B], crown_jewels_reached=[C.CARDHOLDER_DB], first_event="2026-09-10T21:13:02Z", last_event="2026-09-10T21:30:00Z", contextual_score=82, stages=json.dumps(STORYLINE_B_STAGES)),
        # threat intel
        _n(C.ACTOR_CJ, "ThreatActor", "Cinder Jackal", source="ti-sim", aliases=["CJ"], motivation="financial", targeted_sectors=["financial-services"], sector_targeting_relevance=0.9, active=True, description="eCrime actor targeting fintech bastion hosts"),
        _n(C.ACTOR_HT, "ThreatActor", "Hollow Tide", source="ti-sim", motivation="access-broker", targeted_sectors=["financial-services"], sector_targeting_relevance=0.8, active=True, description="Access broker mass-exploiting Log4Shell"),
        _n(C.CAMPAIGN_EMBERCAST, "Campaign", "EMBERCAST", source="ti-sim", actor_id=C.ACTOR_CJ, status="active", started="2026-07-01T00:00:00Z", sector_targeting_relevance=0.9),
        _n(C.CAMPAIGN_SALTWORKS, "Campaign", "SALTWORKS", source="ti-sim", actor_id=C.ACTOR_HT, status="active", started="2026-08-20T00:00:00Z", sector_targeting_relevance=0.8),
        _n(C.MALWARE_MAPLELOADER, "Malware", "MAPLELOADER", source="ti-sim", family="MAPLELOADER", malware_type="loader"),
        _n(C.MALWARE_QUILLDROP, "Malware", "QUILLDROP", source="ti-sim", family="QUILLDROP", malware_type="stealer"),
        _n(C.MALWARE_NIGHTFERRY, "Malware", "NIGHTFERRY", source="ti-sim", family="NIGHTFERRY", malware_type="implant"),
        _n(C.MALWARE_BRACKISH, "Malware", "BRACKISH", source="ti-sim", family="BRACKISH", malware_type="webshell"),
        _n(C.IOC_C2_DOMAIN, "Indicator", C.C2_DOMAIN, source="ti-sim", ioc_type="domain", value=C.C2_DOMAIN, report_id=C.REPORT_EMBERCAST, actor_id=C.ACTOR_CJ, campaign_id=C.CAMPAIGN_EMBERCAST, malware_id=C.MALWARE_NIGHTFERRY, active=True, confidence=0.95),
        _n(C.IOC_C2_IP, "Indicator", C.C2_IP, source="ti-sim", ioc_type="ipv4", value=C.C2_IP, report_id=C.REPORT_EMBERCAST, actor_id=C.ACTOR_CJ, campaign_id=C.CAMPAIGN_EMBERCAST, malware_id=C.MALWARE_NIGHTFERRY, active=True),
        _n(C.IOC_EGRESS_IP, "Indicator", C.ATTACKER_EGRESS_IP, source="ti-sim", ioc_type="ipv4", value=C.ATTACKER_EGRESS_IP, report_id=C.REPORT_EMBERCAST, actor_id=C.ACTOR_CJ, campaign_id=C.CAMPAIGN_EMBERCAST, active=True),
        _n(C.IOC_HASH_MAPLELOADER, "Indicator", "mapleloader sha256", source="ti-sim", ioc_type="sha256", value=C.HASH_MAPLELOADER, report_id=C.REPORT_EMBERCAST, actor_id=C.ACTOR_CJ, campaign_id=C.CAMPAIGN_EMBERCAST, malware_id=C.MALWARE_MAPLELOADER, active=True),
        _n(C.IOC_HASH_QUILLDROP, "Indicator", "quilldrop sha256", source="ti-sim", ioc_type="sha256", value=C.HASH_QUILLDROP, report_id=C.REPORT_EMBERCAST, actor_id=C.ACTOR_CJ, campaign_id=C.CAMPAIGN_EMBERCAST, malware_id=C.MALWARE_QUILLDROP, active=True),
        _n(C.IOC_HASH_NIGHTFERRY, "Indicator", "nightferry sha256", source="ti-sim", ioc_type="sha256", value=C.HASH_NIGHTFERRY, report_id=C.REPORT_EMBERCAST, actor_id=C.ACTOR_CJ, campaign_id=C.CAMPAIGN_EMBERCAST, malware_id=C.MALWARE_NIGHTFERRY, active=True),
        _n(C.IOC_SALTWORKS_IP, "Indicator", C.SALTWORKS_IP, source="ti-sim", ioc_type="ipv4", value=C.SALTWORKS_IP, report_id=C.REPORT_SALTWORKS, actor_id=C.ACTOR_HT, campaign_id=C.CAMPAIGN_SALTWORKS, active=True),
        _n(C.IOC_HASH_BRACKISH, "Indicator", "brackish sha256", source="ti-sim", ioc_type="sha256", value=C.HASH_BRACKISH, report_id=C.REPORT_SALTWORKS, actor_id=C.ACTOR_HT, campaign_id=C.CAMPAIGN_SALTWORKS, malware_id=C.MALWARE_BRACKISH, active=True),
        _n(C.REPORT_EMBERCAST, "IntelReport", "EMBERCAST: Cinder Jackal shifts to bastion-host pivoting against fintech cloud estates", source="ti-sim", title="EMBERCAST: Cinder Jackal shifts to bastion-host pivoting against fintech cloud estates", published="2026-09-02T00:00:00Z", publisher="Throughline Labs", report_confidence="high", actor_ids=[C.ACTOR_CJ], campaign_ids=[C.CAMPAIGN_EMBERCAST], technique_ids=C.CJ_TECHNIQUES, indicator_count=7, targeted_sectors=["financial-services"]),
        _n(C.REPORT_SALTWORKS, "IntelReport", "SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services", source="ti-sim", title="SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services", published="2026-09-08T00:00:00Z", publisher="Throughline Labs", report_confidence="medium-high", actor_ids=[C.ACTOR_HT], campaign_ids=[C.CAMPAIGN_SALTWORKS], cve_ids=["CVE-2021-44228"], technique_ids=C.HT_TECHNIQUES, indicator_count=3),
        _n(C.LOG4SHELL, "Vulnerability", "CVE-2021-44228", source="ti-sim", cve_id="CVE-2021-44228", cvss=10.0, epss=0.97, kev=True, severity="critical", exploitation_status="mass_exploitation", actor_interest=[C.ACTOR_HT], sector_targeting_relevance=0.8, ti_report_ids=[C.REPORT_SALTWORKS], affected_component="log4j-core"),
        _n(C.EDGE_LOG4J_PACKAGE, "Package", "log4j-core 2.14.1", package_name="log4j-core", version="2.14.1", ecosystem="maven", scope=C.EDGE_VM),
    ]
    for tid in sorted(set(C.CJ_TECHNIQUES + C.HT_TECHNIQUES)):
        nodes.append(_n(TECH.format(tid), "AttackTechnique", tid, source="ti-sim", technique_id=tid, tactic="n/a", kill_chain_stage=1))
    for aid in ALERT_ROWS:
        nodes.append(_alert_node(aid))
    for key, (eid, t, name, src, key_id, success, err, count) in C.CLOUDEVENTS_A.items():
        cred = C.CRED_BASTION_KEY if key_id == C.CRED_BASTION_KEY_ID else C.CRED_PROD_KEY
        principal = C.BASTION_ROLE if key_id == C.CRED_BASTION_KEY_ID else C.PROD_READER_ROLE
        target = {"a012": C.PROD_READER_ROLE, "a013": C.CARDHOLDER_VAULT, "a014": C.CARDHOLDER_VAULT, "a015": C.DB_READER_SECRET, "a016": C.HSM_SECRET}.get(key)
        nodes.append(_n(eid, "CloudEvent", name, source="cloudtrail-sim", provider="aws", account_id="222222222222" if principal == C.BASTION_ROLE else "111111111111", event_name=name, event_source=src, event_time=t, principal_id=principal, access_key_id=key_id, source_ip=C.ATTACKER_EGRESS_IP, success=success, error_code=err, target_id=target, count=count, anomalous=True, anomaly_reasons=["new ASN for role"], storyline_id=C.STORYLINE_A))
        edges.append(_e("USED_CREDENTIAL", eid, cred))
        edges.append(_e("PERFORMED_BY", eid, principal))
        edges.append(_e("FROM_IP", eid, IP_EGRESS))
        edges.append(_e("MATCHES_IOC", eid, C.IOC_EGRESS_IP, match_type="exact"))
        edges.append(_e("IN_STORYLINE", eid, C.STORYLINE_A, stage=6 if key in ("a010", "a011", "a012") else 7))
        if target:
            edges.append(_e("TARGETED", eid, target))
        if key == "a012":
            edges.append(_e("ASSUMED", eid, C.PROD_READER_ROLE))

    edges += [
        _e("CONTAINS", A["shared"]["id"], C.BASTION_VM), _e("CONTAINS", A["shared"]["id"], C.BASTION_ROLE), _e("CONTAINS", A["prod"]["id"], C.PROD_READER_ROLE),
        _e("CONTAINS", A["prod"]["id"], C.CARDHOLDER_VAULT), _e("CONTAINS", A["prod"]["id"], C.EDGE_VM), _e("CONTAINS", A["prod"]["id"], C.CARDHOLDER_DB),
        _e("EXPOSES", INTERNET, C.EDGE_VM, ports=["8080"], via="security_group"), _e("EXPOSES", INTERNET, C.STG_EDGE_VM, ports=["8080"], via="security_group"),
        _e("EXPOSES", INTERNET, C.DEV_LOG4J_VM, ports=["8080"], via="security_group"), _e("EXPOSES", INTERNET, C.MARKETING_BUCKET, via="public_acl"),
        _e("SAME_AS", C.EP_BASTION, C.BASTION_VM, method="instance_id", confidence=0.99), _e("SAME_AS", C.EP_EDGE, C.EDGE_VM, method="instance_id"),
        _e("SAME_AS", C.EP_DEV_SANDBOX, C.DEV_SANDBOX_VM, method="hostname_ip"), _e("SAME_AS", C.EP_FILESHARE, C.FILESHARE_VM, method="hostname_ip"),
        _e("PRIMARY_USER", C.WKS_DANA, C.USER_DANA), _e("PRIMARY_USER", C.EP_MREYES, C.USER_MREYES),
        _e("MEMBER_OF", C.USER_DANA, C.TEAM_TREASURY), _e("LEADS", C.USER_JOKAFOR, C.TEAM_PLATFORM),
        _e("HAS_ROLE", C.BASTION_VM, C.BASTION_ROLE, via="instance_profile"), _e("HAS_ROLE", C.EDGE_VM, C.EDGE_ROLE, via="instance_profile"),
        _e("HAS_POLICY", C.BASTION_ROLE, C.BASTION_ASSUME_POLICY, attachment="managed"), _e("HAS_POLICY", C.PROD_READER_ROLE, C.PROD_READER_POLICY, attachment="managed"),
        _e("GRANTS", C.BASTION_ASSUME_POLICY, C.PROD_READER_ROLE, actions=["sts:AssumeRole"], access_level="admin"),
        _e("GRANTS", C.PROD_READER_POLICY, C.CARDHOLDER_VAULT, actions=["s3:GetObject", "s3:ListBucket"], access_level="read"),
        _e("GRANTS", C.PROD_READER_POLICY, C.KYC_DOCS, actions=["s3:GetObject"], access_level="read"),
        _e("CAN_ASSUME", C.BASTION_ROLE, C.PROD_READER_ROLE, via="trust_policy", cross_account=True),
        _e("CAN_ACCESS", C.BASTION_ROLE, C.SHARED_LOGS_BUCKET, access_level="write", path_length=1, transitive=False),
        _e("CAN_ACCESS", C.PROD_READER_ROLE, C.CARDHOLDER_VAULT, access_level="read", path_length=1, transitive=False),
        _e("CAN_ACCESS", C.PROD_READER_ROLE, C.KYC_DOCS, access_level="read", path_length=1, transitive=False),
        _e("CAN_ACCESS", C.PROD_READER_ROLE, C.DB_READER_SECRET, access_level="read", path_length=1, transitive=False),
        _e("CAN_ACCESS", C.PROD_READER_ROLE, C.HSM_SECRET, access_level="read", path_length=1, transitive=False),
        _e("CAN_ACCESS", C.EDGE_ROLE, C.APP_CONFIG_BUCKET, access_level="read", path_length=1, transitive=False),
        _e("CAN_ACCESS", C.EDGE_ROLE, C.STATEMENTS_OUT_BUCKET, access_level="write", path_length=1, transitive=False),
        _e("UNLOCKS", C.DB_READER_SECRET, C.CARDHOLDER_DB, credential_type="db_credentials"),
        _e("CREDENTIAL_FOR", C.CRED_BASTION_KEY, C.BASTION_ROLE), _e("CREDENTIAL_FOR", C.CRED_PROD_KEY, C.PROD_READER_ROLE), _e("CREDENTIAL_FOR", C.CRED_SSH_KEY, C.SVC_FINOPS_SFTP),
        _e("DERIVED_FROM", C.CRED_PROD_KEY, C.CRED_BASTION_KEY, via="assume_role"),
        _e("STOLEN_BY", C.CRED_BASTION_KEY, "alert:falcon:ldt-a009", method="imds"), _e("STOLEN_BY", C.CRED_SSH_KEY, "alert:falcon:ldt-a005", method="file_read"),
        _e("PART_OF", C.CARDHOLDER_VAULT, C.APP_CARD_ISSUING), _e("PART_OF", C.CARDHOLDER_DB, C.APP_CARD_ISSUING), _e("PART_OF", C.EDGE_VM, C.APP_STMT_RENDER),
        _e("PART_OF", C.MARKETING_BUCKET, C.APP_MARKETING), _e("PART_OF", C.BASTION_VM, C.APP_SETTLEMENT_SFTP),
        _e("OWNED_BY", C.APP_SETTLEMENT_SFTP, C.TEAM_TREASURY), _e("OWNED_BY", C.APP_CARD_ISSUING, C.TEAM_PAYMENTS), _e("OWNED_BY", C.BASTION_VM, C.TEAM_PLATFORM), _e("OWNED_BY", C.APP_STMT_RENDER, C.TEAM_PAYMENTS),
        _e("DEPENDS_ON", C.APP_SETTLEMENT_SFTP, C.BASTION_VM, dependency_type="sftp_host"), _e("DEPENDS_ON", C.APP_CARD_ISSUING, C.CARDHOLDER_DB, dependency_type="database"),
        _e("LATERAL_MOVEMENT_TO", C.WKS_DANA, C.EP_BASTION, protocol="ssh", account="svc-finops-sftp", time="2026-09-10T02:05:17Z", alert_id="alert:falcon:ldt-a007"),
        _e("VULNERABLE_TO", C.EDGE_VM, C.LOG4SHELL, via_package="log4j-core 2.14.1", exploitable=True), _e("VULNERABLE_TO", C.STG_EDGE_VM, C.LOG4SHELL, exploitable=True), _e("VULNERABLE_TO", C.DEV_LOG4J_VM, C.LOG4SHELL, exploitable=True),
        _e("HAS_PACKAGE", C.EDGE_VM, C.EDGE_LOG4J_PACKAGE), _e("HAS_VULNERABILITY", C.EDGE_LOG4J_PACKAGE, C.LOG4SHELL, fixed_version="2.17.1"),
        _e("EXPLOITS", C.CAMPAIGN_SALTWORKS, C.LOG4SHELL, status="mass_exploitation"), _e("EXPLOITS", C.ACTOR_HT, C.LOG4SHELL, status="mass_exploitation"),
        _e("ATTRIBUTED_TO", C.CAMPAIGN_EMBERCAST, C.ACTOR_CJ, basis="report"), _e("ATTRIBUTED_TO", C.CAMPAIGN_SALTWORKS, C.ACTOR_HT, basis="report"),
        _e("ATTRIBUTED_TO", C.STORYLINE_A, C.ACTOR_CJ, basis="ioc"), _e("ATTRIBUTED_TO", C.STORYLINE_B, C.ACTOR_HT, basis="ioc"),
        _e("USES_MALWARE", C.ACTOR_CJ, C.MALWARE_MAPLELOADER), _e("USES_MALWARE", C.ACTOR_CJ, C.MALWARE_QUILLDROP), _e("USES_MALWARE", C.ACTOR_CJ, C.MALWARE_NIGHTFERRY), _e("USES_MALWARE", C.ACTOR_HT, C.MALWARE_BRACKISH),
        _e("INDICATES", C.IOC_C2_DOMAIN, C.MALWARE_NIGHTFERRY), _e("INDICATES", C.IOC_C2_DOMAIN, C.CAMPAIGN_EMBERCAST), _e("INDICATES", C.IOC_C2_IP, C.MALWARE_NIGHTFERRY),
        _e("INDICATES", C.IOC_EGRESS_IP, C.ACTOR_CJ), _e("INDICATES", C.IOC_HASH_MAPLELOADER, C.MALWARE_MAPLELOADER), _e("INDICATES", C.IOC_HASH_QUILLDROP, C.MALWARE_QUILLDROP),
        _e("INDICATES", C.IOC_HASH_NIGHTFERRY, C.MALWARE_NIGHTFERRY), _e("INDICATES", C.IOC_SALTWORKS_IP, C.CAMPAIGN_SALTWORKS), _e("INDICATES", C.IOC_HASH_BRACKISH, C.MALWARE_BRACKISH),
        _e("REPORTS_ON", C.REPORT_EMBERCAST, C.ACTOR_CJ), _e("REPORTS_ON", C.REPORT_EMBERCAST, C.CAMPAIGN_EMBERCAST), _e("REPORTS_ON", C.REPORT_SALTWORKS, C.ACTOR_HT), _e("REPORTS_ON", C.REPORT_SALTWORKS, C.LOG4SHELL),
        _e("RESOLVES_TO", DOMAIN_C2, IP_C2),
        _e("MATCHES_IOC", "alert:falcon:ldt-a001", C.IOC_HASH_MAPLELOADER, match_type="exact"), _e("MATCHES_IOC", "alert:falcon:ldt-a002", C.IOC_HASH_NIGHTFERRY, match_type="exact"),
        _e("MATCHES_IOC", "alert:falcon:ldt-a003", C.IOC_C2_DOMAIN, match_type="exact"), _e("MATCHES_IOC", DOMAIN_C2, C.IOC_C2_DOMAIN, match_type="exact"),
        _e("MATCHES_IOC", "alert:falcon:ldt-a004", C.IOC_HASH_QUILLDROP, match_type="exact"), _e("MATCHES_IOC", "alert:cloud-anomaly:ca-a017", C.IOC_EGRESS_IP, match_type="exact"),
        _e("MATCHES_IOC", IP_EGRESS, C.IOC_EGRESS_IP, match_type="exact"), _e("MATCHES_IOC", "alert:waf:waf-b001", C.IOC_SALTWORKS_IP, match_type="exact"),
        _e("MATCHES_IOC", "alert:falcon:ldt-b002", C.IOC_SALTWORKS_IP, match_type="exact"), _e("MATCHES_IOC", "alert:falcon:ldt-b003", C.IOC_HASH_BRACKISH, match_type="exact"),
        _e("INVOLVES", "alert:falcon:ldt-a009", C.CRED_BASTION_KEY, role="credential"), _e("INVOLVES", "alert:cloud-anomaly:ca-a017", C.CRED_PROD_KEY, role="credential"),
        _e("INVOLVES", "alert:cloud-anomaly:ca-a017", IP_EGRESS, role="source"), _e("INVOLVES", "alert:falcon:ldt-a003", DOMAIN_C2, role="destination"),
        _e("INVOLVES", "alert:falcon:ldt-a005", C.CRED_SSH_KEY, role="credential"), _e("INVOLVES", "alert:falcon:ldt-a007", C.SVC_FINOPS_SFTP, role="subject"),
        _e("INVOLVES", "alert:falcon:ldt-n003", C.USER_MREYES, role="subject"), _e("INVOLVES", "alert:waf:waf-b001", IP_SALT, role="source"),
    ]
    for tid in C.CJ_TECHNIQUES:
        edges.append(_e("USES_TECHNIQUE", C.ACTOR_CJ, TECH.format(tid)))
    for tid in C.HT_TECHNIQUES:
        edges.append(_e("USES_TECHNIQUE", C.ACTOR_HT, TECH.format(tid)))
    prev_a: str | None = None
    for aid, row in ALERT_ROWS.items():
        entity_id, entity_label = row[1], row[2]
        edges.append(_e("ON_ENDPOINT" if entity_label == "Endpoint" else "ON_RESOURCE", aid, entity_id))
        for tid in row[4]:
            edges.append(_e("USES_TECHNIQUE", aid, TECH.format(tid)))
        if row[6]:
            edges.append(_e("IN_STORYLINE", aid, row[6], stage=1))
            edges.append(_e("ATTRIBUTED_TO", aid, row[6] == C.STORYLINE_A and C.CAMPAIGN_EMBERCAST or C.CAMPAIGN_SALTWORKS, basis="ioc"))
        if row[6] == C.STORYLINE_A and aid != "alert:cloud-anomaly:ca-a017":
            if prev_a:
                edges.append(_e("NEXT_STAGE", prev_a, aid, storyline_id=C.STORYLINE_A))
            prev_a = aid
    for aid in ("alert:falcon:ldt-a001", "alert:falcon:ldt-a002", "alert:falcon:ldt-a003", "alert:falcon:ldt-a004", "alert:falcon:ldt-a005", "alert:falcon:ldt-a006"):
        edges.append(_e("PART_OF_INCIDENT", aid, C.INCIDENT_WKS))
    for aid in ("alert:falcon:ldt-a007", "alert:falcon:ldt-a008x", "alert:falcon:ldt-a009"):
        edges.append(_e("PART_OF_INCIDENT", aid, C.INCIDENT_BASTION))
    for aid in ("alert:falcon:ldt-b002", "alert:falcon:ldt-b003"):
        edges.append(_e("PART_OF_INCIDENT", aid, C.INCIDENT_EDGE))
    for nid in (C.EP_BASTION, C.BASTION_VM, C.BASTION_ROLE, C.PROD_READER_ROLE, C.CARDHOLDER_VAULT, C.CRED_BASTION_KEY, C.CRED_PROD_KEY, C.WKS_DANA, C.USER_DANA, C.KYC_DOCS, C.CARDHOLDER_DB, C.DB_READER_SECRET, C.HSM_SECRET):
        edges.append(_e("IN_STORYLINE", nid, C.STORYLINE_A, stage=5))
    for nid in (C.EDGE_VM, C.EP_EDGE, C.EDGE_ROLE, C.APP_CONFIG_BUCKET):
        edges.append(_e("IN_STORYLINE", nid, C.STORYLINE_B, stage=2))

    graph = ContextGraph.from_records(nodes, edges)
    graph.build_info = {"seed": C.SEED, "generated_at": C.NOW, "checksum": "fixture", "storylines": [C.STORYLINE_A, C.STORYLINE_B]}
    problems = graph.validate()
    if problems:
        raise AssertionError("fixture graph violates the schema: " + "; ".join(problems[:5]))
    return graph


# ----------------------------------------------------------------------------- FakeStore


class FakeCypherResult(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    elapsed_ms: int
    truncated: bool


class FakeStore(ContextGraphStore):
    """GraphStore over the fixture graph; ``cypher=True`` enables a scripted read-only Cypher endpoint."""

    def __init__(self, graph: ContextGraph, *, cypher: bool = False) -> None:
        super().__init__(graph)
        self.name = "fake-cypher" if cypher else "fake"
        self.cypher = cypher
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def capabilities(self) -> dict[str, Any]:
        return {"cypher": self.cypher, "multi_label_patterns": self.cypher, "shortest_path": True, "read_only": True}

    def run_readonly_cypher(self, query: str, params: dict[str, Any] | None = None, row_limit: int = 200, timeout_ms: int = 3000) -> FakeCypherResult:
        self.calls.append(("cypher", {"query": query, "row_limit": row_limit}))
        if not self.cypher:
            raise NotSupported("Cypher is not available on the fake backend")
        upper = query.upper()
        if any(kw in upper for kw in (" CREATE ", " MERGE ", " DELETE ", " SET ", " DROP ", "CALL ")) or upper.startswith(("CREATE", "MERGE", "DELETE", "DROP")):
            raise QueryRejected("write statements are not allowed")
        if "SLEEP" in upper:
            raise QueryTimeout("query exceeded 3000 ms")
        rows = [
            [{"id": C.BASTION_VM, "label": "VirtualMachine", "name": "bas-01"}, {"src": C.BASTION_VM, "type": "HAS_ROLE", "dst": C.BASTION_ROLE}, {"id": C.BASTION_ROLE, "label": "IamRole", "name": "LarkspurBastionSSMRole"}],
            [{"id": C.EDGE_VM, "label": "VirtualMachine", "name": "stmt-render-2a"}, {"src": C.EDGE_VM, "type": "HAS_ROLE", "dst": C.EDGE_ROLE}, {"id": C.EDGE_ROLE, "label": "IamRole", "name": "LarkspurStmtRenderRole"}],
        ]
        return FakeCypherResult(columns=["vm", "r", "role"], rows=rows[:row_limit], elapsed_ms=3, truncated=len(rows) > row_limit)


# ----------------------------------------------------------------------------- FakeEngine

FORWARD: dict[str, tuple[str, ...]] = {
    "Alert": ("ON_ENDPOINT", "ON_RESOURCE", "INVOLVES"),
    "Endpoint": ("SAME_AS",),
    "VirtualMachine": ("HAS_ROLE",),
    "Workload": ("HAS_ROLE",),
    "IamRole": ("CAN_ASSUME", "CAN_ACCESS"),
    "IamUser": ("CAN_ASSUME", "CAN_ACCESS"),
    "HumanUser": ("MAPS_TO", "CAN_ACCESS", "CAN_ASSUME"),
    "Group": ("MAPS_TO",),
    "Credential": ("CREDENTIAL_FOR",),
    "Secret": ("UNLOCKS",),
}
IDENTITY = {"IamRole", "IamUser", "HumanUser", "ServiceAccount"}
DATA_HOLDERS = {"StorageBucket", "Database"}


class FakeEngine:
    def __init__(self, graph: ContextGraph) -> None:
        self.g = graph
        self.calls: list[str] = []

    # -------------------------------------------------------------- alerts
    def _alert_ids(self) -> list[str]:
        return list(self.g.nodes_by_label("Alert"))

    def _ranked(self) -> tuple[dict[str, int], dict[str, int]]:
        ids = self._alert_ids()
        ctx = sorted(ids, key=lambda a: (-int(self.g.get(a, "contextual_score", 0)), str(self.g.get(a, "detected_at", ""))))
        ven = sorted(ids, key=lambda a: (-int(self.g.get(a, "vendor_severity_rank", 0)), str(self.g.get(a, "detected_at", ""))), reverse=False)
        ven = sorted(ids, key=lambda a: (-int(self.g.get(a, "vendor_severity_rank", 0)), "".join(reversed(str(self.g.get(a, "detected_at", ""))))))
        return {a: i + 1 for i, a in enumerate(ctx)}, {a: i + 1 for i, a in enumerate(ven)}

    def alert_summary(self, alert_id: str) -> AlertSummary:
        attrs = self.g.node(alert_id)
        if attrs is None or attrs.get("label") != "Alert":
            raise KeyError(f"alert {alert_id!r} not found")
        ctx_rank, ven_rank = self._ranked()
        entity_id = attrs.get("entity_id")
        return AlertSummary(
            id=alert_id, title=attrs.get("title") or attrs.get("name"), source_system=attrs.get("source_system"), alert_type=attrs.get("alert_type"),
            vendor_severity=attrs.get("vendor_severity"), vendor_severity_rank=int(attrs.get("vendor_severity_rank", 0)), contextual_score=int(attrs.get("contextual_score", 0)),
            contextual_band=attrs.get("contextual_band") or band_for_score(int(attrs.get("contextual_score", 0))), detected_at=attrs.get("detected_at"), status=attrs.get("status", "new"),
            entity_id=entity_id, entity_name=self.g.get(entity_id, "name") if entity_id else None, entity_label=attrs.get("entity_label"), hostname=attrs.get("hostname"),
            user=attrs.get("user"), techniques=list(attrs.get("techniques") or []), storyline_id=attrs.get("storyline_id"), graph_reasons=list(attrs.get("graph_reasons") or []),
            reaches_crown_jewel=bool(attrs.get("reaches_crown_jewel")), on_attack_path=bool(attrs.get("on_attack_path")), ioc_match_count=int(attrs.get("ioc_match_count") or 0),
            ti_actor_ids=list(attrs.get("ti_actor_ids") or []), vendor_rank_position=ven_rank.get(alert_id), contextual_rank_position=ctx_rank.get(alert_id),
        )

    def list_alerts(self, *, sort: str = "contextual", order: str = "desc", band=None, severity=None, source=None, storyline_id=None, reaches_crown_jewel=None, on_attack_path=None, q=None, limit: int = 50, offset: int = 0) -> tuple[list[AlertSummary], int]:
        self.calls.append("list_alerts")
        items = [self.alert_summary(a) for a in self._alert_ids()]
        if band:
            items = [a for a in items if a.contextual_band == band]
        if severity:
            items = [a for a in items if a.vendor_severity == severity]
        if source:
            items = [a for a in items if a.source_system == source]
        if storyline_id:
            items = [a for a in items if a.storyline_id == storyline_id]
        if reaches_crown_jewel is not None:
            items = [a for a in items if a.reaches_crown_jewel == reaches_crown_jewel]
        if on_attack_path is not None:
            items = [a for a in items if a.on_attack_path == on_attack_path]
        if q:
            ql = q.lower()
            items = [a for a in items if ql in a.title.lower() or ql in (a.hostname or "").lower() or ql in (a.entity_id or "").lower() or ql in a.id.lower() or ql in (a.entity_name or "").lower()]
        if sort == "vendor":
            items.sort(key=lambda a: (a.vendor_severity_rank, a.detected_at or ""), reverse=True)
        elif sort == "time":
            items.sort(key=lambda a: a.detected_at or "", reverse=True)
        else:
            items.sort(key=lambda a: (a.contextual_score, a.detected_at or ""), reverse=True)
        if order == "asc":
            items.reverse()
        total = len(items)
        return items[offset: offset + limit], total

    def flat_view(self, alert_id: str) -> dict[str, Any]:
        attrs = self.g.node(alert_id)
        if attrs is None or attrs.get("label") != "Alert":
            raise KeyError(f"alert {alert_id!r} not found")
        raw = attrs.get("raw")
        return json.loads(raw) if isinstance(raw, str) else dict(raw or {})

    def _blast_ids(self, root: str, depth: int = 5) -> dict[str, tuple[int, list[str], str | None]]:
        """{node_id: (hops, via_path, access_level)} forward reachability with the storyline's edge semantics."""
        out: dict[str, tuple[int, list[str], str | None]] = {root: (0, [root], None)}
        frontier = [root]
        for hop in range(1, depth + 1):
            nxt: list[str] = []
            for u in frontier:
                label = self.g.label_of(u) or ""
                for v, d in self.g.out_edges(u, FORWARD.get(label, ())):
                    if label == "Alert" and d["type"] == "INVOLVES" and self.g.label_of(v) not in ("Credential", "IamRole"):
                        continue
                    if v not in out:
                        out[v] = (hop, out[u][1] + [v], d.get("access_level"))
                        nxt.append(v)
                if label == "StorageBucket":
                    for v in self.g.get(u, "contains_credentials_for") or []:
                        if v in self.g and v not in out:
                            out[v] = (hop, out[u][1] + [v], "read")
                            nxt.append(v)
            frontier = nxt
        return out

    def blast_radius(self, root_id: str, depth: int = 4, max_nodes: int = 500) -> BlastRadiusResult:
        self.calls.append("blast_radius")
        if root_id not in self.g:
            raise KeyError(f"node {root_id!r} not found")
        reach = self._blast_ids(root_id, depth)
        jewels, stores, secrets, idents = [], [], [], []
        accounts: set[str] = set()
        by_hop: dict[int, int] = {}
        for nid, (hops, via, acc) in reach.items():
            if nid == root_id:
                continue
            by_hop[hops] = by_hop.get(hops, 0) + 1
            label = self.g.label_of(nid) or ""
            rn = ReachedNode(node=self.g.node_out(nid, highlight=bool(self.g.get(nid, "crown_jewel"))), hops=hops, reach_score=round(1 / hops, 2), via_path=via, access_level=acc)
            if self.g.get(nid, "account_id"):
                accounts.add(str(self.g.get(nid, "account_id")))
            if self.g.get(nid, "crown_jewel"):
                jewels.append(rn)
            elif label in DATA_HOLDERS:
                stores.append(rn)
            elif label == "Secret":
                secrets.append(rn)
            elif label in IDENTITY:
                idents.append(rn)
        ids = list(reach)[:max_nodes]
        frag = self.g.fragment(ids, highlight_ids=[root_id] + [j.node.id for j in jewels], focus=[root_id], layout_hint="blast_radius", max_nodes=max_nodes)
        summary = f"{len(reach) - 1} nodes reachable from {root_id}: {len(jewels)} crown jewels, {len(secrets)} secrets, {len(idents)} identities"
        return BlastRadiusResult(root_id=root_id, depth=depth, reached_count=len(reach) - 1, crown_jewels=jewels, data_stores=stores, secrets=secrets, identities=idents, accounts_touched=sorted(accounts), by_hop=by_hop, summary=summary, fragment=frag)

    def risk_breakdown(self, alert_id: str) -> RiskBreakdown:
        a = self.alert_summary(alert_id)
        attrs = self.g.node(alert_id) or {}
        sb = json.loads(attrs.get("score_breakdown") or "{}")
        values = sb.get("factors") or {"severity": SEV_RANK[a.vendor_severity] / 4, "exposure": 0.4, "privilege": 0.3, "data": 0.3, "threat_intel": 0.2, "correlation": 0.2}
        rails = list(sb.get("rails") or [])
        reach = self._blast_ids(alert_id, 5)
        jewels = [n for n in reach if self.g.get(n, "crown_jewel")]
        roles = [n for n in reach if self.g.label_of(n) == "IamRole"]
        indicators = [v for _, v in [(u, v) for u in reach for v, d in self.g.out_edges(u, ["MATCHES_IOC"])]]
        story = [a.storyline_id] if a.storyline_id else []
        evidence = {
            "severity": [alert_id], "exposure": [x for x in [a.entity_id] if x] + [n for n in reach if self.g.label_of(n) == "VirtualMachine"],
            "privilege": roles, "data": jewels, "threat_intel": indicators + list(a.ti_actor_ids), "correlation": story,
        }
        reasons = {
            "severity": f"vendor severity {a.vendor_severity}", "exposure": "asset exposure and network position", "privilege": f"{len(roles)} role(s) reachable",
            "data": f"{len(jewels)} crown jewel(s) reachable", "threat_intel": f"{len(indicators)} IOC match(es); actors {', '.join(a.ti_actor_ids) or 'none'}", "correlation": f"storyline {a.storyline_id}" if a.storyline_id else "no correlated alerts",
        }
        factors = [RiskFactor(key=k, label=FACTOR_LABELS[k], value=float(values.get(k, 0)), weight=WEIGHTS[k], contribution=round(100 * WEIGHTS[k] * float(values.get(k, 0)), 1), reason=reasons[k], evidence_ids=[e for e in evidence[k] if e in self.g]) for k in WEIGHTS]
        raw = sum(f.contribution for f in factors)
        return RiskBreakdown(subject_id=alert_id, vendor_severity=a.vendor_severity, vendor_severity_rank=a.vendor_severity_rank, contextual_score=a.contextual_score, band=a.contextual_band, raw_score=round(raw, 1), factors=factors, rails=rails, reasons=list(a.graph_reasons), delta_vs_vendor=(a.contextual_rank_position or 0) - (a.vendor_rank_position or 0))

    def insights(self, alert_id: str) -> list[Insight]:
        a = self.alert_summary(alert_id)
        out: list[Insight] = []
        reach = self._blast_ids(alert_id, 5)
        jewels = [n for n in reach if self.g.get(n, "crown_jewel")]
        if jewels:
            hops = min(reach[j][0] for j in jewels)
            out.append(Insight(kind="blast_radius", statement=f"{a.id} reaches {len(jewels)} crown jewel(s) within {hops} hops via the asset's instance role chain.", hops=hops, sources=["falcon", "wiz"], importance=0.9, evidence_node_ids=jewels, evidence_edge_ids=[edge_id(reach[jewels[0]][1][-2], "CAN_ACCESS", jewels[0])] if len(reach[jewels[0]][1]) > 1 else []))
        iocs = [v for v, _ in self.g.out_edges(alert_id, ["MATCHES_IOC"])]
        if iocs:
            out.append(Insight(kind="ti_match", statement=f"{a.id} matches {len(iocs)} indicator(s) from an active campaign.", hops=1, sources=["falcon", "ti"], importance=0.8, evidence_node_ids=iocs))
        creds = [u for u, _ in self.g.in_edges(alert_id, ["STOLEN_BY"])]
        for c in creds:
            events = [u for u, _ in self.g.in_edges(c, ["USED_CREDENTIAL"])]
            if events:
                out.append(Insight(kind="credential_join", statement=f"Credential {c} stolen by {a.id} was used in {len(events)} cloud API call(s).", hops=2, sources=["falcon", "cloudtrail"], importance=0.95, evidence_node_ids=[c] + events))
        if a.contextual_score <= 25:
            out.append(Insight(kind="noise", statement="No data path, no privilege and no threat-intel relevance: capped at the noise ceiling.", hops=0, sources=[a.source_system], importance=0.3, evidence_node_ids=[alert_id]))
        return out

    def alert_context(self, alert_id: str) -> AlertContext:
        a = self.alert_summary(alert_id)
        br = self.blast_radius(alert_id, depth=5)
        paths = self.attack_paths(through_id=alert_id, k=3)
        story = self.storyline(a.storyline_id, with_fragment=True) if a.storyline_id else None
        related = [self.alert_summary(x) for x in self._alert_ids() if x != alert_id and a.storyline_id and self.g.get(x, "storyline_id") == a.storyline_id]
        evidence = br.fragment
        for p in paths:
            evidence = evidence.merge(p.fragment)
        layout = "path" if paths else "blast_radius"
        evidence = evidence.model_copy(update={"layout_hint": layout, "focus": [alert_id]})
        return AlertContext(alert=a, flat_view=self.flat_view(alert_id), risk=self.risk_breakdown(alert_id), insights=self.insights(alert_id), blast_radius=br, attack_paths=paths, storyline=story, threat_intel=self.threat_intel_context(alert_id), related_alerts=related, evidence=evidence)

    # -------------------------------------------------------------- graph analytics
    def _path_out(self, node_ids: list[str], stages: list[dict[str, Any]], likelihood: float, pid: str) -> AttackPathOut:
        frag = self.g.fragment(node_ids, highlight_ids=node_ids, focus=[node_ids[0], node_ids[-1]], layout_hint="path", paths=[self.g.path_out(node_ids, label=pid, likelihood=likelihood, stages=[s["stage"] for s in stages])])
        return AttackPathOut(id=pid, entry_id=node_ids[0], target_id=node_ids[-1], through_id=None, likelihood=likelihood, hops=len(node_ids) - 1, stages=[StageOut(**{k: v for k, v in s.items()}) for s in stages], summary=f"{len(stages)}-stage path from {node_ids[0]} to {node_ids[-1]}", fragment=frag)

    def attack_paths(self, through_id: str | None = None, target_id: str | None = None, entry_id: str | None = None, k: int = 5) -> list[AttackPathOut]:
        self.calls.append("attack_paths")
        cands = [(PATH_A, STORYLINE_A_STAGES, 0.82, "path:embercast", C.STORYLINE_A), (PATH_B, STORYLINE_B_STAGES, 0.61, "path:saltworks", C.STORYLINE_B)]
        out = []
        for nodes, stages, lik, pid, story in cands:
            members = set(nodes) | {n for s in stages for n in s["node_ids"]} | set(self.g.get(story, "alert_ids") or [])
            members |= {v for m in list(members) for v, d in self.g.out_edges(m, ["SAME_AS"])}
            if through_id and through_id not in members:
                continue
            if target_id and target_id not in nodes:
                continue
            if entry_id and entry_id != nodes[0]:
                continue
            p = self._path_out(nodes, stages, lik, pid)
            p.through_id = through_id
            out.append(p)
        return out[:k]

    def find_paths(self, src_id: str, dst_id: str, max_hops: int = 6, k: int = 3, edge_types=None) -> GraphFragment:
        self.calls.append("find_paths")
        for nid in (src_id, dst_id):
            if nid not in self.g:
                raise KeyError(f"node {nid!r} not found")
        path = self.g.shortest_path(src_id, dst_id, edge_types=edge_types, max_hops=max_hops, directed=False)
        if not path:
            return GraphFragment(focus=[src_id, dst_id], layout_hint="path")
        return self.g.fragment(path, highlight_ids=path, focus=[src_id, dst_id], layout_hint="path", paths=[self.g.path_out(path, label="shortest")])

    def neighborhood(self, node_id: str, depth: int = 1, edge_types=None, direction: str = "both", labels=None, max_nodes: int = 150) -> GraphFragment:
        if node_id not in self.g:
            raise KeyError(f"node {node_id!r} not found")
        dist = self.g.k_hop(node_id, depth=depth, edge_types=edge_types, direction=direction, max_nodes=max_nodes, node_labels=labels)
        ordered = [n for n, _ in sorted(dist.items(), key=lambda kv: (kv[1], kv[0]))]
        return self.g.fragment(ordered, highlight_ids=[node_id], focus=[node_id], layout_hint="neighborhood", max_nodes=max_nodes)

    def _alerts_on(self, node_id: str) -> list[str]:
        if self.g.label_of(node_id) == "Alert":
            return [node_id]
        return [u for u, _ in self.g.in_edges(node_id, ["ON_ENDPOINT", "ON_RESOURCE", "INVOLVES"])]

    def node_card(self, node_id: str) -> dict[str, Any]:
        if node_id not in self.g:
            raise KeyError(f"node {node_id!r} not found")
        counts: dict[str, int] = {}
        for _, d in self.g.out_edges(node_id):
            counts[d["type"]] = counts.get(d["type"], 0) + 1
        for _, d in self.g.in_edges(node_id):
            counts[d["type"]] = counts.get(d["type"], 0) + 1
        alerts = [self.alert_summary(a) for a in self._alerts_on(node_id)][:10]
        ti = self.threat_intel_context(node_id)
        return {"node": self.g.node_out(node_id, highlight=True), "degree": {"in": len(self.g.in_edges(node_id)), "out": len(self.g.out_edges(node_id))}, "edge_type_counts": counts, "alerts": alerts, "threat_intel": ti if (ti.matches or ti.actors) else None}

    # -------------------------------------------------------------- storylines & TI
    def _storyline_out(self, sid: str, with_fragment: bool) -> StorylineOut:
        attrs = self.g.node(sid)
        if attrs is None or attrs.get("label") != "Storyline":
            raise KeyError(f"storyline {sid!r} not found")
        stages_raw = json.loads(attrs.get("stages") or "[]")
        stages = [StageOut(**s) for s in stages_raw]
        frag = None
        if with_fragment:
            ids = list(dict.fromkeys([sid] + [n for s in stages_raw for n in s["node_ids"]] + list(attrs.get("alert_ids") or []) + list(attrs.get("crown_jewels_reached") or [])))
            chain = PATH_A if sid == C.STORYLINE_A else PATH_B
            frag = self.g.fragment(ids, highlight_ids=chain, focus=[sid], layout_hint="storyline", paths=[self.g.path_out(chain, label="kill chain", stages=[s["stage"] for s in stages_raw])])
        actor, campaign = attrs.get("actor_id"), attrs.get("campaign_id")
        return StorylineOut(id=sid, title=attrs.get("title") or attrs.get("name"), summary=attrs.get("summary") or "", actor_id=actor, actor_name=self.g.get(actor, "name") if actor else None, campaign_id=campaign, campaign_name=self.g.get(campaign, "name") if campaign else None, contextual_score=int(attrs.get("contextual_score") or 0), stage_count=int(attrs.get("stage_count") or len(stages)), alert_ids=list(attrs.get("alert_ids") or []), crown_jewels_reached=list(attrs.get("crown_jewels_reached") or []), first_event=attrs.get("first_event"), last_event=attrs.get("last_event"), stages=stages, fragment=frag)

    def list_storylines(self) -> list[StorylineOut]:
        return sorted((self._storyline_out(s, False) for s in self.g.nodes_by_label("Storyline")), key=lambda s: -s.contextual_score)

    def storyline(self, storyline_id: str, with_fragment: bool = True) -> StorylineOut:
        return self._storyline_out(storyline_id, with_fragment)

    def _ti_from_indicators(self, indicators: Iterable[str], matched_from: Iterable[str] | None = None) -> TIContext:
        inds = list(dict.fromkeys(indicators))
        matches: list[TIMatch] = []
        actors: dict[str, NodeOut] = {}
        campaigns: dict[str, NodeOut] = {}
        malware: dict[str, NodeOut] = {}
        reports: dict[str, NodeOut] = {}
        allowed = set(matched_from) if matched_from is not None else None
        for ioc in inds:
            for u, d in self.g.in_edges(ioc, ["MATCHES_IOC"]):
                if allowed is not None and u not in allowed:
                    continue
                matches.append(TIMatch(indicator_id=ioc, ioc_type=str(self.g.get(ioc, "ioc_type")), value=str(self.g.get(ioc, "value")), confidence=float(self.g.get(ioc, "confidence") or 0.8), matched_node_id=u, matched_label=self.g.label_of(u) or "", actor_id=self.g.get(ioc, "actor_id"), campaign_id=self.g.get(ioc, "campaign_id"), malware_id=self.g.get(ioc, "malware_id"), report_id=self.g.get(ioc, "report_id")))
            for key, store in (("actor_id", actors), ("campaign_id", campaigns), ("malware_id", malware), ("report_id", reports)):
                ref = self.g.get(ioc, key)
                if ref and ref in self.g:
                    store[ref] = self.g.node_out(ref)
        for cid in list(campaigns):
            aid = self.g.get(cid, "actor_id")
            if aid and aid in self.g:
                actors[aid] = self.g.node_out(aid)
        rel = max((float(self.g.get(a, "sector_targeting_relevance") or 0) for a in actors), default=None)
        return TIContext(matches=matches, actors=list(actors.values()), campaigns=list(campaigns.values()), malware=list(malware.values()), exploited_vulnerabilities=[], reports=list(reports.values()), ttp_overlap={}, sector_relevance=rel, summary=f"{len(matches)} IOC match(es) across {len(actors)} actor(s)")

    def threat_intel_context(self, node_or_alert_id: str) -> TIContext:
        if node_or_alert_id not in self.g:
            raise KeyError(f"node {node_or_alert_id!r} not found")
        seeds = [node_or_alert_id] + [v for v, _ in self.g.out_edges(node_or_alert_id, ["INVOLVES"])]
        inds = [v for u in seeds for v, _ in self.g.out_edges(u, ["MATCHES_IOC"])]
        ti = self._ti_from_indicators(inds, matched_from=seeds)
        if self.g.label_of(node_or_alert_id) == "Alert":
            techs = set(self.g.get(node_or_alert_id, "techniques") or [])
            for a in ti.actors:
                actor_techs = {self.g.get(v, "technique_id") for v, _ in self.g.out_edges(a.id, ["USES_TECHNIQUE"])}
                ti.ttp_overlap[a.id] = round(len(techs & actor_techs) / max(len(actor_techs), 1), 3)
        return ti

    def _actor_indicators(self, actor_id: str) -> list[str]:
        out = []
        for ioc in self.g.nodes_by_label("Indicator"):
            if self.g.get(ioc, "actor_id") == actor_id or self.g.get(self.g.get(ioc, "campaign_id") or "", "actor_id") == actor_id:
                out.append(ioc)
        return out

    def ti_lookup(self, value: str) -> TIContext:
        v = value.strip().lower()
        if v in {x.lower() for x in self.g.G.nodes} and self.g.label_of(value) in ("ThreatActor", "Campaign", "IntelReport", "Malware"):
            return self._ti_for_ti_node(value)
        for label in ("ThreatActor", "Campaign", "Malware", "IntelReport"):
            for nid in self.g.nodes_by_label(label):
                names = {str(self.g.get(nid, "name", "")).lower(), *(str(a).lower() for a in self.g.get(nid, "aliases") or [])}
                if v in names or v == nid.lower():
                    return self._ti_for_ti_node(nid)
        for ioc in self.g.nodes_by_label("Indicator"):
            if v == str(self.g.get(ioc, "value", "")).lower() or v == ioc.lower():
                return self._ti_from_indicators([ioc])
        if v.startswith("cve-") or v.startswith("cve:"):
            cve = f"cve:{value.upper()}" if not v.startswith("cve:") else value
            if cve in self.g:
                actors = [u for u, _ in self.g.in_edges(cve, ["EXPLOITS"]) if self.g.label_of(u) == "ThreatActor"]
                camps = [u for u, _ in self.g.in_edges(cve, ["EXPLOITS"]) if self.g.label_of(u) == "Campaign"]
                return TIContext(actors=[self.g.node_out(a) for a in actors], campaigns=[self.g.node_out(c) for c in camps], exploited_vulnerabilities=[self.g.node_out(cve)], sector_relevance=float(self.g.get(cve, "sector_targeting_relevance") or 0), summary=f"{cve}: {self.g.get(cve, 'exploitation_status')}")
        if value in self.g:
            return self.threat_intel_context(value)
        return TIContext(summary=f"no threat intel for {value!r}")

    def _ti_for_ti_node(self, nid: str) -> TIContext:
        label = self.g.label_of(nid)
        if label == "ThreatActor":
            actor = nid
        elif label == "Campaign":
            actor = self.g.get(nid, "actor_id")
        elif label == "IntelReport":
            actor = (self.g.get(nid, "actor_ids") or [None])[0]
        else:
            actor = next((u for u, _ in self.g.in_edges(nid, ["USES_MALWARE"]) if self.g.label_of(u) == "ThreatActor"), None)
        inds = self._actor_indicators(actor) if actor else []
        ti = self._ti_from_indicators(inds)
        if actor and actor in self.g and actor not in {a.id for a in ti.actors}:
            ti.actors.append(self.g.node_out(actor))
        for u, _ in self.g.in_edges(actor or "", ["REPORTS_ON"]):
            if u not in {r.id for r in ti.reports}:
                ti.reports.append(self.g.node_out(u))
        cves = [v for v, _ in self.g.out_edges(actor or "", ["EXPLOITS"])]
        ti.exploited_vulnerabilities = [self.g.node_out(c) for c in cves]
        ti.sector_relevance = float(self.g.get(actor, "sector_targeting_relevance") or 0) if actor else None
        techs = {self.g.get(v, "technique_id") for v, _ in self.g.out_edges(actor or "", ["USES_TECHNIQUE"])}
        seen = {str(t) for a in self._alert_ids() if actor in (self.g.get(a, "ti_actor_ids") or []) for t in self.g.get(a, "techniques") or []}
        if actor:
            ti.ttp_overlap[actor] = round(len(techs & seen) / max(len(techs), 1), 3)
        ti.summary = f"{self.g.get(actor, 'name') if actor else nid}: {len(ti.matches)} IOC match(es), TTP overlap {len(techs & seen)}/{len(techs)}, sector relevance {ti.sector_relevance}"
        return ti

    def ti_actors(self) -> list[dict[str, Any]]:
        rows = []
        for a in self.g.nodes_by_label("ThreatActor"):
            ti = self._ti_for_ti_node(a)
            camps = [self.g.node_out(c) for c in self.g.nodes_by_label("Campaign") if self.g.get(c, "actor_id") == a]
            cves = [v for v, _ in self.g.out_edges(a, ["EXPLOITS"])]
            present = [c for c in cves if self.g.in_edges(c, ["VULNERABLE_TO"])]
            rows.append({"actor": self.g.node_out(a), "campaigns": camps, "sector_relevance": float(self.g.get(a, "sector_targeting_relevance") or 0), "active": bool(self.g.get(a, "active")), "ioc_matches": len(ti.matches), "matched_alerts": sorted({m.matched_node_id for m in ti.matches if m.matched_label == "Alert"}), "exploited_cves_present": len(present), "affected_assets": len({m.matched_node_id for m in ti.matches})})
        rows.sort(key=lambda r: (-r["sector_relevance"], -r["ioc_matches"]))
        return rows

    def _ti_detail(self, nid: str) -> dict[str, Any]:
        if nid not in self.g:
            raise KeyError(f"node {nid!r} not found")
        ti = self._ti_for_ti_node(nid)
        actor = ti.actors[0].id if ti.actors else None
        affected_ids = list(dict.fromkeys([m.matched_node_id for m in ti.matches] + [nid]))
        return {
            "actor": self.g.node_out(actor) if actor else None, "campaigns": [self.g.node_out(c) for c in self.g.nodes_by_label("Campaign") if self.g.get(c, "actor_id") == actor],
            "malware": [self.g.node_out(v) for v, _ in self.g.out_edges(actor or "", ["USES_MALWARE"])], "techniques": [self.g.node_out(v) for v, _ in self.g.out_edges(actor or "", ["USES_TECHNIQUE"])],
            "indicators": [self.g.node_out(i) for i in self._actor_indicators(actor)] if actor else [], "reports": ti.reports, "context": ti,
            "affected": self.g.fragment(affected_ids, focus=[nid], layout_hint="neighborhood"),
        }

    def ti_actor(self, actor_id: str) -> dict[str, Any]:
        if self.g.label_of(actor_id) != "ThreatActor":
            raise KeyError(f"actor {actor_id!r} not found")
        return self._ti_detail(actor_id)

    def ti_campaign(self, campaign_id: str) -> dict[str, Any]:
        if self.g.label_of(campaign_id) != "Campaign":
            raise KeyError(f"campaign {campaign_id!r} not found")
        d = self._ti_detail(campaign_id)
        d["campaign"] = self.g.node_out(campaign_id)
        return d

    def ti_reports(self) -> list[NodeOut]:
        return sorted((self.g.node_out(r) for r in self.g.nodes_by_label("IntelReport")), key=lambda n: str(n.props.get("published", "")), reverse=True)

    def ti_report(self, report_id: str) -> dict[str, Any]:
        if self.g.label_of(report_id) != "IntelReport":
            raise KeyError(f"report {report_id!r} not found")
        ti = self._ti_for_ti_node(report_id)
        cves = [v for v, _ in self.g.out_edges(report_id, ["REPORTS_ON"]) if self.g.label_of(v) == "Vulnerability"]
        exposed = [u for c in cves for u, _ in self.g.in_edges(c, ["VULNERABLE_TO"])]
        matched = sorted({m.matched_node_id for m in ti.matches if m.matched_label == "Alert"})
        return {"report": self.g.node_out(report_id), "actors": ti.actors, "campaigns": ti.campaigns, "malware": ti.malware, "cves": [self.g.node_out(c) for c in cves], "indicators": [self.g.node_out(i) for i in {m.indicator_id for m in ti.matches}], "techniques": [self.g.node_out(TECH.format(t)) for t in self.g.get(report_id, "technique_ids") or [] if TECH.format(t) in self.g], "impact": {"matched_alerts": [self.alert_summary(a) for a in matched], "exposed_assets": [self.g.node_out(v) for v in exposed], "summary": f"{len(matched)} matched alert(s), {len(exposed)} exposed asset(s)"}}

    def ti_exposure(self, sector_only: bool = True) -> list[dict[str, Any]]:
        rows = []
        exposed = [v for v, _ in self.g.out_edges(INTERNET, ["EXPOSES"]) if self.g.label_of(v) == "VirtualMachine"]
        for vm in exposed:
            for cve, _ in self.g.out_edges(vm, ["VULNERABLE_TO"]):
                status = self.g.get(cve, "exploitation_status")
                if status not in ("active", "mass_exploitation"):
                    continue
                rel = float(self.g.get(cve, "sector_targeting_relevance") or 0)
                if sector_only and rel < 0.7:
                    continue
                actors = [u for u, _ in self.g.in_edges(cve, ["EXPLOITS"]) if self.g.label_of(u) == "ThreatActor"]
                camps = [u for u, _ in self.g.in_edges(cve, ["EXPLOITS"]) if self.g.label_of(u) == "Campaign"]
                reach = self._blast_ids(vm, 5)
                jewels = [n for n in reach if self.g.get(n, "crown_jewel")]
                alerts = sorted({a for ep in [vm] + [u for u, _ in self.g.in_edges(vm, ["SAME_AS"])] for a in self._alerts_on(ep)})
                score = max([int(self.g.get(a, "contextual_score") or 0) for a in alerts] + [int(60 * float(self.g.get(vm, "ti_exposure_score") or 0.3)) + 10 * len(jewels)])
                rows.append({"vm": self.g.node_out(vm), "cve": self.g.node_out(cve), "exploitation_status": status, "actors": [self.g.node_out(a) for a in actors], "campaigns": [self.g.node_out(c) for c in camps], "sector_relevance": rel, "contextual_score": score, "crown_jewels_reachable": [self.g.node_out(j) for j in jewels], "has_edr_sensor": bool(self.g.get(vm, "has_edr_sensor")), "alert_ids": alerts})
        rows.sort(key=lambda r: -r["contextual_score"])
        return rows

    # -------------------------------------------------------------- typed investigations
    def credential_joins(self) -> dict[str, Any]:
        self.calls.append("credential_joins")
        items, ids = [], []
        for cred in self.g.nodes_by_label("Credential"):
            alerts = [v for v, _ in self.g.out_edges(cred, ["STOLEN_BY"]) if self.g.label_of(v) == "Alert"]
            events = sorted(u for u, _ in self.g.in_edges(cred, ["USED_CREDENTIAL"]))
            if not alerts or not events:
                continue
            derived = [u for u, _ in self.g.in_edges(cred, ["DERIVED_FROM"])]
            alert = self.alert_summary(alerts[0])
            endpoint = alert.entity_id
            principal = next((v for v, _ in self.g.out_edges(cred, ["CREDENTIAL_FOR"])), None)
            all_events = events + sorted(u for d in derived for u, _ in self.g.in_edges(d, ["USED_CREDENTIAL"]))
            items.append({"credential": self.g.node_out(cred, highlight=True), "stolen_by_alert": alert, "endpoint": self.g.node_out(endpoint) if endpoint else None, "principal": self.g.node_out(principal) if principal else None, "used_in_events": [self.g.node_out(e) for e in events], "derived_credentials": [self.g.node_out(d) for d in derived], "first_use": min(str(self.g.get(e, "event_time")) for e in events), "source_ips": sorted({str(self.g.get(e, "source_ip")) for e in all_events if self.g.get(e, "source_ip")})})
            ids += [cred, alerts[0], endpoint, principal] + events + derived
        frag = self.g.fragment([i for i in ids if i], highlight_ids=[i["credential"].id for i in items], focus=[i["credential"].id for i in items], layout_hint="path")
        return {"items": items, "fragment": frag}

    def alerts_reaching_crown_jewels(self, jewel_id: str | None = None, classification: str | None = None) -> dict[str, Any]:
        self.calls.append("alerts_reaching_crown_jewels")
        items, jewels = [], set()
        for aid in self._alert_ids():
            reach = self._blast_ids(aid, 5)
            hit = [n for n in reach if self.g.get(n, "crown_jewel")]
            if jewel_id:
                hit = [n for n in hit if n == jewel_id]
            if classification:
                hit = [n for n in hit if classification.upper() in [str(c).upper() for c in self.g.get(n, "data_classifications") or []]]
            if hit:
                items.append(self.alert_summary(aid))
                jewels.update(hit)
        items.sort(key=lambda a: -a.contextual_score)
        frag = self.g.fragment([a.id for a in items] + sorted(jewels), highlight_ids=sorted(jewels), focus=sorted(jewels), layout_hint="neighborhood")
        return {"items": items, "jewels": [self.g.node_out(j) for j in sorted(jewels)], "fragment": frag}

    def medium_alerts_with_data_path(self, severity: str = "medium", source: str | None = "falcon") -> dict[str, Any]:
        self.calls.append("medium_alerts_with_data_path")
        items = []
        for aid in self._alert_ids():
            a = self.alert_summary(aid)
            if a.vendor_severity != severity or (source and a.source_system != source):
                continue
            reach = self._blast_ids(aid, 5)
            if any(self.g.get(n, "crown_jewel") for n in reach):
                items.append(a)
        items.sort(key=lambda a: -a.contextual_score)
        ids = [a.id for a in items]
        for a in items[:3]:
            ids += list(self._blast_ids(a.id, 5))
        frag = self.g.fragment(ids, highlight_ids=[a.id for a in items], focus=[a.id for a in items[:1]], layout_hint="path")
        return {"items": items, "fragment": frag}

    def identity_footprint(self, identity_id: str) -> BlastRadiusResult:
        if self.g.label_of(identity_id) not in IDENTITY:
            raise KeyError(f"identity {identity_id!r} not found")
        return self.blast_radius(identity_id, depth=4)

    def simulate_containment(self, target_ids: list[str], actions: list[str]) -> ContainmentSimulation:
        self.calls.append("simulate_containment")
        targets = [t for t in target_ids if t in self.g]
        if not targets:
            raise KeyError(f"none of {target_ids} exist")
        vms = set()
        for t in targets:
            vms.add(t)
            for v, _ in self.g.out_edges(t, ["SAME_AS"]):
                vms.add(v)
        cut = [p for p in (PATH_A, PATH_B) if set(p) & vms]
        stories = []
        for p, sid in ((PATH_A, C.STORYLINE_A), (PATH_B, C.STORYLINE_B)):
            if set(p) & vms:
                stories.append(sid)
        protected = sorted({j for s in stories for j in self.g.get(s, "crown_jewels_reached") or []})
        breaks: list[BreakItem] = []
        for vm in vms:
            for app, _ in self.g.in_edges(vm, ["DEPENDS_ON"]):
                team = next((t for t, _ in self.g.out_edges(app, ["OWNED_BY"])), None)
                breaks.append(BreakItem(node_id=app, name=str(self.g.get(app, "name")), label="Application", impact=f"depends on {self.g.get(vm, 'name')} ({self.g.first_edge(app, vm, 'DEPENDS_ON') or {}}.get('dependency_type', 'dependency'))", owner_team_id=team))
            if self.g.label_of(vm) == "VirtualMachine" and "bastion" in str(self.g.get(vm, "tags") or ""):
                team = next((t for t, _ in self.g.out_edges(vm, ["OWNED_BY"])), None)
                breaks.append(BreakItem(node_id=vm, name=str(self.g.get(vm, "name")), label="VirtualMachine", impact="SSM/SSH access path for platform engineering", owner_team_id=team))
        residual, recs = [], []
        if "rotate_role_credentials" in actions:
            for t in targets:
                if self.g.label_of(t) == "IamRole":
                    for cred, _ in self.g.in_edges(t, ["CREDENTIAL_FOR"]):
                        for derived, _ in self.g.in_edges(cred, ["DERIVED_FROM"]):
                            residual.append(f"Rotating {t} invalidates {cred} but not the already-issued session credential {derived} (status {self.g.get(derived, 'status')}, expires {self.g.get(derived, 'expires_at')}).")
                    for r, _ in self.g.out_edges(t, ["CAN_ASSUME"]):
                        recs.append(f"Tighten the trust policy of {r} so only the intended principals can assume it.")
        if "isolate_endpoint" in actions:
            recs.append("Network-contain the endpoint via the EDR and keep forensics access.")
        recs.append("Notify owning teams of the dependent applications before executing.")
        frag = self.g.fragment(list(vms) + protected + [b.node_id for b in breaks], highlight_ids=list(vms), focus=list(vms), layout_hint="neighborhood")
        return ContainmentSimulation(target_ids=targets, actions=list(actions), paths_cut=len(cut), storylines_contained=stories, crown_jewels_protected=protected, breaks=breaks, residual_risks=residual, recommendations=recs, fragment=frag)

    def dashboard(self) -> dict[str, Any]:
        items, total = self.list_alerts(sort="contextual", limit=10)
        vendor, _ = self.list_alerts(sort="vendor", limit=10)
        bands: dict[str, int] = {b: 0 for b in ("critical", "high", "medium", "low", "noise")}
        sources: dict[str, int] = {s: 0 for s in ("falcon", "cspm", "waf", "ids", "cloud-anomaly", "okta")}
        for a in self.list_alerts(limit=500)[0]:
            bands[a.contextual_band] = bands.get(a.contextual_band, 0) + 1
            sources[a.source_system] = sources.get(a.source_system, 0) + 1
        vms = list(self.g.nodes_by_label("VirtualMachine"))
        with_sensor = [v for v in vms if self.g.get(v, "has_edr_sensor")]
        jewels = [n for lbl in ("StorageBucket", "Database", "Secret") for n in self.g.nodes_by_label(lbl) if self.g.get(n, "crown_jewel")]
        at_risk = sorted({j for s in self.g.nodes_by_label("Storyline") for j in self.g.get(s, "crown_jewels_reached") or []})
        return {
            "kpis": {"open_alerts": total, "critical_contextual": bands["critical"], "storylines": len(list(self.g.nodes_by_label("Storyline"))), "crown_jewels": len(jewels), "crown_jewels_at_risk": len(at_risk), "internet_exposed_exploited": len(self.ti_exposure()), "endpoints": len(list(self.g.nodes_by_label("Endpoint"))), "endpoint_coverage_pct": round(100 * len(with_sensor) / max(len(vms), 1), 1), "ioc_matches": len([1 for _ in self.g.G.edges(data=True) if _[2]["type"] == "MATCHES_IOC"])},
            "leaderboard_contextual": items, "leaderboard_vendor": vendor, "storylines": self.list_storylines(), "alerts_by_band": bands, "alerts_by_source": sources,
            "coverage": {"vms_total": len(vms), "vms_with_sensor": len(with_sensor), "vms_without_sensor_prod": len([v for v in vms if not self.g.get(v, "has_edr_sensor") and self.g.get(v, "environment") == "prod"]), "endpoints_total": len(list(self.g.nodes_by_label("Endpoint"))), "endpoints_resolved_to_vm": len([e for e in self.g.nodes_by_label("Endpoint") if self.g.out_edges(e, ["SAME_AS"])])},
            "ti_pressure": [{"actor_id": r["actor"].id, "actor_name": r["actor"].name, "sector_relevance": r["sector_relevance"], "campaigns": len(r["campaigns"]), "ioc_matches": r["ioc_matches"], "exploited_cves_present": r["exploited_cves_present"], "alerts": len(r["matched_alerts"])} for r in self.ti_actors()],
            "rerank_examples": [{"alert_id": a.id, "title": a.title, "vendor_severity": a.vendor_severity, "contextual_score": a.contextual_score, "vendor_rank_position": a.vendor_rank_position, "contextual_rank_position": a.contextual_rank_position} for a in items[:3]],
        }


def ids_in(seq: Sequence[Any]) -> set[str]:
    return {x.id if hasattr(x, "id") else x["id"] for x in seq}
