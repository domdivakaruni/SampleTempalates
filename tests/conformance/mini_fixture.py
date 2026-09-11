"""Generator for the committed ``data/fixtures/mini`` graph (about 60 nodes / 90 edges).

It mirrors the storyline core of docs/04-storyline.md section 2.2 with the exact ids from
``throughline.simulator.storyline_constants``: alert ldt-a009 on endpoint bas-01 -> SAME_AS the bastion VM ->
HAS_ROLE the bastion role -> CAN_ASSUME the prod reader role -> CAN_ACCESS the cardholder vault (PCI, crown jewel),
the KYC bucket, two secrets and (via the DB reader secret) the cardholder database; the credential join
(ASIA5LARKBASTION01Q7 stolen by ldt-a009, used by evt-a012; ASIA5LARKPRODREADER1 derived from it, used by
evt-a014); stmt-render-2a exposed to the internet and VULNERABLE_TO CVE-2021-44228 with the Hollow Tide /
SALTWORKS / BRACKISH chain; plus a couple of noise alerts and users.

Regenerate with ``python tests/conformance/mini_fixture.py data/fixtures/mini`` (deterministic: no wall-clock).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from throughline.simulator import storyline_constants as sc
from throughline.simulator.common import NOW, edge, node, ts, write_jsonl

INTERNET = "internet:global:internet"
PROCESS_CURL = "process:falcon:aid-bas01:4711:1757470305"
IP_EGRESS = f"ip:v4:{sc.ATTACKER_EGRESS_IP}"
IP_SALTWORKS = f"ip:v4:{sc.SALTWORKS_IP}"
TECH_IMDS = "technique:attack:T1552.005"
TECH_EXPLOIT = "technique:attack:T1190"
POLICY_SSM = "policy:aws:222222222222:AmazonSSMManagedInstanceCore"

T_A007 = sc.ALERT_A["a007"][1]
T_A009 = sc.ALERT_A["a009"][1]
T_A012 = sc.CLOUDEVENTS_A["a012"][1]
T_A014 = sc.CLOUDEVENTS_A["a014"][1]
T_B001 = sc.ALERT_B["b001"][1]
T_B002 = sc.ALERT_B["b002"][1]
T_N001 = sc.ALERT_N["n001"][1]
T_N002 = sc.ALERT_N["n002"][1]
INVENTORY_SEEN = "2025-11-02T10:00:00Z"
LAST = ts(NOW)


def _inv(id: str, label: str, name: str, props: dict[str, Any], source: str = "wiz-sim", **kw: Any) -> dict[str, Any]:
    return node(id, label, name, props, source=source, first_seen=kw.pop("first_seen", INVENTORY_SEEN), last_seen=kw.pop("last_seen", LAST), **kw)


def _alert(id: str, title: str, severity: str, detected: str, entity_id: str, entity_label: str, props: dict[str, Any]) -> dict[str, Any]:
    source_system = id.split(":")[1]
    base = {
        "source_system": source_system,
        "alert_type": {"falcon": "detection", "cspm": "issue", "waf": "network", "okta": "identity", "cloud-anomaly": "cloud"}[source_system],
        "title": title,
        "vendor_severity": severity,
        "vendor_severity_rank": {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[severity],
        "status": "new",
        "detected_at": detected,
        "entity_id": entity_id,
        "entity_label": entity_label,
        "raw": {"title": title, "severity": severity, "detected_at": detected},
    }
    base.update(props)
    return node(id, "Alert", title, base, source=f"{source_system}-sim", source_id=id.split(":")[-1], first_seen=detected, last_seen=detected)


def build_records() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    n, e = nodes.append, edges.append

    # ---------------------------------------------------------------- cloud accounts and compute
    prod, shared, dev = sc.ACCOUNTS["prod"], sc.ACCOUNTS["shared"], sc.ACCOUNTS["dev"]
    for acct in (prod, shared, dev):
        n(_inv(acct["id"], "CloudAccount", acct["name"], {"provider": acct["provider"], "account_id": acct["account_id"], "environment": acct["environment"], "purpose": acct["purpose"]}))
    n(_inv(sc.BASTION_VM, "VirtualMachine", sc.BASTION_NAME, {
        "provider": "aws", "account_id": shared["account_id"], "region": "us-east-1", "hostname": sc.BASTION_HOSTNAME,
        "private_ip": sc.BASTION_PRIVATE_IP, "public_ip": sc.BASTION_PUBLIC_IP, "os": "Amazon Linux 2023", "os_family": "linux",
        "instance_type": "t3.medium", "environment": "prod", "exposure": "internal", "has_edr_sensor": True, "is_k8s_node": False,
        "tags": {"role": "bastion", "owner": "platform-eng", "env": "prod"}, "criticality": "tier-1", "crown_jewel_reach": 3,
    }, source_id=sc.BASTION_INSTANCE_ID))
    n(_inv(sc.EDGE_VM, "VirtualMachine", sc.EDGE_NAME, {
        "provider": "aws", "account_id": prod["account_id"], "region": "us-east-1", "hostname": sc.EDGE_HOSTNAME,
        "private_ip": sc.EDGE_PRIVATE_IP, "public_ip": sc.EDGE_PUBLIC_IP, "os": "Ubuntu 22.04", "os_family": "linux",
        "instance_type": "c6i.large", "environment": "prod", "exposure": "internet", "has_edr_sensor": True, "is_k8s_node": False,
        "tags": {"role": "statement-render", "owner": "payments-platform", "env": "prod"}, "criticality": "tier-1", "ti_exposure_score": 0.92, "crown_jewel_reach": 1,
    }, source_id=sc.EDGE_INSTANCE_ID))
    n(_inv(sc.DEV_SANDBOX_VM, "VirtualMachine", sc.DEV_SANDBOX_NAME, {
        "provider": "aws", "account_id": dev["account_id"], "region": "us-west-2", "hostname": f"{sc.DEV_SANDBOX_NAME}.dev.larkspur.internal",
        "private_ip": "10.60.4.31", "public_ip": None, "os": "Ubuntu 22.04", "os_family": "linux", "instance_type": "t3.small",
        "environment": "dev", "exposure": "isolated", "has_edr_sensor": True, "is_k8s_node": False, "tags": {"env": "dev"}, "criticality": "tier-3", "crown_jewel_reach": 0,
    }))
    n(_inv(sc.EDGE_SG, "SecurityGroup", "sg-0edge-public-8080", {
        "provider": "aws", "account_id": prod["account_id"], "inbound_rules": [{"cidr": "0.0.0.0/0", "port_from": 8080, "port_to": 8080, "protocol": "tcp"}],
        "open_to_internet": True, "internet_ports": ["8080/tcp"],
    }))
    n(_inv(INTERNET, "Internet", "internet", {}, source="derived", confidence=1.0))

    # ---------------------------------------------------------------- data holders
    n(_inv(sc.CARDHOLDER_VAULT, "StorageBucket", "larkspur-cardholder-vault", {
        "provider": "aws", "account_id": prod["account_id"], "region": "us-east-1", "public": False, "encrypted": True, "versioning": True,
        "data_classifications": ["PCI"], "sensitivity": "critical", "crown_jewel": True, "size_gb": 4198.0, "environment": "prod",
    }))
    n(_inv(sc.KYC_DOCS, "StorageBucket", "larkspur-kyc-documents", {
        "provider": "aws", "account_id": prod["account_id"], "region": "us-east-1", "public": False, "encrypted": True, "versioning": True,
        "data_classifications": ["PII"], "sensitivity": "high", "crown_jewel": True, "size_gb": 812.5, "environment": "prod",
    }))
    n(_inv(sc.APP_CONFIG_BUCKET, "StorageBucket", "larkspur-prod-app-config", {
        "provider": "aws", "account_id": prod["account_id"], "region": "us-east-1", "public": False, "encrypted": True, "versioning": False,
        "data_classifications": ["SECRETS"], "sensitivity": "high", "crown_jewel": False, "size_gb": 0.4, "environment": "prod",
        "contains_credentials_for": [sc.CARDHOLDER_DB],
    }))
    n(_inv(sc.MARKETING_BUCKET, "StorageBucket", "larkspur-marketing-assets", {
        "provider": "aws", "account_id": sc.ACCOUNTS["corp"]["account_id"], "region": "us-east-1", "public": True, "encrypted": False, "versioning": False,
        "data_classifications": ["PUBLIC"], "sensitivity": "none", "crown_jewel": False, "size_gb": 12.0, "environment": "corp",
    }))
    n(_inv(sc.DB_READER_SECRET, "Secret", "prod/cardholder-db/reader", {
        "provider": "aws", "account_id": prod["account_id"], "secret_type": "db_credentials", "sensitivity": "critical", "rotated_days_ago": 41, "grants_access_to": [sc.CARDHOLDER_DB],
    }))
    n(_inv(sc.HSM_SECRET, "Secret", "prod/hsm/partner-signing-key", {
        "provider": "aws", "account_id": prod["account_id"], "secret_type": "signing_key", "sensitivity": "critical", "rotated_days_ago": 210, "grants_access_to": [],
    }))
    n(_inv(sc.CARDHOLDER_DB, "Database", "cardholder-db", {
        "provider": "aws", "account_id": prod["account_id"], "engine": "postgres", "public": False, "encrypted": True,
        "data_classifications": ["PCI"], "sensitivity": "critical", "crown_jewel": True, "environment": "prod", "exposure": "internal",
    }))

    # ---------------------------------------------------------------- identity
    n(_inv(sc.BASTION_ROLE, "IamRole", "LarkspurBastionSSMRole", {
        "provider": "aws", "account_id": shared["account_id"], "arn": sc.BASTION_ROLE_ARN, "role_type": "instance", "is_admin": False,
        "privilege_score": 0.55, "trust_principals": ["ec2.amazonaws.com"], "last_used": T_A012, "environment": "prod",
    }))
    n(_inv(sc.PROD_READER_ROLE, "IamRole", "LarkspurProdDataReader", {
        "provider": "aws", "account_id": prod["account_id"], "arn": sc.PROD_READER_ROLE_ARN, "role_type": "cross-account", "is_admin": False,
        "privilege_score": 0.8, "trust_principals": [sc.BASTION_ROLE_ARN], "last_used": T_A014, "environment": "prod",
    }))
    n(_inv(sc.EDGE_ROLE, "IamRole", "LarkspurStmtRenderRole", {
        "provider": "aws", "account_id": prod["account_id"], "arn": sc.EDGE_ROLE_ARN, "role_type": "instance", "is_admin": False,
        "privilege_score": 0.35, "trust_principals": ["ec2.amazonaws.com"], "last_used": "2026-09-11T13:40:00Z", "environment": "prod",
    }))
    n(_inv(sc.BASTION_ASSUME_POLICY, "IamPolicy", "LarkspurBastionAssumeProdReader", {
        "provider": "aws", "account_id": shared["account_id"], "managed": False,
        "statements": [{"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": [sc.PROD_READER_ROLE_ARN]}],
        "access_levels": ["admin"], "wildcard_resource": False, "wildcard_action": False,
    }))
    n(_inv(POLICY_SSM, "IamPolicy", "AmazonSSMManagedInstanceCore", {
        "provider": "aws", "account_id": shared["account_id"], "managed": True,
        "statements": [{"Effect": "Allow", "Action": ["ssm:*"], "Resource": "*"}], "access_levels": ["read", "write"], "wildcard_resource": True, "wildcard_action": False,
    }))
    n(_inv(sc.PROD_READER_POLICY, "IamPolicy", "LarkspurProdDataReaderAccess", {
        "provider": "aws", "account_id": prod["account_id"], "managed": False,
        "statements": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "secretsmanager:GetSecretValue"], "Resource": ["arn:aws:s3:::larkspur-cardholder-vault/*", "arn:aws:s3:::larkspur-kyc-documents/*"]}],
        "access_levels": ["read", "list"], "wildcard_resource": False, "wildcard_action": False,
    }))
    n(_inv(sc.USER_DANA, "HumanUser", "Dana Whitfield", {
        "email": f"dwhitfield@{sc.CORP_DOMAIN}", "display_name": "Dana Whitfield", "title": "Treasury Operations Analyst", "department": "Finance",
        "team_id": sc.TEAM_TREASURY, "location": "Boston", "is_privileged": False, "is_executive": False, "mfa_enabled": True, "status": "active",
    }, source="okta-sim", source_id="dwhitfield"))
    n(_inv(sc.USER_MREYES, "HumanUser", "Marcus Reyes", {
        "email": f"mreyes@{sc.CORP_DOMAIN}", "display_name": "Marcus Reyes", "title": "IT Systems Administrator", "department": "Corp IT",
        "team_id": sc.TEAM_CORP_IT, "location": "Austin", "is_privileged": True, "is_executive": False, "mfa_enabled": True, "status": "active",
    }, source="okta-sim", source_id="mreyes"))
    n(_inv(sc.USER_PKAUR, "HumanUser", "Priya Kaur", {
        "email": f"pkaur@{sc.CORP_DOMAIN}", "display_name": "Priya Kaur", "title": "Chief Financial Officer", "department": "Executive",
        "team_id": sc.TEAM_TREASURY, "location": "New York", "is_privileged": False, "is_executive": True, "mfa_enabled": True, "status": "active",
    }, source="okta-sim", source_id="pkaur"))
    n(_inv(sc.SVC_FINOPS_SFTP, "ServiceAccount", "svc-finops-sftp", {"system": "linux", "host_id": sc.BASTION_VM, "purpose": "settlement-file SFTP", "privileged": False}, source="falcon-sim"))
    n(node(sc.CRED_BASTION_KEY, "Credential", sc.CRED_BASTION_KEY_ID, {
        "credential_type": "aws_temporary_key", "principal_id": sc.BASTION_ROLE, "issued_at": T_A009, "expires_at": "2026-09-10T08:11:00Z", "status": "expired",
    }, source="falcon-sim", source_id=sc.CRED_BASTION_KEY_ID, first_seen=T_A009, last_seen=T_A012))
    n(node(sc.CRED_PROD_KEY, "Credential", sc.CRED_PROD_KEY_ID, {
        "credential_type": "aws_temporary_key", "principal_id": sc.PROD_READER_ROLE, "issued_at": T_A012, "expires_at": "2026-09-10T03:24:15Z", "status": "expired", "derived_from": sc.CRED_BASTION_KEY,
    }, source="cloudtrail-sim", source_id=sc.CRED_PROD_KEY_ID, first_seen=T_A012, last_seen=T_A014))

    # ---------------------------------------------------------------- software, business
    n(_inv(sc.EDGE_LOG4J_PACKAGE, "Package", "log4j-core 2.14.1", {"package_name": "log4j-core", "version": "2.14.1", "ecosystem": "maven", "scope": sc.EDGE_VM}))
    n(_inv(sc.LOG4SHELL, "Vulnerability", "CVE-2021-44228", {
        "cve_id": "CVE-2021-44228", "cvss": 10.0, "epss": 0.97, "kev": True, "severity": "critical", "published": "2021-12-10T00:00:00Z",
        "exploitation_status": "mass_exploitation", "actor_interest": [sc.ACTOR_HT], "sector_targeting_relevance": 0.8, "ti_report_ids": [sc.REPORT_SALTWORKS],
        "synthetic": False, "description": "Apache Log4j2 JNDI remote code execution (Log4Shell).", "affected_component": "log4j-core",
    }, source="ti-sim", source_id="CVE-2021-44228", first_seen="2021-12-10T00:00:00Z"))
    n(_inv(sc.APP_CARD_ISSUING, "Application", "card-issuing", {"criticality": "tier-0", "environment": "prod", "owner_team_id": sc.TEAM_PAYMENTS, "description": "Card issuing and cardholder data", "data_classifications": ["PCI", "PII"]}, source="business-sim"))
    n(_inv(sc.APP_STMT_RENDER, "Application", "statement-render", {"criticality": "tier-1", "environment": "prod", "owner_team_id": sc.TEAM_PAYMENTS, "description": "Monthly statement rendering", "data_classifications": ["PII"]}, source="business-sim"))
    n(_inv(sc.TEAM_PLATFORM, "Team", "platform-eng", {"department": "Engineering", "lead_user_id": sc.USER_JOKAFOR, "oncall_channel": "#oncall-platform"}, source="business-sim"))
    n(_inv(sc.TEAM_PAYMENTS, "Team", "payments-platform", {"department": "Engineering", "lead_user_id": sc.USER_LCHEN, "oncall_channel": "#oncall-payments"}, source="business-sim"))

    # ---------------------------------------------------------------- endpoints and telemetry
    n(_inv(sc.EP_BASTION, "Endpoint", "bas-01", {
        "hostname": "bas-01", "device_type": "server", "os": "Amazon Linux 2023", "os_family": "linux", "private_ip": sc.BASTION_PRIVATE_IP, "public_ip": sc.BASTION_PUBLIC_IP,
        "site": "aws us-east-1", "sensor_version": "7.18", "last_seen_sensor": LAST, "cloud_provider": "aws", "cloud_instance_id": sc.BASTION_INSTANCE_ID,
        "cloud_account_id": shared["account_id"], "containment_status": "normal",
    }, source="falcon-sim", source_id="aid-bas01"))
    n(_inv(sc.EP_EDGE, "Endpoint", "stmt-render-2a", {
        "hostname": "stmt-render-2a", "device_type": "server", "os": "Ubuntu 22.04", "os_family": "linux", "private_ip": sc.EDGE_PRIVATE_IP, "public_ip": sc.EDGE_PUBLIC_IP,
        "site": "aws us-east-1", "sensor_version": "7.18", "last_seen_sensor": LAST, "cloud_provider": "aws", "cloud_instance_id": sc.EDGE_INSTANCE_ID,
        "cloud_account_id": prod["account_id"], "containment_status": "normal",
    }, source="falcon-sim", source_id="aid-edge2a"))
    n(_inv(sc.WKS_DANA, "Endpoint", sc.WKS_DANA_HOSTNAME, {
        "hostname": sc.WKS_DANA_HOSTNAME, "device_type": "workstation", "os": "Windows 11", "os_family": "windows", "private_ip": sc.WKS_DANA_IP,
        "site": "Boston office", "sensor_version": "7.18", "last_seen_sensor": LAST, "primary_user_id": sc.USER_DANA, "containment_status": "normal", "ou": "OU=Finance,DC=corp",
    }, source="falcon-sim", source_id="aid-wks3391"))
    n(_inv(sc.EP_DEV_SANDBOX, "Endpoint", sc.DEV_SANDBOX_NAME, {
        "hostname": sc.DEV_SANDBOX_NAME, "device_type": "server", "os": "Ubuntu 22.04", "os_family": "linux", "private_ip": "10.60.4.31",
        "site": "aws us-west-2", "sensor_version": "7.18", "last_seen_sensor": LAST, "cloud_provider": "aws", "cloud_instance_id": "i-0dev7c1a2b3c4d5e6f",
        "cloud_account_id": dev["account_id"], "containment_status": "normal",
    }, source="falcon-sim", source_id="aid-devrun03"))
    n(node(PROCESS_CURL, "Process", "curl", {
        "endpoint_id": sc.EP_BASTION, "pid": 4711, "image_path": "/usr/bin/curl",
        "command_line": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole",
        "user": "svc-finops-sftp", "signed": True, "start_time": T_A009, "integrity_level": "user",
    }, source="falcon-sim", source_id="4711", first_seen=T_A009, last_seen=T_A009))
    n(node(IP_EGRESS, "IpAddress", sc.ATTACKER_EGRESS_IP, {"address": sc.ATTACKER_EGRESS_IP, "is_private": False, "asn": sc.ATTACKER_ASN, "asn_org": sc.ATTACKER_ASN_ORG, "country": "NL", "reputation": "malicious"}, source="cloudtrail-sim", first_seen=sc.CLOUDEVENTS_A["a010"][1], last_seen=T_A014))
    n(node(IP_SALTWORKS, "IpAddress", sc.SALTWORKS_IP, {"address": sc.SALTWORKS_IP, "is_private": False, "asn": "AS64511", "asn_org": "Brinewater Networks (fictional)", "country": "RO", "reputation": "malicious"}, source="waf-sim", first_seen=T_B001, last_seen=T_B002))

    # ---------------------------------------------------------------- alerts, events, incidents
    n(_alert(sc.ALERT_A["a007"][0], "Interactive SSH session from user workstation to bastion outside business hours", "medium", T_A007, sc.EP_BASTION, "Endpoint", {
        "techniques": ["T1021.004", "T1078"], "tactic": "lateral-movement", "hostname": "bas-01", "user": "svc-finops-sftp", "vendor_incident_id": "inc-0094",
        "contextual_score": 91, "contextual_band": "critical", "storyline_id": sc.STORYLINE_A, "graph_reasons": ["lateral movement", "reaches PCI"], "ti_actor_ids": [sc.ACTOR_CJ],
        "ioc_match_count": 0, "reaches_crown_jewel": True, "on_attack_path": True,
    }))
    n(_alert(sc.ALERT_A["a009"][0], "Cloud instance metadata service credential access from interactive shell", "medium", T_A009, sc.EP_BASTION, "Endpoint", {
        "techniques": ["T1552.005"], "tactic": "credential-access", "hostname": "bas-01", "user": "svc-finops-sftp", "vendor_incident_id": "inc-0094",
        "contextual_score": 96, "contextual_band": "critical", "storyline_id": sc.STORYLINE_A, "graph_reasons": ["credential stolen", "reaches PCI", "active TI"],
        "ti_actor_ids": [sc.ACTOR_CJ], "ioc_match_count": 1, "reaches_crown_jewel": True, "on_attack_path": True,
        "score_breakdown": {"S": 0.5, "E": 0.3, "P": 0.8, "D": 1.0, "T": 0.9, "C": 1.0},
    }))
    n(_alert(sc.ALERT_B["b001"][0], "JNDI injection pattern in request header", "medium", T_B001, sc.EDGE_VM, "VirtualMachine", {
        "techniques": ["T1190"], "tactic": "initial-access", "hostname": sc.EDGE_NAME, "contextual_score": 82, "contextual_band": "high", "storyline_id": sc.STORYLINE_B,
        "graph_reasons": ["internet exposed", "mass exploitation"], "ti_actor_ids": [sc.ACTOR_HT], "ioc_match_count": 1, "reaches_crown_jewel": False, "on_attack_path": True,
    }))
    n(_alert(sc.ALERT_B["b002"][0], "Shell spawned by Java application server process", "medium", T_B002, sc.EP_EDGE, "Endpoint", {
        "techniques": ["T1190", "T1059.004"], "tactic": "execution", "hostname": sc.EDGE_NAME, "user": "statement-render", "vendor_incident_id": "inc-0096",
        "contextual_score": 85, "contextual_band": "high", "storyline_id": sc.STORYLINE_B, "graph_reasons": ["internet exposed", "mass exploitation", "IOC match"],
        "ti_actor_ids": [sc.ACTOR_HT], "ioc_match_count": 1, "reaches_crown_jewel": False, "on_attack_path": True,
    }))
    n(_alert(sc.ALERT_N["n001"][0], "EICAR test file detected and quarantined", "high", T_N001, sc.EP_DEV_SANDBOX, "Endpoint", {
        "techniques": [], "hostname": sc.DEV_SANDBOX_NAME, "contextual_score": 12, "contextual_band": "noise", "graph_reasons": ["isolated dev VM", "no data path"],
        "ti_actor_ids": [], "ioc_match_count": 0, "reaches_crown_jewel": False, "on_attack_path": False,
    }))
    n(_alert(sc.ALERT_N["n002"][0], "S3 bucket allows public read", "critical", T_N002, sc.MARKETING_BUCKET, "StorageBucket", {
        "techniques": [], "contextual_score": 18, "contextual_band": "noise", "graph_reasons": ["public marketing assets"], "ti_actor_ids": [], "ioc_match_count": 0,
        "reaches_crown_jewel": False, "on_attack_path": False,
    }))
    a012 = sc.CLOUDEVENTS_A["a012"]
    a014 = sc.CLOUDEVENTS_A["a014"]
    n(node(a012[0], "CloudEvent", "AssumeRole LarkspurProdDataReader", {
        "provider": "aws", "account_id": prod["account_id"], "event_name": a012[2], "event_source": a012[3], "event_time": a012[1], "principal_id": sc.BASTION_ROLE,
        "principal_arn": sc.BASTION_ROLE_ARN, "access_key_id": a012[4], "source_ip": sc.ATTACKER_EGRESS_IP, "user_agent": "aws-cli/2.17.0", "success": True,
        "target_id": sc.PROD_READER_ROLE, "count": 1, "anomalous": True, "anomaly_reasons": ["instance role used from outside AWS", "new ASN"],
    }, source="cloudtrail-sim", source_id="evt-a012", first_seen=a012[1], last_seen=a012[1]))
    n(node(a014[0], "CloudEvent", "GetObject larkspur-cardholder-vault x1247", {
        "provider": "aws", "account_id": prod["account_id"], "event_name": a014[2], "event_source": a014[3], "event_time": a014[1], "principal_id": sc.PROD_READER_ROLE,
        "principal_arn": sc.PROD_READER_ROLE_ARN, "access_key_id": a014[4], "source_ip": sc.ATTACKER_EGRESS_IP, "user_agent": "aws-cli/2.17.0", "success": True,
        "target_id": sc.CARDHOLDER_VAULT, "count": a014[7], "bytes": sc.EXFIL_BYTES, "anomalous": True, "anomaly_reasons": ["bulk read", "new ASN"],
    }, source="cloudtrail-sim", source_id="evt-a014", first_seen=a014[1], last_seen="2026-09-10T03:40:00Z"))
    n(node(sc.INCIDENT_BASTION, "Incident", "inc-0094", {"vendor_severity": "medium", "status": "open", "start_time": T_A007, "end_time": T_A009, "alert_count": 3, "hosts": ["bas-01"], "description": "Suspicious activity on bas-01"}, source="falcon-sim", source_id="inc-0094", first_seen=T_A007, last_seen=T_A009))

    # ---------------------------------------------------------------- threat intel
    n(_inv(sc.ACTOR_HT, "ThreatActor", "Hollow Tide", {"aliases": ["HOLLOW TIDE", "TideBroker"], "motivation": "access-broker", "origin": "unknown", "sophistication": "medium", "targeted_sectors": ["financial-services", "technology"], "targeted_regions": ["NA", "EU"], "sector_targeting_relevance": 0.8, "active": True, "description": "Access broker mass-exploiting internet-facing Java services."}, source="ti-sim", first_seen="2026-08-20T00:00:00Z"))
    n(_inv(sc.ACTOR_CJ, "ThreatActor", "Cinder Jackal", {"aliases": ["CINDER JACKAL"], "motivation": "financial", "origin": "unknown", "sophistication": "high", "targeted_sectors": ["financial-services"], "targeted_regions": ["NA", "EU"], "sector_targeting_relevance": 0.9, "active": True, "description": "eCrime actor pivoting through bastion hosts into fintech cloud estates."}, source="ti-sim", first_seen="2026-07-01T00:00:00Z"))
    n(_inv(sc.CAMPAIGN_SALTWORKS, "Campaign", "SALTWORKS", {"actor_id": sc.ACTOR_HT, "status": "active", "started": "2026-08-20T00:00:00Z", "objective": "sell access", "targeted_sectors": ["financial-services"], "sector_targeting_relevance": 0.8, "description": "Mass exploitation of CVE-2021-44228 dropping the BRACKISH webshell."}, source="ti-sim", first_seen="2026-08-20T00:00:00Z"))
    n(_inv(sc.CAMPAIGN_EMBERCAST, "Campaign", "EMBERCAST", {"actor_id": sc.ACTOR_CJ, "status": "active", "started": "2026-07-01T00:00:00Z", "objective": "cardholder data theft", "targeted_sectors": ["financial-services"], "sector_targeting_relevance": 0.9, "description": "Bastion-host pivoting against fintech cloud estates."}, source="ti-sim", first_seen="2026-07-01T00:00:00Z"))
    n(_inv(sc.MALWARE_BRACKISH, "Malware", "BRACKISH", {"family": "brackish", "malware_type": "webshell", "platforms": ["linux"], "description": "JSP webshell dropped after Log4Shell exploitation."}, source="ti-sim", first_seen="2026-08-20T00:00:00Z"))
    n(node(sc.IOC_SALTWORKS_IP, "Indicator", sc.SALTWORKS_IP, {"ioc_type": "ipv4", "value": sc.SALTWORKS_IP, "report_id": sc.REPORT_SALTWORKS, "actor_id": sc.ACTOR_HT, "campaign_id": sc.CAMPAIGN_SALTWORKS, "malware_id": sc.MALWARE_BRACKISH, "kill_chain_stage": 1, "active": True}, source="ti-sim", first_seen="2026-08-22T00:00:00Z", last_seen="2026-09-08T00:00:00Z", confidence=0.8))
    n(node(sc.IOC_EGRESS_IP, "Indicator", sc.ATTACKER_EGRESS_IP, {"ioc_type": "ipv4", "value": sc.ATTACKER_EGRESS_IP, "report_id": sc.REPORT_EMBERCAST, "actor_id": sc.ACTOR_CJ, "campaign_id": sc.CAMPAIGN_EMBERCAST, "kill_chain_stage": 6, "active": True}, source="ti-sim", first_seen="2026-08-15T00:00:00Z", last_seen="2026-09-02T00:00:00Z", confidence=0.85))
    n(_inv(sc.REPORT_SALTWORKS, "IntelReport", "SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services", {
        "title": "SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services", "published": "2026-09-08T00:00:00Z", "publisher": "Throughline Labs",
        "report_confidence": "medium-high", "tlp": "amber", "summary": "Mass scanning and exploitation of CVE-2021-44228 against financial-services companies.",
        "actor_ids": [sc.ACTOR_HT], "campaign_ids": [sc.CAMPAIGN_SALTWORKS], "cve_ids": ["CVE-2021-44228"], "technique_ids": ["T1190", "T1505.003"], "indicator_count": 3,
        "targeted_sectors": ["financial-services"], "body": "Fictional narrative for the demo.",
    }, source="ti-sim", source_id="TL-2026-0147", first_seen="2026-09-08T00:00:00Z"))
    n(_inv(TECH_IMDS, "AttackTechnique", "Cloud Instance Metadata API", {"technique_id": "T1552.005", "tactic": "credential-access", "kill_chain_stage": 5, "description": "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials."}, source="ti-sim", source_id="T1552.005"))
    n(_inv(TECH_EXPLOIT, "AttackTechnique", "Exploit Public-Facing Application", {"technique_id": "T1190", "tactic": "initial-access", "kill_chain_stage": 2, "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host."}, source="ti-sim", source_id="T1190"))

    # ================================================================ edges
    def inv_edge(t: str, s: str, d: str, props: dict[str, Any] | None = None, source: str = "wiz-sim", **kw: Any) -> None:
        e(edge(t, s, d, props, source=source, first_seen=kw.pop("first_seen", INVENTORY_SEEN), last_seen=kw.pop("last_seen", LAST), **kw))

    for target in (sc.BASTION_VM, sc.BASTION_ROLE, sc.BASTION_ASSUME_POLICY, POLICY_SSM):
        inv_edge("CONTAINS", shared["id"], target)
    for target in (sc.EDGE_VM, sc.EDGE_ROLE, sc.PROD_READER_ROLE, sc.PROD_READER_POLICY, sc.CARDHOLDER_VAULT, sc.KYC_DOCS, sc.APP_CONFIG_BUCKET, sc.DB_READER_SECRET, sc.HSM_SECRET, sc.CARDHOLDER_DB):
        inv_edge("CONTAINS", prod["id"], target)
    inv_edge("CONTAINS", dev["id"], sc.DEV_SANDBOX_VM)
    inv_edge("HAS_SECURITY_GROUP", sc.EDGE_VM, sc.EDGE_SG)
    inv_edge("EXPOSES", INTERNET, sc.EDGE_VM, {"ports": ["8080/tcp"], "via": "security_group", "protocol": "tcp"}, source="derived")
    inv_edge("HAS_PACKAGE", sc.EDGE_VM, sc.EDGE_LOG4J_PACKAGE)
    inv_edge("HAS_VULNERABILITY", sc.EDGE_LOG4J_PACKAGE, sc.LOG4SHELL, {"fixed_version": "2.17.1"})
    inv_edge("VULNERABLE_TO", sc.EDGE_VM, sc.LOG4SHELL, {"via_package": sc.EDGE_LOG4J_PACKAGE, "exploitable": True}, source="derived")
    inv_edge("HAS_ROLE", sc.BASTION_VM, sc.BASTION_ROLE, {"via": "instance_profile"})
    inv_edge("HAS_ROLE", sc.EDGE_VM, sc.EDGE_ROLE, {"via": "instance_profile"})
    inv_edge("HAS_POLICY", sc.BASTION_ROLE, sc.BASTION_ASSUME_POLICY, {"attachment": "inline"})
    inv_edge("HAS_POLICY", sc.BASTION_ROLE, POLICY_SSM, {"attachment": "managed"})
    inv_edge("HAS_POLICY", sc.PROD_READER_ROLE, sc.PROD_READER_POLICY, {"attachment": "inline"})
    inv_edge("GRANTS", sc.BASTION_ASSUME_POLICY, sc.PROD_READER_ROLE, {"actions": ["sts:AssumeRole"], "access_level": "admin", "resource_pattern": sc.PROD_READER_ROLE_ARN})
    for target in (sc.CARDHOLDER_VAULT, sc.KYC_DOCS):
        inv_edge("GRANTS", sc.PROD_READER_POLICY, target, {"actions": ["s3:GetObject", "s3:ListBucket"], "access_level": "read", "resource_pattern": f"arn:aws:s3:::{target.split(':')[-1]}/*"})
    for target in (sc.DB_READER_SECRET, sc.HSM_SECRET):
        inv_edge("GRANTS", sc.PROD_READER_POLICY, target, {"actions": ["secretsmanager:GetSecretValue"], "access_level": "read", "resource_pattern": target.split(":", 3)[-1]})
    inv_edge("CAN_ASSUME", sc.BASTION_ROLE, sc.PROD_READER_ROLE, {"via": "trust_policy", "cross_account": True})
    for target in (sc.CARDHOLDER_VAULT, sc.KYC_DOCS, sc.DB_READER_SECRET, sc.HSM_SECRET):
        inv_edge("CAN_ACCESS", sc.PROD_READER_ROLE, target, {"access_level": "read", "path_length": 1, "via": sc.PROD_READER_POLICY, "transitive": False}, source="derived")
    for target in (sc.CARDHOLDER_VAULT, sc.KYC_DOCS):
        inv_edge("CAN_ACCESS", sc.BASTION_ROLE, target, {"access_level": "read", "path_length": 2, "via": f"{sc.PROD_READER_ROLE},{sc.PROD_READER_POLICY}", "transitive": True}, source="derived", confidence=0.9)
    inv_edge("CAN_ACCESS", sc.EDGE_ROLE, sc.APP_CONFIG_BUCKET, {"access_level": "read", "path_length": 1, "via": sc.EDGE_POLICY, "transitive": False}, source="derived")
    inv_edge("UNLOCKS", sc.DB_READER_SECRET, sc.CARDHOLDER_DB, {"credential_type": "db_credentials"})
    e(edge("CREDENTIAL_FOR", sc.CRED_BASTION_KEY, sc.BASTION_ROLE, source="falcon-sim", first_seen=T_A009, last_seen=T_A012))
    e(edge("CREDENTIAL_FOR", sc.CRED_PROD_KEY, sc.PROD_READER_ROLE, source="cloudtrail-sim", first_seen=T_A012, last_seen=T_A014))
    e(edge("DERIVED_FROM", sc.CRED_PROD_KEY, sc.CRED_BASTION_KEY, {"via": "assume_role"}, source="derived", first_seen=T_A012, last_seen=T_A014))
    inv_edge("PART_OF", sc.CARDHOLDER_VAULT, sc.APP_CARD_ISSUING, source="business-sim")
    inv_edge("PART_OF", sc.CARDHOLDER_DB, sc.APP_CARD_ISSUING, source="business-sim")
    inv_edge("PART_OF", sc.EDGE_VM, sc.APP_STMT_RENDER, source="business-sim")
    inv_edge("OWNED_BY", sc.APP_CARD_ISSUING, sc.TEAM_PAYMENTS, source="business-sim")
    inv_edge("OWNED_BY", sc.APP_STMT_RENDER, sc.TEAM_PAYMENTS, source="business-sim")
    inv_edge("OWNED_BY", sc.BASTION_VM, sc.TEAM_PLATFORM, source="business-sim")
    inv_edge("SAME_AS", sc.EP_BASTION, sc.BASTION_VM, {"method": "instance_id"}, source="derived", confidence=0.99)
    inv_edge("SAME_AS", sc.EP_EDGE, sc.EDGE_VM, {"method": "instance_id"}, source="derived", confidence=0.99)
    inv_edge("SAME_AS", sc.EP_DEV_SANDBOX, sc.DEV_SANDBOX_VM, {"method": "instance_id"}, source="derived", confidence=0.99)
    inv_edge("PRIMARY_USER", sc.WKS_DANA, sc.USER_DANA, source="falcon-sim")
    e(edge("LATERAL_MOVEMENT_TO", sc.WKS_DANA, sc.EP_BASTION, {"protocol": "ssh", "account": "svc-finops-sftp", "time": T_A007, "alert_id": sc.ALERT_A["a007"][0]}, source="derived", first_seen=T_A007, last_seen=T_A007, confidence=0.9))
    e(edge("RAN_ON", PROCESS_CURL, sc.EP_BASTION, source="falcon-sim", first_seen=T_A009, last_seen=T_A009))
    e(edge("RAN_AS", PROCESS_CURL, sc.SVC_FINOPS_SFTP, source="falcon-sim", first_seen=T_A009, last_seen=T_A009))
    e(edge("ACCESSED_CREDENTIAL", PROCESS_CURL, sc.CRED_BASTION_KEY, {"method": "imds"}, source="falcon-sim", first_seen=T_A009, last_seen=T_A009))
    for alert_id, ep, when in ((sc.ALERT_A["a009"][0], sc.EP_BASTION, T_A009), (sc.ALERT_A["a007"][0], sc.EP_BASTION, T_A007), (sc.ALERT_B["b002"][0], sc.EP_EDGE, T_B002), (sc.ALERT_N["n001"][0], sc.EP_DEV_SANDBOX, T_N001)):
        e(edge("ON_ENDPOINT", alert_id, ep, source="falcon-sim", first_seen=when, last_seen=when))
    e(edge("ON_RESOURCE", sc.ALERT_B["b001"][0], sc.EDGE_VM, source="waf-sim", first_seen=T_B001, last_seen=T_B001))
    e(edge("ON_RESOURCE", sc.ALERT_N["n002"][0], sc.MARKETING_BUCKET, source="cspm-sim", first_seen=T_N002, last_seen=T_N002))
    e(edge("INVOLVES", sc.ALERT_A["a009"][0], PROCESS_CURL, {"role": "subject"}, source="falcon-sim", first_seen=T_A009, last_seen=T_A009))
    e(edge("INVOLVES", sc.ALERT_A["a009"][0], sc.CRED_BASTION_KEY, {"role": "credential"}, source="falcon-sim", first_seen=T_A009, last_seen=T_A009))
    e(edge("INVOLVES", sc.ALERT_B["b002"][0], IP_SALTWORKS, {"role": "destination"}, source="falcon-sim", first_seen=T_B002, last_seen=T_B002))
    e(edge("INVOLVES", sc.ALERT_B["b001"][0], IP_SALTWORKS, {"role": "source"}, source="waf-sim", first_seen=T_B001, last_seen=T_B001))
    e(edge("USES_TECHNIQUE", sc.ALERT_A["a009"][0], TECH_IMDS, source="falcon-sim", first_seen=T_A009, last_seen=T_A009))
    e(edge("USES_TECHNIQUE", sc.ALERT_B["b002"][0], TECH_EXPLOIT, source="falcon-sim", first_seen=T_B002, last_seen=T_B002))
    inv_edge("USES_TECHNIQUE", sc.ACTOR_HT, TECH_EXPLOIT, source="ti-sim")
    inv_edge("USES_TECHNIQUE", sc.CAMPAIGN_SALTWORKS, TECH_EXPLOIT, source="ti-sim")
    e(edge("PART_OF_INCIDENT", sc.ALERT_A["a009"][0], sc.INCIDENT_BASTION, source="falcon-sim", first_seen=T_A009, last_seen=T_A009))
    e(edge("PART_OF_INCIDENT", sc.ALERT_A["a007"][0], sc.INCIDENT_BASTION, source="falcon-sim", first_seen=T_A007, last_seen=T_A007))
    e(edge("STOLEN_BY", sc.CRED_BASTION_KEY, sc.ALERT_A["a009"][0], {"method": "imds"}, source="derived", first_seen=T_A009, last_seen=T_A009))
    e(edge("USED_CREDENTIAL", a012[0], sc.CRED_BASTION_KEY, source="cloudtrail-sim", first_seen=a012[1], last_seen=a012[1]))
    e(edge("USED_CREDENTIAL", a014[0], sc.CRED_PROD_KEY, source="cloudtrail-sim", first_seen=a014[1], last_seen=a014[1]))
    e(edge("PERFORMED_BY", a012[0], sc.BASTION_ROLE, source="cloudtrail-sim", first_seen=a012[1], last_seen=a012[1]))
    e(edge("PERFORMED_BY", a014[0], sc.PROD_READER_ROLE, source="cloudtrail-sim", first_seen=a014[1], last_seen=a014[1]))
    e(edge("TARGETED", a014[0], sc.CARDHOLDER_VAULT, source="cloudtrail-sim", first_seen=a014[1], last_seen=a014[1]))
    e(edge("FROM_IP", a012[0], IP_EGRESS, source="cloudtrail-sim", first_seen=a012[1], last_seen=a012[1]))
    e(edge("FROM_IP", a014[0], IP_EGRESS, source="cloudtrail-sim", first_seen=a014[1], last_seen=a014[1]))
    e(edge("ASSUMED", a012[0], sc.PROD_READER_ROLE, source="cloudtrail-sim", first_seen=a012[1], last_seen=a012[1]))
    e(edge("NEXT_STAGE", sc.ALERT_A["a007"][0], sc.ALERT_A["a009"][0], {"storyline_id": sc.STORYLINE_A, "stage": 5}, source="derived", first_seen=T_A009, last_seen=T_A009))
    e(edge("NEXT_STAGE", sc.ALERT_A["a009"][0], a012[0], {"storyline_id": sc.STORYLINE_A, "stage": 6}, source="derived", first_seen=a012[1], last_seen=a012[1]))
    e(edge("NEXT_STAGE", a012[0], a014[0], {"storyline_id": sc.STORYLINE_A, "stage": 7}, source="derived", first_seen=a014[1], last_seen=a014[1]))
    inv_edge("ATTRIBUTED_TO", sc.CAMPAIGN_SALTWORKS, sc.ACTOR_HT, {"basis": "report"}, source="ti-sim")
    inv_edge("ATTRIBUTED_TO", sc.CAMPAIGN_EMBERCAST, sc.ACTOR_CJ, {"basis": "report"}, source="ti-sim")
    e(edge("ATTRIBUTED_TO", sc.ALERT_B["b002"][0], sc.CAMPAIGN_SALTWORKS, {"basis": "ioc"}, source="derived", first_seen=T_B002, last_seen=T_B002, confidence=0.8))
    inv_edge("USES_MALWARE", sc.ACTOR_HT, sc.MALWARE_BRACKISH, source="ti-sim")
    inv_edge("USES_MALWARE", sc.CAMPAIGN_SALTWORKS, sc.MALWARE_BRACKISH, source="ti-sim")
    inv_edge("INDICATES", sc.IOC_SALTWORKS_IP, sc.CAMPAIGN_SALTWORKS, source="ti-sim", confidence=0.8)
    inv_edge("INDICATES", sc.IOC_EGRESS_IP, sc.ACTOR_CJ, source="ti-sim", confidence=0.85)
    inv_edge("EXPLOITS", sc.CAMPAIGN_SALTWORKS, sc.LOG4SHELL, {"status": "mass_exploitation"}, source="ti-sim", first_seen="2026-08-20T00:00:00Z")
    for target in (sc.ACTOR_HT, sc.CAMPAIGN_SALTWORKS, sc.LOG4SHELL):
        inv_edge("REPORTS_ON", sc.REPORT_SALTWORKS, target, source="ti-sim", first_seen="2026-09-08T00:00:00Z")
    e(edge("MATCHES_IOC", IP_SALTWORKS, sc.IOC_SALTWORKS_IP, {"match_type": "exact"}, source="derived", first_seen=T_B001, last_seen=T_B002, confidence=0.8))
    e(edge("MATCHES_IOC", IP_EGRESS, sc.IOC_EGRESS_IP, {"match_type": "exact"}, source="derived", first_seen=a012[1], last_seen=a014[1], confidence=0.85))
    return nodes, edges


def build_mini_fixture(out_dir: Path) -> dict[str, Any]:
    """Write nodes.jsonl / edges.jsonl / manifest.json into ``out_dir`` and return the manifest."""
    from collections import Counter

    from throughline.graph.context_graph import ContextGraph
    from throughline.schema import validate_node

    nodes, edges = build_records()
    problems = [p for rec in nodes for p in validate_node(rec)]
    problems += ContextGraph.from_records(nodes, edges).validate()
    if problems:
        raise ValueError("mini fixture is invalid: " + "; ".join(problems[:10]))
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    nodes_path, edges_path = out_dir / "nodes.jsonl", out_dir / "edges.jsonl"
    write_jsonl(nodes_path, nodes)
    write_jsonl(edges_path, edges)
    digest = hashlib.sha256()
    digest.update(nodes_path.read_bytes())
    digest.update(edges_path.read_bytes())
    manifest = {
        "fixture": "mini",
        "seed": sc.SEED,
        "generated_at": sc.NOW,
        "counts": {
            "nodes": dict(sorted(Counter(r["label"] for r in nodes).items())),
            "edges": dict(sorted(Counter(r["type"] for r in edges).items())),
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        },
        "storylines": [sc.STORYLINE_A, sc.STORYLINE_B],
        "checksum": digest.hexdigest(),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/fixtures/mini")
    result = build_mini_fixture(target)
    print(json.dumps(result["counts"], indent=2))
