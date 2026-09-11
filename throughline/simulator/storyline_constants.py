"""Canonical identifiers and values for the scripted storylines (docs/04-storyline.md).

Every generator imports these instead of retyping strings, so the cloud inventory, the EDR events, the cloud
audit events and the threat-intel catalog all agree on the same ids, IPs, hashes and timestamps.
All values are fictional; external IPs come from documentation ranges.
"""
from __future__ import annotations

NOW = "2026-09-11T14:00:00Z"
SEED = 20260911

# ------------------------------------------------------------------ customer
CUSTOMER = "Larkspur Financial"
CORP_DOMAIN = "corp.larkspur.example"
SECTOR = "financial-services"

ACCOUNTS = {
    "prod": {"id": "account:aws:111111111111", "account_id": "111111111111", "provider": "aws", "name": "larkspur-prod", "environment": "prod", "purpose": "Wallet API, card issuing, statement rendering, cardholder data"},
    "shared": {"id": "account:aws:222222222222", "account_id": "222222222222", "provider": "aws", "name": "larkspur-shared-services", "environment": "prod", "purpose": "Bastions, CI/CD, monitoring, VPN, artifact registry"},
    "staging": {"id": "account:aws:333333333333", "account_id": "333333333333", "provider": "aws", "name": "larkspur-staging", "environment": "staging", "purpose": "Pre-production copies of prod services"},
    "dev": {"id": "account:aws:444444444444", "account_id": "444444444444", "provider": "aws", "name": "larkspur-dev-sandbox", "environment": "dev", "purpose": "Developer experiments, throwaway instances"},
    "data": {"id": "account:aws:555555555555", "account_id": "555555555555", "provider": "aws", "name": "larkspur-data-platform", "environment": "prod", "purpose": "Data lake, warehouse, analytics jobs (PII)"},
    "corp": {"id": "account:aws:666666666666", "account_id": "666666666666", "provider": "aws", "name": "larkspur-corp-it", "environment": "corp", "purpose": "Corporate IT: marketing site, intranet tooling, Okta integrations"},
    "gcp_ml": {"id": "account:gcp:larkspur-ml-fraud", "account_id": "larkspur-ml-fraud", "provider": "gcp", "name": "larkspur-ml-fraud", "environment": "prod", "purpose": "Fraud-model training, BigQuery datasets (PII)"},
    "azure_corp": {"id": "account:azure:7a1c9e2b-4d3f-4a8e-9b1c-2f3e4d5a6b7c", "account_id": "7a1c9e2b-4d3f-4a8e-9b1c-2f3e4d5a6b7c", "provider": "azure", "name": "larkspur-corp-azure", "environment": "corp", "purpose": "Entra-connected corporate services"},
}

# ------------------------------------------------------------------ named resources (must exist exactly)
BASTION_VM = "vm:aws:i-0b4571e2c9a8f3d01"
BASTION_INSTANCE_ID = "i-0b4571e2c9a8f3d01"
BASTION_HOSTNAME = "bas-01.shared.larkspur.internal"
BASTION_NAME = "bas-01"
BASTION_PRIVATE_IP = "10.20.0.15"
BASTION_PUBLIC_IP = "198.51.100.10"
BASTION_SUBNET = "subnet:aws:subnet-0shared-mgmt-a"
BASTION_ROLE = "role:aws:222222222222:LarkspurBastionSSMRole"
BASTION_ROLE_ARN = "arn:aws:iam::222222222222:role/LarkspurBastionSSMRole"
BASTION_ASSUME_POLICY = "policy:aws:222222222222:LarkspurBastionAssumeProdReader"
BASTION_LOGS_POLICY = "policy:aws:222222222222:LarkspurSharedLogsWrite"
SHARED_LOGS_BUCKET = "bucket:aws:larkspur-shared-logs"
PROD_READER_ROLE = "role:aws:111111111111:LarkspurProdDataReader"
PROD_READER_ROLE_ARN = "arn:aws:iam::111111111111:role/LarkspurProdDataReader"
PROD_READER_POLICY = "policy:aws:111111111111:LarkspurProdDataReaderAccess"
CARDHOLDER_VAULT = "bucket:aws:larkspur-cardholder-vault"
KYC_DOCS = "bucket:aws:larkspur-kyc-documents"
DB_READER_SECRET = "secret:aws:111111111111:prod/cardholder-db/reader"
HSM_SECRET = "secret:aws:111111111111:prod/hsm/partner-signing-key"
CARDHOLDER_DB = "database:aws:111111111111:cardholder-db"

EDGE_VM = "vm:aws:i-0edge2a7f19c4b3e88"
EDGE_INSTANCE_ID = "i-0edge2a7f19c4b3e88"
EDGE_HOSTNAME = "stmt-render-2a.prod.larkspur.internal"
EDGE_NAME = "stmt-render-2a"
EDGE_PRIVATE_IP = "10.10.3.24"
EDGE_PUBLIC_IP = "198.51.100.24"
EDGE_SG = "sg:aws:sg-0edge-public-8080"
EDGE_ROLE = "role:aws:111111111111:LarkspurStmtRenderRole"
EDGE_ROLE_ARN = "arn:aws:iam::111111111111:role/LarkspurStmtRenderRole"
EDGE_POLICY = "policy:aws:111111111111:LarkspurStmtRenderAccess"
APP_CONFIG_BUCKET = "bucket:aws:larkspur-prod-app-config"
STATEMENTS_OUT_BUCKET = "bucket:aws:larkspur-statements-out"
EDGE_IMAGE = "image:ecr:larkspur/statement-render:3.8.1"
EDGE_LOG4J_PACKAGE = "package:aws:i-0edge2a7f19c4b3e88:log4j-core:2.14.1"
LOG4SHELL = "cve:CVE-2021-44228"

# other internet-exposed Log4Shell hosts (lower context)
STG_EDGE_VM = "vm:aws:i-0stg4e5f6a7b8c9d0e1"
STG_EDGE_NAME = "stmt-render-stg-1"
DEV_LOG4J_VM = "vm:aws:i-0dev8f9e0d1c2b3a4f5"
DEV_LOG4J_NAME = "log4j-testbed"

MARKETING_BUCKET = "bucket:aws:larkspur-marketing-assets"
DEV_SANDBOX_VM = "vm:aws:i-0dev7c1a2b3c4d5e6f"
DEV_SANDBOX_NAME = "dev-sandbox-runner-03"
SCANNER_VM = "vm:aws:i-0scan9f8e7d6c5b4a3"
SCANNER_NAME = "vulnscan-01"
SCANNER_IP = "10.20.5.9"
FILESHARE_VM = "vm:aws:i-0file1a2b3c4d5e6f7"
FILESHARE_NAME = "srv-fileshare-01"

# endpoints
WKS_DANA = "endpoint:falcon:aid-wks3391"
WKS_DANA_HOSTNAME = "WKS-3391"
WKS_DANA_IP = "10.40.12.77"
EP_BASTION = "endpoint:falcon:aid-bas01"
EP_EDGE = "endpoint:falcon:aid-edge2a"
EP_DEV_SANDBOX = "endpoint:falcon:aid-devrun03"
EP_FILESHARE = "endpoint:falcon:aid-file01"
EP_MREYES = "endpoint:falcon:aid-wks2210"
EP_MREYES_HOSTNAME = "WKS-2210"
EP_PKAUR = "endpoint:falcon:aid-wks1042"
EP_PKAUR_HOSTNAME = "WKS-1042"

# people and identities
USER_DANA = "user:okta:dwhitfield"
USER_MREYES = "user:okta:mreyes"
USER_PKAUR = "user:okta:pkaur"
USER_JOKAFOR = "user:okta:jokafor"
USER_LCHEN = "user:okta:lchen"
SVC_FINOPS_SFTP = "identity:linux:svc-finops-sftp"
CORP_IT_ADMIN_ROLE = "role:aws:666666666666:LarkspurCorpItAdmin"
TEAM_PLATFORM = "team:larkspur:platform-eng"
TEAM_PAYMENTS = "team:larkspur:payments-platform"
TEAM_TREASURY = "team:larkspur:finance-treasury"
TEAM_CORP_IT = "team:larkspur:corp-it"
APP_CARD_ISSUING = "app:larkspur:card-issuing"
APP_STMT_RENDER = "app:larkspur:statement-render"
APP_MARKETING = "app:larkspur:marketing-site"
APP_SETTLEMENT_SFTP = "app:larkspur:settlement-sftp"
GROUP_TREASURY = "group:okta:finance-treasury"
GROUP_ALL = "group:okta:all-employees"

# ------------------------------------------------------------------ campaign A: EMBERCAST / Cinder Jackal
ACTOR_CJ = "actor:ti:cinder-jackal"
CAMPAIGN_EMBERCAST = "campaign:ti:embercast"
MALWARE_MAPLELOADER = "malware:ti:mapleloader"
MALWARE_QUILLDROP = "malware:ti:quilldrop"
MALWARE_NIGHTFERRY = "malware:ti:nightferry"
REPORT_EMBERCAST = "report:ti:TL-2026-0142"
C2_DOMAIN = "cdn-metrics.telemetry-sync.net"
C2_IP = "203.0.113.42"
ATTACKER_EGRESS_IP = "203.0.113.77"
ATTACKER_ASN = "AS64500"
ATTACKER_ASN_ORG = "Stratovault Hosting (fictional)"
HASH_MAPLELOADER = "8f2c1a9e4b7d3f60c5e8a1b2d4f6c7e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
HASH_QUILLDROP = "3b9d7e1f5a2c8b4d6e0f9a1c3b5d7e9f2a4c6e8b0d1f3a5c7e9b1d3f5a7c9e1b"
HASH_NIGHTFERRY = "c4e2a6b8d0f1e3a5c7b9d1f3e5a7c9b1d3f5e7a9c1b3d5f7e9a1c3b5d7f9e1a3"
IOC_C2_DOMAIN = f"ioc:domain:{C2_DOMAIN}"
IOC_C2_IP = f"ioc:ipv4:{C2_IP}"
IOC_EGRESS_IP = f"ioc:ipv4:{ATTACKER_EGRESS_IP}"
IOC_HASH_MAPLELOADER = "ioc:sha256:mapleloader"
IOC_HASH_QUILLDROP = "ioc:sha256:quilldrop"
IOC_HASH_NIGHTFERRY = "ioc:sha256:nightferry"
IOC_FILENAME_SYNCHOST = "ioc:filename:synchost.exe"
CJ_TECHNIQUES = [
    "T1566.001", "T1204.002", "T1059.001", "T1218.011", "T1055", "T1547.001", "T1071.001", "T1573.002", "T1003.001",
    "T1552.001", "T1087.002", "T1018", "T1021.004", "T1078", "T1003.008", "T1552.005", "T1078.004", "T1580", "T1548.005",
    "T1530", "T1567.002",
]
CRED_SSH_KEY = "credential:ssh:dwhitfield-id_ed25519"
CRED_BASTION_KEY = "credential:aws:ASIA5LARKBASTION01Q7"
CRED_BASTION_KEY_ID = "ASIA5LARKBASTION01Q7"
CRED_PROD_KEY = "credential:aws:ASIA5LARKPRODREADER1"
CRED_PROD_KEY_ID = "ASIA5LARKPRODREADER1"

INCIDENT_WKS = "incident:falcon:inc-0091"
INCIDENT_BASTION = "incident:falcon:inc-0094"
INCIDENT_EDGE = "incident:falcon:inc-0096"
STORYLINE_A = "storyline:derived:embercast-larkspur"
STORYLINE_B = "storyline:derived:saltworks-larkspur"

# alert ids for campaign A (see docs/04-storyline.md section 2.1)
ALERT_A = {
    "a001": ("alert:falcon:ldt-a001", "2026-09-09T09:12:04Z", "high"),
    "a002": ("alert:falcon:ldt-a002", "2026-09-09T09:14:30Z", "medium"),
    "a003": ("alert:falcon:ldt-a003", "2026-09-09T11:40:00Z", "medium"),
    "a004": ("alert:falcon:ldt-a004", "2026-09-09T15:22:41Z", "medium"),
    "a005": ("alert:falcon:ldt-a005", "2026-09-09T15:31:10Z", "low"),
    "a006": ("alert:falcon:ldt-a006", "2026-09-09T15:40:00Z", "informational"),
    "a007": ("alert:falcon:ldt-a007", "2026-09-10T02:05:17Z", "medium"),
    "a008x": ("alert:falcon:ldt-a008x", "2026-09-10T02:09:02Z", "low"),
    "a009": ("alert:falcon:ldt-a009", "2026-09-10T02:11:45Z", "medium"),
    "a017": ("alert:cloud-anomaly:ca-a017", "2026-09-10T03:55:00Z", "low"),
}
CLOUDEVENTS_A = {
    "a010": ("cloudevent:aws:evt-a010", "2026-09-10T02:20:31Z", "GetCallerIdentity", "sts.amazonaws.com", CRED_BASTION_KEY_ID, True, None, 1),
    "a011": ("cloudevent:aws:evt-a011", "2026-09-10T02:21:02Z", "ListAllMyBuckets", "s3.amazonaws.com", CRED_BASTION_KEY_ID, False, "AccessDenied", 2),
    "a012": ("cloudevent:aws:evt-a012", "2026-09-10T02:24:15Z", "AssumeRole", "sts.amazonaws.com", CRED_BASTION_KEY_ID, True, None, 1),
    "a013": ("cloudevent:aws:evt-a013", "2026-09-10T02:26:00Z", "ListBucket", "s3.amazonaws.com", CRED_PROD_KEY_ID, True, None, 1),
    "a014": ("cloudevent:aws:evt-a014", "2026-09-10T02:27:10Z", "GetObject", "s3.amazonaws.com", CRED_PROD_KEY_ID, True, None, 1247),
    "a015": ("cloudevent:aws:evt-a015", "2026-09-10T03:41:12Z", "GetSecretValue", "secretsmanager.amazonaws.com", CRED_PROD_KEY_ID, True, None, 1),
    "a016": ("cloudevent:aws:evt-a016", "2026-09-10T03:41:40Z", "GetSecretValue", "secretsmanager.amazonaws.com", CRED_PROD_KEY_ID, True, None, 1),
}
EXFIL_BYTES = 38_400_000_000

# ------------------------------------------------------------------ campaign B: SALTWORKS / Hollow Tide
ACTOR_HT = "actor:ti:hollow-tide"
CAMPAIGN_SALTWORKS = "campaign:ti:saltworks"
MALWARE_BRACKISH = "malware:ti:brackish"
REPORT_SALTWORKS = "report:ti:TL-2026-0147"
SALTWORKS_IP = "203.0.113.99"
IOC_SALTWORKS_IP = f"ioc:ipv4:{SALTWORKS_IP}"
HASH_BRACKISH = "e7a1c3b5d7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1"
IOC_HASH_BRACKISH = "ioc:sha256:brackish"
IOC_BRACKISH_URL = "ioc:url:http-203.0.113.99-8000-s-brackish.sh"
BRACKISH_URL = "http://203.0.113.99:8000/s/brackish.sh"
HT_TECHNIQUES = ["T1595.002", "T1190", "T1059.004", "T1505.003", "T1105", "T1071.001", "T1552.005", "T1530"]
ALERT_B = {
    "b001": ("alert:waf:waf-b001", "2026-09-10T21:13:02Z", "medium"),
    "b002": ("alert:falcon:ldt-b002", "2026-09-10T21:13:07Z", "medium"),
    "b003": ("alert:falcon:ldt-b003", "2026-09-10T21:13:19Z", "low"),
}

# ------------------------------------------------------------------ noise alerts (must exist exactly)
ALERT_N = {
    "n001": ("alert:falcon:ldt-n001", "2026-09-11T09:41:00Z", "high"),  # EICAR on dev-sandbox-runner-03
    "n002": ("alert:cspm:iss-n002", "2026-09-11T06:00:00Z", "critical"),  # public marketing bucket
    "n003": ("alert:falcon:ldt-n003", "2026-09-11T01:12:00Z", "medium"),  # PsExec by mreyes in change window
    "n004": ("alert:okta:idp-n004", "2026-09-11T07:48:00Z", "medium"),  # impossible travel pkaur
}
CHANGE_TICKET = "CHG-2026-0911-014"
VPN_EGRESS_IP = "198.51.100.200"
QUARANTINE_ALERT_IDS = [f"alert:falcon:ldt-n{n:03d}" for n in range(5, 17)]

# sectors used across TI
SECTORS = ["financial-services", "healthcare", "energy", "public-sector", "technology", "retail", "manufacturing", "telecommunications"]

# ------------------------------------------------------------------ external IP allocation (disjoint by construction)
# Every generator draws external addresses from its own reserved block so that noise traffic never matches a
# threat-intel indicator by accident (docs/04-storyline.md section 4: "none in TI").
IP_BLOCK_TI_INDICATORS = "203.0.113"          # TEST-NET-3: attacker infrastructure and generated indicators
IP_BLOCK_ESTATE_PUBLIC = "198.51.100"         # TEST-NET-2: Larkspur's own public IPs (bastion, edge, VPN egress, VMs, LBs)
IP_BLOCKS_NOISE = ("192.0.2", "198.18.0", "198.18.1", "198.18.2")  # TEST-NET-1 + benchmarking range: scanners, benign traffic
IP_BLOCK_PLANTS = "198.18.200"                # low-confidence indicators the build deliberately plants on random telemetry
