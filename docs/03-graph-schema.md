# Graph Schema (build contract)

This is the canonical data model for the Throughline security context graph. The simulator writes it, the loaders (Kuzu embedded, Neo4j server, NetworkX projection) read it, the analytics traverse it, the API serves it, the UI renders it, and the analyst agent cites it. Any change here must be made deliberately and propagated.

## 1. Conventions

- **Node ID**: `<type>:<namespace>:<natural-key>` in lowercase `type`, e.g. `vm:aws:i-0b4571e2c9a8f3d01`, `endpoint:falcon:aid-bas01`, `role:aws:222222222222:LarkspurBastionSSMRole`, `cve:CVE-2021-44228`, `technique:attack:T1552.005`, `alert:falcon:ldt-a009`, `cloudevent:aws:evt-a012`, `credential:aws:ASIA5LARKBASTION01Q7`. IDs are stable across regenerations with the same seed, globally unique, and safe to print in chat answers.
- **Labels** are PascalCase, one label per node (Kuzu needs single-label nodes; Neo4j gets the same single label plus a `Node` super-label for convenience).
- **Relationship types** are UPPER_SNAKE_CASE. Direction is semantic and fixed per type (see section 4). Traversals that need both directions say so explicitly.
- **Time**: all timestamps are ISO-8601 UTC strings in the JSONL files (`2026-09-10T02:11:45Z`). Loaders convert to native TIMESTAMP. The simulation clock is fixed: `NOW = 2026-09-11T14:00:00Z`.
- **Provenance on every node and edge**: `source` (which feed: `wiz-sim`, `falcon-sim`, `cloudtrail-sim`, `waf-sim`, `ids-sim`, `okta-sim`, `ti-sim`, `derived`), `source_id` (the id in the source system, may be null for derived), `first_seen`, `last_seen`, `confidence` (0-1; 1.0 for asserted facts, lower for inferred/derived).
- **Severity enum** (vendor): `informational | low | medium | high | critical`. **Contextual score**: integer 0-100 with band `noise (<26) | low (26-50) | medium (51-75) | high (76-89) | critical (>=90)`.
- **Sensitivity enum** for data holders: `none | low | medium | high | critical`. **Data classifications**: list from `PUBLIC | INTERNAL | PII | PCI | PHI | SECRETS | FINANCIAL`.
- **Exposure enum** for compute/data: `internet | internal | isolated`.
- **Environment enum**: `prod | staging | dev | corp`.

## 2. File formats (produced by the simulator under `data/generated/`)

```
data/generated/
  raw/                       vendor-shaped feeds (loosely mimic real API objects)
    wiz/            cloud_resources.jsonl, iam.jsonl, network.jsonl, vulnerabilities.jsonl, issues.jsonl, business_context.jsonl
    falcon/         devices.jsonl, detections.jsonl, incidents.jsonl, processes.jsonl, network_connections.jsonl, logons.jsonl
    cloudtrail/     events.jsonl
    waf/            alerts.jsonl          ids/ alerts.jsonl          okta/ alerts.jsonl, users.jsonl
    ti/             actors.json, campaigns.json, malware.json, indicators.jsonl, reports.json, exploited_cves.json
  graph/
    nodes.jsonl                one JSON object per node (schema below)
    edges.jsonl                one JSON object per edge
    manifest.json              counts per label/type, seed, generated_at, storyline ids, checksums
```

Node line:
```json
{"id":"vm:aws:i-0b4571e2c9a8f3d01","label":"VirtualMachine","name":"bas-01",
 "source":"wiz-sim","source_id":"i-0b4571e2c9a8f3d01","first_seen":"2025-11-02T10:00:00Z","last_seen":"2026-09-11T13:55:00Z","confidence":1.0,
 "props":{"hostname":"bas-01.shared.larkspur.internal","private_ip":"10.20.0.15", "...":"..."}}
```
Edge line:
```json
{"type":"HAS_ROLE","src":"vm:aws:i-0b4571e2c9a8f3d01","dst":"role:aws:222222222222:LarkspurBastionSSMRole",
 "source":"wiz-sim","first_seen":"2025-11-02T10:00:00Z","last_seen":"2026-09-11T13:55:00Z","confidence":1.0,"props":{"via":"instance_profile"}}
```

Typed columns (section 3) are read from `props` by the loaders; the whole `props` object is also stored as a JSON string column `props` so nothing is lost. Generators must emit typed columns with the exact names and types below.

## 3. Node labels and typed properties

Common columns on every label: `id STRING (PK)`, `name STRING`, `source STRING`, `source_id STRING`, `first_seen TIMESTAMP`, `last_seen TIMESTAMP`, `confidence DOUBLE`, `props STRING(JSON)`. Below, only label-specific typed columns are listed. `category` is the UI grouping.

### 3.1 Cloud and infrastructure (category `cloud`)
| Label | ID form | Typed columns |
|---|---|---|
| `CloudAccount` | `account:<provider>:<id>` | `provider STRING (aws/gcp/azure)`, `account_id STRING`, `environment STRING`, `purpose STRING` |
| `VPC` | `vpc:<provider>:<vpc-id>` | `provider`, `account_id`, `cidr STRING`, `region STRING` |
| `Subnet` | `subnet:<provider>:<subnet-id>` | `provider`, `account_id`, `cidr`, `region`, `public BOOLEAN` |
| `SecurityGroup` | `sg:<provider>:<sg-id>` | `provider`, `account_id`, `inbound_rules STRING(JSON list of {cidr,port_from,port_to,protocol})`, `open_to_internet BOOLEAN`, `internet_ports STRING[]` |
| `LoadBalancer` | `lb:<provider>:<name>` | `provider`, `account_id`, `scheme STRING (internet-facing/internal)`, `dns_name STRING`, `listeners STRING[]` |
| `VirtualMachine` | `vm:<provider>:<instance-id>` | `provider`, `account_id`, `region`, `hostname STRING`, `private_ip STRING`, `public_ip STRING`, `os STRING`, `os_family STRING (linux/windows)`, `instance_type STRING`, `environment STRING`, `exposure STRING`, `has_edr_sensor BOOLEAN`, `is_k8s_node BOOLEAN`, `tags STRING(JSON)`, `criticality STRING (tier-0..tier-3)`, `ti_exposure_score DOUBLE`, `crown_jewel_reach INT64` (derived: number of crown jewels reachable) |
| `KubernetesCluster` | `k8s:<provider>:<name>` | `provider`, `account_id`, `version STRING`, `environment`, `public_endpoint BOOLEAN` |
| `Workload` | `workload:<cluster>:<namespace>/<name>` | `kind STRING (Deployment/StatefulSet/DaemonSet/Job)`, `namespace STRING`, `cluster_id STRING`, `image STRING`, `exposure`, `environment`, `privileged BOOLEAN`, `service_account STRING` |
| `ContainerImage` | `image:<registry>:<repo>:<tag>` | `registry STRING`, `repository STRING`, `tag STRING`, `digest STRING`, `vuln_count_critical INT64`, `vuln_count_high INT64` |
| `ServerlessFunction` | `function:<provider>:<account>:<name>` | `provider`, `account_id`, `runtime STRING`, `exposure`, `environment`, `url_enabled BOOLEAN` |
| `StorageBucket` | `bucket:<provider>:<name>` | `provider`, `account_id`, `region`, `public BOOLEAN`, `encrypted BOOLEAN`, `versioning BOOLEAN`, `data_classifications STRING[]`, `sensitivity STRING`, `crown_jewel BOOLEAN`, `size_gb DOUBLE`, `environment`, `contains_credentials_for STRING[]` |
| `Database` | `database:<provider>:<account>:<name>` | `provider`, `account_id`, `engine STRING`, `public BOOLEAN`, `encrypted BOOLEAN`, `data_classifications STRING[]`, `sensitivity`, `crown_jewel BOOLEAN`, `environment`, `exposure` |
| `Secret` | `secret:<provider>:<account>:<path>` | `provider`, `account_id`, `secret_type STRING (db_credentials/api_key/signing_key/oauth_token/ssh_key)`, `sensitivity`, `rotated_days_ago INT64`, `grants_access_to STRING[]` (node ids the secret unlocks) |
| `Internet` | `internet:global:internet` | singleton. `exposure` edges hang off this node |
| `IpAddress` | `ip:v4:<addr>` | `address STRING`, `is_private BOOLEAN`, `asn STRING`, `asn_org STRING`, `country STRING`, `reputation STRING (unknown/benign/suspicious/malicious)` |
| `Domain` | `domain:dns:<fqdn>` | `fqdn STRING`, `registered_days_ago INT64`, `reputation STRING` |

### 3.2 Identity and access (category `identity`)
| Label | ID form | Typed columns |
|---|---|---|
| `IamRole` | `role:<provider>:<account>:<name>` | `provider`, `account_id`, `arn STRING`, `role_type STRING (instance/service/cross-account/sso/human)`, `is_admin BOOLEAN`, `privilege_score DOUBLE (0-1)`, `trust_principals STRING[]`, `last_used TIMESTAMP`, `environment` |
| `IamUser` | `iamuser:<provider>:<account>:<name>` | `provider`, `account_id`, `arn`, `is_admin BOOLEAN`, `mfa_enabled BOOLEAN`, `console_access BOOLEAN`, `privilege_score DOUBLE` |
| `IamPolicy` | `policy:<provider>:<account>:<name>` | `provider`, `account_id`, `managed BOOLEAN`, `statements STRING(JSON)`, `access_levels STRING[] (read/write/admin/list)`, `wildcard_resource BOOLEAN`, `wildcard_action BOOLEAN` |
| `AccessKey` | `accesskey:<provider>:<key-id>` | `provider`, `account_id`, `owner_id STRING`, `status STRING (active/inactive)`, `age_days INT64`, `last_used TIMESTAMP` |
| `ServiceAccount` | `identity:<system>:<name>` | `system STRING (linux/windows/gcp/k8s)`, `host_id STRING`, `purpose STRING`, `privileged BOOLEAN` |
| `HumanUser` | `user:okta:<login>` | `email STRING`, `display_name STRING`, `title STRING`, `department STRING`, `team_id STRING`, `location STRING`, `is_privileged BOOLEAN`, `is_executive BOOLEAN`, `mfa_enabled BOOLEAN`, `status STRING` |
| `Group` | `group:okta:<name>` | `description STRING`, `member_count INT64`, `privileged BOOLEAN` |
| `Credential` | `credential:<kind>:<key>` | `credential_type STRING (aws_temporary_key/aws_access_key/ssh_private_key/password_hash/session_token/kerberos_ticket/api_token)`, `principal_id STRING` (node id it authenticates as), `issued_at TIMESTAMP`, `expires_at TIMESTAMP`, `status STRING (valid/expired/revoked/unknown)`, `derived_from STRING` (credential id) |

### 3.3 Software, vulnerabilities, findings (category `software`)
| Label | ID form | Typed columns |
|---|---|---|
| `Package` | `package:<scope>:<name>:<version>` | `package_name STRING`, `version STRING`, `ecosystem STRING (maven/npm/pypi/os/go)`, `scope STRING` (image or host id) |
| `Vulnerability` | `cve:<CVE-ID>` | `cve_id STRING`, `cvss DOUBLE`, `epss DOUBLE`, `kev BOOLEAN`, `severity STRING`, `published TIMESTAMP`, `exploitation_status STRING (none/poc_public/active/mass_exploitation)`, `actor_interest STRING[]` (actor ids), `sector_targeting_relevance DOUBLE`, `ti_report_ids STRING[]`, `synthetic BOOLEAN`, `description STRING`, `affected_component STRING` |

### 3.4 Business context (category `business`)
| Label | ID form | Typed columns |
|---|---|---|
| `Application` | `app:larkspur:<slug>` | `criticality STRING (tier-0..tier-3)`, `environment`, `owner_team_id STRING`, `description STRING`, `data_classifications STRING[]` |
| `Team` | `team:larkspur:<slug>` | `department STRING`, `lead_user_id STRING`, `oncall_channel STRING` |

### 3.5 Endpoint and runtime telemetry (category `endpoint`)
| Label | ID form | Typed columns |
|---|---|---|
| `Endpoint` | `endpoint:falcon:<aid>` | `hostname STRING`, `device_type STRING (workstation/server/k8s-node)`, `os STRING`, `os_family STRING`, `private_ip STRING`, `public_ip STRING`, `site STRING`, `sensor_version STRING`, `last_seen_sensor TIMESTAMP`, `cloud_provider STRING`, `cloud_instance_id STRING`, `cloud_account_id STRING`, `primary_user_id STRING`, `containment_status STRING (normal/contained)`, `ou STRING` |
| `Process` | `process:falcon:<aid>:<pid>:<start-epoch>` | `endpoint_id STRING`, `pid INT64`, `parent_process_id STRING`, `image_path STRING`, `command_line STRING`, `user STRING`, `sha256 STRING`, `signed BOOLEAN`, `signer STRING`, `start_time TIMESTAMP`, `end_time TIMESTAMP`, `integrity_level STRING` |
| `File` | `file:sha256:<hash>` | `sha256 STRING`, `file_name STRING`, `file_path STRING`, `size_bytes INT64`, `signed BOOLEAN`, `malware_family STRING`, `verdict STRING (clean/suspicious/malicious/unknown)` |
| `LogonSession` | `logon:falcon:<aid>:<epoch>:<user>` | `endpoint_id STRING`, `user_id STRING`, `logon_type STRING (interactive/remote_interactive/network/service/ssh)`, `source_ip STRING`, `success BOOLEAN`, `logon_time TIMESTAMP` |

### 3.6 Alerts, events, incidents (category `alerts`)
| Label | ID form | Typed columns |
|---|---|---|
| `Alert` | `alert:<source>:<id>` | `source_system STRING (falcon/cspm/waf/ids/cloud-anomaly/okta)`, `alert_type STRING (detection/issue/network/identity/cloud)`, `title STRING`, `description STRING`, `vendor_severity STRING`, `vendor_severity_rank INT64 (0-4)`, `status STRING (new/in_progress/closed/benign)`, `detected_at TIMESTAMP`, `techniques STRING[]`, `tactic STRING`, `entity_id STRING` (primary asset the alert is on), `entity_label STRING`, `hostname STRING`, `user STRING`, `vendor_incident_id STRING`, `change_ticket STRING`, `raw STRING(JSON)` (the flat-view fields exactly as the vendor shows them), `contextual_score INT64`, `contextual_band STRING`, `score_breakdown STRING(JSON)`, `storyline_id STRING`, `graph_reasons STRING[]` (short "why" chips), `ti_actor_ids STRING[]`, `ioc_match_count INT64`, `reaches_crown_jewel BOOLEAN`, `on_attack_path BOOLEAN` |
| `Incident` | `incident:falcon:<id>` | `vendor_severity`, `status`, `start_time TIMESTAMP`, `end_time TIMESTAMP`, `alert_count INT64`, `hosts STRING[]`, `description STRING` |
| `CloudEvent` | `cloudevent:<provider>:<id>` | `provider`, `account_id`, `event_name STRING`, `event_source STRING`, `event_time TIMESTAMP`, `principal_id STRING` (role/user node id), `principal_arn STRING`, `access_key_id STRING`, `source_ip STRING`, `user_agent STRING`, `success BOOLEAN`, `error_code STRING`, `target_id STRING` (resource node id), `count INT64`, `bytes INT64`, `anomalous BOOLEAN`, `anomaly_reasons STRING[]` |
| `Storyline` | `storyline:derived:<slug>` | `title STRING`, `summary STRING`, `actor_id STRING`, `campaign_id STRING`, `stage_count INT64`, `alert_ids STRING[]`, `crown_jewels_reached STRING[]`, `first_event TIMESTAMP`, `last_event TIMESTAMP`, `contextual_score INT64`, `stages STRING(JSON list of {stage, technique_ids, alert_ids, node_ids, summary})` |

### 3.7 Threat intelligence (category `threat_intel`)
| Label | ID form | Typed columns |
|---|---|---|
| `ThreatActor` | `actor:ti:<slug>` | `aliases STRING[]`, `motivation STRING (financial/espionage/hacktivism/access-broker)`, `origin STRING`, `sophistication STRING`, `targeted_sectors STRING[]`, `targeted_regions STRING[]`, `sector_targeting_relevance DOUBLE` (for the customer), `active BOOLEAN`, `description STRING` |
| `Campaign` | `campaign:ti:<slug>` | `actor_id STRING`, `status STRING (active/dormant/historical)`, `started TIMESTAMP`, `objective STRING`, `targeted_sectors STRING[]`, `sector_targeting_relevance DOUBLE`, `description STRING` |
| `Malware` | `malware:ti:<slug>` | `family STRING`, `malware_type STRING (loader/stealer/implant/webshell/ransomware/tool)`, `platforms STRING[]`, `description STRING` |
| `AttackTechnique` | `technique:attack:<Txxxx[.yyy]>` | `technique_id STRING`, `tactic STRING`, `kill_chain_stage INT64 (1-7)`, `description STRING` |
| `Indicator` | `ioc:<type>:<value-or-slug>` | `ioc_type STRING (ipv4/domain/url/sha256/filename/ja3/email)`, `value STRING`, `confidence DOUBLE`, `first_seen`, `last_seen`, `report_id STRING`, `actor_id STRING`, `campaign_id STRING`, `malware_id STRING`, `kill_chain_stage INT64`, `active BOOLEAN` |
| `IntelReport` | `report:ti:<id>` | `title STRING`, `published TIMESTAMP`, `publisher STRING`, `confidence STRING (low/medium/high)`, `tlp STRING`, `summary STRING`, `actor_ids STRING[]`, `campaign_ids STRING[]`, `cve_ids STRING[]`, `technique_ids STRING[]`, `indicator_count INT64`, `targeted_sectors STRING[]`, `body STRING` (a few paragraphs of fictional narrative) |

## 4. Relationship types

Column `props` (JSON) is on every relationship plus `source`, `first_seen`, `last_seen`, `confidence`. Extra typed columns listed per type. The `Kind` column marks raw (asserted by a feed) versus derived (materialized by the enrichment/analytics pipeline; always `source: derived`).

### 4.1 Cloud structure and network
| Type | From -> To | Typed columns | Kind |
|---|---|---|---|
| `CONTAINS` | CloudAccount -> VPC, VirtualMachine, StorageBucket, Database, Secret, IamRole, IamUser, IamPolicy, ServerlessFunction, KubernetesCluster, SecurityGroup, LoadBalancer | | raw |
| `IN_VPC` | Subnet -> VPC | | raw |
| `IN_SUBNET` | VirtualMachine, LoadBalancer, Database -> Subnet | | raw |
| `HAS_SECURITY_GROUP` | VirtualMachine, LoadBalancer, Database -> SecurityGroup | | raw |
| `ROUTES_TO` | LoadBalancer -> VirtualMachine, Workload | `port INT64` | raw |
| `EXPOSES` | Internet -> VirtualMachine, LoadBalancer, StorageBucket, Database, ServerlessFunction, Workload, KubernetesCluster | `ports STRING[]`, `via STRING (security_group/public_acl/function_url/lb)`, `protocol STRING` | derived |
| `HAS_NODE` | KubernetesCluster -> VirtualMachine | | raw |
| `RUNS_ON` | Workload -> KubernetesCluster | | raw |
| `RUNS_IMAGE` | Workload, VirtualMachine -> ContainerImage | | raw |
| `HAS_PACKAGE` | VirtualMachine, ContainerImage, ServerlessFunction -> Package | | raw |
| `HAS_VULNERABILITY` | Package -> Vulnerability | `fixed_version STRING` | raw |
| `VULNERABLE_TO` | VirtualMachine, ContainerImage, ServerlessFunction, Workload -> Vulnerability | `via_package STRING`, `exploitable BOOLEAN` | derived |
| `RESOLVES_TO` | Domain -> IpAddress | | raw |

### 4.2 Identity and access
| Type | From -> To | Typed columns | Kind |
|---|---|---|---|
| `HAS_ROLE` | VirtualMachine, Workload, ServerlessFunction, KubernetesCluster -> IamRole | `via STRING (instance_profile/irsa/service_account/node_role)` | raw |
| `HAS_POLICY` | IamRole, IamUser, Group -> IamPolicy | `attachment STRING (managed/inline)` | raw |
| `GRANTS` | IamPolicy -> StorageBucket, Database, Secret, IamRole, ServerlessFunction, CloudAccount | `actions STRING[]`, `access_level STRING (list/read/write/admin)`, `resource_pattern STRING` | raw |
| `CAN_ASSUME` | IamRole, IamUser, HumanUser -> IamRole | `via STRING (trust_policy/sso_permission_set)`, `cross_account BOOLEAN` | raw (from trust policies) |
| `HAS_ACCESS_KEY` | IamUser -> AccessKey | | raw |
| `MEMBER_OF` | HumanUser -> Group, Team | | raw |
| `MAPS_TO` | HumanUser, Group -> IamRole, IamUser | `via STRING (sso/federation/static)` | raw |
| `CAN_ACCESS` | IamRole, IamUser, HumanUser, VirtualMachine, Workload, ServerlessFunction -> StorageBucket, Database, Secret | `access_level STRING`, `path_length INT64`, `via STRING` (comma-joined node ids on the path), `transitive BOOLEAN` | derived (effective access after policy + role-chain evaluation; depth <= 4) |
| `UNLOCKS` | Secret -> Database, StorageBucket, IamUser, IamRole | `credential_type STRING` | raw (a secret contains credentials for a target) |
| `CREDENTIAL_FOR` | Credential -> IamRole, IamUser, ServiceAccount, HumanUser, AccessKey | | raw/derived |
| `DERIVED_FROM` | Credential -> Credential | `via STRING (assume_role/session)` | derived |

### 4.3 Business context
| Type | From -> To | Typed columns | Kind |
|---|---|---|---|
| `PART_OF` | VirtualMachine, Workload, StorageBucket, Database, ServerlessFunction, Secret, KubernetesCluster, IamRole -> Application | | raw |
| `OWNED_BY` | Application, VirtualMachine, StorageBucket, Database -> Team | | raw |
| `LEADS` | HumanUser -> Team | | raw |
| `DEPENDS_ON` | Application -> Application, VirtualMachine, Database, StorageBucket, Secret | `dependency_type STRING` | raw (used by containment simulation: what breaks) |

### 4.4 Endpoint telemetry
| Type | From -> To | Typed columns | Kind |
|---|---|---|---|
| `SAME_AS` | Endpoint -> VirtualMachine | `method STRING (instance_id/hostname_ip/hostname_only)`, `confidence DOUBLE` | derived (entity resolution) |
| `PRIMARY_USER` | Endpoint -> HumanUser | | raw |
| `LOGGED_ON` | HumanUser, ServiceAccount -> Endpoint | `logon_type STRING`, `logon_time TIMESTAMP`, `source_ip STRING`, `session_id STRING` | raw |
| `RAN_ON` | Process -> Endpoint | | raw |
| `RAN_AS` | Process -> HumanUser, ServiceAccount | | raw |
| `SPAWNED` | Process -> Process | | raw |
| `EXECUTED` | Process -> File | `action STRING (executed/wrote/read/loaded)` | raw |
| `CONNECTED_TO` | Process, Endpoint -> IpAddress, Domain | `port INT64`, `protocol STRING`, `direction STRING (outbound/inbound)`, `count INT64`, `bytes_out INT64`, `first_time TIMESTAMP`, `last_time TIMESTAMP` | raw |
| `LATERAL_MOVEMENT_TO` | Endpoint -> Endpoint | `protocol STRING (ssh/rdp/smb/winrm/psexec)`, `account STRING`, `time TIMESTAMP`, `alert_id STRING` | derived (from logon + network + detection correlation) |
| `ACCESSED_CREDENTIAL` | Process -> Credential | `method STRING (lsass_read/file_read/imds/browser_store)` | raw |

### 4.5 Alerts, events, incidents, storylines
| Type | From -> To | Typed columns | Kind |
|---|---|---|---|
| `ON_ENDPOINT` | Alert -> Endpoint | | raw |
| `ON_RESOURCE` | Alert -> VirtualMachine, StorageBucket, Database, IamRole, IamUser, SecurityGroup, LoadBalancer, ServerlessFunction, Workload, KubernetesCluster, HumanUser, AccessKey, Secret, CloudAccount | | raw |
| `INVOLVES` | Alert -> Process, File, IpAddress, Domain, Credential, HumanUser, ServiceAccount, IamRole, AccessKey, CloudEvent | `role STRING (subject/object/source/destination/credential)` | raw |
| `USES_TECHNIQUE` | Alert, ThreatActor, Campaign, Malware -> AttackTechnique | | raw |
| `PART_OF_INCIDENT` | Alert -> Incident | | raw |
| `STOLEN_BY` | Credential -> Alert, Process | `method STRING` | derived |
| `USED_CREDENTIAL` | CloudEvent -> Credential | | raw |
| `PERFORMED_BY` | CloudEvent -> IamRole, IamUser | | raw |
| `TARGETED` | CloudEvent -> StorageBucket, Database, Secret, IamRole, CloudAccount, IamUser | | raw |
| `FROM_IP` | CloudEvent -> IpAddress | | raw |
| `ASSUMED` | CloudEvent -> IamRole | | raw (AssumeRole events) |
| `IN_STORYLINE` | Alert, CloudEvent, Endpoint, VirtualMachine, Credential, IamRole, StorageBucket, Secret, Database, HumanUser -> Storyline | `stage INT64`, `role STRING` | derived |
| `NEXT_STAGE` | Alert -> Alert, CloudEvent; CloudEvent -> CloudEvent | `storyline_id STRING`, `stage INT64` | derived (ordered kill chain) |

### 4.6 Threat intelligence
| Type | From -> To | Typed columns | Kind |
|---|---|---|---|
| `ATTRIBUTED_TO` | Campaign -> ThreatActor; Alert, Storyline -> Campaign, ThreatActor | `confidence DOUBLE`, `basis STRING (ioc/ttp/report/derived)` | raw for Campaign->Actor, derived otherwise |
| `USES_MALWARE` | ThreatActor, Campaign -> Malware | | raw |
| `INDICATES` | Indicator -> Malware, Campaign, ThreatActor | | raw |
| `EXPLOITS` | ThreatActor, Campaign -> Vulnerability | `status STRING (poc_public/active/mass_exploitation)`, `first_seen TIMESTAMP` | raw |
| `REPORTS_ON` | IntelReport -> ThreatActor, Campaign, Malware, Vulnerability, Indicator, AttackTechnique | | raw |
| `MATCHES_IOC` | IpAddress, Domain, File, Process, Alert, CloudEvent -> Indicator | `match_type STRING (exact/fuzzy)`, `confidence DOUBLE` | derived |
| `TARGETS` | ThreatActor, Campaign -> Application, CloudAccount | `basis STRING` | derived (sector + technology overlap, low confidence) |

## 5. Entity resolution rules (the crux)

The EDR device record and the cloud VM record describe the same machine. The resolver emits `SAME_AS` with a method and confidence:

1. `instance_id` (0.99): the sensor's cloud metadata `instance_id` + `account_id` equals a VM's `source_id` + `account_id`.
2. `hostname_ip` (0.9): normalized hostname (lowercase, strip domain) equals the VM `name` or hostname prefix **and** private IP matches within the last seen window.
3. `hostname_only` (0.6): normalized hostname equality only; flagged `needs_review: true` in props.

Identities: `HumanUser` (Okta login) is the hub. EDR process/logon user strings like `CORP\dwhitfield` or `dwhitfield@corp.larkspur.example` resolve to `user:okta:dwhitfield`. Linux local accounts resolve to `ServiceAccount` nodes scoped by host. AWS SSO permission sets create `MAPS_TO` edges from HumanUser/Group to IamRole.

Credentials are first-class nodes because they are the join key between endpoint theft and cloud use: when an endpoint detection reports credential access (LSASS, IMDS, key file) the generator creates a `Credential` with `STOLEN_BY` from the alert and `CREDENTIAL_FOR` to the principal; when a cloud event uses an access key id, it links `USED_CREDENTIAL` to the same `Credential` node if the key id matches (or creates an `unknown` credential otherwise).

## 6. Derived enrichment expected in `nodes.jsonl` / `edges.jsonl`

The simulator pipeline runs these derivations before writing the graph files (the analytics library re-computes them at load for verification):

1. `EXPOSES` edges from security groups, public ACLs, function URLs, internet-facing load balancers.
2. `VULNERABLE_TO` edges rolled up from packages.
3. `CAN_ACCESS` effective-access edges: policy GRANTS -> resources, then propagated across `CAN_ASSUME` chains up to 4 hops and across `HAS_ROLE` to compute assets; `via` lists the intermediate node ids.
4. `SAME_AS` entity resolution.
5. `MATCHES_IOC` between telemetry (IPs, domains, file hashes) and indicators; `ATTRIBUTED_TO` from alerts to campaigns/actors when their entities match IOCs or when TTP overlap with a campaign is high.
6. Vulnerability TI overlay: `exploitation_status`, `actor_interest`, `sector_targeting_relevance`, `ti_report_ids` on `Vulnerability` nodes from `EXPLOITS` and reports; `ti_exposure_score` on internet-exposed assets carrying those vulnerabilities.
7. `LATERAL_MOVEMENT_TO` from cross-host logons that follow a detection.
8. Storyline correlation: alerts and cloud events chained by shared entities (host, credential, IP, IOC/campaign) and time ordering into `Storyline` nodes with `IN_STORYLINE` and `NEXT_STAGE` edges.
9. Contextual scoring on every `Alert` (`contextual_score`, `contextual_band`, `score_breakdown`, `graph_reasons`, `reaches_crown_jewel`, `on_attack_path`).

## 7. Graph fragment shape returned by the API (for UI and agent)

```json
{"nodes":[{"id":"...","label":"VirtualMachine","name":"bas-01","category":"cloud","severity":null,"highlight":true,"props":{...}}],
 "edges":[{"id":"src|TYPE|dst","type":"HAS_ROLE","src":"...","dst":"...","highlight":true,"props":{...}}],
 "focus":["alert:falcon:ldt-a009"],
 "layout_hint":"neighborhood|path|blast_radius"}
```
Edge ids are `src|TYPE|dst`. `category` comes from the label group above. Fragments are capped (default 150 nodes, 400 edges) and say `truncated: true` when capped.
