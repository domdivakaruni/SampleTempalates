# Product Definition: Prototype v0

**One line:** A security context graph that fuses cloud posture, endpoint (EDR) runtime telemetry, and threat-intelligence impact so that a human or AI analyst can answer multi-hop questions about an alert that no single tool can answer today.

> **Fiction disclaimer.** All companies, people, threat actors, campaigns, malware families, domains, and reports in this document are fictional. Real CVE identifiers are referenced for realism; any attribution of a real CVE to a fictional actor is fictional. `.example` domains are used throughout because that TLD is reserved for documentation.

**Assumptions I am making (stated, not asked):**
- We model **AWS-style** cloud primitives (EC2 instances, IAM roles/policies, STS AssumeRole, S3, access keys, IMDS) for concreteness. The graph schema is provider-agnostic; Azure/GCP equivalents map onto the same node/edge types. We are not affiliated with any cloud provider.
- The prototype ships with **100% simulated data** and must run **offline with no LLM API key** (deterministic traversals + templated narration), upgrading to richer natural-language answers when a key is present.
- EDR schema is modeled on **CrowdStrike Falcon / Cortex XDR** concepts (sensors, processes, detections, incidents, logons, network connections, file hashes). We do not use any vendor's proprietary data.
- Scope is a **demo prototype**, not production. Scale, multi-tenancy, and real ingestion are explicitly out of scope.

---

## 1. Product name and simulated customer

**Candidate names**

| Name | Evokes | Note |
|---|---|---|
| **Throughline** | The single thread connecting scattered alerts into one attack story and its blast radius | On-thesis; low category conflict in security |
| Meridian | A commanding line of sight across the whole estate | Strong, but heavy conflict with fintech/health brands (our buyers) |
| Contour | The blast-radius "contour" drawn around each alert | Short and visual; conflicts with the CNCF Contour ingress project |
| Adjacency | Every answer is one hop away (a pure graph term) | Clean and ownable; a little abstract as a spoken brand |
| Weft | The cross-threads (EDR + cloud + TI) woven through your telemetry | Distinctive and ownable; the word is slightly obscure |

**Pick: Throughline.** It names the job precisely: the platform finds the *throughline* that connects endpoint, cloud, identity, data, and intel signals into one attack story and its blast radius. Trademark and domain clearance is an open item (candidates: `throughline.security`, `thruline.io`).

**Simulated customer: Larkspur Financial ("Larkspur").** A mid-size fintech (~1,400 employees) offering a consumer digital wallet, card issuing, and a banking-as-a-service API. Cloud-native. It holds both **PII** (customer identity/KYC) and **PCI** cardholder data, which makes "can an attacker reach regulated data?" the question that matters. Corp domain `corp.larkspur.example`; production account `larkspur-prod`; crown-jewel store `s3://larkspur-cardholder-vault`.

---

## 2. Purpose and positioning

**Purpose.** Security teams run one tool that maps cloud posture, a second that watches endpoints, and a third (usually a PDF) that describes who is attacking whom. Each tool is blind to the other two, so the work of connecting them, deciding what actually matters, and explaining why falls on a human at 2 a.m. Throughline builds one graph across all three and makes that connective reasoning queryable, so that the right alert rises to the top with a defensible explanation, whether the analyst is a person or an agent.

**Positioning statement.** *Throughline is the security context graph that connects endpoint activity, cloud blast radius, and live threat intelligence, so every alert arrives already answered: what it touches, how bad it really is, and why.*

**Why now.**
- The **graph model is proven for posture** (Wiz-style): teams already trust a graph to reason about cloud exposure and toxic combinations. But that graph stops at the cloud boundary and is blind to what is happening *on the endpoint right now*.
- **EDR is blind to cloud blast radius.** A credential-theft detection on a host is "medium" in isolation; the console has no idea the host is a bastion whose instance role can read the cardholder vault.
- **Threat intel sits in PDFs.** Knowing that an actor is actively exploiting a CVE against fintechs is useless until you can point at *which of your hosts match*.
- **The SOC is going agentic.** Agents need deterministic, typed traversals and cited evidence, not a pile of consoles to click through. A graph is the substrate an agent can actually reason over.

---

## 3. Users and jobs-to-be-done

| User | Primary job-to-be-done | What they need from Throughline |
|---|---|---|
| **SOC Tier-1 analyst** | Triage the queue fast; escalate or close | Contextual score with a one-line "why"; auto-grouping of related alerts into one incident |
| **SOC Tier-2 / Incident Responder** | Scope and contain an active incident | Full cross-domain attack path, blast radius, and a "what breaks if I contain this" simulation |
| **Cloud security engineer** | Fix exposure and over-privilege | Attack-path-to-data view, transitive IAM reachability, remediation ranked by real impact |
| **Threat intel analyst** | Operationalize intel | Attach a report to graph objects; instantly see which assets match an actor/campaign/IOC |
| **AI agent analyst** | Investigate and draft findings autonomously | Typed tools, **deterministic traversals**, stable node/edge IDs, evidence with provenance, read-only guarantees, and reproducible answers offline |

---

## 4. The graph advantage: questions the demo must answer

Each row is a question the analyst types, the data sources and hop sequence that answer it, and why a siloed tool cannot.

| # | Analyst question (as typed) | Sources and hop sequence | Why a silo can't answer |
|---|---|---|---|
| 1 | "Show me everything connected to the credential-dumping alert on BAS-01 — what can an attacker reach from here?" | Detection(T1003) -> Endpoint(BAS-01) -> CloudVM(i-0bastion) -> InstanceRole(bastion-ssm) -> AssumeRole -> Role(prod-data-reader) -> Policy -> S3(cardholder-vault: PCI) | EDR stops at the host; it doesn't know the host is a cloud VM with a role that reaches PCI. CSPM sees the role but not the fresh compromise. |
| 2 | "Which of today's medium-severity endpoint alerts sit on assets with a path to regulated data?" | Detections(sev=med) -> Endpoints -> CloudVM -> InstanceRole -> reachable Roles -> Policies -> DataStore(tag in PCI,PII) | EDR can't rank by cloud data blast radius; CSPM never sees endpoint alerts. |
| 3 | "Is the cloud API activity from the bastion role in the last 6 hours related to any endpoint detection?" | CloudEvent(AssumeRole, S3:GetObject) -> InstanceRole -> CloudVM -> Endpoint -> Detection(same host/time) | Cloud audit log and EDR are separate systems with no shared join key (host <-> instance <-> role). |
| 4 | "What is the blast radius if identity 'svc-bastion' is fully compromised?" | Role -> all AssumeRole edges -> reachable Roles -> Policies -> Resources(compute, secrets, data) -> tags(sensitivity) | Needs the transitive permission graph; an IAM console shows one hop, not transitive reach. |
| 5 | "Which internet-exposed hosts have a vuln a threat actor is actively exploiting against fintechs right now?" | Compute(exposure=public) -> Vulnerability(CVE) <- TI(exploitation=active, sector=fintech, actor=Hollow Tide); then Compute -> InstanceRole -> blast radius | CSPM knows exposure+CVE but not real-world exploitation/actor targeting; the TI PDF knows the campaign but not which of *your* hosts match. |
| 6 | "Rank all open issues by contextual risk, not vendor severity, and explain the top 3." | All Issues -> joined context (exposure, privilege, data sensitivity, TI, incident correlation) -> contextual score | No single tool holds all five inputs. |
| 7 | "Trace the full attack path from the phishing detection on WKS-3391 to any regulated data store." | Detection(T1566/T1204) -> Endpoint(WKS-3391) -> lateral(SSH) -> Endpoint(BAS-01) -> CloudVM -> InstanceRole -> Role -> S3(PCI) | The path crosses endpoint lateral movement *and* cloud privilege escalation; no one console spans both. |
| 8 | "Which credentials used in cloud API calls today were seen being stolen on an endpoint?" | CloudEvent(role/key) -> Credential <- Detection(T1552.005 IMDS or T1003 LSASS) on Endpoint | The credential is the join key: EDR sees theft, cloud sees use, neither links them. |
| 9 | "Do any current detections match IOCs or TTPs from the Cinder Jackal report, and what do they touch?" | TI(IOC hash/domain, TTP) -> matched Detections/CloudEvents -> connected assets -> data | TI lives in a PDF; matching it to live telemetry and mapping impact is manual today. |
| 10 | "Show only alerts on assets that can reach cardholder data; hide everything else." | S3(PCI) <- reverse reachability -> Roles -> InstanceRoles -> CloudVMs -> Endpoints -> Detections | A reverse blast-radius filter requires the graph; EDR/CSPM can't filter alerts by data reachability. |
| 11 | "Is the 'S3 bucket public' critical finding actually risky — what's in it and can an actor reach it?" | Issue(public-bucket) -> S3 -> object tags(sensitivity) -> TI(actor interest) -> contextual score | CSPM flags exposure by config, not by data value or actor interest, so it over-alerts. |
| 12 | "If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?" | Endpoint/Role -> dependency edges (what breaks) + attack-path edges (what is cut) | Needs both the operational dependency graph and the attack-path graph; ops and security tools are separate. |

---

## 5. Threat-intel impact metadata and the contextual risk score

### 5.1 Impact fields attached to graph objects

Each simulated intel report is a structured record (fictional author org, date, actors, campaigns, targeted sectors, CVEs, IOC list, TTP list, exploitation status, narrative). An ingestion step maps its fields onto graph objects and stamps the following **impact metadata** on the affected nodes:

| Field | Meaning | Derived from |
|---|---|---|
| `exploitation_status` | none / poc_public / active / mass_exploitation | Report's exploitation field + a simulated KEV-style flag |
| `actor_interest[]` | Which fictional actors target this CVE / asset type / sector, with confidence and last-seen | Report actor + targeting sections |
| `campaign_linkage[]` | Campaign IDs referencing this object via an IOC or TTP match | IOC/TTP match to live telemetry |
| `sector_targeting_relevance` | 0-1: how strongly the actor targets our sector (fintech) | Report's "targeted sectors" vs customer profile |
| `ioc_match` | {type: hash/domain/ip/ja3, value, confidence, report_id} when a detection or cloud event matches an IOC | Direct match of telemetry to report IOCs |
| `ttp_overlap` | Count/ratio of MITRE technique IDs on the asset that match the actor's known TTPs | Overlap of detection techniques vs report TTPs |
| `kill_chain_stage` | Most advanced matched stage (recon -> actions-on-objectives) | Highest-stage matched detection |
| `ti_adjusted_exposure_score` | Exposure re-weighted by exploitation x actor interest x sector relevance | Computed from the above |
| `report_id` / `report_confidence` | Provenance back to the simulated report | Report metadata |

**Provenance is mandatory:** every TI field carries the `report_id` it came from, so an analyst or agent can always click through to the (simulated) source.

### 5.2 Contextual risk score (simple and explainable)

Vendor severity is the *input*, not the answer. The score re-ranks each alert on a 0-100 scale using six normalized (0-1) factors:

- **S** = vendor severity (info .1, low .25, med .5, high .75, crit 1.0)
- **E** = exposure (internet-exposed 1.0, internal .4, isolated .1)
- **P** = privilege reach (transitive count of sensitive resources the asset's identity can reach, normalized; admin -> 1.0)
- **D** = data sensitivity reachable (PCI/PII/secrets 1.0, internal .5, public 0)
- **T** = TI relevance (`ti_adjusted`: active exploitation + actor targeting our sector + IOC match -> 1.0)
- **C** = incident correlation (1.0 if the alert lies on a confirmed multi-stage attack path; otherwise scaled by number of correlated alerts)

```
Context = 0.15*E + 0.20*P + 0.25*D + 0.20*T + 0.20*C          (weights sum to 1)
Score   = 100 * ( 0.30*S + 0.70*Context )                     (context dominates severity)
```

Two "rails" produce the demo's aha moments and keep the score honest:

- **Attack-path floor:** if C shows the alert is on a confirmed path to regulated data, floor the Score at **90 (Critical)**.
- **No-context ceiling:** if D=0 and T<0.1 and P<0.2 (no data reach, no intel, no privilege), cap the Score at **25 (noise)**, regardless of vendor severity.
- **TI booster:** if `exploitation_status` is active/mass **and** `sector_targeting_relevance` >= 0.7, floor the Score at **80**.

**Worked examples (these drive the live demo):**

| Alert | Vendor sev | S | E | P | D | T | C | Raw | Rail | Final |
|---|---|---|---|---|---|---|---|---|---|---|
| BAS-01 credential dump (Campaign A) | Medium | .5 | .6 | 1.0 | 1.0 | .8 | 1.0 | 78 | attack-path floor | **92 Critical (#1)** |
| Log4Shell host `i-0edge2a` (Campaign B) | Medium | .5 | 1.0 | .7 | .8 | 1.0 | .3 | 68 | TI booster | **80 High (#2)** |
| Dev-sandbox EICAR test file | High | .75 | .1 | .1 | 0 | 0 | 0 | 25 | no-context ceiling | **25 Low (noise)** |
| "S3 bucket public" (marketing assets) | Critical | 1.0 | 1.0 | 0 | 0 | 0 | 0 | 41 | no-context ceiling | **25 Low (noise)** |

The score is always shown with its factor breakdown so it never reads as a black box.

---

## 6. Demo storyline

Three things run at once in the simulated estate: a full targeted intrusion (Campaign A), an unrelated opportunistic exploitation (Campaign B), and background noise. Prioritization only matters because all three are live simultaneously.

### Campaign A — "EMBERCAST" by actor **Cinder Jackal** (fictional eCrime, fintech-focused)

Malware families (fictional): **MAPLELOADER** (initial loader), **QUILLDROP** (LSASS/credential stealer), **NIGHTFERRY** (C2 implant). C2 domain (defanged, fictional): `cdn-metrics.telemetry-sync[.]net`.

| Stage | What happens | EDR detections (MITRE) | Flat EDR console shows | Graph reveals |
|---|---|---|---|---|
| 1. Initial access | Dana Whitfield (AP clerk) opens an ISO -> LNK -> MAPLELOADER on `WKS-3391` | T1566.001, T1204.002, T1059.001, T1055 | One "high" malicious-file alert among dozens | Entry point of a chain; user's group and access mapped |
| 2. Persistence + C2 | NIGHTFERRY installed, beacons out | T1547.001, T1071.001, T1573 | A separate "beaconing" alert; IOC not correlated | C2 domain matches Cinder Jackal IOC in TI |
| 3. Credential access | QUILLDROP dumps LSASS; finds a stored SSH key | T1003.001, T1552.001, T1087, T1018 | A **medium** "credential dumping" alert (one of many that day) | Stolen SSH key becomes a Credential node linking to its next use |
| 4. Lateral movement | SSH to bastion `BAS-01` (= cloud VM `i-0bastion`); dumps creds again; steals instance-role creds from IMDS | T1021.004, T1078, T1003, **T1552.005** | Two hosts, unrelated **medium** alerts | **Pivot point:** BAS-01 is a bastion + cloud VM; IMDS theft bridges endpoint -> cloud |
| 5. Cloud API abuse | Instance-role creds used: `GetCallerIdentity`, `ListBuckets` from a new ASN | T1078.004, T1580, T1552.005 (cloud) | *Nothing* (EDR has no cloud visibility) | Same credential from stage 4; unusual geo on a role tied to a compromised host |
| 6. Privilege escalation | Cross-account `AssumeRole`: bastion-ssm -> prod-data-reader | T1548, T1098 | *Nothing* | Role chain crosses into `larkspur-prod` |
| 7. Collection / exfil | Mass `s3:GetObject` on `s3://larkspur-cardholder-vault` | T1530, T1567.002 | *Nothing* | Blast radius = cardholder vault (PCI) + 2 secrets |

**Flat view vs graph.** A flat EDR console shows stages 1-4 as a handful of medium/high alerts on two hosts, buried in the day's queue, and is completely blind to stages 5-7. The cloud audit log shows stages 5-7 as "valid credential" API calls that look legitimate, with no link back to the endpoint compromise. Throughline joins all seven stages into one attack path whose blast radius is the cardholder vault.

### Campaign B — "SALTWORKS" by actor **Hollow Tide** (fictional access broker, ransomware-linked)

An internet-facing production instance `i-0edge2a` runs Larkspur's Java "statement-render" service, vulnerable to **CVE-2021-44228 (Log4Shell)**. In our simulation Hollow Tide is mass-exploiting this CVE across fintechs and has (fictionally) been linked to follow-on ransomware; it drops the **BRACKISH** webshell. The WAF/IDS logs one **medium** JNDI-exploit-string alert that looks like background scan noise.

**Flat view vs graph.** The WAF sees one exploit string among thousands. Throughline confirms the host is actually exposed (`0.0.0.0/0` on 8080), confirms it is vulnerable (SBOM shows `log4j-core 2.14`), matches Hollow Tide's active, sector-targeting campaign via TI, and shows the host's instance role can read a config bucket holding DB credentials. Contextual score jumps to 80, ranked #2, driven entirely by exposure x exploitation x TI x blast radius, with no endpoint kill chain at all.

### Background noise (so prioritization matters)

- Dev-sandbox EICAR test-file detection (vendor High) on an isolated non-prod VM with no data path -> noise.
- Internal vulnerability scanner's IP triggering hundreds of IDS "exploit attempt" alerts -> known scanner, noise.
- Admin `mreyes` using PsExec (T1569.002) during an approved change window -> matches a change ticket, benign.
- "S3 bucket public" critical CSPM finding on the public marketing-assets bucket -> no sensitive data, no actor interest -> noise.
- Impossible-travel login for an exec actually on corporate VPN -> benign.
- A dozen low-value quarantined-attachment detections (blocked pre-execution) -> noise.

---

## 7. Prototype feature scope

**Data simulation**
- MUST: cloud estate (accounts, VMs, roles, policies, S3, keys, security groups, IMDS), EDR telemetry (sensors, processes, detections with MITRE IDs, logons, network connections, hashes), TI reports (structured JSON), and the three storylines above with realistic noise volume.
- SHOULD: a seed/regenerate script so the demo is reproducible; tunable noise level.
- COULD: adjustable "attacker speed" and alternate variants of Campaign A.

**Graph model**
- MUST: typed nodes (Account, CloudVM, Endpoint, Identity/Role, Policy, Credential, DataStore, Vulnerability, Detection, CloudEvent, Issue, TIReport, Actor, Campaign) and typed edges (RUNS_ON, HAS_ROLE, CAN_ASSUME, GRANTS, REACHES, STOLEN_AS, USED_IN, MATCHES_IOC, EXPLOITS, PART_OF_INCIDENT). Stable IDs.
- SHOULD: entity resolution that joins host <-> instance <-> identity <-> credential (this is the crux of the whole product).
- COULD: temporal edges (validity windows) for point-in-time queries.

**Analytics**
- MUST: blast-radius (forward reachability to sensitive data), attack-path reconstruction across domains, contextual prioritization score with breakdown, TI impact stamping.
- SHOULD: reverse reachability ("what can reach the vault"), incident correlation/grouping.
- COULD: containment simulation ("what breaks if I isolate/rotate").

**UI**
- MUST: dashboard, alert/issue table (vendor severity next to contextual score), alert detail with **Flat view vs Graph context** tabs, graph explorer, threat-intel page, chat drawer.
- SHOULD: click a chat answer to highlight its evidence subgraph on the canvas; saved traversals.
- COULD: timeline scrubber of the intrusion.

**Analyst agent**
- MUST: typed tools (`get_alert`, `traverse`, `blast_radius`, `attack_path`, `ti_match`, `score_explain`), an **offline deterministic fallback** (canned traversals + templated narration) that works with no LLM key, and answers that cite node/edge IDs.
- SHOULD: LLM narration layer when a key is present; refusal to assert any node not returned by a traversal.
- COULD: draft an incident report with evidence citations.

**Agent-facing API**
- MUST: read-only, typed query endpoints returning graph fragments with stable IDs and provenance; deterministic ordering.
- SHOULD: an OpenAPI/tool schema so an external agent can drive it.
- COULD: a streaming traversal endpoint.

---

## 8. UI concept

Wiz-like **dark theme, left nav.** Screens:

- **Dashboard.** A contextual-risk leaderboard (top incidents, not top vendor-severity alerts), incident cards summarizing Campaign A and Campaign B, and a coverage panel. The vendor-severity queue is shown alongside for contrast so the re-ranking is visible.
- **Alerts / Issues table.** Columns: asset, vendor severity, **contextual score** (with up/down arrow vs vendor severity), "why" chips (e.g. *reaches PCI*, *active TI*, *on attack path*), and TI badges. Sortable by contextual score.
- **Alert detail.** Two tabs. *Flat view* = the raw EDR/CSPM fields exactly as the source tool shows them. *Graph context* = the evidence subgraph, the reconstructed attack path, the blast radius, and the contextual-score factor breakdown.
- **Graph explorer.** A pan/zoom canvas with node/edge type filters, saved traversals, and path highlighting. Selecting a node opens its properties and impact metadata.
- **Threat intel page.** Report list, and an actor/campaign/IOC/TTP library. Selecting a campaign highlights *the assets in your estate that match it*.
- **Chat drawer.** Right-side, always available. Answers are grounded in traversals, cite evidence, and can **highlight the evidence subgraph on the canvas** with one click.

---

## 9. Demo script (live founder walkthrough)

1. **Open the dashboard.** The contextual leaderboard shows #1 = Cinder Jackal intrusion reaching the cardholder vault, #2 = the actively exploited Log4Shell host. Point out that the vendor-severity queue would have buried both. "Notice #1 began life as a *medium* endpoint alert."
2. **Type:** *"Which of today's medium-severity endpoint alerts sit on assets with a path to regulated data?"* -> returns the BAS-01 credential-dump alert and highlights its path to the cardholder vault. **The "medium alert is actually #1" moment.**
3. **Open the BAS-01 alert.** Flip between *Flat view* ("OS Credential Dumping, medium, host BAS-01") and *Graph context* (the full path WKS-3391 -> BAS-01 -> instance role -> prod role -> PCI bucket, contextual score 92 with its breakdown).
4. **Chat:** *"Trace the full attack path from the phishing detection on WKS-3391 to any regulated data store."* -> the seven-stage path with MITRE IDs, blast radius = cardholder vault + 2 secrets.
5. **Chat:** *"Which credentials used in cloud API calls today were seen being stolen on an endpoint?"* -> links the IMDS theft (T1552.005) on BAS-01 to the AssumeRole and S3 GetObject events. Proves the endpoint-to-cloud correlation a flat stack cannot make.
6. **Chat:** *"Which internet-exposed hosts have a vuln an actor is actively exploiting against fintechs?"* -> the Log4Shell host, Hollow Tide TI, contextual 80. **The TI-driven prioritization moment.**
7. **Chat:** *"Is the 'S3 bucket public' critical finding actually risky?"* -> public marketing bucket, no sensitive data, no actor interest, contextual 25. **The "this alert is noise" moment.**
8. **Chat:** *"If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?"* -> containment simulation, then the agent drafts an incident summary with cited evidence. Close.

---

## 10. Success criteria, risks, open questions

**Success criteria**
- The graph answers all 12 questions in section 4 with correct multi-hop traversals, **deterministically and offline** (no LLM key required).
- The contextual score visibly re-ranks at least two alerts against vendor severity (one up to #1, one down to noise), each with a legible factor breakdown.
- A non-security viewer can follow the Campaign A attack story from the graph in under five minutes.
- The agent completes demo steps 2, 4, and 5 through typed tools, citing node/edge IDs, with **zero invented nodes**.

**Risks and open questions**
- **Over-fitting the demo to the script.** The noise must feel like real volume, or the prioritization win looks staged.
- **Entity resolution is the crux.** Joining host <-> instance <-> identity <-> credential is hard in reality; we should show it working and be honest that it is the core technical bet.
- **Score believability.** The "why" breakdown must always be visible or the score reads as a black box.
- **Chat grounding.** Deterministic traversal must be the source of truth; the LLM only narrates and must never assert an unreturned node.
- **Cloud coverage.** We model AWS-style primitives first; Azure/GCP mapping is asserted but unproven in v0.
- **Schema scope creep.** Keep node/edge types to the minimal set in section 7 for the prototype.
