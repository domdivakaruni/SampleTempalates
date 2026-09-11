/* eslint-disable */
/** Alert fixtures: the spec shape, the graph writer and the AlertSummary projection. */
import type { AlertSummary, JsonValue, Props, Severity } from '../../types'
import { bandForScore, SEVERITY_RANK } from '../../types'
import type { MockGraph } from '../graph'
import { ID } from './ids'

export interface AlertSpec {
  id: string
  title: string
  description: string
  source: string
  type: string
  severity: Severity
  detected_at: string
  status?: string
  entity_id: string
  hostname?: string
  user?: string
  techniques?: string[]
  tactic?: string
  storyline_id?: string
  score: number
  reasons: string[]
  reaches_crown_jewel?: boolean
  on_attack_path?: boolean
  ioc_match_count?: number
  ti_actor_ids?: string[]
  incident?: string
  change_ticket?: string
  flat: Record<string, JsonValue>
  involves?: [string, string][]
}

const TECH_NAMES: Record<string, [string, string, number]> = {
  'T1566.001': ['Spearphishing Attachment', 'Initial Access', 1],
  'T1204.002': ['User Execution: Malicious File', 'Execution', 1],
  'T1059.001': ['PowerShell', 'Execution', 1],
  'T1218.011': ['Rundll32', 'Defense Evasion', 1],
  T1055: ['Process Injection', 'Defense Evasion', 2],
  'T1547.001': ['Registry Run Keys', 'Persistence', 2],
  'T1071.001': ['Web Protocols (C2)', 'Command and Control', 2],
  'T1573.002': ['Asymmetric Cryptography (C2)', 'Command and Control', 2],
  'T1003.001': ['LSASS Memory', 'Credential Access', 3],
  'T1552.001': ['Credentials In Files', 'Credential Access', 3],
  'T1087.002': ['Domain Account Discovery', 'Discovery', 3],
  T1018: ['Remote System Discovery', 'Discovery', 3],
  'T1021.004': ['Remote Services: SSH', 'Lateral Movement', 4],
  T1078: ['Valid Accounts', 'Defense Evasion', 4],
  'T1003.008': ['/etc/passwd and /etc/shadow', 'Credential Access', 4],
  'T1552.005': ['Cloud Instance Metadata API', 'Credential Access', 4],
  'T1078.004': ['Valid Accounts: Cloud Accounts', 'Defense Evasion', 5],
  T1580: ['Cloud Infrastructure Discovery', 'Discovery', 5],
  'T1548.005': ['Temporary Elevated Cloud Access', 'Privilege Escalation', 6],
  T1530: ['Data from Cloud Storage', 'Collection', 7],
  'T1567.002': ['Exfiltration to Cloud Storage', 'Exfiltration', 7],
  'T1595.002': ['Vulnerability Scanning', 'Reconnaissance', 1],
  T1190: ['Exploit Public-Facing Application', 'Initial Access', 1],
  'T1059.004': ['Unix Shell', 'Execution', 1],
  'T1505.003': ['Web Shell', 'Persistence', 2],
  T1105: ['Ingress Tool Transfer', 'Command and Control', 2],
  'T1569.002': ['Service Execution (PsExec)', 'Execution', 4],
  'T1110.003': ['Password Spraying', 'Credential Access', 1],
  'T1059.003': ['Windows Command Shell', 'Execution', 1],
  T1027: ['Obfuscated Files or Information', 'Defense Evasion', 2],
  'T1566.002': ['Spearphishing Link', 'Initial Access', 1],
  T1046: ['Network Service Discovery', 'Discovery', 3],
}

export function ensureTechnique(g: MockGraph, tid: string): string {
  const id = ID.TECH(tid)
  if (!g.has(id)) {
    const [name, tactic, stage] = TECH_NAMES[tid] ?? [tid, 'Unknown', 1]
    g.node(id, `${tid} ${name}`, { technique_id: tid, tactic, kill_chain_stage: stage, description: name }, { label: 'AttackTechnique' })
  }
  return id
}

export function addAlert(g: MockGraph, spec: AlertSpec): void {
  const entity = g.get(spec.entity_id)
  const props: Props = {
    source_system: spec.source,
    alert_type: spec.type,
    title: spec.title,
    description: spec.description,
    vendor_severity: spec.severity,
    vendor_severity_rank: SEVERITY_RANK[spec.severity],
    status: spec.status ?? 'new',
    detected_at: spec.detected_at,
    techniques: spec.techniques ?? [],
    tactic: spec.tactic ?? null,
    entity_id: spec.entity_id,
    entity_label: entity?.label ?? null,
    hostname: spec.hostname ?? null,
    user: spec.user ?? null,
    vendor_incident_id: spec.incident ? spec.incident.split(':').pop() : null,
    change_ticket: spec.change_ticket ?? null,
    contextual_score: spec.score,
    contextual_band: bandForScore(spec.score),
    storyline_id: spec.storyline_id ?? null,
    graph_reasons: spec.reasons,
    ti_actor_ids: spec.ti_actor_ids ?? [],
    ioc_match_count: spec.ioc_match_count ?? 0,
    reaches_crown_jewel: spec.reaches_crown_jewel ?? false,
    on_attack_path: spec.on_attack_path ?? false,
    source: `${spec.source}-sim`,
    first_seen: spec.detected_at,
    last_seen: spec.detected_at,
    raw: spec.flat,
  }
  const tags: string[] = []
  if (spec.storyline_id) tags.push(`storyline:${spec.storyline_id.split(':').pop()}`)
  if (spec.ioc_match_count) tags.push('ioc_match')
  if (spec.reaches_crown_jewel) tags.push('reaches_crown_jewel')
  if (spec.on_attack_path) tags.push('on_attack_path')
  g.node(spec.id, spec.title, props, { label: 'Alert', severity: spec.severity, score: spec.score, tags })
  if (entity) g.edge(spec.id, entity.label === 'Endpoint' ? 'ON_ENDPOINT' : 'ON_RESOURCE', spec.entity_id)
  for (const t of spec.techniques ?? []) g.edge(spec.id, 'USES_TECHNIQUE', ensureTechnique(g, t))
  if (spec.incident && g.has(spec.incident)) g.edge(spec.id, 'PART_OF_INCIDENT', spec.incident)
  for (const [nid, role] of spec.involves ?? []) if (g.has(nid)) g.edge(spec.id, 'INVOLVES', nid, { role })
}

export function toSummary(g: MockGraph, spec: AlertSpec): AlertSummary {
  const entity = g.get(spec.entity_id)
  return {
    id: spec.id,
    title: spec.title,
    source_system: spec.source,
    alert_type: spec.type,
    vendor_severity: spec.severity,
    vendor_severity_rank: SEVERITY_RANK[spec.severity],
    contextual_score: spec.score,
    contextual_band: bandForScore(spec.score),
    detected_at: spec.detected_at,
    status: spec.status ?? 'new',
    entity_id: spec.entity_id,
    entity_name: entity?.name ?? spec.hostname ?? spec.entity_id,
    entity_label: entity?.label ?? null,
    hostname: spec.hostname ?? null,
    user: spec.user ?? null,
    techniques: spec.techniques ?? [],
    storyline_id: spec.storyline_id ?? null,
    graph_reasons: spec.reasons,
    reaches_crown_jewel: spec.reaches_crown_jewel ?? false,
    on_attack_path: spec.on_attack_path ?? false,
    ioc_match_count: spec.ioc_match_count ?? 0,
    ti_actor_ids: spec.ti_actor_ids ?? [],
    vendor_rank_position: null,
    contextual_rank_position: null,
  }
}

/** Falcon-console-shaped flat view. */
export function falconFlat(o: { host: string; sev: string; tactic: string; technique: string; user: string; file: string; cmdline: string; parent?: string; sha?: string; ip: string; platform: string; ts: string; incident?: string; objective?: string; disposition?: string; extra?: Record<string, JsonValue> }): Record<string, JsonValue> {
  return {
    detection_id: `ldt:${o.host.toLowerCase()}:${o.ts.replace(/\D/g, '').slice(4, 14)}`,
    hostname: o.host,
    severity: o.sev,
    severity_name: o.sev,
    tactic: o.tactic,
    technique: o.technique,
    objective: o.objective ?? 'Follow Through',
    user_name: o.user,
    file_name: o.file,
    cmdline: o.cmdline,
    parent_cmdline: o.parent ?? '',
    sha256: o.sha ?? '',
    local_ip: o.ip,
    platform_name: o.platform,
    sensor_version: '7.18.19507',
    pattern_disposition: o.disposition ?? 'Detection only',
    status: 'new',
    incident_id: o.incident ?? '',
    first_behavior: o.ts,
    last_behavior: o.ts,
    ...(o.extra ?? {}),
  }
}
