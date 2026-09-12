/** UI mirror of throughline/schema/registry.py: labels, categories, id prefixes and edge kinds. */
import type { Category } from '../api/types'

export interface LabelMeta { name: string; category: Category; prefix: string; short: string }

export const CATEGORY_NAMES: Record<Category, string> = {
  cloud: 'Cloud & infrastructure',
  identity: 'Identity & access',
  software: 'Software & vulnerabilities',
  business: 'Business context',
  endpoint: 'Endpoint & runtime',
  alerts: 'Alerts, events & storylines',
  threat_intel: 'Threat intelligence',
  unknown: 'Other',
}

export const CATEGORY_ORDER: Category[] = ['alerts', 'endpoint', 'cloud', 'identity', 'software', 'business', 'threat_intel']

const L = (name: string, category: Category, prefix: string, short: string): LabelMeta => ({ name, category, prefix, short })

export const LABELS: LabelMeta[] = [
  L('CloudAccount', 'cloud', 'account', 'Account'),
  L('VPC', 'cloud', 'vpc', 'VPC'),
  L('Subnet', 'cloud', 'subnet', 'Subnet'),
  L('SecurityGroup', 'cloud', 'sg', 'Sec. group'),
  L('LoadBalancer', 'cloud', 'lb', 'Load balancer'),
  L('VirtualMachine', 'cloud', 'vm', 'VM'),
  L('KubernetesCluster', 'cloud', 'k8s', 'K8s cluster'),
  L('Workload', 'cloud', 'workload', 'Workload'),
  L('ContainerImage', 'cloud', 'image', 'Image'),
  L('ServerlessFunction', 'cloud', 'function', 'Function'),
  L('StorageBucket', 'cloud', 'bucket', 'Bucket'),
  L('Database', 'cloud', 'database', 'Database'),
  L('Secret', 'cloud', 'secret', 'Secret'),
  L('Internet', 'cloud', 'internet', 'Internet'),
  L('IpAddress', 'cloud', 'ip', 'IP'),
  L('Domain', 'cloud', 'domain', 'Domain'),
  L('IamRole', 'identity', 'role', 'IAM role'),
  L('IamUser', 'identity', 'iamuser', 'IAM user'),
  L('IamPolicy', 'identity', 'policy', 'Policy'),
  L('AccessKey', 'identity', 'accesskey', 'Access key'),
  L('ServiceAccount', 'identity', 'identity', 'Service acct'),
  L('HumanUser', 'identity', 'user', 'User'),
  L('Group', 'identity', 'group', 'Group'),
  L('Credential', 'identity', 'credential', 'Credential'),
  L('Package', 'software', 'package', 'Package'),
  L('Vulnerability', 'software', 'cve', 'CVE'),
  L('Application', 'business', 'app', 'Application'),
  L('Team', 'business', 'team', 'Team'),
  L('Endpoint', 'endpoint', 'endpoint', 'Endpoint'),
  L('Process', 'endpoint', 'process', 'Process'),
  L('File', 'endpoint', 'file', 'File'),
  L('LogonSession', 'endpoint', 'logon', 'Logon'),
  L('Alert', 'alerts', 'alert', 'Alert'),
  L('Incident', 'alerts', 'incident', 'Incident'),
  L('CloudEvent', 'alerts', 'cloudevent', 'Cloud event'),
  L('Storyline', 'alerts', 'storyline', 'Storyline'),
  L('ThreatActor', 'threat_intel', 'actor', 'Actor'),
  L('Campaign', 'threat_intel', 'campaign', 'Campaign'),
  L('Malware', 'threat_intel', 'malware', 'Malware'),
  L('AttackTechnique', 'threat_intel', 'technique', 'Technique'),
  L('Indicator', 'threat_intel', 'ioc', 'Indicator'),
  L('IntelReport', 'threat_intel', 'report', 'Report'),
]

export const LABEL_BY_NAME: Record<string, LabelMeta> = Object.fromEntries(LABELS.map((l) => [l.name, l]))
const LABEL_BY_PREFIX: Record<string, LabelMeta> = Object.fromEntries(LABELS.map((l) => [l.prefix, l]))

export function categoryOf(label: string): Category {
  return LABEL_BY_NAME[label]?.category ?? 'unknown'
}

export function labelForId(id: string): string | undefined {
  return LABEL_BY_PREFIX[id.split(':', 1)[0]]?.name
}

export function shortLabel(label: string): string {
  return LABEL_BY_NAME[label]?.short ?? label
}

export const DERIVED_EDGE_TYPES = new Set([
  'EXPOSES', 'VULNERABLE_TO', 'CAN_ACCESS', 'DERIVED_FROM', 'SAME_AS', 'LATERAL_MOVEMENT_TO', 'STOLEN_BY',
  'IN_STORYLINE', 'NEXT_STAGE', 'MATCHES_IOC', 'TARGETS',
])

export const EDGE_TYPES: string[] = [
  'CONTAINS', 'IN_VPC', 'IN_SUBNET', 'HAS_SECURITY_GROUP', 'ROUTES_TO', 'EXPOSES', 'HAS_NODE', 'RUNS_ON', 'RUNS_IMAGE',
  'HAS_PACKAGE', 'HAS_VULNERABILITY', 'VULNERABLE_TO', 'RESOLVES_TO', 'HAS_ROLE', 'HAS_POLICY', 'GRANTS', 'CAN_ASSUME',
  'HAS_ACCESS_KEY', 'MEMBER_OF', 'MAPS_TO', 'CAN_ACCESS', 'UNLOCKS', 'CREDENTIAL_FOR', 'DERIVED_FROM', 'PART_OF',
  'OWNED_BY', 'LEADS', 'DEPENDS_ON', 'SAME_AS', 'PRIMARY_USER', 'LOGGED_ON', 'RAN_ON', 'RAN_AS', 'SPAWNED', 'EXECUTED',
  'CONNECTED_TO', 'LATERAL_MOVEMENT_TO', 'ACCESSED_CREDENTIAL', 'ON_ENDPOINT', 'ON_RESOURCE', 'INVOLVES', 'USES_TECHNIQUE',
  'PART_OF_INCIDENT', 'STOLEN_BY', 'USED_CREDENTIAL', 'PERFORMED_BY', 'TARGETED', 'FROM_IP', 'ASSUMED', 'IN_STORYLINE',
  'NEXT_STAGE', 'ATTRIBUTED_TO', 'USES_MALWARE', 'INDICATES', 'EXPLOITS', 'REPORTS_ON', 'MATCHES_IOC', 'TARGETS',
]

/** Fallback Cypher hints when GET /schema does not carry `example_queries`. */
export const EXAMPLE_QUERIES: { title: string; query: string }[] = [
  {
    title: 'Alerts on hosts whose role can reach a crown jewel',
    query:
      'MATCH (a:Alert)-[:ON_ENDPOINT]->(e:Endpoint)-[:SAME_AS]->(vm:VirtualMachine)-[:HAS_ROLE]->(r:IamRole)-[:CAN_ACCESS]->(d)\nWHERE d.crown_jewel = true\nRETURN DISTINCT a.id, a.title, vm.name, r.name, d.name LIMIT 25',
  },
  {
    title: 'Credentials stolen on an endpoint and used in the cloud',
    query:
      'MATCH (ev:CloudEvent)-[:USED_CREDENTIAL]->(c:Credential)-[:STOLEN_BY]->(a:Alert)\nRETURN c.id, a.id, ev.event_name, ev.event_time ORDER BY ev.event_time LIMIT 50',
  },
  {
    title: 'Internet-exposed VMs with an actively exploited CVE',
    query:
      'MATCH (:Internet)-[:EXPOSES]->(vm:VirtualMachine)-[:VULNERABLE_TO]->(v:Vulnerability)\nWHERE v.exploitation_status IN ["active", "mass_exploitation"]\nRETURN vm.name, v.cve_id, v.exploitation_status LIMIT 25',
  },
  { title: 'Storylines', query: 'MATCH (s:Storyline) RETURN s.id, s.title, s.contextual_score' },
  { title: 'Threat actors targeting our sector', query: 'MATCH (t:ThreatActor) WHERE t.sector_targeting_relevance >= 0.7 RETURN t' },
]
