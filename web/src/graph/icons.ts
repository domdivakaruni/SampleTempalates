/**
 * Per-label inline SVG icons rendered to data URIs for Cytoscape `background-image`.
 * Icons are 24x24 stroke paths (lucide-like); badges for crown jewels and internet exposure sit in the corners.
 */
import { categoryColor, severityColor } from '../theme'
import { categoryOf } from './schema'

const P: Record<string, string> = {
  server: '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
  cloud: '<path d="M17.5 19a4.5 4.5 0 0 0 .4-9A7 7 0 0 0 4.3 12.3 3.5 3.5 0 0 0 6.5 19z"/>',
  network: '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v4M5 17v-3h14v3"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  balance: '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="1.5"/><circle cx="14" cy="12" r="1.5"/><circle cx="10" cy="18" r="1.5"/>',
  k8s: '<path d="M12 2l8.5 4.5v9L12 22l-8.5-6.5v-9z"/><circle cx="12" cy="12" r="3"/>',
  box: '<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3 8l9 5 9-5M12 13v9"/>',
  layers: '<path d="M12 2l9 5-9 5-9-5z"/><path d="M3 12l9 5 9-5M3 17l9 5 9-5"/>',
  lambda: '<path d="M6 20l6-16h1l5 16"/><path d="M9 14h7"/>',
  bucket: '<path d="M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M10.9 12.1L20 3M15 8l2 2M18 5l2 2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  ip: '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 12h.01M11 12h.01M15 12h.01"/>',
  domain: '<path d="M4 8h16M4 8v10a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V8M4 8l2-3h12l2 3"/><path d="M9 13h6"/>',
  role: '<circle cx="12" cy="8" r="4"/><path d="M5 21a7 7 0 0 1 14 0"/><path d="M16 4l2-2M19 6l2-1"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M5 21a7 7 0 0 1 14 0"/>',
  policy: '<path d="M6 2h9l5 5v15H6z"/><path d="M15 2v5h5M9 13h6M9 17h6"/>',
  accesskey: '<rect x="3" y="9" width="18" height="6" rx="3"/><circle cx="8" cy="12" r="1.5"/><path d="M12 12h6"/>',
  service: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/>',
  group: '<circle cx="9" cy="8" r="3.5"/><circle cx="17" cy="9" r="2.5"/><path d="M2 20a7 7 0 0 1 14 0M15 20a5 5 0 0 1 7-4"/>',
  credential: '<path d="M12 2a5 5 0 0 1 5 5v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1V7a5 5 0 0 1 5-5z"/><path d="M9 10V7a3 3 0 0 1 6 0v3"/><circle cx="12" cy="16" r="1.5"/>',
  package: '<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3 8l9 5 9-5M12 13v9M7.5 5.5l9 5"/>',
  bug: '<path d="M8 2l1.5 2M16 2l-1.5 2"/><rect x="7" y="6" width="10" height="12" rx="5"/><path d="M3 10h4M17 10h4M3 16h4M17 16h4M12 6v12"/>',
  app: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  team: '<circle cx="7" cy="9" r="3"/><circle cx="17" cy="9" r="3"/><path d="M1 20a6 6 0 0 1 12 0M11 20a6 6 0 0 1 12 0"/>',
  laptop: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20"/>',
  process: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 10l3 2-3 2M13 14h3"/>',
  file: '<path d="M6 2h9l5 5v15H6z"/><path d="M15 2v5h5"/>',
  logon: '<path d="M10 17l5-5-5-5M15 12H3"/><path d="M13 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/>',
  alert: '<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 18h.01"/>',
  incident: '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16h.01"/>',
  cloudevent: '<path d="M17.5 19a4.5 4.5 0 0 0 .4-9A7 7 0 0 0 4.3 12.3 3.5 3.5 0 0 0 6.5 19z"/><path d="M13 10l-3 5h4l-3 5"/>',
  storyline: '<path d="M3 17c4 0 4-10 8-10s4 10 8 10"/><circle cx="3" cy="17" r="1.5"/><circle cx="11" cy="7" r="1.5"/><circle cx="19" cy="17" r="1.5"/>',
  actor: '<path d="M4 20c0-4 3-6 8-6s8 2 8 6"/><path d="M8 9a4 4 0 1 0 8 0 4 4 0 1 0-8 0z"/><path d="M6 9c2-4 10-4 12 0"/>',
  campaign: '<path d="M4 20V4l16 8z"/>',
  malware: '<circle cx="12" cy="12" r="6"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4M5 5l3 3M16 16l3 3M5 19l3-3M16 8l3-3"/>',
  technique: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  ioc: '<path d="M4 4l16 16M20 4L4 20"/><circle cx="12" cy="12" r="9"/>',
  report: '<path d="M6 2h9l5 5v15H6z"/><path d="M15 2v5h5M9 12h6M9 16h4"/>',
  question: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17h.01"/>',
}

export const LABEL_ICON: Record<string, string> = {
  CloudAccount: 'cloud', VPC: 'network', Subnet: 'network', SecurityGroup: 'shield', LoadBalancer: 'balance', VirtualMachine: 'server',
  KubernetesCluster: 'k8s', Workload: 'box', ContainerImage: 'layers', ServerlessFunction: 'lambda', StorageBucket: 'bucket', Database: 'database',
  Secret: 'key', Internet: 'globe', IpAddress: 'ip', Domain: 'domain', IamRole: 'role', IamUser: 'user', IamPolicy: 'policy', AccessKey: 'accesskey',
  ServiceAccount: 'service', HumanUser: 'user', Group: 'group', Credential: 'credential', Package: 'package', Vulnerability: 'bug', Application: 'app',
  Team: 'team', Endpoint: 'laptop', Process: 'process', File: 'file', LogonSession: 'logon', Alert: 'alert', Incident: 'incident', CloudEvent: 'cloudevent',
  Storyline: 'storyline', ThreatActor: 'actor', Campaign: 'campaign', Malware: 'malware', AttackTechnique: 'technique', Indicator: 'ioc', IntelReport: 'report',
}

export function iconPath(label: string): string {
  return P[LABEL_ICON[label] ?? 'question'] ?? P.question
}

/** Inline SVG markup (for React `dangerouslySetInnerHTML`-free usage we export the path and build the svg in JSX). */
export function iconSvg(label: string, color: string, size = 16): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${iconPath(label)}</svg>`
}

export function nodeColor(label: string, category: string, severity?: string | null): string {
  if (label === 'Alert' || label === 'Incident') return severityColor(severity)
  if (label === 'Storyline') return severityColor('critical')
  return categoryColor(category || categoryOf(label))
}

const cache = new Map<string, string>()

/** Composite node image: icon centred, crown-jewel badge top-right, internet-exposed badge top-left. */
export function nodeImage(label: string, color: string, opts: { crown?: boolean; exposed?: boolean } = {}): string {
  const key = `${label}|${color}|${opts.crown ? 1 : 0}|${opts.exposed ? 1 : 0}`
  const hit = cache.get(key)
  if (hit) return hit
  const badges: string[] = []
  if (opts.crown) badges.push(`<g transform="translate(46,2)"><circle cx="7" cy="7" r="7" fill="#fbbf24" stroke="#070b14" stroke-width="1.5"/><path d="M3.5 9.5 L4.5 5 L6.5 7 L7 4 L7.5 7 L9.5 5 L10.5 9.5 Z" fill="#1c1917"/></g>`)
  if (opts.exposed) badges.push(`<g transform="translate(2,2)"><circle cx="7" cy="7" r="7" fill="#38bdf8" stroke="#070b14" stroke-width="1.5"/><g fill="none" stroke="#0b1220" stroke-width="1.2"><circle cx="7" cy="7" r="3.8"/><path d="M3.2 7h7.6M7 3.2a5.5 5.5 0 0 1 0 7.6M7 3.2a5.5 5.5 0 0 0 0 7.6"/></g></g>`)
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 60 60" width="60" height="60"><g transform="translate(16,16)" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${iconPath(label)}</g>${badges.join('')}</svg>`
  const uri = `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`
  cache.set(key, uri)
  return uri
}
