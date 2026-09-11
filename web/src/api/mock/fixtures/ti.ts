/* eslint-disable */
/** Threat-intel catalog beyond the two campaigns: more actors, campaigns, CVEs on exposed hosts, low-confidence IOC matches. */
import type { MockGraph } from '../graph'
import { ensureTechnique } from './alerts'
import { ID } from './ids'

interface ActorSpec { id: string; name: string; aliases: string[]; motivation: string; sectors: string[]; relevance: number; active: boolean; description: string }

const ACTORS: ActorSpec[] = [
  { id: 'actor:ti:brass-heron', name: 'Brass Heron', aliases: ['TA-7702'], motivation: 'financial', sectors: ['financial-services', 'insurance'], relevance: 0.75, active: true, description: 'eCrime group exploiting collaboration servers at banks and insurers for initial access.' },
  { id: 'actor:ti:glass-lantern', name: 'Glass Lantern', aliases: ['LANTERN PANDA'], motivation: 'espionage', sectors: ['financial-services', 'public-sector'], relevance: 0.7, active: true, description: 'Espionage actor targeting perimeter VPN appliances for long-term access.' },
  { id: 'actor:ti:pale-orchard', name: 'Pale Orchard', aliases: [], motivation: 'financial', sectors: ['healthcare'], relevance: 0.2, active: true, description: 'Ransomware affiliate focused on hospitals.' },
  { id: 'actor:ti:iron-sable', name: 'Iron Sable', aliases: ['SABLE BEAR'], motivation: 'espionage', sectors: ['energy', 'manufacturing'], relevance: 0.1, active: false, description: 'ICS-focused espionage actor; dormant since 2025.' },
  { id: 'actor:ti:quiet-marrow', name: 'Quiet Marrow', aliases: [], motivation: 'hacktivism', sectors: ['public-sector'], relevance: 0.3, active: true, description: 'Hacktivist collective running DDoS and defacement campaigns.' },
  { id: 'actor:ti:vellum-fox', name: 'Vellum Fox', aliases: ['TA-2210'], motivation: 'financial', sectors: ['technology', 'retail'], relevance: 0.3, active: true, description: 'Commodity malware distributor (loaders and stealers) via malvertising.' },
]

interface CampaignSpec { id: string; name: string; actor: string; status: string; started: string; objective: string; cve?: string; cveStatus?: string; relevance: number }

const CAMPAIGNS: CampaignSpec[] = [
  { id: 'campaign:ti:ledgerline', name: 'LEDGERLINE', actor: 'actor:ti:brass-heron', status: 'active', started: '2026-06-12T00:00:00Z', objective: 'Initial access via Confluence servers at financial firms', cve: 'CVE-2023-22515', cveStatus: 'active', relevance: 0.75 },
  { id: 'campaign:ti:glasswing', name: 'GLASSWING', actor: 'actor:ti:glass-lantern', status: 'active', started: '2026-05-01T00:00:00Z', objective: 'Persistent access through GlobalProtect VPN gateways', cve: 'CVE-2024-3400', cveStatus: 'active', relevance: 0.7 },
  { id: 'campaign:ti:tidewater', name: 'TIDEWATER', actor: ID.ACTOR_HT, status: 'dormant', started: '2025-11-03T00:00:00Z', objective: 'Earlier Hollow Tide MOVEit exploitation wave', cve: 'CVE-2023-34362', cveStatus: 'active', relevance: 0.8 },
  { id: 'campaign:ti:orchard-bloom', name: 'ORCHARD BLOOM', actor: 'actor:ti:pale-orchard', status: 'active', started: '2026-07-20T00:00:00Z', objective: 'Ransomware via Ivanti Connect Secure', cve: 'CVE-2024-21887', cveStatus: 'active', relevance: 0.2 },
  { id: 'campaign:ti:sable-grid', name: 'SABLE GRID', actor: 'actor:ti:iron-sable', status: 'historical', started: '2024-09-01T00:00:00Z', objective: 'Spring4Shell exploitation of engineering portals', cve: 'CVE-2022-22965', cveStatus: 'poc_public', relevance: 0.1 },
  { id: 'campaign:ti:foxglove', name: 'FOXGLOVE', actor: 'actor:ti:vellum-fox', status: 'active', started: '2026-08-01T00:00:00Z', objective: 'Malvertising loader distribution', relevance: 0.3 },
]

const CVES: [string, number, number, boolean, string, string][] = [
  ['CVE-2023-22515', 10, 0.95, true, 'confluence-server', 'Atlassian Confluence broken access control allowing admin account creation.'],
  ['CVE-2024-3400', 10, 0.96, true, 'pan-os-globalprotect', 'PAN-OS GlobalProtect command injection.'],
  ['CVE-2024-21887', 9.1, 0.95, true, 'ivanti-connect-secure', 'Ivanti Connect Secure command injection.'],
  ['CVE-2022-22965', 9.8, 0.95, true, 'spring-beans', 'Spring Framework RCE via data binding (Spring4Shell).'],
  ['CVE-2023-34362', 9.8, 0.95, true, 'moveit-transfer', 'MOVEit Transfer SQL injection leading to RCE.'],
]

const HOST_CVE: [string, string][] = [
  [ID.WIKI_VM, 'CVE-2023-22515'],
  [ID.VPN_VM, 'CVE-2024-3400'],
  [ID.IVANTI_VM, 'CVE-2024-21887'],
  [ID.PARTNER_API_VM, 'CVE-2022-22965'],
  [ID.MFT_VM, 'CVE-2023-34362'],
]

export function buildTiCatalog(g: MockGraph): void {
  for (const a of ACTORS) {
    g.node(a.id, a.name, { aliases: a.aliases, motivation: a.motivation, origin: 'unknown', sophistication: 'medium', targeted_sectors: a.sectors, targeted_regions: ['global'], sector_targeting_relevance: a.relevance, active: a.active, description: a.description })
  }
  for (const c of CAMPAIGNS) {
    g.node(c.id, c.name, { actor_id: c.actor, status: c.status, started: c.started, objective: c.objective, targeted_sectors: g.must(c.actor).props.targeted_sectors, sector_targeting_relevance: c.relevance, description: c.objective })
    g.edge(c.id, 'ATTRIBUTED_TO', c.actor, { basis: 'report' })
  }
  for (const [cve, cvss, epss, kev, component, desc] of CVES) {
    const camp = CAMPAIGNS.find((c) => c.cve === cve)
    const actor = camp ? camp.actor : null
    g.node(`cve:${cve}`, cve, { cve_id: cve, cvss, epss, kev, severity: cvss >= 9 ? 'critical' : 'high', published: '2023-01-01T00:00:00Z', exploitation_status: camp?.cveStatus ?? 'none', actor_interest: actor ? [actor] : [], sector_targeting_relevance: camp?.relevance ?? 0, ti_report_ids: [], synthetic: false, description: desc, affected_component: component }, { label: 'Vulnerability', severity: cvss >= 9 ? 'critical' : 'high' })
    if (camp) {
      g.edge(camp.id, 'EXPLOITS', `cve:${cve}`, { status: camp.cveStatus, first_seen: camp.started })
      g.edge(camp.actor, 'EXPLOITS', `cve:${cve}`, { status: camp.cveStatus })
    }
  }
  for (const [vm, cve] of HOST_CVE) g.edge(vm, 'VULNERABLE_TO', `cve:${cve}`, { via_package: g.must(`cve:${cve}`).props.affected_component, exploitable: true })

  // more reports
  const reports: [string, string, string, string, string[], string[], string][] = [
    ['report:ti:TL-2026-0139', 'LEDGERLINE: Brass Heron abuses Confluence access control bypass at regional banks', '2026-08-28T00:00:00Z', 'high', ['actor:ti:brass-heron'], ['campaign:ti:ledgerline'], 'Brass Heron creates rogue administrator accounts on unpatched Confluence servers, then deploys a Go-based tunneller to reach internal document stores.'],
    ['report:ti:TL-2026-0131', 'GLASSWING: Glass Lantern implants on GlobalProtect gateways', '2026-08-12T00:00:00Z', 'medium', ['actor:ti:glass-lantern'], ['campaign:ti:glasswing'], 'A persistent backdoor on PAN-OS gateways harvests VPN credentials of finance staff for later use.'],
    ['report:ti:TL-2026-0126', 'ORCHARD BLOOM ransomware wave through Ivanti Connect Secure', '2026-08-02T00:00:00Z', 'high', ['actor:ti:pale-orchard'], ['campaign:ti:orchard-bloom'], 'Hospital systems compromised through Ivanti command injection; no financial-services victims observed so far.'],
    ['report:ti:TL-2026-0118', 'FOXGLOVE malvertising delivers commodity stealers', '2026-08-04T00:00:00Z', 'medium', ['actor:ti:vellum-fox'], ['campaign:ti:foxglove'], 'Search-ad impersonation of productivity tools leading to loader installs; low targeting specificity.'],
  ]
  for (const [id, title, published, conf, actors, campaigns, summary] of reports) {
    g.node(id, title, { title, published, publisher: 'Throughline Labs (fictional)', report_confidence: conf, tlp: 'GREEN', summary, actor_ids: actors, campaign_ids: campaigns, cve_ids: CAMPAIGNS.filter((c) => campaigns.includes(c.id) && c.cve).map((c) => c.cve!), technique_ids: ['T1190'], indicator_count: 6, targeted_sectors: g.must(actors[0]).props.targeted_sectors, body: `${summary}\n\nThis fictional report exists so the intel library has realistic depth; its indicators are low-confidence and mostly unmatched in the Larkspur estate.` })
    for (const a of actors) g.edge(id, 'REPORTS_ON', a)
    for (const c of campaigns) g.edge(id, 'REPORTS_ON', c)
    for (const c of CAMPAIGNS.filter((c) => campaigns.includes(c.id) && c.cve)) g.edge(id, 'REPORTS_ON', `cve:${c.cve}`)
  }
  for (const t of ['T1190', 'T1505.003', 'T1078', 'T1133']) {
    g.edge('actor:ti:brass-heron', 'USES_TECHNIQUE', ensureTechnique(g, t))
    g.edge('actor:ti:glass-lantern', 'USES_TECHNIQUE', ensureTechnique(g, t))
  }

  // low-confidence IOC matches on random hosts (old campaigns)
  const lowIocs: [string, string, string, number, string, string][] = [
    ['ioc:ipv4:198.51.100.77', 'ipv4', '198.51.100.77', 0.4, 'campaign:ti:foxglove', ID.FILESHARE_VM],
    ['ioc:domain:cdn-static-updates.example', 'domain', 'cdn-static-updates.example', 0.35, 'campaign:ti:foxglove', ID.EP_MREYES],
    ['ioc:sha256:oldloader-2025', 'sha256', '0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b', 0.45, 'campaign:ti:sable-grid', ID.PARTNER_API_VM],
    ['ioc:ipv4:203.0.113.150', 'ipv4', '203.0.113.150', 0.5, 'campaign:ti:tidewater', ID.MFT_VM],
    ['ioc:ipv4:203.0.113.161', 'ipv4', '203.0.113.161', 0.3, 'campaign:ti:glasswing', ID.VPN_VM],
  ]
  for (const [id, type, value, conf, campaign, host] of lowIocs) {
    const camp = CAMPAIGNS.find((c) => c.id === campaign)!
    g.node(id, value, { ioc_type: type, value, confidence: conf, report_id: null, actor_id: camp.actor, campaign_id: campaign, kill_chain_stage: 2, active: camp.status === 'active', first_seen: '2025-10-01T00:00:00Z', last_seen: '2026-03-01T00:00:00Z' }, { label: 'Indicator' })
    g.edge(id, 'INDICATES', campaign)
    const ipId = type === 'ipv4' ? `ip:v4:${value}` : type === 'domain' ? `domain:dns:${value}` : `file:sha256:${value}`
    if (!g.has(ipId)) g.node(ipId, value, type === 'ipv4' ? { address: value, is_private: false, reputation: 'suspicious' } : type === 'domain' ? { fqdn: value, reputation: 'suspicious' } : { sha256: value, file_name: 'updater.bin', verdict: 'suspicious' })
    g.edge(ipId, 'MATCHES_IOC', id, { match_type: 'exact' }, conf)
    const ep = g.get(host)
    if (ep) g.edge(host, 'CONNECTED_TO', ipId, { port: 443, protocol: 'tcp', direction: 'outbound', count: 2 })
  }
}

export const TI_ACTOR_IDS = [ID.ACTOR_CJ, ID.ACTOR_HT, ...ACTORS.map((a) => a.id)]
export const TI_CAMPAIGNS = CAMPAIGNS
