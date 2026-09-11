/* eslint-disable */
/** Mock threat-intelligence endpoints. */
import type { ActorDetailOut, ActorListItem, AlertSummary, ExposureItem, GraphFragment, NodeOut, ReportDetailOut, TIContext, TIMatch } from '../types'
import { dataset } from './dataset'
import { ID } from './fixtures/ids'
import type { MockGraph, MockNode } from './graph'

function indicatorsOf(g: MockGraph, ownerId: string): MockNode[] {
  return g.byLabel('Indicator').filter((i) => i.props.actor_id === ownerId || i.props.campaign_id === ownerId || i.props.malware_id === ownerId)
}

function matchesFor(g: MockGraph, indicators: MockNode[]): TIMatch[] {
  const out: TIMatch[] = []
  for (const ind of indicators) {
    for (const e of g.edgesOf(ind.id, 'in')) {
      if (e.type !== 'MATCHES_IOC') continue
      const m = g.get(e.src)
      if (!m) continue
      out.push({ indicator_id: ind.id, ioc_type: String(ind.props.ioc_type), value: String(ind.props.value), confidence: e.confidence ?? Number(ind.props.confidence ?? 0.5), matched_node_id: m.id, matched_label: m.label, actor_id: (ind.props.actor_id as string) ?? null, campaign_id: (ind.props.campaign_id as string) ?? null, malware_id: (ind.props.malware_id as string) ?? null, report_id: (ind.props.report_id as string) ?? null })
    }
  }
  return out.sort((a, b) => b.confidence - a.confidence)
}

function campaignsOf(g: MockGraph, actorId: string): MockNode[] {
  return g.edgesOf(actorId, 'in').filter((e) => e.type === 'ATTRIBUTED_TO' && e.src.startsWith('campaign:')).map((e) => g.get(e.src)!).filter(Boolean)
}

function exploitedCvesPresent(g: MockGraph, ownerId: string): MockNode[] {
  return g.edgesOf(ownerId, 'out').filter((e) => e.type === 'EXPLOITS').map((e) => g.get(e.dst)!).filter((c) => c && g.edgesOf(c.id, 'in').some((e) => e.type === 'VULNERABLE_TO'))
}

function alertsForActor(actorId: string): AlertSummary[] {
  return dataset().alertsByContextual.filter((a) => a.ti_actor_ids.includes(actorId))
}

function ttpOverlap(g: MockGraph, ownerId: string, alerts: AlertSummary[]): number {
  const actorTechs = new Set(g.edgesOf(ownerId, 'out').filter((e) => e.type === 'USES_TECHNIQUE').map((e) => String(g.get(e.dst)?.props.technique_id)))
  const seen = new Set(alerts.flatMap((a) => a.techniques))
  const overlap = [...seen].filter((t) => actorTechs.has(t)).length
  return actorTechs.size ? overlap / actorTechs.size : 0
}

export function tiContextForOwner(ownerId: string): TIContext {
  const { graph: g } = dataset()
  const owner = g.get(ownerId)
  const indicators = indicatorsOf(g, ownerId)
  const matches = matchesFor(g, indicators)
  const isActor = owner?.label === 'ThreatActor'
  const actorId = isActor ? ownerId : String(owner?.props.actor_id ?? '')
  const actor = g.get(actorId)
  const campaigns = isActor ? campaignsOf(g, ownerId) : owner ? [owner] : []
  const alerts = alertsForActor(actorId)
  const malware = g.edgesOf(ownerId, 'out').filter((e) => e.type === 'USES_MALWARE').map((e) => g.get(e.dst)!).filter(Boolean)
  const cves = g.edgesOf(ownerId, 'out').filter((e) => e.type === 'EXPLOITS').map((e) => g.get(e.dst)!).filter(Boolean)
  const reports = g.edgesOf(ownerId, 'in').filter((e) => e.type === 'REPORTS_ON').map((e) => g.get(e.src)!).filter(Boolean)
  const overlap = ttpOverlap(g, ownerId, alerts)
  const rel = Number((owner ?? actor)?.props.sector_targeting_relevance ?? 0)
  return {
    matches,
    actors: actor ? [actor] : [],
    campaigns,
    malware,
    exploited_vulnerabilities: cves,
    reports,
    ttp_overlap: { [ownerId]: Math.round(overlap * 100) / 100 },
    sector_relevance: rel,
    summary: `${owner?.name ?? ownerId}: ${matches.length} IOC match${matches.length === 1 ? '' : 'es'} in the estate, ${alerts.length} attributed alert${alerts.length === 1 ? '' : 's'}, TTP overlap ${(overlap * 100).toFixed(0)}%, sector relevance ${rel.toFixed(2)}${cves.length ? `, exploits ${cves.map((c) => c.name).join(', ')}` : ''}.`,
  }
}

/** TI context for an arbitrary node (alert, IP, file, VM...): what does it match and who is behind it. */
export function tiContextForNode(nodeId: string): TIContext {
  const { graph: g } = dataset()
  const node = g.get(nodeId)
  const empty: TIContext = { matches: [], actors: [], campaigns: [], malware: [], exploited_vulnerabilities: [], reports: [], ttp_overlap: {}, sector_relevance: null, summary: 'No threat-intelligence match.' }
  if (!node) return empty
  if (['ThreatActor', 'Campaign', 'Malware'].includes(node.label)) return tiContextForOwner(nodeId)
  const related = new Set<string>([nodeId])
  for (const e of g.edgesOf(nodeId, 'out')) if (e.type === 'INVOLVES' || e.type === 'SAME_AS') related.add(e.dst)
  for (const e of g.edgesOf(nodeId, 'in')) if (e.type === 'SAME_AS') related.add(e.src)
  const indicators = new Map<string, MockNode>()
  const matches: TIMatch[] = []
  for (const id of related) {
    for (const e of g.edgesOf(id, 'out')) {
      if (e.type !== 'MATCHES_IOC') continue
      const ind = g.get(e.dst)
      if (!ind) continue
      indicators.set(ind.id, ind)
      matches.push({ indicator_id: ind.id, ioc_type: String(ind.props.ioc_type), value: String(ind.props.value), confidence: e.confidence ?? 0.5, matched_node_id: id, matched_label: g.get(id)!.label, actor_id: (ind.props.actor_id as string) ?? null, campaign_id: (ind.props.campaign_id as string) ?? null, malware_id: (ind.props.malware_id as string) ?? null, report_id: (ind.props.report_id as string) ?? null })
    }
  }
  const actorIds = new Set<string>([...indicators.values()].map((i) => String(i.props.actor_id)).filter(Boolean))
  const alert = dataset().summaries.get(nodeId)
  alert?.ti_actor_ids.forEach((a) => actorIds.add(a))
  if (node.label === 'Alert') {
    const story = dataset().storylines.find((s) => s.alert_ids.includes(nodeId))
    if (story?.actor_id) actorIds.add(story.actor_id)
  }
  const vmCves = g.edgesOf(nodeId, 'out').filter((e) => e.type === 'VULNERABLE_TO').map((e) => g.get(e.dst)!).filter((c) => c && ['active', 'mass_exploitation'].includes(String(c.props.exploitation_status)))
  for (const c of vmCves) ((c.props.actor_interest as string[]) ?? []).forEach((a) => actorIds.add(a))
  if (!actorIds.size && !matches.length && !vmCves.length) return empty
  const actors = [...actorIds].map((a) => g.get(a)!).filter(Boolean)
  const campaigns = actors.flatMap((a) => campaignsOf(g, a.id)).filter((c) => c.props.status === 'active' || indicators.size === 0 || [...indicators.values()].some((i) => i.props.campaign_id === c.id))
  const malware = [...new Set([...indicators.values()].map((i) => i.props.malware_id as string).filter(Boolean))].map((m) => g.get(m)!).filter(Boolean)
  const reports = [...new Set([...[...indicators.values()].map((i) => i.props.report_id as string), ...vmCves.flatMap((c) => (c.props.ti_report_ids as string[]) ?? [])].filter(Boolean))].map((r) => g.get(r)!).filter(Boolean)
  const overlap: Record<string, number> = {}
  for (const a of actors) overlap[a.id] = Math.round(ttpOverlap(g, a.id, alert ? [alert] : dataset().alertsByContextual.filter((x) => x.entity_id === nodeId)) * 100) / 100
  const rel = actors.length ? Math.max(...actors.map((a) => Number(a.props.sector_targeting_relevance ?? 0))) : null
  return {
    matches: matches.sort((a, b) => b.confidence - a.confidence),
    actors, campaigns: [...new Map(campaigns.map((c) => [c.id, c])).values()], malware, exploited_vulnerabilities: vmCves, reports,
    ttp_overlap: overlap, sector_relevance: rel,
    summary: `${matches.length} IOC match${matches.length === 1 ? '' : 'es'}${actors.length ? `; attributed to ${actors.map((a) => a.name).join(', ')}` : ''}${vmCves.length ? `; vulnerable to actively exploited ${vmCves.map((c) => c.name).join(', ')}` : ''}${rel !== null ? ` (sector relevance ${rel.toFixed(2)})` : ''}.`,
  }
}

function affectedAssets(g: MockGraph, ownerId: string, alerts: AlertSummary[]): Set<string> {
  const assets = new Set<string>()
  alerts.forEach((a) => a.entity_id && assets.add(a.entity_id))
  for (const c of exploitedCvesPresent(g, ownerId)) for (const e of g.edgesOf(c.id, 'in')) if (e.type === 'VULNERABLE_TO' && g.get(e.src)?.label === 'VirtualMachine') assets.add(e.src)
  return assets
}

export function actorList(): ActorListItem[] {
  const { graph: g } = dataset()
  const items = g.byLabel('ThreatActor').map((actor) => {
    const alerts = alertsForActor(actor.id)
    const campaigns = campaignsOf(g, actor.id)
    const iocMatches = matchesFor(g, indicatorsOf(g, actor.id).concat(campaigns.flatMap((c) => indicatorsOf(g, c.id)).filter((i) => i.props.actor_id !== actor.id)))
    return {
      actor, campaigns,
      sector_relevance: Number(actor.props.sector_targeting_relevance ?? 0),
      active: actor.props.active === true,
      ioc_matches: iocMatches.length,
      matched_alerts: alerts.length,
      exploited_cves_present: exploitedCvesPresent(g, actor.id).length + campaigns.reduce((n, c) => n + exploitedCvesPresent(g, c.id).filter((cv) => !exploitedCvesPresent(g, actor.id).includes(cv)).length, 0),
      affected_assets: affectedAssets(g, actor.id, alerts).size + campaigns.reduce((n, c) => n + affectedAssets(g, c.id, []).size, 0),
    }
  })
  return items.sort((a, b) => b.sector_relevance - a.sector_relevance || b.ioc_matches - a.ioc_matches || b.matched_alerts - a.matched_alerts)
}

export function actorDetail(id: string): ActorDetailOut | undefined {
  const { graph: g } = dataset()
  const owner = g.get(id)
  if (!owner || !['ThreatActor', 'Campaign'].includes(owner.label)) return undefined
  const isActor = owner.label === 'ThreatActor'
  const campaigns = isActor ? campaignsOf(g, id) : [owner]
  const actor = isActor ? owner : g.get(String(owner.props.actor_id))!
  const owners = [id, ...campaigns.map((c) => c.id), ...(isActor ? [] : [actor.id])]
  const uniq = (nodes: MockNode[]) => [...new Map(nodes.map((n) => [n.id, n])).values()]
  const malware = uniq(owners.flatMap((o) => g.edgesOf(o, 'out').filter((e) => e.type === 'USES_MALWARE').map((e) => g.get(e.dst)!)))
  const techniques = uniq(owners.flatMap((o) => g.edgesOf(o, 'out').filter((e) => e.type === 'USES_TECHNIQUE').map((e) => g.get(e.dst)!))).sort((a, b) => Number(a.props.kill_chain_stage) - Number(b.props.kill_chain_stage))
  const indicators = uniq(owners.flatMap((o) => indicatorsOf(g, o))).sort((a, b) => Number(b.props.confidence) - Number(a.props.confidence))
  const reports = uniq(owners.flatMap((o) => g.edgesOf(o, 'in').filter((e) => e.type === 'REPORTS_ON').map((e) => g.get(e.src)!)))
  const context = tiContextForOwner(id)
  context.matches = matchesFor(g, indicators)
  const alerts = alertsForActor(actor.id).filter((a) => isActor || a.storyline_id === dataset().storylines.find((s) => s.campaign_id === id)?.id)
  const assetIds = affectedAssets(g, id, alerts)
  campaigns.forEach((c) => affectedAssets(g, c.id, []).forEach((a) => assetIds.add(a)))
  const fragIds = new Set<string>([id, actor.id, ...campaigns.map((c) => c.id), ...alerts.map((a) => a.id), ...assetIds, ...context.matches.map((m) => m.matched_node_id), ...indicators.filter((i) => context.matches.some((m) => m.indicator_id === i.id)).map((i) => i.id), ...exploitedCvesPresent(g, id).map((c) => c.id), ...campaigns.flatMap((c) => exploitedCvesPresent(g, c.id).map((x) => x.id))])
  const affected: GraphFragment = g.fragment(fragIds, { focus: [id], hint: 'neighborhood', highlight: new Set([...assetIds, ...alerts.map((a) => a.id)]) })
  return { actor: isActor ? owner : actor, campaign: isActor ? null : owner, campaigns, malware, techniques, indicators, reports, context, affected, matched_alert_ids: alerts.map((a) => a.id), affected_asset_ids: [...assetIds], exploited_cve_ids: [...new Set([...exploitedCvesPresent(g, id).map((c) => c.id), ...campaigns.flatMap((c) => exploitedCvesPresent(g, c.id).map((x) => x.id))])] }
}

export function reportList(): NodeOut[] {
  return dataset().graph.byLabel('IntelReport').sort((a, b) => String(b.props.published).localeCompare(String(a.props.published)))
}

export function reportDetail(id: string): ReportDetailOut | undefined {
  const { graph: g, alertsByContextual } = dataset()
  const report = g.get(id)
  if (!report || report.label !== 'IntelReport') return undefined
  const targets = g.edgesOf(id, 'out').filter((e) => e.type === 'REPORTS_ON').map((e) => g.get(e.dst)!).filter(Boolean)
  const by = (label: string) => targets.filter((t) => t.label === label)
  const actorIds = (report.props.actor_ids as string[]) ?? []
  const matched = alertsByContextual.filter((a) => a.ti_actor_ids.some((x) => actorIds.includes(x)))
  const cves = by('Vulnerability')
  const exposed = [...new Set(cves.flatMap((c) => g.edgesOf(c.id, 'in').filter((e) => e.type === 'VULNERABLE_TO').map((e) => e.src)))].map((v) => g.get(v)!).filter((v) => v && g.edgesOf(v.id, 'in').some((e) => e.type === 'EXPOSES'))
  const techniques = ((report.props.technique_ids as string[]) ?? []).map((t) => g.get(ID.TECH(t))!).filter(Boolean)
  const summary = matched.length || exposed.length
    ? `${matched.length} alert${matched.length === 1 ? '' : 's'} in the estate match this report's indicators or attribution${exposed.length ? `; ${exposed.length} internet-exposed asset${exposed.length === 1 ? '' : 's'} carry the CVEs it describes (${exposed.map((e) => e.name).join(', ')})` : ''}.`
    : 'No alerts or exposed assets in the estate match this report.'
  return { report, actors: by('ThreatActor'), campaigns: by('Campaign'), malware: by('Malware'), cves, indicators: by('Indicator'), techniques, impact: { matched_alerts: matched, exposed_assets: exposed, summary } }
}

export function tiLookup(value: string): TIContext {
  const { graph: g } = dataset()
  const needle = value.trim().toLowerCase()
  const byValue = g.byLabel('Indicator').find((i) => String(i.props.value).toLowerCase() === needle || i.id.toLowerCase() === needle)
  if (byValue) {
    const owner = String(byValue.props.campaign_id ?? byValue.props.actor_id ?? '')
    const ctx = tiContextForOwner(owner)
    ctx.matches = matchesFor(g, [byValue])
    ctx.summary = `${byValue.props.ioc_type} ${byValue.name}: confidence ${Number(byValue.props.confidence).toFixed(2)}, ${ctx.matches.length} match${ctx.matches.length === 1 ? '' : 'es'} in the estate; ${ctx.summary}`
    return ctx
  }
  const named = [...g.nodes.values()].find((n) => ['ThreatActor', 'Campaign', 'Malware', 'IntelReport', 'Vulnerability', 'AttackTechnique'].includes(n.label) && (n.name.toLowerCase() === needle || n.id.toLowerCase() === needle || String(n.props.cve_id ?? '').toLowerCase() === needle || String(n.props.technique_id ?? '').toLowerCase() === needle))
  if (named) {
    if (['ThreatActor', 'Campaign', 'Malware'].includes(named.label)) return tiContextForOwner(named.id)
    if (named.label === 'Vulnerability') {
      const actors = ((named.props.actor_interest as string[]) ?? []).map((a) => g.get(a)!).filter(Boolean)
      const campaigns = g.edgesOf(named.id, 'in').filter((e) => e.type === 'EXPLOITS' && e.src.startsWith('campaign:')).map((e) => g.get(e.src)!)
      return { matches: [], actors, campaigns, malware: [], exploited_vulnerabilities: [named], reports: g.edgesOf(named.id, 'in').filter((e) => e.type === 'REPORTS_ON').map((e) => g.get(e.src)!), ttp_overlap: {}, sector_relevance: Number(named.props.sector_targeting_relevance ?? 0), summary: `${named.name}: ${named.props.exploitation_status} by ${actors.map((a) => a.name).join(', ') || 'no tracked actor'}; ${g.edgesOf(named.id, 'in').filter((e) => e.type === 'VULNERABLE_TO').length} asset(s) vulnerable.` }
    }
    return tiContextForNode(named.id)
  }
  return tiContextForNode(value)
}

export function exposureTable(sectorOnly: boolean): ExposureItem[] {
  const { graph: g, alertsByContextual } = dataset()
  const SCORES: Record<string, number> = { [ID.EDGE_VM]: 80, [ID.VPN_VM]: 66, [ID.WIKI_VM]: 62, [ID.STG_EDGE_VM]: 58, [ID.MFT_VM]: 57, [ID.IVANTI_VM]: 47, [ID.DEV_LOG4J_VM]: 44, [ID.PARTNER_API_VM]: 41 }
  const items: ExposureItem[] = []
  for (const vm of g.byLabel('VirtualMachine')) {
    if (!g.edgesOf(vm.id, 'in').some((e) => e.type === 'EXPOSES')) continue
    for (const ve of g.edgesOf(vm.id, 'out').filter((e) => e.type === 'VULNERABLE_TO')) {
      const cve = g.get(ve.dst)!
      const exploits = g.edgesOf(cve.id, 'in').filter((e) => e.type === 'EXPLOITS')
      if (!exploits.length) continue
      const campaigns = exploits.filter((e) => e.src.startsWith('campaign:')).map((e) => g.get(e.src)!)
      const actors = [...new Set([...exploits.filter((e) => e.src.startsWith('actor:')).map((e) => e.src), ...campaigns.map((c) => String(c.props.actor_id))])].map((a) => g.get(a)!).filter(Boolean)
      const rel = Math.max(0, ...actors.map((a) => Number(a.props.sector_targeting_relevance ?? 0)))
      if (sectorOnly && rel < 0.7) continue
      const status = String(exploits.map((e) => e.props.status).find((s) => s === 'mass_exploitation') ?? exploits[0].props.status ?? cve.props.exploitation_status)
      const roles = g.edgesOf(vm.id, 'out').filter((e) => e.type === 'HAS_ROLE').map((e) => g.get(e.dst)!)
      const jewels = new Map<string, NodeOut>()
      for (const r of roles) for (const e of g.edgesOf(r.id, 'out')) {
        if (e.type !== 'CAN_ACCESS') continue
        const t = g.get(e.dst)!
        if (t.tags.includes('crown_jewel')) jewels.set(t.id, t)
        for (const u of g.edgesOf(t.id, 'out')) if (u.type === 'UNLOCKS' && g.get(u.dst)?.tags.includes('crown_jewel')) jewels.set(u.dst, g.get(u.dst)!)
      }
      const alertIds = alertsByContextual.filter((a) => a.entity_id === vm.id || (a.hostname && a.hostname === vm.name)).map((a) => a.id)
      items.push({ vm, cve, exploitation_status: status, actors, campaigns, sector_relevance: rel, contextual_score: SCORES[vm.id] ?? Math.round(30 + rel * 30), crown_jewels_reachable: [...jewels.values()], has_edr_sensor: vm.props.has_edr_sensor === true, alert_ids: alertIds })
    }
  }
  return items.sort((a, b) => b.contextual_score - a.contextual_score)
}
