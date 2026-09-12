/* eslint-disable */
/** Mock analytics: risk breakdowns, insights, blast radius, attack paths, alert context, storyline fragments, containment. */
import type {
  AlertContext, AlertSummary, AttackPathOut, BlastRadiusResult, BreakItem, ContainmentSimulation, GraphFragment, Insight,
  NodeOut, PathOut, ReachedNode, RiskBreakdown, RiskFactor, StorylineOut, TIContext,
} from '../types'
import { SEVERITY_RANK, type Severity } from '../types'
import { alertSpec, alertSummary, dataset, storylineById } from './dataset'
import { ID } from './fixtures/ids'
import { mergeFragments, type MockGraph, type MockNode } from './graph'
import { tiContextForNode } from './ti'

const REACH_EDGES = new Set(['ON_ENDPOINT', 'ON_RESOURCE', 'SAME_AS', 'HAS_ROLE', 'CAN_ASSUME', 'CAN_ACCESS', 'UNLOCKS', 'MAPS_TO', 'HAS_POLICY', 'GRANTS', 'LATERAL_MOVEMENT_TO', 'CREDENTIAL_FOR', 'INVOLVES'])
const REACH_REVERSE = new Set(['STOLEN_BY'])

// ----------------------------------------------------------------------------- helpers

/** Resolve an alert's primary asset to the cloud VM behind it (Endpoint -> SAME_AS -> VM). */
export function assetChain(g: MockGraph, entityId: string | null | undefined): { entity?: MockNode; vm?: MockNode; roles: MockNode[] } {
  const entity = entityId ? g.get(entityId) : undefined
  if (!entity) return { roles: [] }
  let vm: MockNode | undefined
  if (entity.label === 'VirtualMachine') vm = entity
  else if (entity.label === 'Endpoint') {
    const same = g.edgesOf(entity.id, 'out').find((e) => e.type === 'SAME_AS')
    vm = same ? g.get(same.dst) : undefined
  }
  const roles: MockNode[] = []
  const seedRoles = vm ? g.edgesOf(vm.id, 'out').filter((e) => e.type === 'HAS_ROLE').map((e) => g.get(e.dst)!) : entity.label === 'IamRole' ? [entity] : []
  for (const r of seedRoles) {
    roles.push(r)
    for (const e of g.edgesOf(r.id, 'out')) if (e.type === 'CAN_ASSUME' && g.has(e.dst)) roles.push(g.get(e.dst)!)
  }
  return { entity, vm, roles }
}

function crownJewelsFrom(g: MockGraph, roles: MockNode[]): MockNode[] {
  const out = new Map<string, MockNode>()
  for (const r of roles) {
    for (const e of g.edgesOf(r.id, 'out')) {
      if (e.type !== 'CAN_ACCESS') continue
      const t = g.get(e.dst)
      if (!t) continue
      if (t.tags.includes('crown_jewel')) out.set(t.id, t)
      for (const u of g.edgesOf(t.id, 'out')) if (u.type === 'UNLOCKS' && g.get(u.dst)?.tags.includes('crown_jewel')) out.set(u.dst, g.get(u.dst)!)
    }
  }
  return [...out.values()]
}

function exposureOf(vm: MockNode | undefined, entity: MockNode | undefined): number {
  const target = vm ?? entity
  if (!target) return 0.4
  if (target.props.public === true || target.props.exposure === 'internet') return 1
  if (target.props.exposure === 'isolated') return 0.1
  return 0.4
}

function actorRelevance(g: MockGraph, ids: string[]): number {
  let max = 0
  for (const id of ids) max = Math.max(max, Number(g.get(id)?.props.sector_targeting_relevance ?? 0))
  return max
}

const SEV_INPUT: Record<string, number> = { informational: 0.1, low: 0.25, medium: 0.5, high: 0.75, critical: 1 }

// ----------------------------------------------------------------------------- risk

export function riskBreakdown(alertId: string): RiskBreakdown | undefined {
  const { graph: g } = dataset()
  const spec = alertSpec(alertId)
  const sum = alertSummary(alertId)
  if (!spec || !sum) return undefined
  const { entity, vm, roles } = assetChain(g, spec.entity_id)
  const jewels = crownJewelsFrom(g, roles)
  const S = SEV_INPUT[spec.severity]
  const E = exposureOf(vm, entity)
  const P = roles.length ? Math.max(...roles.map((r) => Number(r.props.privilege_score ?? 0.3))) : 0.05
  const D = jewels.length ? 1 : roles.some((r) => g.edgesOf(r.id, 'out').some((e) => e.type === 'CAN_ACCESS')) ? 0.5 : 0
  const rel = actorRelevance(g, spec.ti_actor_ids ?? [])
  const T = spec.ioc_match_count ? Math.min(1, 0.6 + rel * 0.4) : rel >= 0.7 ? 0.8 : rel > 0 ? rel * 0.5 : 0
  const C = spec.on_attack_path ? 1 : spec.storyline_id ? 0.7 : 0
  const context = 0.15 * E + 0.2 * P + 0.25 * D + 0.2 * T + 0.2 * C
  const raw = Math.round(100 * (0.3 * S + 0.7 * context))
  const rails: string[] = []
  if (spec.on_attack_path && spec.reaches_crown_jewel) rails.push('attack_path_floor:90')
  if (D === 0 && T < 0.1 && P < 0.2) rails.push('no_context_ceiling:25')
  const exploited = vm ? g.edgesOf(vm.id, 'out').filter((e) => e.type === 'VULNERABLE_TO').map((e) => g.get(e.dst)).some((c) => ['active', 'mass_exploitation'].includes(String(c?.props.exploitation_status))) : false
  if (exploited && rel >= 0.7) rails.push('ti_booster:80')
  const jewelNames = jewels.map((j) => j.name).join(', ')
  const factors: RiskFactor[] = [
    { key: 'severity', label: 'Vendor severity', value: S, weight: 0.3, contribution: round(100 * 0.3 * S), reason: `${spec.source} reported ${spec.severity}`, evidence_ids: [alertId] },
    { key: 'exposure', label: 'Exposure', value: E, weight: 0.105, contribution: round(100 * 0.7 * 0.15 * E), reason: E === 1 ? `${(vm ?? entity)?.name} is internet-exposed` : E <= 0.1 ? `${(vm ?? entity)?.name} is isolated` : `${(vm ?? entity)?.name ?? 'asset'} is internal-only`, evidence_ids: [vm?.id ?? entity?.id ?? ''].filter(Boolean) },
    { key: 'privilege', label: 'Privilege reach', value: P, weight: 0.14, contribution: round(100 * 0.7 * 0.2 * P), reason: roles.length ? `identity chain ${roles.map((r) => r.name).join(' -> ')} (privilege ${P.toFixed(2)})` : 'no cloud identity attached to the asset', evidence_ids: roles.map((r) => r.id) },
    { key: 'data', label: 'Data sensitivity reachable', value: D, weight: 0.175, contribution: round(100 * 0.7 * 0.25 * D), reason: jewels.length ? `reaches ${jewels.length} crown jewel${jewels.length > 1 ? 's' : ''}: ${jewelNames}` : D > 0 ? 'reaches internal data only' : 'no data store reachable', evidence_ids: jewels.map((j) => j.id) },
    { key: 'threat_intel', label: 'Threat intel relevance', value: T, weight: 0.14, contribution: round(100 * 0.7 * 0.2 * T), reason: spec.ti_actor_ids?.length ? `${spec.ioc_match_count ?? 0} IOC match(es); actor ${spec.ti_actor_ids.map((a) => g.get(a)?.name ?? a).join(', ')} targets our sector (${rel.toFixed(2)})` : 'no intel match', evidence_ids: spec.ti_actor_ids ?? [] },
    { key: 'correlation', label: 'Incident correlation', value: C, weight: 0.14, contribution: round(100 * 0.7 * 0.2 * C), reason: spec.on_attack_path ? `on the confirmed attack path of ${storylineById(spec.storyline_id ?? '')?.title ?? 'a storyline'}` : spec.storyline_id ? 'correlated into a storyline' : 'no correlated alerts', evidence_ids: spec.storyline_id ? [spec.storyline_id] : [] },
  ]
  return {
    subject_id: alertId,
    vendor_severity: spec.severity,
    vendor_severity_rank: SEVERITY_RANK[spec.severity],
    contextual_score: spec.score,
    band: sum.contextual_band,
    raw_score: raw,
    factors,
    rails,
    reasons: spec.reasons,
    delta_vs_vendor: (sum.contextual_rank_position ?? 0) - (sum.vendor_rank_position ?? 0),
  }
}

const round = (n: number) => Math.round(n * 10) / 10

// ----------------------------------------------------------------------------- insights

export function insightsFor(alertId: string): Insight[] {
  const { graph: g } = dataset()
  const spec = alertSpec(alertId)
  if (!spec) return []
  const { entity, vm, roles } = assetChain(g, spec.entity_id)
  const jewels = crownJewelsFrom(g, roles)
  const out: Insight[] = []
  if (jewels.length && vm) {
    out.push({
      kind: 'blast_radius', hops: entity?.label === 'Endpoint' ? 5 : 4, importance: 1, sources: ['falcon', 'wiz', 'iam', 'data'],
      statement: `${entity?.name} is cloud VM ${vm.name}; its instance role ${roles[0]?.name}${roles[1] ? ` can assume ${roles[1].name}, which` : ''} reads ${jewels.map((j) => `${j.name} (${(j.props.data_classifications as string[] | undefined)?.join('/') ?? j.label})`).join(', ')}.`,
      evidence_node_ids: [alertId, entity!.id, vm.id, ...roles.map((r) => r.id), ...jewels.map((j) => j.id)], evidence_edge_ids: [],
    })
  }
  const stolen = g.edgesOf(alertId, 'in').filter((e) => e.type === 'STOLEN_BY').map((e) => g.get(e.src)!).filter(Boolean)
  for (const cred of stolen) {
    const uses = g.edgesOf(cred.id, 'in').filter((e) => e.type === 'USED_CREDENTIAL').map((e) => g.get(e.src)!).filter(Boolean)
    const derived = g.edgesOf(cred.id, 'in').filter((e) => e.type === 'DERIVED_FROM').map((e) => g.get(e.src)!).filter(Boolean)
    if (uses.length) {
      out.push({
        kind: 'credential_join', hops: 2, importance: 0.95, sources: ['falcon', 'cloudtrail'],
        statement: `Credential ${cred.name} stolen here was used in ${uses.length} cloud API call${uses.length > 1 ? 's' : ''} (${uses.map((u) => String(u.props.event_name)).join(', ')}) from ${String(uses[0].props.source_ip)}${derived.length ? `; it minted ${derived.map((d) => d.name).join(', ')} via AssumeRole` : ''}.`,
        evidence_node_ids: [alertId, cred.id, ...uses.map((u) => u.id), ...derived.map((d) => d.id)], evidence_edge_ids: [],
      })
    }
  }
  const iocEdges = g.edgesOf(alertId, 'out').filter((e) => e.type === 'MATCHES_IOC')
  if (iocEdges.length) {
    const actors = (spec.ti_actor_ids ?? []).map((a) => g.get(a)?.name ?? a)
    out.push({
      kind: 'ti_match', hops: 3, importance: 0.9, sources: ['falcon', 'ti'],
      statement: `Matches ${iocEdges.length} indicator${iocEdges.length > 1 ? 's' : ''} (${iocEdges.map((e) => `${g.get(e.dst)?.props.ioc_type} ${g.get(e.dst)?.name}`).join('; ')}) attributed to ${actors.join(', ')} with confidence ${Math.max(...iocEdges.map((e) => e.confidence ?? 0)).toFixed(2)}.`,
      evidence_node_ids: [alertId, ...iocEdges.map((e) => e.dst), ...(spec.ti_actor_ids ?? [])], evidence_edge_ids: iocEdges.map((e) => e.id),
    })
  }
  if (vm) {
    const cves = g.edgesOf(vm.id, 'out').filter((e) => e.type === 'VULNERABLE_TO').map((e) => g.get(e.dst)!).filter((c) => ['active', 'mass_exploitation'].includes(String(c.props.exploitation_status)))
    const exposed = g.edgesOf(vm.id, 'in').some((e) => e.type === 'EXPOSES')
    if (exposed && cves.length) {
      const actors = cves.flatMap((c) => (c.props.actor_interest as string[]) ?? []).map((a) => g.get(a)?.name ?? a)
      out.push({
        kind: 'exposure', hops: 3, importance: 0.9, sources: ['wiz', 'sbom', 'ti'],
        statement: `${vm.name} is internet-exposed and vulnerable to ${cves.map((c) => c.name).join(', ')} (${cves[0].props.exploitation_status}) which ${actors.join(', ')} is exploiting against our sector.`,
        evidence_node_ids: [vm.id, ID.INTERNET, ...cves.map((c) => c.id)], evidence_edge_ids: [],
      })
    }
  }
  if (entity) {
    const lat = g.edgesOf(entity.id).filter((e) => e.type === 'LATERAL_MOVEMENT_TO')
    for (const e of lat) {
      const other = e.src === entity.id ? g.get(e.dst) : g.get(e.src)
      out.push({
        kind: 'lateral', hops: 1, importance: 0.85, sources: ['falcon'],
        statement: e.src === entity.id ? `${entity.name} moved laterally to ${other?.name} over ${e.props.protocol} as ${e.props.account} at ${e.props.time}.` : `${other?.name} moved laterally into ${entity.name} over ${e.props.protocol} as ${e.props.account} at ${e.props.time}.`,
        evidence_node_ids: [entity.id, other?.id ?? ''].filter(Boolean), evidence_edge_ids: [e.id],
      })
    }
  }
  const story = spec.storyline_id ? storylineById(spec.storyline_id) : undefined
  if (story) {
    const hosts = new Set(story.alert_ids.map((a) => alertSummary(a)?.hostname).filter(Boolean))
    out.push({
      kind: 'correlation', hops: 2, importance: 0.8, sources: ['falcon', 'cloudtrail', 'derived'],
      statement: `One of ${story.alert_ids.length} alerts in "${story.title}" spanning ${hosts.size} host${hosts.size > 1 ? 's' : ''} and ${story.stage_count} kill-chain stages${story.actor_name ? `, attributed to ${story.actor_name}` : ''}.`,
      evidence_node_ids: [story.id, ...story.alert_ids], evidence_edge_ids: [],
    })
  }
  if (spec.score <= 25) {
    out.push({
      kind: 'noise', hops: 2, importance: 0.7, sources: ['wiz', 'iam', 'ti'],
      statement: `No sensitive data reachable, no intel match and no privileged identity behind ${entity?.name ?? 'this asset'}: the vendor ${spec.severity} severity is not corroborated by context (${spec.reasons.join('; ')}).`,
      evidence_node_ids: [alertId, entity?.id ?? ''].filter(Boolean), evidence_edge_ids: [],
    })
  }
  if (spec.change_ticket) {
    out.push({ kind: 'ownership', hops: 1, importance: 0.6, sources: ['itsm'], statement: `Activity falls inside approved change ${spec.change_ticket} by ${spec.user}.`, evidence_node_ids: [alertId], evidence_edge_ids: [] })
  }
  const owner = (vm ?? entity) ? g.edgesOf((vm ?? entity)!.id, 'out').find((e) => e.type === 'OWNED_BY' || e.type === 'PART_OF') : undefined
  if (owner) {
    const o = g.get(owner.dst)
    out.push({ kind: 'ownership', hops: 1, importance: 0.4, sources: ['wiz'], statement: `${(vm ?? entity)!.name} ${owner.type === 'OWNED_BY' ? 'is owned by' : 'is part of'} ${o?.name} (${o?.label}).`, evidence_node_ids: [(vm ?? entity)!.id, owner.dst], evidence_edge_ids: [owner.id] })
  }
  return out.sort((a, b) => b.importance - a.importance)
}

// ----------------------------------------------------------------------------- blast radius

function reached(g: MockGraph, id: string, info: { hops: number; via: string[] }): ReachedNode {
  const node = g.get(id)!
  const access = g.edgesOf(id, 'in').find((e) => e.type === 'CAN_ACCESS' && info.via.includes(e.src))
  return { node, hops: info.hops, reach_score: Math.max(0.1, 1 - info.hops * 0.12), via_path: info.via, access_level: access ? String(access.props.access_level ?? 'read') : null }
}

export function blastRadius(rootId: string, depth = 4, maxNodes = 150): BlastRadiusResult | undefined {
  const { graph: g } = dataset()
  const root = g.get(rootId)
  if (!root) return undefined
  const reach = g.reach(rootId, REACH_EDGES, depth, REACH_REVERSE)
  reach.delete(rootId)
  const entries = [...reach.entries()]
  const crown: ReachedNode[] = []
  const data: ReachedNode[] = []
  const secrets: ReachedNode[] = []
  const identities: ReachedNode[] = []
  const accounts = new Set<string>()
  const byHop: Record<string, number> = {}
  for (const [id, info] of entries) {
    const n = g.get(id)!
    byHop[String(info.hops)] = (byHop[String(info.hops)] ?? 0) + 1
    if (n.props.account_id) accounts.add(String(n.props.account_id))
    const r = reached(g, id, info)
    if (n.tags.includes('crown_jewel')) crown.push(r)
    else if (n.label === 'StorageBucket' || n.label === 'Database') data.push(r)
    if (n.label === 'Secret') secrets.push(r)
    if (['IamRole', 'IamUser', 'HumanUser', 'ServiceAccount', 'Credential'].includes(n.label)) identities.push(r)
  }
  const byScore = (a: ReachedNode, b: ReachedNode) => a.hops - b.hops || a.node.name.localeCompare(b.node.name)
  crown.sort(byScore); data.sort(byScore); secrets.sort(byScore); identities.sort(byScore)
  const edgeIds = new Set<string>()
  for (const [, info] of entries) for (const e of info.edgeIds) edgeIds.add(e)
  const fragment = g.fragment([rootId, ...reach.keys()], { edgeIds, focus: [rootId], hint: 'blast_radius', max: maxNodes, highlight: new Set([rootId, ...crown.map((c) => c.node.id)]) })
  const summary = `${root.name} reaches ${entries.length} nodes within ${depth} hops: ${crown.length} crown jewel${crown.length === 1 ? '' : 's'}${crown.length ? ` (${crown.map((c) => c.node.name).join(', ')})` : ''}, ${secrets.length} secret${secrets.length === 1 ? '' : 's'}, ${identities.length} identit${identities.length === 1 ? 'y' : 'ies'} across ${accounts.size} account${accounts.size === 1 ? '' : 's'}.`
  return { root_id: rootId, depth, reached_count: entries.length, crown_jewels: crown, data_stores: data, secrets, identities, accounts_touched: [...accounts], by_hop: byHop, summary, fragment }
}

// ----------------------------------------------------------------------------- attack paths

function chainFragment(g: MockGraph, ids: string[], hint: GraphFragment['layout_hint']): { fragment: GraphFragment; path: PathOut } {
  const edgeIds: string[] = []
  for (let i = 0; i < ids.length - 1; i++) {
    const e = g.edgeBetween(ids[i], ids[i + 1])
    if (e) edgeIds.push(e.id)
  }
  const path: PathOut = { node_ids: ids, edge_ids: edgeIds, hops: ids.length - 1, label: `${ids.length - 1} hops`, likelihood: 0.9, stages: [] }
  const fragment = g.fragment(ids, { edgeIds, focus: [ids[0], ids[ids.length - 1]], hint, paths: [path], highlight: new Set([...ids, ...edgeIds]) })
  return { fragment, path }
}

export function attackPathsAll(): AttackPathOut[] {
  const { graph: g } = dataset()
  const a = storylineById(ID.STORYLINE_A)!
  const b = storylineById(ID.STORYLINE_B)!
  const chainA = [ID.A001, ID.WKS_DANA, ID.EP_BASTION, ID.BASTION_VM, ID.BASTION_ROLE, ID.PROD_READER_ROLE, ID.CARDHOLDER_VAULT]
  const chainB = [ID.B001, ID.EDGE_VM, ID.EDGE_ROLE, ID.APP_CONFIG_BUCKET, ID.CARDHOLDER_DB]
  const fa = chainFragment(g, chainA, 'path')
  fa.path.stages = a.stages.map((s) => s.stage)
  fa.path.label = 'EMBERCAST: phishing to cardholder vault'
  const fb = chainFragment(g, chainB, 'path')
  fb.path.stages = b.stages.map((s) => s.stage)
  fb.path.label = 'SALTWORKS: Log4Shell to cardholder-db credentials'
  fb.path.likelihood = 0.6
  return [
    { id: 'attackpath:embercast:vault', entry_id: ID.A001, target_id: ID.CARDHOLDER_VAULT, through_id: ID.BASTION_VM, likelihood: 0.9, hops: chainA.length - 1, stages: a.stages, summary: 'Phishing on WKS-3391 -> SSH lateral movement to bas-01 -> instance role -> cross-account AssumeRole -> PCI cardholder vault (observed end to end).', fragment: fa.fragment },
    { id: 'attackpath:saltworks:cardholder-db', entry_id: ID.B001, target_id: ID.CARDHOLDER_DB, through_id: ID.EDGE_VM, likelihood: 0.6, hops: chainB.length - 1, stages: b.stages, summary: 'Log4Shell on internet-exposed stmt-render-2a -> instance role reads prod-app-config (DB credentials) -> cardholder-db (potential; no cloud API use observed yet).', fragment: fb.fragment },
  ]
}

export function attackPathsFor(opts: { through?: string; target?: string; entry?: string; k?: number }): AttackPathOut[] {
  const { graph: g } = dataset()
  const all = attackPathsAll()
  const related = (p: AttackPathOut, id: string) => {
    if (p.fragment.nodes.some((n) => n.id === id) || p.stages.some((s) => s.node_ids.includes(id))) return true
    const chain = assetChain(g, id)
    return [chain.vm?.id, chain.entity?.id, ...chain.roles.map((r) => r.id)].filter(Boolean).some((x) => p.fragment.nodes.some((n) => n.id === x))
  }
  return all.filter((p) => (!opts.through || related(p, opts.through)) && (!opts.target || related(p, opts.target)) && (!opts.entry || related(p, opts.entry))).slice(0, opts.k ?? 5)
}

// ----------------------------------------------------------------------------- storyline fragments

export function storylineFragment(story: StorylineOut): GraphFragment {
  const { graph: g } = dataset()
  const nodeIds: string[] = []
  const edgeIds: string[] = []
  for (const s of story.stages) {
    nodeIds.push(...s.node_ids)
    edgeIds.push(...s.edge_ids)
  }
  const paths = attackPathsAll().filter((p) => story.alert_ids.includes(p.entry_id))
  for (const p of paths) {
    nodeIds.push(...p.fragment.nodes.map((n) => n.id))
    edgeIds.push(...p.fragment.edges.map((e) => e.id))
  }
  const highlight = new Set(paths.flatMap((p) => [...p.fragment.paths[0].node_ids, ...p.fragment.paths[0].edge_ids]))
  const frag = g.fragment(nodeIds, { edgeIds, focus: story.alert_ids.slice(0, 1), hint: 'storyline', paths: paths.map((p) => p.fragment.paths[0]), highlight })
  frag.meta = { storyline_id: story.id, stages: story.stages.map((s) => ({ order: s.order, stage: s.stage, node_ids: s.node_ids })) }
  return frag
}

export function storylineWithFragment(id: string): StorylineOut | undefined {
  const s = storylineById(id)
  if (!s) return undefined
  return { ...s, fragment: storylineFragment(s) }
}

// ----------------------------------------------------------------------------- alert context

export function alertContext(alertId: string): AlertContext | undefined {
  const { graph: g, summaries } = dataset()
  const spec = alertSpec(alertId)
  const alert = alertSummary(alertId)
  const risk = riskBreakdown(alertId)
  if (!spec || !alert || !risk) return undefined
  const story = spec.storyline_id ? storylineWithFragment(spec.storyline_id) : null
  const paths = attackPathsFor({ through: alertId }).filter((p) => !story || story.alert_ids.includes(p.entry_id) || p.fragment.nodes.some((n) => n.id === spec.entity_id))
  const br = blastRadius(alertId, 6, 120)
  let evidence: GraphFragment
  if (story?.fragment) {
    evidence = { ...story.fragment, focus: [alertId], layout_hint: 'path' }
  } else {
    evidence = g.neighborhood(alertId, 2, { maxNodes: 60 })
    if (br) evidence = mergeFragments(evidence, br.fragment)
    evidence.focus = [alertId]
    evidence.layout_hint = 'neighborhood'
  }
  evidence.nodes = evidence.nodes.map((n) => ({ ...n, highlight: n.id === alertId || n.highlight }))
  const related = [...summaries.values()].filter((a) => a.id !== alertId && ((spec.storyline_id && a.storyline_id === spec.storyline_id) || (a.entity_id && a.entity_id === spec.entity_id) || (spec.hostname && a.hostname === spec.hostname))).sort((a, b) => b.contextual_score - a.contextual_score).slice(0, 12)
  const ti: TIContext | null = spec.ti_actor_ids?.length || spec.ioc_match_count ? tiContextForNode(alertId) : null
  return { alert, flat_view: spec.flat, risk, insights: insightsFor(alertId), blast_radius: br ?? null, attack_paths: paths, storyline: story ?? null, threat_intel: ti, related_alerts: related, evidence }
}

// ----------------------------------------------------------------------------- containment

export function containment(targetIds: string[], actions: string[]): ContainmentSimulation {
  const { graph: g, storylines } = dataset()
  const targets = targetIds.map((t) => g.get(t)).filter((n): n is MockNode => !!n)
  const expanded = new Set<string>(targetIds)
  for (const t of targets) {
    const chain = assetChain(g, t.id)
    if (chain.vm) expanded.add(chain.vm.id)
    if (chain.entity) expanded.add(chain.entity.id)
    if (actions.includes('rotate_role_credentials') || actions.includes('tighten_trust_policy')) chain.roles.forEach((r) => expanded.add(r.id))
  }
  const paths = attackPathsAll()
  const cut = paths.filter((p) => p.fragment.nodes.some((n) => expanded.has(n.id)))
  const contained = storylines.filter((s) => cut.some((p) => s.alert_ids.includes(p.entry_id))).map((s) => s.id)
  const protectedJewels = [...new Set(cut.flatMap((p) => p.fragment.nodes.filter((n) => n.tags.includes('crown_jewel')).map((n) => n.id)))]
  const breaks: BreakItem[] = []
  for (const id of expanded) {
    for (const e of g.edgesOf(id, 'in')) {
      if (e.type !== 'DEPENDS_ON') continue
      const app = g.get(e.src)
      if (!app) continue
      const team = g.edgesOf(app.id, 'out').find((x) => x.type === 'OWNED_BY')
      breaks.push({ node_id: app.id, name: app.name, label: app.label, impact: `${app.name} (${app.props.criticality}) depends on ${g.get(id)?.name} for ${e.props.dependency_type}; isolating it interrupts the service for ${g.get(team?.dst ?? '')?.name ?? 'its owner team'}.`, owner_team_id: team?.dst ?? null })
    }
    const n = g.get(id)
    if (n?.label === 'VirtualMachine' && n.props.tags && (n.props.tags as Record<string, string>).role === 'bastion') {
      breaks.push({ node_id: n.id, name: n.name, label: n.label, impact: 'SSM/SSH break-glass access for Platform Engineering goes through this bastion; on-call will need the backup bastion.', owner_team_id: ID.TEAM_PLATFORM })
    }
  }
  const residual: string[] = []
  const recs: string[] = []
  const bastionTargeted = expanded.has(ID.BASTION_VM) || expanded.has(ID.BASTION_ROLE)
  if (bastionTargeted) {
    if (actions.includes('rotate_role_credentials')) {
      residual.push('Rotating LarkspurBastionSSMRole invalidates ASIA5LARKBASTION01Q7 but not the already-issued ASIA5LARKPRODREADER1 session; that session expired at 2026-09-10T03:24Z (+1h), so it is no longer usable, but 1,247 objects (~38 GB) were already read from larkspur-cardholder-vault.')
    } else {
      residual.push('Instance-role credentials ASIA5LARKBASTION01Q7 remain valid until rotated (already expired by clock, but rotate to be certain).')
    }
    if (!actions.includes('tighten_trust_policy')) {
      residual.push('LarkspurProdDataReader still trusts LarkspurBastionSSMRole; any future bastion compromise reaches the PCI vault again.')
      recs.push('Tighten the trust policy of LarkspurProdDataReader: remove the bastion role principal or add an aws:SourceVpc condition.')
    }
    residual.push('WKS-3391 still runs NIGHTFERRY (C2 to cdn-metrics.telemetry-sync.net); the initial foothold is outside the requested containment scope.')
    recs.push('Isolate WKS-3391 as well and reset dwhitfield credentials, including the id_ed25519 SSH key and the svc-finops-sftp authorized key.')
    if (!actions.includes('block_ip')) recs.push('Block 203.0.113.77 and 203.0.113.42 at the egress proxy and in IAM policies (aws:SourceIp deny).')
    recs.push('Treat larkspur-cardholder-vault as breached: begin PCI incident notification and rotate prod/cardholder-db/reader and prod/hsm/partner-signing-key.')
  } else {
    residual.push('Other paths that do not traverse the selected targets remain open.')
    recs.push('Review the remaining attack paths in the explorer and extend containment to the entry point.')
  }
  if (expanded.has(ID.EDGE_VM) || expanded.has(ID.EP_EDGE)) {
    recs.push('Patch log4j-core to 2.17.1 (or redeploy statement-render:3.8.2) before returning stmt-render-2a to service; remove /opt/statement-render/webapps/ROOT/.b.jsp.')
    residual.push('stmt-render-stg-1 and log4j-testbed carry the same CVE and remain internet-exposed.')
  }
  const fragNodes = new Set<string>([...expanded, ...cut.flatMap((p) => p.fragment.nodes.map((n) => n.id)), ...breaks.map((b) => b.node_id)])
  const fragment = g.fragment(fragNodes, { focus: [...expanded], hint: 'path', highlight: new Set(expanded), paths: cut.map((p) => p.fragment.paths[0]) })
  fragment.meta = { cut_edge_ids: cut.flatMap((p) => p.fragment.edges.filter((e) => expanded.has(e.src) || expanded.has(e.dst)).map((e) => e.id)) }
  return { target_ids: targetIds, actions, paths_cut: cut.length, storylines_contained: contained, crown_jewels_protected: protectedJewels, breaks, residual_risks: residual, recommendations: recs, fragment }
}

// ----------------------------------------------------------------------------- investigations

export function credentialJoins() {
  const { graph: g } = dataset()
  const items = []
  const nodeIds = new Set<string>()
  for (const cred of g.byLabel('Credential')) {
    const uses = g.edgesOf(cred.id, 'in').filter((e) => e.type === 'USED_CREDENTIAL').map((e) => g.get(e.src)!).filter(Boolean)
    if (!uses.length) continue
    let stolenAlert = g.edgesOf(cred.id, 'out').find((e) => e.type === 'STOLEN_BY' && e.dst.startsWith('alert:'))?.dst
    const parent = g.edgesOf(cred.id, 'out').find((e) => e.type === 'DERIVED_FROM')?.dst
    if (!stolenAlert && parent) stolenAlert = g.edgesOf(parent, 'out').find((e) => e.type === 'STOLEN_BY' && e.dst.startsWith('alert:'))?.dst
    if (!stolenAlert) continue
    const alert = alertSummary(stolenAlert)!
    const endpoint = g.get(alert.entity_id ?? '')!
    const principal = g.get(String(cred.props.principal_id))!
    const derived = g.edgesOf(cred.id, 'in').filter((e) => e.type === 'DERIVED_FROM').map((e) => g.get(e.src)!)
    uses.sort((a, b) => String(a.props.event_time).localeCompare(String(b.props.event_time)))
    items.push({ credential: cred, stolen_by_alert: alert, endpoint, principal, used_in_events: uses, derived_credentials: derived, first_use: String(uses[0].props.event_time), source_ips: [...new Set(uses.map((u) => String(u.props.source_ip)))] })
    ;[cred.id, stolenAlert, endpoint.id, principal.id, ...uses.map((u) => u.id), ...derived.map((d) => d.id), ...(parent ? [parent] : [])].forEach((i) => nodeIds.add(i))
  }
  items.sort((a, b) => (a.credential.props.derived_from ? 1 : 0) - (b.credential.props.derived_from ? 1 : 0))
  const fragment = g.fragment(nodeIds, { focus: items.map((i) => i.credential.id), hint: 'path', highlight: new Set(items.map((i) => i.credential.id)) })
  return { items, fragment }
}

export function alertsReachingCrownJewels(jewelId?: string, classification?: string) {
  const { graph: g, alertsByContextual } = dataset()
  const jewels = [...g.nodes.values()].filter((n) => n.tags.includes('crown_jewel') && (!jewelId || n.id === jewelId) && (!classification || ((n.props.data_classifications as string[]) ?? []).includes(classification)))
  const items: AlertSummary[] = []
  const nodeIds = new Set<string>(jewels.map((j) => j.id))
  for (const a of alertsByContextual) {
    if (!a.reaches_crown_jewel) continue
    const chain = assetChain(g, a.entity_id)
    const reach = crownJewelsFrom(g, chain.roles)
    const hits = jewelId || classification ? reach.filter((r) => jewels.some((j) => j.id === r.id)) : reach
    if (!hits.length && !(a.storyline_id && !jewelId && !classification)) continue
    items.push(a)
    ;[a.id, chain.entity?.id, chain.vm?.id, ...chain.roles.map((r) => r.id), ...hits.map((h) => h.id)].forEach((i) => i && nodeIds.add(i))
  }
  return { items, jewels, fragment: g.fragment(nodeIds, { focus: jewels.map((j) => j.id), hint: 'blast_radius', highlight: new Set(jewels.map((j) => j.id)) }) }
}

export function mediumAlertsWithDataPath(severity = 'medium', source = 'falcon') {
  const { graph: g, alertsByContextual } = dataset()
  const items = alertsByContextual.filter((a) => a.vendor_severity === severity && a.source_system === source && a.reaches_crown_jewel)
  const nodeIds = new Set<string>()
  for (const a of items) {
    const chain = assetChain(g, a.entity_id)
    ;[a.id, chain.entity?.id, chain.vm?.id, ...chain.roles.map((r) => r.id), ...crownJewelsFrom(g, chain.roles).map((j) => j.id)].forEach((i) => i && nodeIds.add(i))
  }
  return { items, fragment: g.fragment(nodeIds, { focus: items.slice(0, 1).map((a) => a.id), hint: 'path', highlight: new Set(items.map((a) => a.id)) }) }
}

export function nodeAlerts(nodeId: string): AlertSummary[] {
  const { graph: g, alertsByContextual } = dataset()
  const related = new Set<string>([nodeId])
  for (const e of g.edgesOf(nodeId)) if (e.type === 'SAME_AS') related.add(e.src === nodeId ? e.dst : e.src)
  return alertsByContextual.filter((a) => (a.entity_id && related.has(a.entity_id)) || g.edgesOf(a.id, 'out').some((e) => e.type === 'INVOLVES' && related.has(e.dst)))
}

export function nodeOut(n: MockNode): NodeOut {
  return n
}

export function severityOf(s: string): Severity {
  return (s in SEVERITY_RANK ? s : 'informational') as Severity
}
