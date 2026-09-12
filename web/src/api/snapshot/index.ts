/**
 * Snapshot adapter: answers `/api/v1` requests from the precomputed JSON files of the static edition
 * (docs/10-static-snapshot.md section 3). Enabled with `VITE_STATIC=1` at build time or `?snapshot=1`.
 * The route table mirrors the mock adapter's (src/api/mock/index.ts); handlers are async because files load lazily.
 */
import { ApiError, type Query } from '../client'
import type {
  AlertContext, AlertsReachingJewelsOut, AttackPathsOut, BlastRadiusResult, ChatContext, ContainmentSimulation, GraphFragment,
  MediumAlertsDataPathOut, TIContext,
} from '../types'
import { emptyFragment } from '../types'
import { alertsList, relatedAlerts } from './alerts'
import { createSession, getSession, suggestionsFor } from './chat'
import { loadGraph, type Direction } from './graph'
import { hydratePayload } from './hydrate'
import { loadAlertDetail, loadAlerts, loadAttackPathsOptional, loadBlastRadiusOptional, loadChat, loadInvestigate, loadMeta, loadSearch, loadStorylines, loadTi } from './loader'
import { nodeDetail, nodesBatch } from './nodes'
import { absent, bool, list, num, str } from './query'
import type { AlertDetailEntry, ContainmentEntry } from './schema'
import { searchEntries } from './search'

export { snapshotStream } from './chat'

type Handler = (params: Record<string, string>, query: Query, body: unknown) => unknown

/** `meta.note` on payloads served for parameters the exporter did not precompute. */
export const DEFAULT_NOTE = 'static edition: precomputed for the default parameters'
const CYPHER_MESSAGE = 'The static edition has no query engine; run the container to use Cypher.'
const API_DEFAULT_BLAST_DEPTH = 4

const notFound = (what: string) => new ApiError(404, 'not_found', `${what} not found`)

function withNote<T extends { fragment: GraphFragment }>(payload: T, note: string): T {
  return { ...payload, fragment: { ...payload.fragment, meta: { ...payload.fragment.meta, note } } }
}

// ----------------------------------------------------------------------------- alerts

async function alertDetail(id: string): Promise<AlertDetailEntry> {
  const entry = await loadAlertDetail(id)
  if (!entry) throw notFound(`alert ${id}`)
  return entry
}

/** Alerts the exporter did not precompute in full get a context assembled from the shard, `alerts.json` and the graph index. */
async function liteContext(entry: AlertDetailEntry): Promise<AlertContext> {
  const { alert } = entry
  const alerts = await loadAlerts()
  let storyline: AlertContext['storyline'] = null
  if (alert.storyline_id) {
    const sl = await loadStorylines()
    storyline = sl.details[alert.storyline_id] ?? sl.items.find((s) => s.id === alert.storyline_id) ?? null
  }
  let evidence = emptyFragment('neighborhood')
  let blast: BlastRadiusResult | null = null
  try {
    const g = await loadGraph()
    const seed = g.has(alert.id) ? alert.id : alert.entity_id && g.has(alert.entity_id) ? alert.entity_id : null
    if (seed) {
      evidence = g.neighborhood(seed, seed === alert.id ? 2 : 1, { maxNodes: 60 })
      blast = g.approxBlastRadius(seed, API_DEFAULT_BLAST_DEPTH, 100) ?? null
    }
  } catch {
    /* graph shards unavailable: the context still renders without a canvas */
  }
  evidence.focus = [alert.id]
  evidence.nodes = evidence.nodes.map((n) => (n.id === alert.id ? { ...n, highlight: true } : n))
  evidence.meta = { ...evidence.meta, note: 'static edition: lite context (this alert was not precomputed in full)' }
  return { alert, flat_view: entry.flat_view, risk: entry.risk, insights: entry.insights ?? [], blast_radius: blast, attack_paths: [], storyline, threat_intel: null, related_alerts: relatedAlerts(alerts.items, alert), evidence }
}

// ----------------------------------------------------------------------------- graph

function direction(v: string): Direction {
  return v === 'in' || v === 'out' ? v : 'both'
}

async function blastRadius(id: string, query: Query, maxNodesDefault: number): Promise<BlastRadiusResult> {
  if (!id) throw new ApiError(400, 'invalid_argument', 'id is required')
  const depth = absent(query.depth) ? undefined : num(query.depth, API_DEFAULT_BLAST_DEPTH, 6)
  const pre = (await loadBlastRadiusOptional())[id]
  // The engine's result wins for the default depth (or the depth it was computed at); an explicit other depth gets the approximation.
  if (pre && (depth === undefined || depth === pre.depth || depth === API_DEFAULT_BLAST_DEPTH)) return pre
  const g = await loadGraph().catch(() => null)
  const approx = g?.approxBlastRadius(id, depth ?? API_DEFAULT_BLAST_DEPTH, num(query.max_nodes, maxNodesDefault, 300))
  if (approx) return approx
  if (pre) return pre
  throw notFound(`node ${id}`)
}

async function attackPaths(query: Query): Promise<AttackPathsOut> {
  const through = str(query.through)
  const target = str(query.target)
  const entry = str(query.entry)
  const k = Math.max(1, num(query.k, 5, 5))
  const all = await loadAttackPathsOptional()
  let hit = through ? all[through] : undefined
  if (hit && target) hit = { ...hit, paths: hit.paths.filter((p) => p.target_id === target) }
  if (!hit && target) hit = all[`internet->${target}`] ?? (entry ? all[`${entry}->${target}`] : undefined)
  if (hit) return { paths: hit.paths.slice(0, k), fragment: hit.fragment ?? emptyFragment('path') }
  const fragment = emptyFragment('path')
  fragment.meta = { note: 'static edition: attack paths were precomputed for the storyline alerts, their anchor assets and the internet -> crown-jewel pairs only' }
  return { paths: [], fragment }
}

// ----------------------------------------------------------------------------- threat intel

function emptyTiContext(value: string): TIContext {
  return {
    matches: [],
    actors: [],
    campaigns: [],
    malware: [],
    exploited_vulnerabilities: [],
    reports: [],
    ttp_overlap: {},
    sector_relevance: null,
    summary: `No precomputed threat-intel lookup for "${value}" (static edition: only the snapshot's indicators, CVEs, techniques, actors, campaigns and reports are indexed).`,
  }
}

// ----------------------------------------------------------------------------- investigations

function nameOf(sim: ContainmentSimulation, id: string): string {
  return sim.fragment?.nodes.find((n) => n.id === id)?.name ?? id
}

/** Exact target/action set match, else the closest prepared simulation with a visible note. */
function pickContainment(entries: ContainmentEntry[], targets: string[], actions: string[]): ContainmentSimulation {
  if (!entries.length) throw new ApiError(501, 'not_supported', 'The static edition has no containment simulator and this snapshot carries no precomputed simulations; run the container to simulate containment.')
  const tset = new Set(targets)
  const aset = new Set(actions)
  const sameSet = (xs: string[], set: Set<string>) => xs.length === set.size && xs.every((x) => set.has(x))
  const exact = entries.find((e) => sameSet(e.targets, tset) && sameSet(e.actions, aset))
  if (exact) return exact.result
  const overlap = (xs: string[], set: Set<string>) => {
    const union = new Set([...xs, ...set])
    return union.size ? xs.filter((x) => set.has(x)).length / union.size : 1
  }
  let best = entries[0]
  let bestScore = -1
  for (const e of entries) {
    const score = overlap(e.targets, tset) * 2 + overlap(e.actions, aset)
    if (score > bestScore) {
      best = e
      bestScore = score
    }
  }
  const sim = best.result
  const note = `Static edition: your selection was not precomputed. Showing the closest prepared simulation — targets ${best.targets.map((t) => nameOf(sim, t)).join(', ')} with actions ${best.actions.join(', ')}. Run the container for arbitrary containment inputs.`
  return { ...sim, residual_risks: [note, ...(sim.residual_risks ?? [])], fragment: { ...sim.fragment, meta: { ...sim.fragment.meta, note: DEFAULT_NOTE } } }
}

// ----------------------------------------------------------------------------- route table (mirrors src/api/mock/index.ts)

const routes: [RegExp, string, Handler][] = [
  [/^\/health$/, 'GET', async () => (await loadMeta()).health],
  [/^\/stats$/, 'GET', async () => (await loadMeta()).stats],
  [/^\/schema$/, 'GET', async () => (await loadMeta()).schema],
  [/^\/dashboard$/, 'GET', async () => (await loadMeta()).dashboard],
  [/^\/alerts$/, 'GET', async (_p, q) => alertsList((await loadAlerts()).items, q)],
  [/^\/alerts\/([^/]+)$/, 'GET', async (p) => {
    const e = await alertDetail(p[1])
    return { alert: e.alert, flat_view: e.flat_view }
  }],
  [/^\/alerts\/([^/]+)\/context$/, 'GET', async (p) => {
    const e = await alertDetail(p[1])
    return e.context ?? liteContext(e)
  }],
  [/^\/alerts\/([^/]+)\/risk$/, 'GET', async (p) => (await alertDetail(p[1])).risk],
  [/^\/alerts\/([^/]+)\/insights$/, 'GET', async (p) => ({ insights: (await alertDetail(p[1])).insights ?? [] })],
  [/^\/storylines$/, 'GET', async () => ({ items: (await loadStorylines()).items })],
  [/^\/storylines\/([^/]+)$/, 'GET', async (p) => {
    const sl = await loadStorylines()
    const s = sl.details[p[1]] ?? sl.items.find((x) => x.id === p[1])
    if (!s) throw notFound(`storyline ${p[1]}`)
    return s
  }],
  [/^\/search$/, 'GET', async (_p, q) => ({ hits: searchEntries((await loadSearch()).entries, str(q.q), list(q.labels), num(q.limit, 25, 100)) })],
  [/^\/nodes\/batch$/, 'POST', (_p, _q, body) => nodesBatch((body as { ids?: string[] } | null)?.ids ?? [])],
  [/^\/nodes\/([^/]+)$/, 'GET', (p) => nodeDetail(p[1])],
  [/^\/graph\/neighborhood$/, 'GET', async (_p, q) => {
    const id = str(q.id)
    const g = await loadGraph()
    if (!g.has(id)) throw notFound(`node ${id}`)
    return g.neighborhood(id, num(q.depth, 1, 3), { edgeTypes: list(q.edge_types), direction: direction(str(q.direction, 'both')), labels: list(q.labels), maxNodes: num(q.max_nodes, 150, 300) })
  }],
  [/^\/graph\/paths$/, 'GET', async (_p, q) => {
    const src = str(q.src)
    const dst = str(q.dst)
    const g = await loadGraph()
    if (!g.has(src) || !g.has(dst)) throw notFound(`node ${g.has(src) ? dst : src}`)
    return g.paths(src, dst, num(q.max_hops, 6, 8), num(q.k, 3, 5), list(q.edge_types))
  }],
  [/^\/graph\/blast-radius$/, 'GET', (_p, q) => blastRadius(str(q.id), q, 150)],
  [/^\/graph\/attack-paths$/, 'GET', (_p, q) => attackPaths(q)],
  [/^\/graph\/cypher$/, 'POST', () => {
    throw new ApiError(501, 'not_supported', CYPHER_MESSAGE)
  }],
  [/^\/threat-intel\/actors$/, 'GET', async () => (await loadTi()).actors],
  [/^\/threat-intel\/actors\/([^/]+)$/, 'GET', async (p) => {
    const ti = await loadTi()
    return ti.actor_details[p[1]] ?? ti.campaign_details[p[1]] ?? (() => { throw notFound(`actor ${p[1]}`) })()
  }],
  [/^\/threat-intel\/campaigns\/([^/]+)$/, 'GET', async (p) => {
    const ti = await loadTi()
    return ti.campaign_details[p[1]] ?? ti.actor_details[p[1]] ?? (() => { throw notFound(`campaign ${p[1]}`) })()
  }],
  [/^\/threat-intel\/reports$/, 'GET', async () => (await loadTi()).reports],
  [/^\/threat-intel\/reports\/([^/]+)$/, 'GET', async (p) => (await loadTi()).report_details[p[1]] ?? (() => { throw notFound(`report ${p[1]}`) })()],
  [/^\/threat-intel\/lookup$/, 'GET', async (_p, q) => {
    const raw = str(q.value).trim()
    const ti = await loadTi()
    return ti.lookups[raw.toLowerCase()] ?? ti.lookups[raw] ?? emptyTiContext(raw)
  }],
  [/^\/threat-intel\/exposure$/, 'GET', async (_p, q) => {
    const ti = await loadTi()
    return (bool(q.sector_only) ?? true) ? ti.exposure.sector_only : ti.exposure.all
  }],
  [/^\/investigate\/credential-joins$/, 'GET', async () => (await loadInvestigate()).credential_joins],
  [/^\/investigate\/alerts-reaching-crown-jewels$/, 'GET', async (_p, q) => {
    const inv = await loadInvestigate()
    const table = inv.alerts_reaching_crown_jewels
    const jewel = str(q.jewel_id)
    const classification = str(q.classification)
    const hit = table[jewel]
    if (hit && !classification) return hit
    const fallback: AlertsReachingJewelsOut = table[''] ?? Object.values(table)[0] ?? { items: [], jewels: [], fragment: emptyFragment('blast_radius') }
    return withNote(hit ?? fallback, DEFAULT_NOTE)
  }],
  [/^\/investigate\/identity-footprint$/, 'GET', async (_p, q) => {
    const id = str(q.id)
    if (!id) throw new ApiError(400, 'invalid_argument', 'id is required')
    const inv = await loadInvestigate()
    return inv.identity_footprint[id] ?? blastRadius(id, { id }, 200).catch(() => { throw notFound(`identity ${id}`) })
  }],
  [/^\/investigate\/medium-alerts-with-data-path$/, 'GET', async (_p, q) => {
    const inv = await loadInvestigate()
    const table = inv.medium_alerts_with_data_path
    const key = `${str(q.severity, 'medium')}|${str(q.source, 'falcon')}`
    const hit = table[key]
    if (hit) return hit
    const fallback: MediumAlertsDataPathOut = table['medium|falcon'] ?? Object.values(table)[0] ?? { items: [], fragment: emptyFragment('path') }
    return withNote(fallback, DEFAULT_NOTE)
  }],
  [/^\/investigate\/containment$/, 'POST', async (_p, _q, body) => {
    const b = (body ?? {}) as { target_ids?: string[]; actions?: string[] }
    if (!b.target_ids?.length) throw new ApiError(400, 'invalid_argument', 'target_ids is required')
    return pickContainment((await loadInvestigate()).containment ?? [], b.target_ids, b.actions ?? [])
  }],
  [/^\/chat\/sessions$/, 'POST', (_p, _q, body) => createSession((body as { context?: ChatContext } | null)?.context)],
  [/^\/chat\/sessions\/([^/]+)$/, 'GET', (p) => getSession(p[1]) ?? (() => { throw notFound(`session ${p[1]}`) })()],
  [/^\/chat\/suggestions$/, 'GET', async (_p, q) => ({ questions: suggestionsFor(await loadChat(), { alert_id: str(q.alert_id) || undefined, node_id: str(q.node_id) || undefined, storyline_id: str(q.storyline_id) || undefined }) })],
]

function decode(v: string): string {
  try {
    return decodeURIComponent(v)
  } catch {
    return v
  }
}

/** Routes whose payloads carry GraphFragments the exporter may have stripped of node props (see ./hydrate). */
const HYDRATED = /^\/(alerts\/[^/]+\/context|storylines\/[^/]+|graph\/(blast-radius|attack-paths)|threat-intel\/(actors|campaigns|reports)\/[^/]+|investigate\/.+)$/

/** Dispatch one request; every failure surfaces as an `ApiError` (never a raw exception). */
export async function snapshotRequest<T>(method: string, path: string, query: Query, body: unknown): Promise<T> {
  for (const [re, m, handler] of routes) {
    const match = path.match(re)
    if (!match || m !== method) continue
    const params: Record<string, string> = {}
    match.forEach((v, i) => (params[String(i)] = decode(v ?? '')))
    try {
      const payload = await handler(params, query, body)
      return (HYDRATED.test(path) ? await hydratePayload(payload) : payload) as T
    } catch (e) {
      if (e instanceof ApiError) throw e
      throw new ApiError(502, 'upstream_error', `static edition: ${e instanceof Error ? e.message : String(e)}`)
    }
  }
  throw new ApiError(404, 'not_found', `The static edition has no route for ${method} ${path}`)
}
