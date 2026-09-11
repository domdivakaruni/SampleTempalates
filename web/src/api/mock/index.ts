/* eslint-disable */
/**
 * Mock adapter: routes `/api/v1` requests to in-memory handlers over the fixture graph.
 * Enabled with VITE_MOCK=1, `?mock=1`, or automatically in dev when the backend health check fails.
 */
import { ApiError, type Query } from '../client'
import type { AlertSort, ChatContext, CypherCell, CypherOut, GraphFragment, JsonValue } from '../types'
import { emptyFragment } from '../types'
import { alertContext, alertsReachingCrownJewels, attackPathsFor, blastRadius, containment, credentialJoins, insightsFor, mediumAlertsWithDataPath, nodeAlerts, riskBreakdown, storylineWithFragment } from './analytics'
import { createSession, getSession, suggestions } from './chat'
import { dashboard, health, schema, stats } from './dashboard'
import { alertSpec, alertSummary, dataset } from './dataset'
import { mergeFragments } from './graph'
import { actorDetail, actorList, exposureTable, reportDetail, reportList, tiContextForNode, tiLookup } from './ti'

export { mockStream } from './chat'

type Handler = (params: Record<string, string>, query: Query, body: unknown) => unknown

const str = (v: Query[string], d = ''): string => (v === undefined || v === null ? d : Array.isArray(v) ? v.join(',') : String(v))
const num = (v: Query[string], d: number, max?: number): number => {
  const n = Number(str(v, String(d)))
  const val = Number.isFinite(n) ? n : d
  return max !== undefined ? Math.min(val, max) : val
}
const bool = (v: Query[string]): boolean | undefined => (v === undefined || v === null || v === '' ? undefined : String(v) === 'true' || v === true)
const list = (v: Query[string]): string[] | undefined => {
  if (v === undefined || v === null || v === '') return undefined
  return (Array.isArray(v) ? v : String(v).split(',')).map((s) => s.trim()).filter(Boolean)
}

const notFound = (what: string) => new ApiError(404, 'not_found', `${what} not found`)

function alertsList(query: Query) {
  const { alertsByContextual, alertsByVendor } = dataset()
  const sort = (str(query.sort, 'contextual') as AlertSort) || 'contextual'
  const order = str(query.order, 'desc')
  let items = sort === 'vendor' ? [...alertsByVendor] : sort === 'time' ? [...alertsByContextual].sort((a, b) => (b.detected_at ?? '').localeCompare(a.detected_at ?? '')) : [...alertsByContextual]
  if (order === 'asc') items.reverse()
  const band = str(query.band), severity = str(query.severity), source = str(query.source), storyline = str(query.storyline), q = str(query.q).toLowerCase()
  const rcj = bool(query.reaches_crown_jewel), oap = bool(query.on_attack_path)
  items = items.filter((a) =>
    (!band || a.contextual_band === band) && (!severity || a.vendor_severity === severity) && (!source || a.source_system === source) && (!storyline || a.storyline_id === storyline) &&
    (rcj === undefined || a.reaches_crown_jewel === rcj) && (oap === undefined || a.on_attack_path === oap) &&
    (!q || a.title.toLowerCase().includes(q) || (a.hostname ?? '').toLowerCase().includes(q) || (a.entity_name ?? '').toLowerCase().includes(q) || a.id.toLowerCase().includes(q) || (a.user ?? '').toLowerCase().includes(q)),
  )
  const limit = num(query.limit, 50, 500)
  const offset = num(query.offset, 0)
  return { items: items.slice(offset, offset + limit), total: items.length, limit, offset }
}

function cypher(body: unknown): CypherOut {
  const { graph: g } = dataset()
  const b = (body ?? {}) as { query?: string; row_limit?: number }
  const query = (b.query ?? '').trim()
  if (!query) throw new ApiError(400, 'invalid_argument', 'query is required')
  if (/\b(create|merge|delete|set|drop|remove|call|load)\b/i.test(query)) throw new ApiError(400, 'query_rejected', 'Only read-only MATCH ... RETURN queries are allowed (write clause detected).')
  const m = query.replace(/\s+/g, ' ').match(/^MATCH \(\s*(\w+)\s*:\s*(\w+)\s*\)(?: WHERE (.+?))? RETURN (.+?)(?: ORDER BY .+?)?(?: LIMIT (\d+))?\s*;?$/i)
  if (!m) throw new ApiError(501, 'not_supported', 'The mock adapter understands single-label queries of the form MATCH (n:Label) [WHERE n.prop op value [AND ...]] RETURN n | n.prop, ... [LIMIT k]. The LadybugDB backend runs full Cypher.')
  const [, alias, label, where, ret, lim] = m
  const started = performance.now()
  let nodes = g.byLabel(label)
  if (!nodes.length && !dataset().graph.byLabel(label).length) throw new ApiError(400, 'query_rejected', `Unknown label ${label}`)
  if (where) {
    for (const clause of where.split(/ AND /i)) {
      const cm = clause.trim().match(/^(\w+)\.(\w+)\s*(=|<>|>=|<=|>|<|IN)\s*(.+)$/i)
      if (!cm || cm[1] !== alias) throw new ApiError(501, 'not_supported', `Unsupported WHERE clause: ${clause}`)
      const [, , prop, op, rawVal] = cm
      const parseVal = (s: string): JsonValue => {
        const t = s.trim()
        if (/^true$/i.test(t)) return true
        if (/^false$/i.test(t)) return false
        if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t)
        return t.replace(/^['"]|['"]$/g, '')
      }
      const val = op.toUpperCase() === 'IN' ? rawVal.trim().replace(/^\[|\]$/g, '').split(',').map(parseVal) : parseVal(rawVal)
      nodes = nodes.filter((n) => {
        const v = prop === 'id' ? n.id : prop === 'name' ? n.name : (n.props[prop] as JsonValue | undefined)
        if (v === undefined || v === null) return false
        switch (op.toUpperCase()) {
          case '=': return String(v) === String(val)
          case '<>': return String(v) !== String(val)
          case '>': return Number(v) > Number(val)
          case '<': return Number(v) < Number(val)
          case '>=': return Number(v) >= Number(val)
          case '<=': return Number(v) <= Number(val)
          case 'IN': return (val as JsonValue[]).map(String).includes(String(v))
          default: return false
        }
      })
    }
  }
  const rowLimit = Math.min(lim ? Number(lim) : b.row_limit ?? 200, 500)
  const truncated = nodes.length > rowLimit
  nodes = nodes.slice(0, rowLimit)
  const cols = ret.split(',').map((c) => c.trim())
  const columns = cols.map((c) => c.replace(/\s+AS\s+.+$/i, ''))
  const rows: CypherCell[][] = nodes.map((n) => cols.map((c) => {
    const base = c.replace(/\s+AS\s+.+$/i, '').trim()
    if (base === alias) return { id: n.id, label: n.label, name: n.name }
    const pm = base.match(/^(\w+)\.(\w+)$/)
    if (pm && pm[1] === alias) return pm[2] === 'id' ? n.id : pm[2] === 'name' ? n.name : ((n.props[pm[2]] ?? null) as JsonValue)
    if (/^count\(/i.test(base)) return nodes.length
    return null
  }))
  const includesNode = cols.some((c) => c.replace(/\s+AS\s+.+$/i, '').trim() === alias)
  const fragment = includesNode ? g.fragment(nodes.map((n) => n.id), { hint: 'neighborhood' }) : null
  return { columns, rows, elapsed_ms: Math.max(1, Math.round(performance.now() - started)), truncated, fragment }
}

const routes: [RegExp, string, Handler][] = [
  [/^\/health$/, 'GET', () => health()],
  [/^\/stats$/, 'GET', () => stats()],
  [/^\/schema$/, 'GET', () => schema()],
  [/^\/dashboard$/, 'GET', () => dashboard()],
  [/^\/alerts$/, 'GET', (_p, q) => alertsList(q)],
  [/^\/alerts\/([^/]+)$/, 'GET', (p) => {
    const alert = alertSummary(p[1]); const spec = alertSpec(p[1])
    if (!alert || !spec) throw notFound(`alert ${p[1]}`)
    return { alert, flat_view: spec.flat }
  }],
  [/^\/alerts\/([^/]+)\/context$/, 'GET', (p) => alertContext(p[1]) ?? (() => { throw notFound(`alert ${p[1]}`) })()],
  [/^\/alerts\/([^/]+)\/risk$/, 'GET', (p) => riskBreakdown(p[1]) ?? (() => { throw notFound(`alert ${p[1]}`) })()],
  [/^\/alerts\/([^/]+)\/insights$/, 'GET', (p) => ({ insights: insightsFor(p[1]) })],
  [/^\/storylines$/, 'GET', () => ({ items: dataset().storylines.map((s) => ({ ...s, fragment: null })) })],
  [/^\/storylines\/([^/]+)$/, 'GET', (p) => storylineWithFragment(p[1]) ?? (() => { throw notFound(`storyline ${p[1]}`) })()],
  [/^\/search$/, 'GET', (_p, q) => ({ hits: dataset().graph.search(str(q.q), list(q.labels), num(q.limit, 25, 100)) })],
  [/^\/nodes\/batch$/, 'POST', (_p, _q, body) => {
    const ids = ((body as { ids?: string[] })?.ids ?? []).slice(0, 200)
    return { nodes: ids.map((id) => dataset().graph.get(id)).filter(Boolean) }
  }],
  [/^\/nodes\/([^/]+)$/, 'GET', (p) => {
    const g = dataset().graph
    const node = g.get(p[1])
    if (!node) throw notFound(`node ${p[1]}`)
    const ti = tiContextForNode(p[1])
    return { node, degree: g.degree(p[1]), edge_type_counts: g.edgeTypeCounts(p[1]), alerts: nodeAlerts(p[1]).slice(0, 25), threat_intel: ti.matches.length || ti.actors.length || ti.exploited_vulnerabilities.length ? ti : null }
  }],
  [/^\/graph\/neighborhood$/, 'GET', (_p, q) => {
    const id = str(q.id)
    if (!dataset().graph.has(id)) throw notFound(`node ${id}`)
    const depth = num(q.depth, 1, 3)
    return dataset().graph.neighborhood(id, depth, { edgeTypes: list(q.edge_types), direction: (str(q.direction, 'both') as 'both' | 'in' | 'out'), labels: list(q.labels), maxNodes: num(q.max_nodes, 150, 300) })
  }],
  [/^\/graph\/paths$/, 'GET', (_p, q) => {
    const src = str(q.src), dst = str(q.dst)
    if (!dataset().graph.has(src) || !dataset().graph.has(dst)) throw notFound(`node ${dataset().graph.has(src) ? dst : src}`)
    return dataset().graph.paths(src, dst, num(q.max_hops, 6, 8), num(q.k, 3, 5), list(q.edge_types))
  }],
  [/^\/graph\/blast-radius$/, 'GET', (_p, q) => blastRadius(str(q.id), num(q.depth, 4, 6), num(q.max_nodes, 150, 300)) ?? (() => { throw notFound(`node ${str(q.id)}`) })()],
  [/^\/graph\/attack-paths$/, 'GET', (_p, q) => {
    const paths = attackPathsFor({ through: str(q.through) || undefined, target: str(q.target) || undefined, entry: str(q.entry) || undefined, k: num(q.k, 5, 5) })
    const fragment = paths.reduce<GraphFragment>((acc, p) => mergeFragments(acc, p.fragment), emptyFragment('path'))
    fragment.paths = paths.map((p) => p.fragment.paths[0])
    return { paths, fragment }
  }],
  [/^\/graph\/cypher$/, 'POST', (_p, _q, body) => cypher(body)],
  [/^\/threat-intel\/actors$/, 'GET', () => ({ items: actorList() })],
  [/^\/threat-intel\/actors\/([^/]+)$/, 'GET', (p) => actorDetail(p[1]) ?? (() => { throw notFound(`actor ${p[1]}`) })()],
  [/^\/threat-intel\/campaigns\/([^/]+)$/, 'GET', (p) => actorDetail(p[1]) ?? (() => { throw notFound(`campaign ${p[1]}`) })()],
  [/^\/threat-intel\/reports$/, 'GET', () => ({ items: reportList() })],
  [/^\/threat-intel\/reports\/([^/]+)$/, 'GET', (p) => reportDetail(p[1]) ?? (() => { throw notFound(`report ${p[1]}`) })()],
  [/^\/threat-intel\/lookup$/, 'GET', (_p, q) => tiLookup(str(q.value))],
  [/^\/threat-intel\/exposure$/, 'GET', (_p, q) => ({ items: exposureTable(bool(q.sector_only) ?? true) })],
  [/^\/investigate\/credential-joins$/, 'GET', () => credentialJoins()],
  [/^\/investigate\/alerts-reaching-crown-jewels$/, 'GET', (_p, q) => alertsReachingCrownJewels(str(q.jewel_id) || undefined, str(q.classification) || undefined)],
  [/^\/investigate\/identity-footprint$/, 'GET', (_p, q) => blastRadius(str(q.id), 4, 200) ?? (() => { throw notFound(`identity ${str(q.id)}`) })()],
  [/^\/investigate\/medium-alerts-with-data-path$/, 'GET', (_p, q) => mediumAlertsWithDataPath(str(q.severity, 'medium'), str(q.source, 'falcon'))],
  [/^\/investigate\/containment$/, 'POST', (_p, _q, body) => {
    const b = (body ?? {}) as { target_ids?: string[]; actions?: string[] }
    if (!b.target_ids?.length) throw new ApiError(400, 'invalid_argument', 'target_ids is required')
    return containment(b.target_ids, b.actions ?? [])
  }],
  [/^\/chat\/sessions$/, 'POST', (_p, _q, body) => createSession((body as { context?: ChatContext })?.context)],
  [/^\/chat\/sessions\/([^/]+)$/, 'GET', (p) => getSession(p[1]) ?? (() => { throw notFound(`session ${p[1]}`) })()],
  [/^\/chat\/suggestions$/, 'GET', (_p, q) => ({ questions: suggestions({ alert_id: str(q.alert_id) || undefined, node_id: str(q.node_id) || undefined, storyline_id: str(q.storyline_id) || undefined }) })],
]

export async function mockRequest<T>(method: string, path: string, query: Query, body: unknown): Promise<T> {
  await new Promise((r) => setTimeout(r, 40 + Math.random() * 120))
  for (const [re, m, handler] of routes) {
    const match = path.match(re)
    if (!match || m !== method) continue
    const params: Record<string, string> = {}
    match.forEach((v, i) => (params[String(i)] = decodeURIComponent(v ?? '')))
    return handler(params, query, body) as T
  }
  throw new ApiError(404, 'not_found', `No mock route for ${method} ${path}`)
}
