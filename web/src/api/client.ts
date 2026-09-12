/**
 * Typed fetch wrapper for the Throughline API (docs/05-api-contract.md).
 *
 * Transport selection: the real backend at `/api/v1` is the default. The mock adapter (src/api/mock) is used when
 * `VITE_MOCK=1` is set at build time, when the URL carries `?mock=1`, or automatically in dev when `/api/v1/health`
 * is unreachable. The snapshot adapter (src/api/snapshot, the static edition) is used when `VITE_STATIC=1` is set at
 * build time or the URL carries `?snapshot=1`; it answers every request from precomputed JSON files. Both adapters are
 * loaded lazily so production bundles do not pay for them.
 */
import type {
  ActorDetailOut, ActorListOut, AlertContext, AlertListOut, AlertListParams, AlertOut, AlertsReachingJewelsOut,
  AttackPathsOut, AttackPathsParams, BlastRadiusParams, BlastRadiusResult, ChatContext, ChatEvent, ChatMessageIn,
  ChatSession, ContainmentIn, ContainmentSimulation, CredentialJoinsOut, CypherIn, CypherOut, DashboardOut,
  ExposureOut, GraphFragment, HealthOut, Insight, JsonValue, MediumAlertsDataPathOut, NeighborhoodParams,
  NodeDetailOut, NodeOut, PathsParams, ReportDetailOut, ReportListOut, RiskBreakdown, SchemaOut, SearchOut,
  StatsOut, StorylineListOut, StorylineOut, SuggestionsOut, TIContext,
} from './types'
import { readSseStream } from './sse'

export const API_BASE = '/api/v1'

export type QueryValue = string | number | boolean | string[] | undefined | null
export type Query = Record<string, QueryValue>

export class ApiError extends Error {
  status: number
  code: string
  details?: Record<string, JsonValue | undefined>
  constructor(status: number, code: string, message: string, details?: Record<string, JsonValue | undefined>) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError
}

// ----------------------------------------------------------------------------- transport mode

export type ApiMode = 'real' | 'mock' | 'snapshot' | 'unknown'

/** True in the static snapshot edition (`VITE_STATIC=1 npm run build`): hash routing, relative assets, snapshot transport. */
export const IS_STATIC_BUILD = import.meta.env.VITE_STATIC === '1'

/** Read a `?flag=` parameter from the query string, or from inside the hash under hash routing (`#/path?flag=1`). */
function locationFlag(name: string): string | null {
  const fromSearch = new URLSearchParams(window.location.search).get(name)
  if (fromSearch !== null) return fromSearch
  const hashQuery = window.location.hash.split('?')[1]
  return hashQuery ? new URLSearchParams(hashQuery).get(name) : null
}

/** `?flag=1` turns a mode on for the session, `?flag=0` turns it off again; the choice persists in sessionStorage. */
function sessionFlag(name: string, storageKey: string): boolean {
  const value = locationFlag(name)
  if (value === '1') sessionStorage.setItem(storageKey, '1')
  if (value === '0') sessionStorage.removeItem(storageKey)
  return sessionStorage.getItem(storageKey) === '1'
}

function initialMode(): ApiMode {
  if (IS_STATIC_BUILD) return 'snapshot'
  if (import.meta.env.VITE_MOCK === '1') return 'mock'
  if (typeof window !== 'undefined') {
    try {
      if (sessionFlag('snapshot', 'throughline.snapshot')) return 'snapshot'
      if (sessionFlag('mock', 'throughline.mock')) return 'mock'
    } catch {
      /* storage unavailable */
    }
  }
  return 'unknown'
}

let mode: ApiMode = initialMode()
let probe: Promise<ApiMode> | null = null
const listeners = new Set<(m: ApiMode) => void>()

export function getApiMode(): ApiMode {
  return mode
}

export function onApiModeChange(fn: (m: ApiMode) => void): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

function setMode(m: ApiMode) {
  mode = m
  listeners.forEach((fn) => fn(m))
}

export function resolveApiMode(): Promise<ApiMode> {
  if (mode !== 'unknown') return Promise.resolve(mode)
  if (!probe) {
    probe = (async () => {
      try {
        const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(2500) })
        if (!res.ok) throw new Error(`health ${res.status}`)
        const health = (await res.json()) as Partial<HealthOut>
        if (typeof health.status !== 'string') throw new Error('unexpected health payload')
        setMode('real')
      } catch {
        // Only auto-fallback in dev; a production build is expected to be served by FastAPI.
        setMode(import.meta.env.DEV ? 'mock' : 'real')
      }
      return mode
    })()
  }
  return probe
}

// ----------------------------------------------------------------------------- low-level request

function buildQuery(query?: Query): string {
  if (!query) return ''
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue
    if (Array.isArray(v)) {
      if (v.length) sp.set(k, v.join(','))
    } else sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

async function parseError(res: Response): Promise<ApiError> {
  let code = 'http_error'
  let message = `${res.status} ${res.statusText}`
  let details: Record<string, JsonValue | undefined> | undefined
  try {
    const body = (await res.json()) as { error?: { code?: string; message?: string; details?: Record<string, JsonValue | undefined> }; detail?: unknown }
    if (body.error) {
      code = body.error.code ?? code
      message = body.error.message ?? message
      details = body.error.details
    } else if (typeof body.detail === 'string') {
      message = body.detail
    }
  } catch {
    /* non-JSON error body */
  }
  if (res.status === 501 && code === 'http_error') code = 'not_supported'
  if (res.status === 404 && code === 'http_error') code = 'not_found'
  return new ApiError(res.status, code, message, details)
}

async function mockModule() {
  return import('./mock')
}

async function snapshotModule() {
  return import('./snapshot')
}

export async function request<T>(method: 'GET' | 'POST', path: string, opts: { query?: Query; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const current = await resolveApiMode()
  if (current === 'snapshot') {
    const m = await snapshotModule()
    return m.snapshotRequest<T>(method, path, opts.query ?? {}, opts.body)
  }
  if (current === 'mock' && !IS_STATIC_BUILD) {
    const m = await mockModule()
    return m.mockRequest<T>(method, path, opts.query ?? {}, opts.body)
  }
  const res = await fetch(`${API_BASE}${path}${buildQuery(opts.query)}`, {
    method,
    headers: opts.body !== undefined ? { 'content-type': 'application/json', accept: 'application/json' } : { accept: 'application/json' },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  })
  if (!res.ok) throw await parseError(res)
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

const get = <T>(path: string, query?: Query, signal?: AbortSignal) => request<T>('GET', path, { query, signal })
const post = <T>(path: string, body?: unknown, query?: Query, signal?: AbortSignal) => request<T>('POST', path, { body, query, signal })

/** Stream a chat turn; resolves when the stream ends. Events are delivered in order through `onEvent`. */
export async function streamChat(sessionId: string, body: ChatMessageIn, onEvent: (evt: ChatEvent) => void, signal?: AbortSignal): Promise<void> {
  const current = await resolveApiMode()
  if (current === 'snapshot') {
    const m = await snapshotModule()
    return m.snapshotStream(sessionId, body, onEvent, signal)
  }
  if (current === 'mock' && !IS_STATIC_BUILD) {
    const m = await mockModule()
    return m.mockStream(sessionId, body, onEvent, signal)
  }
  const res = await fetch(`${API_BASE}/chat/sessions/${encodeURIComponent(sessionId)}/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
    body: JSON.stringify(body),
    signal,
  })
  if (!res.ok) throw await parseError(res)
  if (!res.body) throw new ApiError(502, 'upstream_error', 'empty response body')
  await readSseStream(
    res.body,
    (raw) => {
      let data: unknown = {}
      try {
        data = raw.data ? JSON.parse(raw.data) : {}
      } catch {
        data = { text: raw.data }
      }
      onEvent({ type: raw.event, data } as ChatEvent)
    },
    signal,
  )
}

// ----------------------------------------------------------------------------- typed endpoints

export const api = {
  health: () => get<HealthOut>('/health'),
  stats: () => get<StatsOut>('/stats'),
  schema: () => get<SchemaOut>('/schema'),
  dashboard: () => get<DashboardOut>('/dashboard'),

  alerts: (params: AlertListParams = {}) => get<AlertListOut>('/alerts', params as Query),
  alert: (id: string) => get<AlertOut>(`/alerts/${encodeURIComponent(id)}`),
  alertContext: (id: string) => get<AlertContext>(`/alerts/${encodeURIComponent(id)}/context`),
  alertRisk: (id: string) => get<RiskBreakdown>(`/alerts/${encodeURIComponent(id)}/risk`),
  alertInsights: (id: string) => get<{ insights: Insight[] }>(`/alerts/${encodeURIComponent(id)}/insights`),
  storylines: () => get<StorylineListOut>('/storylines'),
  storyline: (id: string) => get<StorylineOut>(`/storylines/${encodeURIComponent(id)}`),

  search: (q: string, labels?: string[], limit = 25) => get<SearchOut>('/search', { q, labels, limit }),
  node: (id: string) => get<NodeDetailOut>(`/nodes/${encodeURIComponent(id)}`),
  nodesBatch: (ids: string[]) => post<{ nodes: NodeOut[] }>('/nodes/batch', { ids }),
  neighborhood: (p: NeighborhoodParams) => get<GraphFragment>('/graph/neighborhood', p as unknown as Query),
  paths: (p: PathsParams) => get<GraphFragment>('/graph/paths', p as unknown as Query),
  blastRadius: (p: BlastRadiusParams) => get<BlastRadiusResult>('/graph/blast-radius', p as unknown as Query),
  attackPaths: (p: AttackPathsParams) => get<AttackPathsOut>('/graph/attack-paths', p as unknown as Query),
  cypher: (body: CypherIn) => post<CypherOut>('/graph/cypher', body),

  tiActors: () => get<ActorListOut>('/threat-intel/actors'),
  tiActor: (id: string) => get<ActorDetailOut>(`/threat-intel/actors/${encodeURIComponent(id)}`),
  tiCampaign: (id: string) => get<ActorDetailOut>(`/threat-intel/campaigns/${encodeURIComponent(id)}`),
  tiReports: () => get<ReportListOut>('/threat-intel/reports'),
  tiReport: (id: string) => get<ReportDetailOut>(`/threat-intel/reports/${encodeURIComponent(id)}`),
  tiLookup: (value: string) => get<TIContext>('/threat-intel/lookup', { value }),
  tiExposure: (sectorOnly: boolean) => get<ExposureOut>('/threat-intel/exposure', { sector_only: sectorOnly }),

  credentialJoins: () => get<CredentialJoinsOut>('/investigate/credential-joins'),
  alertsReachingCrownJewels: (p: { jewel_id?: string; classification?: string } = {}) => get<AlertsReachingJewelsOut>('/investigate/alerts-reaching-crown-jewels', p),
  identityFootprint: (id: string) => get<BlastRadiusResult>('/investigate/identity-footprint', { id }),
  mediumAlertsWithDataPath: (p: { severity?: string; source?: string } = {}) => get<MediumAlertsDataPathOut>('/investigate/medium-alerts-with-data-path', p),
  containment: (body: ContainmentIn) => post<ContainmentSimulation>('/investigate/containment', body),

  chatCreateSession: (context?: ChatContext) => post<ChatSession>('/chat/sessions', { context: context ?? {} }),
  chatSession: (id: string) => get<ChatSession>(`/chat/sessions/${encodeURIComponent(id)}`),
  chatSuggestions: (p: { alert_id?: string; node_id?: string; storyline_id?: string } = {}) => get<SuggestionsOut>('/chat/suggestions', p),
  streamChat,
}

export type Api = typeof api
