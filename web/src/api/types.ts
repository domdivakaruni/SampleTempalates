/**
 * TypeScript mirror of `throughline/models.py` plus the response envelopes in docs/05-api-contract.md.
 * Keep field names identical to the pydantic models; the backend is the source of truth.
 */

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
export type Band = 'noise' | 'low' | 'medium' | 'high' | 'critical'
export type LayoutHint = 'neighborhood' | 'path' | 'blast_radius' | 'storyline' | 'tree'
export type Category = 'cloud' | 'identity' | 'software' | 'business' | 'endpoint' | 'alerts' | 'threat_intel' | 'unknown'

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }
export type Props = Record<string, JsonValue | undefined>

export const SEVERITY_RANK: Record<Severity, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 }

export function bandForScore(score: number): Band {
  if (score >= 90) return 'critical'
  if (score >= 76) return 'high'
  if (score >= 51) return 'medium'
  if (score >= 26) return 'low'
  return 'noise'
}

// ----------------------------------------------------------------------------- graph fragments

export interface NodeOut {
  id: string
  label: string
  name: string
  category: string
  severity?: string | null
  score?: number | null
  highlight?: boolean
  tags: string[]
  props: Props
}

export interface EdgeOut {
  id: string // "src|TYPE|dst"
  type: string
  src: string
  dst: string
  derived?: boolean
  confidence?: number
  highlight?: boolean
  props: Props
}

export interface PathOut {
  node_ids: string[]
  edge_ids: string[]
  hops: number
  label?: string | null
  likelihood?: number | null
  stages: string[]
}

export interface GraphFragment {
  nodes: NodeOut[]
  edges: EdgeOut[]
  paths: PathOut[]
  focus: string[]
  layout_hint: LayoutHint
  truncated: boolean
  total_nodes?: number | null
  meta: Record<string, JsonValue | undefined>
}

export function emptyFragment(hint: LayoutHint = 'neighborhood'): GraphFragment {
  return { nodes: [], edges: [], paths: [], focus: [], layout_hint: hint, truncated: false, meta: {} }
}

// ----------------------------------------------------------------------------- risk

export interface RiskFactor {
  key: string // severity | exposure | privilege | data | threat_intel | correlation
  label: string
  value: number
  weight: number
  contribution: number
  reason: string
  evidence_ids: string[]
}

export interface RiskBreakdown {
  subject_id: string
  vendor_severity?: string | null
  vendor_severity_rank?: number | null
  contextual_score: number
  band: Band
  raw_score: number
  factors: RiskFactor[]
  rails: string[]
  reasons: string[]
  delta_vs_vendor: number
}

// ----------------------------------------------------------------------------- analytics results

export interface Insight {
  kind: string
  statement: string
  hops: number
  sources: string[]
  importance: number
  evidence_node_ids: string[]
  evidence_edge_ids: string[]
}

export interface ReachedNode {
  node: NodeOut
  hops: number
  reach_score: number
  via_path: string[]
  access_level?: string | null
}

export interface BlastRadiusResult {
  root_id: string
  depth: number
  reached_count: number
  crown_jewels: ReachedNode[]
  data_stores: ReachedNode[]
  secrets: ReachedNode[]
  identities: ReachedNode[]
  accounts_touched: string[]
  by_hop: Record<string, number>
  summary: string
  fragment: GraphFragment
}

export interface StageOut {
  order: number
  stage: string
  technique_ids: string[]
  node_ids: string[]
  edge_ids: string[]
  alert_ids: string[]
  time?: string | null
  summary: string
}

export interface AttackPathOut {
  id: string
  entry_id: string
  target_id: string
  through_id?: string | null
  likelihood: number
  hops: number
  stages: StageOut[]
  summary: string
  fragment: GraphFragment
}

export interface StorylineOut {
  id: string
  title: string
  summary: string
  actor_id?: string | null
  actor_name?: string | null
  campaign_id?: string | null
  campaign_name?: string | null
  contextual_score: number
  stage_count: number
  alert_ids: string[]
  crown_jewels_reached: string[]
  first_event?: string | null
  last_event?: string | null
  stages: StageOut[]
  fragment?: GraphFragment | null
}

export interface TIMatch {
  indicator_id: string
  ioc_type: string
  value: string
  confidence: number
  matched_node_id: string
  matched_label: string
  actor_id?: string | null
  campaign_id?: string | null
  malware_id?: string | null
  report_id?: string | null
}

export interface TIContext {
  matches: TIMatch[]
  actors: NodeOut[]
  campaigns: NodeOut[]
  malware: NodeOut[]
  exploited_vulnerabilities: NodeOut[]
  reports: NodeOut[]
  ttp_overlap: Record<string, number>
  sector_relevance?: number | null
  summary: string
}

export interface AlertSummary {
  id: string
  title: string
  source_system: string
  alert_type: string
  vendor_severity: string
  vendor_severity_rank: number
  contextual_score: number
  contextual_band: Band
  detected_at?: string | null
  status: string
  entity_id?: string | null
  entity_name?: string | null
  entity_label?: string | null
  hostname?: string | null
  user?: string | null
  techniques: string[]
  storyline_id?: string | null
  graph_reasons: string[]
  reaches_crown_jewel: boolean
  on_attack_path: boolean
  ioc_match_count: number
  ti_actor_ids: string[]
  vendor_rank_position?: number | null
  contextual_rank_position?: number | null
}

export type FlatView = Record<string, JsonValue | undefined>

export interface AlertContext {
  alert: AlertSummary
  flat_view: FlatView
  risk: RiskBreakdown
  insights: Insight[]
  blast_radius?: BlastRadiusResult | null
  attack_paths: AttackPathOut[]
  storyline?: StorylineOut | null
  threat_intel?: TIContext | null
  related_alerts: AlertSummary[]
  evidence: GraphFragment
}

export interface BreakItem {
  node_id: string
  name: string
  label: string
  impact: string
  owner_team_id?: string | null
}

export interface ContainmentSimulation {
  target_ids: string[]
  actions: string[]
  paths_cut: number
  storylines_contained: string[]
  crown_jewels_protected: string[]
  breaks: BreakItem[]
  residual_risks: string[]
  recommendations: string[]
  fragment: GraphFragment
}

export type ContainmentAction =
  | 'isolate_endpoint'
  | 'rotate_role_credentials'
  | 'tighten_trust_policy'
  | 'block_ip'
  | 'disable_user'
  | 'revoke_sessions'

export const CONTAINMENT_ACTIONS: { id: ContainmentAction; label: string; hint: string }[] = [
  { id: 'isolate_endpoint', label: 'Isolate endpoint', hint: 'Network-contain the host with the EDR sensor' },
  { id: 'rotate_role_credentials', label: 'Rotate role credentials', hint: 'Invalidate issued temporary keys for the role' },
  { id: 'tighten_trust_policy', label: 'Tighten trust policy', hint: 'Remove the cross-account AssumeRole trust' },
  { id: 'block_ip', label: 'Block IP', hint: 'Deny the attacker egress IP at the edge and in IAM conditions' },
  { id: 'disable_user', label: 'Disable user', hint: 'Suspend the identity in the IdP' },
  { id: 'revoke_sessions', label: 'Revoke sessions', hint: 'Terminate active sessions and tokens' },
]

export interface SearchHit {
  id: string
  label: string
  name: string
  category: string
  snippet?: string | null
  score: number
}

export interface StatsOut {
  node_counts: Record<string, number>
  edge_counts: Record<string, number>
  total_nodes: number
  total_edges: number
  backend: string
  capabilities: Record<string, JsonValue | undefined>
  build: Record<string, JsonValue | undefined>
}

// ----------------------------------------------------------------------------- analyst agent

export interface Finding {
  statement: string
  severity?: Severity | null
  evidence_ids: string[]
}

export interface ToolCallRecord {
  name: string
  arguments: Record<string, JsonValue | undefined>
  summary: string
  duration_ms: number
  error?: string | null
}

export type AgentMode = 'llm' | 'offline'

export interface AnalystAnswer {
  narrative_md: string
  findings: Finding[]
  evidence: GraphFragment
  confidence: number
  followups: string[]
  tool_calls: ToolCallRecord[]
  mode: AgentMode
  intent?: string | null
  model?: string | null
}

export interface ChatContext {
  alert_id?: string
  storyline_id?: string
  node_id?: string
  selected_node_ids?: string[]
}

export interface ChatMessageIn {
  content: string
  context?: ChatContext | null
  mode?: 'auto' | 'llm' | 'offline' | null
}

export type ChatEventType =
  | 'session'
  | 'text_delta'
  | 'thinking'
  | 'tool_call'
  | 'tool_result'
  | 'evidence'
  | 'answer'
  | 'error'
  | 'done'

export interface SessionEventData { session_id: string; mode: AgentMode; model?: string | null }
export interface TextDeltaEventData { text: string }
export interface ToolCallEventData { id: string; name: string; arguments: Record<string, JsonValue | undefined> }
export interface ToolResultEventData { id: string; name: string; summary: string; duration_ms: number; error?: string | null }
export interface ErrorEventData { code: string; message: string }
export interface DoneEventData { mode: AgentMode; model?: string | null; tool_calls: number; elapsed_ms: number }

export type ChatEvent =
  | { type: 'session'; data: SessionEventData }
  | { type: 'text_delta'; data: TextDeltaEventData }
  | { type: 'thinking'; data: TextDeltaEventData }
  | { type: 'tool_call'; data: ToolCallEventData }
  | { type: 'tool_result'; data: ToolResultEventData }
  | { type: 'evidence'; data: GraphFragment }
  | { type: 'answer'; data: AnalystAnswer }
  | { type: 'error'; data: ErrorEventData }
  | { type: 'done'; data: DoneEventData }

export interface ChatTurn {
  role: 'user' | 'assistant'
  content: string
  answer?: AnalystAnswer | null
  created_at?: string | null
}

export interface ChatSession {
  id: string
  created_at: string
  turns: ChatTurn[]
  context: Record<string, JsonValue | undefined>
}

// ----------------------------------------------------------------------------- API envelopes (docs/05)

export interface ApiErrorBody {
  error: { code: string; message: string; details?: Record<string, JsonValue | undefined> }
}

export interface HealthOut {
  status: string
  backend: string
  total_nodes: number
  total_edges: number
  agent_mode: AgentMode | string
  model?: string | null
  build?: Record<string, JsonValue | undefined>
}

export interface SchemaColumn { name: string; type: string }
export interface SchemaLabel { name: string; category: string; id_prefix: string; columns: SchemaColumn[] }
export interface SchemaEdgeType { name: string; pairs: [string, string][]; columns: SchemaColumn[]; derived: boolean }
export interface SchemaOut {
  categories: Record<string, string>
  labels: SchemaLabel[]
  edge_types: SchemaEdgeType[]
  example_queries?: { title: string; query: string }[]
}

export interface DashboardKpis {
  open_alerts: number
  critical_contextual: number
  storylines: number
  crown_jewels: number
  crown_jewels_at_risk: number
  internet_exposed_exploited: number
  endpoints: number
  endpoint_coverage_pct: number
  ioc_matches: number
}

export interface DashboardCoverage {
  vms_total: number
  vms_with_sensor: number
  vms_without_sensor_prod: number
  endpoints_total: number
  endpoints_resolved_to_vm: number
}

export interface TIPressureItem {
  actor_id: string
  actor_name: string
  sector_relevance: number
  campaigns: number
  ioc_matches: number
  exploited_cves_present: number
  alerts: number
}

export interface RerankExample {
  alert_id: string
  title: string
  vendor_severity: string
  contextual_score: number
  vendor_rank_position: number
  contextual_rank_position: number
}

export interface DashboardOut {
  kpis: DashboardKpis
  leaderboard_contextual: AlertSummary[]
  leaderboard_vendor: AlertSummary[]
  storylines: StorylineOut[]
  alerts_by_band: Record<Band, number>
  alerts_by_source: Record<string, number>
  coverage: DashboardCoverage
  ti_pressure: TIPressureItem[]
  rerank_examples: RerankExample[]
}

export type AlertSort = 'contextual' | 'vendor' | 'time'

export interface AlertListParams {
  sort?: AlertSort
  order?: 'asc' | 'desc'
  band?: string
  severity?: string
  source?: string
  storyline?: string
  reaches_crown_jewel?: boolean
  on_attack_path?: boolean
  q?: string
  limit?: number
  offset?: number
}

export interface AlertListOut { items: AlertSummary[]; total: number; limit: number; offset: number }
export interface AlertOut { alert: AlertSummary; flat_view: FlatView }
export interface StorylineListOut { items: StorylineOut[] }
export interface SearchOut { hits: SearchHit[] }

export interface NodeDetailOut {
  node: NodeOut
  degree: { in: number; out: number }
  edge_type_counts: Record<string, number>
  alerts: AlertSummary[]
  threat_intel?: TIContext | null
}

export interface NeighborhoodParams {
  id: string
  depth?: number
  edge_types?: string[]
  direction?: 'both' | 'in' | 'out'
  labels?: string[]
  max_nodes?: number
}

export interface PathsParams { src: string; dst: string; max_hops?: number; k?: number; edge_types?: string[] }
export interface BlastRadiusParams { id: string; depth?: number; max_nodes?: number }
export interface AttackPathsParams { through?: string; target?: string; entry?: string; k?: number }
export interface AttackPathsOut { paths: AttackPathOut[]; fragment: GraphFragment }

export type CypherCell = JsonValue | { id: string; label: string; name: string } | { src: string; type: string; dst: string }
export interface CypherIn { query: string; params?: Record<string, JsonValue>; row_limit?: number }
export interface CypherOut {
  columns: string[]
  rows: CypherCell[][]
  elapsed_ms: number
  truncated: boolean
  fragment?: GraphFragment | null
}

export interface ActorListItem {
  actor: NodeOut
  campaigns: NodeOut[]
  sector_relevance: number
  active: boolean
  ioc_matches: number
  matched_alerts: number
  exploited_cves_present: number
  affected_assets: number
}
export interface ActorListOut { items: ActorListItem[] }

export interface ActorDetailOut {
  actor: NodeOut
  campaigns: NodeOut[]
  malware: NodeOut[]
  techniques: NodeOut[]
  indicators: NodeOut[]
  reports: NodeOut[]
  context: TIContext
  affected: GraphFragment
}

export interface ReportListOut { items: NodeOut[] }
export interface ReportDetailOut {
  report: NodeOut
  actors: NodeOut[]
  campaigns: NodeOut[]
  malware: NodeOut[]
  cves: NodeOut[]
  indicators: NodeOut[]
  techniques: NodeOut[]
  impact: { matched_alerts: AlertSummary[]; exposed_assets: NodeOut[]; summary: string }
}

export interface ExposureItem {
  vm: NodeOut
  cve: NodeOut
  exploitation_status: string
  actors: NodeOut[]
  campaigns: NodeOut[]
  sector_relevance: number
  contextual_score: number
  crown_jewels_reachable: NodeOut[]
  has_edr_sensor: boolean
  alert_ids: string[]
}
export interface ExposureOut { items: ExposureItem[] }

export interface CredentialJoinItem {
  credential: NodeOut
  stolen_by_alert: AlertSummary
  endpoint: NodeOut
  principal: NodeOut
  used_in_events: NodeOut[]
  derived_credentials: NodeOut[]
  first_use?: string | null
  source_ips: string[]
}
export interface CredentialJoinsOut { items: CredentialJoinItem[]; fragment: GraphFragment }
export interface AlertsReachingJewelsOut { items: AlertSummary[]; jewels: NodeOut[]; fragment: GraphFragment }
export interface MediumAlertsDataPathOut { items: AlertSummary[]; fragment: GraphFragment }
export interface ContainmentIn { target_ids: string[]; actions: ContainmentAction[] }
export interface SuggestionsOut { questions: string[] }
