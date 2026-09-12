/**
 * TypeScript mirror of the files `scripts/export_snapshot.py` writes into `web/snapshot-out/`
 * (docs/10-static-snapshot.md section 1). Payload shapes are the API shapes from `../types`; this module only
 * describes the containers the exporter wraps them in. Keep it in sync with the exporter.
 */
import type {
  ActorDetailOut, ActorListOut, AlertContext, AlertSummary, AlertsReachingJewelsOut, AnalystAnswer, AttackPathsOut,
  BlastRadiusResult, ContainmentSimulation, CredentialJoinsOut, DashboardOut, ExposureOut, FlatView, HealthOut, Insight,
  MediumAlertsDataPathOut, NodeDetailOut, NodeOut, ReportDetailOut, ReportListOut, RiskBreakdown, SchemaOut, StatsOut,
  StorylineOut, TIContext,
} from '../types'

/** `manifest.json` */
export interface SnapshotManifest {
  version: number
  generated_at: string
  seed?: number | string | null
  node_count: number
  edge_count: number
  alert_count: number
  shards: { alert_details: string[]; edges: string[] }
  notes?: string
  /** Hex chars of sha1(alert id) naming the alert_details shards (the exporter's --alert-shard-chars, 1 or 2). */
  alert_shard_prefix_len?: number
}

/** `meta.json` */
export interface SnapshotMeta {
  health: HealthOut
  stats: StatsOut
  schema: SchemaOut
  dashboard: DashboardOut
}

/** `alerts.json`: every alert in contextual order. */
export interface SnapshotAlerts {
  items: AlertSummary[]
}

/** One entry of an `alert_details/<NN>.json` shard. `context` is present only for the alerts precomputed in full. */
export interface AlertDetailEntry {
  alert: AlertSummary
  flat_view: FlatView
  risk: RiskBreakdown
  insights: Insight[]
  context?: AlertContext | null
}
export type AlertDetailsShard = Record<string, AlertDetailEntry>

/** `storylines.json` */
export interface SnapshotStorylines {
  items: StorylineOut[]
  details: Record<string, StorylineOut>
}

/** `ti.json` */
export interface SnapshotTi {
  actors: ActorListOut
  actor_details: Record<string, ActorDetailOut>
  campaign_details: Record<string, ActorDetailOut>
  reports: ReportListOut
  report_details: Record<string, ReportDetailOut>
  exposure: { sector_only: ExposureOut; all: ExposureOut }
  /** Keyed by the lower-cased lookup value (indicator value, CVE id, technique id, actor/campaign/report id or name). */
  lookups: Record<string, TIContext>
}

/** `investigate.json` */
export interface ContainmentEntry {
  targets: string[]
  actions: string[]
  result: ContainmentSimulation
}
export interface SnapshotInvestigate {
  credential_joins: CredentialJoinsOut
  /** `""` is the default (no filter); other keys are crown-jewel ids. */
  alerts_reaching_crown_jewels: Record<string, AlertsReachingJewelsOut>
  /** Keys are `<severity>|<source>` (`medium|falcon`, `medium|`, ...). */
  medium_alerts_with_data_path: Record<string, MediumAlertsDataPathOut>
  identity_footprint: Record<string, BlastRadiusResult>
  containment: ContainmentEntry[]
}

/** `graph/nodes.json` */
export interface SnapshotNodes {
  nodes: NodeOut[]
}

/** One edge of a `graph/edges-<NN>.json` shard: `[src, type, dst, derived (0|1), confidence]`. */
export type CompactEdge = [src: string, type: string, dst: string, derived: 0 | 1 | boolean, confidence: number | null]
export interface SnapshotEdgeShard {
  edges: CompactEdge[]
}

/** `graph/blast_radius.json`: keyed by root node id. */
export type SnapshotBlastRadius = Record<string, BlastRadiusResult>

/** `graph/attack_paths.json`: keyed by `through` id or `internet-><target id>`. */
export type SnapshotAttackPaths = Record<string, AttackPathsOut>

/** `node_cards.json`: `GET /nodes/{id}` payloads keyed by node id. */
export type SnapshotNodeCards = Record<string, NodeDetailOut>

/** One row of `search.json`: `[id, label, name, category, snippet, extra_tokens]` (extra tokens space-joined, lower-cased). */
export type SearchEntry = [id: string, label: string, name: string, category: string, snippet: string | null, extraTokens: string | null]
export interface SnapshotSearch {
  entries: SearchEntry[]
}

/** `chat.json`. Context keys: `""` (global), `alert:<id>`, `node:<id>`, `storyline:<id>`. */
export interface ChatAnswerEntry {
  question: string
  normalized: string
  context_key: string
  answer: AnalystAnswer
}
export interface SnapshotChat {
  suggestions: Record<string, string[]>
  answers: ChatAnswerEntry[]
}
