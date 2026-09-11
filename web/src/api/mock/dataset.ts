/* eslint-disable */
/** Builds the mock dataset once: graph + alert specs + summaries with rank positions + storylines. */
import type { AlertSummary, StorylineOut } from '../types'
import { buildCampaigns } from './fixtures/campaigns'
import { buildEstate } from './fixtures/estate'
import { buildNoise } from './fixtures/noise'
import { buildTiCatalog } from './fixtures/ti'
import { toSummary, type AlertSpec } from './fixtures/alerts'
import { MockGraph } from './graph'

export interface Dataset {
  graph: MockGraph
  specs: Map<string, AlertSpec>
  summaries: Map<string, AlertSummary>
  alertsByContextual: AlertSummary[]
  alertsByVendor: AlertSummary[]
  storylines: StorylineOut[]
}

let cached: Dataset | null = null

export function dataset(): Dataset {
  if (cached) return cached
  const graph = new MockGraph()
  buildEstate(graph)
  const { alerts: campaignAlerts, storylines } = buildCampaigns(graph)
  buildTiCatalog(graph)
  const noise = buildNoise(graph)
  const all = [...campaignAlerts, ...noise]
  const specs = new Map(all.map((a) => [a.id, a]))
  const summaries = new Map(all.map((a) => [a.id, toSummary(graph, a)]))
  const list = [...summaries.values()]
  const byContextual = [...list].sort((a, b) => b.contextual_score - a.contextual_score || (b.detected_at ?? '').localeCompare(a.detected_at ?? ''))
  const byVendor = [...list].sort((a, b) => b.vendor_severity_rank - a.vendor_severity_rank || (b.detected_at ?? '').localeCompare(a.detected_at ?? ''))
  byContextual.forEach((a, i) => (a.contextual_rank_position = i + 1))
  byVendor.forEach((a, i) => (a.vendor_rank_position = i + 1))
  cached = { graph, specs, summaries, alertsByContextual: byContextual, alertsByVendor: byVendor, storylines }
  return cached
}

export function alertSummary(id: string): AlertSummary | undefined {
  return dataset().summaries.get(id)
}

export function alertSpec(id: string): AlertSpec | undefined {
  return dataset().specs.get(id)
}

export function storylineById(id: string): StorylineOut | undefined {
  return dataset().storylines.find((s) => s.id === id)
}
