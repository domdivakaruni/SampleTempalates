/* eslint-disable */
/** Mock dashboard payload, stats, schema and health. */
import type { Band, DashboardOut, HealthOut, SchemaOut, StatsOut } from '../types'
import { CATEGORY_NAMES, DERIVED_EDGE_TYPES, EDGE_TYPES, EXAMPLE_QUERIES, LABELS } from '../../graph/schema'
import { dataset } from './dataset'
import { actorList } from './ti'

export const MOCK_BUILD = { version: '0.1.0-mock', seed: 20260911, generated_at: '2026-09-11T14:00:00Z', backend: 'mock' }

export function health(): HealthOut {
  const { graph } = dataset()
  return { status: 'ok', backend: 'mock', total_nodes: graph.nodes.size, total_edges: graph.edges.size, agent_mode: 'offline', model: null, build: MOCK_BUILD }
}

export function stats(): StatsOut {
  const { graph } = dataset()
  const node_counts: Record<string, number> = {}
  for (const n of graph.nodes.values()) node_counts[n.label] = (node_counts[n.label] ?? 0) + 1
  const edge_counts: Record<string, number> = {}
  for (const e of graph.edges.values()) edge_counts[e.type] = (edge_counts[e.type] ?? 0) + 1
  return { node_counts, edge_counts, total_nodes: graph.nodes.size, total_edges: graph.edges.size, backend: 'mock', capabilities: { cypher: 'limited', streaming: true, llm: false }, build: MOCK_BUILD }
}

export function schema(): SchemaOut {
  return {
    categories: CATEGORY_NAMES,
    labels: LABELS.map((l) => ({ name: l.name, category: l.category, id_prefix: l.prefix, columns: [{ name: 'id', type: 'STRING' }, { name: 'name', type: 'STRING' }] })),
    edge_types: EDGE_TYPES.map((t) => ({ name: t, pairs: [], columns: [], derived: DERIVED_EDGE_TYPES.has(t) })),
    example_queries: EXAMPLE_QUERIES,
  }
}

export function dashboard(): DashboardOut {
  const { graph: g, alertsByContextual, alertsByVendor, storylines } = dataset()
  const bands: Record<Band, number> = { critical: 0, high: 0, medium: 0, low: 0, noise: 0 }
  const sources: Record<string, number> = { falcon: 0, cspm: 0, waf: 0, ids: 0, 'cloud-anomaly': 0, okta: 0 }
  for (const a of alertsByContextual) {
    bands[a.contextual_band]++
    sources[a.source_system] = (sources[a.source_system] ?? 0) + 1
  }
  const jewels = [...g.nodes.values()].filter((n) => n.tags.includes('crown_jewel'))
  const jewelsAtRisk = new Set(storylines.flatMap((s) => s.crown_jewels_reached))
  const exposedExploited = g.byLabel('VirtualMachine').filter((vm) => g.edgesOf(vm.id, 'in').some((e) => e.type === 'EXPOSES') && g.edgesOf(vm.id, 'out').some((e) => e.type === 'VULNERABLE_TO' && ['active', 'mass_exploitation'].includes(String(g.get(e.dst)?.props.exploitation_status))))
  const iocMatches = [...g.edges.values()].filter((e) => e.type === 'MATCHES_IOC').length
  const vms = g.byLabel('VirtualMachine')
  const withSensor = vms.filter((v) => v.props.has_edr_sensor === true)
  const endpoints = g.byLabel('Endpoint')
  const resolved = endpoints.filter((e) => g.edgesOf(e.id, 'out').some((x) => x.type === 'SAME_AS'))
  const actors = actorList()
  const ti_pressure = actors.filter((a) => a.ioc_matches > 0 || a.matched_alerts > 0 || a.exploited_cves_present > 0).slice(0, 6).map((a) => ({
    actor_id: a.actor.id, actor_name: a.actor.name, sector_relevance: a.sector_relevance, campaigns: a.campaigns.length, ioc_matches: a.ioc_matches, exploited_cves_present: a.exploited_cves_present, alerts: a.matched_alerts,
  }))
  const exampleIds = ['alert:falcon:ldt-a009', 'alert:cloud-anomaly:ca-a017', 'alert:falcon:ldt-b002', 'alert:cspm:iss-n002', 'alert:falcon:ldt-n001']
  const rerank_examples = exampleIds.map((id) => alertsByContextual.find((a) => a.id === id)!).filter(Boolean).map((a) => ({
    alert_id: a.id, title: a.title, vendor_severity: a.vendor_severity, contextual_score: a.contextual_score, vendor_rank_position: a.vendor_rank_position ?? 0, contextual_rank_position: a.contextual_rank_position ?? 0,
  }))
  return {
    kpis: {
      open_alerts: alertsByContextual.filter((a) => a.status !== 'closed').length,
      critical_contextual: bands.critical,
      storylines: storylines.length,
      crown_jewels: jewels.length,
      crown_jewels_at_risk: jewelsAtRisk.size,
      internet_exposed_exploited: exposedExploited.length,
      endpoints: endpoints.length,
      endpoint_coverage_pct: Math.round((withSensor.length / Math.max(1, vms.length)) * 1000) / 10,
      ioc_matches: iocMatches,
    },
    leaderboard_contextual: alertsByContextual.slice(0, 10),
    leaderboard_vendor: alertsByVendor.slice(0, 10),
    storylines: storylines.map((s) => ({ ...s, fragment: null })),
    alerts_by_band: bands,
    alerts_by_source: sources,
    coverage: {
      vms_total: vms.length,
      vms_with_sensor: withSensor.length,
      vms_without_sensor_prod: vms.filter((v) => v.props.has_edr_sensor !== true && v.props.environment === 'prod').length,
      endpoints_total: endpoints.length,
      endpoints_resolved_to_vm: resolved.length,
    },
    ti_pressure,
    rerank_examples,
  }
}
