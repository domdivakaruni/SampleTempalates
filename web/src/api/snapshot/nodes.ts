/** GET /nodes/{id} and POST /nodes/batch: precomputed node cards first, then the graph index. */
import { ApiError } from '../client'
import type { NodeDetailOut, NodeOut } from '../types'
import { alertsOnEntities } from './alerts'
import { loadGraph } from './graph'
import { loadAlerts, loadNodeCardsOptional } from './loader'

export async function nodeDetail(id: string): Promise<NodeDetailOut> {
  const cards = await loadNodeCardsOptional()
  const card = cards[id]
  if (card) return card
  const g = await loadGraph()
  const node = g.get(id)
  if (!node) throw new ApiError(404, 'not_found', `node ${id} not found`)
  // Alerts on the node itself, on the asset it resolves to (SAME_AS) and alerts that INVOLVE it.
  const entities = new Set<string>([id])
  const alertIds = new Set<string>()
  for (const e of g.edgesOf(id)) {
    if (e.type === 'SAME_AS') entities.add(e.src === id ? e.dst : e.src)
    if (e.type === 'INVOLVES' && e.dst === id && e.src.startsWith('alert:')) alertIds.add(e.src)
  }
  const alerts = alertsOnEntities((await loadAlerts()).items, entities, alertIds).slice(0, 25)
  return { node, degree: g.degree(id), edge_type_counts: g.edgeTypeCounts(id), alerts, threat_intel: null }
}

export async function nodesBatch(ids: string[]): Promise<{ nodes: NodeOut[] }> {
  const wanted = [...new Set(ids.filter((id) => typeof id === 'string' && id))].slice(0, 200)
  if (!wanted.length) return { nodes: [] }
  const cards = await loadNodeCardsOptional()
  const found = new Map<string, NodeOut>()
  const missing: string[] = []
  for (const id of wanted) {
    const card = cards[id]
    if (card) found.set(id, card.node)
    else missing.push(id)
  }
  if (missing.length) {
    const g = await loadGraph()
    for (const id of missing) {
      const n = g.get(id)
      if (n) found.set(id, n)
    }
  }
  return { nodes: wanted.map((id) => found.get(id)).filter((n): n is NodeOut => !!n) }
}
