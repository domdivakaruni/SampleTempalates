import type cytoscape from 'cytoscape'
import type { EdgeOut, GraphFragment, NodeOut } from '../api/types'
import { nodeColor, nodeImage } from './icons'
import { categoryOf } from './schema'

export interface NodeData {
  id: string
  label: string
  name: string
  display: string
  category: string
  severity?: string | null
  score?: number | null
  tags: string[]
  color: string
  image: string
  crown: boolean
  exposed: boolean
  node: NodeOut
}

export interface EdgeData {
  id: string
  source: string
  target: string
  type: string
  derived: boolean
  confidence: number
  edge: EdgeOut
}

const MAX_LABEL = 28

export function displayName(n: NodeOut): string {
  let name = n.name || n.id
  if (n.label === 'Alert' && typeof n.score === 'number') name = `${name}`
  if (name.length > MAX_LABEL) name = `${name.slice(0, MAX_LABEL - 1)}…`
  return name
}

export function toNodeElement(n: NodeOut): cytoscape.ElementDefinition {
  const category = n.category && n.category !== 'unknown' ? n.category : categoryOf(n.label)
  const color = nodeColor(n.label, category, n.severity)
  const crown = n.tags?.includes('crown_jewel') ?? false
  const exposed = n.tags?.includes('internet_exposed') ?? false
  const data: NodeData = {
    id: n.id, label: n.label, name: n.name, display: displayName(n), category, severity: n.severity ?? null, score: n.score ?? null,
    tags: n.tags ?? [], color, image: nodeImage(n.label, color, { crown, exposed }), crown, exposed, node: n,
  }
  const classes = [`cat-${category}`, `label-${n.label}`]
  if (crown) classes.push('crown')
  return { group: 'nodes', data: data as unknown as Record<string, unknown>, classes: classes.join(' ') }
}

export function toEdgeElement(e: EdgeOut): cytoscape.ElementDefinition {
  const data: EdgeData = { id: e.id, source: e.src, target: e.dst, type: e.type, derived: e.derived ?? false, confidence: e.confidence ?? 1, edge: e }
  return { group: 'edges', data: data as unknown as Record<string, unknown> }
}

export function fragmentElements(f: GraphFragment): cytoscape.ElementDefinition[] {
  const ids = new Set(f.nodes.map((n) => n.id))
  return [...f.nodes.map(toNodeElement), ...f.edges.filter((e) => ids.has(e.src) && ids.has(e.dst)).map(toEdgeElement)]
}

export function fragmentHighlightIds(f: GraphFragment): string[] {
  const ids = new Set<string>()
  for (const n of f.nodes) if (n.highlight) ids.add(n.id)
  for (const e of f.edges) if (e.highlight) ids.add(e.id)
  if (!ids.size && f.paths[0]) {
    f.paths[0].node_ids.forEach((i) => ids.add(i))
    f.paths[0].edge_ids.forEach((i) => ids.add(i))
  }
  return [...ids]
}

export function mergeFragment(a: GraphFragment, b: GraphFragment): GraphFragment {
  const nodes = new Map(a.nodes.map((n) => [n.id, n]))
  for (const n of b.nodes) nodes.set(n.id, nodes.has(n.id) ? { ...nodes.get(n.id)!, ...n, highlight: n.highlight || nodes.get(n.id)!.highlight } : n)
  const edges = new Map(a.edges.map((e) => [e.id, e]))
  for (const e of b.edges) if (!edges.has(e.id)) edges.set(e.id, e)
  return {
    nodes: [...nodes.values()], edges: [...edges.values()], paths: [...a.paths, ...b.paths], focus: [...new Set([...a.focus, ...b.focus])],
    layout_hint: b.layout_hint ?? a.layout_hint, truncated: a.truncated || b.truncated, total_nodes: nodes.size, meta: { ...a.meta, ...b.meta },
  }
}
