/* eslint-disable */
/**
 * Tiny in-memory property graph used by the mock adapter. Mirrors the shapes the backend returns so that the UI
 * cannot tell the difference. Ids follow docs/03-graph-schema.md; edge ids are `src|TYPE|dst`.
 */
import type { EdgeOut, GraphFragment, LayoutHint, NodeOut, PathOut, Props, SearchHit } from '../types'
import { categoryOf, DERIVED_EDGE_TYPES, labelForId } from '../../graph/schema'

export interface MockNode extends NodeOut {
  props: Props
}

export interface MockEdge extends EdgeOut {
  props: Props
}

export const NOW = '2026-09-11T14:00:00Z'

export class MockGraph {
  nodes = new Map<string, MockNode>()
  edges = new Map<string, MockEdge>()
  out = new Map<string, Set<string>>()
  inc = new Map<string, Set<string>>()

  node(id: string, name: string, props: Props = {}, extra: Partial<NodeOut> = {}): MockNode {
    const label = extra.label ?? labelForId(id) ?? 'Unknown'
    const tags = [...(extra.tags ?? [])]
    if (props.crown_jewel === true && !tags.includes('crown_jewel')) tags.push('crown_jewel')
    if ((props.exposure === 'internet' || props.public === true) && !tags.includes('internet_exposed')) tags.push('internet_exposed')
    const n: MockNode = {
      id,
      label,
      name,
      category: categoryOf(label),
      severity: extra.severity ?? null,
      score: extra.score ?? null,
      highlight: false,
      tags,
      props: { source: 'mock-sim', first_seen: '2026-08-01T00:00:00Z', last_seen: NOW, confidence: 1, ...props },
    }
    this.nodes.set(id, n)
    return n
  }

  edge(src: string, type: string, dst: string, props: Props = {}, confidence = 1): MockEdge {
    const id = `${src}|${type}|${dst}`
    const e: MockEdge = { id, type, src, dst, derived: DERIVED_EDGE_TYPES.has(type), confidence, highlight: false, props }
    this.edges.set(id, e)
    if (!this.out.has(src)) this.out.set(src, new Set())
    if (!this.inc.has(dst)) this.inc.set(dst, new Set())
    this.out.get(src)!.add(id)
    this.inc.get(dst)!.add(id)
    return e
  }

  has(id: string): boolean {
    return this.nodes.has(id)
  }

  get(id: string): MockNode | undefined {
    return this.nodes.get(id)
  }

  must(id: string): MockNode {
    const n = this.nodes.get(id)
    if (!n) throw new Error(`mock graph: missing node ${id}`)
    return n
  }

  edgesOf(id: string, direction: 'both' | 'in' | 'out' = 'both'): MockEdge[] {
    const ids: string[] = []
    if (direction !== 'in') ids.push(...(this.out.get(id) ?? []))
    if (direction !== 'out') ids.push(...(this.inc.get(id) ?? []))
    return ids.map((e) => this.edges.get(e)!)
  }

  edgeBetween(a: string, b: string): MockEdge | undefined {
    for (const e of this.edgesOf(a)) if ((e.src === a && e.dst === b) || (e.src === b && e.dst === a)) return e
    return undefined
  }

  byLabel(label: string): MockNode[] {
    return [...this.nodes.values()].filter((n) => n.label === label)
  }

  degree(id: string): { in: number; out: number } {
    return { in: this.inc.get(id)?.size ?? 0, out: this.out.get(id)?.size ?? 0 }
  }

  edgeTypeCounts(id: string): Record<string, number> {
    const counts: Record<string, number> = {}
    for (const e of this.edgesOf(id)) counts[e.type] = (counts[e.type] ?? 0) + 1
    return counts
  }

  /** Build a fragment from node ids, including every edge among them (or only the given edge ids). */
  fragment(nodeIds: Iterable<string>, opts: { edgeIds?: Iterable<string>; focus?: string[]; hint?: LayoutHint; paths?: PathOut[]; highlight?: Set<string>; max?: number } = {}): GraphFragment {
    const ids = [...new Set(nodeIds)].filter((id) => this.nodes.has(id))
    const max = opts.max ?? 150
    const truncated = ids.length > max
    const kept = new Set(ids.slice(0, max))
    const nodes = [...kept].map((id) => ({ ...this.nodes.get(id)!, highlight: opts.highlight?.has(id) ?? false }))
    let edges: EdgeOut[]
    if (opts.edgeIds) {
      edges = [...new Set(opts.edgeIds)].map((id) => this.edges.get(id)).filter((e): e is MockEdge => !!e && kept.has(e.src) && kept.has(e.dst))
    } else {
      const seen = new Set<string>()
      edges = []
      for (const id of kept) {
        for (const e of this.edgesOf(id)) {
          if (seen.has(e.id) || !kept.has(e.src) || !kept.has(e.dst)) continue
          seen.add(e.id)
          edges.push(e)
        }
      }
    }
    edges = edges.map((e) => ({ ...e, highlight: opts.highlight?.has(e.id) ?? false }))
    return {
      nodes,
      edges,
      paths: opts.paths ?? [],
      focus: opts.focus ?? [],
      layout_hint: opts.hint ?? 'neighborhood',
      truncated,
      total_nodes: ids.length,
      meta: {},
    }
  }

  neighborhood(id: string, depth = 1, opts: { edgeTypes?: string[]; direction?: 'both' | 'in' | 'out'; labels?: string[]; maxNodes?: number } = {}): GraphFragment {
    const maxNodes = opts.maxNodes ?? 150
    const seen = new Set<string>([id])
    const edgeIds = new Set<string>()
    let frontier = [id]
    for (let d = 0; d < depth && frontier.length; d++) {
      const next: string[] = []
      for (const cur of frontier) {
        for (const e of this.edgesOf(cur, opts.direction ?? 'both')) {
          if (opts.edgeTypes?.length && !opts.edgeTypes.includes(e.type)) continue
          const other = e.src === cur ? e.dst : e.src
          const n = this.nodes.get(other)
          if (!n) continue
          if (opts.labels?.length && !opts.labels.includes(n.label) && other !== id) continue
          edgeIds.add(e.id)
          if (!seen.has(other)) {
            if (seen.size >= maxNodes) continue
            seen.add(other)
            next.push(other)
          }
        }
      }
      frontier = next
    }
    const frag = this.fragment(seen, { edgeIds, focus: [id], hint: 'neighborhood' })
    frag.truncated = frag.truncated || seen.size >= maxNodes
    return frag
  }

  /** k shortest simple paths (undirected traversal, deterministic), returned as PathOut + fragment. */
  paths(src: string, dst: string, maxHops = 6, k = 3, edgeTypes?: string[]): GraphFragment {
    const found: PathOut[] = []
    if (!this.nodes.has(src) || !this.nodes.has(dst)) return this.fragment([], { hint: 'path' })
    type Item = { node: string; nodes: string[]; edges: string[] }
    const queue: Item[] = [{ node: src, nodes: [src], edges: [] }]
    let expansions = 0
    while (queue.length && found.length < k && expansions < 20000) {
      const cur = queue.shift()!
      expansions++
      if (cur.node === dst) {
        found.push({ node_ids: cur.nodes, edge_ids: cur.edges, hops: cur.edges.length, label: `${cur.edges.length} hops`, likelihood: null, stages: [] })
        continue
      }
      if (cur.edges.length >= maxHops) continue
      for (const e of this.edgesOf(cur.node)) {
        if (edgeTypes?.length && !edgeTypes.includes(e.type)) continue
        if (e.props.transitive === true) continue // derived shortcut edges hide the real hop count
        const other = e.src === cur.node ? e.dst : e.src
        if (cur.nodes.includes(other)) continue
        queue.push({ node: other, nodes: [...cur.nodes, other], edges: [...cur.edges, e.id] })
      }
    }
    const nodeIds = new Set<string>()
    const edgeIds = new Set<string>()
    for (const p of found) {
      p.node_ids.forEach((n) => nodeIds.add(n))
      p.edge_ids.forEach((e) => edgeIds.add(e))
    }
    const highlight = new Set<string>(found[0] ? [...found[0].node_ids, ...found[0].edge_ids] : [])
    return this.fragment(nodeIds, { edgeIds, focus: [src, dst], hint: 'path', paths: found, highlight })
  }

  /** Forward reachability following the given edge types (semantic direction), with hop counts and via paths. */
  reach(root: string, edgeTypes: Set<string>, depth: number, reverseTypes: Set<string> = new Set()): Map<string, { hops: number; via: string[]; edgeIds: string[] }> {
    const result = new Map<string, { hops: number; via: string[]; edgeIds: string[] }>()
    result.set(root, { hops: 0, via: [root], edgeIds: [] })
    let frontier = [root]
    for (let d = 1; d <= depth && frontier.length; d++) {
      const next: string[] = []
      for (const cur of frontier) {
        const info = result.get(cur)!
        for (const e of this.edgesOf(cur, 'out')) {
          if (!edgeTypes.has(e.type)) continue
          if (!result.has(e.dst)) {
            result.set(e.dst, { hops: d, via: [...info.via, e.dst], edgeIds: [...info.edgeIds, e.id] })
            next.push(e.dst)
          }
        }
        for (const e of this.edgesOf(cur, 'in')) {
          if (!reverseTypes.has(e.type)) continue
          if (!result.has(e.src)) {
            result.set(e.src, { hops: d, via: [...info.via, e.src], edgeIds: [...info.edgeIds, e.id] })
            next.push(e.src)
          }
        }
      }
      frontier = next
    }
    return result
  }

  search(q: string, labels?: string[], limit = 25): SearchHit[] {
    const needle = q.trim().toLowerCase()
    if (!needle) return []
    const hits: SearchHit[] = []
    for (const n of this.nodes.values()) {
      if (labels?.length && !labels.includes(n.label)) continue
      const hay = [n.name, n.id, String(n.props.hostname ?? ''), String(n.props.title ?? ''), String(n.props.value ?? ''), String(n.props.display_name ?? ''), String(n.props.cve_id ?? '')]
      let score = 0
      for (const h of hay) {
        const l = h.toLowerCase()
        if (!l) continue
        if (l === needle) score = Math.max(score, 1)
        else if (l.startsWith(needle)) score = Math.max(score, 0.8)
        else if (l.includes(needle)) score = Math.max(score, 0.5)
      }
      if (score > 0) hits.push({ id: n.id, label: n.label, name: n.name, category: n.category, snippet: snippetOf(n), score })
    }
    hits.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name))
    return hits.slice(0, limit)
  }
}

export function snippetOf(n: NodeOut): string {
  const p = n.props
  const parts: string[] = []
  for (const key of ['hostname', 'title', 'private_ip', 'account_id', 'environment', 'exposure', 'value', 'display_name', 'cve_id', 'exploitation_status', 'severity', 'vendor_severity', 'department']) {
    const v = p[key]
    if (v !== undefined && v !== null && v !== '' && String(v) !== n.name) parts.push(`${key}: ${String(v)}`)
    if (parts.length >= 3) break
  }
  return parts.join(' · ')
}

export function mergeFragments(a: GraphFragment, b: GraphFragment): GraphFragment {
  const nodes = new Map(a.nodes.map((n) => [n.id, n]))
  for (const n of b.nodes) if (!nodes.has(n.id)) nodes.set(n.id, n)
  const edges = new Map(a.edges.map((e) => [e.id, e]))
  for (const e of b.edges) if (!edges.has(e.id)) edges.set(e.id, e)
  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    paths: [...a.paths, ...b.paths],
    focus: [...new Set([...a.focus, ...b.focus])],
    layout_hint: a.layout_hint,
    truncated: a.truncated || b.truncated,
    total_nodes: nodes.size,
    meta: { ...a.meta, ...b.meta },
  }
}
