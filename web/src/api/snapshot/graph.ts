/**
 * In-memory graph index over `graph/nodes.json` + the compact `graph/edges-<NN>.json` shards, for the endpoints the
 * exporter cannot precompute for arbitrary inputs: k-hop neighborhoods, shortest paths, approximate blast radius,
 * node degrees. Loaded lazily (a few MB) only when the explorer, an expansion or a non-precomputed root needs it.
 */
import type { BlastRadiusResult, EdgeOut, GraphFragment, LayoutHint, NodeOut, PathOut, ReachedNode } from '../types'
import { loadEdgeShards, loadNodes } from './loader'
import type { CompactEdge } from './schema'

export type Direction = 'both' | 'in' | 'out'

/** Attack-graph edge types followed (in their semantic direction) by the blast-radius approximation. */
export const ATTACK_EDGE_TYPES = new Set(['HAS_ROLE', 'CAN_ASSUME', 'CAN_ACCESS', 'UNLOCKS', 'SAME_AS', 'CREDENTIAL_FOR', 'DERIVED_FROM', 'LATERAL_MOVEMENT_TO', 'MAPS_TO'])
/** From an Alert root the first hop also follows the alert's anchor edges so the approximation starts on the asset. */
const ALERT_ANCHOR_TYPES = new Set(['ON_ENDPOINT', 'ON_RESOURCE'])
const IDENTITY_LABELS = new Set(['IamRole', 'IamUser', 'HumanUser', 'ServiceAccount', 'Credential'])
const REACH_CAP = 500
const PATH_EXPANSION_CAP = 60_000

interface ReachInfo {
  hops: number
  via: string[]
  edgeIds: string[]
}

export interface FragmentOptions {
  edgeIds?: Iterable<string>
  focus?: string[]
  hint?: LayoutHint
  paths?: PathOut[]
  highlight?: Set<string>
  max?: number
}

export interface NeighborhoodOptions {
  edgeTypes?: string[]
  direction?: Direction
  labels?: string[]
  maxNodes?: number
}

export class SnapshotGraph {
  readonly nodes = new Map<string, NodeOut>()
  readonly edges: EdgeOut[] = []
  private readonly edgeIndex = new Map<string, number>()
  private readonly out = new Map<string, number[]>()
  private readonly inc = new Map<string, number[]>()

  constructor(nodes: NodeOut[], shards: CompactEdge[][]) {
    for (const n of nodes) this.nodes.set(n.id, { ...n, tags: n.tags ?? [], props: n.props ?? {}, highlight: false })
    for (const shard of shards) for (const e of shard) this.addEdge(e)
  }

  private addEdge([src, type, dst, derived, confidence]: CompactEdge): void {
    const id = `${src}|${type}|${dst}`
    if (this.edgeIndex.has(id)) return
    const idx = this.edges.length
    this.edges.push({ id, type, src, dst, derived: derived === 1 || derived === true, confidence: typeof confidence === 'number' ? confidence : 1, highlight: false, props: {} })
    this.edgeIndex.set(id, idx)
    push(this.out, src, idx)
    push(this.inc, dst, idx)
  }

  has(id: string): boolean {
    return this.nodes.has(id)
  }

  get(id: string): NodeOut | undefined {
    return this.nodes.get(id)
  }

  edge(id: string): EdgeOut | undefined {
    const idx = this.edgeIndex.get(id)
    return idx === undefined ? undefined : this.edges[idx]
  }

  edgesOf(id: string, direction: Direction = 'both'): EdgeOut[] {
    const result: EdgeOut[] = []
    if (direction !== 'in') for (const i of this.out.get(id) ?? []) result.push(this.edges[i])
    if (direction !== 'out') for (const i of this.inc.get(id) ?? []) result.push(this.edges[i])
    return result
  }

  degree(id: string): { in: number; out: number } {
    return { in: this.inc.get(id)?.length ?? 0, out: this.out.get(id)?.length ?? 0 }
  }

  edgeTypeCounts(id: string): Record<string, number> {
    const counts: Record<string, number> = {}
    for (const e of this.edgesOf(id)) counts[e.type] = (counts[e.type] ?? 0) + 1
    return counts
  }

  /** Fragment over the given node ids with every edge among them (or only the given edge ids). */
  fragment(nodeIds: Iterable<string>, opts: FragmentOptions = {}): GraphFragment {
    const ids = [...new Set(nodeIds)].filter((id) => this.nodes.has(id))
    const max = opts.max ?? 150
    const truncated = ids.length > max
    const kept = new Set(ids.slice(0, max))
    const nodes = [...kept].map((id) => ({ ...this.nodes.get(id)!, highlight: opts.highlight?.has(id) ?? false }))
    let edges: EdgeOut[] = []
    if (opts.edgeIds) {
      for (const id of new Set(opts.edgeIds)) {
        const e = this.edge(id)
        if (e && kept.has(e.src) && kept.has(e.dst)) edges.push(e)
      }
    } else {
      const seen = new Set<string>()
      for (const id of kept) {
        for (const e of this.edgesOf(id)) {
          if (seen.has(e.id) || !kept.has(e.src) || !kept.has(e.dst)) continue
          seen.add(e.id)
          edges.push(e)
        }
      }
    }
    edges = edges.map((e) => ({ ...e, highlight: opts.highlight?.has(e.id) ?? false }))
    return { nodes, edges, paths: opts.paths ?? [], focus: opts.focus ?? [], layout_hint: opts.hint ?? 'neighborhood', truncated, total_nodes: ids.length, meta: {} }
  }

  /** k-hop BFS honouring depth, edge types, labels, direction and the node cap (GET /graph/neighborhood). */
  neighborhood(id: string, depth = 1, opts: NeighborhoodOptions = {}): GraphFragment {
    const maxNodes = opts.maxNodes ?? 150
    const edgeTypes = opts.edgeTypes?.length ? new Set(opts.edgeTypes) : null
    const labels = opts.labels?.length ? new Set(opts.labels) : null
    const seen = new Set<string>([id])
    const edgeIds = new Set<string>()
    let frontier = [id]
    let capped = false
    for (let d = 0; d < depth && frontier.length; d++) {
      const next: string[] = []
      for (const cur of frontier) {
        for (const e of this.edgesOf(cur, opts.direction ?? 'both')) {
          if (edgeTypes && !edgeTypes.has(e.type)) continue
          const other = e.src === cur ? e.dst : e.src
          const n = this.nodes.get(other)
          if (!n) continue
          if (labels && other !== id && !labels.has(n.label)) continue
          if (!seen.has(other)) {
            if (seen.size >= maxNodes) {
              capped = true
              continue
            }
            seen.add(other)
            next.push(other)
          }
          edgeIds.add(e.id)
        }
      }
      frontier = next
    }
    const frag = this.fragment(seen, { edgeIds, focus: [id], hint: 'neighborhood', max: Math.max(maxNodes, seen.size) })
    frag.truncated = frag.truncated || capped
    return frag
  }

  /**
   * Up to k shortest simple paths between src and dst (undirected traversal). A BFS from dst gives the distance of every
   * node to the target; a depth-first walk from src then only follows edges that can still reach dst within the hop
   * budget, enumerating paths in increasing length (GET /graph/paths).
   */
  paths(src: string, dst: string, maxHops = 6, k = 3, edgeTypes?: string[]): GraphFragment {
    if (!this.nodes.has(src) || !this.nodes.has(dst)) return this.fragment([], { hint: 'path', focus: [src, dst] })
    const types = edgeTypes?.length ? new Set(edgeTypes) : null
    const distToDst = this.distances(dst, maxHops, types)
    const found: PathOut[] = []
    const shortest = distToDst.get(src)
    if (shortest !== undefined) {
      let expansions = 0
      const visit = (node: string, nodes: string[], edges: string[], remaining: number): void => {
        if (found.length >= k || expansions > PATH_EXPANSION_CAP) return
        expansions++
        if (node === dst) {
          if (remaining === 0) found.push({ node_ids: nodes, edge_ids: edges, hops: edges.length, label: `${edges.length} hops`, likelihood: null, stages: [] })
          return
        }
        if (remaining === 0) return
        for (const e of this.edgesOf(node)) {
          if (types && !types.has(e.type)) continue
          const other = e.src === node ? e.dst : e.src
          if (nodes.includes(other)) continue
          const need = distToDst.get(other)
          if (need === undefined || need > remaining - 1) continue
          visit(other, [...nodes, other], [...edges, e.id], remaining - 1)
          if (found.length >= k) return
        }
      }
      for (let length = shortest; length <= maxHops && found.length < k && expansions <= PATH_EXPANSION_CAP; length++) visit(src, [src], [], length)
    }
    const nodeIds = new Set<string>([src, dst])
    const edgeIds = new Set<string>()
    for (const p of found) {
      p.node_ids.forEach((n) => nodeIds.add(n))
      p.edge_ids.forEach((e) => edgeIds.add(e))
    }
    const highlight = new Set<string>(found[0] ? [...found[0].node_ids, ...found[0].edge_ids] : [])
    const frag = this.fragment(nodeIds, { edgeIds, focus: [src, dst], hint: 'path', paths: found, highlight })
    if (!found.length) frag.meta = { note: `static edition: no path within ${maxHops} hops (client-side BFS over the snapshot graph)` }
    return frag
  }

  /** Undirected BFS distances from `root`, limited to `maxHops`. */
  private distances(root: string, maxHops: number, types: Set<string> | null): Map<string, number> {
    const dist = new Map<string, number>([[root, 0]])
    let frontier = [root]
    for (let d = 1; d <= maxHops && frontier.length; d++) {
      const next: string[] = []
      for (const cur of frontier) {
        for (const e of this.edgesOf(cur)) {
          if (types && !types.has(e.type)) continue
          const other = e.src === cur ? e.dst : e.src
          if (dist.has(other) || !this.nodes.has(other)) continue
          dist.set(other, d)
          next.push(other)
        }
      }
      frontier = next
    }
    return dist
  }

  /**
   * Approximate blast radius: forward BFS over the attack-graph edge types (GET /graph/blast-radius for roots the
   * exporter did not precompute). The summary is prefixed so the UI never presents it as the engine's result.
   */
  approxBlastRadius(rootId: string, depth = 4, maxNodes = 150): BlastRadiusResult | undefined {
    const root = this.nodes.get(rootId)
    if (!root) return undefined
    const reach = new Map<string, ReachInfo>([[rootId, { hops: 0, via: [rootId], edgeIds: [] }]])
    let frontier = [rootId]
    let capped = false
    for (let d = 1; d <= depth && frontier.length && !capped; d++) {
      const next: string[] = []
      for (const cur of frontier) {
        const info = reach.get(cur)!
        const anchorHop = d === 1 && root.label === 'Alert'
        for (const e of this.edgesOf(cur, 'out')) {
          if (!ATTACK_EDGE_TYPES.has(e.type) && !(anchorHop && ALERT_ANCHOR_TYPES.has(e.type))) continue
          if (reach.has(e.dst) || !this.nodes.has(e.dst)) continue
          if (reach.size > REACH_CAP) {
            capped = true
            break
          }
          reach.set(e.dst, { hops: d, via: [...info.via, e.dst], edgeIds: [...info.edgeIds, e.id] })
          next.push(e.dst)
        }
        if (capped) break
      }
      frontier = next
    }
    reach.delete(rootId)
    const crown: ReachedNode[] = []
    const data: ReachedNode[] = []
    const secrets: ReachedNode[] = []
    const identities: ReachedNode[] = []
    const accounts = new Set<string>()
    const byHop: Record<string, number> = {}
    const edgeIds = new Set<string>()
    for (const [id, info] of reach) {
      const n = this.nodes.get(id)!
      byHop[String(info.hops)] = (byHop[String(info.hops)] ?? 0) + 1
      const account = n.props.account_id
      if (typeof account === 'string' && account) accounts.add(account)
      info.edgeIds.forEach((e) => edgeIds.add(e))
      const r: ReachedNode = { node: n, hops: info.hops, reach_score: Math.max(0.1, Math.round((1 - info.hops * 0.12) * 100) / 100), via_path: info.via, access_level: null }
      if (n.tags.includes('crown_jewel')) crown.push(r)
      else if (n.label === 'StorageBucket' || n.label === 'Database') data.push(r)
      if (n.label === 'Secret') secrets.push(r)
      if (IDENTITY_LABELS.has(n.label)) identities.push(r)
    }
    const order = (a: ReachedNode, b: ReachedNode) => a.hops - b.hops || a.node.name.localeCompare(b.node.name)
    crown.sort(order)
    data.sort(order)
    secrets.sort(order)
    identities.sort(order)
    const highlight = new Set<string>([rootId, ...crown.map((c) => c.node.id)])
    const fragment = this.fragment([rootId, ...reach.keys()], { edgeIds, focus: [rootId], hint: 'blast_radius', max: maxNodes, highlight })
    fragment.truncated = fragment.truncated || capped
    fragment.meta = { note: 'static edition: approximate BFS over attack-graph edge types (this root was not precomputed)' }
    const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`
    const summary = `Approximate (static edition): ${root.name} reaches ${reach.size}${capped ? '+' : ''} nodes within ${depth} hops: ${plural(crown.length, 'crown jewel', 'crown jewels')}${crown.length ? ` (${crown.map((c) => c.node.name).join(', ')})` : ''}, ${plural(secrets.length, 'secret', 'secrets')}, ${plural(identities.length, 'identity', 'identities')} across ${plural(accounts.size, 'account', 'accounts')}.`
    return { root_id: rootId, depth, reached_count: reach.size, crown_jewels: crown, data_stores: data, secrets, identities, accounts_touched: [...accounts], by_hop: byHop, summary, fragment }
  }
}

function push(map: Map<string, number[]>, key: string, value: number): void {
  const list = map.get(key)
  if (list) list.push(value)
  else map.set(key, [value])
}

let graphPromise: Promise<SnapshotGraph> | null = null
let loaded: SnapshotGraph | null = null

/** The graph index, built once from `graph/nodes.json` and the edge shards. */
export function loadGraph(): Promise<SnapshotGraph> {
  if (!graphPromise) {
    graphPromise = Promise.all([loadNodes(), loadEdgeShards()]).then(([nodes, shards]) => {
      loaded = new SnapshotGraph(nodes.nodes, shards.map((s) => s.edges))
      return loaded
    })
    graphPromise.catch(() => (graphPromise = null))
  }
  return graphPromise
}

/** The graph index if it is already in memory (never triggers a load). */
export function peekGraph(): SnapshotGraph | null {
  return loaded
}
