/**
 * The exporter may blank `props` on GraphFragment nodes inside analytics payloads to fit the size budget (its manifest
 * says so in `trim_steps`), keeping the typed props only in `node_cards.json` and `graph/nodes.json`. Screens read a few
 * props straight from fragments (e.g. `role_type` for containment defaults), so fragments are re-hydrated from the
 * node cards (small, always loaded here) and from the graph index when it is already in memory (never loaded for this).
 */
import type { GraphFragment, NodeOut } from '../types'
import { peekGraph } from './graph'
import { loadNodeCardsOptional } from './loader'

const MAX_DEPTH = 6

function isFragment(v: unknown): v is GraphFragment {
  if (!v || typeof v !== 'object') return false
  const f = v as Partial<GraphFragment>
  return Array.isArray(f.nodes) && Array.isArray(f.edges) && typeof f.layout_hint === 'string'
}

function hasProps(n: NodeOut): boolean {
  return !!n.props && Object.keys(n.props).length > 0
}

/** Recursively re-hydrate every fragment inside `payload` in place; returns the same object for chaining. */
export async function hydratePayload<T>(payload: T): Promise<T> {
  const cards = await loadNodeCardsOptional()
  const graph = peekGraph()
  const lookup = (id: string): NodeOut | undefined => cards[id]?.node ?? graph?.get(id)
  const visit = (v: unknown, depth: number): void => {
    if (depth > MAX_DEPTH || !v || typeof v !== 'object') return
    if (isFragment(v)) {
      v.nodes = v.nodes.map((n) => {
        if (hasProps(n)) return n
        const full = lookup(n.id)
        return full && hasProps(full) ? { ...n, props: full.props, tags: n.tags?.length ? n.tags : full.tags } : n
      })
      return
    }
    if (Array.isArray(v)) {
      for (const item of v) visit(item, depth + 1)
      return
    }
    for (const value of Object.values(v as Record<string, unknown>)) visit(value, depth + 1)
  }
  visit(payload, 0)
  return payload
}
