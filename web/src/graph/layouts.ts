import type cytoscape from 'cytoscape'
import type { GraphFragment, LayoutHint } from '../api/types'

export type LayoutName = 'fcose' | 'dagre' | 'concentric' | 'grid'

export const LAYOUT_LABELS: Record<LayoutName, string> = { fcose: 'Force (fcose)', dagre: 'Layered LR (dagre)', concentric: 'Concentric', grid: 'Grid' }

export function layoutForHint(hint: LayoutHint | null | undefined): LayoutName {
  switch (hint) {
    case 'path':
    case 'storyline':
    case 'tree':
      return 'dagre'
    case 'blast_radius':
      return 'fcose'
    default:
      return 'fcose'
  }
}

/** Above this size a layered layout of a storyline fragment (long NEXT_STAGE chains) becomes unreadably wide. */
export const DAGRE_MAX_NODES = 24

/**
 * Layout for a fragment: dagre LR for compact paths / storylines, otherwise fcose. Large path fragments still read
 * left-to-right because the primary path is pinned on a horizontal line through fcose constraints (see `layoutOptions`).
 */
export function layoutForFragment(f: GraphFragment): LayoutName {
  const name = layoutForHint(f.layout_hint)
  if (name === 'dagre' && f.nodes.length > DAGRE_MAX_NODES) return 'fcose'
  return name
}

/** The primary path of a fragment restricted to nodes that exist in it (used for fcose alignment constraints). */
export function primaryPath(f: GraphFragment): string[] {
  const ids = new Set(f.nodes.map((n) => n.id))
  const path = f.paths[0]?.node_ids ?? []
  return path.filter((id, i) => ids.has(id) && path.indexOf(id) === i)
}

export interface LayoutExtras { randomize?: boolean; hint?: LayoutHint | null; path?: string[] }

export function layoutOptions(name: LayoutName, nodeCount: number, opts: LayoutExtras = {}): cytoscape.LayoutOptions {
  const animate = nodeCount <= 80
  const path = opts.path && opts.path.length > 1 ? opts.path : null
  switch (name) {
    case 'dagre':
      return {
        name: 'dagre', rankDir: opts.hint === 'tree' ? 'TB' : 'LR', nodeSep: 22, rankSep: 70, edgeSep: 10, ranker: 'network-simplex',
        fit: true, padding: 32, animate: false, nodeDimensionsIncludeLabels: true,
      } as unknown as cytoscape.LayoutOptions
    case 'concentric':
      return {
        name: 'concentric', fit: true, padding: 32, animate: false, minNodeSpacing: 34, startAngle: Math.PI / 2, equidistant: false,
        concentric: (n: cytoscape.NodeSingular) => (n.hasClass('focus') ? 1000 : n.degree(false)), levelWidth: () => 2,
      } as unknown as cytoscape.LayoutOptions
    case 'grid':
      return { name: 'grid', fit: true, padding: 32, animate: false, avoidOverlap: true, condense: true } as cytoscape.LayoutOptions
    default:
      return {
        name: 'fcose', quality: 'default', randomize: opts.randomize ?? true, animate, animationDuration: 450, fit: true, padding: 32,
        nodeDimensionsIncludeLabels: true, uniformNodeDimensions: true, packComponents: false, nodeRepulsion: 6500, idealEdgeLength: 95,
        edgeElasticity: 0.45, nestingFactor: 0.1, gravity: 0.3, gravityRange: 3.8, numIter: 2500, tile: true, tilingPaddingVertical: 20, tilingPaddingHorizontal: 20,
        // Pin the attack path on one horizontal line, left to right; everything else settles around it.
        ...(path
          ? {
              alignmentConstraint: { horizontal: [path] },
              relativePlacementConstraint: path.slice(1).map((id, i) => ({ left: path[i], right: id, gap: 150 })),
            }
          : {}),
      } as unknown as cytoscape.LayoutOptions
  }
}
