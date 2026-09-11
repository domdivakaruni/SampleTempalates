import type cytoscape from 'cytoscape'
import type { LayoutHint } from '../api/types'

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

export function layoutOptions(name: LayoutName, nodeCount: number, opts: { randomize?: boolean; hint?: LayoutHint | null } = {}): cytoscape.LayoutOptions {
  const animate = nodeCount <= 80
  switch (name) {
    case 'dagre':
      return {
        name: 'dagre', rankDir: opts.hint === 'tree' ? 'TB' : 'LR', nodeSep: 28, rankSep: 95, edgeSep: 14, ranker: 'network-simplex',
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
      } as unknown as cytoscape.LayoutOptions
  }
}
