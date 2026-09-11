import type cytoscape from 'cytoscape'
import { ACCENT, FG_2, LINE } from '../theme'

export const PANEL_BG = '#0d1424'

/** Stylesheet for the security context graph. Classes: highlight, dim, focus, pinned, hover, show-label, cut, nolabel. */
export function graphStylesheet(): cytoscape.Stylesheet[] {
  const styles: { selector: string; style: Record<string, unknown> }[] = [
    {
      selector: 'node',
      style: {
        shape: 'ellipse', width: 36, height: 36,
        'background-color': PANEL_BG, 'background-opacity': 1,
        'border-width': 2, 'border-color': 'data(color)', 'border-opacity': 0.9,
        'background-image': 'data(image)', 'background-fit': 'contain', 'background-clip': 'none', 'background-width': '120%', 'background-height': '120%', 'bounds-expansion': 8,
        label: 'data(display)', color: '#cbd5e1', 'font-size': 9, 'font-family': 'Inter, ui-sans-serif, system-ui, sans-serif', 'font-weight': 500,
        'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 6, 'text-wrap': 'ellipsis', 'text-max-width': 120,
        'text-background-color': '#070b14', 'text-background-opacity': 0.75, 'text-background-padding': 2, 'text-background-shape': 'roundrectangle',
        'min-zoomed-font-size': 7, 'overlay-opacity': 0, 'transition-property': 'opacity, border-width, width, height', 'transition-duration': 150,
        'z-index': 5,
      },
    },
    { selector: 'node[label = "Alert"], node[label = "Incident"], node[label = "CloudEvent"]', style: { shape: 'round-rectangle', width: 34, height: 34 } },
    { selector: 'node[label = "Storyline"]', style: { shape: 'round-hexagon', width: 40, height: 40 } },
    { selector: 'node[label = "ThreatActor"], node[label = "Campaign"]', style: { shape: 'diamond', width: 40, height: 40 } },
    { selector: 'node[label = "Internet"]', style: { width: 44, height: 44, 'border-style': 'dashed' } },
    { selector: 'node.crown', style: { 'border-width': 2.5 } },
    { selector: 'node.hover', style: { 'border-width': 3, 'z-index': 20 } },
    { selector: 'node.highlight', style: { 'underlay-color': 'data(color)', 'underlay-opacity': 0.28, 'underlay-padding': 7, 'border-width': 3, opacity: 1, 'z-index': 15 } },
    { selector: 'node.focus', style: { 'border-color': ACCENT, 'border-width': 3.5, width: 44, height: 44, 'underlay-color': ACCENT, 'underlay-opacity': 0.25, 'underlay-padding': 9, 'z-index': 25 } },
    { selector: 'node.pinned', style: { 'border-style': 'double', 'border-width': 4 } },
    { selector: 'node.dim', style: { opacity: 0.3, 'z-index': 1 } },
    { selector: 'node.nolabel', style: { label: '' } },
    { selector: 'node:selected', style: { 'border-color': '#f8fafc', 'border-width': 3, 'z-index': 30 } },
    {
      selector: 'edge',
      style: {
        width: 1.3, 'line-color': LINE, 'target-arrow-color': LINE, 'target-arrow-shape': 'triangle', 'arrow-scale': 0.8, 'curve-style': 'bezier',
        'control-point-step-size': 40, label: '', 'font-size': 8, color: FG_2, 'text-rotation': 'autorotate', 'text-margin-y': -6,
        'text-background-color': '#070b14', 'text-background-opacity': 0.85, 'text-background-padding': 2, 'text-background-shape': 'roundrectangle',
        'overlay-opacity': 0, opacity: 0.9, 'transition-property': 'opacity, width, line-color', 'transition-duration': 150,
      },
    },
    { selector: 'edge[?derived]', style: { 'line-style': 'dashed', 'line-dash-pattern': [6, 3] } },
    { selector: 'edge.show-label, edge.hover, edge:selected', style: { label: 'data(type)', 'z-index': 12 } },
    { selector: 'edge.hover, edge:selected', style: { 'line-color': '#94a3b8', 'target-arrow-color': '#94a3b8', width: 2 } },
    { selector: 'edge.highlight', style: { 'line-color': ACCENT, 'target-arrow-color': ACCENT, width: 2.4, opacity: 1, 'z-index': 10 } },
    { selector: 'edge.highlight.show-label, edge.highlight.hover', style: { color: '#bae6fd' } },
    { selector: 'edge.dim', style: { opacity: 0.18 } },
    { selector: 'edge.cut', style: { 'line-color': '#f87171', 'target-arrow-color': '#f87171', 'line-style': 'dotted', width: 2.5 } },
  ]
  return styles as unknown as cytoscape.Stylesheet[]
}
