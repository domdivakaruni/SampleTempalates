/** Viewport and highlight helpers shared by GraphCanvas (kept out of the component to keep it small). */
import type cytoscape from 'cytoscape'

/** Zooming closer than this on a fit-to-highlight would blow a handful of nodes up to fill the canvas. */
export const MAX_FIT_ZOOM = 1.35

/** Add `highlight` (and `show-label` on edges) to the given ids; everything else gets `dim` when requested. */
export function highlightElements(cy: cytoscape.Core, ids: string[], dim: boolean, fit: boolean): void {
  const set = new Set(ids)
  cy.batch(() => {
    cy.elements().removeClass('highlight dim show-label')
    if (!set.size) return
    cy.elements().forEach((el) => {
      if (set.has(el.id())) el.addClass(el.isEdge() ? 'highlight show-label' : 'highlight')
      else if (dim) el.addClass('dim')
    })
  })
  if (fit && set.size) {
    const eles = cy.elements('.highlight')
    if (eles.length) cy.animate({ fit: { eles, padding: 70 }, duration: 300, easing: 'ease-out' })
  }
}

/**
 * Fit the viewport to a set of element ids (the highlighted path) so long storyline chains stay legible.
 * Needs at least two highlighted nodes and never zooms past MAX_FIT_ZOOM.
 */
export function fitToIds(cy: cytoscape.Core, ids: string[], padding = 60): void {
  const eles = cy.collection()
  for (const id of ids) eles.merge(cy.getElementById(id))
  if (eles.nodes().length < 2) return
  const bb = eles.boundingBox({ includeLabels: true })
  const w = Math.max(1, cy.width() - 2 * padding)
  const h = Math.max(1, cy.height() - 2 * padding)
  const zoom = Math.min(MAX_FIT_ZOOM, w / Math.max(1, bb.w), h / Math.max(1, bb.h))
  const pan = { x: cy.width() / 2 - zoom * (bb.x1 + bb.w / 2), y: cy.height() / 2 - zoom * (bb.y1 + bb.h / 2) }
  cy.animate({ zoom, pan, duration: 300, easing: 'ease-out' })
}

export function fitAll(cy: cytoscape.Core): void {
  if (cy.nodes().length) cy.animate({ fit: { eles: cy.elements(), padding: 30 }, duration: 250 })
}

export function zoomBy(cy: cytoscape.Core, factor: number): void {
  cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } })
}

export function focusNode(cy: cytoscape.Core, id: string): void {
  const n = cy.getElementById(id)
  if (!n.length) return
  cy.nodes().removeClass('focus')
  n.addClass('focus')
  cy.animate({ center: { eles: n }, zoom: Math.max(cy.zoom(), 1.1), duration: 300, easing: 'ease-out' })
}
