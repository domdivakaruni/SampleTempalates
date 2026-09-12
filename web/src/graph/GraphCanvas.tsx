import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import fcose from 'cytoscape-fcose'
import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState, type ReactNode } from 'react'
import type { EdgeOut, GraphFragment, NodeOut } from '../api/types'
import { CanvasToolbar } from './CanvasToolbar'
import { ContextMenu, type ContextAction } from './ContextMenu'
import { fragmentElements, fragmentHighlightIds } from './elements'
import { layoutForFragment, layoutOptions, primaryPath, type LayoutExtras, type LayoutName } from './layouts'
import { graphStylesheet } from './styles'
import { fitAll, fitToIds, focusNode, highlightElements, zoomBy } from './viewport'

let registered = false
function ensureExtensions() {
  if (registered) return
  cytoscape.use(fcose)
  cytoscape.use(dagre)
  registered = true
}

export interface GraphCanvasHandle {
  setFragment: (f: GraphFragment, opts?: { layout?: LayoutName }) => void
  mergeFragment: (f: GraphFragment, opts?: { highlight?: boolean; relayout?: boolean }) => void
  highlight: (ids: string[], opts?: { dim?: boolean; fit?: boolean }) => void
  clearHighlights: () => void
  focus: (id: string) => void
  layout: (name: LayoutName) => void
  fit: () => void
  zoom: (factor: number) => void
  toggleLabels: (show?: boolean) => void
  markCut: (edgeIds: string[]) => void
  removeNode: (id: string) => void
  has: (id: string) => boolean
  counts: () => { nodes: number; edges: number }
  cy: () => cytoscape.Core | null
}

export interface GraphCanvasProps {
  fragment?: GraphFragment | null
  onSelectNode?: (node: NodeOut | null) => void
  onSelectEdge?: (edge: EdgeOut | null) => void
  onDoubleClickNode?: (node: NodeOut) => void
  contextActions?: (node: NodeOut) => ContextAction[]
  className?: string
  toolbar?: boolean
  emptyHint?: ReactNode
  children?: ReactNode
}

export const GraphCanvas = forwardRef<GraphCanvasHandle, GraphCanvasProps>(function GraphCanvas(
  { fragment, onSelectNode, onSelectEdge, onDoubleClickNode, contextActions, className, toolbar = true, emptyHint, children },
  ref,
) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const layoutRef = useRef<LayoutName>('fcose')
  const labelsRef = useRef(true)
  const pendingFit = useRef(false)
  const [layoutName, setLayoutName] = useState<LayoutName>('fcose')
  const [labels, setLabels] = useState(true)
  const [counts, setCounts] = useState({ nodes: 0, edges: 0 })
  const [menu, setMenu] = useState<{ node: NodeOut; x: number; y: number } | null>(null)
  const callbacks = useRef({ onSelectNode, onSelectEdge, onDoubleClickNode, contextActions })
  useEffect(() => {
    callbacks.current = { onSelectNode, onSelectEdge, onDoubleClickNode, contextActions }
  })

  const refreshCounts = useCallback(() => {
    const cy = cyRef.current
    if (cy) setCounts({ nodes: cy.nodes().length, edges: cy.edges().length })
  }, [])

  const pathRef = useRef<string[]>([])

  const runLayout = useCallback((name: LayoutName, randomize: boolean, hint?: GraphFragment['layout_hint'] | null, after?: () => void, extras: Pick<LayoutExtras, 'path'> = {}) => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    const el = containerRef.current
    if (!el || el.clientWidth === 0 || el.clientHeight === 0) pendingFit.current = true
    const path = (extras.path ?? pathRef.current).filter((id) => cy.getElementById(id).length > 0)
    const layout = cy.layout(layoutOptions(name, cy.nodes().length, { randomize, hint, path }))
    if (after) layout.one('layoutstop', after)
    layout.run()
  }, [])

  const fitTo = useCallback((ids: string[]) => {
    if (cyRef.current) fitToIds(cyRef.current, ids)
  }, [])

  const applyHighlight = useCallback((ids: string[], dim = true, fit = true) => {
    if (cyRef.current) highlightElements(cyRef.current, ids, dim, fit)
  }, [])

  useEffect(() => {
    ensureExtensions()
    const container = containerRef.current
    if (!container) return
    const cy = cytoscape({ container, elements: [], style: graphStylesheet(), wheelSensitivity: 0.25, minZoom: 0.12, maxZoom: 4, boxSelectionEnabled: false, autoungrabify: false })
    cyRef.current = cy
    cy.on('tap', 'node', (e) => {
      setMenu(null)
      callbacks.current.onSelectNode?.((e.target as cytoscape.NodeSingular).data('node') as NodeOut)
    })
    cy.on('tap', 'edge', (e) => callbacks.current.onSelectEdge?.((e.target as cytoscape.EdgeSingular).data('edge') as EdgeOut))
    cy.on('tap', (e) => {
      if (e.target === cy) {
        setMenu(null)
        callbacks.current.onSelectNode?.(null)
        callbacks.current.onSelectEdge?.(null)
      }
    })
    cy.on('dbltap', 'node', (e) => callbacks.current.onDoubleClickNode?.((e.target as cytoscape.NodeSingular).data('node') as NodeOut))
    cy.on('cxttap', 'node', (e) => {
      const node = (e.target as cytoscape.NodeSingular).data('node') as NodeOut
      const pos = e.renderedPosition ?? { x: 0, y: 0 }
      setMenu({ node, x: pos.x, y: pos.y })
    })
    cy.on('cxttap', (e) => {
      if (e.target === cy) setMenu(null)
    })
    cy.on('mouseover', 'node', (e) => {
      const n = e.target as cytoscape.NodeSingular
      n.addClass('hover')
      n.connectedEdges().addClass('show-label')
      container.style.cursor = 'pointer'
    })
    cy.on('mouseout', 'node', (e) => {
      const n = e.target as cytoscape.NodeSingular
      n.removeClass('hover')
      n.connectedEdges().not('.highlight').removeClass('show-label')
      container.style.cursor = ''
    })
    cy.on('mouseover', 'edge', (e) => (e.target as cytoscape.EdgeSingular).addClass('hover'))
    cy.on('mouseout', 'edge', (e) => (e.target as cytoscape.EdgeSingular).removeClass('hover'))
    const ro = new ResizeObserver(() => {
      cy.resize()
      if (pendingFit.current && container.clientWidth > 0 && cy.nodes().length) {
        pendingFit.current = false
        runLayout(layoutRef.current, true)
      }
    })
    ro.observe(container)
    return () => {
      ro.disconnect()
      cy.destroy()
      cyRef.current = null
    }
  }, [runLayout])

  const setFragment = useCallback(
    (f: GraphFragment, opts: { layout?: LayoutName } = {}) => {
      const cy = cyRef.current
      if (!cy) return
      cy.batch(() => {
        cy.elements().remove()
        cy.add(fragmentElements(f))
        if (!labelsRef.current) cy.nodes().addClass('nolabel')
        for (const id of f.focus) cy.getElementById(id).addClass('focus')
      })
      const name = opts.layout ?? layoutForFragment(f)
      layoutRef.current = name
      setLayoutName(name)
      pathRef.current = primaryPath(f)
      const hl = fragmentHighlightIds(f)
      if (hl.length) applyHighlight(hl, true, false)
      runLayout(name, true, f.layout_hint, hl.length ? () => fitTo(hl) : undefined, { path: pathRef.current })
      refreshCounts()
    },
    [applyHighlight, fitTo, refreshCounts, runLayout],
  )

  const mergeFragment = useCallback(
    (f: GraphFragment, opts: { highlight?: boolean; relayout?: boolean } = {}) => {
      const cy = cyRef.current
      if (!cy) return
      if (cy.nodes().length === 0) {
        setFragment(f)
        if (opts.highlight) applyHighlight([...f.nodes.map((n) => n.id), ...f.edges.map((e) => e.id)], true, true)
        return
      }
      const fresh = fragmentElements(f).filter((el) => cy.getElementById(String(el.data.id)).length === 0)
      const ids = [...f.nodes.map((n) => n.id), ...f.edges.map((e) => e.id)]
      if (fresh.length) {
        cy.batch(() => {
          cy.add(fresh)
          if (!labelsRef.current) cy.nodes().addClass('nolabel')
        })
        if (opts.highlight) applyHighlight(ids, true, false)
        if (opts.relayout !== false) runLayout(layoutRef.current, layoutRef.current !== 'fcose', f.layout_hint, opts.highlight ? () => fitTo(ids) : undefined)
        else if (opts.highlight) fitTo(ids)
      } else if (opts.highlight) applyHighlight(ids, true, true)
      refreshCounts()
    },
    [applyHighlight, fitTo, refreshCounts, runLayout, setFragment],
  )

  useImperativeHandle(
    ref,
    () => ({
      setFragment,
      mergeFragment,
      highlight: (ids, opts = {}) => applyHighlight(ids, opts.dim ?? true, opts.fit ?? true),
      clearHighlights: () => {
        const cy = cyRef.current
        cy?.elements().removeClass('highlight dim show-label cut')
      },
      focus: (id) => cyRef.current && focusNode(cyRef.current, id),
      layout: (name) => {
        layoutRef.current = name
        setLayoutName(name)
        runLayout(name, true)
      },
      fit: () => cyRef.current && fitAll(cyRef.current),
      zoom: (factor) => cyRef.current && zoomBy(cyRef.current, factor),
      toggleLabels: (show) => {
        const next = show ?? !labelsRef.current
        labelsRef.current = next
        setLabels(next)
        cyRef.current?.nodes().toggleClass('nolabel', !next)
      },
      markCut: (edgeIds) => {
        const cy = cyRef.current
        if (!cy) return
        cy.edges().removeClass('cut')
        for (const id of edgeIds) cy.getElementById(id).addClass('cut')
      },
      removeNode: (id) => {
        cyRef.current?.getElementById(id).remove()
        refreshCounts()
      },
      has: (id) => (cyRef.current?.getElementById(id).length ?? 0) > 0,
      counts: () => ({ nodes: cyRef.current?.nodes().length ?? 0, edges: cyRef.current?.edges().length ?? 0 }),
      cy: () => cyRef.current,
    }),
    [applyHighlight, mergeFragment, refreshCounts, runLayout, setFragment],
  )

  useEffect(() => {
    if (fragment) setFragment(fragment)
    else if (fragment === null && cyRef.current) {
      cyRef.current.elements().remove()
      refreshCounts()
    }
  }, [fragment, setFragment, refreshCounts])

  return (
    <div className={`relative h-full w-full overflow-hidden bg-bg ${className ?? ''}`}>
      <div ref={containerRef} className="h-full w-full" />
      {counts.nodes === 0 && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-xs text-fg-3">{emptyHint ?? 'No graph loaded'}</div>
      )}
      {toolbar && (
        <CanvasToolbar
          layout={layoutName}
          labels={labels}
          counts={counts}
          onLayout={(name) => {
            layoutRef.current = name
            setLayoutName(name)
            runLayout(name, true)
          }}
          onToggleLabels={() => {
            const next = !labelsRef.current
            labelsRef.current = next
            setLabels(next)
            cyRef.current?.nodes().toggleClass('nolabel', !next)
          }}
          onClear={() => cyRef.current?.elements().removeClass('highlight dim show-label cut')}
          onFit={() => cyRef.current && fitAll(cyRef.current)}
          onZoom={(f) => cyRef.current && zoomBy(cyRef.current, f)}
        />
      )}
      {menu && <ContextMenu x={menu.x} y={menu.y} node={menu.node} actions={contextActions?.(menu.node) ?? []} onClose={() => setMenu(null)} />}
      {children}
    </div>
  )
})
