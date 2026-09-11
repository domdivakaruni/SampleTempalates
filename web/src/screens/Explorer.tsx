import { MousePointerClick, Search } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useNeighborhood } from '../api/hooks'
import type { EdgeOut, GraphFragment, NodeOut } from '../api/types'
import { emptyFragment } from '../api/types'
import { CanvasDetailsOverlay } from '../components/CanvasDetailsOverlay'
import { CanvasLegend } from '../graph/CanvasLegend'
import { GraphCanvas, type GraphCanvasHandle } from '../graph/GraphCanvas'
import { useCanvasHost } from '../graph/useCanvasHost'
import { useCanvasOps } from '../graph/useCanvasOps'
import { useNodeActions } from '../graph/useNodeActions'
import { useCanvasStore } from '../store/canvasStore'
import { useSelectionStore } from '../store/selectionStore'
import { ExplorerSidebar, type SideTab } from './explorer/ExplorerSidebar'

/**
 * /explorer?id=<node id> (also accepts ?seed=). Seeds load GET /graph/neighborhood depth=1; everything else merges into
 * the same canvas: double-click expand, context menu, path finder, blast radius, attack paths, Cypher results and analyst evidence.
 */
export function Explorer() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const seedParam = params.get('id') ?? params.get('seed') ?? ''
  const ref = useRef<GraphCanvasHandle>(null)
  useCanvasHost('explorer', ref)
  const ops = useCanvasOps(ref)
  const contextActions = useNodeActions(ref, { inExplorer: true })
  const selected = useSelectionStore((s) => s.selectedNodeId)
  const select = useSelectionStore((s) => s.select)
  const explorerSeed = useCanvasStore((s) => s.explorerSeed)
  const [loaded, setLoaded] = useState<GraphFragment>(() => emptyFragment())
  const [hiddenLabels, setHiddenLabels] = useState<Set<string>>(() => new Set())
  const [hiddenEdges, setHiddenEdges] = useState<Set<string>>(() => new Set())
  const [tab, setTab] = useState<SideTab>('search')
  const seedQ = useNeighborhood(seedParam ? { id: seedParam, depth: 1, max_nodes: 80 } : null)

  useEffect(() => () => select(null), [select])

  // Mirror the canvas contents so the filter panel and legend know what is drawn (whoever merged it).
  useEffect(() => {
    const cy = ref.current?.cy()
    if (!cy) return
    let timer: number | undefined
    const refresh = () => {
      window.clearTimeout(timer)
      timer = window.setTimeout(() => {
        const c = ref.current?.cy()
        if (!c) return
        const nodes = c.nodes().map((n) => n.data('node') as NodeOut)
        const edges = c.edges().map((e) => e.data('edge') as EdgeOut)
        setLoaded((prev) => ({ ...prev, nodes, edges, total_nodes: nodes.length }))
      }, 60)
    }
    cy.on('add remove', refresh)
    refresh()
    return () => {
      cy.removeListener('add remove', refresh)
      window.clearTimeout(timer)
    }
  }, [])

  // Label / edge-type filters are applied as a `hidden` class (display: none) on the live canvas.
  useEffect(() => {
    const cy = ref.current?.cy()
    if (!cy) return
    cy.batch(() => {
      cy.nodes().forEach((n) => {
        n.toggleClass('hidden', hiddenLabels.has(String(n.data('label'))))
      })
      cy.edges().forEach((e) => {
        e.toggleClass('hidden', hiddenEdges.has(String(e.data('type'))))
      })
    })
  }, [hiddenLabels, hiddenEdges, loaded])

  // "Open in explorer" from the analyst drawer hands us a fragment through the canvas store.
  useEffect(() => {
    if (!explorerSeed) return
    const h = ref.current
    if (h) {
      if (h.counts().nodes === 0) h.setFragment(explorerSeed)
      else h.mergeFragment(explorerSeed, { highlight: true })
    }
    useCanvasStore.getState().setExplorerSeed(null)
  }, [explorerSeed])

  // A seed replaces an empty canvas and merges into a populated one.
  const applySeed = useCallback((frag: GraphFragment, id: string) => {
    const h = ref.current
    if (!h) return
    if (h.counts().nodes === 0) h.setFragment(frag)
    else {
      h.mergeFragment(frag)
      h.focus(id)
    }
    useSelectionStore.getState().select(id)
  }, [])

  useEffect(() => {
    if (seedQ.data && seedParam) applySeed(seedQ.data, seedParam)
  }, [seedQ.data, seedParam, applySeed])

  const onLoadSeed = (id: string) => {
    if (id === seedParam) {
      if (seedQ.data) applySeed(seedQ.data, id)
      else void seedQ.refetch()
    } else navigate(`/explorer?id=${encodeURIComponent(id)}`)
  }
  const clear = () => {
    ref.current?.setFragment(emptyFragment())
    select(null)
    if (seedParam) navigate('/explorer', { replace: true })
  }

  return (
    <div className="flex h-full min-h-0">
      <ExplorerSidebar
        tab={tab}
        onTab={setTab}
        loaded={loaded}
        loading={seedQ.isLoading}
        error={seedQ.error}
        selectedId={selected}
        ops={ops}
        hiddenLabels={hiddenLabels}
        hiddenEdges={hiddenEdges}
        onHiddenLabels={setHiddenLabels}
        onHiddenEdges={setHiddenEdges}
        onLoadSeed={onLoadSeed}
        onClear={clear}
      />
      <div className="relative min-w-0 flex-1">
        <GraphCanvas
          ref={ref}
          onSelectNode={(n) => select(n?.id ?? null)}
          onDoubleClickNode={(n) => void ops.expand(n.id)}
          contextActions={contextActions}
          emptyHint={
            <div className="pointer-events-auto max-w-md text-center">
              <Search size={20} className="mx-auto mb-2 text-fg-3" />
              <div className="text-sm font-medium text-fg-2">Seed the canvas</div>
              <div className="mt-1 text-xs text-fg-3">
                Search a host, role, bucket, CVE or alert in the left panel (or use the global search and press Enter). Then double-click nodes to expand, right-click for blast radius and attack paths, or ask the analyst and watch its evidence land here.
              </div>
              <div className="mt-2 flex items-center justify-center gap-1 text-[10.5px] text-fg-3">
                <MousePointerClick size={11} /> wheel zooms · drag pans · drag a node to move it
              </div>
            </div>
          }
        >
          <CanvasLegend fragment={loaded} />
          <CanvasDetailsOverlay nodeId={selected} onClose={() => select(null)} onExpand={(id) => void ops.expand(id)} onBlastRadius={(id) => void ops.blast(id)} inExplorer />
        </GraphCanvas>
      </div>
    </div>
  )
}
