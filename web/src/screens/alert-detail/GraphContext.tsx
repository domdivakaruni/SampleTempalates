import { useEffect, useRef, useState } from 'react'
import type { AlertContext } from '../../api/types'
import { CanvasDetailsOverlay } from '../../components/CanvasDetailsOverlay'
import { CanvasLegend } from '../../graph/CanvasLegend'
import { GraphCanvas, type GraphCanvasHandle } from '../../graph/GraphCanvas'
import { useCanvasHost } from '../../graph/useCanvasHost'
import { useCanvasOps } from '../../graph/useCanvasOps'
import { useNodeActions } from '../../graph/useNodeActions'
import { useSelectionStore } from '../../store/selectionStore'
import { ContextPanels, type ActiveHighlight } from './ContextPanels'

/** Evidence canvas (layout from `evidence.layout_hint`) next to the explainable context panels. */
export function GraphContext({ ctx }: { ctx: AlertContext }) {
  const ref = useRef<GraphCanvasHandle>(null)
  useCanvasHost('alert-detail', ref)
  const ops = useCanvasOps(ref)
  const contextActions = useNodeActions(ref)
  const select = useSelectionStore((s) => s.select)
  const [selected, setSelected] = useState<string | null>(null)
  const [active, setActive] = useState<ActiveHighlight>({})
  useEffect(() => () => select(null), [select])
  const pick = (id: string | null) => {
    setSelected(id)
    select(id)
  }
  const hint = ctx.evidence.layout_hint
  return (
    <div className="flex h-full min-h-0">
      <div className="relative min-w-0 flex-1 border-r border-line">
        <GraphCanvas
          ref={ref}
          fragment={ctx.evidence}
          onSelectNode={(n) => pick(n?.id ?? null)}
          onDoubleClickNode={(n) => void ops.expand(n.id)}
          contextActions={contextActions}
          emptyHint="No evidence fragment for this alert"
        >
          <div className="pointer-events-none absolute left-2 top-2 z-10 max-w-[calc(100%-360px)] truncate rounded-md border border-line bg-panel/85 px-2 py-1 text-[10.5px] text-fg-2 backdrop-blur">
            Evidence · {ctx.evidence.nodes.length} nodes, {ctx.evidence.edges.length} edges · layout {hint}{hint === 'path' || hint === 'storyline' ? ' (attack path pinned left → right)' : ''}
            {ctx.evidence.truncated && <span className="ml-1 text-sev-medium">truncated</span>}
            <span className="ml-2 text-fg-3">double-click expands · right-click for actions</span>
          </div>
          <CanvasLegend fragment={ctx.evidence} />
          <CanvasDetailsOverlay nodeId={selected} onClose={() => pick(null)} onExpand={(id) => void ops.expand(id)} onBlastRadius={(id) => void ops.blast(id)} />
        </GraphCanvas>
      </div>
      <aside className="w-[400px] shrink-0 space-y-3 overflow-y-auto p-3">
        <ContextPanels ctx={ctx} ops={ops} active={active} onActive={setActive} />
      </aside>
    </div>
  )
}
