import { ExternalLink, Eye, MousePointerClick } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { GraphFragment } from '../../api/types'
import { cn } from '../../lib/format'
import { useCanvasStore } from '../../store/canvasStore'

export function EvidenceBar({ evidence, className }: { evidence: GraphFragment | null | undefined; className?: string }) {
  const navigate = useNavigate()
  const active = useCanvasStore((s) => s.activeCanvas)
  const auto = useCanvasStore((s) => s.autoHighlight)
  const setAuto = useCanvasStore((s) => s.setAutoHighlight)
  const publish = useCanvasStore((s) => s.publish)
  const setHighlight = useCanvasStore((s) => s.setHighlight)
  const setSeed = useCanvasStore((s) => s.setExplorerSeed)
  if (!evidence || !evidence.nodes.length) return null
  const show = () => {
    publish(evidence, 'merge')
    setHighlight([...evidence.nodes.map((n) => n.id), ...evidence.edges.map((e) => e.id)])
  }
  const openExplorer = () => {
    setSeed(evidence)
    navigate('/explorer')
  }
  return (
    <div className={cn('flex flex-wrap items-center gap-1.5 rounded-md border border-line bg-panel-2/70 px-2 py-1 text-[11px]', className)}>
      <span className="text-fg-2">
        Evidence: <span className="font-medium text-fg tabular-nums">{evidence.nodes.length} nodes, {evidence.edges.length} edges</span>
        {evidence.truncated && <span className="ml-1 text-sev-medium">(truncated)</span>}
      </span>
      <span className="flex-1" />
      {active ? (
        <>
          <button type="button" className="btn-ghost py-0.5" onClick={show} title="Merge into the visible canvas and highlight">
            <Eye size={11} /> Show on canvas
          </button>
          <label className="flex cursor-pointer items-center gap-1 text-fg-3" title="Automatically highlight evidence as it streams">
            <input type="checkbox" className="h-3 w-3 accent-sky-400" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            auto
          </label>
        </>
      ) : (
        <button type="button" className="btn-ghost py-0.5" onClick={openExplorer} title="No canvas is visible on this screen">
          <ExternalLink size={11} /> Open in explorer
        </button>
      )}
      <span className="hidden text-fg-3 xl:inline" title="Right-click nodes on the canvas for more actions">
        <MousePointerClick size={11} />
      </span>
    </div>
  )
}
