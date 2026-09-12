import { Eraser, Maximize2, Tag, ZoomIn, ZoomOut } from 'lucide-react'
import { LAYOUT_LABELS, type LayoutName } from './layouts'

interface Props {
  layout: LayoutName
  labels: boolean
  counts: { nodes: number; edges: number }
  onLayout: (name: LayoutName) => void
  onToggleLabels: () => void
  onClear: () => void
  onFit: () => void
  onZoom: (factor: number) => void
}

export function CanvasToolbar({ layout, labels, counts, onLayout, onToggleLabels, onClear, onFit, onZoom }: Props) {
  return (
    <div className="absolute right-2 top-2 z-20 flex items-center gap-1 rounded-md border border-line bg-panel/90 p-1 backdrop-blur">
      <span className="px-2 text-[11px] text-fg-3 tabular-nums" title="Nodes / edges on canvas">
        {counts.nodes} n · {counts.edges} e
      </span>
      <select className="select h-7 py-0 text-[11px]" value={layout} onChange={(e) => onLayout(e.target.value as LayoutName)} title="Layout">
        {(Object.keys(LAYOUT_LABELS) as LayoutName[]).map((k) => (
          <option key={k} value={k}>
            {LAYOUT_LABELS[k]}
          </option>
        ))}
      </select>
      <button type="button" className={`btn-icon ${labels ? 'text-accent' : ''}`} onClick={onToggleLabels} title="Toggle labels">
        <Tag size={13} />
      </button>
      <button type="button" className="btn-icon" onClick={onClear} title="Clear highlights">
        <Eraser size={13} />
      </button>
      <button type="button" className="btn-icon" onClick={onFit} title="Fit">
        <Maximize2 size={13} />
      </button>
      <button type="button" className="btn-icon" onClick={() => onZoom(1.3)} title="Zoom in">
        <ZoomIn size={13} />
      </button>
      <button type="button" className="btn-icon" onClick={() => onZoom(1 / 1.3)} title="Zoom out">
        <ZoomOut size={13} />
      </button>
    </div>
  )
}
