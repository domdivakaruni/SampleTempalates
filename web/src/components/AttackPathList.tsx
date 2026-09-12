import { Plus, Route } from 'lucide-react'
import type { AttackPathOut, StageOut } from '../api/types'
import { cn, fmtPct } from '../lib/format'
import { NodeRef } from './NodeRef'
import { StageStrip } from './StageStrip'

interface Props {
  paths: AttackPathOut[]
  activeId?: string | null
  activeStage?: number | null
  onSelectPath?: (path: AttackPathOut) => void
  onSelectStage?: (path: AttackPathOut, stage: StageOut) => void
  onAddToCanvas?: (path: AttackPathOut) => void
  compact?: boolean
}

/** Attack paths with their kill-chain stage strip (technique ids); clicking highlights on the canvas. */
export function AttackPathList({ paths, activeId, activeStage, onSelectPath, onSelectStage, onAddToCanvas, compact }: Props) {
  if (!paths.length) return <div className="text-xs text-fg-3">No attack path through this node.</div>
  return (
    <div className="space-y-2">
      {paths.map((p) => {
        const active = activeId === p.id
        const label = p.fragment.paths[0]?.label ?? p.summary
        return (
          <div key={p.id} className={cn('rounded-md border p-2', active ? 'border-accent/60 bg-accent/5' : 'border-line bg-panel-2/40')}>
            <div className="flex items-start gap-2">
              <button type="button" className="flex min-w-0 flex-1 items-start gap-2 text-left" onClick={() => onSelectPath?.(p)} title="Highlight this path on the canvas">
                <Route size={13} className="mt-0.5 shrink-0 text-accent" />
                <div className="min-w-0">
                  <div className="text-xs font-medium leading-snug text-fg">{label}</div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[10.5px] text-fg-3">
                    <span className="tabular-nums">likelihood {fmtPct(p.likelihood)}</span>
                    <span>·</span>
                    <span className="tabular-nums">{p.hops} hops</span>
                    <span>·</span>
                    <span>{p.stages.length} stages</span>
                  </div>
                </div>
              </button>
              {onAddToCanvas && (
                <button type="button" className="btn-icon h-6 w-6" title="Add this path to the canvas" onClick={() => onAddToCanvas(p)}>
                  <Plus size={12} />
                </button>
              )}
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-1 text-[11px]">
              <NodeRef id={p.entry_id} mono />
              <span className="text-fg-3">→</span>
              {p.through_id && (
                <>
                  <NodeRef id={p.through_id} mono />
                  <span className="text-fg-3">→</span>
                </>
              )}
              <NodeRef id={p.target_id} mono />
            </div>
            {!compact && p.summary && label !== p.summary && <p className="mt-1 text-[11px] leading-snug text-fg-2">{p.summary}</p>}
            <StageStrip stages={p.stages} compact activeOrder={active ? activeStage : null} onSelect={onSelectStage ? (s) => onSelectStage(p, s) : undefined} className="mt-2" />
          </div>
        )
      })}
    </div>
  )
}
