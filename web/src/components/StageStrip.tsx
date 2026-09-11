import { ChevronRight } from 'lucide-react'
import type { StageOut } from '../api/types'
import { fmtShortTime } from '../lib/format'
import { cn } from '../lib/format'

interface Props {
  stages: StageOut[]
  activeOrder?: number | null
  onSelect?: (stage: StageOut) => void
  compact?: boolean
  className?: string
}

/** Kill-chain stage strip with technique ids; click to highlight a stage on the canvas. */
export function StageStrip({ stages, activeOrder, onSelect, compact, className }: Props) {
  if (!stages.length) return null
  return (
    <div className={cn('flex flex-wrap items-stretch gap-1', className)}>
      {stages.map((s, i) => {
        const active = activeOrder === s.order
        return (
          <div key={s.order} className="flex items-stretch gap-1">
            <button
              type="button"
              onClick={() => onSelect?.(s)}
              className={cn(
                'rounded-md border px-2 py-1 text-left transition-colors',
                active ? 'border-accent bg-accent/15' : 'border-line bg-panel-2/60 hover:border-line-2 hover:bg-panel-2',
                onSelect ? 'cursor-pointer' : 'cursor-default',
                compact ? 'min-w-[96px]' : 'min-w-[128px] max-w-[190px]',
              )}
              title={s.summary}
            >
              <div className="flex items-center gap-1.5">
                <span className={cn('flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-semibold', active ? 'bg-accent text-bg' : 'bg-panel-3 text-fg-2')}>{s.order}</span>
                <span className="truncate text-[11px] font-medium text-fg">{s.stage}</span>
              </div>
              <div className="mt-1 flex flex-wrap gap-0.5">
                {s.technique_ids.slice(0, compact ? 2 : 4).map((t) => (
                  <span key={t} className="mono rounded bg-bg/70 px-1 text-[9.5px] text-fg-2">
                    {t}
                  </span>
                ))}
                {s.technique_ids.length > (compact ? 2 : 4) && <span className="text-[9.5px] text-fg-3">+{s.technique_ids.length - (compact ? 2 : 4)}</span>}
              </div>
              {!compact && (
                <div className="mt-1 flex items-center justify-between text-[10px] text-fg-3">
                  <span>{s.alert_ids.length ? `${s.alert_ids.length} alert${s.alert_ids.length === 1 ? '' : 's'}` : 'no alert'}</span>
                  <span>{fmtShortTime(s.time)}</span>
                </div>
              )}
            </button>
            {i < stages.length - 1 && (
              <span className="flex items-center text-fg-3">
                <ChevronRight size={12} />
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}
