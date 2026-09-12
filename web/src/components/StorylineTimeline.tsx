import { useNavigate } from 'react-router-dom'
import type { AlertSummary, StageOut } from '../api/types'
import { cn, fmtTime, shortId } from '../lib/format'
import { bandColor } from '../theme'
import { ScoreChip, SeverityChip } from './chips'

interface Props {
  stages: StageOut[]
  alerts?: Record<string, AlertSummary>
  activeOrder?: number | null
  onSelectStage?: (stage: StageOut) => void
  className?: string
  /** Alert id to emphasise (the alert whose detail page we are on). */
  currentAlertId?: string | null
}

/** Vertical kill-chain timeline: time, stage, techniques, summary and the member alerts of each stage. */
export function StorylineTimeline({ stages, alerts = {}, activeOrder, onSelectStage, className, currentAlertId }: Props) {
  const navigate = useNavigate()
  if (!stages.length) return <div className="text-xs text-fg-3">No stages.</div>
  return (
    <ol className={cn('relative ml-2 border-l border-line-2 pl-4', className)}>
      {stages.map((s) => {
        const active = activeOrder === s.order
        return (
          <li key={s.order} className="relative pb-3 last:pb-0">
            <span className={cn('absolute -left-[21px] top-1 flex h-[13px] w-[13px] items-center justify-center rounded-full border-2 border-bg text-[8px] font-bold', active ? 'bg-accent text-bg' : 'bg-panel-3 text-fg-2')}>{s.order}</span>
            <button type="button" onClick={() => onSelectStage?.(s)} className={cn('w-full rounded-md border px-2.5 py-1.5 text-left transition-colors', active ? 'border-accent/60 bg-accent/10' : 'border-line bg-panel-2/50 hover:border-line-2', onSelectStage ? 'cursor-pointer' : 'cursor-default')}>
              <div className="flex flex-wrap items-center justify-between gap-1">
                <span className="text-xs font-semibold text-fg">{s.stage}</span>
                <span className="mono text-[10.5px] text-fg-3">{fmtTime(s.time, { seconds: true })}</span>
              </div>
              <div className="mt-1 flex flex-wrap gap-0.5">
                {s.technique_ids.map((t) => (
                  <span key={t} className="mono rounded bg-bg/70 px-1 text-[9.5px] text-fg-2">
                    {t}
                  </span>
                ))}
              </div>
              {s.summary && <p className="mt-1 text-[11.5px] leading-snug text-fg-2">{s.summary}</p>}
              <div className="mt-1.5 space-y-0.5">
                {s.alert_ids.length === 0 && <div className="text-[10.5px] italic text-fg-3">No vendor alert for this stage{s.node_ids.some((n) => n.startsWith('cloudevent:')) ? ' — cloud audit events only' : ''}.</div>}
                {s.alert_ids.map((id) => {
                  const a = alerts[id]
                  const current = id === currentAlertId
                  return (
                    <span
                      key={id}
                      role="link"
                      tabIndex={0}
                      onClick={(e) => {
                        e.stopPropagation()
                        navigate(`/alerts/${encodeURIComponent(id)}`)
                      }}
                      onKeyDown={(e) => e.key === 'Enter' && navigate(`/alerts/${encodeURIComponent(id)}`)}
                      className={cn('flex cursor-pointer items-center gap-1.5 rounded px-1 py-[1px] text-[11px] hover:bg-panel-3', current && 'bg-accent/15')}
                      title={id}
                    >
                      {a ? <SeverityChip severity={a.vendor_severity} /> : <span className="chip border-line-2 text-fg-3">alert</span>}
                      {a && <ScoreChip score={a.contextual_score} band={a.contextual_band} size="sm" />}
                      <span className="truncate text-fg" style={current ? { color: bandColor(a?.contextual_band) } : undefined}>{a?.title ?? shortId(id)}</span>
                      <span className="mono ml-auto shrink-0 text-[10px] text-fg-3">{shortId(id)}</span>
                    </span>
                  )
                })}
              </div>
            </button>
          </li>
        )
      })}
    </ol>
  )
}
