import { ArrowDown, ArrowUp, Minus, ShieldAlert } from 'lucide-react'
import type { AlertSummary, Band } from '../api/types'
import { bandForScore } from '../api/types'
import { bandColor, severityColor, sourceLabel } from '../theme'
import { cn } from '../lib/format'

export function SeverityChip({ severity, className }: { severity: string | null | undefined; className?: string }) {
  const sev = severity ?? 'informational'
  const c = severityColor(sev)
  return (
    <span className={cn('chip', className)} style={{ borderColor: `${c}66`, color: c, background: `${c}14` }} title={`Vendor severity: ${sev}`}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
      {sev === 'informational' ? 'info' : sev}
    </span>
  )
}

export function BandChip({ band, className }: { band: Band | string; className?: string }) {
  const c = bandColor(band)
  return (
    <span className={cn('chip', className)} style={{ borderColor: `${c}66`, color: c, background: `${c}14` }}>
      {band}
    </span>
  )
}

export function ScoreChip({ score, band, size = 'md', className }: { score: number; band?: Band; size?: 'sm' | 'md' | 'lg'; className?: string }) {
  const b = band ?? bandForScore(score)
  const c = bandColor(b)
  const sz = size === 'lg' ? 'text-base px-2.5 py-0.5 min-w-[44px]' : size === 'sm' ? 'text-[11px] px-1.5 min-w-[28px]' : 'text-xs px-2 min-w-[34px]'
  return (
    <span className={cn('inline-flex items-center justify-center rounded-md font-semibold tabular-nums', sz, className)} style={{ background: `${c}22`, color: c, border: `1px solid ${c}55` }} title={`Contextual score ${score} (${b})`}>
      {score}
    </span>
  )
}

/** Rank movement: contextual position vs vendor position (negative delta = moved up the queue). */
export function RankDelta({ alert, className }: { alert: Pick<AlertSummary, 'vendor_rank_position' | 'contextual_rank_position'>; className?: string }) {
  if (alert.vendor_rank_position == null || alert.contextual_rank_position == null) return null
  const delta = alert.vendor_rank_position - alert.contextual_rank_position
  if (delta === 0)
    return (
      <span className={cn('inline-flex items-center gap-0.5 text-[11px] text-fg-3', className)} title="Same position as in the vendor queue">
        <Minus size={11} />
      </span>
    )
  const up = delta > 0
  return (
    <span className={cn('inline-flex items-center gap-0.5 text-[11px] tabular-nums', up ? 'text-sev-critical' : 'text-sev-low', className)} title={`${up ? 'Moved up' : 'Moved down'} ${Math.abs(delta)} places vs the vendor-severity queue (vendor #${alert.vendor_rank_position} -> contextual #${alert.contextual_rank_position})`}>
      {up ? <ArrowUp size={11} /> : <ArrowDown size={11} />}
      {Math.abs(delta)}
    </span>
  )
}

export function ReasonChips({ reasons, max = 3, className }: { reasons: string[]; max?: number; className?: string }) {
  if (!reasons?.length) return <span className="text-[11px] text-fg-3">—</span>
  const shown = reasons.slice(0, max)
  const rest = reasons.length - shown.length
  return (
    <span className={cn('flex flex-wrap gap-1', className)}>
      {shown.map((r) => (
        <span key={r} className="chip border-line-2 bg-panel-2 text-fg-2" title={r}>
          {r.length > 34 ? `${r.slice(0, 33)}…` : r}
        </span>
      ))}
      {rest > 0 && (
        <span className="chip border-line-2 text-fg-3" title={reasons.slice(max).join('\n')}>
          +{rest}
        </span>
      )}
    </span>
  )
}

export function TIBadge({ alert, actorNames, className }: { alert: Pick<AlertSummary, 'ioc_match_count' | 'ti_actor_ids'>; actorNames?: Record<string, string>; className?: string }) {
  if (!alert.ioc_match_count && !alert.ti_actor_ids?.length) return <span className="text-[11px] text-fg-3">—</span>
  const names = (alert.ti_actor_ids ?? []).map((a) => actorNames?.[a] ?? a.split(':').pop()?.replace(/-/g, ' ')).join(', ')
  return (
    <span className={cn('chip border-cat-ti/40 bg-cat-ti/10 text-cat-ti', className)} title={`${alert.ioc_match_count} IOC match(es)${names ? `; actors: ${names}` : ''}`}>
      <ShieldAlert size={11} />
      {alert.ioc_match_count > 0 && <span className="tabular-nums">{alert.ioc_match_count} IOC</span>}
      {names && <span className="max-w-[110px] truncate capitalize">{names}</span>}
    </span>
  )
}

export function SourceChip({ source, className }: { source: string; className?: string }) {
  return (
    <span className={cn('chip border-line-2 text-fg-2', className)} title={source}>
      {sourceLabel(source)}
    </span>
  )
}

export function StorylineChip({ id, title, onClick, className }: { id: string | null | undefined; title?: string; onClick?: () => void; className?: string }) {
  if (!id) return <span className="text-[11px] text-fg-3">—</span>
  const short = id.split(':').pop() ?? id
  const Comp = onClick ? 'button' : 'span'
  return (
    <Comp type={onClick ? 'button' : undefined} onClick={onClick} className={cn('chip border-sev-critical/40 bg-sev-critical/10 text-sev-critical', onClick && 'hover:bg-sev-critical/20 cursor-pointer', className)} title={title ?? id}>
      {short.replace(/-larkspur$/, '')}
    </Comp>
  )
}

export function Pill({ children, tone = 'neutral', className, title }: { children: React.ReactNode; tone?: 'neutral' | 'accent' | 'good' | 'warn' | 'bad'; className?: string; title?: string }) {
  const tones: Record<string, string> = {
    neutral: 'border-line-2 text-fg-2',
    accent: 'border-accent/40 bg-accent/10 text-accent',
    good: 'border-cat-endpoint/40 bg-cat-endpoint/10 text-cat-endpoint',
    warn: 'border-sev-medium/40 bg-sev-medium/10 text-sev-medium',
    bad: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
  }
  return (
    <span className={cn('chip', tones[tone], className)} title={title}>
      {children}
    </span>
  )
}
