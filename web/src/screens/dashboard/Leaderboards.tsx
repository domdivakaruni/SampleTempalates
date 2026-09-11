import { ArrowLeftRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { AlertSummary } from '../../api/types'
import { LabelIcon } from '../../components/LabelIcon'
import { Panel } from '../../components/Page'
import { RankDelta, ScoreChip, SeverityChip, StorylineChip } from '../../components/chips'
import { cn, shortId } from '../../lib/format'

function Board({ alerts, mode }: { alerts: AlertSummary[]; mode: 'contextual' | 'vendor' }) {
  const navigate = useNavigate()
  return (
    <table className="table-dense w-full text-xs">
      <thead>
        <tr>
          <th className="w-8 text-right">#</th>
          <th className="w-[150px]">Asset</th>
          <th>Alert</th>
          <th className="w-[84px]">Vendor</th>
          <th className="w-[104px]">Contextual</th>
          <th className="w-[92px]">Storyline</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((a, i) => {
          const buried = mode === 'vendor' && a.contextual_band !== 'critical' && a.contextual_band !== 'high'
          const surfaced = mode === 'contextual' && (a.vendor_rank_position ?? 0) - (a.contextual_rank_position ?? 0) >= 10
          return (
            <tr key={a.id} className={cn('cursor-pointer', surfaced && 'bg-sev-critical/5', buried && 'opacity-70')} onClick={() => navigate(`/alerts/${encodeURIComponent(a.id)}?tab=graph`)}>
              <td className="text-right tabular-nums text-fg-3">{i + 1}</td>
              <td>
                <span className="flex items-center gap-1.5 min-w-0">
                  <LabelIcon label={a.entity_label ?? 'Endpoint'} size={12} />
                  <span className="truncate font-medium text-fg" title={a.entity_id ?? ''}>{a.entity_name ?? a.hostname ?? shortId(a.entity_id)}</span>
                </span>
              </td>
              <td>
                <span className="line-clamp-1 leading-snug text-fg" title={a.title}>{a.title}</span>
              </td>
              <td><SeverityChip severity={a.vendor_severity} /></td>
              <td>
                <span className="flex items-center gap-1.5">
                  <ScoreChip score={a.contextual_score} band={a.contextual_band} size="sm" />
                  <RankDelta alert={a} />
                </span>
              </td>
              <td><StorylineChip id={a.storyline_id} /></td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/** Contextual priority next to the vendor-severity queue, so the re-ranking is visible at a glance. */
export function Leaderboards({ contextual, vendor }: { contextual: AlertSummary[]; vendor: AlertSummary[] }) {
  const navigate = useNavigate()
  const contextualIds = new Set(contextual.map((a) => a.id))
  const overlap = vendor.filter((a) => contextualIds.has(a.id)).length
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel
        title={<span className="text-accent">Contextual priority</span>}
        flush
        actions={<button type="button" className="btn-ghost py-0.5" onClick={() => navigate('/alerts?sort=contextual')}>All alerts →</button>}
      >
        <Board alerts={contextual} mode="contextual" />
        <div className="border-t border-line px-3 py-1.5 text-[10.5px] text-fg-3">Ranked by contextual score: exposure, privilege reach, data sensitivity, threat intel and incident correlation. Arrows show the move versus the vendor queue.</div>
      </Panel>
      <Panel
        title="Vendor severity queue"
        flush
        actions={
          <span className="flex items-center gap-1 text-[10.5px] text-fg-3" title="How many of the vendor top 10 also appear in the contextual top 10">
            <ArrowLeftRight size={11} /> {overlap}/10 overlap
          </span>
        }
      >
        <Board alerts={vendor} mode="vendor" />
        <div className="border-t border-line px-3 py-1.5 text-[10.5px] text-fg-3">What the consoles show: sorted by vendor severity, then time. Dimmed rows fall below High once graph context is applied.</div>
      </Panel>
    </div>
  )
}
