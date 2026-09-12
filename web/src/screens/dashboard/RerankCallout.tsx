import { ArrowDownRight, ArrowUpRight, Sparkles } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { RerankExample } from '../../api/types'
import { SeverityChip, ScoreChip } from '../../components/chips'
import { bandForScore } from '../../api/types'

/** "The #1 alert was a vendor Medium": the alerts the graph moved the most, up and down. */
export function RerankCallout({ examples }: { examples: RerankExample[] }) {
  const navigate = useNavigate()
  if (!examples.length) return null
  const up = examples.filter((e) => e.vendor_rank_position > e.contextual_rank_position).sort((a, b) => a.contextual_rank_position - b.contextual_rank_position)
  const down = examples.filter((e) => e.vendor_rank_position < e.contextual_rank_position).sort((a, b) => a.vendor_rank_position - b.vendor_rank_position)
  const top = up.find((e) => e.contextual_rank_position === 1) ?? up[0] ?? examples[0]
  const open = (id: string) => navigate(`/alerts/${encodeURIComponent(id)}?tab=graph`)
  return (
    <div className="panel flex flex-wrap items-center gap-x-4 gap-y-2 border-accent/30 bg-accent/5 px-3 py-2">
      <div className="flex min-w-0 flex-1 items-center gap-2 text-xs">
        <Sparkles size={14} className="shrink-0 text-accent" />
        <span className="min-w-0 text-fg-2">
          <span className="font-semibold text-fg">The #{top.contextual_rank_position} alert began life as a vendor {top.vendor_severity}.</span>{' '}
          <button type="button" className="text-fg underline decoration-fg-3 underline-offset-2 hover:text-accent" onClick={() => open(top.alert_id)} title={top.title}>
            “{top.title.length > 70 ? `${top.title.slice(0, 69)}…` : top.title}”
          </button>{' '}
          sat at <span className="tabular-nums text-fg">#{top.vendor_rank_position}</span> in the vendor-severity queue; with graph context it scores{' '}
          <span className="font-semibold text-fg">{top.contextual_score}</span>.
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {up.slice(0, 3).map((e) => (
          <button key={e.alert_id} type="button" className="chip border-sev-critical/40 bg-sev-critical/10 text-fg hover:bg-sev-critical/20" onClick={() => open(e.alert_id)} title={`${e.title}\nvendor #${e.vendor_rank_position} -> contextual #${e.contextual_rank_position}`}>
            <ArrowUpRight size={11} className="text-sev-critical" />
            <SeverityChip severity={e.vendor_severity} className="border-0 bg-transparent px-0" /> → <ScoreChip score={e.contextual_score} band={bandForScore(e.contextual_score)} size="sm" />
            <span className="tabular-nums text-fg-3">#{e.vendor_rank_position}→#{e.contextual_rank_position}</span>
          </button>
        ))}
        {down.slice(0, 2).map((e) => (
          <button key={e.alert_id} type="button" className="chip border-line-2 bg-panel-2 text-fg hover:bg-panel-3" onClick={() => open(e.alert_id)} title={`${e.title}\nvendor #${e.vendor_rank_position} -> contextual #${e.contextual_rank_position}`}>
            <ArrowDownRight size={11} className="text-sev-low" />
            <SeverityChip severity={e.vendor_severity} className="border-0 bg-transparent px-0" /> → <ScoreChip score={e.contextual_score} band={bandForScore(e.contextual_score)} size="sm" />
            <span className="tabular-nums text-fg-3">#{e.vendor_rank_position}→#{e.contextual_rank_position}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
