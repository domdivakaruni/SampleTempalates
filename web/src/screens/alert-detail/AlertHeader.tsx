import { ArrowLeft, Bot, ExternalLink, Table2 } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { AlertContext } from '../../api/types'
import { LabelIcon } from '../../components/LabelIcon'
import { RankDelta, ReasonChips, ScoreChip, SeverityChip, SourceChip, StorylineChip, TIBadge } from '../../components/chips'
import { fmtTime, shortId } from '../../lib/format'
import { useDrawerStore } from '../../store/drawerStore'

export function AlertHeader({ ctx }: { ctx: AlertContext }) {
  const navigate = useNavigate()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const a = ctx.alert
  const ask = () =>
    askAbout(
      `Why is "${a.title}" (${a.id}) ranked #${a.contextual_rank_position ?? '?'} in context when the vendor says ${a.vendor_severity}? What can an attacker reach from ${a.entity_name ?? 'this asset'}?`,
      { alert_id: a.id },
    )
  return (
    <div className="border-b border-line px-4 pb-3 pt-3">
      <button type="button" className="btn-ghost -ml-2 mb-1 py-0" onClick={() => navigate('/alerts')}>
        <ArrowLeft size={12} /> Alerts
      </button>
      <div className="flex flex-wrap items-start gap-3">
        <ScoreChip score={a.contextual_score} band={a.contextual_band} size="lg" className="mt-0.5 h-10 min-w-[52px] text-xl" />
        <div className="min-w-0 flex-1">
          <h1 className="text-base font-semibold leading-snug text-fg" title={a.id}>
            {a.title}
          </h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-2">
            <button type="button" className="flex items-center gap-1 rounded px-1 hover:bg-panel-3" onClick={() => a.entity_id && navigate(`/explorer?id=${encodeURIComponent(a.entity_id)}`)} title={a.entity_id ?? ''}>
              <LabelIcon label={a.entity_label ?? 'Endpoint'} size={13} />
              <span className="font-medium text-fg">{a.entity_name ?? a.hostname ?? shortId(a.entity_id)}</span>
              {a.entity_label && <span className="text-fg-3">{a.entity_label}</span>}
            </button>
            <span className="text-fg-3">·</span>
            <SourceChip source={a.source_system} />
            <span className="text-fg-3">·</span>
            <span className="mono">{fmtTime(a.detected_at, { seconds: true })}</span>
            {a.user && (
              <>
                <span className="text-fg-3">·</span>
                <span>user {a.user}</span>
              </>
            )}
            <span className="text-fg-3">·</span>
            <span className="capitalize">{a.status.replace('_', ' ')}</span>
            {a.techniques.length > 0 && (
              <>
                <span className="text-fg-3">·</span>
                {a.techniques.map((t) => (
                  <span key={t} className="mono rounded bg-panel-3 px-1 text-[10.5px] text-fg-2">
                    {t}
                  </span>
                ))}
              </>
            )}
            <span className="mono text-[10.5px] text-fg-3">{a.id}</span>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs">
            <span className="flex items-center gap-1.5">
              <span className="text-fg-3">Vendor</span>
              <SeverityChip severity={a.vendor_severity} />
              {a.vendor_rank_position != null && <span className="tabular-nums text-fg-3">#{a.vendor_rank_position}</span>}
            </span>
            <span className="text-fg-3">→</span>
            <span className="flex items-center gap-1.5">
              <span className="text-fg-3">Contextual</span>
              <ScoreChip score={a.contextual_score} band={a.contextual_band} size="sm" />
              <span className="capitalize text-fg-2">{a.contextual_band}</span>
              {a.contextual_rank_position != null && <span className="tabular-nums text-fg-3">#{a.contextual_rank_position}</span>}
              <RankDelta alert={a} />
            </span>
            <StorylineChip id={a.storyline_id} title={ctx.storyline?.title} onClick={a.storyline_id ? () => navigate(`/storylines/${encodeURIComponent(a.storyline_id!)}`) : undefined} />
            <TIBadge alert={a} actorNames={Object.fromEntries((ctx.threat_intel?.actors ?? []).map((x) => [x.id, x.name]))} />
            <ReasonChips reasons={a.graph_reasons} max={6} />
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-stretch gap-1.5">
          <button type="button" className="btn-primary" onClick={ask} data-testid="ask-about-alert">
            <Bot size={13} /> Ask analyst about this alert
          </button>
          <button type="button" className="btn" onClick={() => navigate(`/explorer?id=${encodeURIComponent(a.id)}`)}>
            <ExternalLink size={13} /> Open in explorer
          </button>
          <span className="flex items-center justify-center gap-1 text-[10.5px] text-fg-3" title="Raw vendor fields are on the Flat view tab">
            <Table2 size={10} /> flat view available
          </span>
        </div>
      </div>
    </div>
  )
}
