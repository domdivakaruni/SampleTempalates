import { Eye } from 'lucide-react'
import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import type { AlertContext, AttackPathOut, StageOut } from '../../api/types'
import { AlertsTable } from '../../components/AlertsTable'
import { AttackPathList } from '../../components/AttackPathList'
import { BlastRadiusSummary } from '../../components/BlastRadiusSummary'
import { InsightList } from '../../components/InsightList'
import { Panel } from '../../components/Page'
import { RiskBreakdownBars } from '../../components/RiskBreakdownBars'
import { StageStrip } from '../../components/StageStrip'
import { StorylineTimeline } from '../../components/StorylineTimeline'
import { TIContextPanel } from '../../components/TIContextPanel'
import { ScoreChip, StorylineChip } from '../../components/chips'
import type { CanvasOps } from '../../graph/useCanvasOps'
import { fmtShortTime } from '../../lib/format'

export interface ActiveHighlight { pathId?: string | null; stage?: number | null }

interface Props {
  ctx: AlertContext
  ops: CanvasOps
  active: ActiveHighlight
  onActive: (a: ActiveHighlight) => void
}

/** Right-hand column of the Graph context tab; every panel can highlight its evidence on the canvas. */
export function ContextPanels({ ctx, ops, active, onActive }: Props) {
  const navigate = useNavigate()
  const alertsById = useMemo(() => Object.fromEntries([ctx.alert, ...ctx.related_alerts].map((a) => [a.id, a])), [ctx])
  const story = ctx.storyline
  const showStage = (s: StageOut, pathId?: string | null) => {
    onActive({ pathId: pathId ?? null, stage: s.order })
    void ops.highlight([...s.node_ids, ...s.edge_ids, ...s.alert_ids])
  }
  const showPath = (p: AttackPathOut) => {
    onActive({ pathId: p.id, stage: null })
    ops.merge(p.fragment)
    const p0 = p.fragment.paths[0]
    if (p0) ops.showPath(p0)
    else void ops.highlight(p.fragment.nodes.map((n) => n.id))
  }
  return (
    <>
      <Panel title="Contextual score breakdown">
        <RiskBreakdownBars risk={ctx.risk} onEvidence={(ids) => void ops.highlight(ids)} />
      </Panel>
      {ctx.attack_paths.length > 0 && (
        <Panel title={`Attack paths (${ctx.attack_paths.length})`}>
          <AttackPathList paths={ctx.attack_paths} activeId={active.pathId} activeStage={active.stage} onSelectPath={showPath} onSelectStage={(p, s) => showStage(s, p.id)} onAddToCanvas={(p) => ops.merge(p.fragment, { highlight: true })} compact />
        </Panel>
      )}
      {story && (
        <Panel
          title="Storyline"
          actions={
            <button type="button" className="btn-ghost py-0.5" onClick={() => navigate(`/storylines/${encodeURIComponent(story.id)}`)}>
              Open storyline →
            </button>
          }
        >
          <div className="mb-2 flex flex-wrap items-center gap-1.5 text-xs">
            <ScoreChip score={story.contextual_score} size="sm" />
            <StorylineChip id={story.id} title={story.title} onClick={() => navigate(`/storylines/${encodeURIComponent(story.id)}`)} />
            <span className="font-medium text-fg">{story.title}</span>
            {story.actor_name && <span className="chip border-cat-ti/40 bg-cat-ti/10 text-cat-ti">{story.actor_name}</span>}
            <span className="mono text-[10.5px] text-fg-3">
              {fmtShortTime(story.first_event)} → {fmtShortTime(story.last_event)}
            </span>
          </div>
          {story.stages.length > 0 && <StageStrip stages={story.stages} compact activeOrder={active.stage} onSelect={(s) => showStage(s)} className="mb-2" />}
          <StorylineTimeline stages={story.stages} alerts={alertsById} activeOrder={active.stage} onSelectStage={(s) => showStage(s)} currentAlertId={ctx.alert.id} />
        </Panel>
      )}
      <Panel title={`Insights (${ctx.insights.length})`}>
        <InsightList insights={ctx.insights} onHighlight={(ins) => void ops.highlight([...ins.evidence_node_ids, ...ins.evidence_edge_ids])} />
      </Panel>
      {ctx.blast_radius && (
        <Panel
          title="Blast radius"
          actions={
            <button type="button" className="btn-ghost py-0.5" onClick={() => ops.merge(ctx.blast_radius!.fragment, { highlight: true })} title="Merge the full blast-radius fragment into the canvas">
              <Eye size={11} /> Show all
            </button>
          }
        >
          <BlastRadiusSummary br={ctx.blast_radius} onHighlight={(ids) => void ops.highlight(ids)} />
        </Panel>
      )}
      <Panel title="Threat intelligence">
        {ctx.threat_intel ? <TIContextPanel ti={ctx.threat_intel} onEvidence={(ids) => void ops.highlight(ids)} /> : <div className="text-xs text-fg-3">No IOC, actor or exploited-CVE match for this alert.</div>}
      </Panel>
      <Panel title={`Related alerts (${ctx.related_alerts.length})`} flush>
        {ctx.related_alerts.length ? (
          <AlertsTable alerts={ctx.related_alerts} columns={['title', 'vendor', 'contextual', 'time']} emptyTitle="No related alerts" className="max-h-[320px]" />
        ) : (
          <div className="p-3 text-xs text-fg-3">No other alert shares this storyline or asset.</div>
        )}
      </Panel>
    </>
  )
}
