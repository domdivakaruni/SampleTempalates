import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useAlerts, useNodesBatch, useStoryline } from '../api/hooks'
import type { ContainmentSimulation, StageOut } from '../api/types'
import { AlertsTable } from '../components/AlertsTable'
import { CanvasDetailsOverlay } from '../components/CanvasDetailsOverlay'
import { NodeRef } from '../components/NodeRef'
import { Page, Panel } from '../components/Page'
import { StageStrip } from '../components/StageStrip'
import { StorylineTimeline } from '../components/StorylineTimeline'
import { ErrorState, SkeletonBlock } from '../components/states'
import { CanvasLegend } from '../graph/CanvasLegend'
import { GraphCanvas, type GraphCanvasHandle } from '../graph/GraphCanvas'
import { useCanvasHost } from '../graph/useCanvasHost'
import { useCanvasOps } from '../graph/useCanvasOps'
import { useNodeActions } from '../graph/useNodeActions'
import { useSelectionStore } from '../store/selectionStore'
import { ContainmentSection } from './storylines/ContainmentSection'
import { StorylineHeader } from './storylines/StorylineHeader'

/** /storylines/:id — dagre canvas of the stages, timeline, member alerts, crown jewels and the containment simulator. */
export function StorylineDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const sid = decodeURIComponent(id)
  const q = useStoryline(sid)
  const alertsQ = useAlerts({ storyline: sid, limit: 200, sort: 'time', order: 'asc' })
  const ref = useRef<GraphCanvasHandle>(null)
  useCanvasHost('storyline-detail', ref)
  const ops = useCanvasOps(ref)
  const contextActions = useNodeActions(ref)
  const select = useSelectionStore((s) => s.select)
  const [selected, setSelected] = useState<string | null>(null)
  const [activeStage, setActiveStage] = useState<number | null>(null)
  useEffect(() => () => select(null), [select])
  const alerts = useMemo(() => alertsQ.data?.items ?? [], [alertsQ.data])
  const jewels = useNodesBatch(q.data?.crown_jewels_reached ?? [])
  const alertsById = useMemo(() => Object.fromEntries(alerts.map((a) => [a.id, a])), [alerts])
  const pick = (nid: string | null) => {
    setSelected(nid)
    select(nid)
  }
  const showStage = (s: StageOut) => {
    setActiveStage(s.order)
    void ops.highlight([...s.node_ids, ...s.edge_ids, ...s.alert_ids])
  }
  const showSimulation = (sim: ContainmentSimulation) => {
    const h = ref.current
    if (!h) return
    h.mergeFragment(sim.fragment)
    const cut = sim.fragment.meta.cut_edge_ids
    if (Array.isArray(cut)) h.markCut(cut.filter((x): x is string => typeof x === 'string'))
    h.highlight([...sim.target_ids, ...sim.crown_jewels_protected], { dim: true, fit: true })
  }
  if (q.isLoading) return <SkeletonBlock lines={10} className="p-4" />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  if (!q.data) return null
  const story = q.data
  return (
    <Page className="flex flex-col" scroll>
      <StorylineHeader story={story} />
      <div className="grid gap-3 p-4 xl:grid-cols-[minmax(0,1fr)_400px]">
        <div className="min-w-0 space-y-3">
          <Panel title="Kill chain" flush bodyClassName="relative h-[400px]">
            <GraphCanvas ref={ref} fragment={story.fragment ?? null} onSelectNode={(n) => pick(n?.id ?? null)} onDoubleClickNode={(n) => void ops.expand(n.id)} contextActions={contextActions} emptyHint="This storyline has no graph fragment">
              <CanvasLegend fragment={story.fragment} />
              <CanvasDetailsOverlay nodeId={selected} onClose={() => pick(null)} onExpand={(nid) => void ops.expand(nid)} onBlastRadius={(nid) => void ops.blast(nid)} />
            </GraphCanvas>
          </Panel>
          <Panel title="Stages (click to highlight)">
            <StageStrip stages={story.stages} activeOrder={activeStage} onSelect={showStage} />
          </Panel>
          <Panel title={`Member alerts (${alerts.length || story.alert_ids.length})`} flush>
            {alertsQ.isLoading && <SkeletonBlock lines={4} className="p-3" />}
            {alertsQ.data && <AlertsTable alerts={alerts} columns={['time', 'asset', 'title', 'source', 'vendor', 'contextual', 'why']} emptyTitle="No member alerts returned" />}
          </Panel>
          <ContainmentSection story={story} alerts={alerts} onShowOnCanvas={showSimulation} />
        </div>
        <div className="min-w-0 space-y-3">
          <Panel title="Timeline">
            <StorylineTimeline stages={story.stages} alerts={alertsById} activeOrder={activeStage} onSelectStage={showStage} />
          </Panel>
          <Panel title={`Crown jewels reached (${story.crown_jewels_reached.length})`}>
            {story.crown_jewels_reached.length === 0 && <div className="text-xs text-fg-3">No crown jewel in reach.</div>}
            <ul className="space-y-1 text-xs">
              {story.crown_jewels_reached.map((j) => (
                <li key={j} className="flex items-center justify-between gap-2 rounded border border-sev-critical/30 bg-sev-critical/5 px-2 py-1">
                  <NodeRef id={j} node={jewels.data?.nodes.find((n) => n.id === j)} />
                  <button type="button" className="btn-ghost py-0" onClick={() => void ops.highlight([j])}>
                    highlight
                  </button>
                </li>
              ))}
            </ul>
          </Panel>
          {(story.actor_id || story.campaign_id) && (
            <Panel title="Attribution">
              <div className="space-y-1 text-xs">
                {story.actor_id && (
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-fg-2">Actor</span>
                    <NodeRef id={story.actor_id} name={story.actor_name ?? undefined} label="ThreatActor" mode="select" onSelect={(nid) => navigate(`/threat-intel/actors/${encodeURIComponent(nid)}`)} />
                  </div>
                )}
                {story.campaign_id && (
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-fg-2">Campaign</span>
                    <NodeRef id={story.campaign_id} name={story.campaign_name ?? undefined} label="Campaign" mode="select" onSelect={(nid) => navigate(`/threat-intel/campaigns/${encodeURIComponent(nid)}`)} />
                  </div>
                )}
                <div className="text-[10.5px] text-fg-3">Attribution comes from IOC matches (hashes, C2 domain, egress IP) and TTP overlap with the intel report; open the actor for the full context.</div>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </Page>
  )
}
