import { ArrowLeft, Bot } from 'lucide-react'
import { useEffect, useMemo, useRef } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useAlerts, useTiActor, useTiCampaign } from '../../api/hooks'
import type { ActorDetailOut } from '../../api/types'
import { AlertsTable } from '../../components/AlertsTable'
import { LabelIcon } from '../../components/LabelIcon'
import { Page, Panel } from '../../components/Page'
import { TIContextPanel } from '../../components/TIContextPanel'
import { Pill } from '../../components/chips'
import { ErrorState, SkeletonBlock } from '../../components/states'
import { CanvasLegend } from '../../graph/CanvasLegend'
import { GraphCanvas, type GraphCanvasHandle } from '../../graph/GraphCanvas'
import { useCanvasHost } from '../../graph/useCanvasHost'
import { useNodeActions } from '../../graph/useNodeActions'
import { fmtPct, fmtTime } from '../../lib/format'
import { useDrawerStore } from '../../store/drawerStore'
import { useSelectionStore } from '../../store/selectionStore'
import { RelevanceBar } from './ActorsTab'
import { IndicatorsTable, TechniqueChips } from './IndicatorsTable'

function Body({ data, kind, subjectId }: { data: ActorDetailOut; kind: 'actor' | 'campaign'; subjectId: string }) {
  const navigate = useNavigate()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const select = useSelectionStore((s) => s.select)
  const ref = useRef<GraphCanvasHandle>(null)
  useCanvasHost('ti-actor', ref)
  const contextActions = useNodeActions(ref)
  useEffect(() => () => select(null), [select])
  const subject = kind === 'campaign' ? (data.campaign ?? data.campaigns.find((c) => c.id === subjectId) ?? data.actor) : data.actor
  const actorId = data.actor?.id
  const alertsQ = useAlerts({ limit: 500, sort: 'contextual' })
  const matched = useMemo(() => {
    const all = alertsQ.data?.items ?? []
    if (data.matched_alert_ids?.length) {
      const ids = new Set(data.matched_alert_ids)
      return all.filter((a) => ids.has(a.id))
    }
    const fragAlerts = new Set(data.affected.nodes.filter((n) => n.label === 'Alert').map((n) => n.id))
    return all.filter((a) => (actorId && a.ti_actor_ids.includes(actorId)) || fragAlerts.has(a.id))
  }, [alertsQ.data, data, actorId])
  const seenTechniques = useMemo(() => new Set(matched.flatMap((a) => a.techniques)), [matched])
  const p = subject?.props ?? {}
  const name = subject?.name ?? subjectId
  return (
    <Page className="flex flex-col">
      <div className="border-b border-line px-4 pb-3 pt-3">
        <button type="button" className="btn-ghost -ml-2 mb-1 py-0" onClick={() => navigate('/threat-intel')}>
          <ArrowLeft size={12} /> Threat intel
        </button>
        <div className="flex flex-wrap items-start gap-3">
          <div className="rounded-md border border-cat-ti/40 bg-cat-ti/10 p-2">
            <LabelIcon label={kind === 'campaign' ? 'Campaign' : 'ThreatActor'} size={22} />
          </div>
          <div className="min-w-0 flex-1">
            <h1 className="text-base font-semibold text-fg">{name}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-2">
              {Array.isArray(p.aliases) && p.aliases.length > 0 && <span>aka {(p.aliases as string[]).join(', ')}</span>}
              {p.motivation ? <Pill tone="neutral">{String(p.motivation)}</Pill> : null}
              {p.status ? <Pill tone={p.status === 'active' ? 'bad' : 'neutral'}>{String(p.status)}</Pill> : null}
              {p.active === true && <Pill tone="bad">active</Pill>}
              {p.origin ? <span>origin {String(p.origin)}</span> : null}
              {p.sophistication ? <span>sophistication {String(p.sophistication)}</span> : null}
              {Array.isArray(p.targeted_sectors) && <span>targets {(p.targeted_sectors as string[]).join(', ')}</span>}
              {p.started ? <span className="mono">since {fmtTime(String(p.started))}</span> : null}
              <RelevanceBar value={Number(p.sector_targeting_relevance ?? data.context.sector_relevance ?? 0)} />
              <span className="mono text-[10.5px] text-fg-3">{subjectId}</span>
            </div>
            {p.description ? <p className="mt-1.5 max-w-4xl text-xs leading-snug text-fg-2">{String(p.description)}</p> : null}
            {p.objective ? <p className="mt-1 text-xs text-fg-2">Objective: {String(p.objective)}</p> : null}
            {kind === 'campaign' && data.actor && (
              <div className="mt-1 text-xs text-fg-2">
                Attributed to <button type="button" className="text-cat-ti hover:underline" onClick={() => navigate(`/threat-intel/actors/${encodeURIComponent(data.actor!.id)}`)}>{data.actor.name}</button>
              </div>
            )}
          </div>
          <button type="button" className="btn-primary shrink-0" onClick={() => askAbout(`Do any current detections match IOCs or TTPs from the ${name} report, and what do they touch?`)}>
            <Bot size={13} /> Ask: what does {name} touch in our estate?
          </button>
        </div>
      </div>
      <div className="grid gap-3 p-4 xl:grid-cols-[minmax(0,1fr)_440px]">
        <div className="min-w-0 space-y-3">
          <Panel title={`Affected assets in our estate (${data.affected.nodes.length} nodes)`} flush bodyClassName="relative h-[360px]">
            <GraphCanvas ref={ref} fragment={data.affected} contextActions={contextActions} onSelectNode={(n) => select(n?.id ?? null)} emptyHint="Nothing in the estate matches this actor">
              <CanvasLegend fragment={data.affected} />
            </GraphCanvas>
          </Panel>
          <Panel title={`Matched alerts (${matched.length})`} flush>
            {alertsQ.isLoading && <SkeletonBlock lines={3} className="p-3" />}
            {alertsQ.data && <AlertsTable alerts={matched} columns={['asset', 'title', 'vendor', 'contextual', 'storyline', 'time']} emptyTitle="No alert is attributed to this actor" />}
          </Panel>
          <Panel title={`Indicators (${data.indicators.length})`}>
            <IndicatorsTable indicators={data.indicators} matches={data.context.matches} />
          </Panel>
        </div>
        <div className="min-w-0 space-y-3">
          <Panel title="Estate context">
            <TIContextPanel ti={data.context} />
          </Panel>
          {kind === 'actor' && (
            <Panel title={`Campaigns (${data.campaigns.length})`}>
              <div className="space-y-1 text-xs">
                {data.campaigns.map((c) => (
                  <button key={c.id} type="button" className="flex w-full items-center gap-2 rounded-md border border-line bg-panel-2/50 px-2 py-1.5 text-left hover:border-line-2" onClick={() => navigate(`/threat-intel/campaigns/${encodeURIComponent(c.id)}`)}>
                    <LabelIcon label="Campaign" size={13} />
                    <span className="min-w-0 flex-1">
                      <span className="block font-medium text-fg">{c.name}</span>
                      <span className="block truncate text-[10.5px] text-fg-3">{String(c.props.objective ?? '')}</span>
                    </span>
                    <Pill tone={c.props.status === 'active' ? 'bad' : 'neutral'}>{String(c.props.status ?? '')}</Pill>
                    <span className="tabular-nums text-fg-3">{fmtPct(Number(c.props.sector_targeting_relevance ?? 0))}</span>
                  </button>
                ))}
                {data.campaigns.length === 0 && <div className="text-fg-3">No campaign recorded.</div>}
              </div>
            </Panel>
          )}
          <Panel title={`Malware (${data.malware.length})`}>
            <div className="flex flex-wrap gap-1.5 text-xs">
              {data.malware.map((m) => (
                <span key={m.id} className="chip border-line-2 text-fg-2" title={String(m.props.description ?? '')}>
                  <LabelIcon label="Malware" size={11} /> {m.name} <span className="text-fg-3">{String(m.props.malware_type ?? '')}</span>
                </span>
              ))}
              {data.malware.length === 0 && <span className="text-fg-3">None recorded.</span>}
            </div>
          </Panel>
          <Panel title={`Techniques (${data.techniques.length})`}>
            <TechniqueChips techniques={data.techniques} seen={seenTechniques} />
            {seenTechniques.size > 0 && <div className="mt-2 text-[10.5px] text-fg-3">Highlighted technique ids were observed in the matched alerts (TTP overlap).</div>}
          </Panel>
          <Panel title={`Reports (${data.reports.length})`}>
            <ul className="space-y-1 text-xs">
              {data.reports.map((r) => (
                <li key={r.id}>
                  <button type="button" className="flex w-full items-start gap-2 rounded px-1 py-1 text-left hover:bg-panel-3" onClick={() => navigate(`/threat-intel/reports/${encodeURIComponent(r.id)}`)}>
                    <LabelIcon label="IntelReport" size={13} className="mt-0.5" />
                    <span className="min-w-0">
                      <span className="block leading-snug text-fg">{String(r.props.title ?? r.name)}</span>
                      <span className="mono block text-[10.5px] text-fg-3">{fmtTime(String(r.props.published ?? ''))} · {String(r.props.publisher ?? '')}</span>
                    </span>
                  </button>
                </li>
              ))}
              {data.reports.length === 0 && <li className="text-fg-3">No report.</li>}
            </ul>
          </Panel>
        </div>
      </div>
    </Page>
  )
}

/** /threat-intel/actors/:id and /threat-intel/campaigns/:id share the ActorDetailOut shape. */
export function ActorDetail({ kind }: { kind: 'actor' | 'campaign' }) {
  const { id = '' } = useParams()
  const subjectId = decodeURIComponent(id)
  const actorQ = useTiActor(kind === 'actor' ? subjectId : undefined)
  const campaignQ = useTiCampaign(kind === 'campaign' ? subjectId : undefined)
  const q = kind === 'actor' ? actorQ : campaignQ
  if (q.isLoading) return <SkeletonBlock lines={10} className="p-4" />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  if (!q.data) return null
  return <Body key={subjectId} data={q.data} kind={kind} subjectId={subjectId} />
}
