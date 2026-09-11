import { ArrowLeft, Bot } from 'lucide-react'
import { useNavigate, useParams } from 'react-router-dom'
import { useTiReport } from '../../api/hooks'
import { AlertsTable } from '../../components/AlertsTable'
import { LabelIcon } from '../../components/LabelIcon'
import { NodeRef } from '../../components/NodeRef'
import { Page, Panel } from '../../components/Page'
import { Pill } from '../../components/chips'
import { ErrorState, SkeletonBlock } from '../../components/states'
import { fmtTime, shortId } from '../../lib/format'
import { useDrawerStore } from '../../store/drawerStore'
import { IndicatorsTable, TechniqueChips } from './IndicatorsTable'

/** /threat-intel/reports/:id — the report text and its measured impact on our estate. */
export function ReportDetail() {
  const { id = '' } = useParams()
  const rid = decodeURIComponent(id)
  const q = useTiReport(rid)
  const navigate = useNavigate()
  const askAbout = useDrawerStore((s) => s.askAbout)
  if (q.isLoading) return <SkeletonBlock lines={10} className="p-4" />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  if (!q.data) return null
  const { report, impact } = q.data
  const p = report.props
  const paragraphs = String(p.body ?? '').split(/\n\s*\n/).filter(Boolean)
  const actorName = q.data.actors[0]?.name ?? shortId(String(((p.actor_ids as string[] | undefined) ?? [])[0] ?? ''))
  return (
    <Page className="flex flex-col">
      <div className="border-b border-line px-4 pb-3 pt-3">
        <button type="button" className="btn-ghost -ml-2 mb-1 py-0" onClick={() => navigate('/threat-intel?tab=reports')}>
          <ArrowLeft size={12} /> Reports
        </button>
        <div className="flex flex-wrap items-start gap-3">
          <LabelIcon label="IntelReport" size={22} className="mt-1" />
          <div className="min-w-0 flex-1">
            <h1 className="text-base font-semibold leading-snug text-fg">{String(p.title ?? report.name)}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-2">
              <span className="mono">{shortId(report.id)}</span>
              <span>·</span>
              <span>{String(p.publisher ?? '')}</span>
              <span>·</span>
              <span className="mono">{fmtTime(String(p.published ?? ''))}</span>
              {p.report_confidence || p.confidence ? <Pill tone="neutral">confidence {String(p.report_confidence ?? p.confidence)}</Pill> : null}
              {p.tlp ? <Pill tone="neutral">TLP:{String(p.tlp)}</Pill> : null}
              {Array.isArray(p.targeted_sectors) && <span>sectors {(p.targeted_sectors as string[]).join(', ')}</span>}
            </div>
          </div>
          <button type="button" className="btn-primary shrink-0" onClick={() => askAbout(`Do any current detections match IOCs or TTPs from the ${actorName || 'this'} report (${shortId(report.id)}), and what do they touch?`)}>
            <Bot size={13} /> Ask: does this report match our telemetry?
          </button>
        </div>
      </div>
      <div className="grid gap-3 p-4 xl:grid-cols-[minmax(0,1fr)_440px]">
        <div className="min-w-0 space-y-3">
          <Panel title="Summary">
            <p className="text-xs leading-relaxed text-fg">{String(p.summary ?? '')}</p>
          </Panel>
          <Panel title="Report">
            <div className="max-w-3xl space-y-2 text-xs leading-relaxed text-fg-2">
              {paragraphs.map((para, i) => (
                <p key={i}>{para}</p>
              ))}
              {paragraphs.length === 0 && <p className="text-fg-3">No body text.</p>}
            </div>
          </Panel>
          <Panel title={`Indicators (${q.data.indicators.length})`}>
            <IndicatorsTable indicators={q.data.indicators} matches={q.data.matches ?? []} />
          </Panel>
          <Panel title={`Techniques (${q.data.techniques.length})`}>
            <TechniqueChips techniques={q.data.techniques} seen={new Set(impact.ttp_overlap ?? [])} />
          </Panel>
        </div>
        <div className="min-w-0 space-y-3">
          <Panel title="Impact on us">
            <p className="text-xs leading-snug text-fg">{impact.summary}</p>
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-md border border-line bg-panel-2/60 px-2 py-1.5">
                <div className="text-[10.5px] uppercase tracking-wider text-fg-3">Matched alerts</div>
                <div className={`text-lg font-semibold tabular-nums ${impact.matched_alerts.length ? 'text-sev-critical' : 'text-fg-3'}`}>{impact.matched_alerts.length}</div>
              </div>
              <div className="rounded-md border border-line bg-panel-2/60 px-2 py-1.5">
                <div className="text-[10.5px] uppercase tracking-wider text-fg-3">Exposed vulnerable assets</div>
                <div className={`text-lg font-semibold tabular-nums ${impact.exposed_assets.length ? 'text-sev-high' : 'text-fg-3'}`}>{impact.exposed_assets.length}</div>
              </div>
            </div>
            {impact.exposed_assets.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {impact.exposed_assets.map((a) => (
                  <NodeRef key={a.id} node={a} mode="explorer" />
                ))}
              </div>
            )}
            {impact.crown_jewels_touched && impact.crown_jewels_touched.length > 0 && (
              <div className="mt-2 flex flex-wrap items-center gap-1 text-xs">
                <span className="text-sev-critical">Crown jewels touched:</span>
                {impact.crown_jewels_touched.map((j) => (
                  <NodeRef key={j} id={j} mode="explorer" />
                ))}
              </div>
            )}
          </Panel>
          <Panel title="Matched alerts" flush>
            <AlertsTable alerts={impact.matched_alerts} columns={['asset', 'title', 'vendor', 'contextual', 'time']} emptyTitle="No alert matches this report" />
          </Panel>
          <Panel title="Related">
            <div className="flex flex-wrap gap-1.5 text-xs">
              {q.data.actors.map((a) => (
                <button key={a.id} type="button" className="chip border-cat-ti/40 bg-cat-ti/10 text-cat-ti hover:bg-cat-ti/20" onClick={() => navigate(`/threat-intel/actors/${encodeURIComponent(a.id)}`)}>
                  <LabelIcon label="ThreatActor" size={11} color="currentColor" /> {a.name}
                </button>
              ))}
              {q.data.campaigns.map((c) => (
                <button key={c.id} type="button" className="chip border-line-2 text-fg-2 hover:bg-panel-3" onClick={() => navigate(`/threat-intel/campaigns/${encodeURIComponent(c.id)}`)}>
                  <LabelIcon label="Campaign" size={11} /> {c.name}
                </button>
              ))}
              {q.data.malware.map((m) => (
                <span key={m.id} className="chip border-line-2 text-fg-2">
                  <LabelIcon label="Malware" size={11} /> {m.name}
                </span>
              ))}
              {q.data.cves.map((c) => (
                <NodeRef key={c.id} node={c} mode="explorer" mono />
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </Page>
  )
}
