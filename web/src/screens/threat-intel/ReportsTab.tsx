import { useNavigate } from 'react-router-dom'
import { useTiReports } from '../../api/hooks'
import { LabelIcon } from '../../components/LabelIcon'
import { Pill } from '../../components/chips'
import { EmptyState, ErrorState, SkeletonRows } from '../../components/states'
import { fmtTime, shortId } from '../../lib/format'

const CONF_TONE: Record<string, 'good' | 'warn' | 'neutral'> = { high: 'good', 'medium-high': 'warn', medium: 'warn', low: 'neutral' }

/** GET /threat-intel/reports, newest first. */
export function ReportsTab() {
  const q = useTiReports()
  const navigate = useNavigate()
  if (q.isLoading) return <SkeletonRows rows={6} cols={4} />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  const items = q.data?.items ?? []
  if (!items.length) return <EmptyState title="No intel reports" />
  return (
    <div className="panel h-full min-h-0 overflow-y-auto">
      <ul className="divide-y divide-line/70">
        {items.map((r) => {
          const conf = String(r.props.report_confidence ?? r.props.confidence ?? '')
          const actors = (r.props.actor_ids as string[] | undefined) ?? []
          const cves = (r.props.cve_ids as string[] | undefined) ?? []
          return (
            <li key={r.id}>
              <button type="button" className="flex w-full items-start gap-3 px-3 py-2.5 text-left hover:bg-panel-2" onClick={() => navigate(`/threat-intel/reports/${encodeURIComponent(r.id)}`)}>
                <LabelIcon label="IntelReport" size={16} className="mt-0.5" />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium leading-snug text-fg">{String(r.props.title ?? r.name)}</span>
                  {r.props.summary ? <span className="mt-0.5 line-clamp-2 block text-xs leading-snug text-fg-2">{String(r.props.summary)}</span> : null}
                  <span className="mt-1 flex flex-wrap items-center gap-1.5 text-[10.5px] text-fg-3">
                    <span className="mono">{shortId(r.id)}</span>
                    <span>·</span>
                    <span>{String(r.props.publisher ?? '')}</span>
                    <span>·</span>
                    <span className="mono">{fmtTime(String(r.props.published ?? ''))}</span>
                    {conf && <Pill tone={CONF_TONE[conf] ?? 'neutral'}>confidence {conf}</Pill>}
                    {r.props.tlp ? <Pill tone="neutral">TLP:{String(r.props.tlp)}</Pill> : null}
                    {actors.map((a) => (
                      <span key={a} className="chip border-cat-ti/40 bg-cat-ti/10 text-cat-ti">{shortId(a).replace(/-/g, ' ')}</span>
                    ))}
                    {cves.map((c) => (
                      <span key={c} className="mono chip border-sev-high/40 text-sev-high">{c}</span>
                    ))}
                    {typeof r.props.indicator_count === 'number' && <span>{r.props.indicator_count} indicators</span>}
                  </span>
                </span>
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
