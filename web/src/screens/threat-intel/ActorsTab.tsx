import { useNavigate } from 'react-router-dom'
import { useTiActors } from '../../api/hooks'
import type { ActorListItem } from '../../api/types'
import { DataTable, type Column } from '../../components/DataTable'
import { LabelIcon } from '../../components/LabelIcon'
import { Pill } from '../../components/chips'
import { ErrorState, SkeletonRows } from '../../components/states'
import { fmtPct } from '../../lib/format'

export function RelevanceBar({ value }: { value: number }) {
  return (
    <span className="flex items-center gap-1.5" title={`Sector targeting relevance for Larkspur: ${value.toFixed(2)}`}>
      <span className="h-1.5 w-16 overflow-hidden rounded bg-panel-3">
        <span className="block h-full rounded" style={{ width: `${Math.round(value * 100)}%`, background: value >= 0.7 ? 'var(--color-cat-ti)' : 'var(--color-fg-3)' }} />
      </span>
      <span className="w-8 tabular-nums text-fg-2">{fmtPct(value)}</span>
    </span>
  )
}

const COLUMNS: Column<ActorListItem>[] = [
  {
    key: 'actor', header: 'Actor', width: '220px',
    render: (r) => (
      <span className="flex items-center gap-2">
        <LabelIcon label="ThreatActor" size={14} />
        <span className="min-w-0">
          <span className="block truncate font-medium text-fg">{r.actor.name}</span>
          <span className="block truncate text-[10.5px] text-fg-3">{((r.actor.props.aliases as string[] | undefined) ?? []).join(', ') || r.actor.id}</span>
        </span>
      </span>
    ),
    sortValue: (r) => r.actor.name,
  },
  { key: 'motivation', header: 'Motivation', width: '110px', render: (r) => <span className="capitalize text-fg-2">{String(r.actor.props.motivation ?? '—')}</span>, sortValue: (r) => String(r.actor.props.motivation ?? '') },
  { key: 'relevance', header: 'Sector relevance', width: '150px', render: (r) => <RelevanceBar value={r.sector_relevance} />, sortValue: (r) => r.sector_relevance },
  { key: 'active', header: 'Status', width: '80px', render: (r) => (r.active ? <Pill tone="bad">active</Pill> : <Pill tone="neutral">dormant</Pill>), sortValue: (r) => (r.active ? 1 : 0) },
  {
    key: 'campaigns', header: 'Campaigns',
    render: (r) => (
      <span className="flex flex-wrap gap-1">
        {r.campaigns.map((c) => (
          <span key={c.id} className="chip border-line-2 text-fg-2" title={String(c.props.objective ?? c.id)}>
            {c.name}
            <span className="text-fg-3">{String(c.props.status ?? '')}</span>
          </span>
        ))}
        {r.campaigns.length === 0 && <span className="text-fg-3">—</span>}
      </span>
    ),
    sortValue: (r) => r.campaigns.length,
  },
  { key: 'ioc', header: 'IOC matches', width: '100px', align: 'right', render: (r) => <span className={`tabular-nums ${r.ioc_matches ? 'font-semibold text-cat-ti' : 'text-fg-3'}`}>{r.ioc_matches}</span>, sortValue: (r) => r.ioc_matches },
  { key: 'alerts', header: 'Matched alerts', width: '110px', align: 'right', render: (r) => <span className={`tabular-nums ${r.matched_alerts ? 'font-semibold text-fg' : 'text-fg-3'}`}>{r.matched_alerts}</span>, sortValue: (r) => r.matched_alerts },
  { key: 'cves', header: 'Exploited CVEs present', width: '150px', align: 'right', render: (r) => <span className={`tabular-nums ${r.exploited_cves_present ? 'font-semibold text-sev-high' : 'text-fg-3'}`}>{r.exploited_cves_present}</span>, sortValue: (r) => r.exploited_cves_present },
  { key: 'assets', header: 'Affected assets', width: '120px', align: 'right', render: (r) => <span className="tabular-nums text-fg-2">{r.affected_assets}</span>, sortValue: (r) => r.affected_assets },
]

/** GET /threat-intel/actors: actors sorted by sector relevance then matches in the estate. */
export function ActorsTab() {
  const q = useTiActors()
  const navigate = useNavigate()
  if (q.isLoading) return <SkeletonRows rows={8} cols={7} />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return (
    <div className="panel flex h-full min-h-0 flex-col overflow-hidden">
      <DataTable columns={COLUMNS} rows={q.data?.items ?? []} rowKey={(r) => r.actor.id} onRowClick={(r) => navigate(`/threat-intel/actors/${encodeURIComponent(r.actor.id)}`)} className="min-h-0 flex-1" emptyTitle="No threat actors in the intel library" />
      <div className="border-t border-line px-3 py-1.5 text-[10.5px] text-fg-3">Sector relevance is the actor's targeting overlap with a fintech payment processor; actors ≥ 0.7 drive the TI booster rail in the contextual score. Click an actor to see the assets in your estate that match it.</div>
    </div>
  )
}
