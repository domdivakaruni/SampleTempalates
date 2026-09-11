import { Bot } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTiExposure } from '../../api/hooks'
import type { ExposureItem } from '../../api/types'
import { bandForScore } from '../../api/types'
import { DataTable, type Column } from '../../components/DataTable'
import { LabelIcon } from '../../components/LabelIcon'
import { NodeRef } from '../../components/NodeRef'
import { Pill, ScoreChip } from '../../components/chips'
import { ErrorState, SkeletonRows } from '../../components/states'
import { cn, fmtNum, fmtPct } from '../../lib/format'
import { useDrawerStore } from '../../store/drawerStore'
import { RelevanceBar } from './ActorsTab'

const STATUS_TONE: Record<string, 'bad' | 'warn' | 'neutral'> = { mass_exploitation: 'bad', active: 'warn', poc_public: 'neutral', none: 'neutral' }

const COLUMNS: Column<ExposureItem>[] = [
  {
    key: 'host', header: 'Internet-exposed host', width: '220px',
    render: (r) => (
      <span className="flex items-center gap-2">
        <LabelIcon label={r.vm.label} category={r.vm.category} size={14} />
        <span className="min-w-0">
          <span className="block truncate font-medium text-fg">{r.vm.name}</span>
          <span className="block truncate text-[10.5px] text-fg-3">
            {String(r.vm.props.environment ?? '')} · {String(r.vm.props.public_ip ?? '')} · {String(r.vm.props.criticality ?? '')}
          </span>
        </span>
      </span>
    ),
    sortValue: (r) => r.vm.name,
  },
  {
    key: 'cve', header: 'CVE', width: '170px',
    render: (r) => (
      <span className="min-w-0">
        <span className="mono block text-fg">{r.cve.name}</span>
        <span className="block text-[10.5px] text-fg-3">
          CVSS {String(r.cve.props.cvss ?? '?')} · EPSS {r.cve.props.epss != null ? fmtPct(Number(r.cve.props.epss)) : '?'}{r.cve.props.kev ? ' · KEV' : ''}
        </span>
      </span>
    ),
    sortValue: (r) => r.cve.name,
  },
  { key: 'status', header: 'Exploitation', width: '130px', render: (r) => <Pill tone={STATUS_TONE[r.exploitation_status] ?? 'neutral'}>{r.exploitation_status.replace('_', ' ')}</Pill>, sortValue: (r) => r.exploitation_status },
  {
    key: 'actors', header: 'Actor / campaign', width: '210px',
    render: (r) => (
      <span className="min-w-0">
        <span className="flex flex-wrap gap-1">
          {r.actors.map((a) => (
            <span key={a.id} className="chip border-cat-ti/40 bg-cat-ti/10 text-cat-ti">{a.name}</span>
          ))}
          {r.campaigns.map((c) => (
            <span key={c.id} className="chip border-line-2 text-fg-2">{c.name}</span>
          ))}
        </span>
        <RelevanceBar value={r.sector_relevance} />
      </span>
    ),
    sortValue: (r) => r.sector_relevance,
  },
  { key: 'score', header: 'Contextual', width: '90px', render: (r) => <ScoreChip score={r.contextual_score} band={bandForScore(r.contextual_score)} />, sortValue: (r) => r.contextual_score },
  {
    key: 'jewels', header: 'Crown jewels reachable',
    render: (r) => (r.crown_jewels_reachable.length ? <span className="flex flex-wrap gap-1">{r.crown_jewels_reachable.map((j) => <NodeRef key={j.id} node={j} mode="explorer" />)}</span> : <span className="text-fg-3">none</span>),
    sortValue: (r) => r.crown_jewels_reachable.length,
  },
  { key: 'edr', header: 'EDR', width: '70px', render: (r) => (r.has_edr_sensor ? <Pill tone="good">sensor</Pill> : <Pill tone="warn">no sensor</Pill>), sortValue: (r) => (r.has_edr_sensor ? 1 : 0) },
  { key: 'alerts', header: 'Alerts', width: '70px', align: 'right', render: (r) => <span className={cn('tabular-nums', r.alert_ids.length ? 'font-semibold text-fg' : 'text-fg-3')}>{r.alert_ids.length}</span>, sortValue: (r) => r.alert_ids.length },
]

/** Demo question 5: internet-exposed hosts with a vulnerability an actor is actively exploiting against our sector. */
export function ExposureTab() {
  const [sectorOnly, setSectorOnly] = useState(true)
  const q = useTiExposure(sectorOnly)
  const navigate = useNavigate()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const items = q.data?.items ?? []
  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <label className="flex cursor-pointer items-center gap-1.5 text-fg-2">
          <input type="checkbox" className="h-3 w-3 accent-sky-400" checked={sectorOnly} onChange={(e) => setSectorOnly(e.target.checked)} />
          Sector-relevant actors only (relevance ≥ 0.7)
        </label>
        <span className="text-fg-3">
          {q.data ? `${fmtNum(items.length)} host/CVE pair${items.length === 1 ? '' : 's'} · Compute(exposure=public) → Vulnerability ← TI(exploitation active, actor targets fintech) → role → blast radius` : 'Loading…'}
        </span>
        <button type="button" className="btn-primary ml-auto" onClick={() => askAbout('Which internet-exposed hosts have a vuln a threat actor is actively exploiting against fintechs right now?')}>
          <Bot size={13} /> Ask the analyst this question
        </button>
      </div>
      <div className="panel flex min-h-0 flex-1 flex-col overflow-hidden">
        {q.isLoading && <SkeletonRows rows={8} cols={8} />}
        {q.error && <ErrorState error={q.error} onRetry={() => q.refetch()} />}
        {q.data && <DataTable columns={COLUMNS} rows={items} rowKey={(r) => `${r.vm.id}|${r.cve.id}`} onRowClick={(r) => navigate(`/explorer?id=${encodeURIComponent(r.vm.id)}`)} defaultSort={{ key: 'score', dir: 'desc' }} className="min-h-0 flex-1" emptyTitle="No exposed host carries an actively exploited CVE" />}
        <div className="border-t border-line px-3 py-1.5 text-[10.5px] text-fg-3">Ranked by contextual score: the top row combines internet exposure, a mass-exploited CVE, an actor targeting our sector and an instance role that reaches PCI data. Rows lower down share the CVE but not the blast radius. Click a row to open the host in the explorer.</div>
      </div>
    </div>
  )
}
