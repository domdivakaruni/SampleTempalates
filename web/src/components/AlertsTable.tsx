import { useNavigate } from 'react-router-dom'
import type { AlertSummary } from '../api/types'
import { fmtTime, shortId } from '../lib/format'
import { LabelIcon } from './LabelIcon'
import { RankDelta, ReasonChips, ScoreChip, SeverityChip, SourceChip, StorylineChip, TIBadge } from './chips'
import { DataTable, type Column } from './DataTable'

export type AlertColumnKey = 'asset' | 'title' | 'source' | 'vendor' | 'contextual' | 'why' | 'storyline' | 'ti' | 'time' | 'rank'

interface Props {
  alerts: AlertSummary[]
  columns?: AlertColumnKey[]
  sort?: { key: string; dir: 'asc' | 'desc' } | null
  onSortChange?: (s: { key: string; dir: 'asc' | 'desc' }) => void
  serverSort?: boolean
  onRowClick?: (a: AlertSummary) => void
  selectedId?: string | null
  className?: string
  emptyTitle?: string
  actorNames?: Record<string, string>
}


export function AlertsTable({ alerts, columns, sort, onSortChange, serverSort, onRowClick, selectedId, className, emptyTitle, actorNames }: Props) {
  const navigate = useNavigate()
  const all: Record<AlertColumnKey, Column<AlertSummary>> = {
    rank: { key: 'rank', header: '#', width: '44px', align: 'right', render: (a) => <span className="tabular-nums text-fg-3">{a.contextual_rank_position ?? '—'}</span>, sortValue: (a) => a.contextual_rank_position ?? 9999 },
    asset: {
      key: 'asset', header: 'Asset', width: '190px',
      render: (a) => (
        <span className="flex items-center gap-1.5 min-w-0">
          <LabelIcon label={a.entity_label ?? 'Endpoint'} size={13} />
          <span className="truncate font-medium text-fg" title={a.entity_id ?? ''}>{a.entity_name ?? a.hostname ?? shortId(a.entity_id)}</span>
        </span>
      ),
      sortValue: (a) => a.entity_name ?? a.hostname ?? '',
    },
    title: { key: 'title', header: 'Alert', render: (a) => <span className="line-clamp-2 leading-snug text-fg" title={a.title}>{a.title}</span>, sortValue: (a) => a.title },
    source: { key: 'source', header: 'Source', width: '90px', render: (a) => <SourceChip source={a.source_system} />, sortValue: (a) => a.source_system },
    vendor: { key: 'vendor', header: 'Vendor', width: '90px', render: (a) => <SeverityChip severity={a.vendor_severity} />, sortValue: (a) => a.vendor_severity_rank },
    contextual: {
      key: 'contextual', header: 'Contextual', width: '112px',
      render: (a) => (
        <span className="flex items-center gap-1.5">
          <ScoreChip score={a.contextual_score} band={a.contextual_band} />
          <RankDelta alert={a} />
        </span>
      ),
      sortValue: (a) => a.contextual_score,
    },
    why: { key: 'why', header: 'Why', render: (a) => <ReasonChips reasons={a.graph_reasons} max={2} /> },
    storyline: { key: 'storyline', header: 'Storyline', width: '110px', render: (a) => <StorylineChip id={a.storyline_id} onClick={a.storyline_id ? () => navigate(`/storylines/${encodeURIComponent(a.storyline_id!)}`) : undefined} />, sortValue: (a) => a.storyline_id ?? '' },
    ti: { key: 'ti', header: 'Threat intel', width: '150px', render: (a) => <TIBadge alert={a} actorNames={actorNames} />, sortValue: (a) => a.ioc_match_count + a.ti_actor_ids.length * 10 },
    time: { key: 'time', header: 'Detected', width: '128px', render: (a) => <span className="mono text-[11px] text-fg-2 whitespace-nowrap">{fmtTime(a.detected_at)}</span>, sortValue: (a) => a.detected_at ?? '' },
  }
  const keys = columns ?? ['asset', 'title', 'source', 'vendor', 'contextual', 'why', 'storyline', 'ti', 'time']
  const cols = keys.map((k) => all[k])
  return (
    <DataTable
      columns={cols}
      rows={alerts}
      rowKey={(a) => a.id}
      onRowClick={onRowClick ?? ((a) => navigate(`/alerts/${encodeURIComponent(a.id)}`))}
      sort={serverSort ? sort ?? null : undefined}
      onSortChange={serverSort ? onSortChange : undefined}
      defaultSort={serverSort ? undefined : { key: 'contextual', dir: 'desc' }}
      selectedKey={selectedId}
      className={className}
      emptyTitle={emptyTitle ?? 'No alerts match'}
    />
  )
}
