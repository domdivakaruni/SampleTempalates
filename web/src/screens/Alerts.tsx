import { Bot } from 'lucide-react'
import { useCallback, useMemo } from 'react'
import { useAlerts, useStorylines, useTiActors } from '../api/hooks'
import type { AlertListParams, AlertSort } from '../api/types'
import { AlertsTable } from '../components/AlertsTable'
import { Page, PageHeader } from '../components/Page'
import { Pagination } from '../components/Pagination'
import { ErrorState, SkeletonRows } from '../components/states'
import { fmtNum } from '../lib/format'
import { useSearchParamsObject } from '../lib/useSearchParam'
import { useDrawerStore } from '../store/drawerStore'
import { ALERT_PARAM_KEYS, AlertFilters } from './alerts/AlertFilters'

const SORTS: Record<string, AlertSort> = { contextual: 'contextual', rank: 'contextual', vendor: 'vendor', time: 'time' }
const SORT_LABEL: Record<AlertSort, string> = { contextual: 'contextual score', vendor: 'vendor severity', time: 'detection time' }

export function Alerts() {
  const [p, patch] = useSearchParamsObject(ALERT_PARAM_KEYS)
  const sort: AlertSort = SORTS[p.sort] ?? 'contextual'
  const order: 'asc' | 'desc' = p.order === 'asc' ? 'asc' : 'desc'
  const limit = Number(p.limit) > 0 ? Number(p.limit) : 50
  const offset = Number(p.offset) > 0 ? Number(p.offset) : 0
  const params = useMemo<AlertListParams>(
    () => ({
      sort,
      order,
      band: p.band || undefined,
      severity: p.severity || undefined,
      source: p.source || undefined,
      storyline: p.storyline || undefined,
      // Only send the boolean filters when set: `false` would filter to the complement.
      reaches_crown_jewel: p.rcj === '1' ? true : undefined,
      on_attack_path: p.oap === '1' ? true : undefined,
      q: p.q || undefined,
      limit,
      offset,
    }),
    [sort, order, p.band, p.severity, p.source, p.storyline, p.rcj, p.oap, p.q, limit, offset],
  )
  const q = useAlerts(params)
  const stories = useStorylines()
  const actors = useTiActors()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const actorNames = useMemo(() => Object.fromEntries((actors.data?.items ?? []).map((i) => [i.actor.id, i.actor.name])), [actors.data])

  const onSortChange = useCallback(
    (s: { key: string; dir: 'asc' | 'desc' }) => {
      const api = SORTS[s.key]
      if (!api) return
      patch({ sort: api === 'contextual' ? null : api, order: s.dir === 'desc' ? null : s.dir, offset: null })
    },
    [patch],
  )

  const total = q.data?.total ?? 0
  return (
    <Page className="flex flex-col p-4" scroll={false}>
      <PageHeader
        title="Alerts"
        subtitle={q.data ? `${fmtNum(total)} alert${total === 1 ? '' : 's'} · sorted by ${SORT_LABEL[sort]} ${order === 'desc' ? '↓' : '↑'} · vendor severity next to the contextual score, with the rank move and the graph reasons` : 'Loading…'}
        actions={
          <button type="button" className="btn-primary" onClick={() => askAbout("Which of today's medium-severity endpoint alerts sit on assets with a path to regulated data?")}>
            <Bot size={13} /> Ask: which medium alerts reach regulated data?
          </button>
        }
      />
      <div className="mt-3">
        <AlertFilters values={p} patch={patch} storylines={stories.data?.items ?? []} />
      </div>
      <div className="panel mt-3 flex min-h-0 flex-1 flex-col overflow-hidden">
        {q.isLoading && <SkeletonRows rows={10} cols={8} />}
        {q.error && <ErrorState error={q.error} onRetry={() => q.refetch()} />}
        {q.data && (
          <AlertsTable
            alerts={q.data.items}
            columns={['rank', 'asset', 'title', 'source', 'vendor', 'contextual', 'why', 'storyline', 'ti', 'time']}
            serverSort
            sort={{ key: sort, dir: order }}
            onSortChange={onSortChange}
            actorNames={actorNames}
            className="min-h-0 flex-1"
            emptyTitle="No alerts match these filters"
          />
        )}
        <Pagination className="border-t border-line px-3 py-2" total={total} limit={limit} offset={offset} onChange={(n) => patch({ offset: n.offset || null, limit: n.limit === 50 ? null : n.limit })} />
      </div>
    </Page>
  )
}
