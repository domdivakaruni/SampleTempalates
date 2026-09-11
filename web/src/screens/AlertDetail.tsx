import { Table2, Waypoints } from 'lucide-react'
import { useNavigate, useParams } from 'react-router-dom'
import { useAlertContext } from '../api/hooks'
import { Tabs } from '../components/Tabs'
import { ErrorState, SkeletonBlock } from '../components/states'
import { useSearchParamState } from '../lib/useSearchParam'
import { AlertHeader } from './alert-detail/AlertHeader'
import { FlatView } from './alert-detail/FlatView'
import { GraphContext } from './alert-detail/GraphContext'

/** /alerts/:id?tab=flat|graph — Flat view (vendor fields) vs Graph context (evidence canvas + explainable panels). */
export function AlertDetail() {
  const { id = '' } = useParams()
  const alertId = decodeURIComponent(id)
  const [tabParam, setTab] = useSearchParamState('tab', 'graph')
  const tab = tabParam === 'flat' ? 'flat' : 'graph'
  const q = useAlertContext(alertId)
  const navigate = useNavigate()
  return (
    <div className="flex h-full flex-col">
      {q.isLoading && <SkeletonBlock lines={8} className="p-4" />}
      {q.error && (
        <ErrorState
          error={q.error}
          onRetry={() => q.refetch()}
          className="p-4"
        />
      )}
      {q.error && (
        <div className="text-center">
          <button type="button" className="btn" onClick={() => navigate('/alerts')}>
            Back to alerts
          </button>
        </div>
      )}
      {q.data && (
        <>
          <AlertHeader ctx={q.data} />
          <Tabs
            className="px-4"
            active={tab}
            onChange={setTab}
            tabs={[
              { id: 'flat', label: 'Flat view', icon: <Table2 size={13} />, title: 'The raw vendor fields, exactly as the source console shows them' },
              { id: 'graph', label: 'Graph context', icon: <Waypoints size={13} />, count: q.data.evidence.nodes.length, title: 'Evidence subgraph, attack path, blast radius and score breakdown' },
            ]}
            right={<span className="text-[10.5px] text-fg-3">{tab === 'flat' ? 'what the vendor console shows' : 'what the graph adds'}</span>}
          />
          <div className="min-h-0 flex-1 overflow-hidden">{tab === 'flat' ? <FlatView ctx={q.data} /> : <GraphContext key={alertId} ctx={q.data} />}</div>
        </>
      )}
    </div>
  )
}
