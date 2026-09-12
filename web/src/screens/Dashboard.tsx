import { Bot } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useDashboard } from '../api/hooks'
import { Page, PageHeader, Panel } from '../components/Page'
import { StorylineCard } from '../components/StorylineCard'
import { ErrorState, SkeletonBlock } from '../components/states'
import { useDrawerStore } from '../store/drawerStore'
import { BandAndSourceBars, CoveragePanel, TIPressure } from './dashboard/DashboardPanels'
import { KpiTiles } from './dashboard/KpiTiles'
import { Leaderboards } from './dashboard/Leaderboards'
import { RerankCallout } from './dashboard/RerankCallout'

export function Dashboard() {
  const q = useDashboard()
  const navigate = useNavigate()
  const askAbout = useDrawerStore((s) => s.askAbout)
  return (
    <Page className="p-4">
      <PageHeader
        title="Dashboard"
        subtitle="Larkspur Financial · contextual risk from the security context graph, next to what the vendor consoles show."
        actions={
          <button type="button" className="btn-primary" onClick={() => askAbout('Rank all open issues by contextual risk, not vendor severity, and explain the top 3.')} data-testid="dashboard-ask">
            <Bot size={13} /> Ask the analyst to explain the top 3
          </button>
        }
      />
      {q.isLoading && <SkeletonBlock lines={10} className="mt-4" />}
      {q.error && <ErrorState error={q.error} onRetry={() => q.refetch()} />}
      {q.data && (
        <div className="mt-3 space-y-3">
          <KpiTiles kpis={q.data.kpis} coverage={q.data.coverage} />
          <RerankCallout examples={q.data.rerank_examples} />
          <Leaderboards contextual={q.data.leaderboard_contextual} vendor={q.data.leaderboard_vendor} />
          <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_400px]">
            <div className="space-y-3">
              <Panel title="Storylines" actions={<button type="button" className="btn-ghost py-0.5" onClick={() => navigate('/storylines')}>All storylines →</button>} bodyClassName="space-y-2">
                {q.data.storylines.length === 0 && <div className="text-xs text-fg-3">No correlated storyline.</div>}
                {q.data.storylines.map((s) => (
                  <StorylineCard key={s.id} story={s} />
                ))}
              </Panel>
              <BandAndSourceBars bands={q.data.alerts_by_band} sources={q.data.alerts_by_source} />
            </div>
            <div className="space-y-3">
              <TIPressure items={q.data.ti_pressure} />
              <CoveragePanel coverage={q.data.coverage} />
            </div>
          </div>
        </div>
      )}
    </Page>
  )
}
