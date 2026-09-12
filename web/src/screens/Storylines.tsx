import { Bot } from 'lucide-react'
import { useStorylines } from '../api/hooks'
import { Page, PageHeader } from '../components/Page'
import { StorylineCard } from '../components/StorylineCard'
import { EmptyState, ErrorState, SkeletonBlock } from '../components/states'
import { useDrawerStore } from '../store/drawerStore'

export function Storylines() {
  const q = useStorylines()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const items = q.data?.items ?? []
  return (
    <Page className="p-4">
      <PageHeader
        title="Storylines"
        subtitle="Multi-stage intrusions reconstructed across EDR, cloud audit, identity and threat intel; each one is a single incident the vendor consoles show as unrelated alerts."
        actions={
          <button type="button" className="btn-primary" onClick={() => askAbout('Trace the full attack path from the phishing detection on WKS-3391 to any regulated data store.')}>
            <Bot size={13} /> Ask: trace the phishing-to-data path
          </button>
        }
      />
      {q.isLoading && <SkeletonBlock lines={8} className="mt-4" />}
      {q.error && <ErrorState error={q.error} onRetry={() => q.refetch()} />}
      {q.data && items.length === 0 && <EmptyState title="No storylines" hint="Correlation has not produced a multi-stage storyline yet." />}
      <div className="mt-3 grid gap-3 2xl:grid-cols-2">
        {items.map((s) => (
          <StorylineCard key={s.id} story={s} />
        ))}
      </div>
    </Page>
  )
}
