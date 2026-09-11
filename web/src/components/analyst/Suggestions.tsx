import { Sparkles } from 'lucide-react'
import { useSuggestions } from '../../api/hooks'
import type { ChatContext } from '../../api/types'
import { useDrawerStore } from '../../store/drawerStore'

export function Suggestions({ context, compact }: { context: ChatContext; compact?: boolean }) {
  const q = useSuggestions({ alert_id: context.alert_id, node_id: context.node_id, storyline_id: context.storyline_id })
  const send = useDrawerStore((s) => s.send)
  const streaming = useDrawerStore((s) => s.streaming)
  const questions = q.data?.questions ?? []
  if (!questions.length) return null
  return (
    <div className="px-3 py-2">
      <div className="mb-1.5 flex items-center gap-1 text-[10.5px] uppercase tracking-wider text-fg-3">
        <Sparkles size={11} className="text-accent" /> Suggested questions{context.alert_id || context.node_id || context.storyline_id ? ' for this context' : ''}
      </div>
      <div className="flex flex-col gap-1">
        {questions.slice(0, compact ? 4 : 12).map((s) => (
          <button key={s} type="button" disabled={streaming} className="rounded-md border border-line bg-panel-2/60 px-2 py-1.5 text-left text-[12px] leading-snug text-fg-2 hover:border-accent/50 hover:text-fg disabled:opacity-50" onClick={() => void send(s)}>
            {s}
          </button>
        ))}
      </div>
    </div>
  )
}
