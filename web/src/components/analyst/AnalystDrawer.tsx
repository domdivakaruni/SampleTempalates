import { Bot, RotateCcw, X } from 'lucide-react'
import { useEffect, useMemo } from 'react'
import { matchPath, useLocation } from 'react-router-dom'
import type { ChatContext } from '../../api/types'
import { useDrawerStore } from '../../store/drawerStore'
import { useSelectionStore } from '../../store/selectionStore'
import { Composer } from './Composer'
import { MessageList } from './MessageList'
import { Suggestions } from './Suggestions'

/** Persistent right-side analyst chat drawer. Page context (alert / storyline / selected node) is attached to every turn. */
export function AnalystDrawer() {
  const open = useDrawerStore((s) => s.open)
  const setOpen = useDrawerStore((s) => s.setOpen)
  const messages = useDrawerStore((s) => s.messages)
  const mode = useDrawerStore((s) => s.mode)
  const model = useDrawerStore((s) => s.model)
  const reset = useDrawerStore((s) => s.reset)
  const setContext = useDrawerStore((s) => s.setContext)
  const context = useDrawerStore((s) => s.context)
  const { pathname } = useLocation()
  const selected = useSelectionStore((s) => s.selectedNodeId)

  const pageContext = useMemo<ChatContext>(() => {
    const alert = matchPath('/alerts/:id', pathname)
    const story = matchPath('/storylines/:id', pathname)
    const ctx: ChatContext = {}
    if (alert?.params.id) ctx.alert_id = decodeURIComponent(alert.params.id)
    if (story?.params.id) ctx.storyline_id = decodeURIComponent(story.params.id)
    if (selected) {
      ctx.node_id = selected
      ctx.selected_node_ids = [selected]
    }
    return ctx
  }, [pathname, selected])

  useEffect(() => {
    setContext(pageContext)
  }, [pageContext, setContext])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && open && !(e.target instanceof HTMLTextAreaElement)) setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, setOpen])

  if (!open) return null
  const contextChips = [context.alert_id && `alert ${context.alert_id.split(':').pop()}`, context.storyline_id && `storyline ${context.storyline_id.split(':').pop()?.replace('-larkspur', '')}`, context.node_id && `node ${context.node_id.split(':').slice(2).join(':').slice(0, 24)}`].filter(Boolean) as string[]
  return (
    <aside className="flex h-full w-[420px] shrink-0 flex-col border-l border-line bg-panel" aria-label="Analyst">
      <div className="flex items-center gap-2 border-b border-line px-3 py-2">
        <Bot size={15} className="text-accent" />
        <div className="text-sm font-semibold text-fg">Analyst</div>
        <span className={`chip ${mode === 'llm' ? 'border-accent/40 bg-accent/10 text-accent' : 'border-line-2 text-fg-2'}`} title="Answer mode: LLM narration over typed graph tools, or deterministic offline playbooks">
          {mode === 'llm' ? model ?? 'LLM' : mode === 'offline' ? 'Offline playbooks' : 'auto'}
        </span>
        <span className="flex-1" />
        <button type="button" className="btn-icon h-6 w-6" onClick={reset} title="New conversation">
          <RotateCcw size={12} />
        </button>
        <button type="button" className="btn-icon h-6 w-6" onClick={() => setOpen(false)} title="Close (Esc)">
          <X size={12} />
        </button>
      </div>
      {contextChips.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 border-b border-line px-3 py-1.5 text-[10.5px] text-fg-3">
          Context:
          {contextChips.map((c) => (
            <span key={c} className="chip border-line-2 text-fg-2">
              {c}
            </span>
          ))}
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {messages.length === 0 ? (
          <div className="px-3 pt-4 text-xs text-fg-2">
            <p className="leading-relaxed">
              Ask about any alert, host, identity or data store. Answers are grounded in graph traversals, cite node ids, and their evidence is drawn on whichever canvas is visible.
            </p>
          </div>
        ) : (
          <MessageList messages={messages} />
        )}
        <Suggestions context={context} compact={messages.length > 0} />
      </div>
      <Composer />
    </aside>
  )
}
