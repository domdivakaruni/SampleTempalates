import { Send, Square } from 'lucide-react'
import { useRef } from 'react'
import { useDrawerStore } from '../../store/drawerStore'

export function Composer() {
  const draft = useDrawerStore((s) => s.draft)
  const setDraft = useDrawerStore((s) => s.setDraft)
  const send = useDrawerStore((s) => s.send)
  const abort = useDrawerStore((s) => s.abort)
  const streaming = useDrawerStore((s) => s.streaming)
  const ref = useRef<HTMLTextAreaElement>(null)
  const submit = () => {
    if (!draft.trim() || streaming) return
    void send(draft)
    ref.current?.focus()
  }
  return (
    <div className="border-t border-line p-2">
      <div className="flex items-end gap-1.5 rounded-md border border-line-2 bg-bg px-2 py-1.5 focus-within:border-accent-2">
        <textarea
          ref={ref}
          data-testid="analyst-input"
          aria-label="Ask the analyst"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              submit()
            }
          }}
          rows={Math.min(5, Math.max(1, draft.split('\n').length))}
          placeholder="Ask the analyst… (Enter sends)"
          className="max-h-32 min-h-[22px] flex-1 resize-none bg-transparent text-[13px] leading-snug text-fg placeholder:text-fg-3 focus:outline-none"
        />
        {streaming ? (
          <button type="button" className="btn-icon text-sev-critical" onClick={abort} title="Stop">
            <Square size={12} />
          </button>
        ) : (
          <button type="button" className="btn-icon text-accent" onClick={submit} disabled={!draft.trim()} title="Send">
            <Send size={13} />
          </button>
        )}
      </div>
    </div>
  )
}
