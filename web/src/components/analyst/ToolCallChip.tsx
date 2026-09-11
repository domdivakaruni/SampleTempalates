import { ChevronDown, ChevronRight, CircleAlert, Check, Loader2, Wrench } from 'lucide-react'
import { useState } from 'react'
import type { ToolCallUI } from '../../store/drawerStore'

export function ToolCallChip({ call }: { call: ToolCallUI }) {
  const [open, setOpen] = useState(false)
  const hasArgs = Object.keys(call.arguments ?? {}).length > 0
  return (
    <div className="rounded-md border border-line bg-panel-2/70 text-[11px]">
      <button type="button" className="flex w-full items-center gap-1.5 px-2 py-1 text-left" onClick={() => hasArgs && setOpen((o) => !o)}>
        {call.status === 'running' ? <Loader2 size={11} className="animate-spin text-accent" /> : call.status === 'error' ? <CircleAlert size={11} className="text-sev-critical" /> : <Check size={11} className="text-cat-endpoint" />}
        <Wrench size={10} className="text-fg-3" />
        <span className="mono font-medium text-fg">{call.name}</span>
        {call.summary && <span className="min-w-0 flex-1 truncate text-fg-2" title={call.summary}>{call.summary}</span>}
        {call.status === 'running' && !call.summary && <span className="flex-1 text-fg-3">running…</span>}
        {call.duration_ms !== undefined && <span className="shrink-0 tabular-nums text-fg-3">{call.duration_ms} ms</span>}
        {hasArgs && (open ? <ChevronDown size={11} className="text-fg-3" /> : <ChevronRight size={11} className="text-fg-3" />)}
      </button>
      {open && <pre className="mono max-h-40 overflow-auto border-t border-line px-2 py-1 text-[10.5px] leading-snug text-fg-2">{JSON.stringify(call.arguments, null, 1)}</pre>}
      {call.error && <div className="border-t border-line px-2 py-1 text-sev-critical">{call.error}</div>}
    </div>
  )
}
