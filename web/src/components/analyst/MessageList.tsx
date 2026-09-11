import { CircleAlert, Sparkles } from 'lucide-react'
import { useEffect, useRef } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useNavigate } from 'react-router-dom'
import { labelForId } from '../../graph/schema'
import { useCanvasStore } from '../../store/canvasStore'
import { useDrawerStore, type ChatMessage } from '../../store/drawerStore'
import { useSelectionStore } from '../../store/selectionStore'
import { EvidenceBar } from './EvidenceBar'
import { Findings } from './Findings'
import { ToolCallChip } from './ToolCallChip'

const ID_RE = /^[a-z]+:[a-z0-9-]+:.+/i

/** Inline `code` that looks like a node id becomes a clickable evidence reference. */
function CodeRef({ children }: { children?: React.ReactNode }) {
  const navigate = useNavigate()
  const focus = useCanvasStore((s) => s.focus)
  const active = useCanvasStore((s) => s.activeCanvas)
  const select = useSelectionStore((s) => s.select)
  const text = String(children ?? '')
  if (!ID_RE.test(text)) return <code>{children}</code>
  const label = labelForId(text)
  const open = () => {
    if (label === 'Alert') return navigate(`/alerts/${encodeURIComponent(text)}`)
    if (label === 'Storyline') return navigate(`/storylines/${encodeURIComponent(text)}`)
    if (active) {
      focus(text)
      select(text)
    } else navigate(`/explorer?id=${encodeURIComponent(text)}`)
  }
  return (
    <button type="button" onClick={open} className="cursor-pointer rounded border border-transparent hover:border-accent/50" title={`${label ?? 'node'}: ${text}`}>
      <code>{text.length > 46 ? `${text.slice(0, 44)}…` : text}</code>
    </button>
  )
}

function AssistantMessage({ m }: { m: ChatMessage }) {
  const send = useDrawerStore((s) => s.send)
  const streaming = useDrawerStore((s) => s.streaming)
  return (
    <div className="space-y-2">
      {m.toolCalls.length > 0 && (
        <div className="space-y-1">
          {m.toolCalls.map((t) => (
            <ToolCallChip key={t.id} call={t} />
          ))}
        </div>
      )}
      {m.thinking && <div className="rounded-md border border-dashed border-line px-2 py-1 text-[11px] italic text-fg-3">{m.thinking}</div>}
      {(m.content || m.streaming) && (
        <div className={`prose-chat rounded-lg border border-line bg-panel-2/60 px-3 py-2 ${m.streaming && !m.answer ? 'caret' : ''}`}>
          {m.content ? <Markdown remarkPlugins={[remarkGfm]} components={{ code: CodeRef }}>{m.content}</Markdown> : <span className="text-fg-3">Thinking…</span>}
        </div>
      )}
      {m.error && (
        <div className="flex items-start gap-1.5 rounded-md border border-sev-critical/40 bg-sev-critical/10 px-2 py-1.5 text-[11px] text-sev-critical">
          <CircleAlert size={12} className="mt-0.5" /> {m.error}
        </div>
      )}
      <EvidenceBar evidence={m.evidence ?? m.answer?.evidence} />
      {m.answer && <Findings findings={m.answer.findings} />}
      {m.answer && (
        <div className="flex flex-wrap items-center gap-1.5 text-[10.5px] text-fg-3">
          <span>confidence {(m.answer.confidence * 100).toFixed(0)}%</span>
          {m.answer.intent && <span>· intent {m.answer.intent}</span>}
          <span>· {m.answer.tool_calls.length} tool call{m.answer.tool_calls.length === 1 ? '' : 's'}</span>
        </div>
      )}
      {m.answer && m.answer.followups.length > 0 && !streaming && (
        <div className="flex flex-wrap gap-1">
          {m.answer.followups.map((f) => (
            <button key={f} type="button" className="chip border-line-2 bg-panel-2 text-fg-2 hover:border-accent/50 hover:text-fg max-w-full" onClick={() => void send(f)} title={f}>
              <Sparkles size={10} className="shrink-0 text-accent" />
              <span className="truncate">{f}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export function MessageList({ messages }: { messages: ChatMessage[] }) {
  const endRef = useRef<HTMLDivElement>(null)
  const last = messages[messages.length - 1]
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' })
  }, [messages.length, last?.content.length, last?.toolCalls.length, last?.answer])
  return (
    <div className="space-y-3 px-3 py-3">
      {messages.map((m) =>
        m.role === 'user' ? (
          <div key={m.id} className="flex justify-end">
            <div className="max-w-[92%] rounded-lg bg-accent/15 px-3 py-2 text-[13px] leading-snug text-fg">{m.content}</div>
          </div>
        ) : (
          <AssistantMessage key={m.id} m={m} />
        ),
      )}
      <div ref={endRef} />
    </div>
  )
}
