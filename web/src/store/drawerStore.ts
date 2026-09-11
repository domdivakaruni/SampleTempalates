/** Analyst drawer state: session, streamed messages, tool calls, evidence and page context. */
import { create } from 'zustand'
import { api, streamChat } from '../api/client'
import type { AgentMode, AnalystAnswer, ChatContext, ChatEvent, GraphFragment, JsonValue } from '../api/types'
import { mergeFragment } from '../graph/elements'
import { useCanvasStore } from './canvasStore'

export interface ToolCallUI {
  id: string
  name: string
  arguments: Record<string, JsonValue | undefined>
  summary?: string
  duration_ms?: number
  error?: string | null
  status: 'running' | 'done' | 'error'
}

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  thinking?: string
  streaming?: boolean
  toolCalls: ToolCallUI[]
  evidence?: GraphFragment
  answer?: AnalystAnswer
  error?: string
  createdAt: string
}

interface DrawerState {
  open: boolean
  sessionId: string | null
  mode: AgentMode | null
  model: string | null
  messages: ChatMessage[]
  context: ChatContext
  draft: string
  streaming: boolean
  controller: AbortController | null
  setOpen: (v: boolean) => void
  toggle: () => void
  setContext: (ctx: ChatContext) => void
  setDraft: (v: string) => void
  send: (content: string, ctx?: ChatContext) => Promise<void>
  askAbout: (prompt: string, ctx?: ChatContext, opts?: { send?: boolean }) => void
  abort: () => void
  reset: () => void
}

let msgSeq = 1
const nextId = () => `m${msgSeq++}`

export const useDrawerStore = create<DrawerState>((set, get) => ({
  open: false,
  sessionId: null,
  mode: null,
  model: null,
  messages: [],
  context: {},
  draft: '',
  streaming: false,
  controller: null,
  setOpen: (v) => set({ open: v }),
  toggle: () => set((s) => ({ open: !s.open })),
  setContext: (ctx) => set({ context: ctx }),
  setDraft: (v) => set({ draft: v }),
  askAbout: (prompt, ctx, opts = {}) => {
    set((s) => ({ open: true, context: ctx ? { ...s.context, ...ctx } : s.context, draft: opts.send ? s.draft : prompt }))
    if (opts.send) void get().send(prompt, ctx)
  },
  abort: () => {
    get().controller?.abort()
    set({ controller: null, streaming: false })
  },
  reset: () => {
    get().controller?.abort()
    set({ sessionId: null, messages: [], streaming: false, controller: null })
    useCanvasStore.getState().resetEvidence()
  },
  send: async (content, ctx) => {
    const text = content.trim()
    if (!text || get().streaming) return
    const context = { ...get().context, ...(ctx ?? {}) }
    const controller = new AbortController()
    const userMsg: ChatMessage = { id: nextId(), role: 'user', content: text, toolCalls: [], createdAt: new Date().toISOString() }
    const asstId = nextId()
    const asst: ChatMessage = { id: asstId, role: 'assistant', content: '', toolCalls: [], streaming: true, createdAt: new Date().toISOString() }
    set((s) => ({ messages: [...s.messages, userMsg, asst], streaming: true, controller, draft: '', open: true, context }))
    useCanvasStore.getState().resetEvidence()

    const update = (fn: (m: ChatMessage) => ChatMessage) => set((s) => ({ messages: s.messages.map((m) => (m.id === asstId ? fn(m) : m)) }))

    const onEvent = (evt: ChatEvent) => {
      switch (evt.type) {
        case 'session':
          set({ sessionId: evt.data.session_id, mode: evt.data.mode, model: evt.data.model ?? null })
          break
        case 'text_delta':
          update((m) => ({ ...m, content: m.content + evt.data.text }))
          break
        case 'thinking':
          update((m) => ({ ...m, thinking: (m.thinking ?? '') + evt.data.text }))
          break
        case 'tool_call':
          update((m) => ({ ...m, toolCalls: [...m.toolCalls, { id: evt.data.id, name: evt.data.name, arguments: evt.data.arguments ?? {}, status: 'running' }] }))
          break
        case 'tool_result':
          update((m) => ({
            ...m,
            toolCalls: m.toolCalls.some((t) => t.id === evt.data.id)
              ? m.toolCalls.map((t) => (t.id === evt.data.id ? { ...t, summary: evt.data.summary, duration_ms: evt.data.duration_ms, error: evt.data.error ?? null, status: evt.data.error ? 'error' : 'done' } : t))
              : [...m.toolCalls, { id: evt.data.id, name: evt.data.name, arguments: {}, summary: evt.data.summary, duration_ms: evt.data.duration_ms, error: evt.data.error ?? null, status: evt.data.error ? 'error' : 'done' }],
          }))
          break
        case 'evidence': {
          const frag = evt.data
          update((m) => ({ ...m, evidence: m.evidence ? mergeFragment(m.evidence, frag) : frag }))
          const canvas = useCanvasStore.getState()
          canvas.publish(frag, 'merge')
          break
        }
        case 'answer':
          update((m) => ({ ...m, answer: evt.data, content: m.content || evt.data.narrative_md, evidence: evt.data.evidence?.nodes?.length ? evt.data.evidence : m.evidence }))
          if (evt.data.mode) set({ mode: evt.data.mode, model: evt.data.model ?? get().model })
          break
        case 'error':
          update((m) => ({ ...m, error: `${evt.data.code}: ${evt.data.message}` }))
          break
        case 'done':
          set({ mode: evt.data.mode ?? get().mode, model: evt.data.model ?? get().model })
          break
      }
    }

    try {
      let sessionId = get().sessionId
      if (!sessionId) {
        const session = await api.chatCreateSession(context)
        sessionId = session.id
        set({ sessionId })
      }
      await streamChat(sessionId, { content: text, context, mode: 'auto' }, onEvent, controller.signal)
    } catch (e) {
      if (!(e instanceof DOMException && e.name === 'AbortError')) {
        const message = e instanceof Error ? e.message : String(e)
        update((m) => ({ ...m, error: m.error ?? message }))
      }
    } finally {
      update((m) => ({ ...m, streaming: false }))
      set({ streaming: false, controller: null })
    }
  },
}))
