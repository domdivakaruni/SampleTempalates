/**
 * Precomputed analyst for the static edition: suggestions per context key, question matching (exact normalised
 * string, then Jaccard token overlap) and a replay of the recorded answer as the same event sequence the SSE stream
 * produces (docs/10-static-snapshot.md sections 2 and 3).
 */
import type { AnalystAnswer, ChatContext, ChatEvent, ChatMessageIn, ChatSession, JsonValue } from '../types'
import { emptyFragment } from '../types'
import { hydratePayload } from './hydrate'
import { loadChat } from './loader'
import type { ChatAnswerEntry, SnapshotChat } from './schema'

export const GLOBAL_KEY = ''
export const JACCARD_MIN = 0.55
const TOOL_PACE_MS = 120
const TEXT_PACE_MS = 18
const WORDS_PER_CHUNK = 8
const ID_TOKEN_RE = /(?:^|\s)[a-z]+:[a-z0-9-]+:\S+/i

/** Lower-case, strip punctuation except `:/.-` (and `_`), collapse whitespace. Must agree with the exporter. */
export function normalizeQuestion(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^\p{L}\p{N}_\s:/.-]/gu, '')
    .replace(/\s+/g, ' ')
    .trim()
}

/** Context keys for a turn, most specific first: the selected node, then the alert, then the storyline. */
export function contextKeys(ctx?: ChatContext | null): string[] {
  const keys: string[] = []
  const nodeId = ctx?.node_id ?? (ctx?.selected_node_ids?.length === 1 ? ctx.selected_node_ids[0] : undefined)
  if (nodeId) keys.push(`node:${nodeId}`)
  if (ctx?.alert_id) keys.push(`alert:${ctx.alert_id}`)
  if (ctx?.storyline_id) keys.push(`storyline:${ctx.storyline_id}`)
  return keys
}

/** GET /chat/suggestions: the recorded lists for the given context keys followed by the global list, de-duplicated. */
export function suggestionsFor(chat: SnapshotChat, ctx: { alert_id?: string; node_id?: string; storyline_id?: string }): string[] {
  const keys: string[] = []
  if (ctx.alert_id) keys.push(`alert:${ctx.alert_id}`)
  if (ctx.node_id) keys.push(`node:${ctx.node_id}`)
  if (ctx.storyline_id) keys.push(`storyline:${ctx.storyline_id}`)
  keys.push(GLOBAL_KEY)
  const out: string[] = []
  for (const key of keys) out.push(...(chat.suggestions[key] ?? []))
  return [...new Set(out)]
}

// ----------------------------------------------------------------------------- matching

interface IndexedAnswer {
  entry: ChatAnswerEntry
  tokens: Set<string>
}

interface AnswerIndex {
  byKey: Map<string, IndexedAnswer[]>
  /** `${context key}\u0000${normalised question}` -> entry (both the exporter's and our own normalisation are registered). */
  exact: Map<string, ChatAnswerEntry>
  /** normalised question -> entry, any context (used only when the question names a node id explicitly). */
  exactAny: Map<string, ChatAnswerEntry>
}

const indexes = new WeakMap<SnapshotChat, AnswerIndex>()

function indexOf(chat: SnapshotChat): AnswerIndex {
  let idx = indexes.get(chat)
  if (idx) return idx
  idx = { byKey: new Map(), exact: new Map(), exactAny: new Map() }
  for (const entry of chat.answers ?? []) {
    if (!entry || typeof entry.question !== 'string' || !entry.answer) continue
    const key = entry.context_key ?? GLOBAL_KEY
    const forms = new Set([normalizeQuestion(entry.question), ...(entry.normalized ? [entry.normalized] : [])])
    for (const form of forms) {
      if (!idx.exact.has(`${key}\u0000${form}`)) idx.exact.set(`${key}\u0000${form}`, entry)
      if (!idx.exactAny.has(form)) idx.exactAny.set(form, entry)
    }
    const list = idx.byKey.get(key) ?? []
    list.push({ entry, tokens: new Set(normalizeQuestion(entry.question).split(' ').filter(Boolean)) })
    idx.byKey.set(key, list)
  }
  indexes.set(chat, idx)
  return idx
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0
  let inter = 0
  for (const t of a) if (b.has(t)) inter++
  return inter / (a.size + b.size - inter)
}

export interface AnswerMatch {
  entry: ChatAnswerEntry
  how: 'exact' | 'exact-any-context' | 'jaccard'
  score: number
}

/**
 * Exact normalised match in the turn's context keys, then in the global key; an exact match under any other context
 * key when the question names a node id explicitly (such questions are context-independent); then the best Jaccard
 * overlap >= 0.55 in the context keys, then in the global key.
 */
export function matchAnswer(chat: SnapshotChat, question: string, ctx?: ChatContext | null): AnswerMatch | null {
  const idx = indexOf(chat)
  const norm = normalizeQuestion(question)
  if (!norm) return null
  const keys = [...contextKeys(ctx), GLOBAL_KEY]
  for (const key of keys) {
    const hit = idx.exact.get(`${key}\u0000${norm}`)
    if (hit) return { entry: hit, how: 'exact', score: 1 }
  }
  if (ID_TOKEN_RE.test(norm)) {
    const hit = idx.exactAny.get(norm)
    if (hit) return { entry: hit, how: 'exact-any-context', score: 1 }
  }
  const tokens = new Set(norm.split(' ').filter(Boolean))
  for (const key of keys) {
    let best: IndexedAnswer | null = null
    let bestScore = 0
    for (const candidate of idx.byKey.get(key) ?? []) {
      const s = jaccard(tokens, candidate.tokens)
      if (s > bestScore) {
        best = candidate
        bestScore = s
      }
    }
    if (best && bestScore >= JACCARD_MIN) return { entry: best.entry, how: 'jaccard', score: bestScore }
  }
  return null
}

// ----------------------------------------------------------------------------- fallback

/** The answer for questions the snapshot does not cover: lists the demo questions and the context's suggestions. */
export function fallbackAnswer(chat: SnapshotChat, ctx?: ChatContext | null): AnalystAnswer {
  const demo = chat.suggestions[GLOBAL_KEY] ?? []
  const contextual = suggestionsFor(chat, { alert_id: ctx?.alert_id, node_id: ctx?.node_id ?? ctx?.selected_node_ids?.[0], storyline_id: ctx?.storyline_id }).filter((q) => !demo.includes(q))
  const bullets = (qs: string[]) => qs.map((q) => `- ${q}`).join('\n')
  const narrative = [
    '### Static edition',
    '',
    'This build has no query engine or language model behind it: the analyst replays answers that were precomputed for the demo questions and for the suggested questions of each alert, storyline and selected node. I could not match your question to one of them.',
    '',
    '**Prepared questions**',
    demo.length ? bullets(demo) : '- (no global questions were recorded in this snapshot)',
    ...(contextual.length ? ['', '**For the current context**', bullets(contextual)] : []),
    '',
    'Run the container (`make demo`) to ask free-form questions against the live graph.',
  ].join('\n')
  const followups = [...new Set([...contextual.slice(0, 4), ...demo])].slice(0, 6)
  return { narrative_md: narrative, findings: [], evidence: emptyFragment(), confidence: 0, followups, tool_calls: [], mode: 'offline', intent: 'help', model: null }
}

// ----------------------------------------------------------------------------- sessions and replay

const sessions = new Map<string, ChatSession>()
let seq = 1

export function createSession(context?: ChatContext | null): ChatSession {
  const id = `static-session-${seq++}`
  const session: ChatSession = { id, created_at: new Date().toISOString(), turns: [], context: (context ?? {}) as Record<string, JsonValue | undefined> }
  sessions.set(id, session)
  return session
}

export function getSession(id: string): ChatSession | undefined {
  return sessions.get(id)
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException('aborted', 'AbortError'))
    const onAbort = () => {
      clearTimeout(timer)
      reject(new DOMException('aborted', 'AbortError'))
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

/** Defensive copy with every optional collection present, so the UI never sees `undefined` where the API sends `[]`. */
function completeAnswer(answer: AnalystAnswer): AnalystAnswer {
  return {
    ...answer,
    narrative_md: answer.narrative_md ?? '',
    findings: answer.findings ?? [],
    evidence: answer.evidence ?? emptyFragment(),
    followups: answer.followups ?? [],
    tool_calls: answer.tool_calls ?? [],
    mode: answer.mode ?? 'offline',
    confidence: typeof answer.confidence === 'number' ? answer.confidence : 0,
    model: answer.model ?? null,
  }
}

/** Replay a precomputed answer as `session`, `tool_call`/`tool_result` pairs, `evidence`, `text_delta` chunks, `answer`, `done`. */
export async function snapshotStream(sessionId: string, body: ChatMessageIn, onEvent: (evt: ChatEvent) => void, signal?: AbortSignal): Promise<void> {
  const session = sessions.get(sessionId) ?? createSession(body.context)
  const started = performance.now()
  const chat = await loadChat()
  const match = matchAnswer(chat, body.content, body.context)
  const answer = await hydratePayload(completeAnswer(match ? match.entry.answer : fallbackAnswer(chat, body.context)))
  onEvent({ type: 'session', data: { session_id: session.id, mode: answer.mode, model: answer.model ?? null } })
  await sleep(TOOL_PACE_MS, signal)
  for (const [i, call] of answer.tool_calls.entries()) {
    const id = `call_${i + 1}`
    onEvent({ type: 'tool_call', data: { id, name: call.name, arguments: call.arguments ?? {} } })
    await sleep(TOOL_PACE_MS, signal)
    onEvent({ type: 'tool_result', data: { id, name: call.name, summary: call.summary ?? '', duration_ms: call.duration_ms ?? 0, error: call.error ?? null } })
  }
  if (answer.evidence.nodes.length) {
    onEvent({ type: 'evidence', data: answer.evidence })
    await sleep(80, signal)
  }
  const words = answer.narrative_md.split(/(\s+)/)
  let buffer = ''
  for (let i = 0; i < words.length; i++) {
    buffer += words[i]
    if (i % (WORDS_PER_CHUNK * 2) === WORDS_PER_CHUNK * 2 - 1 || i === words.length - 1) {
      if (buffer) onEvent({ type: 'text_delta', data: { text: buffer } })
      buffer = ''
      await sleep(TEXT_PACE_MS, signal)
    }
  }
  onEvent({ type: 'answer', data: answer })
  const now = new Date().toISOString()
  session.turns.push({ role: 'user', content: body.content, created_at: now })
  session.turns.push({ role: 'assistant', content: answer.narrative_md, answer, created_at: now })
  onEvent({ type: 'done', data: { mode: answer.mode, model: answer.model ?? null, tool_calls: answer.tool_calls.length, elapsed_ms: Math.round(performance.now() - started) } })
}
