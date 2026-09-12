/**
 * Minimal Server-Sent-Events reader over `fetch` + `ReadableStream`.
 * We cannot use EventSource because the chat endpoint is a POST. Frames are `event: <type>` + `data: <json>` + blank line.
 */

export interface RawSseEvent { event: string; data: string; id?: string }

export async function readSseStream(
  body: ReadableStream<Uint8Array>,
  onEvent: (evt: RawSseEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const reader = body.getReader()
  const decoder = new TextDecoder('utf-8')
  let buffer = ''
  const abort = () => reader.cancel().catch(() => undefined)
  signal?.addEventListener('abort', abort, { once: true })
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      buffer = buffer.replace(/\r\n/g, '\n')
      let idx: number
      while ((idx = buffer.indexOf('\n\n')) >= 0) {
        const frame = buffer.slice(0, idx)
        buffer = buffer.slice(idx + 2)
        const evt = parseFrame(frame)
        if (evt) onEvent(evt)
      }
    }
    buffer += decoder.decode()
    const tail = parseFrame(buffer)
    if (tail) onEvent(tail)
  } finally {
    signal?.removeEventListener('abort', abort)
    reader.releaseLock()
  }
}

export function parseFrame(frame: string): RawSseEvent | null {
  if (!frame.trim()) return null
  let event = 'message'
  let id: string | undefined
  const data: string[] = []
  for (const line of frame.split('\n')) {
    if (!line || line.startsWith(':')) continue
    const colon = line.indexOf(':')
    const field = colon < 0 ? line : line.slice(0, colon)
    let value = colon < 0 ? '' : line.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    if (field === 'event') event = value
    else if (field === 'data') data.push(value)
    else if (field === 'id') id = value
  }
  if (data.length === 0) return null
  return { event, data: data.join('\n'), id }
}
