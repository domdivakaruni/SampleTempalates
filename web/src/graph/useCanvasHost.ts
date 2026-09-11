import { useEffect, useRef, type RefObject } from 'react'
import { useCanvasStore } from '../store/canvasStore'
import type { GraphCanvasHandle } from './GraphCanvas'

/**
 * Register a mounted GraphCanvas as the active target of the highlight bus so analyst evidence lands on it.
 * Handles: inbox fragments (merge/set), highlight sets, focus requests and clear requests.
 */
export function useCanvasHost(id: string, ref: RefObject<GraphCanvasHandle | null>) {
  const registerCanvas = useCanvasStore((s) => s.registerCanvas)
  const unregisterCanvas = useCanvasStore((s) => s.unregisterCanvas)
  const inbox = useCanvasStore((s) => s.inbox)
  const autoHighlight = useCanvasStore((s) => s.autoHighlight)
  const highlightSeq = useCanvasStore((s) => s.highlightSeq)
  const highlightIds = useCanvasStore((s) => s.highlightIds)
  const focusSeq = useCanvasStore((s) => s.focusSeq)
  const focusId = useCanvasStore((s) => s.focusId)
  const clearSeq = useCanvasStore((s) => s.clearSeq)
  const seen = useRef({ inbox: inbox?.seq ?? 0, highlight: highlightSeq, focus: focusSeq, clear: clearSeq })

  useEffect(() => {
    registerCanvas(id)
    return () => unregisterCanvas(id)
  }, [id, registerCanvas, unregisterCanvas])

  useEffect(() => {
    if (!inbox || inbox.seq === seen.current.inbox) return
    seen.current.inbox = inbox.seq
    const h = ref.current
    if (!h) return
    if (inbox.mode === 'set') h.setFragment(inbox.fragment)
    else h.mergeFragment(inbox.fragment, { highlight: autoHighlight })
  }, [inbox, autoHighlight, ref])

  useEffect(() => {
    if (highlightSeq === seen.current.highlight) return
    seen.current.highlight = highlightSeq
    ref.current?.highlight(highlightIds, { dim: true, fit: true })
  }, [highlightSeq, highlightIds, ref])

  useEffect(() => {
    if (focusSeq === seen.current.focus || !focusId) return
    seen.current.focus = focusSeq
    ref.current?.focus(focusId)
  }, [focusSeq, focusId, ref])

  useEffect(() => {
    if (clearSeq === seen.current.clear) return
    seen.current.clear = clearSeq
    ref.current?.clearHighlights()
  }, [clearSeq, ref])
}
