/**
 * Highlight bus between the Analyst drawer and whichever graph canvas is visible.
 * A canvas host registers itself on mount; evidence fragments published by the drawer are delivered to the active host.
 */
import { create } from 'zustand'
import type { GraphFragment, LayoutHint } from '../api/types'
import { mergeFragment } from '../graph/elements'

export interface CanvasInbox { seq: number; fragment: GraphFragment; mode: 'merge' | 'set' }

interface CanvasState {
  activeCanvas: string | null
  inbox: CanvasInbox | null
  evidence: GraphFragment | null
  highlightIds: string[]
  highlightSeq: number
  focusId: string | null
  focusSeq: number
  clearSeq: number
  autoHighlight: boolean
  layoutHint: LayoutHint | null
  explorerSeed: GraphFragment | null
  registerCanvas: (id: string) => void
  unregisterCanvas: (id: string) => void
  publish: (fragment: GraphFragment, mode?: 'merge' | 'set') => boolean
  resetEvidence: () => void
  setHighlight: (ids: string[]) => void
  focus: (id: string) => void
  clearHighlights: () => void
  setAutoHighlight: (v: boolean) => void
  setExplorerSeed: (f: GraphFragment | null) => void
}

export const useCanvasStore = create<CanvasState>((set, get) => ({
  activeCanvas: null,
  inbox: null,
  evidence: null,
  highlightIds: [],
  highlightSeq: 0,
  focusId: null,
  focusSeq: 0,
  clearSeq: 0,
  autoHighlight: true,
  layoutHint: null,
  explorerSeed: null,
  registerCanvas: (id) => set({ activeCanvas: id }),
  unregisterCanvas: (id) => set((s) => (s.activeCanvas === id ? { activeCanvas: null } : {})),
  publish: (fragment, mode = 'merge') => {
    const s = get()
    const evidence = s.evidence && mode === 'merge' ? mergeFragment(s.evidence, fragment) : fragment
    const delivered = !!s.activeCanvas
    set({ evidence, layoutHint: fragment.layout_hint, inbox: delivered ? { seq: (s.inbox?.seq ?? 0) + 1, fragment, mode } : s.inbox })
    return delivered
  },
  resetEvidence: () => set({ evidence: null }),
  setHighlight: (ids) => set((s) => ({ highlightIds: ids, highlightSeq: s.highlightSeq + 1 })),
  focus: (id) => set((s) => ({ focusId: id, focusSeq: s.focusSeq + 1 })),
  clearHighlights: () => set((s) => ({ highlightIds: [], clearSeq: s.clearSeq + 1 })),
  setAutoHighlight: (v) => set({ autoHighlight: v }),
  setExplorerSeed: (f) => set({ explorerSeed: f }),
}))
