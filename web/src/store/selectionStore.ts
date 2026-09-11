import { create } from 'zustand'

interface SelectionState {
  selectedNodeId: string | null
  pinned: string[]
  select: (id: string | null) => void
  togglePin: (id: string) => void
  isPinned: (id: string) => boolean
}

export const useSelectionStore = create<SelectionState>((set, get) => ({
  selectedNodeId: null,
  pinned: [],
  select: (id) => set({ selectedNodeId: id }),
  togglePin: (id) => set((s) => ({ pinned: s.pinned.includes(id) ? s.pinned.filter((p) => p !== id) : [...s.pinned, id] })),
  isPinned: (id) => get().pinned.includes(id),
}))
