/** Imperative canvas operations shared by screens, context menus and detail panels. */
import { useCallback, useMemo, type RefObject } from 'react'
import { api } from '../api/client'
import type { AttackPathsOut, BlastRadiusResult, GraphFragment, PathOut } from '../api/types'
import type { GraphCanvasHandle } from './GraphCanvas'

export interface CanvasOps {
  /** GET /graph/neighborhood depth=1 merged into the canvas, focusing the node. */
  expand: (id: string) => Promise<GraphFragment | undefined>
  /** GET /graph/blast-radius merged into the canvas; crown jewels and secrets highlighted. */
  blast: (id: string, depth?: number) => Promise<BlastRadiusResult | undefined>
  /** GET /graph/attack-paths through the node; the first path is highlighted. */
  attackPaths: (id: string) => Promise<AttackPathsOut | undefined>
  /** Highlight ids; nodes missing from the canvas are fetched with POST /nodes/batch and merged first. */
  highlight: (ids: string[], opts?: { fetchMissing?: boolean; fit?: boolean }) => Promise<void>
  showPath: (path: PathOut) => void
  merge: (fragment: GraphFragment, opts?: { highlight?: boolean }) => void
}

export function useCanvasOps(ref: RefObject<GraphCanvasHandle | null>): CanvasOps {
  const expand = useCallback(
    async (id: string) => {
      const frag = await api.neighborhood({ id, depth: 1, max_nodes: 60 })
      ref.current?.mergeFragment(frag)
      ref.current?.focus(id)
      return frag
    },
    [ref],
  )

  const blast = useCallback(
    async (id: string, depth = 4) => {
      const res = await api.blastRadius({ id, depth, max_nodes: 150 })
      const h = ref.current
      if (!h) return res
      h.mergeFragment(res.fragment)
      const important = res.fragment.nodes.filter((n) => n.tags.includes('crown_jewel') || n.label === 'Secret').map((n) => n.id)
      h.highlight([id, ...important, ...res.fragment.edges.map((e) => e.id)])
      return res
    },
    [ref],
  )

  const attackPaths = useCallback(
    async (id: string) => {
      const res = await api.attackPaths({ through: id, k: 3 })
      const h = ref.current
      if (!h || !res.paths.length) return res
      h.mergeFragment(res.fragment)
      const p = res.paths[0].fragment.paths[0]
      h.highlight(p ? [...p.node_ids, ...p.edge_ids] : res.paths[0].fragment.nodes.map((n) => n.id))
      return res
    },
    [ref],
  )

  const highlight = useCallback(
    async (ids: string[], opts: { fetchMissing?: boolean; fit?: boolean } = {}) => {
      const h = ref.current
      if (!h) return
      const wanted = [...new Set(ids.filter(Boolean))]
      const missingNodes = wanted.filter((id) => !id.includes('|') && !h.has(id))
      if ((opts.fetchMissing ?? true) && missingNodes.length && missingNodes.length <= 50) {
        try {
          const res = await api.nodesBatch(missingNodes)
          if (res.nodes.length) h.mergeFragment({ nodes: res.nodes, edges: [], paths: [], focus: [], layout_hint: 'neighborhood', truncated: false, meta: {} })
        } catch {
          /* highlight what is present */
        }
      }
      h.highlight(wanted, { dim: true, fit: opts.fit ?? true })
    },
    [ref],
  )

  const showPath = useCallback((path: PathOut) => ref.current?.highlight([...path.node_ids, ...path.edge_ids], { dim: true, fit: true }), [ref])
  const merge = useCallback((fragment: GraphFragment, opts: { highlight?: boolean } = {}) => ref.current?.mergeFragment(fragment, { highlight: opts.highlight }), [ref])

  return useMemo(() => ({ expand, blast, attackPaths, highlight, showPath, merge }), [expand, blast, attackPaths, highlight, showPath, merge])
}
