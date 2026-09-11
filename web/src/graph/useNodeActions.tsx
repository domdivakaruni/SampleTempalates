import { Bot, Copy, Crosshair, Expand, ExternalLink, Pin, PinOff, Route } from 'lucide-react'
import { useCallback, type RefObject } from 'react'
import { useNavigate } from 'react-router-dom'
import type { NodeOut } from '../api/types'
import { useDrawerStore } from '../store/drawerStore'
import { useSelectionStore } from '../store/selectionStore'
import type { ContextAction } from './ContextMenu'
import type { GraphCanvasHandle } from './GraphCanvas'
import { useCanvasOps } from './useCanvasOps'

/** Default right-click actions for any canvas: expand, blast radius, attack paths, ask analyst, pin, open in explorer. */
export function useNodeActions(ref: RefObject<GraphCanvasHandle | null>, opts: { inExplorer?: boolean } = {}) {
  const navigate = useNavigate()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const togglePin = useSelectionStore((s) => s.togglePin)
  const pinned = useSelectionStore((s) => s.pinned)
  const ops = useCanvasOps(ref)

  return useCallback(
    (node: NodeOut): ContextAction[] => {
      const isPinned = pinned.includes(node.id)
      const actions: ContextAction[] = [
        { id: 'expand', label: 'Expand neighborhood', icon: <Expand size={13} />, onSelect: () => void ops.expand(node.id), hint: 'GET /graph/neighborhood depth=1' },
        { id: 'blast', label: 'Blast radius', icon: <Crosshair size={13} />, onSelect: () => void ops.blast(node.id), hint: 'GET /graph/blast-radius' },
        { id: 'paths', label: 'Attack paths through this', icon: <Route size={13} />, onSelect: () => void ops.attackPaths(node.id), hint: 'GET /graph/attack-paths' },
        { id: 'ask', label: 'Ask analyst about this', icon: <Bot size={13} />, onSelect: () => askAbout(`What is ${node.name} (${node.id}) and what can an attacker reach from it?`, { node_id: node.id, selected_node_ids: [node.id] }) },
        { id: 'pin', label: isPinned ? 'Unpin' : 'Pin', icon: isPinned ? <PinOff size={13} /> : <Pin size={13} />, onSelect: () => {
          togglePin(node.id)
          ref.current?.cy()?.getElementById(node.id).toggleClass('pinned', !isPinned)
        } },
        { id: 'copy', label: 'Copy id', icon: <Copy size={13} />, onSelect: () => void navigator.clipboard?.writeText(node.id).catch(() => undefined) },
      ]
      if (!opts.inExplorer) actions.splice(4, 0, { id: 'explorer', label: 'Open in explorer', icon: <ExternalLink size={13} />, onSelect: () => navigate(`/explorer?id=${encodeURIComponent(node.id)}`) })
      return actions
    },
    [askAbout, navigate, ops, opts.inExplorer, pinned, ref, togglePin],
  )
}
