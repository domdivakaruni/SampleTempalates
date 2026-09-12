import { useNavigate } from 'react-router-dom'
import type { NodeOut } from '../api/types'
import { labelForId } from '../graph/schema'
import { cn, shortId } from '../lib/format'
import { useCanvasStore } from '../store/canvasStore'
import { LabelIcon } from './LabelIcon'

interface Props {
  node?: NodeOut | null
  id?: string
  name?: string
  label?: string
  className?: string
  mode?: 'focus' | 'explorer' | 'select'
  onSelect?: (id: string) => void
  mono?: boolean
}

/** `database:aws:111111111111:cardholder-db` -> `cardholder-db`; three-segment ids keep their tail. */
function fallbackName(id: string): string {
  const parts = id.split(':')
  return parts.length > 3 ? parts[parts.length - 1] : shortId(id)
}

/** Clickable node reference (icon + name). `focus` mode focuses the active canvas; `explorer` opens the node in the explorer. */
export function NodeRef({ node, id, name, label, className, mode = 'focus', onSelect, mono }: Props) {
  const navigate = useNavigate()
  const focus = useCanvasStore((s) => s.focus)
  const active = useCanvasStore((s) => s.activeCanvas)
  const nid = node?.id ?? id ?? ''
  const nlabel = node?.label ?? label ?? labelForId(nid) ?? 'Unknown'
  const nname = node?.name ?? name ?? fallbackName(nid)
  const click = () => {
    if (mode === 'select' && onSelect) return onSelect(nid)
    if (mode === 'focus' && active) return focus(nid)
    navigate(`/explorer?id=${encodeURIComponent(nid)}`)
  }
  return (
    <button type="button" onClick={click} className={cn('inline-flex max-w-full items-center gap-1 rounded px-1 py-[1px] text-left hover:bg-panel-3', className)} title={nid}>
      <LabelIcon label={nlabel} category={node?.category} severity={node?.severity} size={12} />
      <span className={cn('truncate text-fg', mono && 'mono text-[11px]')}>{nname}</span>
    </button>
  )
}
