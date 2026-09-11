import { useEffect, useRef, type ReactNode } from 'react'
import type { NodeOut } from '../api/types'
import { LabelIcon } from '../components/LabelIcon'

export interface ContextAction {
  id: string
  label: string
  icon?: ReactNode
  onSelect: () => void
  disabled?: boolean
  hint?: string
}

interface Props {
  x: number
  y: number
  node: NodeOut
  actions: ContextAction[]
  onClose: () => void
}

export function ContextMenu({ x, y, node, actions, onClose }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [onClose])
  return (
    <div ref={ref} className="absolute z-40 min-w-[210px] rounded-md border border-line-2 bg-panel-2 py-1 shadow-2xl" style={{ left: x + 6, top: y + 6 }}>
      <div className="flex items-center gap-2 border-b border-line px-3 py-1.5">
        <LabelIcon label={node.label} category={node.category} severity={node.severity} size={13} />
        <div className="min-w-0">
          <div className="truncate text-xs font-medium text-fg">{node.name}</div>
          <div className="truncate text-[10px] text-fg-3">{node.label}</div>
        </div>
      </div>
      {actions.length === 0 && <div className="px-3 py-2 text-[11px] text-fg-3">No actions</div>}
      {actions.map((a) => (
        <button
          key={a.id}
          type="button"
          disabled={a.disabled}
          className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs text-fg hover:bg-panel-3 disabled:opacity-40"
          onClick={() => {
            a.onSelect()
            onClose()
          }}
          title={a.hint}
        >
          <span className="text-fg-3">{a.icon}</span>
          {a.label}
        </button>
      ))}
    </div>
  )
}
