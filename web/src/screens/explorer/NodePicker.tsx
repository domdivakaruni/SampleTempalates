import { MousePointer2, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useSearch } from '../../api/hooks'
import type { SearchHit } from '../../api/types'
import { LabelIcon } from '../../components/LabelIcon'
import { labelForId } from '../../graph/schema'
import { cn, shortId } from '../../lib/format'

interface Props {
  value: string
  onChange: (id: string, hit?: SearchHit) => void
  placeholder?: string
  /** Currently selected canvas node; offers a one-click "use selected". */
  selectedId?: string | null
  labels?: string[]
  className?: string
}

/** Typeahead for a node id backed by GET /search. */
export function NodePicker({ value, onChange, placeholder = 'Search a node…', selectedId, labels, className }: Props) {
  const [text, setText] = useState('')
  const [open, setOpen] = useState(false)
  const q = useSearch(text, labels, open)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const onDown = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false)
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [])
  const hits = q.data?.hits ?? []
  if (value) {
    return (
      <div className={cn('input flex items-center gap-1.5 py-1', className)} title={value}>
        <LabelIcon label={labelForId(value) ?? 'Unknown'} size={12} />
        <span className="min-w-0 flex-1 truncate">{shortId(value)}</span>
        <button type="button" className="text-fg-3 hover:text-fg" onClick={() => onChange('')} aria-label="Clear">
          <X size={12} />
        </button>
      </div>
    )
  }
  return (
    <div ref={box} className={cn('relative', className)}>
      <div className="input flex items-center gap-1 py-1">
        <input value={text} onChange={(e) => { setText(e.target.value); setOpen(true) }} onFocus={() => setOpen(true)} placeholder={placeholder} className="w-full bg-transparent focus:outline-none" />
        {selectedId && (
          <button type="button" className="flex shrink-0 items-center gap-0.5 text-[10px] text-accent hover:underline" onClick={() => onChange(selectedId)} title={`Use the selected node ${selectedId}`}>
            <MousePointer2 size={10} /> selected
          </button>
        )}
      </div>
      {open && text.trim().length >= 2 && (
        <div className="absolute left-0 right-0 top-full z-40 mt-1 max-h-60 overflow-y-auto rounded-md border border-line-2 bg-panel-2 shadow-xl">
          {hits.length === 0 && <div className="px-2 py-2 text-[11px] text-fg-3">{q.isFetching ? 'Searching…' : 'No matches'}</div>}
          {hits.map((h) => (
            <button key={h.id} type="button" className="flex w-full items-center gap-2 px-2 py-1 text-left text-xs hover:bg-panel-3" onClick={() => { onChange(h.id, h); setOpen(false); setText('') }}>
              <LabelIcon label={h.label} category={h.category} size={12} />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-fg">{h.name}</span>
                <span className="block truncate text-[10px] text-fg-3">{h.label}{h.snippet ? ` · ${h.snippet}` : ''}</span>
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
