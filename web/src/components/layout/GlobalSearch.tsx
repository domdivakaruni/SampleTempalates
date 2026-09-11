import { Search } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSearch } from '../../api/hooks'
import type { Category, SearchHit } from '../../api/types'
import { CATEGORY_NAMES, CATEGORY_ORDER } from '../../graph/schema'
import { cn } from '../../lib/format'
import { categoryColor } from '../../theme'
import { LabelIcon } from '../LabelIcon'

/** Top-bar global search: hits grouped by category; Enter opens the first hit in the explorer. */
export function GlobalSearch() {
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const navigate = useNavigate()
  const search = useSearch(q, undefined, open)
  const boxRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const grouped = useMemo(() => {
    const hits = search.data?.hits ?? []
    const byCat = new Map<string, SearchHit[]>()
    for (const h of hits) {
      if (!byCat.has(h.category)) byCat.set(h.category, [])
      byCat.get(h.category)!.push(h)
    }
    const order = [...CATEGORY_ORDER, 'unknown'] as string[]
    const groups = [...byCat.entries()].sort(([a], [b]) => order.indexOf(a) - order.indexOf(b))
    const flat = groups.flatMap(([, hs]) => hs)
    return { groups, flat }
  }, [search.data])

  useEffect(() => {
    const onDown = (e: MouseEvent) => boxRef.current && !boxRef.current.contains(e.target as Node) && setOpen(false)
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement))) {
        e.preventDefault()
        inputRef.current?.focus()
        setOpen(true)
      }
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [])

  const go = (hit: SearchHit) => {
    setOpen(false)
    setQ('')
    if (hit.label === 'Alert') navigate(`/alerts/${encodeURIComponent(hit.id)}`)
    else if (hit.label === 'Storyline') navigate(`/storylines/${encodeURIComponent(hit.id)}`)
    else if (hit.label === 'ThreatActor') navigate(`/threat-intel/actors/${encodeURIComponent(hit.id)}`)
    else if (hit.label === 'Campaign') navigate(`/threat-intel/campaigns/${encodeURIComponent(hit.id)}`)
    else if (hit.label === 'IntelReport') navigate(`/threat-intel/reports/${encodeURIComponent(hit.id)}`)
    else navigate(`/explorer?seed=${encodeURIComponent(hit.id)}`)
  }

  return (
    <div ref={boxRef} className="relative w-full max-w-[520px]">
      <div className="flex items-center gap-2 rounded-md border border-line-2 bg-bg px-2.5 py-1.5 focus-within:border-accent-2">
        <Search size={13} className="text-fg-3" />
        <input
          ref={inputRef}
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setOpen(true)
            setActive(0)
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, grouped.flat.length - 1)) }
            else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)) }
            else if (e.key === 'Enter' && grouped.flat[active]) go(grouped.flat[active])
            else if (e.key === 'Escape') setOpen(false)
          }}
          placeholder="Search hosts, roles, buckets, alerts, IOCs…  ( / or ⌘K )"
          className="w-full bg-transparent text-xs text-fg placeholder:text-fg-3 focus:outline-none"
        />
        {search.isFetching && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />}
      </div>
      {open && q.trim().length >= 2 && (
        <div className="absolute left-0 right-0 top-full z-50 mt-1 max-h-[420px] overflow-y-auto rounded-md border border-line-2 bg-panel-2 shadow-2xl">
          {grouped.flat.length === 0 && <div className="px-3 py-3 text-xs text-fg-3">{search.isFetching ? 'Searching…' : 'No matches'}</div>}
          {grouped.groups.map(([cat, hits]) => (
            <div key={cat}>
              <div className="sticky top-0 flex items-center gap-1.5 bg-panel-2 px-3 py-1 text-[10px] uppercase tracking-wider text-fg-3">
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: categoryColor(cat) }} />
                {CATEGORY_NAMES[cat as Category] ?? cat}
              </div>
              {hits.map((h) => {
                const idx = grouped.flat.indexOf(h)
                return (
                  <button
                    key={h.id}
                    type="button"
                    onMouseEnter={() => setActive(idx)}
                    onClick={() => go(h)}
                    className={cn('flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-panel-3', idx === active && 'bg-panel-3')}
                  >
                    <LabelIcon label={h.label} category={h.category} size={13} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-fg">{h.name}</span>
                      <span className="block truncate text-[10.5px] text-fg-3">
                        {h.label}
                        {h.snippet ? ` · ${h.snippet}` : ''}
                      </span>
                    </span>
                    <span className="mono max-w-[180px] truncate text-[10px] text-fg-3">{h.id}</span>
                  </button>
                )
              })}
            </div>
          ))}
          <div className="border-t border-line px-3 py-1 text-[10px] text-fg-3">
            <span className="kbd">↑↓</span> navigate · <span className="kbd">Enter</span> open in explorer · <span className="kbd">Esc</span> close
          </div>
        </div>
      )}
    </div>
  )
}
