import { useMemo } from 'react'
import type { GraphFragment } from '../../api/types'
import { LabelIcon } from '../../components/LabelIcon'
import { CATEGORY_NAMES, CATEGORY_ORDER, categoryOf } from '../../graph/schema'
import { cn } from '../../lib/format'
import { categoryColor } from '../../theme'

interface Props {
  loaded: GraphFragment
  hiddenLabels: Set<string>
  hiddenEdges: Set<string>
  onHiddenLabels: (s: Set<string>) => void
  onHiddenEdges: (s: Set<string>) => void
}

/** Label/category and edge-type visibility filters for what is currently drawn. */
export function FiltersPanel({ loaded, hiddenLabels, hiddenEdges, onHiddenLabels, onHiddenEdges }: Props) {
  const labelCounts = useMemo(() => {
    const m = new Map<string, number>()
    for (const n of loaded.nodes) m.set(n.label, (m.get(n.label) ?? 0) + 1)
    return m
  }, [loaded.nodes])
  const edgeCounts = useMemo(() => {
    const m = new Map<string, { count: number; derived: boolean }>()
    for (const e of loaded.edges) m.set(e.type, { count: (m.get(e.type)?.count ?? 0) + 1, derived: !!e.derived })
    return m
  }, [loaded.edges])
  const byCategory = CATEGORY_ORDER.map((c) => [c, [...labelCounts.keys()].filter((l) => categoryOf(l) === c).sort()] as const).filter(([, ls]) => ls.length)
  const toggle = (set: Set<string>, key: string, apply: (s: Set<string>) => void) => {
    const next = new Set(set)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    apply(next)
  }
  const setMany = (set: Set<string>, keys: string[], hidden: boolean, apply: (s: Set<string>) => void) => {
    const next = new Set(set)
    for (const k of keys) if (hidden) next.add(k)
    else next.delete(k)
    apply(next)
  }
  const derivedTypes = [...edgeCounts.entries()].filter(([, v]) => v.derived).map(([k]) => k)
  const derivedHidden = derivedTypes.length > 0 && derivedTypes.every((t) => hiddenEdges.has(t))
  if (!loaded.nodes.length) return <div className="text-xs text-fg-3">Load a seed first; filters apply to what is drawn.</div>
  return (
    <div className="space-y-3 text-xs">
      <div className="flex items-center justify-between">
        <span className="panel-title">Node labels</span>
        <span className="flex gap-2 text-[10.5px]">
          <button type="button" className="text-accent hover:underline" onClick={() => onHiddenLabels(new Set())}>show all</button>
        </span>
      </div>
      {byCategory.map(([cat, labels]) => (
        <div key={cat}>
          <div className="mb-0.5 flex items-center justify-between text-[10.5px] uppercase tracking-wider text-fg-3">
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: categoryColor(cat) }} />
              {CATEGORY_NAMES[cat]}
            </span>
            <span className="flex gap-1.5 normal-case tracking-normal">
              <button type="button" className="hover:text-fg" onClick={() => setMany(hiddenLabels, labels, false, onHiddenLabels)}>all</button>
              <button type="button" className="hover:text-fg" onClick={() => setMany(hiddenLabels, labels, true, onHiddenLabels)}>none</button>
            </span>
          </div>
          {labels.map((l) => (
            <label key={l} className={cn('flex cursor-pointer items-center gap-1.5 rounded px-1 py-[1px] hover:bg-panel-3', hiddenLabels.has(l) && 'opacity-50')}>
              <input type="checkbox" className="h-3 w-3 accent-sky-400" checked={!hiddenLabels.has(l)} onChange={() => toggle(hiddenLabels, l, onHiddenLabels)} />
              <LabelIcon label={l} size={12} />
              <span className="flex-1 text-fg">{l}</span>
              <span className="tabular-nums text-fg-3">{labelCounts.get(l)}</span>
            </label>
          ))}
        </div>
      ))}
      <div className="flex items-center justify-between">
        <span className="panel-title">Edge types</span>
        <span className="flex gap-2 text-[10.5px]">
          <button type="button" className="text-accent hover:underline" onClick={() => onHiddenEdges(new Set())}>show all</button>
          {derivedTypes.length > 0 && (
            <button type="button" className="hover:text-fg" onClick={() => setMany(hiddenEdges, derivedTypes, !derivedHidden, onHiddenEdges)}>
              {derivedHidden ? 'show derived' : 'hide derived'}
            </button>
          )}
        </span>
      </div>
      <div className="grid grid-cols-1 gap-y-[1px]">
        {[...edgeCounts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([t, v]) => (
          <label key={t} className={cn('flex cursor-pointer items-center gap-1.5 rounded px-1 py-[1px] hover:bg-panel-3', hiddenEdges.has(t) && 'opacity-50')}>
            <input type="checkbox" className="h-3 w-3 accent-sky-400" checked={!hiddenEdges.has(t)} onChange={() => toggle(hiddenEdges, t, onHiddenEdges)} />
            <span className={cn('mono flex-1 text-[11px]', v.derived ? 'text-fg-2' : 'text-fg')}>{t}</span>
            {v.derived && <span className="text-[9.5px] uppercase text-fg-3">derived</span>}
            <span className="tabular-nums text-fg-3">{v.count}</span>
          </label>
        ))}
      </div>
    </div>
  )
}
