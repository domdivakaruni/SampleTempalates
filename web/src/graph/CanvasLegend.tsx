import type { GraphFragment } from '../api/types'
import { CATEGORY_NAMES, CATEGORY_ORDER, categoryOf } from './schema'
import { categoryColor } from '../theme'

/** Compact legend for the categories present on a canvas plus the derived-edge and badge conventions. */
export function CanvasLegend({ fragment, className }: { fragment: GraphFragment | null | undefined; className?: string }) {
  if (!fragment || !fragment.nodes.length) return null
  const present = new Set(fragment.nodes.map((n) => (n.category && n.category !== 'unknown' ? n.category : categoryOf(n.label))))
  const cats = CATEGORY_ORDER.filter((c) => present.has(c))
  const derived = fragment.edges.some((e) => e.derived)
  const crown = fragment.nodes.some((n) => n.tags.includes('crown_jewel'))
  const exposed = fragment.nodes.some((n) => n.tags.includes('internet_exposed'))
  return (
    <div className={`pointer-events-none absolute bottom-2 left-2 z-10 flex flex-wrap items-center gap-x-2.5 gap-y-1 rounded-md border border-line bg-panel/85 px-2 py-1 text-[10px] text-fg-2 backdrop-blur ${className ?? ''}`}>
      {cats.map((c) => (
        <span key={c} className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full" style={{ background: categoryColor(c) }} />
          {CATEGORY_NAMES[c].split(' ')[0].replace(',', '')}
        </span>
      ))}
      {derived && (
        <span className="flex items-center gap-1">
          <span className="inline-block w-4 border-t border-dashed border-fg-2" /> derived
        </span>
      )}
      {crown && (
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-sev-medium" /> crown jewel
        </span>
      )}
      {exposed && (
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-accent" /> internet-exposed
        </span>
      )}
    </div>
  )
}
