import { ChevronLeft, ChevronRight } from 'lucide-react'
import { cn, fmtNum } from '../lib/format'

interface Props {
  total: number
  limit: number
  offset: number
  onChange: (next: { offset: number; limit: number }) => void
  pageSizes?: number[]
  className?: string
}

export function Pagination({ total, limit, offset, onChange, pageSizes = [25, 50, 100, 200], className }: Props) {
  const from = total === 0 ? 0 : offset + 1
  const to = Math.min(total, offset + limit)
  const page = Math.floor(offset / limit) + 1
  const pages = Math.max(1, Math.ceil(total / limit))
  return (
    <div className={cn('flex flex-wrap items-center justify-between gap-2 text-xs text-fg-2', className)}>
      <span className="tabular-nums">
        {fmtNum(from)}–{fmtNum(to)} of {fmtNum(total)}
      </span>
      <div className="flex items-center gap-2">
        <label className="flex items-center gap-1 text-fg-3">
          per page
          <select className="select h-7 py-0" value={limit} onChange={(e) => onChange({ offset: 0, limit: Number(e.target.value) })}>
            {pageSizes.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="btn-icon" disabled={offset === 0} onClick={() => onChange({ offset: Math.max(0, offset - limit), limit })} aria-label="Previous page">
          <ChevronLeft size={13} />
        </button>
        <span className="tabular-nums text-fg-3">
          {page} / {pages}
        </span>
        <button type="button" className="btn-icon" disabled={offset + limit >= total} onClick={() => onChange({ offset: offset + limit, limit })} aria-label="Next page">
          <ChevronRight size={13} />
        </button>
      </div>
    </div>
  )
}
