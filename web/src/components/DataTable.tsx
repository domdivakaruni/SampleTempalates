import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react'
import { useMemo, useState, type ReactNode } from 'react'
import { cn } from '../lib/format'
import { EmptyState } from './states'

export interface Column<T> {
  key: string
  header: ReactNode
  render: (row: T) => ReactNode
  sortValue?: (row: T) => string | number | null | undefined
  width?: string
  align?: 'left' | 'right' | 'center'
  className?: string
}

interface Props<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  onRowClick?: (row: T) => void
  defaultSort?: { key: string; dir: 'asc' | 'desc' }
  sort?: { key: string; dir: 'asc' | 'desc' } | null
  onSortChange?: (s: { key: string; dir: 'asc' | 'desc' }) => void
  emptyTitle?: string
  emptyHint?: ReactNode
  dense?: boolean
  className?: string
  rowClassName?: (row: T) => string | undefined
  selectedKey?: string | null
  stickyHeader?: boolean
}

/** Dense sortable table. Sorting is client-side unless `sort`/`onSortChange` are provided (server-side). */
export function DataTable<T>({ columns, rows, rowKey, onRowClick, defaultSort, sort, onSortChange, emptyTitle = 'No rows', emptyHint, className, rowClassName, selectedKey, stickyHeader = true }: Props<T>) {
  const [localSort, setLocalSort] = useState<{ key: string; dir: 'asc' | 'desc' } | null>(defaultSort ?? null)
  const active = sort !== undefined ? sort : localSort
  const controlled = sort !== undefined

  const sorted = useMemo(() => {
    if (controlled || !active) return rows
    const col = columns.find((c) => c.key === active.key)
    if (!col?.sortValue) return rows
    const sv = col.sortValue
    return [...rows].sort((a, b) => {
      const va = sv(a), vb = sv(b)
      if (va == null && vb == null) return 0
      if (va == null) return 1
      if (vb == null) return -1
      const r = typeof va === 'number' && typeof vb === 'number' ? va - vb : String(va).localeCompare(String(vb))
      return active.dir === 'asc' ? r : -r
    })
  }, [rows, active, columns, controlled])

  const toggle = (key: string) => {
    const col = columns.find((c) => c.key === key)
    if (!col?.sortValue && !controlled) return
    const next = active?.key === key ? { key, dir: active.dir === 'desc' ? ('asc' as const) : ('desc' as const) } : { key, dir: 'desc' as const }
    if (controlled) onSortChange?.(next)
    else setLocalSort(next)
  }

  return (
    <div className={cn('overflow-auto', className)}>
      <table className="table-dense w-full border-collapse text-xs">
        <thead className={stickyHeader ? 'sticky top-0 z-10 bg-panel' : ''}>
          <tr>
            {columns.map((c) => {
              const sortable = !!c.sortValue || controlled
              const isActive = active?.key === c.key
              return (
                <th key={c.key} style={{ width: c.width }} className={cn(sortable && 'cursor-pointer hover:text-fg', c.align === 'right' && 'text-right', c.align === 'center' && 'text-center')} onClick={() => sortable && toggle(c.key)}>
                  <span className="inline-flex items-center gap-1">
                    {c.header}
                    {sortable && (isActive ? active.dir === 'desc' ? <ArrowDown size={11} className="text-accent" /> : <ArrowUp size={11} className="text-accent" /> : <ChevronsUpDown size={11} className="opacity-40" />)}
                  </span>
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => {
            const k = rowKey(row)
            return (
              <tr key={k} className={cn(onRowClick && 'cursor-pointer', selectedKey === k && 'bg-accent-soft', rowClassName?.(row))} onClick={() => onRowClick?.(row)}>
                {columns.map((c) => (
                  <td key={c.key} className={cn(c.className, c.align === 'right' && 'text-right', c.align === 'center' && 'text-center')}>
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
      {sorted.length === 0 && <EmptyState title={emptyTitle} hint={emptyHint} />}
    </div>
  )
}
