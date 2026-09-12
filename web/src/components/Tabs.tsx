import type { ReactNode } from 'react'
import { cn } from '../lib/format'

export interface TabItem { id: string; label: ReactNode; count?: number | null; icon?: ReactNode; title?: string }

/** Underlined tab strip; the active id is controlled by the parent (usually a `?tab=` search param). */
export function Tabs({ tabs, active, onChange, className, right }: { tabs: TabItem[]; active: string; onChange: (id: string) => void; className?: string; right?: ReactNode }) {
  return (
    <div className={cn('flex items-center gap-1 border-b border-line', className)} role="tablist">
      {tabs.map((t) => (
        <button key={t.id} type="button" role="tab" aria-selected={active === t.id} title={t.title} className={cn('tab flex items-center gap-1.5', active === t.id && 'tab-active')} onClick={() => onChange(t.id)}>
          {t.icon}
          {t.label}
          {t.count !== undefined && t.count !== null && <span className="rounded-full bg-panel-3 px-1.5 text-[10px] tabular-nums text-fg-2">{t.count}</span>}
        </button>
      ))}
      {right && <div className="ml-auto flex items-center gap-2 pr-1">{right}</div>}
    </div>
  )
}
