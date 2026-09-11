import type { ReactNode } from 'react'
import { cn } from '../lib/format'

export function Page({ children, className, scroll = true }: { children: ReactNode; className?: string; scroll?: boolean }) {
  return <div className={cn('h-full w-full', scroll ? 'overflow-y-auto' : 'overflow-hidden', className)}>{children}</div>
}

export function PageHeader({ title, subtitle, actions, className }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-wrap items-start justify-between gap-3', className)}>
      <div className="min-w-0">
        <h1 className="text-base font-semibold tracking-tight text-fg">{title}</h1>
        {subtitle && <div className="mt-0.5 text-xs text-fg-2">{subtitle}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Panel({ title, children, className, actions, bodyClassName, flush }: { title?: ReactNode; children: ReactNode; className?: string; actions?: ReactNode; bodyClassName?: string; flush?: boolean }) {
  return (
    <section className={cn('panel flex min-w-0 flex-col', className)}>
      {(title || actions) && (
        <div className="flex items-center justify-between gap-2 border-b border-line px-3 py-2">
          <div className="panel-title">{title}</div>
          {actions}
        </div>
      )}
      <div className={cn('min-h-0 flex-1', flush ? '' : 'p-3', bodyClassName)}>{children}</div>
    </section>
  )
}
