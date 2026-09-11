import { CircleAlert, Inbox, RefreshCw } from 'lucide-react'
import type { ReactNode } from 'react'
import { isApiError } from '../api/client'
import { cn } from '../lib/format'

export function EmptyState({ title = 'Nothing here', hint, icon, action, className }: { title?: string; hint?: ReactNode; icon?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-2 py-10 text-center', className)}>
      <div className="text-fg-3">{icon ?? <Inbox size={22} />}</div>
      <div className="text-sm font-medium text-fg-2">{title}</div>
      {hint && <div className="max-w-md text-xs text-fg-3">{hint}</div>}
      {action}
    </div>
  )
}

export function ErrorState({ error, onRetry, className, compact }: { error: unknown; onRetry?: () => void; className?: string; compact?: boolean }) {
  const message = isApiError(error) ? `${error.code}: ${error.message}` : error instanceof Error ? error.message : String(error)
  const notSupported = isApiError(error) && error.status === 501
  return (
    <div className={cn('flex flex-col items-center justify-center gap-2 text-center', compact ? 'py-4' : 'py-10', className)}>
      <CircleAlert size={compact ? 16 : 22} className={notSupported ? 'text-sev-medium' : 'text-sev-critical'} />
      <div className="text-sm font-medium text-fg-2">{notSupported ? 'Not supported by this backend' : 'Request failed'}</div>
      <div className="max-w-lg break-words text-xs text-fg-3">{message}</div>
      {onRetry && (
        <button type="button" className="btn mt-1" onClick={onRetry}>
          <RefreshCw size={12} /> Retry
        </button>
      )}
    </div>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse-soft rounded bg-panel-3', className)} />
}

export function SkeletonRows({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2 p-3">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className="h-4 flex-1" style-hint={c} />
          ))}
        </div>
      ))}
    </div>
  )
}

export function SkeletonBlock({ lines = 4, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn('space-y-2', className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cn('h-3', i % 3 === 2 ? 'w-2/3' : 'w-full')} />
      ))}
    </div>
  )
}

export function Spinner({ className }: { className?: string }) {
  return <RefreshCw size={13} className={cn('animate-spin text-fg-3', className)} />
}
