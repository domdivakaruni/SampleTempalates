import type { ReactNode } from 'react'
import { cn } from '../lib/format'

interface Props {
  label: string
  value: ReactNode
  hint?: ReactNode
  tone?: 'neutral' | 'bad' | 'warn' | 'good' | 'accent'
  icon?: ReactNode
  onClick?: () => void
  className?: string
}

const TONES: Record<NonNullable<Props['tone']>, string> = {
  neutral: 'text-fg',
  bad: 'text-sev-critical',
  warn: 'text-sev-medium',
  good: 'text-cat-endpoint',
  accent: 'text-accent',
}

export function KpiTile({ label, value, hint, tone = 'neutral', icon, onClick, className }: Props) {
  const Comp = onClick ? 'button' : 'div'
  return (
    <Comp type={onClick ? 'button' : undefined} onClick={onClick} className={cn('panel flex min-w-0 flex-col justify-between px-3 py-2.5 text-left', onClick && 'cursor-pointer hover:border-line-2 hover:bg-panel-2', className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="panel-title truncate">{label}</span>
        {icon && <span className="text-fg-3">{icon}</span>}
      </div>
      <div className={cn('mt-1 text-2xl font-semibold leading-none tabular-nums tracking-tight', TONES[tone])}>{value}</div>
      {hint && <div className="mt-1 truncate text-[11px] text-fg-3">{hint}</div>}
    </Comp>
  )
}
