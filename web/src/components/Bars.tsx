import { cn, fmtNum } from '../lib/format'

export interface BarDatum { label: string; value: number; color?: string; hint?: string }

/** Small horizontal bar list (plain CSS, no chart library). */
export function HBars({ data, max, className, valueFormat = (v: number) => fmtNum(v) }: { data: BarDatum[]; max?: number; className?: string; valueFormat?: (v: number) => string }) {
  const m = Math.max(1, max ?? Math.max(...data.map((d) => d.value)))
  return (
    <div className={cn('space-y-1.5', className)}>
      {data.map((d) => (
        <div key={d.label} className="flex items-center gap-2 text-xs" title={d.hint}>
          <span className="w-24 shrink-0 truncate text-fg-2 capitalize">{d.label}</span>
          <div className="h-2 flex-1 overflow-hidden rounded bg-panel-3">
            <div className="h-full rounded" style={{ width: `${Math.max(1.5, (d.value / m) * 100)}%`, background: d.color ?? 'var(--color-accent)' }} />
          </div>
          <span className="w-10 shrink-0 text-right tabular-nums text-fg">{valueFormat(d.value)}</span>
        </div>
      ))}
    </div>
  )
}

/** Ring gauge for a percentage (SVG). */
export function Ring({ pct, size = 56, stroke = 6, color = 'var(--color-accent)', children }: { pct: number; size?: number; stroke?: number; color?: string; children?: React.ReactNode }) {
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const p = Math.max(0, Math.min(1, pct))
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="#1e293b" strokeWidth={stroke} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={stroke} fill="none" strokeDasharray={`${c * p} ${c * (1 - p)}`} strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center text-xs font-semibold tabular-nums text-fg">{children ?? `${Math.round(p * 100)}%`}</div>
    </div>
  )
}

export function Sparkbar({ values, color = 'var(--color-accent)', height = 22, className }: { values: number[]; color?: string; height?: number; className?: string }) {
  const max = Math.max(1, ...values)
  return (
    <div className={cn('flex items-end gap-px', className)} style={{ height }}>
      {values.map((v, i) => (
        <div key={i} className="flex-1 rounded-sm" style={{ height: `${Math.max(6, (v / max) * 100)}%`, background: color, opacity: 0.55 + (i / values.length) * 0.45 }} />
      ))}
    </div>
  )
}
