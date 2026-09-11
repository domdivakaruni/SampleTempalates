import type { RiskBreakdown } from '../api/types'
import { bandColor } from '../theme'
import { ScoreChip, SeverityChip } from './chips'

interface Props {
  risk: RiskBreakdown
  onEvidence?: (ids: string[]) => void
  compact?: boolean
}

const RAIL_LABELS: Record<string, string> = { attack_path_floor: 'Attack-path floor', no_context_ceiling: 'No-context ceiling', ti_booster: 'TI booster' }

/** Factor bars: value x weight = contribution, with reason; rails listed below. */
export function RiskBreakdownBars({ risk, onEvidence, compact }: Props) {
  const maxContribution = Math.max(1, ...risk.factors.map((f) => f.contribution))
  return (
    <div className="space-y-2">
      {!compact && (
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <span className="flex items-center gap-1.5 text-fg-2">
            Vendor <SeverityChip severity={risk.vendor_severity} />
          </span>
          <span className="text-fg-3">→</span>
          <span className="flex items-center gap-1.5 text-fg-2">
            Contextual <ScoreChip score={risk.contextual_score} band={risk.band} />
          </span>
          <span className="text-fg-3">raw {Math.round(risk.raw_score)}</span>
          {risk.delta_vs_vendor !== 0 && (
            <span className="text-fg-3">
              {risk.delta_vs_vendor < 0 ? `up ${Math.abs(risk.delta_vs_vendor)} places` : `down ${risk.delta_vs_vendor} places`} vs vendor queue
            </span>
          )}
        </div>
      )}
      <div className="space-y-1.5">
        {risk.factors.map((f) => {
          const pct = Math.max(2, (f.contribution / maxContribution) * 100)
          const color = f.value >= 0.75 ? bandColor('critical') : f.value >= 0.5 ? bandColor('high') : f.value >= 0.25 ? bandColor('medium') : bandColor('noise')
          return (
            <button
              type="button"
              key={f.key}
              className={`group w-full rounded-md px-2 py-1.5 text-left transition-colors ${onEvidence && f.evidence_ids.length ? 'hover:bg-panel-2 cursor-pointer' : 'cursor-default'}`}
              onClick={() => onEvidence && f.evidence_ids.length && onEvidence(f.evidence_ids)}
              title={f.evidence_ids.length ? `Highlight ${f.evidence_ids.length} evidence node(s)` : undefined}
            >
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className="font-medium text-fg">{f.label}</span>
                <span className="tabular-nums text-fg-3">
                  {f.value.toFixed(2)} × {f.weight.toFixed(f.weight < 0.1 ? 3 : 2)} = <span className="font-semibold text-fg">{f.contribution.toFixed(1)}</span> pts
                </span>
              </div>
              <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-panel-3">
                <div className="h-full rounded" style={{ width: `${pct}%`, background: color }} />
              </div>
              {!compact && <div className="mt-1 text-[11px] leading-snug text-fg-2">{f.reason}</div>}
            </button>
          )
        })}
      </div>
      {risk.rails.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-[11px] uppercase tracking-wider text-fg-3">Rails</span>
          {risk.rails.map((r) => {
            const [key, val] = r.split(':')
            return (
              <span key={r} className="chip border-accent/40 bg-accent/10 text-accent" title={r}>
                {RAIL_LABELS[key] ?? key}
                {val ? ` ${val}` : ''}
              </span>
            )
          })}
        </div>
      )}
    </div>
  )
}
