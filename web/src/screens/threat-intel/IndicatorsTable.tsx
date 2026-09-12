import type { NodeOut, TIMatch } from '../../api/types'
import { NodeRef } from '../../components/NodeRef'
import { ConfidenceDots } from '../../components/TIContextPanel'
import { Pill } from '../../components/chips'
import { fmtShortTime } from '../../lib/format'

/** Indicators with confidence, kill-chain stage, activity window and where they matched in the estate. */
export function IndicatorsTable({ indicators, matches }: { indicators: NodeOut[]; matches: TIMatch[] }) {
  if (!indicators.length) return <div className="text-xs text-fg-3">No indicators.</div>
  const matchedBy = new Map<string, TIMatch[]>()
  for (const m of matches) matchedBy.set(m.indicator_id, [...(matchedBy.get(m.indicator_id) ?? []), m])
  return (
    <div className="overflow-x-auto">
      <table className="table-dense w-full text-xs">
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
            <th>Confidence</th>
            <th>Stage</th>
            <th>Seen</th>
            <th>Matched in estate</th>
          </tr>
        </thead>
        <tbody>
          {indicators.map((i) => {
            const ms = matchedBy.get(i.id) ?? []
            const value = String(i.props.value ?? i.name)
            return (
              <tr key={i.id} className={ms.length ? 'bg-cat-ti/5' : ''}>
                <td><span className="chip border-line-2 uppercase text-fg-3">{String(i.props.ioc_type ?? '')}</span></td>
                <td className="mono max-w-[260px] truncate text-[11px] text-fg" title={value}>{value.length > 44 ? `${value.slice(0, 20)}…${value.slice(-16)}` : value}</td>
                <td><ConfidenceDots value={Number(i.props.confidence ?? 0)} /></td>
                <td className="tabular-nums text-fg-2">{i.props.kill_chain_stage != null ? String(i.props.kill_chain_stage) : '—'}</td>
                <td className="mono whitespace-nowrap text-[10.5px] text-fg-3">{fmtShortTime(String(i.props.first_seen ?? ''))} → {fmtShortTime(String(i.props.last_seen ?? ''))}{i.props.active === false ? ' (inactive)' : ''}</td>
                <td>
                  {ms.length ? (
                    <span className="flex flex-wrap gap-1">
                      {ms.slice(0, 3).map((m) => (
                        <NodeRef key={m.matched_node_id} id={m.matched_node_id} label={m.matched_label} mono />
                      ))}
                      {ms.length > 3 && <span className="text-fg-3">+{ms.length - 3}</span>}
                    </span>
                  ) : (
                    <Pill tone="neutral">no match</Pill>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/** ATT&CK techniques grouped by tactic in kill-chain order. */
export function TechniqueChips({ techniques, seen }: { techniques: NodeOut[]; seen?: Set<string> }) {
  if (!techniques.length) return <div className="text-xs text-fg-3">No techniques recorded.</div>
  const groups = new Map<string, NodeOut[]>()
  for (const t of [...techniques].sort((a, b) => Number(a.props.kill_chain_stage ?? 0) - Number(b.props.kill_chain_stage ?? 0))) {
    const tactic = String(t.props.tactic ?? 'Unknown')
    groups.set(tactic, [...(groups.get(tactic) ?? []), t])
  }
  return (
    <div className="space-y-1.5">
      {[...groups.entries()].map(([tactic, ts]) => (
        <div key={tactic} className="flex flex-wrap items-center gap-1 text-xs">
          <span className="w-[150px] shrink-0 text-[10.5px] uppercase tracking-wider text-fg-3">{tactic}</span>
          {ts.map((t) => {
            const tid = String(t.props.technique_id ?? t.name)
            const hit = seen?.has(tid)
            return (
              <span key={t.id} className={`mono chip ${hit ? 'border-sev-high/50 bg-sev-high/10 text-sev-high' : 'border-line-2 text-fg-2'}`} title={`${t.name}${hit ? ' · observed in our alerts' : ''}`}>
                {tid}
              </span>
            )
          })}
        </div>
      ))}
    </div>
  )
}
