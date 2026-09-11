import { Crosshair, GitBranch, Globe, KeyRound, Link2, ShieldAlert, Users, VolumeX, Waypoints } from 'lucide-react'
import type { Insight } from '../api/types'
import { sourceLabel } from '../theme'

const KIND_ICON: Record<string, React.ReactNode> = {
  blast_radius: <Crosshair size={13} />,
  ti_match: <ShieldAlert size={13} />,
  credential_join: <KeyRound size={13} />,
  exposure: <Globe size={13} />,
  lateral: <Waypoints size={13} />,
  correlation: <GitBranch size={13} />,
  noise: <VolumeX size={13} />,
  ownership: <Users size={13} />,
}

interface Props {
  insights: Insight[]
  onHighlight?: (insight: Insight) => void
}

/** Cross-domain insights with hop count and the data sources crossed ("4 hops, EDR + Cloud + IAM + Data"). */
export function InsightList({ insights, onHighlight }: Props) {
  if (!insights.length) return <div className="text-xs text-fg-3">No insights.</div>
  return (
    <ul className="space-y-1.5">
      {insights.map((ins, i) => (
        <li key={`${ins.kind}-${i}`}>
          <button
            type="button"
            className={`w-full rounded-md border border-line bg-panel-2/60 px-2.5 py-2 text-left ${onHighlight ? 'hover:border-line-2 hover:bg-panel-2 cursor-pointer' : 'cursor-default'}`}
            onClick={() => onHighlight?.(ins)}
            title={onHighlight ? 'Highlight evidence on the canvas' : undefined}
          >
            <div className="flex items-start gap-2">
              <span className="mt-0.5 text-accent">{KIND_ICON[ins.kind] ?? <Link2 size={13} />}</span>
              <div className="min-w-0 flex-1">
                <div className="text-xs leading-snug text-fg">{ins.statement}</div>
                <div className="mt-1 flex flex-wrap items-center gap-1">
                  <span className="chip border-line-2 text-fg-2 tabular-nums">{ins.hops} hop{ins.hops === 1 ? '' : 's'}</span>
                  <span className="chip border-line-2 text-fg-2">{ins.sources.map(sourceLabel).join(' + ')}</span>
                  <span className="chip border-transparent text-fg-3 capitalize">{ins.kind.replace('_', ' ')}</span>
                  {ins.evidence_node_ids.length > 0 && <span className="text-[10px] text-fg-3">{ins.evidence_node_ids.length} evidence nodes</span>}
                </div>
              </div>
            </div>
          </button>
        </li>
      ))}
    </ul>
  )
}
