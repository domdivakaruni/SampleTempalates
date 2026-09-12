import { AlertTriangle, CheckCircle2, Eye, Lightbulb, Scissors } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { ContainmentSimulation } from '../api/types'
import { shortId } from '../lib/format'
import { NodeRef } from './NodeRef'
import { StorylineChip } from './chips'

interface Props {
  sim: ContainmentSimulation
  onShowOnCanvas?: () => void
}

function Stat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-md border border-line bg-panel-2/60 px-2.5 py-1.5">
      <div className="text-[10.5px] uppercase tracking-wider text-fg-3">{label}</div>
      <div className="text-lg font-semibold tabular-nums" style={{ color: tone }}>{value}</div>
    </div>
  )
}

/** Renders a ContainmentSimulation: what is cut, what is protected, what breaks, residual risks, recommendations. */
export function ContainmentResult({ sim, onShowOnCanvas }: Props) {
  const navigate = useNavigate()
  return (
    <div className="space-y-3 text-xs">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Stat label="Attack paths cut" value={sim.paths_cut} tone="var(--color-accent)" />
        <Stat label="Storylines contained" value={sim.storylines_contained.length} tone="var(--color-cat-endpoint)" />
        <Stat label="Crown jewels protected" value={sim.crown_jewels_protected.length} tone="var(--color-sev-medium)" />
        <Stat label="Things that break" value={sim.breaks.length} tone={sim.breaks.length ? 'var(--color-sev-high)' : 'var(--color-fg-3)'} />
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-fg-3">Actions:</span>
        {sim.actions.map((a) => (
          <span key={a} className="chip border-accent/40 bg-accent/10 text-accent">{a.replace(/_/g, ' ')}</span>
        ))}
        <span className="text-fg-3">on</span>
        {sim.target_ids.map((t) => (
          <NodeRef key={t} id={t} mono />
        ))}
        {onShowOnCanvas && (
          <button type="button" className="btn-ghost ml-auto" onClick={onShowOnCanvas} title="Merge the simulation fragment into the canvas and mark the cut edges">
            <Eye size={11} /> Show on canvas
          </button>
        )}
      </div>
      {(sim.storylines_contained.length > 0 || sim.crown_jewels_protected.length > 0) && (
        <div className="flex flex-wrap items-center gap-1.5">
          {sim.storylines_contained.map((s) => (
            <StorylineChip key={s} id={s} onClick={() => navigate(`/storylines/${encodeURIComponent(s)}`)} />
          ))}
          {sim.crown_jewels_protected.map((j) => (
            <NodeRef key={j} id={j} />
          ))}
        </div>
      )}
      <div>
        <div className="panel-title mb-1 flex items-center gap-1"><Scissors size={11} /> What breaks</div>
        {sim.breaks.length === 0 && <div className="text-fg-3">Nothing in the dependency graph depends on the selected targets.</div>}
        {sim.breaks.length > 0 && (
          <table className="w-full">
            <tbody>
              {sim.breaks.map((b) => (
                <tr key={`${b.node_id}-${b.impact.slice(0, 20)}`} className="border-b border-line/60 align-top last:border-0">
                  <td className="py-1 pr-2 whitespace-nowrap"><NodeRef id={b.node_id} name={b.name} label={b.label} /></td>
                  <td className="py-1 pr-2 text-fg-2 leading-snug">{b.impact}</td>
                  <td className="py-1 whitespace-nowrap text-fg-3">{b.owner_team_id ? <NodeRef id={b.owner_team_id} name={shortId(b.owner_team_id)} label="Team" /> : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <div className="panel-title mb-1 flex items-center gap-1 text-sev-medium"><AlertTriangle size={11} /> Residual risks</div>
          <ul className="space-y-1">
            {sim.residual_risks.map((r) => (
              <li key={r} className="rounded border border-sev-medium/30 bg-sev-medium/5 px-2 py-1 leading-snug text-fg-2">{r}</li>
            ))}
            {sim.residual_risks.length === 0 && <li className="text-fg-3">None recorded.</li>}
          </ul>
        </div>
        <div>
          <div className="panel-title mb-1 flex items-center gap-1 text-accent"><Lightbulb size={11} /> Recommendations</div>
          <ul className="space-y-1">
            {sim.recommendations.map((r) => (
              <li key={r} className="flex items-start gap-1.5 rounded border border-line bg-panel-2/50 px-2 py-1 leading-snug text-fg-2">
                <CheckCircle2 size={11} className="mt-0.5 shrink-0 text-accent" /> {r}
              </li>
            ))}
            {sim.recommendations.length === 0 && <li className="text-fg-3">None.</li>}
          </ul>
        </div>
      </div>
    </div>
  )
}
