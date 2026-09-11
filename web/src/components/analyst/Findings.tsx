import { useNavigate } from 'react-router-dom'
import type { Finding } from '../../api/types'
import { labelForId } from '../../graph/schema'
import { shortId } from '../../lib/format'
import { useCanvasStore } from '../../store/canvasStore'
import { useSelectionStore } from '../../store/selectionStore'
import { severityColor } from '../../theme'
import { LabelIcon } from '../LabelIcon'

export function Findings({ findings }: { findings: Finding[] }) {
  const navigate = useNavigate()
  const focus = useCanvasStore((s) => s.focus)
  const active = useCanvasStore((s) => s.activeCanvas)
  const setHighlight = useCanvasStore((s) => s.setHighlight)
  const select = useSelectionStore((s) => s.select)
  if (!findings.length) return null
  const openEvidence = (id: string) => {
    const label = labelForId(id)
    if (label === 'Alert') return navigate(`/alerts/${encodeURIComponent(id)}`)
    if (label === 'Storyline') return navigate(`/storylines/${encodeURIComponent(id)}`)
    if (active) {
      focus(id)
      select(id)
    } else navigate(`/explorer?seed=${encodeURIComponent(id)}`)
  }
  return (
    <div className="space-y-1">
      <div className="panel-title">Findings</div>
      {findings.map((f, i) => {
        const color = severityColor(f.severity ?? 'informational')
        return (
          <div key={i} className="rounded-md border border-line bg-panel-2/60 px-2 py-1.5 text-[11.5px]">
            <div className="flex items-start gap-2">
              <span className="mt-[3px] h-2 w-2 shrink-0 rounded-full" style={{ background: color }} title={f.severity ?? 'informational'} />
              <span className="leading-snug text-fg">{f.statement}</span>
            </div>
            {f.evidence_ids.length > 0 && (
              <div className="mt-1 flex flex-wrap gap-1 pl-4">
                {f.evidence_ids.slice(0, 8).map((id) => (
                  <button key={id} type="button" className="mono inline-flex items-center gap-1 rounded border border-line-2 bg-bg px-1 py-[1px] text-[10px] text-fg-2 hover:border-accent hover:text-accent" onClick={() => openEvidence(id)} title={id}>
                    <LabelIcon label={labelForId(id) ?? 'Unknown'} size={10} />
                    {shortId(id).slice(0, 34)}
                  </button>
                ))}
                {f.evidence_ids.length > 8 && (
                  <button type="button" className="text-[10px] text-fg-3 hover:text-accent" onClick={() => setHighlight(f.evidence_ids)}>
                    +{f.evidence_ids.length - 8} more · highlight all
                  </button>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
