import { Crosshair } from 'lucide-react'
import { useState } from 'react'
import type { BlastRadiusResult } from '../../api/types'
import { BlastRadiusSummary } from '../../components/BlastRadiusSummary'
import { ErrorState } from '../../components/states'
import type { CanvasOps } from '../../graph/useCanvasOps'
import { NodePicker } from './NodePicker'

interface Props { ops: CanvasOps; selectedId: string | null }

/** GET /graph/blast-radius with a depth slider; crown jewels, secrets and identities summarised and highlightable. */
export function BlastPanel({ ops, selectedId }: Props) {
  const [root, setRoot] = useState('')
  const [depth, setDepth] = useState(4)
  const [result, setResult] = useState<BlastRadiusResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const target = root || selectedId || ''
  const run = async () => {
    if (!target) return
    setBusy(true)
    setError(null)
    try {
      const res = await ops.blast(target, depth)
      setResult(res ?? null)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-2 text-xs">
      <div>
        <div className="mb-0.5 text-[10.5px] uppercase tracking-wider text-fg-3">Root {!root && selectedId ? '(selected node)' : ''}</div>
        <NodePicker value={root || (selectedId ?? '')} onChange={setRoot} selectedId={selectedId} placeholder="Identity, host or alert" />
      </div>
      <label className="flex items-center gap-2 text-fg-2">
        depth
        <input type="range" min={1} max={6} value={depth} onChange={(e) => setDepth(Number(e.target.value))} className="flex-1 accent-sky-400" />
        <span className="w-4 tabular-nums text-fg">{depth}</span>
      </label>
      <button type="button" className="btn-primary w-full justify-center" disabled={!target || busy} onClick={() => void run()}>
        <Crosshair size={12} /> {busy ? 'Computing…' : 'Compute blast radius'}
      </button>
      {error ? <ErrorState error={error} compact /> : null}
      {result && <BlastRadiusSummary br={result} onHighlight={(ids) => void ops.highlight([result.root_id, ...ids])} />}
    </div>
  )
}
