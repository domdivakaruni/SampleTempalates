import { Route } from 'lucide-react'
import { useState } from 'react'
import { api } from '../../api/client'
import type { GraphFragment, PathOut } from '../../api/types'
import { ErrorState } from '../../components/states'
import type { CanvasOps } from '../../graph/useCanvasOps'
import { cn } from '../../lib/format'
import { NodePicker } from './NodePicker'

interface Props { ops: CanvasOps; selectedId: string | null }

/** GET /graph/paths between two nodes; results merge into the canvas and each path can be highlighted. */
export function PathFinder({ ops, selectedId }: Props) {
  const [src, setSrc] = useState('')
  const [dst, setDst] = useState('bucket:aws:larkspur-cardholder-vault')
  const [maxHops, setMaxHops] = useState(6)
  const [k, setK] = useState(3)
  const [result, setResult] = useState<GraphFragment | null>(null)
  const [active, setActive] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const run = async () => {
    if (!src || !dst) return
    setBusy(true)
    setError(null)
    try {
      const frag = await api.paths({ src, dst, max_hops: maxHops, k })
      setResult(frag)
      setActive(0)
      ops.merge(frag)
      if (frag.paths[0]) ops.showPath(frag.paths[0])
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  const show = (p: PathOut, i: number) => {
    setActive(i)
    ops.showPath(p)
  }
  return (
    <div className="space-y-2 text-xs">
      <div>
        <div className="mb-0.5 text-[10.5px] uppercase tracking-wider text-fg-3">From</div>
        <NodePicker value={src} onChange={setSrc} selectedId={selectedId} placeholder="Source (e.g. an alert or endpoint)" />
      </div>
      <div>
        <div className="mb-0.5 text-[10.5px] uppercase tracking-wider text-fg-3">To</div>
        <NodePicker value={dst} onChange={setDst} selectedId={selectedId} placeholder="Target (e.g. a crown-jewel bucket)" />
      </div>
      <div className="flex items-center gap-2">
        <label className="flex items-center gap-1 text-fg-2">
          max hops
          <select className="select h-7 py-0" value={maxHops} onChange={(e) => setMaxHops(Number(e.target.value))}>
            {[2, 3, 4, 5, 6, 7, 8].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1 text-fg-2">
          k
          <select className="select h-7 py-0" value={k} onChange={(e) => setK(Number(e.target.value))}>
            {[1, 2, 3, 4, 5].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </label>
        <button type="button" className="btn-primary ml-auto" disabled={!src || !dst || busy} onClick={() => void run()}>
          <Route size={12} /> {busy ? 'Finding…' : 'Find paths'}
        </button>
      </div>
      {error ? <ErrorState error={error} compact /> : null}
      {result && (
        <div className="space-y-1">
          <div className="text-fg-2">
            {result.paths.length} path{result.paths.length === 1 ? '' : 's'} · {result.nodes.length} nodes merged
          </div>
          {result.paths.length === 0 && <div className="text-fg-3">No path within {maxHops} hops. Try more hops or a different edge set.</div>}
          {result.paths.map((p, i) => (
            <button key={i} type="button" className={cn('w-full rounded-md border px-2 py-1 text-left', active === i ? 'border-accent/60 bg-accent/10' : 'border-line bg-panel-2/50 hover:border-line-2')} onClick={() => show(p, i)}>
              <div className="flex items-center justify-between">
                <span className="font-medium text-fg">{p.label ?? `${p.hops} hops`}</span>
                <span className="tabular-nums text-fg-3">{p.hops} hops{p.likelihood != null ? ` · ${(p.likelihood * 100).toFixed(0)}%` : ''}</span>
              </div>
              <div className="mono mt-0.5 truncate text-[10px] text-fg-3" title={p.edge_ids.map((e) => e.split('|')[1]).join(' → ')}>
                {p.edge_ids.map((e) => e.split('|')[1]).join(' → ')}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
