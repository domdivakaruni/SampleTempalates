import { Waypoints } from 'lucide-react'
import { useState } from 'react'
import { api } from '../../api/client'
import type { AttackPathOut, AttackPathsOut } from '../../api/types'
import { AttackPathList } from '../../components/AttackPathList'
import { ErrorState } from '../../components/states'
import type { CanvasOps } from '../../graph/useCanvasOps'
import { NodePicker } from './NodePicker'

interface Props { ops: CanvasOps; selectedId: string | null }

/** GET /graph/attack-paths through a node (or towards a target); stages are clickable. */
export function AttackPathsPanel({ ops, selectedId }: Props) {
  const [through, setThrough] = useState('')
  const [target, setTarget] = useState('')
  const [result, setResult] = useState<AttackPathsOut | null>(null)
  const [active, setActive] = useState<{ id: string | null; stage: number | null }>({ id: null, stage: null })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const thr = through || selectedId || ''
  const run = async () => {
    if (!thr && !target) return
    setBusy(true)
    setError(null)
    try {
      const res = await api.attackPaths({ through: thr || undefined, target: target || undefined, k: 5 })
      setResult(res)
      if (res.paths.length) {
        ops.merge(res.fragment)
        const p0 = res.paths[0].fragment.paths[0]
        if (p0) ops.showPath(p0)
        setActive({ id: res.paths[0].id, stage: null })
      }
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  const selectPath = (p: AttackPathOut) => {
    setActive({ id: p.id, stage: null })
    ops.merge(p.fragment)
    const p0 = p.fragment.paths[0]
    if (p0) ops.showPath(p0)
  }
  return (
    <div className="space-y-2 text-xs">
      <div>
        <div className="mb-0.5 text-[10.5px] uppercase tracking-wider text-fg-3">Through {!through && selectedId ? '(selected node)' : ''}</div>
        <NodePicker value={through || (selectedId ?? '')} onChange={setThrough} selectedId={selectedId} placeholder="Any node on the path" />
      </div>
      <div>
        <div className="mb-0.5 text-[10.5px] uppercase tracking-wider text-fg-3">Target (optional)</div>
        <NodePicker value={target} onChange={setTarget} placeholder="Crown jewel or data store" labels={['StorageBucket', 'Database', 'Secret']} />
      </div>
      <button type="button" className="btn-primary w-full justify-center" disabled={(!thr && !target) || busy} onClick={() => void run()}>
        <Waypoints size={12} /> {busy ? 'Searching…' : 'Find attack paths'}
      </button>
      {error ? <ErrorState error={error} compact /> : null}
      {result && (
        <AttackPathList
          paths={result.paths}
          activeId={active.id}
          activeStage={active.stage}
          onSelectPath={selectPath}
          onSelectStage={(p, s) => {
            setActive({ id: p.id, stage: s.order })
            void ops.highlight([...s.node_ids, ...s.edge_ids, ...s.alert_ids])
          }}
          onAddToCanvas={(p) => ops.merge(p.fragment, { highlight: true })}
          compact
        />
      )}
    </div>
  )
}
