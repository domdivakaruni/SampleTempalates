import { Loader2, ShieldCheck } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { ContainmentAction, ContainmentIn, NodeOut } from '../api/types'
import { CONTAINMENT_ACTIONS } from '../api/types'
import { cn, shortId } from '../lib/format'
import { LabelIcon } from './LabelIcon'

interface Props {
  candidates: NodeOut[]
  defaultTargets?: string[]
  defaultActions?: ContainmentAction[]
  onSimulate: (body: ContainmentIn) => void
  loading?: boolean
  error?: unknown
}

const TARGET_LABELS = new Set(['Endpoint', 'VirtualMachine', 'IamRole', 'IamUser', 'HumanUser', 'ServiceAccount', 'IpAddress', 'Credential', 'AccessKey', 'Workload', 'KubernetesCluster'])
const GROUPS: [string, string[]][] = [
  ['Hosts', ['Endpoint', 'VirtualMachine', 'Workload', 'KubernetesCluster']],
  ['Identities & credentials', ['IamRole', 'IamUser', 'HumanUser', 'ServiceAccount', 'Credential', 'AccessKey']],
  ['Network', ['IpAddress']],
]

/** Pick containment targets (hosts, roles, users, IPs) and actions, then POST /investigate/containment. */
export function ContainmentForm({ candidates, defaultTargets = [], defaultActions = ['isolate_endpoint', 'rotate_role_credentials'], onSimulate, loading, error }: Props) {
  const [targets, setTargets] = useState<Set<string>>(() => new Set(defaultTargets))
  const [actions, setActions] = useState<Set<ContainmentAction>>(() => new Set(defaultActions))
  const grouped = useMemo(() => {
    const seen = new Set<string>()
    const list = candidates.filter((n) => TARGET_LABELS.has(n.label) && !seen.has(n.id) && seen.add(n.id))
    return GROUPS.map(([title, labels]) => [title, list.filter((n) => labels.includes(n.label))] as [string, NodeOut[]]).filter(([, ns]) => ns.length)
  }, [candidates])
  const toggle = (id: string) => setTargets((s) => {
    const n = new Set(s)
    if (n.has(id)) n.delete(id)
    else n.add(id)
    return n
  })
  const toggleAction = (a: ContainmentAction) => setActions((s) => {
    const n = new Set(s)
    if (n.has(a)) n.delete(a)
    else n.add(a)
    return n
  })
  const canRun = targets.size > 0 && actions.size > 0 && !loading
  return (
    <div className="space-y-3 text-xs">
      <div>
        <div className="panel-title mb-1">Targets</div>
        {grouped.length === 0 && <div className="text-fg-3">No containable entities in this storyline.</div>}
        <div className="grid gap-x-3 gap-y-1 sm:grid-cols-2">
          {grouped.map(([title, nodes]) => (
            <div key={title}>
              <div className="mb-0.5 text-[10.5px] uppercase tracking-wider text-fg-3">{title}</div>
              {nodes.map((n) => (
                <label key={n.id} className={cn('flex cursor-pointer items-center gap-1.5 rounded px-1 py-[2px] hover:bg-panel-3', targets.has(n.id) && 'bg-accent/10')} title={n.id}>
                  <input type="checkbox" className="h-3 w-3 accent-sky-400" checked={targets.has(n.id)} onChange={() => toggle(n.id)} />
                  <LabelIcon label={n.label} category={n.category} size={12} />
                  <span className="truncate text-fg">{n.name}</span>
                  <span className="mono ml-auto shrink-0 text-[10px] text-fg-3">{shortId(n.id).slice(0, 22)}</span>
                </label>
              ))}
            </div>
          ))}
        </div>
      </div>
      <div>
        <div className="panel-title mb-1">Actions</div>
        <div className="grid gap-1 sm:grid-cols-2">
          {CONTAINMENT_ACTIONS.map((a) => (
            <label key={a.id} className={cn('flex cursor-pointer items-start gap-1.5 rounded border px-2 py-1', actions.has(a.id) ? 'border-accent/50 bg-accent/10' : 'border-line hover:border-line-2')}>
              <input type="checkbox" className="mt-0.5 h-3 w-3 accent-sky-400" checked={actions.has(a.id)} onChange={() => toggleAction(a.id)} />
              <span>
                <span className="block font-medium text-fg">{a.label}</span>
                <span className="block text-[10.5px] leading-snug text-fg-3">{a.hint}</span>
              </span>
            </label>
          ))}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className="btn-primary" disabled={!canRun} onClick={() => onSimulate({ target_ids: [...targets], actions: [...actions] })}>
          {loading ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />} Simulate containment
        </button>
        <span className="text-fg-3">
          {targets.size} target{targets.size === 1 ? '' : 's'}, {actions.size} action{actions.size === 1 ? '' : 's'} · POST /investigate/containment
        </span>
        {error ? <span className="text-sev-critical">{error instanceof Error ? error.message : String(error)}</span> : null}
      </div>
    </div>
  )
}
