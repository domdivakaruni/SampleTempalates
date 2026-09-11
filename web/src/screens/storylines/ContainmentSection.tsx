import { useMemo, useState } from 'react'
import { useContainment } from '../../api/hooks'
import type { AlertSummary, ContainmentAction, ContainmentSimulation, GraphFragment, StorylineOut } from '../../api/types'
import { ContainmentForm } from '../../components/ContainmentForm'
import { ContainmentResult } from '../../components/ContainmentResult'
import { Panel } from '../../components/Page'
import { useDrawerStore } from '../../store/drawerStore'

interface Props {
  story: StorylineOut
  alerts: AlertSummary[]
  onShowOnCanvas: (sim: ContainmentSimulation) => void
}

/** "If we isolate X and rotate Y, what do we contain and what breaks?" (demo question 12). */
export function ContainmentSection({ story, alerts, onShowOnCanvas }: Props) {
  const mutation = useContainment()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const [sim, setSim] = useState<ContainmentSimulation | null>(null)
  const fragment: GraphFragment | null | undefined = story.fragment
  const candidates = useMemo(() => fragment?.nodes ?? [], [fragment])
  const defaults = useMemo(() => {
    const top = [...alerts].sort((a, b) => b.contextual_score - a.contextual_score).find((a) => a.entity_label === 'Endpoint' || a.entity_label === 'VirtualMachine')
    const roles = candidates.filter((n) => n.label === 'IamRole' && n.props.role_type === 'instance').map((n) => n.id)
    return [...(top?.entity_id ? [top.entity_id] : []), ...roles.slice(0, 1)]
  }, [alerts, candidates])
  const defaultActions: ContainmentAction[] = ['isolate_endpoint', 'rotate_role_credentials']
  const targetNames = (sim?.target_ids ?? defaults).map((id) => candidates.find((n) => n.id === id)?.name ?? id)
  return (
    <Panel
      title="Containment simulation"
      actions={
        <button type="button" className="btn-ghost py-0.5" onClick={() => askAbout(`If we isolate ${targetNames[0] ?? 'the compromised host'}${targetNames[1] ? ` and rotate ${targetNames[1]}` : ''} now, what do we contain and what breaks?`, { storyline_id: story.id })}>
          Ask the analyst instead →
        </button>
      }
    >
      <div className="space-y-3">
        <ContainmentForm
          candidates={candidates}
          defaultTargets={defaults}
          defaultActions={defaultActions}
          loading={mutation.isPending}
          error={mutation.error}
          onSimulate={(body) => mutation.mutate(body, { onSuccess: (res) => setSim(res) })}
        />
        {sim && (
          <div className="border-t border-line pt-3">
            <ContainmentResult sim={sim} onShowOnCanvas={() => onShowOnCanvas(sim)} />
          </div>
        )}
      </div>
    </Panel>
  )
}
