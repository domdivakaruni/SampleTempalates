import type { BlastRadiusResult, ReachedNode } from '../api/types'
import { NodeRef } from './NodeRef'

interface Props {
  br: BlastRadiusResult
  onHighlight?: (ids: string[]) => void
}

function Group({ title, items, tone, onHighlight }: { title: string; items: ReachedNode[]; tone: string; onHighlight?: (ids: string[]) => void }) {
  return (
    <div className="rounded-md border border-line bg-panel-2/60 p-2">
      <button type="button" className="flex w-full items-center justify-between text-left" onClick={() => onHighlight?.(items.map((i) => i.node.id))} disabled={!items.length}>
        <span className="text-[11px] uppercase tracking-wider text-fg-3">{title}</span>
        <span className="text-sm font-semibold tabular-nums" style={{ color: items.length ? tone : 'var(--color-fg-3)' }}>
          {items.length}
        </span>
      </button>
      {items.length > 0 && (
        <ul className="mt-1 space-y-0.5">
          {items.slice(0, 5).map((r) => (
            <li key={r.node.id} className="flex items-center justify-between gap-1 text-[11px]">
              <NodeRef node={r.node} className="min-w-0" />
              <span className="shrink-0 tabular-nums text-fg-3">
                {r.hops}h{r.access_level ? ` · ${r.access_level}` : ''}
              </span>
            </li>
          ))}
          {items.length > 5 && <li className="text-[10px] text-fg-3">+{items.length - 5} more</li>}
        </ul>
      )}
    </div>
  )
}

/** Blast radius: crown jewels, secrets, identities, accounts with hop counts. */
export function BlastRadiusSummary({ br, onHighlight }: Props) {
  return (
    <div className="space-y-2">
      <p className="text-xs leading-snug text-fg-2">{br.summary}</p>
      <div className="grid grid-cols-2 gap-2">
        <Group title="Crown jewels" items={br.crown_jewels} tone="var(--color-sev-critical)" onHighlight={onHighlight} />
        <Group title="Secrets" items={br.secrets} tone="var(--color-sev-high)" onHighlight={onHighlight} />
        <Group title="Identities" items={br.identities} tone="var(--color-cat-identity)" onHighlight={onHighlight} />
        <Group title="Other data stores" items={br.data_stores} tone="var(--color-cat-cloud)" onHighlight={onHighlight} />
      </div>
      <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-fg-3">
        <span>{br.reached_count} nodes within {br.depth} hops</span>
        <span>·</span>
        <span>accounts: {br.accounts_touched.length ? br.accounts_touched.join(', ') : 'none'}</span>
        <span>·</span>
        <span>by hop: {Object.entries(br.by_hop).sort(([a], [b]) => Number(a) - Number(b)).map(([h, c]) => `${h}:${c}`).join(' ')}</span>
      </div>
    </div>
  )
}
