import { Eraser, Search } from 'lucide-react'
import { useState } from 'react'
import { useSearch } from '../../api/hooks'
import type { GraphFragment } from '../../api/types'
import { LabelIcon } from '../../components/LabelIcon'
import { ErrorState } from '../../components/states'
import { CATEGORY_NAMES, CATEGORY_ORDER } from '../../graph/schema'
import { categoryColor } from '../../theme'

const SHORTCUTS: { id: string; label: string }[] = [
  { id: 'endpoint:falcon:aid-bas01', label: 'bas-01 (bastion endpoint)' },
  { id: 'endpoint:falcon:aid-wks3391', label: 'WKS-3391 (phished workstation)' },
  { id: 'role:aws:222222222222:LarkspurBastionSSMRole', label: 'LarkspurBastionSSMRole' },
  { id: 'bucket:aws:larkspur-cardholder-vault', label: 'larkspur-cardholder-vault (PCI)' },
  { id: 'vm:aws:i-0edge2a7f19c4b3e88', label: 'stmt-render-2a (Log4Shell host)' },
  { id: 'actor:ti:cinder-jackal', label: 'Cinder Jackal' },
]

interface Props {
  loaded: GraphFragment
  loading: boolean
  error: unknown
  onLoadSeed: (id: string) => void
  onClear: () => void
}

/** Seed the canvas from search (GET /search) or a demo shortcut; a second seed merges into the existing canvas. */
export function SeedSearch({ loaded, loading, error, onLoadSeed, onClear }: Props) {
  const [text, setText] = useState('')
  const q = useSearch(text)
  const hits = q.data?.hits ?? []
  const groups = CATEGORY_ORDER.map((c) => [c, hits.filter((h) => h.category === c)] as const).filter(([, hs]) => hs.length)
  const other = hits.filter((h) => !CATEGORY_ORDER.includes(h.category as (typeof CATEGORY_ORDER)[number]))
  return (
    <div className="space-y-3 text-xs">
      <label className="input flex items-center gap-2 py-1">
        <Search size={12} className="text-fg-3" />
        <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Host, role, bucket, CVE, IOC, alert id…" className="w-full bg-transparent focus:outline-none" autoFocus />
        {q.isFetching && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />}
      </label>
      {text.trim().length >= 2 && (
        <div className="max-h-[40vh] overflow-y-auto rounded-md border border-line">
          {hits.length === 0 && <div className="px-2 py-2 text-fg-3">{q.isFetching ? 'Searching…' : 'No matches'}</div>}
          {[...groups, ...(other.length ? ([['unknown', other]] as const) : [])].map(([cat, hs]) => (
            <div key={cat}>
              <div className="sticky top-0 flex items-center gap-1.5 bg-panel-2 px-2 py-1 text-[10px] uppercase tracking-wider text-fg-3">
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: categoryColor(cat) }} />
                {CATEGORY_NAMES[cat as keyof typeof CATEGORY_NAMES] ?? cat}
              </div>
              {hs.map((h) => (
                <button key={h.id} type="button" className="flex w-full items-center gap-2 px-2 py-1 text-left hover:bg-panel-3" onClick={() => onLoadSeed(h.id)} title={h.id}>
                  <LabelIcon label={h.label} category={h.category} size={12} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-fg">{h.name}</span>
                    <span className="block truncate text-[10px] text-fg-3">{h.label}{h.snippet ? ` · ${h.snippet}` : ''}</span>
                  </span>
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
      <div>
        <div className="panel-title mb-1">Demo shortcuts</div>
        <div className="flex flex-wrap gap-1">
          {SHORTCUTS.map((s) => (
            <button key={s.id} type="button" className="chip border-line-2 bg-panel-2 text-fg-2 hover:border-accent/50 hover:text-fg" onClick={() => onLoadSeed(s.id)} title={s.id}>
              {s.label}
            </button>
          ))}
        </div>
      </div>
      <div className="rounded-md border border-line bg-panel-2/50 px-2 py-1.5">
        <div className="flex items-center justify-between">
          <span className="text-fg-2">
            On canvas: <span className="tabular-nums text-fg">{loaded.nodes.length}</span> nodes, <span className="tabular-nums text-fg">{loaded.edges.length}</span> edges
            {loading && <span className="ml-1 text-accent">loading…</span>}
          </span>
          <button type="button" className="btn-ghost py-0.5" onClick={onClear} disabled={!loaded.nodes.length}>
            <Eraser size={11} /> Clear
          </button>
        </div>
        <div className="mt-1 text-[10.5px] text-fg-3">Seeding loads GET /graph/neighborhood depth=1 and merges into what is already drawn. Double-click a node to expand it; right-click for blast radius, attack paths and the analyst.</div>
      </div>
      {error ? <ErrorState error={error} compact /> : null}
    </div>
  )
}
