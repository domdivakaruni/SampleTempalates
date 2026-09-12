import { Crosshair, Filter, Route, Search, Terminal, Waypoints } from 'lucide-react'
import type { ReactNode } from 'react'
import type { GraphFragment } from '../../api/types'
import type { CanvasOps } from '../../graph/useCanvasOps'
import { cn } from '../../lib/format'
import { AttackPathsPanel } from './AttackPathsPanel'
import { BlastPanel } from './BlastPanel'
import { CypherPanel } from './CypherPanel'
import { FiltersPanel } from './FiltersPanel'
import { PathFinder } from './PathFinder'
import { SeedSearch } from './SeedSearch'

export type SideTab = 'search' | 'filters' | 'paths' | 'blast' | 'attack' | 'cypher'

const TABS: { id: SideTab; label: string; icon: ReactNode; title: string }[] = [
  { id: 'search', label: 'Seed', icon: <Search size={14} />, title: 'Search a node and load its neighborhood' },
  { id: 'filters', label: 'Filters', icon: <Filter size={14} />, title: 'Label / category and edge-type filters' },
  { id: 'paths', label: 'Paths', icon: <Route size={14} />, title: 'Path finder (GET /graph/paths)' },
  { id: 'blast', label: 'Blast', icon: <Crosshair size={14} />, title: 'Blast radius (GET /graph/blast-radius)' },
  { id: 'attack', label: 'Attack', icon: <Waypoints size={14} />, title: 'Attack paths (GET /graph/attack-paths)' },
  { id: 'cypher', label: 'Cypher', icon: <Terminal size={14} />, title: 'Read-only Cypher (POST /graph/cypher)' },
]

interface Props {
  tab: SideTab
  onTab: (t: SideTab) => void
  loaded: GraphFragment
  loading: boolean
  error: unknown
  selectedId: string | null
  ops: CanvasOps
  hiddenLabels: Set<string>
  hiddenEdges: Set<string>
  onHiddenLabels: (s: Set<string>) => void
  onHiddenEdges: (s: Set<string>) => void
  onLoadSeed: (id: string) => void
  onClear: () => void
}

export function ExplorerSidebar(p: Props) {
  const filterCount = p.hiddenLabels.size + p.hiddenEdges.size
  return (
    <aside className="flex w-[300px] shrink-0 flex-col border-r border-line bg-panel">
      <div className="grid grid-cols-6 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            title={t.title}
            onClick={() => p.onTab(t.id)}
            className={cn('relative flex flex-col items-center gap-0.5 py-2 text-[10px] text-fg-3 hover:bg-panel-2 hover:text-fg', p.tab === t.id && 'bg-panel-2 text-accent')}
          >
            {t.icon}
            {t.label}
            {t.id === 'filters' && filterCount > 0 && <span className="absolute right-1 top-1 h-1.5 w-1.5 rounded-full bg-sev-medium" />}
            {p.tab === t.id && <span className="absolute inset-x-2 bottom-0 h-[2px] rounded-t bg-accent" />}
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {p.tab === 'search' && <SeedSearch loaded={p.loaded} loading={p.loading} error={p.error} onLoadSeed={p.onLoadSeed} onClear={p.onClear} />}
        {p.tab === 'filters' && <FiltersPanel loaded={p.loaded} hiddenLabels={p.hiddenLabels} hiddenEdges={p.hiddenEdges} onHiddenLabels={p.onHiddenLabels} onHiddenEdges={p.onHiddenEdges} />}
        {p.tab === 'paths' && <PathFinder ops={p.ops} selectedId={p.selectedId} />}
        {p.tab === 'blast' && <BlastPanel ops={p.ops} selectedId={p.selectedId} />}
        {p.tab === 'attack' && <AttackPathsPanel ops={p.ops} selectedId={p.selectedId} />}
        {p.tab === 'cypher' && <CypherPanel ops={p.ops} />}
      </div>
    </aside>
  )
}
