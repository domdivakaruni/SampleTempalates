import { Bot, PanelRightClose } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import { useApiMode, useHealth } from '../../api/hooks'
import { cn, fmtNum } from '../../lib/format'
import { useDrawerStore } from '../../store/drawerStore'
import { GlobalSearch } from './GlobalSearch'

const TITLES: [RegExp, string][] = [
  [/^\/$/, 'Dashboard'],
  [/^\/alerts\/.+/, 'Alert detail'],
  [/^\/alerts/, 'Alerts'],
  [/^\/storylines\/.+/, 'Storyline'],
  [/^\/storylines/, 'Storylines'],
  [/^\/explorer/, 'Graph Explorer'],
  [/^\/threat-intel/, 'Threat Intel'],
]

export function TopBar() {
  const { pathname } = useLocation()
  const title = TITLES.find(([re]) => re.test(pathname))?.[1] ?? 'Throughline'
  const open = useDrawerStore((s) => s.open)
  const toggle = useDrawerStore((s) => s.toggle)
  const streaming = useDrawerStore((s) => s.streaming)
  const mode = useApiMode()
  const health = useHealth()
  return (
    <header className="flex h-12 shrink-0 items-center gap-4 border-b border-line bg-panel px-4">
      <div className="flex items-baseline gap-2 min-w-[160px]">
        <span className="text-sm font-semibold tracking-tight text-fg">Throughline</span>
        <span className="text-xs text-fg-3">/ {title}</span>
      </div>
      <div className="flex flex-1 justify-center">
        <GlobalSearch />
      </div>
      <div className="flex items-center gap-2">
        {mode === 'mock' && (
          <span className="chip border-sev-medium/40 bg-sev-medium/10 text-sev-medium" title="The API is unreachable or VITE_MOCK=1: the UI is serving fixtures from src/api/mock">
            Mock data
          </span>
        )}
        {mode === 'snapshot' && (
          <span className="chip border-accent/40 bg-accent/10 text-accent" title="Static edition (VITE_STATIC=1): every payload was precomputed from the simulated graph; no backend, no query engine, the analyst replays prepared answers">
            Static edition
          </span>
        )}
        {health.data && (
          <span className="hidden items-center gap-1 text-[11px] text-fg-3 lg:flex" title={`backend ${health.data.backend}, agent ${health.data.agent_mode}${health.data.model ? ` (${health.data.model})` : ''}`}>
            <span className={cn('h-1.5 w-1.5 rounded-full', health.data.status === 'ok' ? 'bg-cat-endpoint' : 'bg-sev-critical')} />
            {fmtNum(health.data.total_nodes)} nodes · {fmtNum(health.data.total_edges)} edges
          </span>
        )}
        <button type="button" data-testid="analyst-toggle" onClick={toggle} className={cn('btn', open && 'border-accent/50 text-accent')} title="Toggle the Analyst drawer" aria-pressed={open}>
          {open ? <PanelRightClose size={13} /> : <Bot size={13} />}
          Analyst
          {streaming && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />}
        </button>
      </div>
    </header>
  )
}
