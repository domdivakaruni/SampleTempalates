import { Bell, GitBranch, LayoutDashboard, Radar, Waypoints } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { cn } from '../../lib/format'

const ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/storylines', label: 'Storylines', icon: GitBranch },
  { to: '/explorer', label: 'Graph Explorer', icon: Waypoints },
  { to: '/threat-intel', label: 'Threat Intel', icon: Radar },
]

export function NavRail() {
  return (
    <nav className="flex h-full w-14 shrink-0 flex-col items-center border-r border-line bg-panel py-2" aria-label="Primary">
      <NavLink to="/" className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 text-accent" title="Throughline">
        <svg viewBox="0 0 32 32" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round">
          <path d="M6 22 L13 10 L19 18 L26 8" />
          <circle cx="6" cy="22" r="2" fill="#f87171" stroke="none" />
          <circle cx="13" cy="10" r="2" fill="#a78bfa" stroke="none" />
          <circle cx="19" cy="18" r="2" fill="#2dd4bf" stroke="none" />
          <circle cx="26" cy="8" r="2" fill="#fbbf24" stroke="none" />
        </svg>
      </NavLink>
      {ITEMS.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          title={label}
          className={({ isActive }) =>
            cn('group relative my-0.5 flex h-10 w-10 items-center justify-center rounded-lg text-fg-3 transition-colors hover:bg-panel-3 hover:text-fg', isActive && 'bg-panel-3 text-accent')
          }
        >
          {({ isActive }) => (
            <>
              {isActive && <span className="absolute -left-2 h-5 w-[3px] rounded-r bg-accent" />}
              <Icon size={18} />
              <span className="pointer-events-none absolute left-12 z-50 hidden whitespace-nowrap rounded border border-line bg-panel-2 px-2 py-1 text-[11px] text-fg shadow-lg group-hover:block">{label}</span>
            </>
          )}
        </NavLink>
      ))}
      <div className="mt-auto px-1 text-center text-[9px] leading-tight text-fg-3">Larkspur Financial · sim</div>
    </nav>
  )
}
