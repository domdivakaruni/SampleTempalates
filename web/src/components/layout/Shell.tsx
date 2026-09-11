import { Outlet } from 'react-router-dom'
import { AnalystDrawer } from '../analyst/AnalystDrawer'
import { NavRail } from './NavRail'
import { TopBar } from './TopBar'

export function Shell() {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-bg text-fg">
      <NavRail />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <div className="flex min-h-0 flex-1">
          <main className="min-w-0 flex-1 overflow-hidden">
            <Outlet />
          </main>
          <AnalystDrawer />
        </div>
      </div>
    </div>
  )
}
