import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, HashRouter, Navigate, Route, Routes } from 'react-router-dom'
import { IS_STATIC_BUILD } from './api/client'
import { Shell } from './components/layout/Shell'
import { AlertDetail } from './screens/AlertDetail'
import { Alerts } from './screens/Alerts'
import { Dashboard } from './screens/Dashboard'
import { Explorer } from './screens/Explorer'
import { StorylineDetail } from './screens/StorylineDetail'
import { Storylines } from './screens/Storylines'
import { ThreatIntel } from './screens/ThreatIntel'

// The static edition is served from plain files (GitHub Pages, an artifact origin), so routes live in the hash.
const Router = IS_STATIC_BUILD ? HashRouter : BrowserRouter

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 30_000 },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Routes>
          <Route element={<Shell />}>
            <Route index element={<Dashboard />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="alerts/:id" element={<AlertDetail />} />
            <Route path="storylines" element={<Storylines />} />
            <Route path="storylines/:id" element={<StorylineDetail />} />
            <Route path="explorer" element={<Explorer />} />
            <Route path="threat-intel/*" element={<ThreatIntel />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </Router>
    </QueryClientProvider>
  )
}
