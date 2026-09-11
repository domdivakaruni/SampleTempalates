import { FileText, Globe, Users } from 'lucide-react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useTiActors, useTiExposure, useTiReports } from '../api/hooks'
import { Page, PageHeader } from '../components/Page'
import { Tabs } from '../components/Tabs'
import { useSearchParamState } from '../lib/useSearchParam'
import { ActorDetail } from './threat-intel/ActorDetail'
import { ActorsTab } from './threat-intel/ActorsTab'
import { ExposureTab } from './threat-intel/ExposureTab'
import { ReportDetail } from './threat-intel/ReportDetail'
import { ReportsTab } from './threat-intel/ReportsTab'

function TIHome() {
  const [tabParam, setTab] = useSearchParamState('tab', 'actors')
  const tab = tabParam === 'exposure' || tabParam === 'reports' ? tabParam : 'actors'
  const actors = useTiActors()
  const reports = useTiReports()
  const exposure = useTiExposure(true)
  return (
    <Page className="flex flex-col p-4" scroll={false}>
      <PageHeader title="Threat intel" subtitle="Actor, campaign, IOC and TTP library, matched against live telemetry: selecting an actor highlights the assets in your estate that match it." />
      <Tabs
        className="mt-3"
        active={tab}
        onChange={setTab}
        tabs={[
          { id: 'actors', label: 'Actors', icon: <Users size={13} />, count: actors.data?.items.length ?? null, title: 'GET /threat-intel/actors' },
          { id: 'reports', label: 'Reports', icon: <FileText size={13} />, count: reports.data?.items.length ?? null, title: 'GET /threat-intel/reports' },
          { id: 'exposure', label: 'Exposure', icon: <Globe size={13} />, count: exposure.data?.items.length ?? null, title: 'GET /threat-intel/exposure (demo question 5)' },
        ]}
      />
      <div className="mt-3 min-h-0 flex-1 overflow-hidden">{tab === 'exposure' ? <ExposureTab /> : tab === 'reports' ? <ReportsTab /> : <ActorsTab />}</div>
    </Page>
  )
}

/** /threat-intel?tab=actors|reports|exposure plus nested actor / campaign / report detail routes. */
export function ThreatIntel() {
  return (
    <Routes>
      <Route index element={<TIHome />} />
      <Route path="actors/:id" element={<ActorDetail kind="actor" />} />
      <Route path="campaigns/:id" element={<ActorDetail kind="campaign" />} />
      <Route path="reports/:id" element={<ReportDetail />} />
      <Route path="*" element={<Navigate to="/threat-intel" replace />} />
    </Routes>
  )
}
