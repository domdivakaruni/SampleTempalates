import { useNavigate } from 'react-router-dom'
import type { DashboardCoverage, DashboardKpis } from '../../api/types'
import { KpiTile } from '../../components/KpiTile'
import { fmtNum } from '../../lib/format'

export function KpiTiles({ kpis, coverage }: { kpis: DashboardKpis; coverage: DashboardCoverage }) {
  const navigate = useNavigate()
  return (
    <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-8">
      <KpiTile label="Open alerts" value={fmtNum(kpis.open_alerts)} hint="all sources" onClick={() => navigate('/alerts')} />
      <KpiTile label="Critical (context)" value={fmtNum(kpis.critical_contextual)} tone={kpis.critical_contextual ? 'bad' : 'neutral'} hint="contextual band ≥ 90" onClick={() => navigate('/alerts?band=critical')} />
      <KpiTile label="Storylines" value={fmtNum(kpis.storylines)} tone="accent" hint="correlated intrusions" onClick={() => navigate('/storylines')} />
      <KpiTile
        label="Jewels at risk"
        value={
          <span>
            {fmtNum(kpis.crown_jewels_at_risk)}
            <span className="text-sm text-fg-3"> / {fmtNum(kpis.crown_jewels)}</span>
          </span>
        }
        tone={kpis.crown_jewels_at_risk ? 'bad' : 'good'}
        hint="reachable from an active alert"
        onClick={() => navigate('/alerts?rcj=1')}
      />
      <KpiTile label="Exploited exposure" value={fmtNum(kpis.internet_exposed_exploited)} tone={kpis.internet_exposed_exploited ? 'warn' : 'neutral'} hint="internet-facing hosts with an actively exploited CVE" onClick={() => navigate('/threat-intel?tab=exposure')} />
      <KpiTile
        label="EDR coverage"
        value={`${fmtNum(kpis.endpoint_coverage_pct, kpis.endpoint_coverage_pct % 1 ? 1 : 0)}%`}
        tone={kpis.endpoint_coverage_pct >= 90 ? 'good' : 'warn'}
        hint={`${fmtNum(coverage.vms_without_sensor_prod)} prod VMs without a sensor`}
      />
      <KpiTile label="IOC matches" value={fmtNum(kpis.ioc_matches)} tone={kpis.ioc_matches ? 'warn' : 'neutral'} hint="indicators seen in telemetry" onClick={() => navigate('/threat-intel')} />
      <KpiTile label="Endpoints" value={fmtNum(kpis.endpoints)} hint={`${fmtNum(coverage.endpoints_resolved_to_vm)} resolved to cloud VMs`} />
    </div>
  )
}
