import { useNavigate } from 'react-router-dom'
import type { Band, DashboardCoverage, TIPressureItem } from '../../api/types'
import { HBars, Ring } from '../../components/Bars'
import { LabelIcon } from '../../components/LabelIcon'
import { Panel } from '../../components/Page'
import { fmtNum, fmtPct } from '../../lib/format'
import { bandColor, sourceLabel } from '../../theme'

const BAND_ORDER: Band[] = ['critical', 'high', 'medium', 'low', 'noise']

export function BandAndSourceBars({ bands, sources }: { bands: Record<Band, number>; sources: Record<string, number> }) {
  const navigate = useNavigate()
  const bandData = BAND_ORDER.map((b) => ({ label: b, value: bands[b] ?? 0, color: bandColor(b), hint: `${fmtNum(bands[b] ?? 0)} alerts in the ${b} band` }))
  const sourceData = Object.entries(sources).sort(([, a], [, b]) => b - a).map(([s, v]) => ({ label: sourceLabel(s), value: v, hint: `${fmtNum(v)} alerts from ${s}` }))
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Panel title="Alerts by contextual band" actions={<button type="button" className="btn-ghost py-0.5" onClick={() => navigate('/alerts?band=noise&sort=vendor')}>vendor High+ scored noise →</button>}>
        <HBars data={bandData} />
      </Panel>
      <Panel title="Alerts by source">
        <HBars data={sourceData} />
      </Panel>
    </div>
  )
}

export function CoveragePanel({ coverage }: { coverage: DashboardCoverage }) {
  const pct = coverage.vms_total ? coverage.vms_with_sensor / coverage.vms_total : 0
  const resolved = coverage.endpoints_total ? coverage.endpoints_resolved_to_vm / coverage.endpoints_total : 0
  return (
    <Panel title="Coverage">
      <div className="flex items-center gap-4">
        <Ring pct={pct} size={64} color={pct >= 0.9 ? 'var(--color-cat-endpoint)' : 'var(--color-sev-medium)'} />
        <div className="min-w-0 flex-1 space-y-1 text-xs">
          <div className="flex justify-between gap-2"><span className="text-fg-2">Cloud VMs with EDR sensor</span><span className="tabular-nums text-fg">{fmtNum(coverage.vms_with_sensor)} / {fmtNum(coverage.vms_total)}</span></div>
          <div className="flex justify-between gap-2"><span className="text-fg-2">Prod VMs without a sensor</span><span className={`tabular-nums ${coverage.vms_without_sensor_prod ? 'text-sev-medium' : 'text-fg'}`}>{fmtNum(coverage.vms_without_sensor_prod)}</span></div>
          <div className="flex justify-between gap-2"><span className="text-fg-2">Endpoints resolved to a cloud VM</span><span className="tabular-nums text-fg">{fmtNum(coverage.endpoints_resolved_to_vm)} / {fmtNum(coverage.endpoints_total)} ({fmtPct(resolved)})</span></div>
          <div className="text-[10.5px] text-fg-3">Entity resolution (SAME_AS) joins EDR devices to cloud instances so endpoint alerts inherit cloud blast radius.</div>
        </div>
      </div>
    </Panel>
  )
}

export function TIPressure({ items }: { items: TIPressureItem[] }) {
  const navigate = useNavigate()
  return (
    <Panel title="Threat-intel pressure" actions={<button type="button" className="btn-ghost py-0.5" onClick={() => navigate('/threat-intel')}>Library →</button>} flush>
      {items.length === 0 && <div className="p-3 text-xs text-fg-3">No actor with matches in the estate.</div>}
      <ul className="divide-y divide-line/70">
        {items.map((t) => (
          <li key={t.actor_id}>
            <button type="button" className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-panel-2" onClick={() => navigate(`/threat-intel/actors/${encodeURIComponent(t.actor_id)}`)}>
              <LabelIcon label="ThreatActor" size={13} />
              <span className="w-[112px] shrink-0 truncate font-medium text-fg" title={t.actor_id}>{t.actor_name}</span>
              <span className="flex w-[90px] shrink-0 items-center gap-1" title={`Sector targeting relevance ${t.sector_relevance.toFixed(2)}`}>
                <span className="h-1.5 flex-1 overflow-hidden rounded bg-panel-3"><span className="block h-full rounded bg-cat-ti" style={{ width: `${Math.round(t.sector_relevance * 100)}%` }} /></span>
                <span className="w-7 text-right tabular-nums text-fg-3">{fmtPct(t.sector_relevance)}</span>
              </span>
              <span className="flex flex-1 flex-wrap justify-end gap-x-3 gap-y-0.5 tabular-nums text-fg-2">
                <span title="Campaigns">{t.campaigns} camp.</span>
                <span title="IOC matches in telemetry" className={t.ioc_matches ? 'text-cat-ti' : ''}>{t.ioc_matches} IOC</span>
                <span title="Actively exploited CVEs present on our hosts" className={t.exploited_cves_present ? 'text-sev-high' : ''}>{t.exploited_cves_present} CVE</span>
                <span title="Attributed alerts" className={t.alerts ? 'text-fg' : ''}>{t.alerts} alerts</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  )
}
