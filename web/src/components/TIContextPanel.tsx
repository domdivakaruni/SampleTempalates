import { useNavigate } from 'react-router-dom'
import type { TIContext } from '../api/types'
import { fmtPct, shortId } from '../lib/format'
import { LabelIcon } from './LabelIcon'
import { NodeRef } from './NodeRef'
import { Pill } from './chips'

interface Props {
  ti: TIContext
  compact?: boolean
  onEvidence?: (ids: string[]) => void
}

/** Threat-intel context: actors, campaigns, malware, exploited CVEs, matched IOCs with confidence, reports. */
export function TIContextPanel({ ti, compact, onEvidence }: Props) {
  const navigate = useNavigate()
  const empty = !ti.actors.length && !ti.matches.length && !ti.exploited_vulnerabilities.length
  if (empty) return <div className="text-xs text-fg-3">No threat-intelligence match.</div>
  return (
    <div className="space-y-2 text-xs">
      {ti.summary && <p className="leading-snug text-fg-2">{ti.summary}</p>}
      {(ti.actors.length > 0 || ti.campaigns.length > 0) && (
        <div className="flex flex-wrap gap-1.5">
          {ti.actors.map((a) => (
            <button type="button" key={a.id} className="chip border-cat-ti/40 bg-cat-ti/10 text-cat-ti hover:bg-cat-ti/20" onClick={() => navigate(`/threat-intel/actors/${encodeURIComponent(a.id)}`)} title={`Sector relevance ${fmtPct(Number(a.props.sector_targeting_relevance ?? 0))}`}>
              <LabelIcon label="ThreatActor" size={11} color="currentColor" /> {a.name}
              <span className="opacity-70">{fmtPct(Number(a.props.sector_targeting_relevance ?? 0))}</span>
            </button>
          ))}
          {ti.campaigns.map((c) => (
            <button type="button" key={c.id} className="chip border-line-2 text-fg-2 hover:bg-panel-3" onClick={() => navigate(`/threat-intel/campaigns/${encodeURIComponent(c.id)}`)}>
              <LabelIcon label="Campaign" size={11} /> {c.name} <span className="opacity-70">{String(c.props.status ?? '')}</span>
            </button>
          ))}
          {ti.malware.map((m) => (
            <Pill key={m.id} tone="neutral">
              <LabelIcon label="Malware" size={11} /> {m.name}
            </Pill>
          ))}
        </div>
      )}
      {ti.exploited_vulnerabilities.length > 0 && (
        <div>
          <div className="panel-title mb-1">Exploited vulnerabilities</div>
          <div className="flex flex-wrap gap-1.5">
            {ti.exploited_vulnerabilities.map((v) => (
              <Pill key={v.id} tone="bad" title={String(v.props.description ?? '')}>
                {v.name} · {String(v.props.exploitation_status ?? '').replace('_', ' ')}
              </Pill>
            ))}
          </div>
        </div>
      )}
      {ti.matches.length > 0 && (
        <div>
          <div className="panel-title mb-1">Matched indicators ({ti.matches.length})</div>
          <ul className="space-y-1">
            {ti.matches.slice(0, compact ? 4 : 12).map((m) => (
              <li key={`${m.indicator_id}-${m.matched_node_id}`} className="flex items-center justify-between gap-2 rounded border border-line bg-panel-2/60 px-2 py-1">
                <span className="flex min-w-0 items-center gap-1.5">
                  <span className="chip border-line-2 text-fg-3 uppercase">{m.ioc_type}</span>
                  <span className="mono truncate text-[11px] text-fg" title={m.value}>{m.value.length > 34 ? `${m.value.slice(0, 16)}…${m.value.slice(-12)}` : m.value}</span>
                </span>
                <span className="flex shrink-0 items-center gap-2">
                  <span className="text-fg-3">on</span>
                  <NodeRef id={m.matched_node_id} label={m.matched_label} name={shortId(m.matched_node_id)} mono />
                  <ConfidenceDots value={m.confidence} />
                </span>
              </li>
            ))}
            {ti.matches.length > (compact ? 4 : 12) && <li className="text-[11px] text-fg-3">+{ti.matches.length - (compact ? 4 : 12)} more</li>}
          </ul>
          {onEvidence && (
            <button type="button" className="btn-ghost mt-1" onClick={() => onEvidence([...new Set([...ti.matches.map((m) => m.matched_node_id), ...ti.matches.map((m) => m.indicator_id)])])}>
              Highlight matches on canvas
            </button>
          )}
        </div>
      )}
      {Object.keys(ti.ttp_overlap).length > 0 && (
        <div className="text-[11px] text-fg-3">
          TTP overlap: {Object.entries(ti.ttp_overlap).map(([k, v]) => `${shortId(k)} ${fmtPct(v)}`).join(', ')}
        </div>
      )}
      {ti.reports.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {ti.reports.map((r) => (
            <button type="button" key={r.id} className="chip border-line-2 text-fg-2 hover:bg-panel-3 max-w-full" onClick={() => navigate(`/threat-intel/reports/${encodeURIComponent(r.id)}`)} title={r.name}>
              <LabelIcon label="IntelReport" size={11} /> <span className="truncate">{shortId(r.id)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export function ConfidenceDots({ value }: { value: number }) {
  const n = Math.round(value * 5)
  return (
    <span className="inline-flex items-center gap-[2px]" title={`confidence ${value.toFixed(2)}`}>
      {Array.from({ length: 5 }).map((_, i) => (
        <span key={i} className="h-1.5 w-1.5 rounded-full" style={{ background: i < n ? 'var(--color-cat-ti)' : '#1e293b' }} />
      ))}
    </span>
  )
}
