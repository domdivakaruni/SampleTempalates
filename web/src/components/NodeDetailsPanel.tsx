import { Bot, Crosshair, Expand, ExternalLink, Pin, PinOff, X } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useNode } from '../api/hooks'
import type { JsonValue, NodeOut } from '../api/types'
import { CATEGORY_NAMES } from '../graph/schema'
import { cn, fmtValue, humanKey, isComplex } from '../lib/format'
import { useDrawerStore } from '../store/drawerStore'
import { useSelectionStore } from '../store/selectionStore'
import { categoryColor } from '../theme'
import { AlertsTable } from './AlertsTable'
import { LabelIcon } from './LabelIcon'
import { TIContextPanel } from './TIContextPanel'
import { Pill } from './chips'
import { ErrorState, SkeletonBlock } from './states'

interface Props {
  nodeId: string
  onClose?: () => void
  onExpand?: (id: string) => void
  onBlastRadius?: (id: string) => void
  className?: string
  inExplorer?: boolean
}

const GROUPS: [string, string[]][] = [
  ['Identity', ['hostname', 'display_name', 'email', 'title', 'department', 'arn', 'account_id', 'provider', 'region', 'environment', 'role_type', 'credential_type', 'principal_id', 'cve_id', 'technique_id', 'ioc_type', 'value', 'event_name', 'event_source', 'event_time', 'principal_arn', 'access_key_id']],
  ['Network & exposure', ['private_ip', 'public_ip', 'exposure', 'public', 'open_to_internet', 'internet_ports', 'source_ip', 'address', 'asn', 'asn_org', 'country', 'reputation', 'fqdn', 'ssh_ingress']],
  ['Security', ['criticality', 'sensitivity', 'data_classifications', 'crown_jewel', 'has_edr_sensor', 'is_admin', 'privilege_score', 'mfa_enabled', 'exploitation_status', 'cvss', 'epss', 'kev', 'sector_targeting_relevance', 'confidence', 'verdict', 'malware_family', 'sha256', 'ti_exposure_score', 'crown_jewel_reach', 'status', 'active', 'anomalous', 'anomaly_reasons']],
  ['Time', ['first_seen', 'last_seen', 'detected_at', 'issued_at', 'expires_at', 'last_used', 'published', 'started', 'start_time', 'end_time', 'logon_time', 'last_seen_sensor', 'rotated_days_ago']],
]
const HIDDEN = new Set(['source', 'source_id', 'raw', 'statements', 'body', 'score_breakdown'])

function groupProps(props: Record<string, JsonValue | undefined>): [string, [string, JsonValue | undefined][]][] {
  const used = new Set<string>()
  const out: [string, [string, JsonValue | undefined][]][] = []
  for (const [title, keys] of GROUPS) {
    const rows: [string, JsonValue | undefined][] = []
    for (const k of keys) if (k in props && props[k] !== undefined && props[k] !== null && props[k] !== '') { rows.push([k, props[k]]); used.add(k) }
    if (rows.length) out.push([title, rows])
  }
  const rest = Object.entries(props).filter(([k, v]) => !used.has(k) && !HIDDEN.has(k) && v !== undefined && v !== null && v !== '')
  if (rest.length) out.push(['Other', rest])
  return out
}

export function NodeDetailsPanel({ nodeId, onClose, onExpand, onBlastRadius, className, inExplorer }: Props) {
  const q = useNode(nodeId)
  const navigate = useNavigate()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const pinned = useSelectionStore((s) => s.pinned.includes(nodeId))
  const togglePin = useSelectionStore((s) => s.togglePin)
  return (
    <div className={cn('flex h-full flex-col overflow-hidden', className)}>
      {q.isLoading && <SkeletonBlock lines={8} className="p-3" />}
      {q.error && <ErrorState error={q.error} onRetry={() => q.refetch()} compact />}
      {q.data && (
        <>
          <Header node={q.data.node} onClose={onClose} />
          <div className="flex flex-wrap gap-1 border-b border-line px-3 py-2">
            {onExpand && (
              <button type="button" className="btn" onClick={() => onExpand(nodeId)}>
                <Expand size={12} /> Expand
              </button>
            )}
            {onBlastRadius && (
              <button type="button" className="btn" onClick={() => onBlastRadius(nodeId)}>
                <Crosshair size={12} /> Blast radius
              </button>
            )}
            <button type="button" className="btn" onClick={() => askAbout(`What is ${q.data!.node.name} (${nodeId}) and what can an attacker reach from it?`, { node_id: nodeId, selected_node_ids: [nodeId] })}>
              <Bot size={12} /> Ask analyst
            </button>
            <button type="button" className="btn" onClick={() => togglePin(nodeId)} title={pinned ? 'Unpin' : 'Pin'}>
              {pinned ? <PinOff size={12} /> : <Pin size={12} />}
            </button>
            {!inExplorer && (
              <button type="button" className="btn" onClick={() => navigate(`/explorer?id=${encodeURIComponent(nodeId)}`)}>
                <ExternalLink size={12} /> Explorer
              </button>
            )}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-3 py-2 text-xs">
            <div className="flex flex-wrap gap-1">
              {q.data.node.tags.map((t) => (
                <Pill key={t} tone={t === 'crown_jewel' ? 'bad' : t === 'internet_exposed' ? 'accent' : 'neutral'}>{t}</Pill>
              ))}
              <Pill tone="neutral" title="in / out degree">deg {q.data.degree.in}↓ {q.data.degree.out}↑</Pill>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {Object.entries(q.data.edge_type_counts).sort(([, a], [, b]) => b - a).map(([t, c]) => (
                <span key={t} className="mono rounded bg-panel-2 px-1 py-[1px] text-[10px] text-fg-2">
                  {t} <span className="text-fg-3">{c}</span>
                </span>
              ))}
            </div>
            {groupProps(q.data.node.props).map(([title, rows]) => (
              <div key={title} className="mt-3">
                <div className="panel-title mb-1">{title}</div>
                <table className="w-full table-fixed">
                  <tbody>
                    {rows.map(([k, v]) => (
                      <tr key={k} className="border-b border-line/50 align-top last:border-0">
                        <td className="w-[42%] py-1 pr-2 text-fg-2">{humanKey(k)}</td>
                        <td className="py-1 break-words text-fg">{isComplex(v) ? <pre className="whitespace-pre-wrap text-[10.5px] text-fg-2">{JSON.stringify(v, null, 1)}</pre> : <span className={typeof v === 'string' && v.length > 20 ? 'mono text-[11px]' : ''}>{fmtValue(v)}</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
            {q.data.alerts.length > 0 && (
              <div className="mt-3">
                <div className="panel-title mb-1">Alerts on this node ({q.data.alerts.length})</div>
                <div className="-mx-3">
                  <AlertsTable alerts={q.data.alerts.slice(0, 8)} columns={['title', 'vendor', 'contextual']} />
                </div>
              </div>
            )}
            {q.data.threat_intel && (
              <div className="mt-3">
                <div className="panel-title mb-1">Threat intel</div>
                <TIContextPanel ti={q.data.threat_intel} compact />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function Header({ node, onClose }: { node: NodeOut; onClose?: () => void }) {
  return (
    <div className="flex items-start gap-2 border-b border-line px-3 py-2">
      <div className="mt-0.5 rounded-md border p-1.5" style={{ borderColor: `${categoryColor(node.category)}55`, background: `${categoryColor(node.category)}14` }}>
        <LabelIcon label={node.label} category={node.category} severity={node.severity} size={18} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-semibold text-fg" title={node.name}>{node.name}</div>
        <div className="flex flex-wrap items-center gap-1 text-[11px] text-fg-3">
          <span style={{ color: categoryColor(node.category) }}>{node.label}</span>
          <span>·</span>
          <span>{CATEGORY_NAMES[node.category as keyof typeof CATEGORY_NAMES] ?? node.category}</span>
        </div>
        <div className="mono mt-0.5 truncate text-[10.5px] text-fg-3" title={node.id}>{node.id}</div>
      </div>
      {onClose && (
        <button type="button" className="btn-icon h-6 w-6" onClick={onClose} aria-label="Close">
          <X size={12} />
        </button>
      )}
    </div>
  )
}
