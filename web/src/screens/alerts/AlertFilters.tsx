import { Crown, Route, Search, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { StorylineOut } from '../../api/types'
import { cn } from '../../lib/format'
import type { ParamPatch } from '../../lib/useSearchParam'
import { sourceLabel } from '../../theme'

export const ALERT_PARAM_KEYS = ['q', 'band', 'severity', 'source', 'storyline', 'rcj', 'oap', 'sort', 'order', 'offset', 'limit'] as const
export type AlertParamKey = (typeof ALERT_PARAM_KEYS)[number]

const BANDS = ['critical', 'high', 'medium', 'low', 'noise']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']
const SOURCES = ['falcon', 'cspm', 'waf', 'ids', 'cloud-anomaly', 'okta']

interface Preset { id: string; label: string; hint: string; patch: ParamPatch<AlertParamKey> }
const PRESETS: Preset[] = [
  { id: 'q2', label: 'Medium EDR alerts with a path to regulated data', hint: 'Demo question 2: severity=medium, source=falcon, reaches_crown_jewel=true', patch: { severity: 'medium', source: 'falcon', rcj: '1', band: null, storyline: null, oap: null, q: null } },
  { id: 'q10', label: 'Only alerts that can reach crown jewels', hint: 'Demo question 10: reaches_crown_jewel=true', patch: { rcj: '1', severity: null, source: null, band: null, oap: null, q: null } },
  { id: 'paths', label: 'On a confirmed attack path', hint: 'on_attack_path=true', patch: { oap: '1', rcj: null, severity: null, source: null, band: null, q: null } },
  { id: 'noise', label: 'Vendor-severe but noise in context', hint: 'band=noise sorted by vendor severity: what the graph demoted', patch: { band: 'noise', sort: 'vendor', order: 'desc', rcj: null, oap: null, severity: null, source: null, q: null } },
]

interface Props {
  values: Record<AlertParamKey, string>
  patch: (p: ParamPatch<AlertParamKey>) => void
  storylines: StorylineOut[]
}

export function AlertFilters({ values, patch, storylines }: Props) {
  const [text, setText] = useState(values.q)
  useEffect(() => setText(values.q), [values.q])
  useEffect(() => {
    if (text === values.q) return
    const t = setTimeout(() => patch({ q: text, offset: null }), 300)
    return () => clearTimeout(t)
  }, [text, values.q, patch])
  const set = (p: ParamPatch<AlertParamKey>) => patch({ ...p, offset: null })
  const activeCount = ['q', 'band', 'severity', 'source', 'storyline', 'rcj', 'oap'].filter((k) => values[k as AlertParamKey]).length
  const isPreset = (p: Preset) => Object.entries(p.patch).every(([k, v]) => (values[k as AlertParamKey] || null) === (v ?? null) || (k === 'sort' || k === 'order'))
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <label className="input flex min-w-[220px] flex-1 items-center gap-2 py-1">
          <Search size={12} className="text-fg-3" />
          <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Search title, host, entity, user…" className="w-full bg-transparent focus:outline-none" aria-label="Search alerts" />
          {text && (
            <button type="button" className="text-fg-3 hover:text-fg" onClick={() => setText('')} aria-label="Clear search">
              <X size={12} />
            </button>
          )}
        </label>
        <select className="select" value={values.band} onChange={(e) => set({ band: e.target.value })} aria-label="Contextual band">
          <option value="">Any band</option>
          {BANDS.map((b) => (
            <option key={b} value={b}>
              band: {b}
            </option>
          ))}
        </select>
        <select className="select" value={values.severity} onChange={(e) => set({ severity: e.target.value })} aria-label="Vendor severity">
          <option value="">Any vendor severity</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              vendor: {s}
            </option>
          ))}
        </select>
        <select className="select" value={values.source} onChange={(e) => set({ source: e.target.value })} aria-label="Source">
          <option value="">Any source</option>
          {SOURCES.map((s) => (
            <option key={s} value={s}>
              {sourceLabel(s)}
            </option>
          ))}
        </select>
        <select className="select max-w-[220px]" value={values.storyline} onChange={(e) => set({ storyline: e.target.value })} aria-label="Storyline">
          <option value="">Any storyline</option>
          {storylines.map((s) => (
            <option key={s.id} value={s.id}>
              {s.title}
            </option>
          ))}
        </select>
        <button type="button" className={cn('btn', values.rcj === '1' && 'border-sev-critical/50 text-sev-critical')} onClick={() => set({ rcj: values.rcj === '1' ? null : '1' })} title="reaches_crown_jewel=true">
          <Crown size={12} /> Reaches crown jewel
        </button>
        <button type="button" className={cn('btn', values.oap === '1' && 'border-accent/50 text-accent')} onClick={() => set({ oap: values.oap === '1' ? null : '1' })} title="on_attack_path=true">
          <Route size={12} /> On attack path
        </button>
        {activeCount > 0 && (
          <button type="button" className="btn-ghost" onClick={() => set({ q: null, band: null, severity: null, source: null, storyline: null, rcj: null, oap: null })}>
            <X size={12} /> Clear {activeCount}
          </button>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
        <span className="text-fg-3">Show me:</span>
        {PRESETS.map((p) => (
          <button key={p.id} type="button" className={cn('chip border-line-2 bg-panel-2 text-fg-2 hover:border-accent/50 hover:text-fg', isPreset(p) && 'border-accent/60 bg-accent/10 text-accent')} title={p.hint} onClick={() => set(p.patch)}>
            {p.label}
          </button>
        ))}
      </div>
    </div>
  )
}
