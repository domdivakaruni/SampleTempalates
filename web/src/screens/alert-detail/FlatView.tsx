import { Info } from 'lucide-react'
import type { AlertContext } from '../../api/types'
import { KeyValueTable } from '../../components/KeyValueTable'
import { SeverityChip } from '../../components/chips'
import { fmtNum } from '../../lib/format'
import { sourceLabel } from '../../theme'

const CONSOLE_NAMES: Record<string, string> = {
  falcon: 'EDR console (Falcon-like detection record)',
  cspm: 'CSPM console (cloud posture issue)',
  waf: 'WAF / edge console',
  ids: 'IDS sensor console',
  'cloud-anomaly': 'Cloud anomaly detector finding',
  okta: 'Identity provider (IdP) system log',
}

/** The vendor's raw fields, exactly as the source console shows them: no graph context applied. */
export function FlatView({ ctx }: { ctx: AlertContext }) {
  const a = ctx.alert
  const fields = Object.keys(ctx.flat_view).length
  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="mx-auto max-w-4xl space-y-3">
        <div className="flex items-start gap-2 rounded-md border border-sev-medium/30 bg-sev-medium/5 px-3 py-2 text-xs text-fg-2">
          <Info size={14} className="mt-0.5 shrink-0 text-sev-medium" />
          <div>
            <span className="font-medium text-fg">This is what the {sourceLabel(a.source_system)} console shows.</span> {fmtNum(fields)} vendor fields, unchanged: a <SeverityChip severity={a.vendor_severity} /> {a.alert_type} on{' '}
            <span className="font-medium text-fg">{a.hostname ?? a.entity_name ?? 'the resource'}</span>. No entity resolution, no cloud identity chain, no data sensitivity, no threat intel, no correlation with other hosts. Switch to <span className="font-medium text-fg">Graph context</span> to see why Throughline ranks it #{a.contextual_rank_position ?? '?'} (score {a.contextual_score}).
          </div>
        </div>
        <div className="panel overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-panel-2 px-3 py-2 text-xs">
            <span className="font-medium text-fg">{CONSOLE_NAMES[a.source_system] ?? `${a.source_system} console`}</span>
            <span className="mono text-[10.5px] text-fg-3">{a.id}</span>
          </div>
          <KeyValueTable data={ctx.flat_view} />
        </div>
        {ctx.storyline && (
          <p className="text-[11px] text-fg-3">
            The console groups this alert with {a.hostname ? `other detections on ${a.hostname}` : 'nothing else'}; it does not know that it is stage {ctx.storyline.stages.find((s) => s.alert_ids.includes(a.id))?.order ?? '?'} of {ctx.storyline.stage_count} in “{ctx.storyline.title}”.
          </p>
        )}
      </div>
    </div>
  )
}
