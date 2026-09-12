/** Client-side filter / sort / page over `alerts.json` (GET /alerts), mirroring the mock adapter's `alertsList`. */
import type { Query } from '../client'
import type { AlertListOut, AlertSort, AlertSummary } from '../types'
import { bool, num, str } from './query'

const byTimeDesc = (a: AlertSummary, b: AlertSummary) => (b.detected_at ?? '').localeCompare(a.detected_at ?? '')

function byRank(a: number | null | undefined, b: number | null | undefined): number {
  return typeof a === 'number' && typeof b === 'number' ? a - b : 0
}

/** Contextual order = the exporter's rank positions (file order as a tiebreak); vendor = vendor rank; time = newest first. */
export function sortAlerts(all: AlertSummary[], sort: AlertSort): AlertSummary[] {
  const items = [...all]
  if (sort === 'time') return items.sort(byTimeDesc)
  if (sort === 'vendor') return items.sort((a, b) => byRank(a.vendor_rank_position, b.vendor_rank_position) || b.vendor_severity_rank - a.vendor_severity_rank || byTimeDesc(a, b))
  return items.sort((a, b) => byRank(a.contextual_rank_position, b.contextual_rank_position) || b.contextual_score - a.contextual_score || byTimeDesc(a, b))
}

export function alertsList(all: AlertSummary[], query: Query): AlertListOut {
  const sortParam = str(query.sort, 'contextual')
  const sort: AlertSort = sortParam === 'vendor' || sortParam === 'time' ? sortParam : 'contextual'
  let items = sortAlerts(all, sort)
  if (str(query.order, 'desc') === 'asc') items.reverse()
  const band = str(query.band)
  const severity = str(query.severity)
  const source = str(query.source)
  const storyline = str(query.storyline)
  const q = str(query.q).trim().toLowerCase()
  const rcj = bool(query.reaches_crown_jewel)
  const oap = bool(query.on_attack_path)
  items = items.filter(
    (a) =>
      (!band || a.contextual_band === band) &&
      (!severity || a.vendor_severity === severity) &&
      (!source || a.source_system === source) &&
      (!storyline || a.storyline_id === storyline) &&
      (rcj === undefined || a.reaches_crown_jewel === rcj) &&
      (oap === undefined || a.on_attack_path === oap) &&
      (!q || a.title.toLowerCase().includes(q) || (a.hostname ?? '').toLowerCase().includes(q) || (a.entity_name ?? '').toLowerCase().includes(q) || a.id.toLowerCase().includes(q) || (a.user ?? '').toLowerCase().includes(q)),
  )
  const limit = Math.max(1, num(query.limit, 50, 500))
  const offset = Math.max(0, num(query.offset, 0))
  return { items: items.slice(offset, offset + limit), total: items.length, limit, offset }
}

/** Alerts sharing the storyline, entity or host of `alert` (for the lite alert context). */
export function relatedAlerts(all: AlertSummary[], alert: AlertSummary, limit = 12): AlertSummary[] {
  return all
    .filter((a) => a.id !== alert.id && ((!!alert.storyline_id && a.storyline_id === alert.storyline_id) || (!!a.entity_id && a.entity_id === alert.entity_id) || (!!alert.hostname && a.hostname === alert.hostname)))
    .sort((a, b) => b.contextual_score - a.contextual_score)
    .slice(0, limit)
}

/** Alerts whose primary entity is one of `entityIds` (or that are listed in `alertIds`), best contextual score first. */
export function alertsOnEntities(all: AlertSummary[], entityIds: Set<string>, alertIds: Set<string> = new Set()): AlertSummary[] {
  return sortAlerts(all.filter((a) => (!!a.entity_id && entityIds.has(a.entity_id)) || alertIds.has(a.id)), 'contextual')
}
