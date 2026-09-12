/** GET /search over `search.json`: exact / prefix / substring scoring on name, id and the exporter's extra tokens. */
import type { SearchHit } from '../types'
import type { SearchEntry } from './schema'

export function searchEntries(entries: SearchEntry[], q: string, labels?: string[], limit = 25): SearchHit[] {
  const needle = q.trim().toLowerCase()
  if (!needle) return []
  const labelSet = labels?.length ? new Set(labels) : null
  const hits: SearchHit[] = []
  for (const [id, label, name, category, snippet, extra] of entries) {
    if (labelSet && !labelSet.has(label)) continue
    let score = 0
    const consider = (hay: string) => {
      const l = hay.toLowerCase()
      if (!l) return
      if (l === needle) score = Math.max(score, 1)
      else if (l.startsWith(needle)) score = Math.max(score, 0.8)
      else if (l.includes(needle)) score = Math.max(score, 0.5)
    }
    consider(name)
    consider(id)
    if (extra && score < 1) {
      for (const token of extra.split(' ')) {
        if (!token) continue
        consider(token)
        if (score >= 1) break
      }
      // multi-word needles: a substring of the joined tokens still counts, at a lower score
      if (score === 0 && extra.toLowerCase().includes(needle)) score = 0.4
    }
    if (score > 0) hits.push({ id, label, name, category, snippet: snippet || null, score })
  }
  hits.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name))
  return hits.slice(0, Math.max(1, limit))
}
