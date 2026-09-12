/**
 * Lazy, cached loading of the precomputed snapshot files (docs/10-static-snapshot.md section 1).
 *
 * Every path is relative (`snapshot/...`, no leading slash) so the static site works under a sub-path (GitHub Pages)
 * or an artifact origin. With a relative Vite base (`./`) the path is resolved against the document, with an absolute
 * base (`/`, dev server with `?snapshot=1`) against that base.
 */
import { ApiError } from '../client'
import type {
  AlertDetailEntry, AlertDetailsShard, SnapshotAlerts, SnapshotAttackPaths, SnapshotBlastRadius, SnapshotChat, SnapshotEdgeShard,
  SnapshotInvestigate, SnapshotManifest, SnapshotMeta, SnapshotNodeCards, SnapshotNodes, SnapshotSearch, SnapshotStorylines, SnapshotTi,
} from './schema'

const cache = new Map<string, Promise<unknown>>()

export function snapshotUrl(rel: string): string {
  const base = import.meta.env.BASE_URL || '/'
  const path = `snapshot/${rel.replace(/^\/+/, '')}`
  if (/^(?:[a-z]+:)?\/\//i.test(base) || base.startsWith('/')) return `${base.replace(/\/?$/, '/')}${path}`
  if (typeof document !== 'undefined') return new URL(path, document.baseURI).toString()
  return `${base.replace(/\/?$/, '/')}${path}`
}

/** Fetch + parse one snapshot file; concurrent and repeated calls share one request. Failures are not cached. */
export function loadJson<T>(rel: string): Promise<T> {
  let pending = cache.get(rel)
  if (!pending) {
    pending = (async () => {
      const url = snapshotUrl(rel)
      let res: Response
      try {
        res = await fetch(url, { headers: { accept: 'application/json' } })
      } catch (e) {
        throw new ApiError(502, 'upstream_error', `static edition: could not load ${rel} (${e instanceof Error ? e.message : String(e)})`)
      }
      if (!res.ok) {
        if (res.status === 404) throw new ApiError(404, 'not_found', `static edition: ${rel} is not part of this snapshot`)
        throw new ApiError(502, 'upstream_error', `static edition: ${rel} -> HTTP ${res.status}`)
      }
      try {
        return (await res.json()) as T
      } catch (e) {
        throw new ApiError(502, 'upstream_error', `static edition: ${rel} is not valid JSON (${e instanceof Error ? e.message : String(e)})`)
      }
    })()
    cache.set(rel, pending)
    pending.catch(() => cache.delete(rel))
  }
  return pending as Promise<T>
}

export const loadManifest = () => loadJson<SnapshotManifest>('manifest.json')
export const loadMeta = () => loadJson<SnapshotMeta>('meta.json')
export const loadAlerts = () => loadJson<SnapshotAlerts>('alerts.json')
export const loadStorylines = () => loadJson<SnapshotStorylines>('storylines.json')
export const loadTi = () => loadJson<SnapshotTi>('ti.json')
export const loadInvestigate = () => loadJson<SnapshotInvestigate>('investigate.json')
export const loadChat = () => loadJson<SnapshotChat>('chat.json')
export const loadNodes = () => loadJson<SnapshotNodes>('graph/nodes.json')
export const loadBlastRadius = () => loadJson<SnapshotBlastRadius>('graph/blast_radius.json')
export const loadAttackPaths = () => loadJson<SnapshotAttackPaths>('graph/attack_paths.json')
export const loadNodeCards = () => loadJson<SnapshotNodeCards>('node_cards.json')
export const loadSearch = () => loadJson<SnapshotSearch>('search.json')

/** Optional files: a missing file (404) reads as an empty container instead of an error. */
export const loadBlastRadiusOptional = () => loadBlastRadius().catch(optionalAsEmpty<SnapshotBlastRadius>({}))
export const loadAttackPathsOptional = () => loadAttackPaths().catch(optionalAsEmpty<SnapshotAttackPaths>({}))
export const loadNodeCardsOptional = () => loadNodeCards().catch(optionalAsEmpty<SnapshotNodeCards>({}))

function optionalAsEmpty<T>(empty: T): (e: unknown) => T {
  return (e: unknown) => {
    if (e instanceof ApiError && e.status === 404) return empty
    throw e
  }
}

/** All compact edge shards listed in the manifest (falls back to probing `graph/edges-00.json`, `-01`, ... when the list is missing). */
export async function loadEdgeShards(): Promise<SnapshotEdgeShard[]> {
  const manifest = await loadManifest().catch(() => null)
  const listed = manifest?.shards?.edges ?? []
  if (listed.length) return Promise.all(listed.map((f) => loadJson<SnapshotEdgeShard>(`graph/${basename(f)}`)))
  const shards: SnapshotEdgeShard[] = []
  for (let i = 0; i < 64; i++) {
    try {
      shards.push(await loadJson<SnapshotEdgeShard>(`graph/edges-${String(i).padStart(2, '0')}.json`))
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) break
      throw e
    }
  }
  return shards
}

// ----------------------------------------------------------------------------- alert detail shards

/**
 * Shard key = first two hex chars of sha1(alert id) per the contract (the exporter can also use one char; the
 * manifest's `alert_shard_prefix_len` says which). Both schemes are tried, the manifest's shard list decides which
 * candidate files exist.
 */
export function alertShardCandidates(alertId: string, listedFiles: string[], prefixLen?: number): string[] {
  const h = sha1Hex(alertId)
  const candidates = [h.slice(0, 2), h.slice(0, 1), h.slice(0, 1).padStart(2, '0')]
  if (prefixLen === 1 || prefixLen === 2) candidates.unshift(h.slice(0, prefixLen))
  const unique = [...new Set(candidates)]
  if (!listedFiles.length) return unique.slice(0, 2)
  const listed = new Set(listedFiles.map((f) => basename(f).replace(/\.json$/i, '')))
  const known = unique.filter((c) => listed.has(c))
  return known.length ? known : unique
}

export async function loadAlertDetail(alertId: string): Promise<AlertDetailEntry | undefined> {
  const manifest = await loadManifest().catch(() => null)
  for (const key of alertShardCandidates(alertId, manifest?.shards?.alert_details ?? [], manifest?.alert_shard_prefix_len)) {
    let shard: AlertDetailsShard | null = null
    try {
      shard = await loadJson<AlertDetailsShard>(`alert_details/${key}.json`)
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 404)) throw e
    }
    const entry = shard?.[alertId]
    if (entry) return entry
  }
  return undefined
}

function basename(file: string): string {
  const parts = file.split('/')
  return parts[parts.length - 1]
}

// ----------------------------------------------------------------------------- sha1 (sync; crypto.subtle is async and needs a secure context)

/** Hex SHA-1 of the UTF-8 encoding of `input`. Inputs here are short ids, so the 32-bit length word is enough. */
export function sha1Hex(input: string): string {
  const bytes = new TextEncoder().encode(input)
  const len = bytes.length
  const wordCount = (((len + 8) >> 6) << 4) + 16
  const words = new Uint32Array(wordCount)
  for (let i = 0; i < len; i++) words[i >> 2] |= bytes[i] << (24 - (i % 4) * 8)
  words[len >> 2] |= 0x80 << (24 - (len % 4) * 8)
  words[wordCount - 1] = len * 8
  let h0 = 0x67452301
  let h1 = 0xefcdab89
  let h2 = 0x98badcfe
  let h3 = 0x10325476
  let h4 = 0xc3d2e1f0
  const w = new Uint32Array(80)
  for (let block = 0; block < wordCount; block += 16) {
    for (let t = 0; t < 16; t++) w[t] = words[block + t]
    for (let t = 16; t < 80; t++) {
      const x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]
      w[t] = (x << 1) | (x >>> 31)
    }
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    for (let t = 0; t < 80; t++) {
      let f: number
      let k: number
      if (t < 20) {
        f = (b & c) | (~b & d)
        k = 0x5a827999
      } else if (t < 40) {
        f = b ^ c ^ d
        k = 0x6ed9eba1
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d)
        k = 0x8f1bbcdc
      } else {
        f = b ^ c ^ d
        k = 0xca62c1d6
      }
      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) >>> 0
      e = d
      d = c
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = temp
    }
    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
  }
  return [h0, h1, h2, h3, h4].map((x) => x.toString(16).padStart(8, '0')).join('')
}
