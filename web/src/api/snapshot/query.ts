/** Query-string coercion helpers shared by the snapshot route handlers (same semantics as the mock adapter). */
import type { Query } from '../client'

export const str = (v: Query[string], d = ''): string => (v === undefined || v === null ? d : Array.isArray(v) ? v.join(',') : String(v))

export const num = (v: Query[string], d: number, max?: number): number => {
  const n = Number(str(v, String(d)))
  const val = Number.isFinite(n) ? n : d
  return max !== undefined ? Math.min(val, max) : val
}

export const bool = (v: Query[string]): boolean | undefined => (v === undefined || v === null || v === '' ? undefined : String(v) === 'true' || v === true)

export const list = (v: Query[string]): string[] | undefined => {
  if (v === undefined || v === null || v === '') return undefined
  return (Array.isArray(v) ? v : String(v).split(',')).map((s) => s.trim()).filter(Boolean)
}

/** True when the parameter was not sent at all (so a precomputed default can be served without a note). */
export const absent = (v: Query[string]): boolean => v === undefined || v === null || v === ''
