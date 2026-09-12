/** Small formatting helpers shared by screens and components. */
import type { JsonValue } from '../api/types'

export const SIM_NOW = Date.parse('2026-09-11T14:00:00Z')

export function fmtTime(iso: string | null | undefined, opts: { seconds?: boolean } = {}): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, '0')
  const base = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  return opts.seconds ? `${base}:${pad(d.getUTCSeconds())}Z` : `${base}Z`
}

export function fmtShortTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
}

export function fmtAgo(iso: string | null | undefined, now = SIM_NOW): string {
  if (!iso) return '—'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  const diff = Math.max(0, now - t)
  const m = Math.round(diff / 60000)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 48) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

export function fmtNum(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '—'
  return n.toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits })
}

export function fmtPct(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined) return '—'
  return `${fmtNum(n * 100, digits)}%`
}

export function fmtBytes(n: number | null | undefined): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

/** `alert:falcon:ldt-a009` -> `ldt-a009`; `role:aws:2222:Name` -> `Name`. */
export function shortId(id: string | null | undefined): string {
  if (!id) return ''
  const parts = id.split(':')
  return parts.length > 2 ? parts.slice(2).join(':') : id
}

export function titleCase(s: string): string {
  return s.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function humanKey(k: string): string {
  return k.replace(/_/g, ' ')
}

export function fmtValue(v: JsonValue | undefined): string {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : v.toFixed(2)
  if (typeof v === 'string') return v
  if (Array.isArray(v)) return v.map((x) => fmtValue(x)).join(', ')
  return JSON.stringify(v)
}

export function isComplex(v: JsonValue | undefined): boolean {
  return v !== null && typeof v === 'object' && !(Array.isArray(v) && v.every((x) => typeof x !== 'object' || x === null))
}

export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n))
}

export function pluralize(n: number, one: string, many = `${one}s`): string {
  return `${fmtNum(n)} ${n === 1 ? one : many}`
}
