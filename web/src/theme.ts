/** Colour constants shared by CSS-free surfaces (Cytoscape styles, inline SVG). Keep in sync with index.css @theme. */
import type { Band, Category, Severity } from './api/types'

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#60a5fa',
  informational: '#94a3b8',
}

export const BAND_COLORS: Record<Band, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#60a5fa',
  noise: '#64748b',
}

export const CATEGORY_COLORS: Record<Category, string> = {
  cloud: '#60a5fa',
  identity: '#a78bfa',
  software: '#2dd4bf',
  business: '#94a3b8',
  endpoint: '#4ade80',
  alerts: '#f87171',
  threat_intel: '#e879f9',
  unknown: '#64748b',
}

export const ACCENT = '#38bdf8'
export const FG = '#e2e8f0'
export const FG_2 = '#94a3b8'
export const FG_3 = '#64748b'
export const LINE = '#334155'
export const PANEL = '#0d1424'

export function severityColor(sev: string | null | undefined): string {
  return SEVERITY_COLORS[(sev ?? 'informational') as Severity] ?? SEVERITY_COLORS.informational
}

export function bandColor(band: string | null | undefined): string {
  return BAND_COLORS[(band ?? 'noise') as Band] ?? BAND_COLORS.noise
}

export function categoryColor(cat: string | null | undefined): string {
  return CATEGORY_COLORS[(cat ?? 'unknown') as Category] ?? CATEGORY_COLORS.unknown
}

export const SOURCE_LABELS: Record<string, string> = {
  falcon: 'EDR',
  cspm: 'CSPM',
  waf: 'WAF',
  ids: 'IDS',
  'cloud-anomaly': 'Cloud anomaly',
  okta: 'IdP',
  cloudtrail: 'Cloud audit',
  wiz: 'Cloud posture',
  ti: 'Threat intel',
  iam: 'IAM',
  data: 'Data',
  derived: 'Derived',
}

export function sourceLabel(src: string): string {
  return SOURCE_LABELS[src] ?? src
}
