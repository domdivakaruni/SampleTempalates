/** TanStack Query hooks for every endpoint the screens consume. */
import { keepPreviousData, useMutation, useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { api, getApiMode, onApiModeChange, resolveApiMode, type ApiMode } from './client'
import type { AlertListParams, AttackPathsParams, BlastRadiusParams, ChatContext, ContainmentIn, CypherIn, NeighborhoodParams, PathsParams } from './types'

export const qk = {
  health: ['health'] as const,
  stats: ['stats'] as const,
  schema: ['schema'] as const,
  dashboard: ['dashboard'] as const,
  alerts: (p: AlertListParams) => ['alerts', p] as const,
  alert: (id: string) => ['alert', id] as const,
  alertContext: (id: string) => ['alert-context', id] as const,
  storylines: ['storylines'] as const,
  storyline: (id: string) => ['storyline', id] as const,
  search: (q: string, labels?: string[]) => ['search', q, labels ?? []] as const,
  node: (id: string) => ['node', id] as const,
  neighborhood: (p: NeighborhoodParams) => ['neighborhood', p] as const,
  paths: (p: PathsParams) => ['paths', p] as const,
  blastRadius: (p: BlastRadiusParams) => ['blast-radius', p] as const,
  attackPaths: (p: AttackPathsParams) => ['attack-paths', p] as const,
  tiActors: ['ti-actors'] as const,
  tiActor: (id: string) => ['ti-actor', id] as const,
  tiCampaign: (id: string) => ['ti-campaign', id] as const,
  tiReports: ['ti-reports'] as const,
  tiReport: (id: string) => ['ti-report', id] as const,
  tiExposure: (sectorOnly: boolean) => ['ti-exposure', sectorOnly] as const,
  credentialJoins: ['credential-joins'] as const,
  suggestions: (p: { alert_id?: string; node_id?: string; storyline_id?: string }) => ['chat-suggestions', p] as const,
}

export function useApiMode(): ApiMode {
  const [mode, setMode] = useState<ApiMode>(getApiMode())
  useEffect(() => {
    const off = onApiModeChange(setMode)
    void resolveApiMode().then(setMode)
    return off
  }, [])
  return mode
}

export const useHealth = () => useQuery({ queryKey: qk.health, queryFn: api.health, staleTime: 60_000, retry: 0 })
export const useStats = () => useQuery({ queryKey: qk.stats, queryFn: api.stats, staleTime: 60_000 })
export const useSchema = () => useQuery({ queryKey: qk.schema, queryFn: api.schema, staleTime: Infinity })
export const useDashboard = () => useQuery({ queryKey: qk.dashboard, queryFn: api.dashboard, staleTime: 30_000 })

export const useAlerts = (params: AlertListParams) =>
  useQuery({ queryKey: qk.alerts(params), queryFn: () => api.alerts(params), placeholderData: keepPreviousData, staleTime: 30_000 })
export const useAlert = (id: string | undefined) =>
  useQuery({ queryKey: qk.alert(id ?? ''), queryFn: () => api.alert(id!), enabled: !!id, staleTime: 60_000 })
export const useAlertContext = (id: string | undefined) =>
  useQuery({ queryKey: qk.alertContext(id ?? ''), queryFn: () => api.alertContext(id!), enabled: !!id, staleTime: 60_000 })

export const useStorylines = () => useQuery({ queryKey: qk.storylines, queryFn: api.storylines, staleTime: 60_000 })
export const useStoryline = (id: string | undefined) =>
  useQuery({ queryKey: qk.storyline(id ?? ''), queryFn: () => api.storyline(id!), enabled: !!id, staleTime: 60_000 })

export const useSearch = (q: string, labels?: string[], enabled = true) =>
  useQuery({ queryKey: qk.search(q, labels), queryFn: () => api.search(q, labels), enabled: enabled && q.trim().length >= 2, staleTime: 30_000, placeholderData: keepPreviousData })
export const useNode = (id: string | undefined) =>
  useQuery({ queryKey: qk.node(id ?? ''), queryFn: () => api.node(id!), enabled: !!id, staleTime: 60_000 })
export const useNeighborhood = (p: NeighborhoodParams | null) =>
  useQuery({ queryKey: qk.neighborhood(p ?? { id: '' }), queryFn: () => api.neighborhood(p!), enabled: !!p?.id, staleTime: 60_000 })
export const usePaths = (p: PathsParams | null) =>
  useQuery({ queryKey: qk.paths(p ?? { src: '', dst: '' }), queryFn: () => api.paths(p!), enabled: !!p?.src && !!p?.dst, staleTime: 60_000 })
export const useBlastRadius = (p: BlastRadiusParams | null) =>
  useQuery({ queryKey: qk.blastRadius(p ?? { id: '' }), queryFn: () => api.blastRadius(p!), enabled: !!p?.id, staleTime: 60_000 })
export const useAttackPaths = (p: AttackPathsParams | null) =>
  useQuery({ queryKey: qk.attackPaths(p ?? {}), queryFn: () => api.attackPaths(p!), enabled: !!p && !!(p.through || p.target || p.entry), staleTime: 60_000 })
export const useCypher = () => useMutation({ mutationFn: (body: CypherIn) => api.cypher(body) })

export const useTiActors = () => useQuery({ queryKey: qk.tiActors, queryFn: api.tiActors, staleTime: 60_000 })
export const useTiActor = (id: string | undefined) =>
  useQuery({ queryKey: qk.tiActor(id ?? ''), queryFn: () => api.tiActor(id!), enabled: !!id, staleTime: 60_000 })
export const useTiCampaign = (id: string | undefined) =>
  useQuery({ queryKey: qk.tiCampaign(id ?? ''), queryFn: () => api.tiCampaign(id!), enabled: !!id, staleTime: 60_000 })
export const useTiReports = () => useQuery({ queryKey: qk.tiReports, queryFn: api.tiReports, staleTime: 60_000 })
export const useTiReport = (id: string | undefined) =>
  useQuery({ queryKey: qk.tiReport(id ?? ''), queryFn: () => api.tiReport(id!), enabled: !!id, staleTime: 60_000 })
export const useTiExposure = (sectorOnly: boolean) =>
  useQuery({ queryKey: qk.tiExposure(sectorOnly), queryFn: () => api.tiExposure(sectorOnly), staleTime: 60_000, placeholderData: keepPreviousData })

export const useCredentialJoins = () => useQuery({ queryKey: qk.credentialJoins, queryFn: api.credentialJoins, staleTime: 60_000 })
export const useContainment = () => useMutation({ mutationFn: (body: ContainmentIn) => api.containment(body) })
export const useCreateChatSession = () => useMutation({ mutationFn: (context?: ChatContext) => api.chatCreateSession(context) })
export const useSuggestions = (p: { alert_id?: string; node_id?: string; storyline_id?: string }) =>
  useQuery({ queryKey: qk.suggestions(p), queryFn: () => api.chatSuggestions(p), staleTime: 60_000, placeholderData: keepPreviousData })
