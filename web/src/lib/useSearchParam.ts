/** Small helpers to keep screen state (tabs, filters, seeds) in the URL so deep links and the screenshot script work. */
import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

type Setter = (value: string | null | undefined, opts?: { replace?: boolean }) => void

/** One search param as state. Empty / null / the fallback value removes the key from the URL. */
export function useSearchParamState(key: string, fallback = ''): [string, Setter] {
  const [params, setParams] = useSearchParams()
  const value = params.get(key) ?? fallback
  const set = useCallback<Setter>(
    (v, opts = {}) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          if (v === null || v === undefined || v === '' || v === fallback) next.delete(key)
          else next.set(key, v)
          return next
        },
        { replace: opts.replace ?? true },
      )
    },
    [key, fallback, setParams],
  )
  return [value, set]
}

export type ParamPatch<K extends string> = Partial<Record<K, string | number | boolean | null | undefined>>

/** Several params read together and patched in one history entry (filters). */
export function useSearchParamsObject<K extends string>(keys: readonly K[]): [Record<K, string>, (patch: ParamPatch<K>, opts?: { replace?: boolean }) => void] {
  const [params, setParams] = useSearchParams()
  const values = useMemo(() => {
    const out = {} as Record<K, string>
    for (const k of keys) out[k] = params.get(k) ?? ''
    return out
  }, [params, keys])
  const patch = useCallback(
    (p: ParamPatch<K>, opts: { replace?: boolean } = {}) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          for (const [k, v] of Object.entries(p) as [K, ParamPatch<K>[K]][]) {
            if (v === null || v === undefined || v === '' || v === false) next.delete(k)
            else next.set(k, String(v))
          }
          return next
        },
        { replace: opts.replace ?? true },
      )
    },
    [setParams],
  )
  return [values, patch]
}
