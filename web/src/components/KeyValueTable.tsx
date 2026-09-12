import type { JsonValue } from '../api/types'
import { fmtValue, humanKey, isComplex } from '../lib/format'

interface Props {
  data: Record<string, JsonValue | undefined>
  className?: string
  mono?: boolean
  order?: string[]
  hide?: string[]
}

/** Two-column key/value console table; nested objects render as pre-formatted JSON. */
export function KeyValueTable({ data, className, mono = true, order, hide = [] }: Props) {
  const keys = Object.keys(data).filter((k) => !hide.includes(k))
  const sorted = order ? [...order.filter((k) => keys.includes(k)), ...keys.filter((k) => !order.includes(k))] : keys
  if (!sorted.length) return <div className="p-3 text-xs text-fg-3">No fields</div>
  return (
    <table className={`w-full table-fixed text-xs ${className ?? ''}`}>
      <tbody>
        {sorted.map((k) => {
          const v = data[k]
          return (
            <tr key={k} className="border-b border-line/60 align-top last:border-0">
              <td className="w-[38%] max-w-[260px] py-1.5 pr-3 pl-3 font-medium text-fg-2 break-words">{humanKey(k)}</td>
              <td className={`py-1.5 pr-3 text-fg break-words ${mono ? 'mono text-[11.5px]' : ''}`}>
                {isComplex(v) ? <pre className="whitespace-pre-wrap rounded bg-bg/60 p-1.5 text-[11px] leading-snug text-fg-2">{JSON.stringify(v, null, 2)}</pre> : <span className={v === null || v === undefined || v === '' ? 'text-fg-3' : ''}>{fmtValue(v) || '—'}</span>}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
