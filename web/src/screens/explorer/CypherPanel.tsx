import { Play, Plus } from 'lucide-react'
import { useState } from 'react'
import { isApiError } from '../../api/client'
import { useCypher, useSchema } from '../../api/hooks'
import type { CypherCell } from '../../api/types'
import { NodeRef } from '../../components/NodeRef'
import { EXAMPLE_QUERIES } from '../../graph/schema'
import type { CanvasOps } from '../../graph/useCanvasOps'
import { fmtNum } from '../../lib/format'

function isNodeCell(c: CypherCell): c is { id: string; label: string; name: string } {
  return !!c && typeof c === 'object' && !Array.isArray(c) && 'id' in c && 'label' in c
}
function isRelCell(c: CypherCell): c is { src: string; type: string; dst: string } {
  return !!c && typeof c === 'object' && !Array.isArray(c) && 'src' in c && 'type' in c && 'dst' in c
}

function Cell({ v }: { v: CypherCell }) {
  if (v === null || v === undefined) return <span className="text-fg-3">null</span>
  if (isNodeCell(v)) return <NodeRef id={v.id} name={v.name} label={v.label} />
  if (isRelCell(v)) return <span className="mono text-[10.5px] text-fg-2">{v.src.split(':').pop()} -{v.type}-&gt; {v.dst.split(':').pop()}</span>
  if (typeof v === 'object') return <span className="mono text-[10.5px] text-fg-2">{JSON.stringify(v)}</span>
  return <span className="text-fg">{String(v)}</span>
}

/** POST /graph/cypher: read-only queries with example picker, results table and "add results to canvas". */
export function CypherPanel({ ops }: { ops: CanvasOps }) {
  const schema = useSchema()
  const examples = schema.data?.example_queries?.length ? schema.data.example_queries : EXAMPLE_QUERIES
  const [query, setQuery] = useState(examples[0]?.query ?? '')
  const run = useCypher()
  const submit = () => query.trim() && run.mutate({ query, row_limit: 200 })
  const err = run.error
  const notSupported = isApiError(err) && err.status === 501
  const rejected = isApiError(err) && err.code === 'query_rejected'
  return (
    <div className="space-y-2 text-xs">
      <select className="select w-full" value="" onChange={(e) => { const ex = examples.find((x) => x.title === e.target.value); if (ex) setQuery(ex.query) }} aria-label="Example queries">
        <option value="">Example queries{schema.data?.example_queries?.length ? ' (from /schema)' : ''}…</option>
        {examples.map((ex) => (
          <option key={ex.title} value={ex.title}>{ex.title}</option>
        ))}
      </select>
      <textarea
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); submit() } }}
        rows={6}
        spellCheck={false}
        className="input mono w-full resize-y text-[11px] leading-snug"
        placeholder="MATCH (a:Alert) RETURN a.id, a.title LIMIT 25"
      />
      <div className="flex items-center gap-2">
        <button type="button" className="btn-primary" disabled={!query.trim() || run.isPending} onClick={submit}>
          <Play size={12} /> {run.isPending ? 'Running…' : 'Run'}
        </button>
        <span className="text-[10.5px] text-fg-3">Ctrl/⌘+Enter · read-only, 3 s timeout, 200 rows</span>
        {run.data?.fragment && (
          <button type="button" className="btn ml-auto" onClick={() => ops.merge(run.data!.fragment!, { highlight: true })}>
            <Plus size={12} /> Add results to canvas
          </button>
        )}
      </div>
      {err ? (
        <div className={`rounded-md border px-2 py-1.5 leading-snug ${notSupported ? 'border-sev-medium/40 bg-sev-medium/5 text-fg-2' : 'border-sev-critical/40 bg-sev-critical/5 text-fg-2'}`}>
          {notSupported ? (
            <>
              <span className="font-medium text-sev-medium">Cypher is not available on this backend.</span> The NetworkX fallback answers the typed endpoints but not free-form queries; run the LadybugDB (or Kùzu / Neo4j) backend for full Cypher.
              <div className="mt-1 text-[10.5px] text-fg-3">{err.message}</div>
            </>
          ) : rejected ? (
            <>
              <span className="font-medium text-sev-critical">Query rejected by the read-only gate.</span> Only MATCH … RETURN queries without write clauses or procedure calls are allowed. <div className="mt-1 text-[10.5px] text-fg-3">{err.message}</div>
            </>
          ) : (
            <span>{err instanceof Error ? err.message : String(err)}</span>
          )}
        </div>
      ) : null}
      {run.data && (
        <div className="space-y-1">
          <div className="text-fg-2">
            {fmtNum(run.data.rows.length)} row{run.data.rows.length === 1 ? '' : 's'} · {run.data.elapsed_ms} ms{run.data.truncated && <span className="text-sev-medium"> · truncated</span>}
            {run.data.fragment && <span> · {run.data.fragment.nodes.length} graph nodes in results</span>}
          </div>
          <div className="max-h-[40vh] overflow-auto rounded-md border border-line">
            <table className="table-dense w-full text-[11px]">
              <thead className="sticky top-0 bg-panel">
                <tr>
                  {run.data.columns.map((c) => (
                    <th key={c}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {run.data.rows.map((r, i) => (
                  <tr key={i}>
                    {r.map((v, j) => (
                      <td key={j} className="max-w-[220px] truncate">
                        <Cell v={v} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {run.data.rows.length === 0 && <div className="p-2 text-fg-3">No rows.</div>}
          </div>
        </div>
      )}
    </div>
  )
}
