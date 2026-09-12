#!/usr/bin/env node
/**
 * Route-level check of the snapshot adapter (src/api/snapshot) against a snapshot directory, without a browser:
 * loads the TypeScript adapter through Vite's SSR loader, points `fetch` at the directory and calls every route the
 * UI uses, including the paths a page walk cannot reach (lite alert context, blast-radius approximation, unmatched
 * chat question, closest containment, Cypher 501). Exits non-zero on any unexpected error or shape problem.
 *
 *   node scripts/check-snapshot-routes.mjs [snapshot-out]
 */
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createServer } from 'vite'

const here = path.dirname(fileURLToPath(import.meta.url))
const webDir = path.resolve(here, '..')
const dir = path.resolve(webDir, process.argv[2] ?? 'snapshot-out')
if (!existsSync(path.join(dir, 'manifest.json'))) {
  console.error(`${dir}/manifest.json not found`)
  process.exit(1)
}

// The adapter fetches `${BASE_URL}snapshot/<file>`; in SSR BASE_URL is "/", so serve "/snapshot/..." from the directory.
const fetched = new Set()
globalThis.fetch = async (url) => {
  const rel = String(url).replace(/^.*\/snapshot\//, '')
  const file = path.join(dir, rel)
  fetched.add(rel)
  if (!existsSync(file)) return new Response('not found', { status: 404 })
  return new Response(readFileSync(file), { status: 200, headers: { 'content-type': 'application/json' } })
}
globalThis.performance ??= { now: () => Date.now() }

const server = await createServer({ configFile: false, root: webDir, logLevel: 'error', appType: 'custom', server: { middlewareMode: true, hmr: false, watch: null }, optimizeDeps: { noDiscovery: true } })
let failures = 0
const ok = (label, cond, detail = '') => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}`)
  if (!cond) failures++
}
try {
  const snap = await server.ssrLoadModule('/src/api/snapshot/index.ts')
  const client = await server.ssrLoadModule('/src/api/client.ts')
  const get = (p, q = {}) => snap.snapshotRequest('GET', p, q, undefined)
  const post = (p, body) => snap.snapshotRequest('POST', p, {}, body)
  const expectError = async (label, fn, status, code) => {
    try {
      await fn()
      ok(label, false, 'resolved instead of failing')
    } catch (e) {
      ok(label, e instanceof client.ApiError && e.status === status && (!code || e.code === code), e instanceof client.ApiError ? `${e.status} ${e.code}: ${e.message}` : String(e))
    }
  }
  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'))
  const chat = JSON.parse(readFileSync(path.join(dir, 'chat.json'), 'utf8'))
  const alertsFile = JSON.parse(readFileSync(path.join(dir, 'alerts.json'), 'utf8'))

  const health = await get('/health')
  ok('GET /health', health.backend === 'snapshot' && typeof health.total_nodes === 'number', `backend ${health.backend}, ${health.total_nodes} nodes`)
  const stats = await get('/stats')
  ok('GET /stats', stats.capabilities?.cypher === false, `cypher=${JSON.stringify(stats.capabilities?.cypher)}`)
  const schema = await get('/schema')
  ok('GET /schema', Array.isArray(schema.labels) && schema.labels.length > 0, `${schema.labels?.length} labels`)
  const dash = await get('/dashboard')
  ok('GET /dashboard', Array.isArray(dash.leaderboard_contextual) && dash.kpis, `${dash.leaderboard_contextual?.length} leaders, ${dash.storylines?.length} storylines`)

  const page = await get('/alerts', { limit: 5, sort: 'contextual' })
  ok('GET /alerts (contextual)', page.items.length === 5 && page.total === alertsFile.items.length && page.items[0].contextual_score >= page.items[1].contextual_score, `total ${page.total}, top ${page.items[0]?.id}`)
  const vendor = await get('/alerts', { limit: 3, sort: 'vendor' })
  ok('GET /alerts (vendor)', vendor.items.length === 3 && vendor.items[0].vendor_severity_rank >= vendor.items[2].vendor_severity_rank, vendor.items.map((a) => a.vendor_severity).join(','))
  const filtered = await get('/alerts', { band: 'critical', reaches_crown_jewel: true, limit: 500 })
  ok('GET /alerts (filters)', filtered.items.every((a) => a.contextual_band === 'critical' && a.reaches_crown_jewel), `${filtered.total} critical alerts reaching crown jewels`)
  const byStoryline = await get('/alerts', { storyline: dash.storylines?.[0]?.id ?? '', sort: 'time', order: 'asc', limit: 200 })
  ok('GET /alerts (storyline, time asc)', byStoryline.items.length > 0 && byStoryline.items.every((a, i, arr) => i === 0 || (a.detected_at ?? '') >= (arr[i - 1].detected_at ?? '')), `${byStoryline.total} alerts`)

  const topAlert = page.items[0].id
  const alert = await get(`/alerts/${encodeURIComponent(topAlert)}`)
  ok('GET /alerts/{id}', alert.alert?.id === topAlert && alert.flat_view && typeof alert.flat_view === 'object')
  const ctx = await get(`/alerts/${encodeURIComponent(topAlert)}/context`)
  ok('GET /alerts/{id}/context (precomputed)', ctx.alert?.id === topAlert && ctx.risk && Array.isArray(ctx.insights) && ctx.evidence?.nodes?.length > 0, `${ctx.evidence?.nodes?.length} evidence nodes, storyline ${ctx.storyline?.id ?? 'none'}`)
  const risk = await get(`/alerts/${encodeURIComponent(topAlert)}/risk`)
  ok('GET /alerts/{id}/risk', risk.subject_id === topAlert && Array.isArray(risk.factors))
  const insights = await get(`/alerts/${encodeURIComponent(topAlert)}/insights`)
  ok('GET /alerts/{id}/insights', Array.isArray(insights.insights))
  // An alert without a precomputed context (if any) exercises the lite path.
  let lite = null
  for (const a of [...alertsFile.items].reverse()) {
    const c = await get(`/alerts/${encodeURIComponent(a.id)}/context`)
    if (c.evidence?.meta?.note?.includes('lite')) {
      lite = { id: a.id, c }
      break
    }
  }
  ok('GET /alerts/{id}/context (lite, non-precomputed alert)', !lite || (lite.c.alert.id === lite.id && lite.c.risk && Array.isArray(lite.c.related_alerts)), lite ? `${lite.id}: ${lite.c.evidence.nodes.length} evidence nodes, blast ${lite.c.blast_radius ? lite.c.blast_radius.summary.slice(0, 60) : 'null'}` : 'every alert has a precomputed context')
  await expectError('GET /alerts/{missing} -> 404', () => get('/alerts/alert:nope:missing'), 404, 'not_found')

  const storylines = await get('/storylines')
  ok('GET /storylines', storylines.items.length > 0, storylines.items.map((s) => s.id).join(', '))
  const story = await get(`/storylines/${encodeURIComponent(storylines.items[0].id)}`)
  ok('GET /storylines/{id}', story.fragment?.nodes?.length > 0 && story.stages?.length > 0, `${story.fragment?.nodes?.length} nodes, ${story.stages?.length} stages`)
  await expectError('GET /storylines/{missing} -> 404', () => get('/storylines/storyline:derived:nope'), 404)

  const search = await get('/search', { q: 'bas-01', limit: 10 })
  ok('GET /search', search.hits.length > 0 && search.hits[0].score > 0, search.hits.slice(0, 3).map((h) => `${h.id} (${h.score})`).join(', '))
  const searchLabels = await get('/search', { q: 'larkspur', labels: ['StorageBucket'], limit: 5 })
  ok('GET /search (labels)', searchLabels.hits.every((h) => h.label === 'StorageBucket'), `${searchLabels.hits.length} buckets`)

  const seed = story.fragment.nodes.find((n) => n.label === 'Endpoint')?.id ?? story.fragment.nodes[0].id
  const node = await get(`/nodes/${encodeURIComponent(seed)}`)
  ok('GET /nodes/{id} (card)', node.node?.id === seed && node.degree && node.edge_type_counts && Array.isArray(node.alerts), `${seed}: in ${node.degree.in} out ${node.degree.out}, ${node.alerts.length} alerts`)
  const nodes = JSON.parse(readFileSync(path.join(dir, 'graph/nodes.json'), 'utf8')).nodes
  const cards = existsSync(path.join(dir, 'node_cards.json')) ? JSON.parse(readFileSync(path.join(dir, 'node_cards.json'), 'utf8')) : {}
  const uncarded = nodes.find((n) => !cards[n.id] && !n.id.startsWith('alert:'))
  if (uncarded) {
    const built = await get(`/nodes/${encodeURIComponent(uncarded.id)}`)
    ok('GET /nodes/{id} (built from graph)', built.node?.id === uncarded.id && built.threat_intel === null && typeof built.degree.in === 'number', `${uncarded.id}: ${Object.keys(built.edge_type_counts).length} edge types`)
  }
  await expectError('GET /nodes/{missing} -> 404', () => get('/nodes/vm:aws:i-nope'), 404)
  const batch = await post('/nodes/batch', { ids: [seed, uncarded?.id, 'vm:aws:i-nope'].filter(Boolean) })
  ok('POST /nodes/batch', batch.nodes.length === (uncarded ? 2 : 1), batch.nodes.map((n) => n.id).join(', '))

  const nb = await get('/graph/neighborhood', { id: seed, depth: 1, max_nodes: 80 })
  ok('GET /graph/neighborhood', nb.nodes.length > 1 && nb.focus[0] === seed && nb.edges.every((e) => nb.nodes.some((n) => n.id === e.src) && nb.nodes.some((n) => n.id === e.dst)), `${nb.nodes.length} nodes, ${nb.edges.length} edges`)
  const nb2 = await get('/graph/neighborhood', { id: seed, depth: 2, max_nodes: 10, direction: 'out', edge_types: ['SAME_AS', 'HAS_ROLE'] })
  ok('GET /graph/neighborhood (filters, cap)', nb2.nodes.length <= 10 && nb2.edges.every((e) => ['SAME_AS', 'HAS_ROLE'].includes(e.type)), `${nb2.nodes.length} nodes, truncated=${nb2.truncated}`)
  const jewel = nodes.find((n) => n.tags?.includes('crown_jewel'))
  const paths = await get('/graph/paths', { src: seed, dst: jewel.id, max_hops: 6, k: 3 })
  ok('GET /graph/paths', paths.layout_hint === 'path' && Array.isArray(paths.paths) && (paths.paths.length === 0 || paths.paths[0].hops <= 6), `${paths.paths.length} path(s), shortest ${paths.paths[0]?.hops ?? '-'} hops`)
  const preBlast = existsSync(path.join(dir, 'graph/blast_radius.json')) ? JSON.parse(readFileSync(path.join(dir, 'graph/blast_radius.json'), 'utf8')) : {}
  const preRoot = Object.keys(preBlast)[0]
  if (preRoot) {
    const br = await get('/graph/blast-radius', { id: preRoot, depth: 4, max_nodes: 150 })
    ok('GET /graph/blast-radius (precomputed)', br.root_id === preRoot && !br.summary.startsWith('Approximate'), br.summary.slice(0, 80))
  }
  const approxRoot = nodes.find((n) => !preBlast[n.id] && ['VirtualMachine', 'Endpoint', 'IamRole'].includes(n.label))
  const approx = await get('/graph/blast-radius', { id: approxRoot.id, depth: 3 })
  ok('GET /graph/blast-radius (approximation)', approx.root_id === approxRoot.id && approx.summary.startsWith('Approximate (static edition):') && approx.fragment.layout_hint === 'blast_radius', approx.summary.slice(0, 90))
  const preAP = JSON.parse(readFileSync(path.join(dir, 'graph/attack_paths.json'), 'utf8'))
  const apKey = Object.keys(preAP).find((k) => preAP[k].paths?.length) ?? Object.keys(preAP)[0]
  const ap = await get('/graph/attack-paths', apKey.startsWith('internet->') ? { target: apKey.slice('internet->'.length) } : { through: apKey, k: 3 })
  ok('GET /graph/attack-paths (precomputed)', Array.isArray(ap.paths) && ap.fragment, `${apKey}: ${ap.paths.length} path(s)`)
  const apMiss = await get('/graph/attack-paths', { through: 'vm:aws:i-nope' })
  ok('GET /graph/attack-paths (miss -> empty + note)', apMiss.paths.length === 0 && typeof apMiss.fragment.meta.note === 'string', apMiss.fragment.meta.note)
  await expectError('POST /graph/cypher -> 501 not_supported', () => post('/graph/cypher', { query: 'MATCH (n) RETURN n' }), 501, 'not_supported')

  const actors = await get('/threat-intel/actors')
  ok('GET /threat-intel/actors', actors.items.length > 0, `${actors.items.length} actors`)
  const actor = await get(`/threat-intel/actors/${encodeURIComponent(actors.items[0].actor.id)}`)
  ok('GET /threat-intel/actors/{id}', actor.actor?.id === actors.items[0].actor.id && actor.context && actor.affected, `${actor.affected.nodes.length} affected nodes`)
  const campaignId = actors.items.flatMap((a) => a.campaigns)[0]?.id
  if (campaignId) {
    const camp = await get(`/threat-intel/campaigns/${encodeURIComponent(campaignId)}`)
    ok('GET /threat-intel/campaigns/{id}', camp.campaigns?.length > 0 && camp.context, campaignId)
  }
  const reports = await get('/threat-intel/reports')
  ok('GET /threat-intel/reports', reports.items.length > 0, `${reports.items.length} reports`)
  const report = await get(`/threat-intel/reports/${encodeURIComponent(reports.items[0].id)}`)
  ok('GET /threat-intel/reports/{id}', report.report?.id === reports.items[0].id && report.impact, report.impact.summary.slice(0, 80))
  const ti = JSON.parse(readFileSync(path.join(dir, 'ti.json'), 'utf8'))
  const lookupKey = Object.keys(ti.lookups)[0]
  const lookup = await get('/threat-intel/lookup', { value: lookupKey.toUpperCase() })
  ok('GET /threat-intel/lookup (case-insensitive hit)', Array.isArray(lookup.matches) && lookup.summary === ti.lookups[lookupKey].summary, lookupKey)
  const lookupMiss = await get('/threat-intel/lookup', { value: 'not-an-indicator' })
  ok('GET /threat-intel/lookup (miss -> empty context)', lookupMiss.matches.length === 0 && lookupMiss.summary.includes('static edition'))
  const exposure = await get('/threat-intel/exposure', { sector_only: true })
  const exposureAll = await get('/threat-intel/exposure', { sector_only: false })
  ok('GET /threat-intel/exposure', exposure.items.length > 0 && exposureAll.items.length >= exposure.items.length, `${exposure.items.length} sector rows, ${exposureAll.items.length} all`)

  const joins = await get('/investigate/credential-joins')
  ok('GET /investigate/credential-joins', Array.isArray(joins.items) && joins.fragment, `${joins.items.length} joins`)
  const reaching = await get('/investigate/alerts-reaching-crown-jewels')
  ok('GET /investigate/alerts-reaching-crown-jewels', Array.isArray(reaching.items) && Array.isArray(reaching.jewels) && !reaching.fragment.meta.note, `${reaching.items.length} alerts, ${reaching.jewels.length} jewels`)
  const reachingMiss = await get('/investigate/alerts-reaching-crown-jewels', { jewel_id: 'bucket:aws:nope' })
  ok('GET /investigate/alerts-reaching-crown-jewels (unknown key -> default + note)', reachingMiss.fragment.meta.note === snap.DEFAULT_NOTE)
  const medium = await get('/investigate/medium-alerts-with-data-path', { severity: 'medium', source: 'falcon' })
  ok('GET /investigate/medium-alerts-with-data-path', Array.isArray(medium.items) && !medium.fragment.meta.note, `${medium.items.length} alerts`)
  const mediumMiss = await get('/investigate/medium-alerts-with-data-path', { severity: 'critical', source: 'okta' })
  ok('GET /investigate/medium-alerts-with-data-path (unknown key -> default + note)', mediumMiss.fragment.meta.note === snap.DEFAULT_NOTE)
  const inv = JSON.parse(readFileSync(path.join(dir, 'investigate.json'), 'utf8'))
  const identity = Object.keys(inv.identity_footprint)[0]
  if (identity) {
    const fp = await get('/investigate/identity-footprint', { id: identity })
    ok('GET /investigate/identity-footprint (precomputed)', fp.root_id === identity, fp.summary.slice(0, 80))
  }
  const fpApprox = await get('/investigate/identity-footprint', { id: approxRoot.id })
  ok('GET /investigate/identity-footprint (approximation)', fpApprox.root_id === approxRoot.id && fpApprox.summary.startsWith('Approximate'))
  await expectError('GET /investigate/identity-footprint (missing) -> 404', () => get('/investigate/identity-footprint', { id: 'role:aws:nope' }), 404)
  const c0 = inv.containment[0]
  const exact = await post('/investigate/containment', { target_ids: [...c0.targets].reverse(), actions: [...c0.actions].reverse() })
  ok('POST /investigate/containment (exact set match)', exact.paths_cut === c0.result.paths_cut && !exact.fragment.meta.note && exact.residual_risks[0] === c0.result.residual_risks[0])
  const closest = await post('/investigate/containment', { target_ids: [c0.targets[0]], actions: ['block_ip'] })
  ok('POST /investigate/containment (closest + visible note)', closest.residual_risks[0].startsWith('Static edition') && closest.fragment.meta.note === snap.DEFAULT_NOTE, closest.residual_risks[0].slice(0, 100))
  await expectError('POST /investigate/containment (no targets) -> 400', () => post('/investigate/containment', { target_ids: [], actions: [] }), 400, 'invalid_argument')

  const session = await post('/chat/sessions', { context: { alert_id: topAlert } })
  ok('POST /chat/sessions', typeof session.id === 'string' && Array.isArray(session.turns))
  const session2 = await get(`/chat/sessions/${encodeURIComponent(session.id)}`)
  ok('GET /chat/sessions/{id}', session2.id === session.id)
  const sugg = await get('/chat/suggestions', { alert_id: topAlert })
  const globalSugg = await get('/chat/suggestions')
  ok('GET /chat/suggestions', sugg.questions.length >= globalSugg.questions.length && globalSugg.questions.length > 0, `${sugg.questions.length} for the alert, ${globalSugg.questions.length} global`)

  const run = async (content, context) => {
    const events = []
    await snap.snapshotStream(session.id, { content, context, mode: 'auto' }, (e) => events.push(e))
    const answer = events.find((e) => e.type === 'answer')?.data
    const types = events.map((e) => e.type)
    return { events, answer, types, text: events.filter((e) => e.type === 'text_delta').map((e) => e.data.text).join('') }
  }
  const globalEntry = chat.answers.find((a) => (a.context_key ?? '') === '')
  const r1 = await run(globalEntry.question, {})
  ok('streamChat (exact global match)', r1.answer?.narrative_md === globalEntry.answer.narrative_md && r1.types[0] === 'session' && r1.types.at(-1) === 'done' && r1.text === r1.answer.narrative_md, `${r1.types.filter((t) => t === 'tool_call').length} tool calls replayed, ${r1.events.length} events`)
  const r2 = await run(globalEntry.question.toUpperCase() + '!!!', { alert_id: topAlert })
  ok('streamChat (normalised match from an alert context)', r2.answer?.narrative_md === globalEntry.answer.narrative_md)
  const alertEntry = chat.answers.find((a) => a.context_key === `alert:${topAlert}`)
  if (alertEntry) {
    const r3 = await run(alertEntry.question, { alert_id: topAlert })
    ok('streamChat (alert-context match)', r3.answer?.narrative_md === alertEntry.answer.narrative_md, alertEntry.question.slice(0, 60))
    const words = alertEntry.question.split(' ')
    const fuzzy = [...words.slice(0, -1), 'please'].join(' ')
    const r4 = await run(fuzzy, { alert_id: topAlert })
    ok('streamChat (Jaccard match within context)', r4.answer?.narrative_md === alertEntry.answer.narrative_md || words.length < 5, `"${fuzzy.slice(0, 60)}" -> intent ${r4.answer?.intent}`)
  }
  const r5 = await run('What is the airspeed velocity of an unladen swallow?', { alert_id: topAlert })
  ok('streamChat (unmatched -> help fallback)', r5.answer?.intent === 'help' && r5.answer.confidence === 0 && r5.answer.mode === 'offline' && r5.answer.evidence.nodes.length === 0 && r5.answer.narrative_md.includes('Prepared questions') && r5.answer.followups.length > 0, `${r5.answer?.followups.length} followups`)
  const session3 = await get(`/chat/sessions/${encodeURIComponent(session.id)}`)
  ok('session records turns', session3.turns.length >= 2 * 3)

  await expectError('unknown route -> 404', () => get('/nope'), 404)
  const unfetched = [...manifest.shards.edges, ...manifest.shards.alert_details].map((f) => f.split('/').pop())
  console.log(`\nfetched ${fetched.size} distinct snapshot files (${unfetched.filter((f) => ![...fetched].some((x) => x.endsWith(f))).length} listed shards untouched)`)
} finally {
  await server.close()
}
if (failures) {
  console.log(`\n${failures} failure(s)`)
  process.exit(1)
}
console.log('snapshot route check passed')
