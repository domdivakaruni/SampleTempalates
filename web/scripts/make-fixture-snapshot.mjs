#!/usr/bin/env node
/**
 * Build a small, shape-correct `web/snapshot-out/` from the mock fixtures (src/api/mock) so the static edition can be
 * built and tested before / without the Python exporter (scripts/export_snapshot.py). Same file layout as
 * docs/10-static-snapshot.md section 1; every payload comes from the mock adapter's own route handlers, so the shapes
 * are exactly the API shapes the UI consumes.
 *
 *   node scripts/make-fixture-snapshot.mjs [--out snapshot-out]
 *
 * The mock modules are TypeScript; they are loaded through Vite's SSR module loader (no extra tooling).
 */
import { createHash } from 'node:crypto'
import { mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createServer } from 'vite'

const here = path.dirname(fileURLToPath(import.meta.url))
const webDir = path.resolve(here, '..')
const outFlag = process.argv.indexOf('--out')
const outDir = path.resolve(webDir, outFlag > 0 && process.argv[outFlag + 1] ? process.argv[outFlag + 1] : 'snapshot-out')

const EDGE_SHARD_SIZE = 40_000
const ANSWER_CAP = 320
const TRIMMED_PROPS = new Set(['raw', 'score_breakdown', 'stages', 'statements', 'inbound_rules', 'body'])
const TOKEN_PROPS = ['hostname', 'private_ip', 'public_ip', 'address', 'fqdn', 'value', 'sha256', 'cve_id', 'technique_id', 'email', 'display_name', 'title', 'account_id']
const GENERIC_ALERT_QUESTIONS = ['Why is this alert risky?', 'What can an attacker reach from this alert?']
const GENERIC_STORYLINE_QUESTIONS = ['Summarize this storyline', 'If we contain this storyline now, what breaks?']
const GENERIC_NODE_QUESTIONS = ['What is this?', 'What is connected to this node?']

/** Same normalisation as web/src/api/snapshot/chat.ts (and the exporter): lower-case, strip punctuation except :/.-, collapse whitespace. */
const normalize = (s) => s.toLowerCase().replace(/[^\p{L}\p{N}_\s:/.-]/gu, '').replace(/\s+/g, ' ').trim()
const enc = encodeURIComponent
const uniq = (xs) => [...new Set(xs)]
const sha1 = (s) => createHash('sha1').update(s, 'utf8').digest('hex')

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length)
  let next = 0
  const worker = async () => {
    for (;;) {
      const i = next++
      if (i >= items.length) return
      out[i] = await fn(items[i], i)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return out
}

function trimNode(n) {
  const props = {}
  for (const [k, v] of Object.entries(n.props ?? {})) {
    if (TRIMMED_PROPS.has(k) || v === undefined) continue
    if (k === 'description' && typeof v === 'string' && v.length > 200) continue
    props[k] = v
  }
  return { id: n.id, label: n.label, name: n.name, category: n.category, severity: n.severity ?? null, score: n.score ?? null, highlight: false, tags: n.tags ?? [], props }
}

function extraTokens(n) {
  const toks = []
  for (const key of TOKEN_PROPS) {
    const v = n.props?.[key]
    if (v === undefined || v === null || v === '') continue
    for (const part of String(v).toLowerCase().split(/\s+/)) if (part && part !== n.name.toLowerCase()) toks.push(part)
  }
  return uniq(toks).join(' ')
}

/** Cap a fragment at maxNodes/maxEdges keeping highlighted nodes first (contract section 2). */
function capFragment(frag, maxNodes, maxEdges) {
  if (!frag) return frag
  const nodes = [...frag.nodes].sort((a, b) => Number(!!b.highlight) - Number(!!a.highlight)).slice(0, maxNodes)
  const kept = new Set(nodes.map((n) => n.id))
  const edges = frag.edges.filter((e) => kept.has(e.src) && kept.has(e.dst)).slice(0, maxEdges)
  return { ...frag, nodes, edges, truncated: frag.truncated || nodes.length < frag.nodes.length || edges.length < frag.edges.length, total_nodes: frag.total_nodes ?? frag.nodes.length }
}

async function main() {
  const server = await createServer({ configFile: false, root: webDir, logLevel: 'error', appType: 'custom', server: { middlewareMode: true, hmr: false, watch: null }, optimizeDeps: { noDiscovery: true } })
  try {
    const mock = await server.ssrLoadModule('/src/api/mock/index.ts')
    const chat = await server.ssrLoadModule('/src/api/mock/chat.ts')
    const dsMod = await server.ssrLoadModule('/src/api/mock/dataset.ts')
    const graphMod = await server.ssrLoadModule('/src/api/mock/graph.ts')
    const idsMod = await server.ssrLoadModule('/src/api/mock/fixtures/ids.ts')
    const types = await server.ssrLoadModule('/src/api/types.ts')
    const ID = idsMod.ID
    const { graph, storylines: storylineList } = dsMod.dataset()
    const get = (p, q = {}) => mock.mockRequest('GET', p, q, undefined)
    const post = (p, body) => mock.mockRequest('POST', p, {}, body)
    const tryGet = (p, q) => get(p, q).catch(() => undefined)
    const nodesByLabel = (label) => [...graph.nodes.values()].filter((n) => n.label === label)

    const files = new Map() // relative path -> object
    const put = (rel, obj) => files.set(rel, obj)

    // ---------------------------------------------------------------- meta
    const [health, stats, schema, dashboard] = await Promise.all([get('/health'), get('/stats'), get('/schema'), get('/dashboard')])
    health.backend = 'snapshot'
    health.agent_mode = 'offline'
    health.analyst_mode = 'precomputed'
    health.build = { ...(health.build ?? {}), backend: 'snapshot', edition: 'static-fixture' }
    stats.backend = 'snapshot'
    stats.capabilities = { ...(stats.capabilities ?? {}), cypher: false, streaming: true, llm: false }
    stats.build = { ...(stats.build ?? {}), backend: 'snapshot', edition: 'static-fixture' }
    put('meta.json', { health, stats, schema, dashboard })

    // ---------------------------------------------------------------- alerts + details
    const alerts = (await get('/alerts', { limit: 500 })).items
    put('alerts.json', { items: alerts })
    const storylineAlertIds = new Set(storylineList.flatMap((s) => s.alert_ids))
    const noiseIds = [ID.N001, ID.N002, ID.N003, ID.N004]
    const rerankIds = (dashboard.rerank_examples ?? []).map((r) => r.alert_id)
    const withContext = new Set([...storylineAlertIds, ...alerts.slice(0, 12).map((a) => a.id), ...noiseIds, ...rerankIds])
    const shards = new Map()
    await mapLimit(alerts, 32, async (a) => {
      const [detail, risk, insights] = await Promise.all([get(`/alerts/${enc(a.id)}`), get(`/alerts/${enc(a.id)}/risk`), get(`/alerts/${enc(a.id)}/insights`)])
      const entry = { alert: detail.alert, flat_view: detail.flat_view, risk, insights: insights.insights }
      if (withContext.has(a.id)) {
        const ctx = await get(`/alerts/${enc(a.id)}/context`)
        ctx.evidence = capFragment(ctx.evidence, 150, 400)
        entry.context = ctx
      }
      const key = sha1(a.id).slice(0, 2)
      if (!shards.has(key)) shards.set(key, {})
      shards.get(key)[a.id] = entry
    })
    for (const [key, shard] of shards) put(`alert_details/${key}.json`, shard)

    // ---------------------------------------------------------------- storylines
    const storylineItems = (await get('/storylines')).items
    const storylineDetails = {}
    for (const s of storylineItems) storylineDetails[s.id] = await get(`/storylines/${enc(s.id)}`)
    put('storylines.json', { items: storylineItems, details: storylineDetails })
    const storylineNodeIds = uniq(Object.values(storylineDetails).flatMap((s) => (s.fragment?.nodes ?? []).map((n) => n.id)))
    const storylineMemberNodes = storylineNodeIds.filter((id) => !id.startsWith('alert:'))

    // ---------------------------------------------------------------- threat intel
    const actors = await get('/threat-intel/actors')
    const actorDetails = Object.fromEntries(await mapLimit(actors.items, 8, async (it) => [it.actor.id, await get(`/threat-intel/actors/${enc(it.actor.id)}`)]))
    const campaignIds = uniq(actors.items.flatMap((it) => it.campaigns.map((c) => c.id)))
    const campaignDetails = Object.fromEntries((await mapLimit(campaignIds, 8, async (id) => [id, await tryGet(`/threat-intel/campaigns/${enc(id)}`)])).filter(([, v]) => v))
    const reports = await get('/threat-intel/reports')
    const reportDetails = Object.fromEntries(await mapLimit(reports.items, 8, async (r) => [r.id, await get(`/threat-intel/reports/${enc(r.id)}`)]))
    const [exposureSector, exposureAll] = await Promise.all([get('/threat-intel/exposure', { sector_only: true }), get('/threat-intel/exposure', { sector_only: false })])
    const lookupValues = uniq([
      ...nodesByLabel('Indicator').map((i) => String(i.props.value ?? '')),
      ...nodesByLabel('Vulnerability').filter((c) => graph.edgesOf(c.id, 'in').some((e) => e.type === 'EXPLOITS')).map((c) => String(c.props.cve_id ?? c.name)),
      ...['ThreatActor', 'Campaign', 'IntelReport', 'Malware'].flatMap((l) => nodesByLabel(l).flatMap((n) => [n.id, n.name])),
      ...idsMod.CJ_TECHNIQUES, ...idsMod.HT_TECHNIQUES,
    ].filter(Boolean))
    const lookups = {}
    for (const [value, ctx] of await mapLimit(lookupValues, 16, async (v) => [v, await get('/threat-intel/lookup', { value: v })])) lookups[value.toLowerCase()] = ctx
    put('ti.json', { actors, actor_details: actorDetails, campaign_details: campaignDetails, reports, report_details: reportDetails, exposure: { sector_only: exposureSector, all: exposureAll }, lookups })

    // ---------------------------------------------------------------- investigations
    const jewels = [...graph.nodes.values()].filter((n) => n.tags.includes('crown_jewel'))
    const reaching = { '': await get('/investigate/alerts-reaching-crown-jewels') }
    for (const j of jewels) reaching[j.id] = await get('/investigate/alerts-reaching-crown-jewels', { jewel_id: j.id })
    const mediumFalcon = await get('/investigate/medium-alerts-with-data-path', { severity: 'medium', source: 'falcon' })
    const sources = Object.keys(dashboard.alerts_by_source ?? { falcon: 0 })
    const mediumAll = { items: [], fragment: types.emptyFragment('path') }
    for (const src of sources) {
      const part = await get('/investigate/medium-alerts-with-data-path', { severity: 'medium', source: src })
      mediumAll.items.push(...part.items)
      mediumAll.fragment = graphMod.mergeFragments(mediumAll.fragment, part.fragment)
    }
    mediumAll.items.sort((a, b) => b.contextual_score - a.contextual_score)
    const mediumTable = {
      'medium|falcon': mediumFalcon,
      'medium|': mediumAll,
      'high|falcon': await get('/investigate/medium-alerts-with-data-path', { severity: 'high', source: 'falcon' }),
      'low|falcon': await get('/investigate/medium-alerts-with-data-path', { severity: 'low', source: 'falcon' }),
    }
    const identityLabels = new Set(['IamRole', 'IamUser', 'HumanUser', 'Credential', 'ServiceAccount'])
    const identityIds = uniq([
      ...storylineMemberNodes.filter((id) => identityLabels.has(graph.get(id)?.label)),
      ...[...graph.nodes.values()].filter((n) => identityLabels.has(n.label) && (n.props.is_admin === true || Number(n.props.privilege_score ?? 0) >= 0.7)).map((n) => n.id),
    ]).slice(0, 60)
    const identityFootprint = Object.fromEntries((await mapLimit(identityIds, 16, async (id) => [id, await tryGet('/investigate/identity-footprint', { id })])).filter(([, v]) => v))
    const actionSets = [['isolate_endpoint', 'rotate_role_credentials'], ['isolate_endpoint', 'rotate_role_credentials', 'tighten_trust_policy'], ['isolate_endpoint'], ['rotate_role_credentials']]
    const targetSets = [[ID.EP_BASTION, ID.BASTION_ROLE], [ID.EP_BASTION, ID.BASTION_VM, ID.BASTION_ROLE], [ID.EP_EDGE, ID.EDGE_ROLE], [ID.EP_EDGE, ID.EDGE_VM, ID.EDGE_ROLE], [ID.EP_EDGE]]
    const containment = []
    for (const targets of targetSets) for (const actions of actionSets) containment.push({ targets, actions, result: await post('/investigate/containment', { target_ids: targets, actions }) })
    put('investigate.json', { credential_joins: await get('/investigate/credential-joins'), alerts_reaching_crown_jewels: reaching, medium_alerts_with_data_path: mediumTable, identity_footprint: identityFootprint, containment })

    // ---------------------------------------------------------------- graph: nodes, edges, blast radius, attack paths
    const allNodes = [...graph.nodes.values()].map(trimNode)
    put('graph/nodes.json', { nodes: allNodes })
    const compact = [...graph.edges.values()].map((e) => [e.src, e.type, e.dst, e.derived ? 1 : 0, typeof e.confidence === 'number' ? e.confidence : 1])
    const edgeFiles = []
    for (let i = 0; i * EDGE_SHARD_SIZE < compact.length || i === 0; i++) {
      const name = `edges-${String(i).padStart(2, '0')}.json`
      edgeFiles.push(name)
      put(`graph/${name}`, { edges: compact.slice(i * EDGE_SHARD_SIZE, (i + 1) * EDGE_SHARD_SIZE) })
    }
    const anchorsOf = (alertId) => {
      const a = alerts.find((x) => x.id === alertId)
      const out = []
      if (a?.entity_id) {
        out.push(a.entity_id)
        for (const e of graph.edgesOf(a.entity_id, 'out')) if (e.type === 'SAME_AS') out.push(e.dst)
      }
      return out
    }
    const blastRoots = uniq([...withContext, ...[...withContext].flatMap(anchorsOf), ...storylineMemberNodes, ...identityIds])
    const blastRadius = Object.fromEntries((await mapLimit(blastRoots, 16, async (id) => [id, await tryGet('/graph/blast-radius', { id, depth: 4, max_nodes: 100 })])).filter(([, v]) => v))
    put('graph/blast_radius.json', blastRadius)
    const throughIds = uniq([...storylineAlertIds, ...[...storylineAlertIds].flatMap(anchorsOf)])
    const attackPaths = {}
    for (const [id, res] of await mapLimit(throughIds, 16, async (id) => [id, await get('/graph/attack-paths', { through: id })])) attackPaths[id] = res
    for (const j of jewels) attackPaths[`internet->${j.id}`] = await get('/graph/attack-paths', { target: j.id })
    put('graph/attack_paths.json', attackPaths)

    // ---------------------------------------------------------------- node cards + search
    const exposedHosts = nodesByLabel('VirtualMachine').filter((n) => n.tags.includes('internet_exposed'))
    const exposedEndpoints = exposedHosts.flatMap((vm) => graph.edgesOf(vm.id, 'in').filter((e) => e.type === 'SAME_AS').map((e) => e.src))
    const cardIds = uniq([
      ...storylineMemberNodes, ...jewels.map((j) => j.id),
      ...['ThreatActor', 'Campaign', 'IntelReport', 'Malware'].flatMap((l) => nodesByLabel(l).map((n) => n.id)),
      ...exposedHosts.map((n) => n.id), ...exposedEndpoints,
      ...rerankIds.flatMap(anchorsOf),
    ]).slice(0, 400)
    const nodeCards = Object.fromEntries((await mapLimit(cardIds, 16, async (id) => [id, await tryGet(`/nodes/${enc(id)}`)])).filter(([, v]) => v))
    put('node_cards.json', nodeCards)
    put('search.json', { entries: [...graph.nodes.values()].map((n) => [n.id, n.label, n.name, n.category, graphMod.snippetOf(n) || '', extraTokens(n)]) })

    // ---------------------------------------------------------------- chat: suggestions + precomputed answers
    const DEMO = chat.DEMO_QUESTIONS
    const suggestions = { '': chat.suggestions({}) }
    const answers = []
    const addAnswer = (question, contextKey, ctx) => {
      const pb = chat.playbookFor(question, ctx)
      let evidence = types.emptyFragment(pb.tools.find((t) => t.evidence)?.evidence?.layout_hint ?? 'neighborhood')
      const toolCalls = []
      for (const t of pb.tools) {
        toolCalls.push({ name: t.name, arguments: t.arguments, summary: t.summary, duration_ms: t.duration_ms })
        if (t.evidence) {
          evidence = graphMod.mergeFragments(evidence, t.evidence)
          evidence.layout_hint = t.evidence.layout_hint
        }
      }
      const answer = { narrative_md: pb.narrative, findings: pb.findings, evidence: capFragment(evidence, 120, 300), confidence: pb.confidence, followups: pb.followups, tool_calls: toolCalls, mode: 'offline', intent: pb.intent, model: null }
      answers.push({ question, normalized: normalize(question), context_key: contextKey, answer })
    }
    for (const q of uniq([...DEMO, ...suggestions['']])) addAnswer(q, '', {})
    const chatAlertIds = uniq([...storylineAlertIds, ...alerts.slice(0, 8).map((a) => a.id), ...noiseIds])
    for (const id of chatAlertIds) {
      const sugg = chat.suggestions({ alert_id: id })
      suggestions[`alert:${id}`] = sugg
      for (const q of uniq([...sugg.filter((s) => !DEMO.includes(s)), ...GENERIC_ALERT_QUESTIONS])) addAnswer(q, `alert:${id}`, { alert_id: id })
    }
    for (const s of storylineItems) {
      const sugg = chat.suggestions({ storyline_id: s.id })
      suggestions[`storyline:${s.id}`] = sugg
      for (const q of uniq([...sugg.filter((x) => !DEMO.includes(x)), ...GENERIC_STORYLINE_QUESTIONS])) addAnswer(q, `storyline:${s.id}`, { storyline_id: s.id })
    }
    const nodeAnswers = []
    const chatNodeIds = uniq([...storylineMemberNodes.slice(0, 16), ...jewels.map((j) => j.id), ...exposedHosts.map((n) => n.id), ...nodesByLabel('ThreatActor').map((n) => n.id)])
    for (const id of chatNodeIds) {
      const sugg = chat.suggestions({ node_id: id })
      suggestions[`node:${id}`] = sugg
      for (const q of uniq([...sugg.filter((x) => !DEMO.includes(x)), ...GENERIC_NODE_QUESTIONS])) nodeAnswers.push([q, `node:${id}`, { node_id: id, selected_node_ids: [id] }])
    }
    for (const [q, key, ctx] of nodeAnswers.slice(0, Math.max(0, ANSWER_CAP - answers.length))) addAnswer(q, key, ctx)
    put('chat.json', { suggestions, answers: answers.slice(0, ANSWER_CAP) })

    // ---------------------------------------------------------------- manifest + write
    put('manifest.json', {
      version: 1,
      generated_at: new Date().toISOString(),
      seed: health.build?.seed ?? null,
      node_count: allNodes.length,
      edge_count: compact.length,
      alert_count: alerts.length,
      shards: { alert_details: [...shards.keys()].sort().map((k) => `alert_details/${k}.json`), edges: edgeFiles.map((f) => `graph/${f}`) },
      notes: 'Fixture snapshot generated from the in-browser mock adapter by web/scripts/make-fixture-snapshot.mjs (not the Python exporter). Shapes follow docs/10-static-snapshot.md section 1.',
    })
    rmSync(outDir, { recursive: true, force: true })
    let total = 0
    for (const [rel, obj] of files) {
      const file = path.join(outDir, rel)
      mkdirSync(path.dirname(file), { recursive: true })
      writeFileSync(file, JSON.stringify(obj))
      total += statSync(file).size
    }
    const count = (dir) => readdirSync(dir, { withFileTypes: true }).reduce((n, d) => n + (d.isDirectory() ? count(path.join(dir, d.name)) : 1), 0)
    console.log(`wrote ${count(outDir)} files (${(total / 1024).toFixed(0)} KB) to ${path.relative(process.cwd(), outDir)}: ${alerts.length} alerts (${withContext.size} with full context), ${allNodes.length} nodes, ${compact.length} edges, ${answers.length} chat answers, ${Object.keys(suggestions).length} suggestion contexts`)
  } finally {
    await server.close()
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
