/* eslint-disable */
/** Offline analyst playbooks for the mock adapter and the fake SSE stream generator. */
import type { AnalystAnswer, ChatContext, ChatEvent, ChatMessageIn, ChatSession, Finding, GraphFragment, JsonValue, ToolCallRecord } from '../types'
import { emptyFragment } from '../types'
import { alertContext, attackPathsAll, blastRadius, containment, credentialJoins, mediumAlertsWithDataPath, alertsReachingCrownJewels } from './analytics'
import { alertSummary, dataset, storylineById } from './dataset'
import { ID } from './fixtures/ids'
import { mergeFragments } from './graph'
import { exposureTable, tiContextForOwner } from './ti'

interface ToolStep { name: string; arguments: Record<string, JsonValue | undefined>; summary: string; evidence?: GraphFragment; duration_ms: number }
interface Playbook { intent: string; tools: ToolStep[]; narrative: string; findings: Finding[]; followups: string[]; confidence: number }

export const DEMO_QUESTIONS = [
  'Show me everything connected to the credential-dumping alert on BAS-01 — what can an attacker reach from here?',
  "Which of today's medium-severity endpoint alerts sit on assets with a path to regulated data?",
  'Is the cloud API activity from the bastion role in the last 6 hours related to any endpoint detection?',
  "What is the blast radius if identity 'LarkspurBastionSSMRole' is fully compromised?",
  'Which internet-exposed hosts have a vuln a threat actor is actively exploiting against fintechs right now?',
  'Rank all open issues by contextual risk, not vendor severity, and explain the top 3.',
  'Trace the full attack path from the phishing detection on WKS-3391 to any regulated data store.',
  'Which credentials used in cloud API calls today were seen being stolen on an endpoint?',
  'Do any current detections match IOCs or TTPs from the Cinder Jackal report, and what do they touch?',
  'Show only alerts on assets that can reach cardholder data; hide everything else.',
  "Is the 'S3 bucket public' critical finding actually risky — what's in it and can an actor reach it?",
  'If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?',
]

export function suggestions(ctx: { alert_id?: string; node_id?: string; storyline_id?: string }): string[] {
  const out: string[] = []
  if (ctx.alert_id) {
    const a = alertSummary(ctx.alert_id)
    if (a) {
      out.push(`Why is "${a.title}" ranked #${a.contextual_rank_position} when the vendor says ${a.vendor_severity}?`)
      if (a.entity_name) out.push(`What can an attacker reach from ${a.entity_name}?`)
      if (a.ioc_match_count || a.ti_actor_ids.length) out.push('Which IOCs and actors does this alert match, and what else do they touch?')
      if (a.storyline_id) out.push('Summarise the storyline this alert belongs to, stage by stage.')
      out.push(`If we contain ${a.entity_name ?? 'this asset'} now, what do we cut and what breaks?`)
    }
  }
  if (ctx.node_id) {
    const n = dataset().graph.get(ctx.node_id)
    if (n) {
      out.push(`What is the blast radius if ${n.name} is fully compromised?`)
      out.push(`Show me the neighborhood of ${n.name}.`)
      out.push(`Which alerts touch ${n.name}?`)
    }
  }
  if (ctx.storyline_id) {
    const s = storylineById(ctx.storyline_id)
    if (s) {
      out.push(`Trace the attack path of "${s.title}" with technique IDs.`)
      out.push(`Draft an incident summary for ${s.campaign_name ?? s.title} with cited evidence.`)
    }
  }
  return [...out, ...DEMO_QUESTIONS.filter((q) => !out.includes(q))].slice(0, 14)
}

// ----------------------------------------------------------------------------- playbooks

const T = (name: string, args: Record<string, JsonValue | undefined>, summary: string, evidence?: GraphFragment, ms = 180): ToolStep => ({ name, arguments: args, summary, evidence, duration_ms: ms })
const F = (statement: string, severity: Finding['severity'], evidence_ids: string[]): Finding => ({ statement, severity, evidence_ids })

function pbBlastRadius(rootId: string, label: string): Playbook {
  const br = blastRadius(rootId, 5, 100)!
  const jewels = br.crown_jewels.map((c) => `\`${c.node.id}\` (${c.node.name}, ${(c.node.props.data_classifications as string[] | undefined)?.join('/') ?? c.node.label}, ${c.hops} hops)`)
  return {
    intent: 'blast_radius',
    tools: [T('get_entity', { id: rootId }, `${label}: ${br.fragment.nodes.find((n) => n.id === rootId)?.label}`, undefined, 90), T('blast_radius', { id: rootId, depth: 5 }, `${br.reached_count} nodes, ${br.crown_jewels.length} crown jewels, ${br.secrets.length} secrets`, br.fragment, 260)],
    narrative: `## Blast radius of ${label}\n\n${br.summary}\n\n**Crown jewels reachable**\n${jewels.length ? jewels.map((j) => `- ${j}`).join('\n') : '- none'}\n\n**Secrets**\n${br.secrets.length ? br.secrets.map((s) => `- \`${s.node.id}\` (${s.hops} hops)`).join('\n') : '- none'}\n\n**Identities in reach**\n${br.identities.slice(0, 6).map((i) => `- \`${i.node.id}\``).join('\n') || '- none'}\n\nAccounts touched: ${br.accounts_touched.map((a) => `\`${a}\``).join(', ') || 'none'}. Hop distribution: ${Object.entries(br.by_hop).map(([h, c]) => `${c} at ${h}`).join(', ')}.`,
    findings: [
      F(`${label} reaches ${br.crown_jewels.length} crown jewel(s) within ${br.depth} hops`, br.crown_jewels.length ? 'critical' : 'low', [rootId, ...br.crown_jewels.map((c) => c.node.id)]),
      ...(br.secrets.length ? [F(`${br.secrets.length} secret(s) readable through the identity chain`, 'high' as const, br.secrets.map((s) => s.node.id))] : []),
    ],
    followups: ['Which alerts sit on assets in this blast radius?', `If we contain ${label} now, what breaks?`, 'Show the shortest path to the cardholder vault.'],
    confidence: 0.9,
  }
}

function pbQ1(): Playbook {
  const pb = pbBlastRadius(ID.A009, 'the IMDS credential-access alert on bas-01')
  const ctx = alertContext(ID.A009)!
  pb.tools.unshift(T('get_alert', { alert_id: ID.A009 }, `ldt-a009: medium (vendor) -> 92 critical (contextual), storyline EMBERCAST`, undefined, 110))
  pb.tools.push(T('get_neighborhood', { id: ID.A009, depth: 2 }, `${ctx.evidence.nodes.length} nodes, ${ctx.evidence.edges.length} edges`, ctx.evidence, 200))
  pb.narrative = `## Everything connected to \`${ID.A009}\`\n\nThe alert **"${ctx.alert.title}"** is a vendor **medium** that Throughline ranks **#1 (score 92)**. Here is why:\n\n1. It sits on endpoint \`${ID.EP_BASTION}\`, which entity resolution ties (SAME_AS, confidence 0.99) to cloud VM \`${ID.BASTION_VM}\` (bas-01).\n2. bas-01 carries the instance role \`${ID.BASTION_ROLE}\`, whose inline policy allows \`sts:AssumeRole\` into \`${ID.PROD_READER_ROLE}\` in **larkspur-prod**.\n3. That role reads the PCI bucket \`${ID.CARDHOLDER_VAULT}\`, the PII bucket \`${ID.KYC_DOCS}\`, and two secrets (\`${ID.DB_READER_SECRET}\`, \`${ID.HSM_SECRET}\`); the DB secret unlocks \`${ID.CARDHOLDER_DB}\`.\n4. The stolen keys \`${ID.CRED_BASTION_KEY}\` were **actually used**: \`${ID.EVT('a010')}\` (GetCallerIdentity), \`${ID.EVT('a012')}\` (AssumeRole) from 203.0.113.77, a Cinder Jackal IOC.\n\n${pb.narrative.split('\n').slice(2).join('\n')}`
  pb.findings.unshift(F('A vendor-medium IMDS credential theft on bas-01 is the pivot from endpoint to cloud in the EMBERCAST storyline', 'critical', [ID.A009, ID.EP_BASTION, ID.BASTION_VM, ID.BASTION_ROLE]))
  pb.followups = ['Which credentials used in cloud API calls today were seen being stolen on an endpoint?', 'Trace the full attack path from the phishing detection on WKS-3391.', 'If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?']
  pb.intent = 'alert_reach'
  return pb
}

function pbQ2(): Playbook {
  const res = mediumAlertsWithDataPath('medium', 'falcon')
  const rows = res.items.map((a) => `| \`${a.id}\` | ${a.title} | ${a.entity_name} | **${a.contextual_score}** | ${a.graph_reasons.slice(0, 2).join('; ')} |`).join('\n')
  return {
    intent: 'medium_alerts_data_path',
    tools: [T('list_alerts', { severity: 'medium', source: 'falcon', sort: 'contextual', limit: 50 }, `${dataset().alertsByContextual.filter((a) => a.vendor_severity === 'medium' && a.source_system === 'falcon').length} medium EDR alerts`, undefined, 120), T('alerts_reaching_crown_jewels', {}, `${res.items.length} of them sit on assets with a path to regulated data`, res.fragment, 240)],
    narrative: `## Medium-severity endpoint alerts with a path to regulated data\n\n${res.items.length} of the medium EDR alerts sit on assets whose identity chain reaches PCI/PII data. Everything else (PsExec by the admin on the fileshare, the EICAR test, commodity detections on workstations) has **no data path** and stays low.\n\n| Alert | Title | Asset | Contextual | Why |\n|---|---|---|---|---|\n${rows}\n\nThe first row, \`${ID.A009}\`, is the pivotal alert: **medium in the console, #1 in context** because the bastion's role chain ends at \`${ID.CARDHOLDER_VAULT}\` and the stolen keys were used in the cloud minutes later.`,
    findings: [F(`${res.items.length} medium EDR alerts sit on assets with a path to regulated data; ldt-a009 ranks first`, 'critical', res.items.slice(0, 3).map((a) => a.id)), F('ldt-n003 (PsExec) and ldt-n001 (EICAR) have no regulated data path and are excluded', 'informational', [ID.N003, ID.N001])],
    followups: ['Show me everything connected to the credential-dumping alert on BAS-01.', 'Explain the score breakdown of ldt-a009.', 'Which of these are part of the same storyline?'],
    confidence: 0.92,
  }
}

function pbQ3(): Playbook {
  const cj = credentialJoins()
  const item = cj.items[0]
  return {
    intent: 'cloud_activity_correlation',
    tools: [T('threat_intel_lookup', { value: 'LarkspurBastionSSMRole' }, 'role last used 2026-09-10T02:24Z from 203.0.113.77 (AS64500)', undefined, 100), T('credential_joins', {}, `${cj.items.length} credentials seen stolen on an endpoint and used in the cloud`, cj.fragment, 230)],
    narrative: `## Yes: the bastion role's API calls trace back to an endpoint detection\n\nThe temporary key \`${ID.CRED_BASTION_KEY}\` was **stolen** by \`${ID.A009}\` on \`${ID.EP_BASTION}\` at 02:11:45Z (IMDS read from an interactive shell) and **used** nine minutes later from \`${ID.EGRESS_IP}\`:\n\n- \`${ID.EVT('a010')}\` sts:GetCallerIdentity (02:20:31Z)\n- \`${ID.EVT('a011')}\` s3:ListAllMyBuckets, iam:ListRoles (AccessDenied)\n- \`${ID.EVT('a012')}\` sts:AssumeRole -> \`${ID.PROD_READER_ROLE}\` (session ember-sync)\n\nThe AssumeRole minted \`${ID.CRED_PROD_KEY}\` (DERIVED_FROM the stolen key), which then performed \`${ID.EVT('a013')}\`..\`${ID.EVT('a016')}\`: 1,247 GetObject on the cardholder vault and two GetSecretValue calls. The source IP ${item ? item.source_ips.join(', ') : '203.0.113.77'} matches Cinder Jackal indicator \`${ID.IOC_EGRESS_IP}\`.\n\nA cloud-only view sees valid credentials from a new ASN (\`${ID.A017}\`, vendor low); the EDR sees a medium IMDS read. The credential node is the join key.`,
    findings: [F('Instance-role credentials stolen in ldt-a009 were used for STS/S3 calls from Cinder Jackal infrastructure', 'critical', [ID.A009, ID.CRED_BASTION_KEY, ID.EVT('a010'), ID.EVT('a012')]), F('AssumeRole into LarkspurProdDataReader produced a derived credential that read the PCI vault', 'critical', [ID.CRED_PROD_KEY, ID.EVT('a014'), ID.CARDHOLDER_VAULT])],
    followups: ['Trace the full attack path from the phishing detection on WKS-3391.', 'If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?'],
    confidence: 0.93,
  }
}

function pbQ5(): Playbook {
  const rows = exposureTable(true)
  const table = rows.map((r) => `| \`${r.vm.id}\` (${r.vm.name}) | ${r.cve.name} | ${r.exploitation_status} | ${r.actors.map((a) => a.name).join(', ')} (${r.sector_relevance.toFixed(2)}) | **${r.contextual_score}** | ${r.crown_jewels_reachable.map((j) => j.name).join(', ') || '—'} | ${r.has_edr_sensor ? 'yes' : 'no'} |`).join('\n')
  const first = rows[0]
  const frag = first ? mergeFragments(blastRadius(first.vm.id, 3, 60)!.fragment, dataset().graph.neighborhood(first.cve.id, 1, { maxNodes: 30 })) : emptyFragment()
  frag.layout_hint = 'neighborhood'
  frag.focus = first ? [first.vm.id] : []
  return {
    intent: 'exposed_exploited',
    tools: [T('exposed_hosts_with_exploited_vulns', { sector_only: true }, `${rows.length} internet-exposed hosts with CVEs actively exploited by actors targeting financial services`, undefined, 210), T('blast_radius', { id: first?.vm.id ?? ID.EDGE_VM, depth: 3 }, `${first?.vm.name}: role reaches ${first?.crown_jewels_reachable.map((j) => j.name).join(', ') || 'no crown jewels'}`, frag, 190)],
    narrative: `## Internet-exposed hosts with actively exploited vulnerabilities (sector-relevant actors)\n\n| Host | CVE | Exploitation | Actor (relevance) | Contextual | Crown jewels reachable | EDR |\n|---|---|---|---|---|---|---|\n${table}\n\n**\`${ID.EDGE_VM}\` (stmt-render-2a) comes first**: \`0.0.0.0/0\` on TCP 8080, log4j-core 2.14.1 in the SBOM, **mass exploitation** by Hollow Tide's SALTWORKS campaign (sector relevance 0.8), and a live foothold (\`${ID.B002}\`, \`${ID.B003}\`). Its role \`${ID.EDGE_ROLE}\` reads \`${ID.APP_CONFIG_BUCKET}\`, which holds credentials for \`${ID.CARDHOLDER_DB}\`. The TI booster rail floors its score at 80.\n\nstmt-render-stg-1 and log4j-testbed share the CVE but have no crown-jewel reach; bas-01 does not appear because SSH is restricted to the VPN CIDR.`,
    findings: [F('stmt-render-2a is internet-exposed, vulnerable to CVE-2021-44228 under mass exploitation by Hollow Tide, and already compromised', 'high', [ID.EDGE_VM, ID.LOG4SHELL, ID.ACTOR_HT, ID.B002]), F('Its instance role can read prod-app-config, which contains credentials for the PCI cardholder database', 'high', [ID.EDGE_ROLE, ID.APP_CONFIG_BUCKET, ID.CARDHOLDER_DB])],
    followups: ['Show the SALTWORKS storyline.', 'Include actors outside our sector too.', 'What does the Hollow Tide report say about follow-on activity?'],
    confidence: 0.9,
  }
}

function pbQ6(): Playbook {
  const top = dataset().alertsByContextual.slice(0, 3)
  const ctxs = top.map((a) => alertContext(a.id)!)
  const explain = ctxs.map((c, i) => {
    const f = c.risk.factors
    return `### #${i + 1} \`${c.alert.id}\` — ${c.alert.title} (${c.alert.vendor_severity} -> **${c.alert.contextual_score}**)\n${f.map((x) => `- **${x.label}** ${x.value.toFixed(2)} x ${x.weight} = ${x.contribution} pts: ${x.reason}`).join('\n')}\n- Rails: ${c.risk.rails.join(', ') || 'none'}; moved ${Math.abs(c.risk.delta_vs_vendor)} places ${c.risk.delta_vs_vendor <= 0 ? 'up' : 'down'} versus the vendor queue.`
  })
  const frag = ctxs.reduce((acc, c) => mergeFragments(acc, c.evidence), emptyFragment('path'))
  frag.focus = top.map((a) => a.id)
  const noiseIds: string[] = [ID.N002, ID.N001]
  const noise = dataset().alertsByContextual.filter((a) => noiseIds.includes(a.id))
  return {
    intent: 'rank_explain',
    tools: [T('list_alerts', { sort: 'contextual', limit: 50 }, `${dataset().alertsByContextual.length} open alerts re-ranked by context`, undefined, 130), ...top.map((a, i) => T('explain_risk', { alert_id: a.id }, `${a.id}: ${a.contextual_score} (${a.contextual_band}), ${a.graph_reasons[0]}`, i === 0 ? frag : undefined, 150))],
    narrative: `## Open alerts by contextual risk\n\nThe vendor queue would start with \`${noise[0]?.id}\` (${noise[0]?.vendor_severity}, public marketing bucket) and \`${noise[1]?.id}\` (${noise[1]?.vendor_severity}, EICAR on a sandbox). In context they score ${noise[0]?.contextual_score} and ${noise[1]?.contextual_score} and fall to positions #${noise[0]?.contextual_rank_position} and #${noise[1]?.contextual_rank_position}.\n\n${explain.join('\n\n')}\n\nAll three top alerts share one throughline: the EMBERCAST intrusion reaching \`${ID.CARDHOLDER_VAULT}\`. The highest-scoring alert outside it is \`${ID.B002}\` (Log4Shell foothold, 80).`,
    findings: top.map((a, i) => F(`#${i + 1}: ${a.title} (${a.vendor_severity} -> ${a.contextual_score})`, a.contextual_band === 'noise' ? 'low' : a.contextual_band, [a.id])),
    followups: ['Why is the public S3 bucket finding only 25?', 'Show only alerts on assets that can reach cardholder data.', 'Explain the score of ldt-b002.'],
    confidence: 0.9,
  }
}

function pbQ7(): Playbook {
  const path = attackPathsAll()[0]
  const story = storylineById(ID.STORYLINE_A)!
  const stages = story.stages.map((s) => `${s.order}. **${s.stage}** (${s.technique_ids.join(', ')}) — ${s.summary}${s.alert_ids.length ? ` Alerts: ${s.alert_ids.map((a) => `\`${a}\``).join(', ')}.` : ' No alert: only CloudTrail events.'}`).join('\n')
  const br = blastRadius(ID.A009, 6, 100)!
  return {
    intent: 'attack_path',
    tools: [T('attack_paths', { entry_id: ID.A001, target_id: ID.CARDHOLDER_VAULT, k: 3 }, `1 observed path, ${path.hops} hops, likelihood ${path.likelihood}`, path.fragment, 260), T('get_storyline', { storyline_id: ID.STORYLINE_A }, `${story.stage_count} stages, ${story.alert_ids.length} alerts, actor ${story.actor_name}`, undefined, 120), T('blast_radius', { id: ID.A009, depth: 6 }, br.summary, br.fragment, 220)],
    narrative: `## Attack path: phishing on WKS-3391 to the cardholder vault\n\n\`${ID.A001}\` -> \`${ID.WKS_DANA}\` -LATERAL_MOVEMENT_TO-> \`${ID.EP_BASTION}\` -SAME_AS-> \`${ID.BASTION_VM}\` -HAS_ROLE-> \`${ID.BASTION_ROLE}\` -CAN_ASSUME-> \`${ID.PROD_READER_ROLE}\` -CAN_ACCESS-> \`${ID.CARDHOLDER_VAULT}\` (${path.hops} hops).\n\n${stages}\n\n**Blast radius at the end of the path:** ${br.crown_jewels.map((c) => `\`${c.node.id}\``).join(', ')} plus secrets ${br.secrets.map((s) => `\`${s.node.id}\``).join(', ')}. The EDR grouped stages 1-3 into inc-0091 and stage 4 into inc-0094 on a different host; it never saw stages 5-7.`,
    findings: [F('End-to-end seven-stage intrusion from a treasury workstation to the PCI cardholder vault is confirmed', 'critical', [ID.A001, ID.A007, ID.A009, ID.EVT('a012'), ID.EVT('a014'), ID.CARDHOLDER_VAULT]), F('Two crown-jewel buckets, one crown-jewel database and two secrets are in the blast radius', 'critical', br.crown_jewels.map((c) => c.node.id))],
    followups: ['Which credentials used in cloud API calls today were seen being stolen on an endpoint?', 'If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?', 'Draft an incident summary with cited evidence.'],
    confidence: 0.95,
  }
}

function pbQ8(): Playbook {
  const cj = credentialJoins()
  const rows = cj.items.map((i) => `| \`${i.credential.id}\` | \`${i.stolen_by_alert.id}\` on ${i.endpoint.name} | ${i.principal.name} | ${i.used_in_events.map((e) => `\`${e.id}\` ${e.props.event_name}`).join(', ')} | ${i.first_use} | ${i.source_ips.join(', ')} |`).join('\n')
  return {
    intent: 'credential_join',
    tools: [T('credential_joins', {}, `${cj.items.length} credentials joined between endpoint theft and cloud use`, cj.fragment, 240)],
    narrative: `## Credentials stolen on an endpoint and used in the cloud\n\n| Credential | Stolen by | Principal | Cloud use | First use | Source IP |\n|---|---|---|---|---|---|\n${rows}\n\nExactly two credentials satisfy the join. \`${ID.CRED_BASTION_KEY}\` was read from IMDS in \`${ID.A009}\`; \`${ID.CRED_PROD_KEY}\` was minted by its AssumeRole (\`${ID.EVT('a012')}\`) and did the collection (\`${ID.EVT('a014')}\`, 1,247 objects, 38.4 GB). Both were used from \`${ID.EGRESS_IP}\`, a Cinder Jackal IOC. No other credential in the estate shows both a theft detection and cloud use.`,
    findings: cj.items.map((i) => F(`${i.credential.name} (${i.principal.name}) stolen in ${i.stolen_by_alert.id} and used in ${i.used_in_events.length} cloud events`, 'critical', [i.credential.id, i.stolen_by_alert.id, ...i.used_in_events.map((e) => e.id)])),
    followups: ['Is the cloud API activity from the bastion role related to any endpoint detection?', 'Rotate the bastion role: what breaks?'],
    confidence: 0.95,
  }
}

function pbQ9(): Playbook {
  const ctx = tiContextForOwner(ID.ACTOR_CJ)
  const g = dataset().graph
  const alerts = dataset().alertsByContextual.filter((a) => a.ti_actor_ids.includes(ID.ACTOR_CJ))
  const ids = new Set<string>([ID.ACTOR_CJ, ID.CAMPAIGN_EMBERCAST, ID.REPORT_EMBERCAST, ...ctx.matches.map((m) => m.matched_node_id), ...ctx.matches.map((m) => m.indicator_id), ...alerts.map((a) => a.id), ID.CARDHOLDER_VAULT, ID.BASTION_ROLE, ID.PROD_READER_ROLE])
  const frag = g.fragment(ids, { focus: [ID.ACTOR_CJ], hint: 'neighborhood', highlight: new Set(alerts.map((a) => a.id)) })
  const overlap = Math.round((ctx.ttp_overlap[ID.ACTOR_CJ] ?? 0) * 100)
  return {
    intent: 'ti_match',
    tools: [T('threat_intel_lookup', { value: 'Cinder Jackal' }, `${ctx.matches.length} IOC matches, ${alerts.length} attributed alerts, TTP overlap ${overlap}%`, frag, 220), T('get_storyline', { storyline_id: ID.STORYLINE_A }, 'EMBERCAST storyline reaches the cardholder vault', undefined, 100)],
    narrative: `## Cinder Jackal (report \`${ID.REPORT_EMBERCAST}\`) in our estate\n\n**IOC matches (${ctx.matches.length})**\n${ctx.matches.map((m) => `- ${m.ioc_type} \`${m.value}\` (confidence ${m.confidence.toFixed(2)}) matched \`${m.matched_node_id}\``).join('\n')}\n\n**Detections attributed:** ${alerts.map((a) => `\`${a.id}\``).join(', ')} (hash matches on MAPLELOADER, NIGHTFERRY and QUILLDROP; C2 domain match; egress IP match on the cloud anomaly alert). TTP overlap with the report is **${overlap}%** of the actor's ${Object.keys(ctx.ttp_overlap).length ? 'known' : ''} techniques.\n\n**What they touch:** the chain ends at \`${ID.CARDHOLDER_VAULT}\` via \`${ID.BASTION_ROLE}\` -> \`${ID.PROD_READER_ROLE}\`. Hollow Tide indicators are unrelated and not included.`,
    findings: [F(`${ctx.matches.length} Cinder Jackal indicators match live telemetry across WKS-3391, bas-01 and CloudTrail`, 'critical', ctx.matches.slice(0, 6).map((m) => m.matched_node_id)), F('The matched activity forms one storyline that reached the PCI cardholder vault', 'critical', [ID.STORYLINE_A, ID.CARDHOLDER_VAULT])],
    followups: ['Trace the full attack path from the phishing detection on WKS-3391.', 'Which other actors target our sector?'],
    confidence: 0.92,
  }
}

function pbQ10(): Playbook {
  const res = alertsReachingCrownJewels(undefined, 'PCI')
  return {
    intent: 'alerts_reaching_jewels',
    tools: [T('alerts_reaching_crown_jewels', { classification: 'PCI' }, `${res.items.length} alerts on assets that can reach cardholder data`, res.fragment, 230)],
    narrative: `## Alerts on assets that can reach cardholder data (PCI)\n\n${res.items.map((a) => `- \`${a.id}\` **${a.contextual_score}** ${a.title} — ${a.entity_name} (${a.vendor_severity})`).join('\n')}\n\nHidden: ${dataset().alertsByContextual.length - res.items.length} alerts whose assets have no path to \`${ID.CARDHOLDER_VAULT}\` or \`${ID.CARDHOLDER_DB}\`, including \`${ID.N001}\`, \`${ID.N002}\` and \`${ID.N003}\`. The filter is a reverse reachability query from the PCI stores through CAN_ACCESS, CAN_ASSUME, HAS_ROLE and SAME_AS.`,
    findings: [F(`${res.items.length} alerts touch assets with a path to PCI data`, 'high', res.items.slice(0, 5).map((a) => a.id))],
    followups: ['Explain the top one.', 'Show the same for PII.'],
    confidence: 0.9,
  }
}

function pbQ11(): Playbook {
  const ctx = alertContext(ID.N002)!
  const br = blastRadius(ID.MARKETING_BUCKET, 3, 40)!
  return {
    intent: 'noise_check',
    tools: [T('get_alert', { alert_id: ID.N002 }, 'iss-n002: critical (vendor) -> 25 noise (contextual)', undefined, 100), T('explain_risk', { alert_id: ID.N002 }, `no_context_ceiling:25; ${ctx.risk.reasons.join(', ')}`, undefined, 120), T('blast_radius', { id: ID.MARKETING_BUCKET, depth: 3 }, `${br.reached_count} nodes, 0 crown jewels`, ctx.evidence, 180)],
    narrative: `## Is \`${ID.N002}\` actually risky? No.\n\n- **What is in it:** \`${ID.MARKETING_BUCKET}\` is classified **PUBLIC** (static website assets, sensitivity none, 12 GB) and belongs to \`${ID.APP_MARKETING}\` (tier-3).\n- **Who can reach it:** anyone, by design; but nothing sensitive is reachable *from* it: no role, no secret, no CAN_ACCESS edges leave the bucket.\n- **Actor interest:** no IOC or actor targets the marketing site; sector-relevant actors are after cardholder and KYC data.\n- **Score:** ${ctx.risk.factors.map((f) => `${f.label} ${f.value.toFixed(2)}`).join(', ')} -> raw ${ctx.risk.raw_score}, then the **no-context ceiling** caps it at 25.\n\nRecommendation: low priority. Confirm the bucket is intentionally public and move on; the CSPM "critical" reflects configuration, not risk.`,
    findings: [F('Public marketing bucket holds only PUBLIC data with no privilege or data reach; contextual score 25 (noise)', 'low', [ID.N002, ID.MARKETING_BUCKET])],
    followups: ['Rank all open issues by contextual risk and explain the top 3.', 'Which CSPM issues do score high in context?'],
    confidence: 0.94,
  }
}

function pbQ12(targets: string[] = [ID.EP_BASTION, ID.BASTION_ROLE], actions: string[] = ['isolate_endpoint', 'rotate_role_credentials']): Playbook {
  const sim = containment(targets, actions)
  const story = storylineById(ID.STORYLINE_A)!
  return {
    intent: 'containment',
    tools: [T('simulate_containment', { target_ids: targets, actions }, `${sim.paths_cut} attack path(s) cut, ${sim.crown_jewels_protected.length} crown jewels protected, ${sim.breaks.length} things break`, sim.fragment, 280)],
    narrative: `## Containment simulation: ${targets.map((t) => dataset().graph.get(t)?.name ?? t).join(' + ')}\n\n**Contained:** ${sim.paths_cut} attack path(s); storyline${sim.storylines_contained.length === 1 ? '' : 's'} ${sim.storylines_contained.map((s) => `\`${s}\``).join(', ')}. Protected crown jewels: ${sim.crown_jewels_protected.map((j) => `\`${j}\``).join(', ') || 'none'}.\n\n**What breaks**\n${sim.breaks.map((b) => `- **${b.name}** (${b.label}): ${b.impact}`).join('\n') || '- nothing recorded in the dependency graph'}\n\n**Residual risks**\n${sim.residual_risks.map((r) => `- ${r}`).join('\n')}\n\n**Recommendations**\n${sim.recommendations.map((r) => `- ${r}`).join('\n')}\n\n---\n### Draft incident summary\n**${story.title}** (${story.actor_name}, ${story.campaign_name}). First event ${story.first_event}; last ${story.last_event}. ${story.summary} Evidence: ${story.alert_ids.slice(0, 4).map((a) => `\`${a}\``).join(', ')}, \`${ID.EVT('a012')}\`, \`${ID.EVT('a014')}\`.`,
    findings: [F(`Isolating bas-01 and rotating the bastion role cuts ${sim.paths_cut} path(s) to the cardholder vault`, 'high', [ID.BASTION_VM, ID.BASTION_ROLE, ID.CARDHOLDER_VAULT]), ...sim.breaks.slice(0, 2).map((b) => F(`Breaks: ${b.name}`, 'medium' as const, [b.node_id])), F('The initial foothold on WKS-3391 stays active unless it is isolated too', 'high', [ID.WKS_DANA, ID.A003])],
    followups: ['Also isolate WKS-3391: what changes?', 'Tighten the trust policy on LarkspurProdDataReader as well.'],
    confidence: 0.9,
  }
}

function pbExplainAlert(alertId: string): Playbook {
  const ctx = alertContext(alertId)
  if (!ctx) return pbFallback(`alert ${alertId}`)
  const f = ctx.risk.factors
  return {
    intent: 'explain_alert',
    tools: [T('get_alert_context', { alert_id: alertId }, `${ctx.alert.id}: ${ctx.alert.vendor_severity} -> ${ctx.alert.contextual_score} (${ctx.alert.contextual_band}); ${ctx.insights.length} insights`, ctx.evidence, 240)],
    narrative: `## \`${alertId}\` — ${ctx.alert.title}\n\nVendor **${ctx.alert.vendor_severity}** (#${ctx.alert.vendor_rank_position} in the vendor queue) -> contextual **${ctx.alert.contextual_score} ${ctx.alert.contextual_band}** (#${ctx.alert.contextual_rank_position}).\n\n**Score breakdown**\n${f.map((x) => `- ${x.label}: ${x.value.toFixed(2)} x ${x.weight} = ${x.contribution} pts — ${x.reason}`).join('\n')}\n${ctx.risk.rails.length ? `- Rails applied: ${ctx.risk.rails.join(', ')}` : ''}\n\n**Insights**\n${ctx.insights.slice(0, 5).map((i) => `- (${i.hops} hops, ${i.sources.join(' + ')}) ${i.statement}`).join('\n')}\n\n${ctx.blast_radius ? `**Blast radius:** ${ctx.blast_radius.summary}` : ''}`,
    findings: [F(`${ctx.alert.title}: ${ctx.alert.vendor_severity} -> ${ctx.alert.contextual_score}`, ctx.alert.contextual_band === 'noise' ? 'low' : ctx.alert.contextual_band, [alertId]), ...ctx.insights.slice(0, 2).map((i) => F(i.statement, i.importance > 0.85 ? ('high' as const) : ('medium' as const), i.evidence_node_ids.slice(0, 6)))],
    followups: [ctx.alert.entity_name ? `What can an attacker reach from ${ctx.alert.entity_name}?` : 'What is the blast radius?', 'Which alerts are related to this one?', ctx.alert.entity_name ? `If we contain ${ctx.alert.entity_name} now, what breaks?` : 'What should we contain first?'],
    confidence: 0.9,
  }
}

function pbEntity(nodeId: string): Playbook {
  const g = dataset().graph
  const n = g.get(nodeId)!
  const nb = g.neighborhood(nodeId, 1, { maxNodes: 60 })
  const alerts = dataset().alertsByContextual.filter((a) => a.entity_id === nodeId)
  const props = Object.entries(n.props).filter(([k, v]) => !['source', 'first_seen', 'last_seen', 'confidence', 'raw', 'statements'].includes(k) && v !== null && v !== undefined && typeof v !== 'object').slice(0, 8)
  return {
    intent: 'entity_card',
    tools: [T('get_entity', { id: nodeId }, `${n.label} ${n.name}: ${g.degree(nodeId).in + g.degree(nodeId).out} edges, ${alerts.length} alerts`, undefined, 90), T('get_neighborhood', { id: nodeId, depth: 1 }, `${nb.nodes.length} nodes, ${nb.edges.length} edges`, nb, 170)],
    narrative: `## ${n.name} (\`${nodeId}\`)\n\n**${n.label}** in category ${n.category}${n.tags.length ? `, tags: ${n.tags.join(', ')}` : ''}.\n\n${props.map(([k, v]) => `- **${k}**: ${String(v)}`).join('\n')}\n\n**Connections:** ${Object.entries(g.edgeTypeCounts(nodeId)).map(([t, c]) => `${t} x${c}`).join(', ') || 'none'}.\n\n${alerts.length ? `**Alerts on this entity:** ${alerts.map((a) => `\`${a.id}\` (${a.contextual_score})`).join(', ')}` : 'No alerts on this entity.'}`,
    findings: alerts.slice(0, 3).map((a) => F(`${a.title} (${a.contextual_score})`, a.contextual_band === 'noise' ? 'low' : a.contextual_band, [a.id])),
    followups: [`What is the blast radius if ${n.name} is fully compromised?`, `Which alerts touch ${n.name}?`],
    confidence: 0.85,
  }
}

function pbFallback(topic: string): Playbook {
  return {
    intent: 'unknown',
    tools: [T('search_entities', { query: topic.slice(0, 40), limit: 5 }, 'no confident entity match', undefined, 80)],
    narrative: `I could not map that question to a graph traversal (offline playbooks only; no LLM key configured in this mock). I can answer questions like:\n\n${DEMO_QUESTIONS.slice(0, 6).map((q) => `- ${q}`).join('\n')}\n\nYou can also name an entity (a host such as **bas-01**, a role, a bucket, an alert id) and I will show its card and neighborhood.`,
    findings: [],
    followups: DEMO_QUESTIONS.slice(0, 4),
    confidence: 0.2,
  }
}

function resolveEntity(text: string): string | undefined {
  const g = dataset().graph
  const lower = text.toLowerCase()
  const idMatch = text.match(/\b[a-z]+:[a-z0-9-]+:[^\s`'"),]+/i)
  if (idMatch && g.has(idMatch[0])) return idMatch[0]
  const candidates = [...g.nodes.values()].filter((n) => n.label !== 'Alert' && n.label !== 'AttackTechnique' && n.name.length >= 4 && lower.includes(n.name.toLowerCase()))
  candidates.sort((a, b) => b.name.length - a.name.length)
  return candidates[0]?.id
}

export function playbookFor(content: string, ctx?: ChatContext | null): Playbook {
  const q = content.toLowerCase()
  const has = (...re: RegExp[]) => re.some((r) => r.test(q))
  if (has(/isolate|rotate|contain(ment)?\b|what breaks/)) {
    const ent = resolveEntity(content)
    if (ent && ![ID.BASTION_VM, ID.EP_BASTION, ID.BASTION_ROLE].includes(ent as never) && !/bas-01|bastion/.test(q)) return pbQ12([ent], ['isolate_endpoint', 'rotate_role_credentials'])
    const targets = /wks-3391/.test(q) ? [ID.EP_BASTION, ID.BASTION_ROLE, ID.WKS_DANA] : [ID.EP_BASTION, ID.BASTION_ROLE]
    const actions = ['isolate_endpoint', 'rotate_role_credentials', ...(/trust/.test(q) ? ['tighten_trust_policy'] : [])]
    return pbQ12(targets, actions)
  }
  if (has(/medium/) && has(/regulated|data|path/)) return pbQ2()
  if (has(/credential/) && has(/cloud api|api call|stolen|used in/)) return pbQ8()
  if (has(/cloud api activity|related to any endpoint|bastion role.*(6|six) hours/)) return pbQ3()
  if (has(/internet[- ]exposed|actively exploit|exploiting against/)) return pbQ5()
  if (has(/rank|top 3|top three|explain the top/)) return pbQ6()
  if (has(/trace|full attack path|phishing detection/)) return pbQ7()
  if (has(/cinder jackal|ioc|ttp|report/) && !has(/incident summary/)) return pbQ9()
  if (has(/only alerts|hide everything|reach cardholder/)) return pbQ10()
  if (has(/bucket public|s3 bucket|actually risky|marketing/)) return pbQ11()
  if (has(/everything connected|credential[- ]dumping alert on bas-01/)) return pbQ1()
  if (has(/blast radius|fully compromised|footprint|attacker reach/)) {
    const ent = resolveEntity(content) ?? (ctx?.node_id && dataset().graph.has(ctx.node_id) ? ctx.node_id : undefined) ?? (ctx?.alert_id ? alertSummary(ctx.alert_id)?.entity_id ?? undefined : undefined)
    if (ent) return pbBlastRadius(ent, dataset().graph.get(ent)?.name ?? ent)
    return pbBlastRadius(ID.BASTION_ROLE, 'LarkspurBastionSSMRole')
  }
  if (has(/why|explain|risky|score|ranked|summari[sz]e|storyline|stage by stage|this alert|incident summary/)) {
    const alertRef = content.match(/(ldt|iss|waf|ids|idp|ca)-[a-z0-9]+/i)
    const byRef = alertRef ? dataset().alertsByContextual.find((a) => a.id.toLowerCase().endsWith(alertRef[0].toLowerCase()))?.id : undefined
    const target = byRef ?? ctx?.alert_id
    if (target && alertSummary(target)) return pbExplainAlert(target)
    if (ctx?.storyline_id === ID.STORYLINE_B) return pbQ5()
    if (has(/storyline|incident summary|stage/)) return pbQ7()
  }
  const alertRef = content.match(/(ldt|iss|waf|ids|idp|ca)-[a-z0-9]+/i)
  if (alertRef) {
    const a = dataset().alertsByContextual.find((x) => x.id.toLowerCase().endsWith(alertRef[0].toLowerCase()))
    if (a) return pbExplainAlert(a.id)
  }
  const ent = resolveEntity(content)
  if (ent) {
    if (has(/neighbou?rhood|connected|show me|what is|who is|alerts touch/)) return pbEntity(ent)
    return pbEntity(ent)
  }
  if (ctx?.alert_id && has(/this|it\b/)) return pbExplainAlert(ctx.alert_id)
  if (ctx?.node_id && dataset().graph.has(ctx.node_id) && has(/this|it\b|here/)) return pbEntity(ctx.node_id)
  return pbFallback(content)
}

// ----------------------------------------------------------------------------- sessions and streaming

const sessions = new Map<string, ChatSession>()
let seq = 1

export function createSession(context?: ChatContext | null): ChatSession {
  const id = `mock-session-${seq++}`
  const s: ChatSession = { id, created_at: new Date().toISOString(), turns: [], context: (context ?? {}) as Record<string, JsonValue | undefined> }
  sessions.set(id, s)
  return s
}

export function getSession(id: string): ChatSession | undefined {
  return sessions.get(id)
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException('aborted', 'AbortError'))
    const t = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = () => {
      clearTimeout(t)
      reject(new DOMException('aborted', 'AbortError'))
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

export async function mockStream(sessionId: string, body: ChatMessageIn, onEvent: (evt: ChatEvent) => void, signal?: AbortSignal): Promise<void> {
  const session = sessions.get(sessionId) ?? createSession(body.context)
  const started = performance.now()
  const pb = playbookFor(body.content, body.context)
  onEvent({ type: 'session', data: { session_id: session.id, mode: 'offline', model: null } })
  await sleep(120, signal)
  let evidence = emptyFragment(pb.tools.find((t) => t.evidence)?.evidence?.layout_hint ?? 'neighborhood')
  const records: ToolCallRecord[] = []
  for (const [i, tool] of pb.tools.entries()) {
    const id = `call_${i + 1}`
    onEvent({ type: 'tool_call', data: { id, name: tool.name, arguments: tool.arguments } })
    await sleep(tool.duration_ms, signal)
    onEvent({ type: 'tool_result', data: { id, name: tool.name, summary: tool.summary, duration_ms: tool.duration_ms } })
    records.push({ name: tool.name, arguments: tool.arguments, summary: tool.summary, duration_ms: tool.duration_ms })
    if (tool.evidence) {
      evidence = mergeFragments(evidence, tool.evidence)
      evidence.layout_hint = tool.evidence.layout_hint
      onEvent({ type: 'evidence', data: tool.evidence })
      await sleep(80, signal)
    }
  }
  const words = pb.narrative.split(/(\s+)/)
  let buf = ''
  for (let i = 0; i < words.length; i++) {
    buf += words[i]
    if (i % 8 === 7 || i === words.length - 1) {
      onEvent({ type: 'text_delta', data: { text: buf } })
      buf = ''
      await sleep(22, signal)
    }
  }
  const answer: AnalystAnswer = { narrative_md: pb.narrative, findings: pb.findings, evidence, confidence: pb.confidence, followups: pb.followups, tool_calls: records, mode: 'offline', intent: pb.intent, model: null }
  onEvent({ type: 'answer', data: answer })
  session.turns.push({ role: 'user', content: body.content, created_at: new Date().toISOString() })
  session.turns.push({ role: 'assistant', content: pb.narrative, answer, created_at: new Date().toISOString() })
  onEvent({ type: 'done', data: { mode: 'offline', model: null, tool_calls: records.length, elapsed_ms: Math.round(performance.now() - started) } })
}
