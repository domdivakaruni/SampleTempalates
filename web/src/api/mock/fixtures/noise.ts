/* eslint-disable */
/** Background noise: the four named benign/noise alerts, quarantined attachments, IDS/WAF/CSPM/EDR filler. */
import type { Severity } from '../../types'
import type { MockGraph } from '../graph'
import { addAlert, falconFlat, type AlertSpec } from './alerts'
import { CHANGE_TICKET, ID } from './ids'

/** Deterministic pseudo-random generator so the mock looks the same on every load. */
export function rng(seed: number): () => number {
  let s = seed >>> 0
  return () => {
    s = (s + 0x6d2b79f5) >>> 0
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const pick = <T>(r: () => number, arr: T[]): T => arr[Math.floor(r() * arr.length)]

export function buildNoise(g: MockGraph): AlertSpec[] {
  const r = rng(20260911)
  g.node(ID.VPN_IP, '198.51.100.200', { address: '198.51.100.200', is_private: false, asn: 'AS64496', asn_org: 'Larkspur corporate VPN egress', country: 'US', reputation: 'benign' })

  const named: AlertSpec[] = [
    {
      id: ID.N001, title: 'EICAR test file detected and quarantined', description: 'Known EICAR anti-virus test string written by a CI job; quarantined pre-execution.',
      source: 'falcon', type: 'detection', severity: 'high', detected_at: '2026-09-11T09:41:00Z', entity_id: ID.EP_DEV_SANDBOX, hostname: 'dev-sandbox-runner-03', user: 'runner', techniques: [], tactic: 'Malware',
      score: 22, reasons: ['isolated dev VM', 'no instance role', 'no data path', 'no TI'],
      flat: falconFlat({ host: 'dev-sandbox-runner-03', sev: 'High', tactic: 'Malware', technique: 'Malicious File', user: 'runner', file: 'eicar.com', cmdline: '/bin/sh -c "curl -o /tmp/eicar.com https://secure.eicar.org/eicar.com"', ip: '10.44.7.21', platform: 'Linux', ts: '2026-09-11T09:41:00Z', objective: 'Falcon Detection Method', disposition: 'Quarantined', extra: { quarantined: true, file_hash_known: 'EICAR-Test-File' } }),
    },
    {
      id: ID.N002, title: 'S3 bucket allows public read', description: 'Bucket policy and ACL allow s3:GetObject to everyone.',
      source: 'cspm', type: 'issue', severity: 'critical', detected_at: '2026-09-11T06:00:00Z', entity_id: ID.MARKETING_BUCKET, hostname: undefined, techniques: [], tactic: 'Exposure',
      score: 25, reasons: ['classification PUBLIC', 'no sensitive data', 'no actor interest', 'no privilege reach'],
      flat: { issue_id: 'iss-n002', control: 'S3 bucket allows public read access', severity: 'Critical', status: 'OPEN', resource: 'larkspur-marketing-assets', resource_type: 'S3 Bucket', account: '666666666666 (larkspur-corp-it)', region: 'us-east-1', first_seen: '2026-06-02T06:00:00Z', last_seen: '2026-09-11T06:00:00Z', evidence: 'Bucket policy Principal "*" allows s3:GetObject on arn:aws:s3:::larkspur-marketing-assets/*; static website hosting enabled', remediation: 'Block public access unless the bucket intentionally serves public content.', framework_mappings: ['CIS AWS 2.1.5', 'PCI DSS 1.3'] },
    },
    {
      id: ID.N003, title: 'PsExec service execution by admin', description: 'PSEXESVC installed on srv-fileshare-01 from WKS-2210 by mreyes.',
      source: 'falcon', type: 'detection', severity: 'medium', detected_at: '2026-09-11T01:12:00Z', entity_id: ID.EP_FILESHARE, hostname: 'srv-fileshare-01', user: 'CORP\\mreyes', techniques: ['T1569.002'], tactic: 'Execution',
      score: 31, reasons: ['inside approved change window CHG-2026-0911-014', "admin's own workstation as source", 'no regulated data path'], change_ticket: CHANGE_TICKET, status: 'benign',
      involves: [[ID.USER_MREYES, 'subject'], [ID.EP_MREYES, 'source']],
      flat: falconFlat({ host: 'srv-fileshare-01', sev: 'Medium', tactic: 'Execution', technique: 'System Services: Service Execution (T1569.002)', user: 'CORP\\mreyes', file: 'PSEXESVC.exe', cmdline: 'C:\\Windows\\PSEXESVC.exe', parent: 'services.exe', ip: '10.60.2.40', platform: 'Windows', ts: '2026-09-11T01:12:00Z', extra: { source_host: 'WKS-2210', source_ip: '10.41.8.12', change_ticket: CHANGE_TICKET } }),
    },
    {
      id: ID.N004, title: 'Impossible travel: London then New York within 46 minutes', description: 'pkaur signed in from London 07:02 UTC then from New York 07:48 UTC.',
      source: 'okta', type: 'identity', severity: 'medium', detected_at: '2026-09-11T07:48:00Z', entity_id: ID.USER_PKAUR, hostname: undefined, user: 'pkaur', techniques: ['T1078'], tactic: 'Initial Access',
      score: 24, reasons: ['second egress is the corporate VPN 198.51.100.200', 'MFA satisfied', 'no privileged cloud mapping'], status: 'benign',
      involves: [[ID.VPN_IP, 'source']],
      flat: { event_type: 'policy.evaluate_sign_on', outcome: 'ALLOW', risk_level: 'MEDIUM', risk_reasons: ['Anomalous Location', 'Velocity'], actor: 'pkaur@corp.larkspur.example', client: 'Safari 17 / macOS', first_login: { time: '2026-09-11T07:02:00Z', city: 'London', country: 'GB', ip: '203.0.113.120' }, second_login: { time: '2026-09-11T07:48:00Z', city: 'New York', country: 'US', ip: '198.51.100.200' }, mfa: 'Okta Verify push (satisfied)' },
    },
  ]
  named.forEach((a) => addAlert(g, a))
  g.edge(ID.N003, 'INVOLVES', ID.USER_MREYES, { role: 'subject' })

  // 12 quarantined attachments on random workstations
  const specs: AlertSpec[] = [...named]
  const depts = ['Engineering', 'Operations', 'Finance', 'Sales', 'Support', 'Compliance']
  for (let i = 5; i <= 16; i++) {
    const n = String(i).padStart(3, '0')
    const host = `WKS-${2000 + Math.floor(r() * 3000)}`
    const epId = `endpoint:falcon:aid-${host.toLowerCase()}`
    const login = `${pick(r, ['a', 'j', 'm', 'r', 's', 't'])}${pick(r, ['garcia', 'nguyen', 'patel', 'osei', 'kowalski', 'brennan', 'ito', 'haddad'])}${i}`
    g.node(epId, host, { hostname: host, device_type: 'workstation', os: 'Windows 11 23H2', os_family: 'windows', private_ip: `10.4${Math.floor(r() * 9)}.${Math.floor(r() * 250)}.${Math.floor(r() * 250)}`, site: pick(r, ['Boston office', 'Austin office', 'Remote']), primary_user_id: `user:okta:${login}`, containment_status: 'normal', department: pick(r, depts) })
    const ts = `2026-09-${String(9 + Math.floor(r() * 3)).padStart(2, '0')}T${String(Math.floor(r() * 24)).padStart(2, '0')}:${String(Math.floor(r() * 60)).padStart(2, '0')}:00Z`
    const fname = pick(r, ['Invoice_8812.zip', 'Payment_Advice.iso', 'Scan_0921.img', 'DHL_Shipment.js', 'Quote_Q3.one', 'Remit.lnk'])
    specs.push({
      id: `alert:falcon:ldt-n${n}`, title: 'Quarantined malicious attachment (blocked pre-execution)', description: `${fname} blocked before execution.`, source: 'falcon', type: 'detection', severity: 'low', detected_at: ts,
      entity_id: epId, hostname: host, user: `CORP\\${login}`, techniques: ['T1566.001'], tactic: 'Initial Access', score: 12 + Math.floor(r() * 7), reasons: ['blocked, no execution', 'workstation without privileged reach'],
      flat: falconFlat({ host, sev: 'Low', tactic: 'Initial Access', technique: 'Phishing: Spearphishing Attachment (T1566.001)', user: `CORP\\${login}`, file: fname, cmdline: '', ip: '10.40.0.0', platform: 'Windows', ts, disposition: 'Quarantined', objective: 'Falcon Detection Method' }),
    })
  }

  // IDS "exploit attempt" from the internal scanner
  const idsTargets = [ID.EDGE_VM, ID.FILESHARE_VM, ID.PARTNER_API_VM, ID.MFT_VM, ID.VPN_VM, ID.WIKI_VM, ID.BASTION_VM, ID.IVANTI_VM]
  const sigs = ['ET EXPLOIT Apache Struts OGNL', 'ET WEB_SERVER SQLi UNION SELECT', 'ET SCAN Nmap Scripting Engine', 'ET EXPLOIT Log4j JNDI probe', 'ET WEB_SPECIFIC_APPS Confluence OGNL', 'ET EXPLOIT SMB Trans2 overflow', 'ET SCAN Nikto', 'ET EXPLOIT Shellshock']
  for (let i = 1; i <= 8; i++) {
    const target = idsTargets[i - 1]
    const name = g.must(target).name
    const ts = `2026-09-11T${String(2 + i).padStart(2, '0')}:${String(Math.floor(r() * 60)).padStart(2, '0')}:00Z`
    specs.push({
      id: `alert:ids:ids-n1${String(i).padStart(2, '0')}`, title: `Exploit attempt: ${sigs[i - 1]}`, description: `Signature ${sigs[i - 1]} from 10.20.5.9 (vulnscan-01) to ${name}.`, source: 'ids', type: 'network', severity: i % 3 === 0 ? 'medium' : 'low', detected_at: ts,
      entity_id: target, hostname: name, techniques: ['T1046'], tactic: 'Discovery', score: 14 + Math.floor(r() * 10), reasons: ['source is the internal vulnerability scanner (tag)', 'authorised scan window'], status: 'benign',
      involves: [[ID.SCANNER_VM, 'source']],
      flat: { signature: sigs[i - 1], sid: 2024000 + i, classification: 'Attempted Administrator Privilege Gain', priority: i % 3 === 0 ? 2 : 3, src_ip: '10.20.5.9', src_port: 40000 + i, dst_ip: String(g.must(target).props.private_ip ?? '10.10.0.1'), dst_port: pick(r, [80, 443, 8080, 445]), proto: 'TCP', sensor: 'ids-sensor-prod-1', timestamp: ts, count: 1 + Math.floor(r() * 40) },
    })
  }

  // WAF scanner noise against patched hosts
  const wafHosts = [ID.PARTNER_API_VM, ID.MFT_VM, ID.WIKI_VM, ID.EDGE_VM, ID.VPN_VM, ID.STG_EDGE_VM]
  const rules = ['SQLi in query string', 'Path traversal ../../etc/passwd', 'PHP unit RCE probe', 'WordPress xmlrpc probe', 'Shellshock header', 'Generic JNDI probe']
  for (let i = 1; i <= 6; i++) {
    const target = wafHosts[i - 1]
    const name = g.must(target).name
    const ts = `2026-09-1${i % 2}T${String(Math.floor(r() * 24)).padStart(2, '0')}:${String(Math.floor(r() * 60)).padStart(2, '0')}:00Z`
    const ip = `203.0.113.${100 + Math.floor(r() * 150)}`
    specs.push({
      id: `alert:waf:waf-n${String(i).padStart(3, '0')}`, title: `${rules[i - 1]} (aggregated x${20 + Math.floor(r() * 300)})`, description: `Generic scanner pattern from ${ip} against ${name}; target is patched.`, source: 'waf', type: 'network', severity: i % 2 === 0 ? 'medium' : 'low', detected_at: ts,
      entity_id: target, hostname: name, techniques: ['T1595.002'], tactic: 'Reconnaissance', score: 16 + Math.floor(r() * 14), reasons: ['no matching vulnerability on target', 'source not in TI'],
      flat: { rule_id: `9${40 + i}100`, rule_group: rules[i - 1], action: 'BLOCK', severity: i % 2 === 0 ? 'Medium' : 'Low', client_ip: ip, host: `${name}.larkspur.example`, uri: pick(r, ['/', '/api/v1/health', '/wp-login.php', '/cgi-bin/test']), method: 'GET', timestamp: ts, aggregated_count: 20 + Math.floor(r() * 300) },
    })
  }

  // CSPM issues (with a couple of toxic combinations that legitimately score 60-78)
  const cspm: [string, string, Severity, string, number, string[]][] = [
    ['iss-c101', 'IAM access key older than 90 days', 'low', ID.CORP_IT_ADMIN_ROLE, 34, ['admin role but key unused for 120 days']],
    ['iss-c102', 'Security group allows SSH from 0.0.0.0/0 (dev)', 'medium', ID.DEV_LOG4J_VM, 38, ['dev account', 'no instance role']],
    ['iss-c103', 'EBS volume not encrypted', 'low', ID.SCANNER_VM, 12, ['internal scanner host', 'no sensitive data']],
    ['iss-c104', 'Internet-exposed VM with critical CVE and privileged instance role', 'high', ID.PARTNER_API_VM, 74, ['internet-exposed prod host', 'critical exploitable CVE', 'role can read statements-out (PII)']],
    ['iss-c105', 'Cross-account trust allows bastion role to assume data reader', 'medium', ID.PROD_READER_ROLE, 78, ['trust from shared-services bastion role', 'grants read on PCI vault', 'already abused in EMBERCAST']],
    ['iss-c106', 'Secret not rotated in 180 days', 'medium', ID.HSM_SECRET, 66, ['critical signing key', 'reachable from compromised role chain']],
    ['iss-c107', 'Public snapshot of database volume', 'high', ID.STG_CONFIG_BUCKET, 40, ['staging data only', 'no PCI/PII classification']],
    ['iss-c108', 'MFA not enforced for IAM user', 'medium', ID.ACC_DEV, 28, ['dev sandbox account']],
    ['iss-c109', 'Outdated AMI in use (>365 days)', 'low', ID.FILESHARE_VM, 21, ['corp fileshare', 'no regulated data path']],
    ['iss-c110', 'Over-permissive policy with wildcard resource', 'high', ID.EDGE_POLICY, 58, ['policy attached to internet-exposed workload role']],
  ]
  for (const [sid, title, sev, entity, score, reasons] of cspm) {
    const ent = g.must(entity)
    const ts = `2026-09-1${Math.floor(r() * 2)}T${String(Math.floor(r() * 24)).padStart(2, '0')}:00:00Z`
    specs.push({
      id: `alert:cspm:${sid}`, title, description: `${title} on ${ent.name}.`, source: 'cspm', type: 'issue', severity: sev, detected_at: ts, entity_id: entity, hostname: ent.label === 'VirtualMachine' ? ent.name : undefined,
      techniques: [], tactic: 'Posture', score, reasons, reaches_crown_jewel: score >= 66, on_attack_path: sid === 'iss-c105',
      flat: { issue_id: sid, control: title, severity: sev.charAt(0).toUpperCase() + sev.slice(1), status: 'OPEN', resource: ent.name, resource_type: ent.label, account: String(ent.props.account_id ?? 'n/a'), first_seen: '2026-08-15T00:00:00Z', last_seen: ts, remediation: 'See control documentation.' },
    })
  }

  // generic EDR detections on random endpoints
  const edr: [string, Severity, string, string, number][] = [
    ['Suspicious PowerShell download cradle in IT script', 'medium', 'T1059.001', 'Execution', 44],
    ['Potentially unwanted program: bundled toolbar', 'low', 'T1204.002', 'Execution', 11],
    ['Office macro spawned WScript', 'high', 'T1204.002', 'Execution', 52],
    ['LOLBin usage: certutil decode', 'medium', 'T1027', 'Defense Evasion', 47],
    ['Commodity infostealer quarantined', 'high', 'T1555', 'Credential Access', 61],
    ['Password spraying attempt against local accounts', 'medium', 'T1110.003', 'Credential Access', 39],
    ['Credential dumping technique observed (LSASS memory read)', 'medium', 'T1003.001', 'Credential Access', 57],
    ['Suspicious scheduled task created by script', 'medium', 'T1053.005', 'Persistence', 43],
    ['Mimikatz-like memory access pattern', 'high', 'T1003.001', 'Credential Access', 64],
    ['Browser credential store access by unsigned binary', 'medium', 'T1555.003', 'Credential Access', 49],
  ]
  edr.forEach(([title, sev, tech, tactic, score], i) => {
    const host = `WKS-${1100 + i * 37}`
    const epId = `endpoint:falcon:aid-${host.toLowerCase()}`
    const login = `${pick(r, ['k', 'l', 'n', 'o', 'p'])}${pick(r, ['adams', 'silva', 'moreau', 'yamada', 'okoro', 'lindqvist'])}`
    g.node(epId, host, { hostname: host, device_type: 'workstation', os: 'Windows 11 23H2', os_family: 'windows', private_ip: `10.4${i % 9}.${10 + i}.${50 + i}`, site: pick(r, ['Boston office', 'Austin office', 'Remote']), primary_user_id: `user:okta:${login}`, containment_status: 'normal' })
    const ts = `2026-09-1${i % 2}T${String((i * 3) % 24).padStart(2, '0')}:${String((i * 17) % 60).padStart(2, '0')}:00Z`
    specs.push({
      id: `alert:falcon:ldt-g${String(i + 1).padStart(3, '0')}`, title, description: `${title} on ${host}.`, source: 'falcon', type: 'detection', severity: sev, detected_at: ts, entity_id: epId, hostname: host, user: `CORP\\${login}`, techniques: [tech], tactic,
      score, reasons: score >= 55 ? ['true positive commodity malware', 'workstation without privileged reach'] : ['single host', 'no privileged reach', 'no TI'],
      flat: falconFlat({ host, sev: sev.charAt(0).toUpperCase() + sev.slice(1), tactic, technique: tech, user: `CORP\\${login}`, file: pick(r, ['powershell.exe', 'wscript.exe', 'certutil.exe', 'rundll32.exe', 'svchost.exe']), cmdline: '', ip: '10.40.0.0', platform: 'Windows', ts }),
    })
  })

  specs.filter((s) => !named.includes(s)).forEach((s) => addAlert(g, s))
  return specs
}
