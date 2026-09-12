/* eslint-disable */
/** Larkspur estate: accounts, VMs, roles, policies, data stores, people, teams, apps and endpoints. */
import type { MockGraph } from '../graph'
import { ID } from './ids'

export function buildEstate(g: MockGraph): void {
  // ---------------------------------------------------------------- accounts
  g.node(ID.ACC_PROD, 'larkspur-prod', { provider: 'aws', account_id: '111111111111', environment: 'prod', purpose: 'Wallet API, card issuing, statement rendering, cardholder data' })
  g.node(ID.ACC_SHARED, 'larkspur-shared-services', { provider: 'aws', account_id: '222222222222', environment: 'prod', purpose: 'Bastions, CI/CD, monitoring, VPN, artifact registry' })
  g.node(ID.ACC_STAGING, 'larkspur-staging', { provider: 'aws', account_id: '333333333333', environment: 'staging', purpose: 'Pre-production copies of prod services' })
  g.node(ID.ACC_DEV, 'larkspur-dev-sandbox', { provider: 'aws', account_id: '444444444444', environment: 'dev', purpose: 'Developer experiments, throwaway instances' })
  g.node(ID.ACC_CORP, 'larkspur-corp-it', { provider: 'aws', account_id: '666666666666', environment: 'corp', purpose: 'Corporate IT: marketing site, intranet tooling, Okta integrations' })
  g.node(ID.INTERNET, 'Internet', {})

  // ---------------------------------------------------------------- bastion chain (Campaign A)
  g.node(ID.BASTION_SUBNET, 'shared-mgmt-a', { provider: 'aws', account_id: '222222222222', cidr: '10.20.0.0/24', region: 'us-east-1', public: false })
  g.node(ID.BASTION_VM, 'bas-01', {
    provider: 'aws', account_id: '222222222222', region: 'us-east-1', hostname: 'bas-01.shared.larkspur.internal', private_ip: '10.20.0.15', public_ip: '198.51.100.10',
    os: 'Amazon Linux 2023', os_family: 'linux', instance_type: 't3.medium', environment: 'prod', exposure: 'internal', has_edr_sensor: true, is_k8s_node: false,
    tags: { role: 'bastion', owner: 'platform-eng', env: 'prod' }, criticality: 'tier-1', ti_exposure_score: 0.35, crown_jewel_reach: 3,
    ssh_ingress: 'restricted to VPN CIDR 10.99.0.0/16',
  })
  g.edge(ID.ACC_SHARED, 'CONTAINS', ID.BASTION_VM)
  g.edge(ID.BASTION_VM, 'IN_SUBNET', ID.BASTION_SUBNET)
  g.node(ID.BASTION_ROLE, 'LarkspurBastionSSMRole', {
    provider: 'aws', account_id: '222222222222', arn: 'arn:aws:iam::222222222222:role/LarkspurBastionSSMRole', role_type: 'instance', is_admin: false, privilege_score: 0.72,
    trust_principals: ['ec2.amazonaws.com'], last_used: '2026-09-10T02:24:15Z', environment: 'prod',
  })
  g.edge(ID.ACC_SHARED, 'CONTAINS', ID.BASTION_ROLE)
  g.edge(ID.BASTION_VM, 'HAS_ROLE', ID.BASTION_ROLE, { via: 'instance_profile' })
  g.node(ID.BASTION_ASSUME_POLICY, 'LarkspurBastionAssumeProdReader', { provider: 'aws', account_id: '222222222222', managed: false, access_levels: ['admin'], wildcard_resource: false, wildcard_action: false, statements: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::111111111111:role/LarkspurProdDataReader' }] })
  g.node(ID.BASTION_LOGS_POLICY, 'LarkspurSharedLogsWrite', { provider: 'aws', account_id: '222222222222', managed: false, access_levels: ['write'], wildcard_resource: false, wildcard_action: false })
  g.edge(ID.BASTION_ROLE, 'HAS_POLICY', ID.BASTION_ASSUME_POLICY, { attachment: 'inline' })
  g.edge(ID.BASTION_ROLE, 'HAS_POLICY', ID.BASTION_LOGS_POLICY, { attachment: 'managed' })
  g.node(ID.SHARED_LOGS_BUCKET, 'larkspur-shared-logs', { provider: 'aws', account_id: '222222222222', region: 'us-east-1', public: false, encrypted: true, versioning: false, data_classifications: ['INTERNAL'], sensitivity: 'low', crown_jewel: false, size_gb: 820, environment: 'prod' })
  g.edge(ID.BASTION_LOGS_POLICY, 'GRANTS', ID.SHARED_LOGS_BUCKET, { actions: ['s3:PutObject'], access_level: 'write', resource_pattern: 'arn:aws:s3:::larkspur-shared-logs/*' })
  g.edge(ID.BASTION_ROLE, 'CAN_ACCESS', ID.SHARED_LOGS_BUCKET, { access_level: 'write', path_length: 2, via: ID.BASTION_LOGS_POLICY, transitive: false })

  g.node(ID.PROD_READER_ROLE, 'LarkspurProdDataReader', {
    provider: 'aws', account_id: '111111111111', arn: 'arn:aws:iam::111111111111:role/LarkspurProdDataReader', role_type: 'cross-account', is_admin: false, privilege_score: 0.9,
    trust_principals: ['arn:aws:iam::222222222222:role/LarkspurBastionSSMRole'], last_used: '2026-09-10T03:41:40Z', environment: 'prod',
  })
  g.edge(ID.ACC_PROD, 'CONTAINS', ID.PROD_READER_ROLE)
  g.edge(ID.BASTION_ASSUME_POLICY, 'GRANTS', ID.PROD_READER_ROLE, { actions: ['sts:AssumeRole'], access_level: 'admin', resource_pattern: 'arn:aws:iam::111111111111:role/LarkspurProdDataReader' })
  g.edge(ID.BASTION_ROLE, 'CAN_ASSUME', ID.PROD_READER_ROLE, { via: 'trust_policy', cross_account: true })
  g.node(ID.PROD_READER_POLICY, 'LarkspurProdDataReaderAccess', {
    provider: 'aws', account_id: '111111111111', managed: false, access_levels: ['read', 'list'], wildcard_resource: false, wildcard_action: false,
    statements: [
      { Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: ['arn:aws:s3:::larkspur-cardholder-vault/*', 'arn:aws:s3:::larkspur-kyc-documents/*'] },
      { Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: ['arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/cardholder-db/reader', 'arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/hsm/partner-signing-key'] },
      { Effect: 'Allow', Action: 'rds:DescribeDBInstances', Resource: '*' },
    ],
  })
  g.edge(ID.PROD_READER_ROLE, 'HAS_POLICY', ID.PROD_READER_POLICY, { attachment: 'inline' })

  g.node(ID.CARDHOLDER_VAULT, 'larkspur-cardholder-vault', { provider: 'aws', account_id: '111111111111', region: 'us-east-1', public: false, encrypted: true, versioning: true, data_classifications: ['PCI'], sensitivity: 'critical', crown_jewel: true, size_gb: 4100, environment: 'prod' })
  g.node(ID.KYC_DOCS, 'larkspur-kyc-documents', { provider: 'aws', account_id: '111111111111', region: 'us-east-1', public: false, encrypted: true, versioning: true, data_classifications: ['PII'], sensitivity: 'high', crown_jewel: true, size_gb: 960, environment: 'prod' })
  g.node(ID.DB_READER_SECRET, 'prod/cardholder-db/reader', { provider: 'aws', account_id: '111111111111', secret_type: 'db_credentials', sensitivity: 'high', rotated_days_ago: 41, grants_access_to: [ID.CARDHOLDER_DB] })
  g.node(ID.HSM_SECRET, 'prod/hsm/partner-signing-key', { provider: 'aws', account_id: '111111111111', secret_type: 'signing_key', sensitivity: 'critical', rotated_days_ago: 210, grants_access_to: [] })
  g.node(ID.CARDHOLDER_DB, 'cardholder-db', { provider: 'aws', account_id: '111111111111', engine: 'postgres 15 (RDS)', public: false, encrypted: true, data_classifications: ['PCI'], sensitivity: 'critical', crown_jewel: true, environment: 'prod', exposure: 'internal' })
  for (const t of [ID.CARDHOLDER_VAULT, ID.KYC_DOCS, ID.DB_READER_SECRET, ID.HSM_SECRET, ID.CARDHOLDER_DB]) g.edge(ID.ACC_PROD, 'CONTAINS', t)
  g.edge(ID.PROD_READER_POLICY, 'GRANTS', ID.CARDHOLDER_VAULT, { actions: ['s3:GetObject', 's3:ListBucket'], access_level: 'read', resource_pattern: 'arn:aws:s3:::larkspur-cardholder-vault/*' })
  g.edge(ID.PROD_READER_POLICY, 'GRANTS', ID.KYC_DOCS, { actions: ['s3:GetObject', 's3:ListBucket'], access_level: 'read', resource_pattern: 'arn:aws:s3:::larkspur-kyc-documents/*' })
  g.edge(ID.PROD_READER_POLICY, 'GRANTS', ID.DB_READER_SECRET, { actions: ['secretsmanager:GetSecretValue'], access_level: 'read', resource_pattern: 'prod/cardholder-db/reader' })
  g.edge(ID.PROD_READER_POLICY, 'GRANTS', ID.HSM_SECRET, { actions: ['secretsmanager:GetSecretValue'], access_level: 'read', resource_pattern: 'prod/hsm/partner-signing-key' })
  for (const t of [ID.CARDHOLDER_VAULT, ID.KYC_DOCS, ID.DB_READER_SECRET, ID.HSM_SECRET]) {
    g.edge(ID.PROD_READER_ROLE, 'CAN_ACCESS', t, { access_level: 'read', path_length: 2, via: ID.PROD_READER_POLICY, transitive: false })
    g.edge(ID.BASTION_ROLE, 'CAN_ACCESS', t, { access_level: 'read', path_length: 4, via: `${ID.BASTION_ASSUME_POLICY},${ID.PROD_READER_ROLE},${ID.PROD_READER_POLICY}`, transitive: true }, 0.95)
  }
  g.edge(ID.DB_READER_SECRET, 'UNLOCKS', ID.CARDHOLDER_DB, { credential_type: 'db_credentials' })

  // ---------------------------------------------------------------- statement-render chain (Campaign B)
  g.node(ID.EDGE_SG, 'sg-0edge-public-8080', { provider: 'aws', account_id: '111111111111', open_to_internet: true, internet_ports: ['8080'], inbound_rules: [{ cidr: '0.0.0.0/0', port_from: 8080, port_to: 8080, protocol: 'tcp' }] })
  g.node(ID.EDGE_VM, 'stmt-render-2a', {
    provider: 'aws', account_id: '111111111111', region: 'us-east-1', hostname: 'stmt-render-2a.prod.larkspur.internal', private_ip: '10.10.3.24', public_ip: '198.51.100.24',
    os: 'Ubuntu 22.04', os_family: 'linux', instance_type: 'c6i.large', environment: 'prod', exposure: 'internet', has_edr_sensor: true, is_k8s_node: false,
    tags: { app: 'statement-render', owner: 'payments-platform', env: 'prod' }, criticality: 'tier-1', ti_exposure_score: 0.93, crown_jewel_reach: 1,
  })
  g.edge(ID.ACC_PROD, 'CONTAINS', ID.EDGE_VM)
  g.edge(ID.EDGE_VM, 'HAS_SECURITY_GROUP', ID.EDGE_SG)
  g.edge(ID.INTERNET, 'EXPOSES', ID.EDGE_VM, { ports: ['8080'], via: 'security_group', protocol: 'tcp' })
  g.node(ID.EDGE_ROLE, 'LarkspurStmtRenderRole', { provider: 'aws', account_id: '111111111111', arn: 'arn:aws:iam::111111111111:role/LarkspurStmtRenderRole', role_type: 'instance', is_admin: false, privilege_score: 0.55, trust_principals: ['ec2.amazonaws.com'], last_used: '2026-09-11T13:40:00Z', environment: 'prod' })
  g.edge(ID.EDGE_VM, 'HAS_ROLE', ID.EDGE_ROLE, { via: 'instance_profile' })
  g.node(ID.EDGE_POLICY, 'LarkspurStmtRenderAccess', { provider: 'aws', account_id: '111111111111', managed: false, access_levels: ['read', 'write'], wildcard_resource: false, wildcard_action: false })
  g.edge(ID.EDGE_ROLE, 'HAS_POLICY', ID.EDGE_POLICY, { attachment: 'inline' })
  g.node(ID.APP_CONFIG_BUCKET, 'larkspur-prod-app-config', { provider: 'aws', account_id: '111111111111', region: 'us-east-1', public: false, encrypted: true, versioning: true, data_classifications: ['SECRETS'], sensitivity: 'high', crown_jewel: false, size_gb: 0.4, environment: 'prod', contains_credentials_for: [ID.CARDHOLDER_DB], notable_objects: ['db-connection.yaml'] })
  g.node(ID.STATEMENTS_OUT_BUCKET, 'larkspur-statements-out', { provider: 'aws', account_id: '111111111111', region: 'us-east-1', public: false, encrypted: true, versioning: false, data_classifications: ['PII', 'FINANCIAL'], sensitivity: 'medium', crown_jewel: false, size_gb: 310, environment: 'prod' })
  g.edge(ID.EDGE_POLICY, 'GRANTS', ID.APP_CONFIG_BUCKET, { actions: ['s3:GetObject'], access_level: 'read', resource_pattern: 'arn:aws:s3:::larkspur-prod-app-config/*' })
  g.edge(ID.EDGE_POLICY, 'GRANTS', ID.STATEMENTS_OUT_BUCKET, { actions: ['s3:PutObject'], access_level: 'write', resource_pattern: 'arn:aws:s3:::larkspur-statements-out/*' })
  g.edge(ID.EDGE_ROLE, 'CAN_ACCESS', ID.APP_CONFIG_BUCKET, { access_level: 'read', path_length: 2, via: ID.EDGE_POLICY, transitive: false })
  g.edge(ID.EDGE_ROLE, 'CAN_ACCESS', ID.STATEMENTS_OUT_BUCKET, { access_level: 'write', path_length: 2, via: ID.EDGE_POLICY, transitive: false })
  g.edge(ID.APP_CONFIG_BUCKET, 'UNLOCKS', ID.CARDHOLDER_DB, { credential_type: 'db_credentials' }, 0.9)
  g.node(ID.EDGE_IMAGE, 'larkspur/statement-render:3.8.1', { registry: 'ecr', repository: 'larkspur/statement-render', tag: '3.8.1', digest: 'sha256:5f1c…9a2e', vuln_count_critical: 1, vuln_count_high: 4 })
  g.edge(ID.EDGE_VM, 'RUNS_IMAGE', ID.EDGE_IMAGE)
  g.node(ID.EDGE_LOG4J_PACKAGE, 'log4j-core 2.14.1', { package_name: 'log4j-core', version: '2.14.1', ecosystem: 'maven', scope: 'i-0edge2a7f19c4b3e88' })
  g.edge(ID.EDGE_VM, 'HAS_PACKAGE', ID.EDGE_LOG4J_PACKAGE)
  g.edge(ID.EDGE_IMAGE, 'HAS_PACKAGE', ID.EDGE_LOG4J_PACKAGE)

  // other Log4Shell hosts with less context
  g.node(ID.STG_EDGE_VM, 'stmt-render-stg-1', { provider: 'aws', account_id: '333333333333', region: 'us-east-1', hostname: 'stmt-render-stg-1.staging.larkspur.internal', private_ip: '10.30.3.11', public_ip: '198.51.100.31', os: 'Ubuntu 22.04', os_family: 'linux', environment: 'staging', exposure: 'internet', has_edr_sensor: true, criticality: 'tier-2', ti_exposure_score: 0.62, crown_jewel_reach: 0 })
  g.edge(ID.ACC_STAGING, 'CONTAINS', ID.STG_EDGE_VM)
  g.edge(ID.INTERNET, 'EXPOSES', ID.STG_EDGE_VM, { ports: ['8080'], via: 'security_group', protocol: 'tcp' })
  g.node(ID.STG_EDGE_ROLE, 'LarkspurStgStmtRenderRole', { provider: 'aws', account_id: '333333333333', role_type: 'instance', is_admin: false, privilege_score: 0.2, environment: 'staging' })
  g.edge(ID.STG_EDGE_VM, 'HAS_ROLE', ID.STG_EDGE_ROLE, { via: 'instance_profile' })
  g.node(ID.STG_CONFIG_BUCKET, 'larkspur-stg-app-config', { provider: 'aws', account_id: '333333333333', public: false, encrypted: true, data_classifications: ['INTERNAL'], sensitivity: 'low', crown_jewel: false, environment: 'staging' })
  g.edge(ID.STG_EDGE_ROLE, 'CAN_ACCESS', ID.STG_CONFIG_BUCKET, { access_level: 'read', path_length: 2, transitive: false })
  g.node(ID.DEV_LOG4J_VM, 'log4j-testbed', { provider: 'aws', account_id: '444444444444', region: 'us-east-1', hostname: 'log4j-testbed.dev.larkspur.internal', private_ip: '10.44.1.9', public_ip: '198.51.100.44', os: 'Ubuntu 20.04', os_family: 'linux', environment: 'dev', exposure: 'internet', has_edr_sensor: false, criticality: 'tier-3', ti_exposure_score: 0.4, crown_jewel_reach: 0 })
  g.edge(ID.ACC_DEV, 'CONTAINS', ID.DEV_LOG4J_VM)
  g.edge(ID.INTERNET, 'EXPOSES', ID.DEV_LOG4J_VM, { ports: ['8080'], via: 'security_group', protocol: 'tcp' })

  // five more internet-exposed hosts with other exploited CVEs (question 5)
  const others: [string, string, string, string, string, boolean, string][] = [
    [ID.VPN_VM, 'vpn-gw-01', '222222222222', 'prod', '198.51.100.12', false, 'tier-1'],
    [ID.WIKI_VM, 'confluence-01', '666666666666', 'corp', '198.51.100.60', true, 'tier-2'],
    [ID.IVANTI_VM, 'ivanti-ics-01', '222222222222', 'prod', '198.51.100.13', false, 'tier-1'],
    [ID.PARTNER_API_VM, 'partner-api-gw-01', '111111111111', 'prod', '198.51.100.25', true, 'tier-1'],
    [ID.MFT_VM, 'mft-01', '111111111111', 'prod', '198.51.100.26', true, 'tier-1'],
  ]
  for (const [id, name, acct, env, pip, sensor, crit] of others) {
    g.node(id, name, { provider: 'aws', account_id: acct, region: 'us-east-1', hostname: `${name}.${env}.larkspur.internal`, public_ip: pip, os: 'Linux', os_family: 'linux', environment: env, exposure: 'internet', has_edr_sensor: sensor, criticality: crit, ti_exposure_score: 0.5, crown_jewel_reach: 0 })
    g.edge(`account:aws:${acct}`, 'CONTAINS', id)
    g.edge(ID.INTERNET, 'EXPOSES', id, { ports: ['443'], via: 'security_group', protocol: 'tcp' })
  }

  // ---------------------------------------------------------------- noise resources
  g.node(ID.MARKETING_BUCKET, 'larkspur-marketing-assets', { provider: 'aws', account_id: '666666666666', region: 'us-east-1', public: true, encrypted: false, versioning: false, data_classifications: ['PUBLIC'], sensitivity: 'none', crown_jewel: false, size_gb: 12, environment: 'corp', website_hosting: true })
  g.edge(ID.ACC_CORP, 'CONTAINS', ID.MARKETING_BUCKET)
  g.edge(ID.INTERNET, 'EXPOSES', ID.MARKETING_BUCKET, { via: 'public_acl', protocol: 'https' })
  g.node(ID.DEV_SANDBOX_VM, 'dev-sandbox-runner-03', { provider: 'aws', account_id: '444444444444', region: 'us-east-1', hostname: 'dev-sandbox-runner-03.dev.larkspur.internal', private_ip: '10.44.7.21', os: 'Ubuntu 22.04', os_family: 'linux', environment: 'dev', exposure: 'isolated', has_edr_sensor: true, criticality: 'tier-3', ti_exposure_score: 0, crown_jewel_reach: 0 })
  g.edge(ID.ACC_DEV, 'CONTAINS', ID.DEV_SANDBOX_VM)
  g.node(ID.SCANNER_VM, 'vulnscan-01', { provider: 'aws', account_id: '222222222222', region: 'us-east-1', private_ip: '10.20.5.9', os: 'Ubuntu 22.04', os_family: 'linux', environment: 'prod', exposure: 'internal', has_edr_sensor: true, tags: { role: 'vulnerability-scanner' }, criticality: 'tier-2' })
  g.edge(ID.ACC_SHARED, 'CONTAINS', ID.SCANNER_VM)
  g.node(ID.FILESHARE_VM, 'srv-fileshare-01', { provider: 'aws', account_id: '666666666666', region: 'us-east-1', hostname: 'srv-fileshare-01.corp.larkspur.internal', private_ip: '10.60.2.40', os: 'Windows Server 2022', os_family: 'windows', environment: 'corp', exposure: 'internal', has_edr_sensor: true, criticality: 'tier-2', crown_jewel_reach: 0 })
  g.edge(ID.ACC_CORP, 'CONTAINS', ID.FILESHARE_VM)

  // ---------------------------------------------------------------- business context
  g.node(ID.TEAM_PLATFORM, 'Platform Engineering', { department: 'Engineering', lead_user_id: ID.USER_JOKAFOR, oncall_channel: '#oncall-platform' })
  g.node(ID.TEAM_PAYMENTS, 'Payments Platform', { department: 'Engineering', lead_user_id: ID.USER_LCHEN, oncall_channel: '#oncall-payments' })
  g.node(ID.TEAM_TREASURY, 'Finance Treasury', { department: 'Finance', oncall_channel: '#finance-treasury' })
  g.node(ID.TEAM_CORP_IT, 'Corporate IT', { department: 'IT', oncall_channel: '#corp-it-helpdesk' })
  g.node(ID.APP_CARD_ISSUING, 'card-issuing', { criticality: 'tier-0', environment: 'prod', owner_team_id: ID.TEAM_PAYMENTS, description: 'Card issuing and cardholder data platform', data_classifications: ['PCI', 'PII'] })
  g.node(ID.APP_STMT_RENDER, 'statement-render', { criticality: 'tier-1', environment: 'prod', owner_team_id: ID.TEAM_PAYMENTS, description: 'Monthly statement rendering (Java)', data_classifications: ['PII', 'FINANCIAL'] })
  g.node(ID.APP_MARKETING, 'marketing-site', { criticality: 'tier-3', environment: 'corp', owner_team_id: ID.TEAM_CORP_IT, description: 'Public marketing website assets', data_classifications: ['PUBLIC'] })
  g.node(ID.APP_SETTLEMENT_SFTP, 'settlement-sftp', { criticality: 'tier-2', environment: 'prod', owner_team_id: ID.TEAM_TREASURY, description: 'Settlement-file SFTP pickup through the bastion', data_classifications: ['FINANCIAL'] })
  g.edge(ID.CARDHOLDER_VAULT, 'PART_OF', ID.APP_CARD_ISSUING)
  g.edge(ID.CARDHOLDER_DB, 'PART_OF', ID.APP_CARD_ISSUING)
  g.edge(ID.KYC_DOCS, 'PART_OF', ID.APP_CARD_ISSUING)
  g.edge(ID.EDGE_VM, 'PART_OF', ID.APP_STMT_RENDER)
  g.edge(ID.EDGE_ROLE, 'PART_OF', ID.APP_STMT_RENDER)
  g.edge(ID.MARKETING_BUCKET, 'PART_OF', ID.APP_MARKETING)
  g.edge(ID.BASTION_VM, 'PART_OF', ID.APP_SETTLEMENT_SFTP)
  g.edge(ID.APP_CARD_ISSUING, 'OWNED_BY', ID.TEAM_PAYMENTS)
  g.edge(ID.APP_STMT_RENDER, 'OWNED_BY', ID.TEAM_PAYMENTS)
  g.edge(ID.APP_MARKETING, 'OWNED_BY', ID.TEAM_CORP_IT)
  g.edge(ID.APP_SETTLEMENT_SFTP, 'OWNED_BY', ID.TEAM_TREASURY)
  g.edge(ID.BASTION_VM, 'OWNED_BY', ID.TEAM_PLATFORM)
  g.edge(ID.APP_SETTLEMENT_SFTP, 'DEPENDS_ON', ID.BASTION_VM, { dependency_type: 'sftp_jump_host' })
  g.edge(ID.APP_STMT_RENDER, 'DEPENDS_ON', ID.APP_CONFIG_BUCKET, { dependency_type: 'configuration' })
  g.edge(ID.APP_STMT_RENDER, 'DEPENDS_ON', ID.CARDHOLDER_DB, { dependency_type: 'database' })

  // ---------------------------------------------------------------- people
  g.node(ID.USER_DANA, 'Dana Whitfield', { email: 'dwhitfield@corp.larkspur.example', display_name: 'Dana Whitfield', title: 'Treasury Operations Analyst', department: 'Finance', team_id: ID.TEAM_TREASURY, location: 'Boston', is_privileged: false, is_executive: false, mfa_enabled: true, status: 'active' })
  g.node(ID.USER_MREYES, 'Marcus Reyes', { email: 'mreyes@corp.larkspur.example', display_name: 'Marcus Reyes', title: 'IT Systems Administrator', department: 'IT', team_id: ID.TEAM_CORP_IT, location: 'Austin', is_privileged: true, is_executive: false, mfa_enabled: true, status: 'active' })
  g.node(ID.USER_PKAUR, 'Priya Kaur', { email: 'pkaur@corp.larkspur.example', display_name: 'Priya Kaur', title: 'Chief Financial Officer', department: 'Executive', location: 'New York', is_privileged: false, is_executive: true, mfa_enabled: true, status: 'active' })
  g.node(ID.USER_JOKAFOR, 'Jide Okafor', { email: 'jokafor@corp.larkspur.example', display_name: 'Jide Okafor', title: 'Platform Engineering Lead', department: 'Engineering', team_id: ID.TEAM_PLATFORM, location: 'Boston', is_privileged: true, is_executive: false, mfa_enabled: true, status: 'active' })
  g.node(ID.USER_LCHEN, 'Lin Chen', { email: 'lchen@corp.larkspur.example', display_name: 'Lin Chen', title: 'Staff Engineer, Payments Platform', department: 'Engineering', team_id: ID.TEAM_PAYMENTS, location: 'Seattle', is_privileged: true, is_executive: false, mfa_enabled: true, status: 'active' })
  g.node(ID.SVC_FINOPS_SFTP, 'svc-finops-sftp', { system: 'linux', host_id: ID.BASTION_VM, purpose: 'Settlement-file SFTP pickup', privileged: false, authorized_keys: ['dwhitfield id_ed25519'] })
  g.node(ID.GROUP_TREASURY, 'finance-treasury', { description: 'Treasury operations staff', member_count: 14, privileged: false })
  g.node(ID.GROUP_ALL, 'all-employees', { description: 'Every active employee', member_count: 1400, privileged: false })
  g.node(ID.CORP_IT_ADMIN_ROLE, 'LarkspurCorpItAdmin', { provider: 'aws', account_id: '666666666666', role_type: 'sso', is_admin: true, privilege_score: 0.8, environment: 'corp' })
  g.edge(ID.ACC_CORP, 'CONTAINS', ID.CORP_IT_ADMIN_ROLE)
  g.edge(ID.USER_DANA, 'MEMBER_OF', ID.GROUP_TREASURY)
  g.edge(ID.USER_DANA, 'MEMBER_OF', ID.GROUP_ALL)
  g.edge(ID.USER_DANA, 'MEMBER_OF', ID.TEAM_TREASURY)
  g.edge(ID.USER_MREYES, 'MEMBER_OF', ID.TEAM_CORP_IT)
  g.edge(ID.USER_MREYES, 'MAPS_TO', ID.CORP_IT_ADMIN_ROLE, { via: 'sso' })
  g.edge(ID.USER_JOKAFOR, 'LEADS', ID.TEAM_PLATFORM)
  g.edge(ID.USER_LCHEN, 'LEADS', ID.TEAM_PAYMENTS)

  // ---------------------------------------------------------------- endpoints and entity resolution
  g.node(ID.WKS_DANA, 'WKS-3391', { hostname: 'WKS-3391', device_type: 'workstation', os: 'Windows 11 23H2', os_family: 'windows', private_ip: '10.40.12.77', site: 'Boston office', sensor_version: '7.18.19507', last_seen_sensor: '2026-09-11T13:58:00Z', primary_user_id: ID.USER_DANA, containment_status: 'normal', ou: 'OU=Finance,DC=corp,DC=larkspur' })
  g.node(ID.EP_BASTION, 'bas-01', { hostname: 'bas-01', device_type: 'server', os: 'Amazon Linux 2023', os_family: 'linux', private_ip: '10.20.0.15', site: 'aws:us-east-1', sensor_version: '7.18.19507', last_seen_sensor: '2026-09-11T13:59:00Z', cloud_provider: 'aws', cloud_instance_id: 'i-0b4571e2c9a8f3d01', cloud_account_id: '222222222222', containment_status: 'normal' })
  g.node(ID.EP_EDGE, 'stmt-render-2a', { hostname: 'stmt-render-2a', device_type: 'server', os: 'Ubuntu 22.04', os_family: 'linux', private_ip: '10.10.3.24', site: 'aws:us-east-1', sensor_version: '7.18.19507', last_seen_sensor: '2026-09-11T13:59:00Z', cloud_provider: 'aws', cloud_instance_id: 'i-0edge2a7f19c4b3e88', cloud_account_id: '111111111111', containment_status: 'normal' })
  g.node(ID.EP_DEV_SANDBOX, 'dev-sandbox-runner-03', { hostname: 'dev-sandbox-runner-03', device_type: 'server', os: 'Ubuntu 22.04', os_family: 'linux', private_ip: '10.44.7.21', site: 'aws:us-east-1', cloud_provider: 'aws', cloud_instance_id: 'i-0dev7c1a2b3c4d5e6f', cloud_account_id: '444444444444', containment_status: 'normal' })
  g.node(ID.EP_FILESHARE, 'srv-fileshare-01', { hostname: 'srv-fileshare-01', device_type: 'server', os: 'Windows Server 2022', os_family: 'windows', private_ip: '10.60.2.40', site: 'aws:us-east-1', cloud_provider: 'aws', cloud_instance_id: 'i-0file1a2b3c4d5e6f7', cloud_account_id: '666666666666', containment_status: 'normal' })
  g.node(ID.EP_MREYES, 'WKS-2210', { hostname: 'WKS-2210', device_type: 'workstation', os: 'Windows 11 23H2', os_family: 'windows', private_ip: '10.41.8.12', site: 'Austin office', primary_user_id: ID.USER_MREYES, containment_status: 'normal' })
  g.node(ID.EP_PKAUR, 'WKS-1042', { hostname: 'WKS-1042', device_type: 'workstation', os: 'macOS 15.1', os_family: 'macos', private_ip: '10.42.3.5', site: 'New York office', primary_user_id: ID.USER_PKAUR, containment_status: 'normal' })
  g.edge(ID.EP_BASTION, 'SAME_AS', ID.BASTION_VM, { method: 'instance_id' }, 0.99)
  g.edge(ID.EP_EDGE, 'SAME_AS', ID.EDGE_VM, { method: 'instance_id' }, 0.99)
  g.edge(ID.EP_DEV_SANDBOX, 'SAME_AS', ID.DEV_SANDBOX_VM, { method: 'instance_id' }, 0.99)
  g.edge(ID.EP_FILESHARE, 'SAME_AS', ID.FILESHARE_VM, { method: 'hostname_ip' }, 0.9)
  g.edge(ID.WKS_DANA, 'PRIMARY_USER', ID.USER_DANA)
  g.edge(ID.EP_MREYES, 'PRIMARY_USER', ID.USER_MREYES)
  g.edge(ID.EP_PKAUR, 'PRIMARY_USER', ID.USER_PKAUR)
  g.edge(ID.SVC_FINOPS_SFTP, 'LOGGED_ON', ID.EP_BASTION, { logon_type: 'ssh', logon_time: '2026-09-10T02:05:17Z', source_ip: '10.40.12.77', session_id: 'ssh-7f21' })
  g.edge(ID.USER_DANA, 'LOGGED_ON', ID.WKS_DANA, { logon_type: 'interactive', logon_time: '2026-09-09T08:31:02Z', source_ip: '10.40.12.77' })
}
