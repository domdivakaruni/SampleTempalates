"""Identity and access: IAM roles, users, policies, access keys, SSO mappings, trust policies (CAN_ASSUME) and
local service accounts. The storyline roles/policies (bastion -> prod reader, statement-render, corp IT admin)
are created with their exact ids; everything else is derived from the service placement in ``cloud.py``.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from throughline.simulator import storyline_constants as sc
from throughline.simulator.common import rng
from throughline.simulator.inventory._base import (
    SOURCE_FALCON,
    SOURCE_OKTA,
    SOURCE_WIZ,
    Inventory,
    days_ago,
    hexid,
    minutes_ago,
)
from throughline.simulator.inventory.business import APP_BY_SLUG, AppSpec
from throughline.simulator.inventory.cloud import ACCOUNT_ENV, ACCOUNT_ID, PROVIDER, Estate
from throughline.simulator.inventory.world import World

ACCOUNT_BY_ID: dict[str, str] = {v: k for k, v in ACCOUNT_ID.items()}
SENSITIVE = ("high", "critical")

# AWS-managed policies: name -> (access_levels, account-level grant (level, scope labels) or None, statement actions)
MANAGED: dict[str, tuple[list[str], tuple[str, list[str]] | None, list[str]]] = {
    "AmazonSSMManagedInstanceCore": (["read", "write"], None, ["ssm:UpdateInstanceInformation", "ssmmessages:*", "ec2messages:*"]),
    "CloudWatchAgentServerPolicy": (["write"], None, ["cloudwatch:PutMetricData", "logs:PutLogEvents", "logs:CreateLogStream"]),
    "AmazonEKSWorkerNodePolicy": (["read"], None, ["ec2:Describe*", "eks:DescribeCluster"]),
    "AmazonEKS_CNI_Policy": (["write"], None, ["ec2:AssignPrivateIpAddresses", "ec2:AttachNetworkInterface"]),
    "AmazonEC2ContainerRegistryReadOnly": (["read"], None, ["ecr:GetAuthorizationToken", "ecr:BatchGetImage"]),
    "AmazonEKSClusterPolicy": (["write"], None, ["ec2:*", "elasticloadbalancing:*"]),
    "AWSLambdaBasicExecutionRole": (["write"], None, ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]),
    "AWSLambdaVPCAccessExecutionRole": (["write"], None, ["ec2:CreateNetworkInterface", "logs:PutLogEvents"]),
    "AdministratorAccess": (["admin"], ("admin", ["StorageBucket", "Database", "Secret"]), ["*"]),
    "PowerUserAccess": (["write", "read", "list"], ("write", ["StorageBucket", "Database", "Secret"]), ["NotAction:iam:*,organizations:*"]),
    "ReadOnlyAccess": (["read", "list"], ("read", ["StorageBucket", "Database", "Secret"]), ["*:Get*", "*:List*", "*:Describe*"]),
    "SecurityAudit": (["list"], ("list", ["StorageBucket", "Database", "Secret"]), ["*:Describe*", "*:List*", "iam:GenerateCredentialReport"]),
    "ViewOnlyAccess": (["list"], ("list", ["StorageBucket", "Database", "Secret"]), ["*:List*", "*:Describe*"]),
    "AmazonS3ReadOnlyAccess": (["read", "list"], ("read", ["StorageBucket"]), ["s3:Get*", "s3:List*"]),
    "AmazonS3FullAccess": (["admin"], ("admin", ["StorageBucket"]), ["s3:*"]),
    "SecretsManagerReadWrite": (["read", "write"], ("write", ["Secret"]), ["secretsmanager:*"]),
    "AmazonRDSFullAccess": (["admin"], ("admin", ["Database"]), ["rds:*"]),
    "AmazonRDSReadOnlyAccess": (["list"], ("list", ["Database"]), ["rds:Describe*"]),
    "AWSBackupServiceRolePolicyForBackup": (["read"], ("read", ["StorageBucket", "Database"]), ["backup:*", "s3:GetObject", "rds:CreateDBSnapshot"]),
}

SERVICE_LINKED = ["AWSServiceRoleForAutoScaling", "AWSServiceRoleForRDS", "AWSServiceRoleForAmazonEKS", "AWSServiceRoleForSupport", "AWSServiceRoleForTrustedAdvisor", "AWSServiceRoleForElasticLoadBalancing", "AWSServiceRoleForAmazonGuardDuty"]

# static IAM users per account: (name, console, mfa, admin, policies, key count)
IAM_USERS: dict[str, list[tuple[str, bool, bool, bool, list[str], int]]] = {
    "prod": [("svc-legacy-etl", False, False, False, ["AmazonS3ReadOnlyAccess"], 2), ("breakglass-admin", True, True, True, ["AdministratorAccess"], 1), ("svc-payment-network-poller", False, False, False, [], 1),
             ("datadog-integration", False, False, False, ["ReadOnlyAccess"], 1), ("svc-statements-sftp-push", False, False, False, [], 2), ("svc-hsm-attestation", False, False, False, [], 1), ("wiz-connector", False, False, False, ["SecurityAudit", "ReadOnlyAccess"], 1), ("svc-kms-rotation-legacy", False, False, False, [], 1)],
    "shared": [("svc-ci-legacy", False, False, False, ["PowerUserAccess"], 2), ("terraform-cloud", False, False, False, ["AdministratorAccess"], 1), ("github-actions-legacy", False, False, False, ["AmazonS3FullAccess"], 2), ("pagerduty-events", False, False, False, [], 1),
               ("svc-backup-agent", False, False, False, ["AWSBackupServiceRolePolicyForBackup"], 1), ("svc-artifact-sync", False, False, False, ["AmazonS3FullAccess"], 2), ("svc-vulnscan-cloud", False, False, False, ["ReadOnlyAccess"], 1), ("svc-loki-s3", False, False, False, [], 1),
               ("svc-grafana-cloudwatch", False, False, False, ["ReadOnlyAccess"], 1), ("jokafor-cli", True, True, False, ["PowerUserAccess"], 1), ("svc-vault-kms", False, False, False, [], 1), ("svc-sftp-sync", False, False, False, [], 1), ("wiz-connector", False, False, False, ["SecurityAudit", "ReadOnlyAccess"], 1), ("svc-eks-velero", False, False, False, [], 1)],
    "staging": [("svc-ci-staging", False, False, False, ["PowerUserAccess"], 2), ("svc-loadtest", False, False, False, [], 1), ("qa-automation", True, False, False, ["PowerUserAccess"], 2), ("svc-synthetic-monitor", False, False, False, [], 1),
                ("svc-db-refresh", False, False, False, ["AmazonRDSFullAccess", "AmazonS3ReadOnlyAccess"], 1), ("wiz-connector", False, False, False, ["SecurityAudit"], 1), ("svc-staging-deploy", False, False, False, ["PowerUserAccess"], 2), ("perf-team-shared", True, False, False, ["ReadOnlyAccess"], 1)],
    "dev": [("svc-dev-ci", False, False, False, ["PowerUserAccess"], 2), ("hackathon-shared", True, False, False, ["PowerUserAccess"], 2), ("svc-notebook-s3", False, False, False, ["AmazonS3FullAccess"], 1), ("intern-sandbox", True, False, False, ["PowerUserAccess"], 1), ("wiz-connector", False, False, False, ["SecurityAudit"], 1), ("svc-mobile-build", False, False, False, ["AmazonS3ReadOnlyAccess"], 2)],
    "data": [("svc-snowflake-loader", False, False, False, ["AmazonS3ReadOnlyAccess"], 2), ("svc-fivetran", False, False, False, ["AmazonS3FullAccess", "AmazonRDSReadOnlyAccess"], 1), ("svc-airflow-legacy", False, False, False, ["PowerUserAccess"], 2), ("bi-service-account", False, False, False, ["AmazonS3ReadOnlyAccess"], 1),
             ("svc-regrep-submit", False, False, False, [], 1), ("data-oncall-shared", True, False, False, ["ReadOnlyAccess"], 1), ("wiz-connector", False, False, False, ["SecurityAudit", "ReadOnlyAccess"], 1), ("svc-dbt-cloud", False, False, False, ["AmazonRDSReadOnlyAccess"], 1)],
    "corp": [("svc-okta-scim", False, False, False, [], 1), ("svc-marketing-deploy", False, False, False, ["AmazonS3FullAccess"], 2), ("svc-ad-connector", False, False, False, [], 1), ("svc-mdm-backup", False, False, False, ["AmazonS3FullAccess"], 1), ("helpdesk-shared", True, False, False, ["ReadOnlyAccess"], 1),
             ("mreyes-cli", True, True, True, ["AdministratorAccess"], 1), ("wiz-connector", False, False, False, ["SecurityAudit"], 1), ("svc-confluence-backup", False, False, False, ["AmazonS3FullAccess"], 1), ("svc-print-audit", False, False, False, [], 1)],
}

WINDOWS_SVC = [("svc-sql", "erp-app"), ("svc-backup", "srv-fileshare"), ("svc-okta-agent", "okta-ad-agent"), ("svc-print", "srv-print"), ("svc-scan", "srv-fileshare"), ("svc-mdm", "mdm-connector"), ("svc-exchange-hybrid", "exch-hybrid"), ("svc-adconnect", "dc")]
LINUX_SVC = [("svc-jenkins", "ci-jenkins"), ("svc-deploy", "ci-runner"), ("airflow", "airflow"), ("spark", "spark-worker"), ("prometheus", "prometheus"), ("grafana", "grafana"), ("vault", "vault"), ("loki", "loki"), ("svc-backup-linux", "backup-agent-shared-mgmt"),
             ("svc-scanner", "vulnscan"), ("svc-log-forwarder", "log-forwarder"), ("tomcat", "stmt-render"), ("svc-edge", "edge-proxy"), ("svc-artifactory", "artifact-registry"), ("kafka", "kafka-broker"), ("svc-etl", "warehouse-loader"), ("svc-mlops", "fraud-train"), ("svc-notebook", "notebook")]
K8S_SVC = ["argocd-server-sa", "external-secrets-sa", "aws-load-balancer-controller-sa", "cluster-autoscaler-sa", "karpenter-sa", "velero-sa"]


@dataclass
class Identity:
    roles: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    keys: list[str] = field(default_factory=list)
    service_accounts: list[str] = field(default_factory=list)
    role_by_key: dict[tuple[str, str, str], str] = field(default_factory=dict)  # (app, env, service) -> role id


def camel(text: str) -> str:
    return "".join(part.capitalize() for part in text.replace("_", "-").split("-") if part)


def role_arn(acct_key: str, name: str, path: str = "/") -> str:
    provider = PROVIDER[acct_key]
    if provider == "aws":
        return f"arn:aws:iam::{ACCOUNT_ID[acct_key]}:role{path}{name}"
    if provider == "gcp":
        return f"{name}@{ACCOUNT_ID[acct_key]}.iam.gserviceaccount.com"
    return f"/subscriptions/{ACCOUNT_ID[acct_key]}/resourceGroups/rg-corp/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}"


# ---------------------------------------------------------------------------- primitives


class IamBuilder:
    def __init__(self, inv: Inventory, est: Estate, ident: Identity) -> None:
        self.inv = inv
        self.est = est
        self.ident = ident
        self.r = rng("inventory.identity")
        self.data_by_account: dict[str, list[str]] = {}
        for label in ("StorageBucket", "Database", "Secret"):
            for nid in inv.ids(label):
                self.data_by_account.setdefault(inv.props(nid)["account_id"], []).append(nid)

    # -- roles
    def role(self, acct_key: str, name: str, role_type: str, trust: list[str], *, description: str, is_admin: bool = False, path: str = "/",
             last_used: str | None = "recent", app: str | None = None, role_id: str | None = None, env: str | None = None) -> str:
        provider = PROVIDER[acct_key]
        rid = role_id or f"role:{provider}:{ACCOUNT_ID[acct_key]}:{name}"
        if self.inv.has(rid):
            return rid
        if last_used == "recent":
            last_used = minutes_ago(self.r, 10, 14 * 1440)
        created = days_ago(self.r, 30, 900)
        self.inv.add_node(
            rid, "IamRole", name,
            {
                "provider": provider, "account_id": ACCOUNT_ID[acct_key], "arn": role_arn(acct_key, name, path), "role_type": role_type, "is_admin": is_admin,
                "privilege_score": 0.1, "trust_principals": list(trust), "last_used": last_used, "environment": env or ACCOUNT_ENV[acct_key], "path": path,
                "description": description, "max_session_duration": 3600 if role_type != "human" else 43200, "created": created, "app_id": f"app:larkspur:{app}" if app else None,
            },
            source=SOURCE_WIZ, source_id=rid.split(":")[-1], first_seen=created, account=acct_key, kind="role", app=app, role_type=role_type,
        )
        self.inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], rid, source=SOURCE_WIZ, first_seen=created)
        self.ident.roles.append(rid)
        if app:
            APP_BY_SLUG[app].resources.setdefault("role", []).append(rid)
        return rid

    def policy(self, acct_key: str, name: str, statements: list[dict[str, Any]], access_levels: list[str], *, managed: bool = True, aws_managed: bool = False,
               description: str = "", policy_id: str | None = None) -> str:
        provider = PROVIDER[acct_key]
        pid = policy_id or f"policy:{provider}:{ACCOUNT_ID[acct_key]}:{name}"
        if self.inv.has(pid):
            return pid
        resources = [res for st in statements for res in (st.get("Resource") if isinstance(st.get("Resource"), list) else [st.get("Resource", "*")])]
        actions = [a for st in statements for a in (st.get("Action") if isinstance(st.get("Action"), list) else [st.get("Action", "*")])]
        arn = f"arn:aws:iam::aws:policy/{name}" if aws_managed else (f"arn:aws:iam::{ACCOUNT_ID[acct_key]}:policy/{name}" if provider == "aws" else f"{provider}:policy/{name}")
        created = days_ago(self.r, 30, 900)
        self.inv.add_node(
            pid, "IamPolicy", name,
            {
                "provider": provider, "account_id": ACCOUNT_ID[acct_key], "managed": managed, "statements": statements, "access_levels": sorted(set(access_levels)),
                "wildcard_resource": any(res == "*" for res in resources), "wildcard_action": any(a in ("*", "*:*") for a in actions), "arn": arn,
                "aws_managed": aws_managed, "description": description or f"{'AWS managed' if aws_managed else 'Customer managed'} policy {name}",
            },
            source=SOURCE_WIZ, source_id=pid.split(":")[-1], first_seen=created, account=acct_key, kind="policy",
        )
        if not aws_managed:
            self.inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], pid, source=SOURCE_WIZ, first_seen=created)
        else:
            self.inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], pid, {"note": "AWS managed policy attached in this account"}, source=SOURCE_WIZ, first_seen=created)
        self.ident.policies.append(pid)
        return pid

    def managed(self, acct_key: str, name: str) -> str:
        levels, account_grant, actions = MANAGED[name]
        pid = self.policy(acct_key, name, [{"Effect": "Allow", "Action": actions, "Resource": "*"}], levels, aws_managed=True)
        if account_grant and not self.inv.has_edge("GRANTS", pid, sc.ACCOUNTS[acct_key]["id"]):
            level, scope = account_grant
            self.grant(pid, sc.ACCOUNTS[acct_key]["id"], actions, level, "*", scope_labels=scope)
        return pid

    def attach(self, principal: str, policy_id: str, attachment: str = "managed") -> None:
        self.inv.add_edge("HAS_POLICY", principal, policy_id, {"attachment": attachment}, source=SOURCE_WIZ)

    def grant(self, policy_id: str, dst: str, actions: list[str], level: str, pattern: str, scope_labels: list[str] | None = None) -> None:
        props: dict[str, Any] = {"actions": list(actions), "access_level": level, "resource_pattern": pattern}
        if scope_labels:
            props["scope_labels"] = list(scope_labels)
        self.inv.add_edge("GRANTS", policy_id, dst, props, source=SOURCE_WIZ)

    def can_assume(self, src: str, dst: str, via: str = "trust_policy") -> None:
        src_acct = self.inv.props(src).get("account_id")
        dst_acct = self.inv.props(dst)["account_id"]
        self.inv.add_edge("CAN_ASSUME", src, dst, {"via": via, "cross_account": src_acct != dst_acct}, source=SOURCE_WIZ)
        if self.inv.label(src) in ("IamRole", "IamUser"):
            tp = self.inv.props(dst)["trust_principals"]
            arn = self.inv.props(src)["arn"]
            if arn not in tp:
                tp.append(arn)

    # -- resource helpers
    def s3_pattern(self, bucket_id: str) -> str:
        return f"arn:aws:s3:::{self.inv.name(bucket_id)}/*"

    def grant_bucket(self, pid: str, bid: str, level: str) -> None:
        actions = {"read": ["s3:GetObject", "s3:ListBucket"], "write": ["s3:PutObject", "s3:AbortMultipartUpload"], "list": ["s3:ListBucket"], "admin": ["s3:*"]}[level]
        self.grant(pid, bid, actions, level, self.s3_pattern(bid))

    def grant_secret(self, pid: str, sid: str, level: str = "read") -> None:
        acct = self.inv.props(sid)["account_id"]
        self.grant(pid, sid, ["secretsmanager:GetSecretValue"] if level == "read" else ["secretsmanager:*"], level, f"arn:aws:secretsmanager:us-east-1:{acct}:secret:{self.inv.name(sid)}-*")

    def grant_db(self, pid: str, did: str, level: str = "list") -> None:
        acct = self.inv.props(did)["account_id"]
        actions = {"list": ["rds:DescribeDBInstances"], "read": ["rds-db:connect", "rds:DescribeDBInstances"], "write": ["rds:ModifyDBInstance", "rds-db:connect"], "admin": ["rds:*"]}[level]
        self.grant(pid, did, actions, level, f"arn:aws:rds:us-east-1:{acct}:db:{self.inv.name(did)}")

    def finalize_scores(self) -> None:
        """Set privilege_score / is_admin from the effective grants (direct policies only)."""
        for rid in self.ident.roles + self.ident.users:
            best = 0.15
            admin = self.inv.props(rid).get("is_admin", False)
            for pid in self.inv.out(rid, "HAS_POLICY"):
                for dst in self.inv.out(pid, "GRANTS"):
                    e = self.inv.get_edge("GRANTS", pid, dst)
                    level = e["props"]["access_level"] if e else "list"
                    if self.inv.label(dst) == "CloudAccount":
                        if level == "admin":
                            admin = True
                            best = max(best, 0.95)
                        elif level == "write":
                            best = max(best, 0.8)
                        else:
                            best = max(best, 0.5)
                        continue
                    if self.inv.label(dst) == "IamRole":
                        best = max(best, 0.4)
                        continue
                    sens = self.inv.props(dst).get("sensitivity", "low")
                    if level in ("admin", "write"):
                        best = max(best, 0.7 if sens in SENSITIVE else 0.45)
                    elif level == "read":
                        best = max(best, 0.6 if sens in SENSITIVE else 0.35)
                    else:
                        best = max(best, 0.25)
            self.inv.props(rid)["privilege_score"] = round(best, 2)
            self.inv.props(rid)["is_admin"] = admin


# ---------------------------------------------------------------------------- entry point


def build_identity(inv: Inventory, world: World, apps: list[AppSpec], est: Estate) -> Identity:
    ident = Identity()
    b = IamBuilder(inv, est, ident)
    _storyline_roles(b)
    _cluster_roles(b)
    _service_roles(b, apps)
    _workload_roles(b)
    _function_roles(b, apps)
    _sso_roles(b, world)
    _cross_account_roles(b)
    _service_linked_roles(b)
    _legacy_roles(b)
    _iam_users(b, world)
    _service_accounts(inv, est, ident)
    b.finalize_scores()
    inv.props(sc.BASTION_ROLE)["privilege_score"] = max(inv.props(sc.BASTION_ROLE)["privilege_score"], 0.55)
    inv.storyline.update({
        "bastion_role": sc.BASTION_ROLE, "bastion_assume_policy": sc.BASTION_ASSUME_POLICY, "bastion_logs_policy": sc.BASTION_LOGS_POLICY,
        "prod_reader_role": sc.PROD_READER_ROLE, "prod_reader_policy": sc.PROD_READER_POLICY, "edge_role": sc.EDGE_ROLE, "edge_policy": sc.EDGE_POLICY,
        "corp_it_admin_role": sc.CORP_IT_ADMIN_ROLE, "svc_finops_sftp": sc.SVC_FINOPS_SFTP, "prod_deploy_role": "role:aws:111111111111:LarkspurProdDeployRole",
        "jenkins_role": "role:aws:222222222222:LarkspurCiJenkinsRole", "stg_edge_role": "role:aws:333333333333:LarkspurStmtRenderStagingRole",
    })
    return ident


# ---------------------------------------------------------------------------- storyline


def _storyline_roles(b: IamBuilder) -> None:
    inv = b.inv
    # bastion instance role
    bastion = b.role("shared", "LarkspurBastionSSMRole", "instance", ["ec2.amazonaws.com"], description="Instance profile for the shared-services bastion (bas-01): SSM, log shipping and prod read access via role chaining.", app="platform-ssm-access", role_id=sc.BASTION_ROLE, env="prod")
    b.attach(bastion, b.managed("shared", "AmazonSSMManagedInstanceCore"))
    assume = b.policy("shared", "LarkspurBastionAssumeProdReader", [{"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": sc.PROD_READER_ROLE_ARN}], ["read"], policy_id=sc.BASTION_ASSUME_POLICY, description="Allows the bastion role to assume LarkspurProdDataReader in larkspur-prod")
    b.attach(bastion, assume)
    logs = b.policy("shared", "LarkspurSharedLogsWrite", [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:AbortMultipartUpload"], "Resource": "arn:aws:s3:::larkspur-shared-logs/bastion/*"}], ["write"], policy_id=sc.BASTION_LOGS_POLICY, description="Write session logs to the shared logs bucket")
    b.attach(bastion, logs)
    b.grant(logs, sc.SHARED_LOGS_BUCKET, ["s3:PutObject", "s3:AbortMultipartUpload"], "write", "arn:aws:s3:::larkspur-shared-logs/bastion/*")
    for vm in est_vms_of(b, "platform-ssm-access", "prod", "bastion"):
        inv.add_edge("HAS_ROLE", vm, bastion, {"via": "instance_profile"}, source=SOURCE_WIZ, first_seen="2025-11-02T10:00:00Z")
    b.ident.role_by_key[("platform-ssm-access", "prod", "bastion")] = bastion
    # prod data reader (cross-account, trusted by the bastion role)
    reader = b.role("prod", "LarkspurProdDataReader", "cross-account", [sc.BASTION_ROLE_ARN], description="Read access to cardholder vault, KYC documents and prod secrets for operational support from the shared-services bastion.", app="card-issuing", role_id=sc.PROD_READER_ROLE)
    pol = b.policy("prod", "LarkspurProdDataReaderAccess", [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::larkspur-cardholder-vault", "arn:aws:s3:::larkspur-cardholder-vault/*", "arn:aws:s3:::larkspur-kyc-documents", "arn:aws:s3:::larkspur-kyc-documents/*"]},
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": ["arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/cardholder-db/reader-*", "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/hsm/partner-signing-key-*"]},
        {"Effect": "Allow", "Action": ["rds:DescribeDBInstances"], "Resource": "arn:aws:rds:us-east-1:111111111111:db:cardholder-db"},
    ], ["read", "list"], policy_id=sc.PROD_READER_POLICY, description="Read cardholder vault, KYC documents, DB reader and HSM secrets")
    b.attach(reader, pol)
    b.grant(pol, sc.CARDHOLDER_VAULT, ["s3:GetObject", "s3:ListBucket"], "read", "arn:aws:s3:::larkspur-cardholder-vault/*")
    b.grant(pol, sc.KYC_DOCS, ["s3:GetObject", "s3:ListBucket"], "read", "arn:aws:s3:::larkspur-kyc-documents/*")
    b.grant(pol, sc.DB_READER_SECRET, ["secretsmanager:GetSecretValue"], "read", "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/cardholder-db/reader-*")
    b.grant(pol, sc.HSM_SECRET, ["secretsmanager:GetSecretValue"], "read", "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/hsm/partner-signing-key-*")
    b.grant(pol, sc.CARDHOLDER_DB, ["rds:DescribeDBInstances"], "list", "arn:aws:rds:us-east-1:111111111111:db:cardholder-db")
    b.grant(assume, reader, ["sts:AssumeRole"], "assume", sc.PROD_READER_ROLE_ARN)
    b.can_assume(bastion, reader)
    inv.props(reader)["trust_principals"] = [sc.BASTION_ROLE_ARN]
    inv.props(reader)["last_used"] = "2026-09-10T02:24:15Z"
    inv.props(bastion)["last_used"] = "2026-09-11T13:41:07Z"
    # statement-render instance role
    edge = b.role("prod", "LarkspurStmtRenderRole", "instance", ["ec2.amazonaws.com"], description="Instance profile for statement-render hosts: reads prod app config, writes rendered statements.", app="statement-render", role_id=sc.EDGE_ROLE)
    b.attach(edge, b.managed("prod", "AmazonSSMManagedInstanceCore"))
    epol = b.policy("prod", "LarkspurStmtRenderAccess", [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::larkspur-prod-app-config/*"},
        {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::larkspur-statements-out/*"},
    ], ["read", "write"], policy_id=sc.EDGE_POLICY)
    b.attach(edge, epol)
    b.grant(epol, sc.APP_CONFIG_BUCKET, ["s3:GetObject"], "read", "arn:aws:s3:::larkspur-prod-app-config/*")
    b.grant(epol, sc.STATEMENTS_OUT_BUCKET, ["s3:PutObject"], "write", "arn:aws:s3:::larkspur-statements-out/*")
    for vm in est_vms_of(b, "statement-render", "prod", "stmt-render"):
        inv.add_edge("HAS_ROLE", vm, edge, {"via": "instance_profile"}, source=SOURCE_WIZ)
    b.ident.role_by_key[("statement-render", "prod", "stmt-render")] = edge
    # staging copy: only a staging config bucket
    sedge = b.role("staging", "LarkspurStmtRenderStagingRole", "instance", ["ec2.amazonaws.com"], description="Instance profile for statement-render staging hosts.", app="statement-render")
    b.attach(sedge, b.managed("staging", "AmazonSSMManagedInstanceCore"))
    spol = b.policy("staging", "LarkspurStmtRenderStagingAccess", [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::larkspur-staging-app-config/*"}], ["read"])
    b.attach(sedge, spol)
    if inv.has("bucket:aws:larkspur-staging-app-config"):
        b.grant_bucket(spol, "bucket:aws:larkspur-staging-app-config", "read")
    for vm in est_vms_of(b, "statement-render", "staging", "stmt-render"):
        inv.add_edge("HAS_ROLE", vm, sedge, {"via": "instance_profile"}, source=SOURCE_WIZ)
    b.ident.role_by_key[("statement-render", "staging", "stmt-render")] = sedge
    # partner-api: reads partner data (PII)
    partner = b.role("prod", "LarkspurPartnerApiRole", "instance", ["ec2.amazonaws.com"], description="Instance profile for partner-api hosts.", app="baas-gateway")
    b.attach(partner, b.managed("prod", "AmazonSSMManagedInstanceCore"))
    ppol = b.policy("prod", "LarkspurPartnerApiAccess", [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::larkspur-partner-data/*"}, {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::larkspur-baas-gateway-logs/*"}], ["read", "write"])
    b.attach(partner, ppol)
    b.grant_bucket(ppol, "bucket:aws:larkspur-partner-data", "read")
    if inv.has("bucket:aws:larkspur-baas-gateway-logs"):
        b.grant_bucket(ppol, "bucket:aws:larkspur-baas-gateway-logs", "write")
    for vm in est_vms_of(b, "baas-gateway", "prod", "partner-api"):
        inv.add_edge("HAS_ROLE", vm, partner, {"via": "instance_profile"}, source=SOURCE_WIZ)
    b.ident.role_by_key[("baas-gateway", "prod", "partner-api")] = partner
    # jenkins: writes artifacts, can assume the prod deploy role
    jenkins = b.role("shared", "LarkspurCiJenkinsRole", "instance", ["ec2.amazonaws.com"], description="Instance profile for the Jenkins controller.", app="ci-cd-pipeline")
    b.attach(jenkins, b.managed("shared", "AmazonSSMManagedInstanceCore"))
    jpol = b.policy("shared", "LarkspurCiJenkinsAccess", [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": "arn:aws:s3:::larkspur-ci-artifacts/*"}, {"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": "arn:aws:iam::111111111111:role/LarkspurProdDeployRole"}], ["read", "write"])
    b.attach(jenkins, jpol)
    b.grant_bucket(jpol, "bucket:aws:larkspur-ci-artifacts", "write")
    deploy = b.role("prod", "LarkspurProdDeployRole", "cross-account", [], description="Deployment role assumed by CI to update prod functions and publish deploy artifacts.", app="ci-cd-pipeline")
    dpol = b.policy("prod", "LarkspurProdDeployAccess", [{"Effect": "Allow", "Action": ["lambda:UpdateFunctionCode", "lambda:PublishVersion"], "Resource": "arn:aws:lambda:us-east-1:111111111111:function:*"}, {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::larkspur-prod-deploy-artifacts/*"}], ["write"])
    b.attach(deploy, dpol)
    b.grant_bucket(dpol, "bucket:aws:larkspur-prod-deploy-artifacts", "write")
    prod_fns = [f for f in b.est.functions if inv.props(f)["account_id"] == "111111111111"]
    for f in prod_fns[:6]:
        b.grant(dpol, f, ["lambda:UpdateFunctionCode"], "write", f"arn:aws:lambda:us-east-1:111111111111:function:{inv.name(f)}")
    b.grant(jpol, deploy, ["sts:AssumeRole"], "assume", "arn:aws:iam::111111111111:role/LarkspurProdDeployRole")
    b.can_assume(jenkins, deploy)
    for vm in est_vms_of(b, "ci-cd-pipeline", "prod", "ci-jenkins"):
        inv.add_edge("HAS_ROLE", vm, jenkins, {"via": "instance_profile"}, source=SOURCE_WIZ)
    b.ident.role_by_key[("ci-cd-pipeline", "prod", "ci-jenkins")] = jenkins
    # NetScaler gateways: logs only
    nsgw = b.role("shared", "LarkspurNsGwRole", "instance", ["ec2.amazonaws.com"], description="CloudWatch logging for the NetScaler gateways.", app="remote-access-gateway")
    b.attach(nsgw, b.managed("shared", "CloudWatchAgentServerPolicy"))
    for vm in est_vms_of(b, "remote-access-gateway", "prod", "ns-gw"):
        inv.add_edge("HAS_ROLE", vm, nsgw, {"via": "instance_profile"}, source=SOURCE_WIZ)
    b.ident.role_by_key[("remote-access-gateway", "prod", "ns-gw")] = nsgw
    # corp IT admin (SSO)
    corp_admin = b.role("corp", "LarkspurCorpItAdmin", "sso", ["arn:aws:iam::666666666666:saml-provider/Okta"], description="Corporate IT administrators (Okta SSO) in larkspur-corp-it.", is_admin=True, role_id=sc.CORP_IT_ADMIN_ROLE)
    b.attach(corp_admin, b.managed("corp", "AdministratorAccess"))
    inv.add_edge("MAPS_TO", sc.USER_MREYES, corp_admin, {"via": "sso"}, source=SOURCE_OKTA)
    inv.add_edge("MAPS_TO", "group:okta:corp-it-admins", corp_admin, {"via": "sso"}, source=SOURCE_OKTA)
    inv.props(corp_admin)["last_used"] = "2026-09-11T01:05:44Z"


def est_vms_of(b: IamBuilder, app: str, env: str, service: str) -> list[str]:
    return b.est.service_vms.get((app, env, service), [])


# ---------------------------------------------------------------------------- generated roles


def _cluster_roles(b: IamBuilder) -> None:
    inv = b.inv
    for cname, cid in b.est.cluster_ids.items():
        acct = ACCOUNT_BY_ID[inv.props(cid)["account_id"]]
        cluster_role = b.role(acct, f"Larkspur{camel(cname)}ClusterRole", "service", ["eks.amazonaws.com"], description=f"EKS control plane role for {cname}.", app="container-platform")
        b.attach(cluster_role, b.managed(acct, "AmazonEKSClusterPolicy"))
        inv.add_edge("HAS_ROLE", cid, cluster_role, {"via": "service_account"}, source=SOURCE_WIZ)
        node_role = b.role(acct, f"Larkspur{camel(cname)}NodeRole", "instance", ["ec2.amazonaws.com"], description=f"Node instance role for {cname} worker nodes.", app="container-platform")
        for pol in ("AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly", "AmazonSSMManagedInstanceCore"):
            b.attach(node_role, b.managed(acct, pol))
        for vm in b.est.cluster_nodes[cname]:
            inv.add_edge("HAS_ROLE", vm, node_role, {"via": "node_role"}, source=SOURCE_WIZ)
        b.ident.role_by_key[("container-platform", "prod", f"{cname}-nodes")] = node_role


def _app_resources(b: IamBuilder, app: AppSpec, environment: str, account_id: str) -> tuple[list[str], list[str], list[str]]:
    inv = b.inv
    buckets = [x for x in app.resources.get("bucket", []) if inv.props(x)["account_id"] == account_id and inv.props(x)["environment"] == environment]
    dbs = [x for x in app.resources.get("database", []) if inv.props(x)["account_id"] == account_id and inv.props(x)["environment"] == environment]
    secrets = [x for x in app.resources.get("secret", []) if inv.props(x)["account_id"] == account_id]
    return buckets, dbs, secrets


def _generic_grants(b: IamBuilder, pid: str, app: AppSpec, environment: str, acct_key: str, r: random.Random, *, strength: float = 1.0) -> list[dict[str, Any]]:
    """Attach plausible least-privilege-ish grants for a service of ``app`` and return the policy statements."""
    inv = b.inv
    buckets, dbs, secrets = _app_resources(b, app, environment, ACCOUNT_ID[acct_key])
    statements: list[dict[str, Any]] = []
    tier0 = app.tier in ("tier-0", "tier-1")
    for bid in buckets:
        name = inv.name(bid)
        p = inv.props(bid)
        if name.endswith("-logs"):
            b.grant_bucket(pid, bid, "write")
            statements.append({"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{name}/*"})
        elif name.endswith("-backups"):
            if r.random() < 0.3 * strength:
                b.grant_bucket(pid, bid, "write")
                statements.append({"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": f"arn:aws:s3:::{name}/*"})
        else:
            chance = (0.45 if p.get("crown_jewel") else 0.6) * strength * (1.15 if tier0 else 0.85)
            if r.random() < chance:
                level = "write" if r.random() < 0.3 else "read"
                b.grant_bucket(pid, bid, level)
                statements.append({"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"] if level == "read" else ["s3:PutObject", "s3:GetObject"], "Resource": f"arn:aws:s3:::{name}/*"})
    for sid in secrets:
        st = inv.props(sid)["secret_type"]
        chance = (0.65 if st == "db_credentials" else 0.4) * strength
        if r.random() < chance:
            b.grant_secret(pid, sid)
            statements.append({"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID[acct_key]}:secret:{inv.name(sid)}-*"})
    for did in dbs:
        if r.random() < 0.4 * strength:
            b.grant_db(pid, did, "list")
            statements.append({"Effect": "Allow", "Action": ["rds:DescribeDBInstances"], "Resource": f"arn:aws:rds:us-east-1:{ACCOUNT_ID[acct_key]}:db:{inv.name(did)}"})
    # permission sprawl: an unrelated bucket in the same account
    pool = [x for x in b.data_by_account.get(ACCOUNT_ID[acct_key], []) if inv.label(x) == "StorageBucket" and x not in buckets]
    if pool and r.random() < 0.12 * strength:
        extra = r.choice(pool)
        b.grant_bucket(pid, extra, "read")
        statements.append({"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": f"arn:aws:s3:::{inv.name(extra)}/*"})
    if not statements:
        statements.append({"Effect": "Allow", "Action": ["cloudwatch:PutMetricData"], "Resource": "*"})
    return statements


def _service_roles(b: IamBuilder, apps: list[AppSpec]) -> None:
    inv = b.inv
    r = rng("inventory.identity.service-roles")
    for key in sorted(b.est.service_vms):
        app_slug, env, service = key
        if key in b.ident.role_by_key:
            continue
        vms = b.est.service_vms[key]
        if not vms or not inv.meta[vms[0]].get("role"):
            continue
        if service in ("vpn-pa", "vpn-gw", "wiki-confluence", "log4j-testbed"):
            continue
        app = APP_BY_SLUG[app_slug]
        acct_key = inv.meta[vms[0]]["account"]
        environment = inv.meta[vms[0]]["env"]
        provider = PROVIDER[acct_key]
        suffix = "" if env == "prod" else camel(env)
        if provider == "aws":
            name = f"Larkspur{camel(service)}{suffix}Role"
            rid = b.role(acct_key, name, "instance", ["ec2.amazonaws.com"], description=f"Instance profile for {service} ({environment}).", app=app_slug, env=environment)
            b.attach(rid, b.managed(acct_key, "AmazonSSMManagedInstanceCore"))
            if r.random() < 0.6:
                b.attach(rid, b.managed(acct_key, "CloudWatchAgentServerPolicy"))
            pid = b.policy(acct_key, f"Larkspur{camel(service)}{suffix}Access", [], ["read"], description=f"Access policy for {service}")
        elif provider == "gcp":
            name = f"{service}-sa"
            rid = b.role(acct_key, name, "instance", ["compute.googleapis.com"], description=f"GCE service account for {service}.", app=app_slug, env=environment)
            pid = b.policy(acct_key, f"{service}-binding", [], ["read"], description=f"IAM binding for {service}")
        else:
            name = f"mi-{service}"
            rid = b.role(acct_key, name, "instance", ["Microsoft.Compute/virtualMachines"], description=f"User-assigned managed identity for {service}.", app=app_slug, env=environment)
            pid = b.policy(acct_key, f"ra-{service}", [], ["read"], description=f"Role assignments for {service}")
        strength = 1.0 if environment in ("prod", "corp") else 0.7
        statements = _generic_grants(b, pid, app, environment, acct_key, r, strength=strength)
        inv.props(pid)["statements"] = statements
        inv.props(pid)["access_levels"] = sorted({lvl for pid2 in [pid] for dst in inv.out(pid2, "GRANTS") for lvl in [inv.get_edge("GRANTS", pid2, dst)["props"]["access_level"]]} or {"read"})
        b.attach(rid, pid, "inline" if r.random() < 0.2 else "managed")
        inv.props(pid)["managed"] = not inv.get_edge("HAS_POLICY", rid, pid)["props"]["attachment"] == "inline"
        # a few legacy roles carry a wildcard S3 policy
        if provider == "aws" and r.random() < (0.04 if environment == "prod" else 0.09):
            wild = b.policy(acct_key, f"Larkspur{camel(service)}{suffix}S3Legacy", [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}], ["admin"], description="Legacy wildcard S3 policy (migration leftover)")
            b.grant(wild, sc.ACCOUNTS[acct_key]["id"], ["s3:*"], "admin", "*", scope_labels=["StorageBucket"])
            b.attach(rid, wild)
        for vm in vms:
            inv.add_edge("HAS_ROLE", vm, rid, {"via": "instance_profile"}, source=SOURCE_WIZ)
        b.ident.role_by_key[key] = rid


def _workload_roles(b: IamBuilder) -> None:
    inv = b.inv
    r = rng("inventory.identity.irsa")
    for key in sorted(b.est.service_workloads):
        app_slug, environment, service = key
        wids = b.est.service_workloads[key]
        if not inv.meta[wids[0]].get("role"):
            continue
        cname = inv.meta[wids[0]]["cluster"]
        acct_key = inv.meta[wids[0]]["account"]
        app = APP_BY_SLUG[app_slug]
        suffix = "" if environment == "prod" else camel(environment)
        oidc = f"arn:aws:iam::{ACCOUNT_ID[acct_key]}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/{hexid('oidc', cname, length=32).upper()}"
        rid = b.role(acct_key, f"Larkspur{camel(service)}Irsa{suffix}Role", "service", [oidc], description=f"IRSA role for {service} pods in {cname}.", app=app_slug, env=environment)
        pid = b.policy(acct_key, f"Larkspur{camel(service)}Irsa{suffix}Access", [], ["read"], description=f"IRSA access policy for {service}")
        if app_slug == "container-platform":
            statements = [{"Effect": "Allow", "Action": ["ec2:Describe*", "elasticloadbalancing:*", "autoscaling:*"], "Resource": "*"}]
        else:
            statements = _generic_grants(b, pid, app, environment, acct_key, r, strength=1.0 if environment == "prod" else 0.7)
        inv.props(pid)["statements"] = statements
        b.attach(rid, pid)
        for wid in wids:
            inv.add_edge("HAS_ROLE", wid, rid, {"via": "irsa"}, source=SOURCE_WIZ)
        b.ident.role_by_key[("irsa", environment, f"{app_slug}/{service}")] = rid


def _function_roles(b: IamBuilder, apps: list[AppSpec]) -> None:
    inv = b.inv
    r = rng("inventory.identity.lambda")
    by_app_env: dict[tuple[str, str, str], list[str]] = {}
    for fid in b.est.functions:
        m = inv.meta[fid]
        if not m.get("role"):
            continue
        by_app_env.setdefault((m["app"], m["env"], m["account"]), []).append(fid)
    for (app_slug, environment, acct_key), fids in sorted(by_app_env.items()):
        app = APP_BY_SLUG[app_slug]
        suffix = "" if environment == "prod" else camel(environment)
        acct_suffix = camel(acct_key) if acct_key != app.account else ""
        rid = b.role(acct_key, f"Larkspur{camel(app_slug)}Lambda{acct_suffix}{suffix}Role", "service", ["lambda.amazonaws.com"], description=f"Execution role for {app.name} functions ({environment}).", app=app_slug, env=environment)
        b.attach(rid, b.managed(acct_key, "AWSLambdaBasicExecutionRole"))
        if r.random() < 0.4:
            b.attach(rid, b.managed(acct_key, "AWSLambdaVPCAccessExecutionRole"))
        pid = b.policy(acct_key, f"Larkspur{camel(app_slug)}Lambda{acct_suffix}{suffix}Access", [], ["read"], description=f"Data access for {app.name} functions")
        inv.props(pid)["statements"] = _generic_grants(b, pid, app, environment, acct_key, r, strength=0.8)
        b.attach(rid, pid)
        for fid in fids:
            inv.add_edge("HAS_ROLE", fid, rid, {"via": "service_account"}, source=SOURCE_WIZ)


SSO_SETS: list[tuple[str, str, str]] = [  # (permission set, managed policy, group)
    ("AdministratorAccess", "AdministratorAccess", "aws-{acct}-admins"), ("PowerUserAccess", "PowerUserAccess", "aws-{acct}-power"),
    ("ReadOnlyAccess", "ReadOnlyAccess", "aws-{acct}-readonly"), ("SecurityAudit", "SecurityAudit", "security-eng"),
]
SSO_GROUP_FOR_ACCOUNT: dict[str, dict[str, str]] = {
    "prod": {"AdministratorAccess": "aws-prod-admins", "ReadOnlyAccess": "aws-prod-readonly", "PowerUserAccess": "breakglass-approvers"},
    "shared": {"AdministratorAccess": "aws-shared-admins", "ReadOnlyAccess": "oncall-platform", "PowerUserAccess": "oncall-platform"},
    "staging": {"AdministratorAccess": "aws-shared-admins", "ReadOnlyAccess": "github-org-members", "PowerUserAccess": "aws-staging-power"},
    "dev": {"AdministratorAccess": "aws-shared-admins", "ReadOnlyAccess": "github-org-members", "PowerUserAccess": "aws-dev-power"},
    "data": {"AdministratorAccess": "aws-data-admins", "ReadOnlyAccess": "data-lake-readers", "PowerUserAccess": "oncall-data"},
    "corp": {"AdministratorAccess": "aws-corp-admins", "ReadOnlyAccess": "support-tooling", "PowerUserAccess": "corp-it-admins"},
}


def _sso_roles(b: IamBuilder, world: World) -> None:
    inv = b.inv
    for acct_key in ("prod", "shared", "staging", "dev", "data", "corp"):
        saml = f"arn:aws:iam::{ACCOUNT_ID[acct_key]}:saml-provider/AWSSSO_{hexid('saml', acct_key, length=10)}_DO_NOT_DELETE"
        for pset, managed_name, _ in SSO_SETS:
            name = f"AWSReservedSSO_{pset}_{hexid('pset', acct_key, pset, length=16)}"
            rid = b.role(acct_key, name, "sso", [saml], description=f"IAM Identity Center permission set {pset}", path="/aws-reserved/sso.amazonaws.com/", is_admin=pset == "AdministratorAccess")
            b.attach(rid, b.managed(acct_key, managed_name))
            group = "security-eng" if pset == "SecurityAudit" else SSO_GROUP_FOR_ACCOUNT[acct_key][pset]
            gid = world.groups[group]
            inv.add_edge("MAPS_TO", gid, rid, {"via": "sso"}, source=SOURCE_OKTA)
            # privileged individuals also get a direct mapping so their footprint is queryable
            if pset in ("AdministratorAccess", "PowerUserAccess") or acct_key == "prod":
                for uid in world.group_members.get(group, []):
                    p = world.person(uid)
                    if p.privileged or pset == "ReadOnlyAccess" and acct_key == "prod":
                        inv.add_edge("MAPS_TO", uid, rid, {"via": "sso", "group": group}, source=SOURCE_OKTA)
    # data analysts: a custom permission set in the data account
    analyst = b.role("data", f"AWSReservedSSO_LarkspurDataAnalyst_{hexid('pset', 'data', 'analyst', length=16)}", "sso", [f"arn:aws:iam::555555555555:saml-provider/AWSSSO_{hexid('saml', 'data', length=10)}_DO_NOT_DELETE"], description="IAM Identity Center permission set LarkspurDataAnalyst", path="/aws-reserved/sso.amazonaws.com/")
    apol = b.policy("data", "LarkspurDataAnalystAccess", [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::larkspur-data-lake-curated/*", "arn:aws:s3:::larkspur-bi-exports/*"]}, {"Effect": "Allow", "Action": ["redshift-data:*"], "Resource": "*"}], ["read"])
    b.attach(analyst, apol)
    for bid in ("bucket:aws:larkspur-data-lake-curated", "bucket:aws:larkspur-bi-exports"):
        if inv.has(bid):
            b.grant_bucket(apol, bid, "read")
    if inv.has("database:aws:555555555555:warehouse-redshift"):
        b.grant_db(apol, "database:aws:555555555555:warehouse-redshift", "read")
    inv.add_edge("MAPS_TO", world.groups["bi-dashboard-viewers"], analyst, {"via": "sso"}, source=SOURCE_OKTA)
    inv.add_edge("MAPS_TO", world.groups["data-lake-readers"], analyst, {"via": "sso"}, source=SOURCE_OKTA)
    # SecOps role in shared services used to hop into every account's audit role
    secops = b.role("shared", "LarkspurSecOpsRole", "sso", [f"arn:aws:iam::222222222222:saml-provider/AWSSSO_{hexid('saml', 'shared', length=10)}_DO_NOT_DELETE"], description="Security operations hub role (assumes per-account audit roles).")
    b.attach(secops, b.managed("shared", "SecurityAudit"))
    inv.add_edge("MAPS_TO", world.groups["security-eng"], secops, {"via": "sso"}, source=SOURCE_OKTA)
    b.ident.role_by_key[("hub", "shared", "secops")] = secops


def _cross_account_roles(b: IamBuilder) -> None:
    inv = b.inv
    secops = b.ident.role_by_key[("hub", "shared", "secops")]
    ci_runner = b.ident.role_by_key.get(("ci-cd-pipeline", "prod", "ci-runner"))
    backup_hub = b.role("shared", "LarkspurBackupOrchestratorRole", "service", ["backup.amazonaws.com"], description="AWS Backup orchestrator assuming per-account backup roles.", app="siem-forwarders")
    terraform_user = "iamuser:aws:222222222222:terraform-cloud"
    for acct_key in ("prod", "shared", "staging", "dev", "data", "corp"):
        audit = b.role(acct_key, "LarkspurSecurityAuditRole", "cross-account", [], description="Security audit role assumed from the shared-services SecOps hub.")
        b.attach(audit, b.managed(acct_key, "SecurityAudit"))
        b.attach(audit, b.managed(acct_key, "ViewOnlyAccess"))
        b.can_assume(secops, audit)
        backup = b.role(acct_key, "LarkspurBackupRole", "cross-account", [], description="Backup role assumed by the shared backup orchestrator.")
        b.attach(backup, b.managed(acct_key, "AWSBackupServiceRolePolicyForBackup"))
        b.can_assume(backup_hub, backup)
        wiz = b.role(acct_key, "LarkspurWizScannerRole", "cross-account", ["arn:aws:iam::999999999999:role/wiz-connector"], description="Read-only role trusted by the CSPM vendor account (external).")
        b.attach(wiz, b.managed(acct_key, "ReadOnlyAccess"))
        b.attach(wiz, b.managed(acct_key, "SecurityAudit"))
        tf_level = "PowerUserAccess" if acct_key == "prod" else "AdministratorAccess"
        tf = b.role(acct_key, "LarkspurTerraformRole", "cross-account", [], description=f"Terraform apply role ({tf_level}).", is_admin=tf_level == "AdministratorAccess")
        b.attach(tf, b.managed(acct_key, tf_level))
        if ci_runner:
            b.can_assume(ci_runner, tf)
        if inv.has(terraform_user):
            b.can_assume(terraform_user, tf)
    # deploy chain dev -> staging -> prod
    devops = b.role("dev", "LarkspurDevOpsRole", "human", [f"arn:aws:iam::{ACCOUNT_ID['dev']}:root"], description="Shared developer operations role (assumable by anyone in the dev account).")
    b.attach(devops, b.managed("dev", "PowerUserAccess"))
    stg_deploy = b.role("staging", "LarkspurStagingDeployRole", "cross-account", [], description="Staging deploy role.")
    b.attach(stg_deploy, b.managed("staging", "PowerUserAccess"))
    b.can_assume(devops, stg_deploy)
    b.can_assume(stg_deploy, "role:aws:111111111111:LarkspurProdDeployRole")
    # data lake reader assumed by prod fraud scoring
    lake_reader = b.role("data", "LarkspurDataLakeReaderRole", "cross-account", [], description="Read curated data lake zones from prod fraud-scoring pods.", app="data-lake")
    lpol = b.policy("data", "LarkspurDataLakeReaderAccess", [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::larkspur-data-lake-curated/*"}], ["read"])
    b.attach(lake_reader, lpol)
    if inv.has("bucket:aws:larkspur-data-lake-curated"):
        b.grant_bucket(lpol, "bucket:aws:larkspur-data-lake-curated", "read")
    fraud_irsa = b.ident.role_by_key.get(("irsa", "prod", "fraud-scoring/fraud-scorer"))
    if fraud_irsa:
        b.can_assume(fraud_irsa, lake_reader)
    ledger_reader = b.role("prod", "LarkspurLedgerReplicaReaderRole", "cross-account", [], description="Read the ledger replica for data lake ingestion.", app="ledger")
    rpol = b.policy("prod", "LarkspurLedgerReplicaReaderAccess", [{"Effect": "Allow", "Action": ["rds-db:connect", "secretsmanager:GetSecretValue"], "Resource": "*"}], ["read"])
    b.attach(ledger_reader, rpol)
    if inv.has("database:aws:111111111111:ledger-db-replica"):
        b.grant_db(rpol, "database:aws:111111111111:ledger-db-replica", "read")
    if inv.has("secret:aws:111111111111:prod/ledger-db/readonly"):
        b.grant_secret(rpol, "secret:aws:111111111111:prod/ledger-db/readonly")
    lake_irsa = b.ident.role_by_key.get(("irsa", "prod", "data-lake/lake-ingest"))
    if lake_irsa:
        b.can_assume(lake_irsa, ledger_reader)
    # break-glass admin in prod, assumable by the break-glass IAM user (created later, trust recorded by can_assume in _iam_users)
    bg = b.role("prod", "LarkspurBreakGlassAdmin", "human", [], description="Emergency administrator role; use requires an approved incident ticket.", is_admin=True)
    b.attach(bg, b.managed("prod", "AdministratorAccess"))
    b.ident.role_by_key[("hub", "prod", "breakglass")] = bg


def _service_linked_roles(b: IamBuilder) -> None:
    for acct_key in ("prod", "shared", "staging", "dev", "data", "corp"):
        for name in SERVICE_LINKED:
            service = name.replace("AWSServiceRoleFor", "").lower()
            b.role(acct_key, name, "service", [f"{service}.amazonaws.com"], description=f"Service-linked role for {service}.", path="/aws-service-role/", last_used=None if service in ("support", "trustedadvisor") else "recent")


def _legacy_roles(b: IamBuilder) -> None:
    r = rng("inventory.identity.legacy")
    names = ["LarkspurLegacyEtlRole", "lambda-role-migration-2023", "LarkspurOldDeployRole", "ec2-admin-role-DEPRECATED", "LarkspurTempAuditRole", "codebuild-legacy-service-role", "LarkspurHackathonRole", "LarkspurVendorPocRole"]
    for acct_key in ("prod", "shared", "staging", "dev", "data", "corp"):
        for name in r.sample(names, 5 if acct_key in ("dev", "staging") else 3):
            rid = b.role(acct_key, name, "service" if "lambda" in name or "codebuild" in name else "human", [f"arn:aws:iam::{ACCOUNT_ID[acct_key]}:root"], description="Legacy role without an owner; no activity recorded.", last_used=None if r.random() < 0.7 else "recent")
            if "admin" in name.lower() and acct_key != "prod":
                b.attach(rid, b.managed(acct_key, "AdministratorAccess"))
            elif r.random() < 0.5:
                b.attach(rid, b.managed(acct_key, "ReadOnlyAccess"))
            else:
                b.attach(rid, b.managed(acct_key, "AmazonS3ReadOnlyAccess"))


def _iam_users(b: IamBuilder, world: World) -> None:
    inv = b.inv
    r = rng("inventory.identity.users")
    eng = [p for p in world.people if p.team.department == "Engineering" and p.status == "active" and p.login not in ("jokafor", "lchen")]
    extra_cli = r.sample(eng, 20)
    spec: list[tuple[str, str, bool, bool, bool, list[str], int]] = []
    for acct_key, users in IAM_USERS.items():
        for name, console, mfa, admin, policies, keys in users:
            spec.append((acct_key, name, console, mfa, admin, policies, keys))
    for i, p in enumerate(extra_cli):
        acct_key = "dev" if i % 3 else "staging"
        spec.append((acct_key, f"{p.login}-cli", i % 4 == 0, i % 5 != 0, False, ["PowerUserAccess" if acct_key == "dev" else "ReadOnlyAccess"], 1 + (i % 3 == 0)))
    for acct_key, name, console, mfa, admin, policies, keys in spec:
        uid = f"iamuser:aws:{ACCOUNT_ID[acct_key]}:{name}"
        created = days_ago(r, 40, 1200)
        inv.add_node(
            uid, "IamUser", name,
            {
                "provider": "aws", "account_id": ACCOUNT_ID[acct_key], "arn": f"arn:aws:iam::{ACCOUNT_ID[acct_key]}:user/{name}", "is_admin": admin, "mfa_enabled": mfa,
                "console_access": console, "privilege_score": 0.1, "environment": ACCOUNT_ENV[acct_key], "created": created, "path": "/",
                "password_last_used": minutes_ago(r, 60, 60 * 1440) if console else None, "owner_user_id": f"user:okta:{name.removesuffix('-cli')}" if name.endswith("-cli") else None,
                "purpose": "personal CLI access" if name.endswith("-cli") else ("break-glass" if "breakglass" in name else "service integration"),
            },
            source=SOURCE_WIZ, source_id=name, first_seen=created, account=acct_key, kind="iamuser",
        )
        inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], uid, source=SOURCE_WIZ, first_seen=created)
        b.ident.users.append(uid)
        for pol in policies:
            b.attach(uid, b.managed(acct_key, pol))
        if name.endswith("-cli") and inv.has(f"user:okta:{name.removesuffix('-cli')}"):
            inv.add_edge("MAPS_TO", f"user:okta:{name.removesuffix('-cli')}", uid, {"via": "static"}, source=SOURCE_OKTA)
        if name == "mreyes-cli":
            inv.add_edge("MAPS_TO", sc.USER_MREYES, uid, {"via": "static"}, source=SOURCE_OKTA)
        if name == "jokafor-cli":
            inv.add_edge("MAPS_TO", sc.USER_JOKAFOR, uid, {"via": "static"}, source=SOURCE_OKTA)
        for k in range(keys):
            key_id = "AKIA" + "".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
            age = r.choice([3, 12, 30, 45, 61, 88, 95, 120, 180, 260, 400, 730]) if k == 0 else r.choice([200, 300, 400, 500, 800])
            status = "active" if (k == 0 or r.random() < 0.5) else "inactive"
            last_used = minutes_ago(r, 30, 20 * 1440) if status == "active" and r.random() < 0.8 else (days_ago(r, 30, 300) if r.random() < 0.6 else None)
            kid = f"accesskey:aws:{key_id}"
            inv.add_node(
                kid, "AccessKey", key_id,
                {"provider": "aws", "account_id": ACCOUNT_ID[acct_key], "owner_id": uid, "status": status, "age_days": age, "last_used": last_used, "last_used_service": r.choice(["s3", "sts", "ec2", "rds", "lambda", "secretsmanager"]) if last_used else None, "last_used_region": "us-east-1" if last_used else None},
                source=SOURCE_WIZ, source_id=key_id, first_seen=days_ago(r, age, age), account=acct_key, kind="accesskey",
            )
            inv.add_edge("HAS_ACCESS_KEY", uid, kid, source=SOURCE_WIZ)
            b.ident.keys.append(kid)
        if name == "breakglass-admin":
            b.can_assume(uid, b.ident.role_by_key[("hub", "prod", "breakglass")])
        if name == "terraform-cloud":
            for acct2 in ("prod", "shared", "staging", "dev", "data", "corp"):
                b.can_assume(uid, f"role:aws:{ACCOUNT_ID[acct2]}:LarkspurTerraformRole")
    # a secret holding a legacy IAM user's keys (secret -> IamUser)
    if inv.has("iamuser:aws:222222222222:svc-ci-legacy"):
        sid = "secret:aws:222222222222:shared/ci/legacy-deploy-user-keys"
        inv.add_node(sid, "Secret", "shared/ci/legacy-deploy-user-keys", {"provider": "aws", "account_id": "222222222222", "secret_type": "api_key", "sensitivity": "high", "rotated_days_ago": 412, "grants_access_to": ["iamuser:aws:222222222222:svc-ci-legacy"], "environment": "prod", "rotation_enabled": False, "kms_key": "aws/secretsmanager", "app_id": "app:larkspur:ci-cd-pipeline"}, source=SOURCE_WIZ, first_seen="2025-07-26T10:00:00Z", account="shared", kind="secret", app="ci-cd-pipeline")
        inv.add_edge("CONTAINS", sc.ACCOUNTS["shared"]["id"], sid, source=SOURCE_WIZ)
        inv.add_edge("UNLOCKS", sid, "iamuser:aws:222222222222:svc-ci-legacy", {"credential_type": "aws_access_key"}, source=SOURCE_WIZ)
        b.est.secrets.append(sid)
        APP_BY_SLUG["ci-cd-pipeline"].resources.setdefault("secret", []).append(sid)


def _service_accounts(inv: Inventory, est: Estate, ident: Identity) -> None:
    r = rng("inventory.identity.svc-accounts")
    by_service: dict[str, list[str]] = {}
    for vm in est.vms:
        by_service.setdefault(inv.meta[vm].get("service", ""), []).append(vm)

    def add(system: str, name: str, host: str | None, purpose: str, privileged: bool, source: str = SOURCE_FALCON) -> None:
        sid = f"identity:{system}:{name}"
        if inv.has(sid):
            return
        inv.add_node(sid, "ServiceAccount", name, {"system": system, "host_id": host, "purpose": purpose, "privileged": privileged, "hostname": inv.props(host)["hostname"] if host else None, "shell": "/usr/sbin/nologin" if system == "linux" and not privileged else ("/bin/bash" if system == "linux" else None), "last_logon": days_ago(r, 0, 30)}, source=source, first_seen=days_ago(r, 30, 700))
        ident.service_accounts.append(sid)

    add("linux", "svc-finops-sftp", sc.BASTION_VM, "settlement-file SFTP for Finance Treasury", False)
    for name, service in LINUX_SVC:
        hosts = by_service.get(service, [])
        if hosts:
            add("linux", name, hosts[0], f"{name} service account on {inv.name(hosts[0])}", name in ("svc-deploy", "svc-backup-linux", "vault"))
    for name, service in WINDOWS_SVC:
        hosts = by_service.get(service, [])
        if hosts:
            add("windows", f"CORP\\{name}", hosts[0], f"{name} domain service account ({inv.name(hosts[0])})", name in ("svc-sql", "svc-backup", "svc-adconnect", "svc-exchange-hybrid"))
    for name in K8S_SVC:
        add("k8s", name, None, f"Kubernetes service account {name} (prod-eks)", name in ("argocd-server-sa", "external-secrets-sa", "karpenter-sa"), source=SOURCE_WIZ)
    for gname in ("fraud-train-sa", "vertex-endpoint-sa", "ml-notebook-sa"):
        hosts = by_service.get(gname.removesuffix("-sa"), [])
        add("gcp", gname, hosts[0] if hosts else None, f"GCE default service account for {gname.removesuffix('-sa')}", False, source=SOURCE_WIZ)
