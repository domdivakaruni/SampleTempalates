"""CSPM issues (~600 ``Alert`` nodes, ``source_system: cspm``) derived from the posture of the generated estate,
with ``ON_RESOURCE`` edges and a Wiz-shaped ``raw`` flat view. ``alert:cspm:iss-n002`` (public marketing bucket)
is produced exactly as docs/04 section 4 requires.
"""
from __future__ import annotations

import random
from datetime import timedelta
from typing import Any

from throughline.simulator import storyline_constants as sc
from throughline.simulator.catalog.cves import CVES
from throughline.simulator.common import NOW, parse_ts, rng, ts
from throughline.simulator.inventory._base import SOURCE_WIZ, Inventory
from throughline.simulator.inventory.cloud import Estate

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WIZ_TYPE = {
    "VirtualMachine": "VIRTUAL_MACHINE", "StorageBucket": "BUCKET", "Database": "DATABASE", "IamRole": "SERVICE_ACCOUNT", "IamUser": "USER_ACCOUNT",
    "SecurityGroup": "FIREWALL", "LoadBalancer": "LOAD_BALANCER", "ServerlessFunction": "SERVERLESS", "Workload": "CONTAINER_WORKLOAD",
    "KubernetesCluster": "KUBERNETES_CLUSTER", "AccessKey": "ACCESS_KEY", "Secret": "SECRET", "CloudAccount": "SUBSCRIPTION", "HumanUser": "USER_ACCOUNT",
}
PLATFORM = {"aws": "AWS", "gcp": "GCP", "azure": "Azure"}
TARGET_TOTAL = 600


class IssueSink:
    def __init__(self, inv: Inventory) -> None:
        self.inv = inv
        self.r = rng("inventory.issues")
        self.pending: list[dict[str, Any]] = []

    def add(self, resource: str, control: str, title: str, severity: str, description: str, remediation: str, *, category: str = "CLOUD_CONFIGURATION",
            techniques: list[str] | None = None, mandatory: bool = False, alert_id: str | None = None, detected_at: str | None = None, weight: float = 1.0) -> None:
        self.pending.append({
            "resource": resource, "control": control, "title": title, "severity": severity, "description": description, "remediation": remediation,
            "category": category, "techniques": techniques or [], "mandatory": mandatory, "alert_id": alert_id, "detected_at": detected_at, "weight": weight,
        })


def build_issues(inv: Inventory, est: Estate) -> int:
    sink = IssueSink(inv)
    _vm_issues(inv, sink)
    _bucket_issues(inv, sink)
    _database_issues(inv, sink)
    _secret_issues(inv, sink)
    _iam_issues(inv, sink)
    _network_issues(inv, sink)
    _function_issues(inv, sink)
    _k8s_issues(inv, sink)
    _lb_issues(inv, sink)
    _account_issues(inv, sink)
    return _emit(inv, sink)


# ---------------------------------------------------------------------------- generators


def _vm_issues(inv: Inventory, s: IssueSink) -> None:
    r = s.r
    for vm in inv.ids("VirtualMachine"):
        p = inv.props(vm)
        name = inv.name(vm)
        prod = p["environment"] == "prod"
        if p.get("ebs_encrypted") is False:
            s.add(vm, "wc-id-ebs-unencrypted", "EBS volume attached to instance is not encrypted", "medium" if prod else "low",
                  f"The root volume of {name} is not encrypted at rest.", "Enable EBS encryption by default and re-create the volume from an encrypted snapshot.", weight=0.8)
        if p.get("imdsv2_required") is False and (prod or r.random() < 0.5):
            s.add(vm, "wc-id-imdsv1", "EC2 instance allows IMDSv1 (session tokens not required)", "medium" if prod else "low",
                  f"{name} accepts IMDSv1 requests; credentials of its instance role can be read by any local process or SSRF.",
                  "Set HttpTokens=required on the instance metadata options.", techniques=["T1552.005"], mandatory=vm == sc.BASTION_VM, weight=0.55)
        if p.get("ami_age_days", 0) > 180 and r.random() < 0.3:
            s.add(vm, "wc-id-outdated-ami", "EC2 instance launched from an outdated AMI (>180 days)", "low",
                  f"{name} runs an AMI that is {p['ami_age_days']} days old.", "Rebuild from a current golden image.", weight=0.5)
        if p["has_edr_sensor"] is False and inv.meta[vm].get("stack") != "appliance":
            s.add(vm, "wc-id-no-edr", "Virtual machine without endpoint protection agent", "high" if prod else "medium",
                  f"No EDR sensor reports for {name} ({p['os']}).", "Install the Falcon sensor via SSM or rebuild from the hardened image.", mandatory=prod)
        exposed = p.get("exposure") == "internet"
        crit_cves = [c for c in inv.out(vm, "VULNERABLE_TO") if CVES[c.split(':', 1)[1]].cvss >= 9.0]
        sensitive = [t for t in inv.out(vm, "CAN_ACCESS") if inv.props(t).get("sensitivity") in ("high", "critical")]
        if exposed and crit_cves and sensitive:
            s.add(vm, "wc-id-toxic-exposed-vuln-data", "Toxic combination: internet-exposed VM with critical vulnerability and access to sensitive data", "critical",
                  f"{name} is reachable from the Internet on {', '.join(p.get('public_ports', []))}, is vulnerable to {', '.join(c.split(':', 1)[1] for c in crit_cves[:3])} and its role can reach {len(sensitive)} sensitive data stores.",
                  "Patch the vulnerable component, restrict ingress to the load balancer/WAF, and scope the instance role to the buckets it needs.",
                  category="TOXIC_COMBINATION", techniques=["T1190"], mandatory=True)
        elif exposed and crit_cves:
            s.add(vm, "wc-id-exposed-critical-vuln", "Publicly exposed VM with critical vulnerability", "high",
                  f"{name} is reachable from the Internet and vulnerable to {', '.join(c.split(':', 1)[1] for c in crit_cves[:3])}.",
                  "Patch the vulnerable component or remove the public exposure.", category="TOXIC_COMBINATION", techniques=["T1190"], mandatory=True)
        elif exposed and any(port in ("22", "3389") for port in p.get("public_ports", [])):
            s.add(vm, "wc-id-exposed-mgmt-port", "Management port (SSH/RDP) exposed to the Internet", "high",
                  f"{name} accepts SSH/RDP from 0.0.0.0/0.", "Restrict the security group to the VPN CIDR or use Session Manager.", mandatory=True)
        admin_roles = [rid for rid in inv.out(vm, "HAS_ROLE") if inv.props(rid).get("is_admin")]
        if admin_roles and not p["is_k8s_node"]:
            s.add(vm, "wc-id-admin-instance-role", "EC2 instance with administrative IAM role", "high" if exposed else "medium",
                  f"{name} carries the administrative role {inv.name(admin_roles[0])}.", "Replace the role with a least-privilege policy.", weight=0.9)
        if p.get("is_k8s_node") and r.random() < 0.05:
            s.add(vm, "wc-id-node-outdated-kubelet", "EKS worker node running an outdated kubelet", "low", f"{name} runs a kubelet two minor versions behind the control plane.", "Roll the node group.", weight=0.6)


def _bucket_issues(inv: Inventory, s: IssueSink) -> None:
    r = s.r
    for bid in inv.ids("StorageBucket"):
        p = inv.props(bid)
        name = inv.name(bid)
        if p["public"]:
            is_marketing = bid == sc.MARKETING_BUCKET
            s.add(bid, "wc-id-s3-public-read", "S3 bucket allows public read", "critical",
                  f"Bucket {name} grants s3:GetObject to AllUsers through its bucket policy/ACL.",
                  "Enable S3 Block Public Access and serve static content through CloudFront with an origin access control.",
                  techniques=["T1530"], mandatory=True, alert_id=sc.ALERT_N["n002"][0] if is_marketing else None, detected_at=sc.ALERT_N["n002"][1] if is_marketing else None)
        if not p["encrypted"]:
            s.add(bid, "wc-id-s3-no-encryption", "S3 bucket without default encryption", "medium" if p.get("sensitivity") in ("high", "critical") else "low",
                  f"Bucket {name} has no default server-side encryption configuration.", "Enable SSE-KMS default encryption.", weight=0.8)
        if p.get("crown_jewel") and not p["versioning"]:
            s.add(bid, "wc-id-s3-no-versioning", "Critical data bucket without versioning", "medium", f"Crown-jewel bucket {name} has versioning disabled.", "Enable versioning and MFA delete.", mandatory=True)
        if p.get("sensitivity") in ("high", "critical") and not p.get("access_logging") and r.random() < 0.8:
            s.add(bid, "wc-id-s3-no-access-logs", "Sensitive bucket without access logging", "low", f"Bucket {name} ({', '.join(p['data_classifications'])}) does not log object access.", "Enable server access logging or CloudTrail data events.", weight=0.7)
        if p["environment"] in ("staging", "dev") and any(c in ("PII", "PCI", "FINANCIAL") for c in p["data_classifications"]):
            s.add(bid, "wc-id-prod-data-nonprod", "Production data classification found in non-production bucket", "high",
                  f"Bucket {name} in {p['environment']} contains {', '.join(p['data_classifications'])} data.", "Mask or delete production copies outside the CDE.", mandatory=True)
        if "SECRETS" in p["data_classifications"] and p["public"] is False and r.random() < 0.5:
            s.add(bid, "wc-id-s3-secrets-broad-read", "Bucket containing secrets is readable by many principals", "high" if p["environment"] == "prod" else "medium",
                  f"{len(inv.inn(bid, 'CAN_ACCESS'))} principals can read {name}, which holds credentials/config secrets.", "Move secrets to Secrets Manager and tighten the bucket policy.", weight=0.9)


def _database_issues(inv: Inventory, s: IssueSink) -> None:
    for did in inv.ids("Database"):
        p = inv.props(did)
        name = inv.name(did)
        if p["public"]:
            s.add(did, "wc-id-rds-public", "RDS instance is publicly accessible", "critical" if p.get("sensitivity") in ("high", "critical") else "high",
                  f"Database {name} has PubliclyAccessible=true and a security group open to the Internet on {p.get('port')}.", "Disable public accessibility and move the instance to private subnets.", mandatory=True)
        if not p["encrypted"]:
            s.add(did, "wc-id-rds-unencrypted", "RDS storage is not encrypted", "high" if p.get("sensitivity") in ("high", "critical") else "medium", f"Database {name} storage is not encrypted at rest.", "Snapshot, copy with encryption and restore.", mandatory=True)
        if p.get("backup_retention_days") == 0 and p["engine"] not in ("dynamodb", "bigquery"):
            s.add(did, "wc-id-rds-no-backups", "Database automated backups disabled", "medium" if p["environment"] == "prod" else "low", f"Database {name} has a backup retention of 0 days.", "Set retention to at least 7 days.", weight=0.8)
        if p.get("crown_jewel") and not p.get("multi_az"):
            s.add(did, "wc-id-rds-single-az", "Crown-jewel database without Multi-AZ", "low", f"Database {name} runs in a single availability zone.", "Enable Multi-AZ.", weight=0.6)


def _secret_issues(inv: Inventory, s: IssueSink) -> None:
    for sid in inv.ids("Secret"):
        p = inv.props(sid)
        name = inv.name(sid)
        if p["rotated_days_ago"] > 365:
            s.add(sid, "wc-id-secret-stale", "Secret not rotated in over a year", "medium" if p["sensitivity"] in ("high", "critical") else "low", f"Secret {name} was last rotated {p['rotated_days_ago']} days ago.", "Enable automatic rotation.", weight=0.9)
        elif p["rotated_days_ago"] > 90 and p["sensitivity"] == "critical":
            s.add(sid, "wc-id-secret-rotation-overdue", "Critical secret rotation overdue (>90 days)", "high", f"Critical secret {name} was rotated {p['rotated_days_ago']} days ago.", "Rotate now and enable automatic rotation.", mandatory=True)
        readers = len(inv.inn(sid, "CAN_ACCESS"))
        if p["sensitivity"] == "critical" and readers > 12:
            s.add(sid, "wc-id-secret-broad-access", "Critical secret readable by many principals", "high", f"{readers} principals and workloads can read {name}.", "Scope secretsmanager:GetSecretValue to the owning workload.", weight=0.9)


def _iam_issues(inv: Inventory, s: IssueSink) -> None:
    r = s.r
    for uid in inv.ids("IamUser"):
        p = inv.props(uid)
        name = inv.name(uid)
        if p["console_access"] and not p["mfa_enabled"]:
            s.add(uid, "wc-id-iam-user-no-mfa", "IAM user with console access and no MFA", "high", f"IAM user {name} can sign in to the console without MFA.", "Enforce MFA or remove console access.", mandatory=True)
        if p["is_admin"]:
            s.add(uid, "wc-id-iam-user-admin", "IAM user with administrative privileges", "high", f"IAM user {name} has AdministratorAccess attached.", "Move to SSO roles; delete long-lived admin users.", mandatory=True)
        for kid in inv.out(uid, "HAS_ACCESS_KEY"):
            k = inv.props(kid)
            if k["status"] == "active" and k["age_days"] > 90:
                s.add(kid, "wc-id-access-key-old", "IAM access key older than 90 days", "medium" if k["age_days"] < 365 else "high", f"Access key {inv.name(kid)} of {name} is {k['age_days']} days old.", "Rotate the key and set a 90-day rotation reminder.", weight=0.9)
            elif k["status"] == "active" and not k.get("last_used") and r.random() < 0.7:
                s.add(kid, "wc-id-access-key-unused", "Active access key never used", "low", f"Access key {inv.name(kid)} of {name} is active but has never been used.", "Deactivate and delete unused keys.", weight=0.6)
    for rid in inv.ids("IamRole"):
        p = inv.props(rid)
        name = inv.name(rid)
        if p.get("path") == "/aws-service-role/":
            continue
        pols = inv.out(rid, "HAS_POLICY")
        if any(inv.props(pid)["wildcard_action"] and inv.props(pid)["wildcard_resource"] and not inv.props(pid).get("aws_managed") for pid in pols):
            s.add(rid, "wc-id-iam-policy-full-admin", "IAM policy allows full administrative privileges (*:*)", "high", f"Role {name} has a customer-managed policy granting *:* on *.", "Replace with scoped actions and resources.", mandatory=True)
        elif any(inv.props(pid)["wildcard_resource"] and "admin" in inv.props(pid)["access_levels"] and not inv.props(pid).get("aws_managed") for pid in pols):
            s.add(rid, "wc-id-iam-policy-service-wildcard", "IAM policy grants full service access on all resources", "medium", f"Role {name} carries a legacy policy with s3:* on *.", "Scope the policy to the buckets the workload uses.", mandatory=True)
        if any(tp.endswith(":root") for tp in p.get("trust_principals", [])) and p["role_type"] in ("human", "service", "cross-account"):
            s.add(rid, "wc-id-iam-role-root-trust", "IAM role can be assumed by any principal in the account", "medium", f"Role {name} trusts the account root principal.", "Restrict the trust policy to specific principals.", weight=0.9)
        if any("999999999999" in tp for tp in p.get("trust_principals", [])):
            s.add(rid, "wc-id-iam-role-external-trust", "IAM role trusts an external AWS account", "medium", f"Role {name} can be assumed from account 999999999999 (CSPM vendor).", "Confirm the external ID condition and review quarterly.", weight=0.5)
        if p.get("last_used") is None and r.random() < 0.8:
            s.add(rid, "wc-id-iam-role-unused", "IAM role unused for 90+ days", "low", f"Role {name} has no recorded activity.", "Delete unused roles.", weight=0.7)
        if p.get("is_admin") and p["role_type"] == "instance":
            s.add(rid, "wc-id-iam-admin-instance-role", "Administrative policy attached to an instance role", "high", f"Instance role {name} grants administrator access to EC2 workloads.", "Scope the role to least privilege.", mandatory=True)


def _network_issues(inv: Inventory, s: IssueSink) -> None:
    for sg in inv.ids("SecurityGroup"):
        p = inv.props(sg)
        if not p["open_to_internet"]:
            continue
        ports = set(p["internet_ports"])
        attached = inv.inn(sg, "HAS_SECURITY_GROUP")
        env = inv.props(attached[0])["environment"] if attached else "unknown"
        if "0-65535" in ports:
            s.add(sg, "wc-id-sg-open-all", "Security group allows all traffic from 0.0.0.0/0", "critical", f"Security group {inv.name(sg)} allows every port from the Internet.", "Remove the open rule.", mandatory=True)
        if "22" in ports:
            s.add(sg, "wc-id-sg-open-ssh", "Security group allows SSH (22) from 0.0.0.0/0", "high" if env == "prod" else "medium", f"Security group {inv.name(sg)} ({env}) allows SSH from any address; attached to {len(attached)} resource(s).", "Restrict SSH to the VPN CIDR 10.99.0.0/16.", mandatory=True)
        if "3389" in ports:
            s.add(sg, "wc-id-sg-open-rdp", "Security group allows RDP (3389) from 0.0.0.0/0", "high", f"Security group {inv.name(sg)} allows RDP from any address.", "Restrict RDP to the VPN CIDR.", mandatory=True)
        if ports & {"5432", "3306", "6379", "1433"}:
            s.add(sg, "wc-id-sg-open-db", "Security group exposes a database port to the Internet", "critical", f"Security group {inv.name(sg)} allows database ports {sorted(ports & {'5432', '3306', '6379', '1433'})} from 0.0.0.0/0.", "Remove the rule and use private connectivity.", mandatory=True)
        if ports & {"8080", "8443", "9000", "3000"} and attached:
            s.add(sg, "wc-id-sg-open-app-port", "Security group exposes an application port directly to the Internet", "medium", f"Security group {inv.name(sg)} exposes {sorted(ports & {'8080', '8443', '9000', '3000'})} without a load balancer or WAF.", "Front the service with an ALB + WAF and restrict the SG to the ALB.", mandatory=True)


def _function_issues(inv: Inventory, s: IssueSink) -> None:
    r = s.r
    for fid in inv.ids("ServerlessFunction"):
        p = inv.props(fid)
        name = inv.name(fid)
        if p["url_enabled"] and p.get("url_auth_type") == "NONE":
            s.add(fid, "wc-id-lambda-url-noauth", "Lambda function URL without authentication", "high", f"Function {name} exposes a function URL with AuthType NONE.", "Require IAM auth or front the function with API Gateway.", mandatory=True)
        crit = [c for c in inv.out(fid, "VULNERABLE_TO") if CVES[c.split(':', 1)[1]].cvss >= 9.0]
        sensitive = [t for t in inv.out(fid, "CAN_ACCESS") if inv.props(t).get("sensitivity") in ("high", "critical")]
        if p["url_enabled"] and crit and sensitive:
            s.add(fid, "wc-id-toxic-exposed-function-data", "Toxic combination: internet-exposed function with critical vulnerability and access to sensitive data", "critical",
                  f"Function {name} is reachable through its function URL, bundles a dependency vulnerable to {', '.join(c.split(':', 1)[1] for c in crit[:3])} and its execution role can reach {len(sensitive)} sensitive data stores.",
                  "Update the vulnerable dependency, require IAM auth on the URL and scope the execution role.", category="TOXIC_COMBINATION", techniques=["T1190"], mandatory=True)
        elif p["url_enabled"] and crit:
            s.add(fid, "wc-id-exposed-function-vuln", "Publicly exposed function with critical vulnerability", "high", f"Function {name} is reachable through its function URL and bundles a dependency vulnerable to {', '.join(c.split(':', 1)[1] for c in crit[:3])}.", "Update the vulnerable dependency.", category="TOXIC_COMBINATION", techniques=["T1190"], mandatory=True)
        if p["runtime"] in ("python3.9", "nodejs18.x", "java11") and r.random() < 0.7:
            s.add(fid, "wc-id-lambda-deprecated-runtime", "Lambda function uses a deprecated runtime", "low", f"Function {name} runs on {p['runtime']}.", "Upgrade the runtime.", weight=0.6)
        if p.get("env_var_secrets"):
            s.add(fid, "wc-id-lambda-env-secrets", "Lambda environment variables may contain secrets", "medium", f"Function {name} has environment variables named like credentials (DB_PASSWORD, API_KEY).", "Move secrets to Secrets Manager.", weight=0.9)


def _k8s_issues(inv: Inventory, s: IssueSink) -> None:
    for cid in inv.ids("KubernetesCluster"):
        p = inv.props(cid)
        if p["public_endpoint"]:
            s.add(cid, "wc-id-eks-public-endpoint", "EKS cluster API endpoint is publicly accessible", "high", f"Cluster {inv.name(cid)} exposes its API server endpoint to the Internet.", "Disable public endpoint access or restrict the CIDR allow-list.", mandatory=True)
        if not p.get("logging_enabled", True):
            s.add(cid, "wc-id-eks-no-logging", "EKS control plane logging disabled", "low", f"Cluster {inv.name(cid)} does not ship audit/authenticator logs.", "Enable control plane logging.", mandatory=True)
    for wid in inv.ids("Workload"):
        p = inv.props(wid)
        if p["privileged"]:
            s.add(wid, "wc-id-k8s-privileged", "Container runs in privileged mode", "medium", f"Workload {inv.name(wid)} runs privileged containers.", "Drop privileged mode; use specific capabilities.", weight=0.8)
        crit = [c for c in inv.out(wid, "VULNERABLE_TO") if CVES[c.split(':', 1)[1]].cvss >= 9.0]
        sensitive = [t for t in inv.out(wid, "CAN_ACCESS") if inv.props(t).get("sensitivity") in ("high", "critical")]
        if p.get("exposure") == "internet" and crit and sensitive:
            s.add(wid, "wc-id-toxic-exposed-workload-data", "Toxic combination: internet-exposed workload with critical vulnerability and access to sensitive data", "critical",
                  f"Workload {inv.name(wid)} is exposed through a load balancer, is vulnerable to {', '.join(c.split(':', 1)[1] for c in crit[:3])} and its IRSA role can reach {len(sensitive)} sensitive data stores.",
                  "Rebuild the image with patched packages and scope the IRSA role to the data the service needs.", category="TOXIC_COMBINATION", techniques=["T1190"], mandatory=True)
        elif p.get("exposure") == "internet" and crit:
            s.add(wid, "wc-id-exposed-workload-vuln", "Publicly exposed workload with critical vulnerability", "high", f"Workload {inv.name(wid)} is exposed through a load balancer and vulnerable to {', '.join(c.split(':', 1)[1] for c in crit[:3])}.", "Rebuild the image with patched packages.", category="TOXIC_COMBINATION", techniques=["T1190"], mandatory=True)


def _lb_issues(inv: Inventory, s: IssueSink) -> None:
    for lb in inv.ids("LoadBalancer"):
        p = inv.props(lb)
        if p.get("tls_policy") == "ELBSecurityPolicy-2016-08":
            s.add(lb, "wc-id-alb-old-tls", "Load balancer uses an outdated TLS security policy", "medium", f"{inv.name(lb)} negotiates TLS 1.0/1.1 (ELBSecurityPolicy-2016-08).", "Switch to a TLS 1.2+/1.3 policy.", mandatory=True)
        if p["scheme"] == "internet-facing" and not p.get("waf_attached"):
            s.add(lb, "wc-id-alb-no-waf", "Internet-facing load balancer without WAF", "medium", f"{inv.name(lb)} has no AWS WAF web ACL associated.", "Associate the standard web ACL.", mandatory=True)
        if not p.get("access_logs_enabled"):
            s.add(lb, "wc-id-alb-no-logs", "Load balancer access logging disabled", "low", f"{inv.name(lb)} does not write access logs.", "Enable access logs to the alb-access-logs bucket.", weight=0.7)


def _account_issues(inv: Inventory, s: IssueSink) -> None:
    acct_issues = [
        (sc.ACCOUNTS["dev"]["id"], "wc-id-root-no-hw-mfa", "Root account without hardware MFA", "high", "The root user of larkspur-dev-sandbox uses a virtual MFA device.", "Register a hardware MFA token for the root user."),
        (sc.ACCOUNTS["corp"]["id"], "wc-id-root-no-hw-mfa", "Root account without hardware MFA", "high", "The root user of larkspur-corp-it uses a virtual MFA device.", "Register a hardware MFA token for the root user."),
        (sc.ACCOUNTS["dev"]["id"], "wc-id-cloudtrail-partial", "CloudTrail not enabled in all regions", "medium", "larkspur-dev-sandbox has a single-region trail.", "Create an organization trail covering all regions."),
        (sc.ACCOUNTS["staging"]["id"], "wc-id-config-disabled", "AWS Config recorder disabled", "low", "AWS Config is not recording in us-east-2.", "Enable the recorder."),
        (sc.ACCOUNTS["corp"]["id"], "wc-id-config-disabled", "AWS Config recorder disabled", "low", "AWS Config is not recording in larkspur-corp-it.", "Enable the recorder."),
        (sc.ACCOUNTS["dev"]["id"], "wc-id-weak-password-policy", "Account password policy does not meet baseline", "low", "Minimum length 8, no symbol requirement.", "Apply the baseline password policy."),
        (sc.ACCOUNTS["data"]["id"], "wc-id-guardduty-disabled", "GuardDuty not enabled in a region", "medium", "GuardDuty is disabled in us-west-2 for larkspur-data-platform.", "Enable GuardDuty organization-wide."),
        (sc.ACCOUNTS["gcp_ml"]["id"], "wc-id-gcp-os-login", "GCP project without OS Login enforced", "low", "Project larkspur-ml-fraud allows metadata-based SSH keys.", "Enforce OS Login at the project level."),
        (sc.ACCOUNTS["azure_corp"]["id"], "wc-id-azure-defender", "Defender for Cloud not enabled for servers", "medium", "Subscription larkspur-corp-azure lacks Defender for Servers plan.", "Enable Defender for Servers P1."),
    ]
    for res, control, title, sev, desc, rem in acct_issues:
        s.add(res, control, title, sev, desc, rem, mandatory=True)


# ---------------------------------------------------------------------------- emission


def _emit(inv: Inventory, s: IssueSink) -> int:
    r = random.Random(s.r.random())
    mandatory = [i for i in s.pending if i["mandatory"]]
    optional = [i for i in s.pending if not i["mandatory"]]
    budget = max(0, TARGET_TOTAL - len(mandatory))
    if len(optional) > budget:
        # weighted deterministic sub-sample
        keyed = sorted(optional, key=lambda i: -(r.random() * i["weight"]))
        optional = keyed[:budget]
    selected = mandatory + optional
    # stable ordering: by resource id then control so ids are deterministic
    selected.sort(key=lambda i: (i["resource"], i["control"]))
    n = 1001
    count = 0
    for issue in selected:
        rr = rng(f"inventory.issues.{issue['resource']}.{issue['control']}")
        resource = issue["resource"]
        label = inv.label(resource)
        rp = inv.props(resource)
        alert_id = issue["alert_id"] or f"alert:cspm:iss-{n:04d}"
        if not issue["alert_id"]:
            n += 1
        detected = issue["detected_at"] or ts(NOW - timedelta(minutes=rr.randint(60, 45 * 1440)))
        status = "new" if rr.random() < 0.85 else "in_progress"
        severity = issue["severity"]
        wiz_id = alert_id.split(":")[-1]
        provider = rp.get("provider", "aws")
        raw = {
            "id": wiz_id,
            "type": issue["category"],
            "severity": severity.upper(),
            "status": "OPEN" if status == "new" else "IN_PROGRESS",
            "createdAt": detected,
            "updatedAt": ts(min(parse_ts(detected) + timedelta(hours=rr.randint(1, 72)), NOW - timedelta(minutes=5))),
            "dueAt": ts(parse_ts(detected) + timedelta(days={"critical": 7, "high": 14, "medium": 30, "low": 90, "informational": 180}[severity])),
            "sourceRule": {"id": issue["control"], "name": issue["title"], "controlDescription": issue["description"]},
            "entitySnapshot": {
                "id": inv.nodes[resource]["source_id"], "graphEntityId": resource, "type": WIZ_TYPE.get(label, label.upper()), "name": inv.name(resource),
                "nativeType": _native_type(label, rp), "cloudPlatform": PLATFORM.get(provider, "AWS"), "subscriptionExternalId": rp.get("account_id"),
                "region": rp.get("region"), "tags": rp.get("tags") if isinstance(rp.get("tags"), dict) else {},
            },
            "projects": [{"id": f"proj-{(rp.get('app_id') or 'app:larkspur:shared').split(':')[-1]}", "name": (rp.get("app_id") or "shared").split(":")[-1]}],
            "description": issue["description"],
            "remediationInstructions": issue["remediation"],
            "resolutionReason": None,
            "notes": [],
        }
        inv.add_node(
            alert_id, "Alert", issue["title"],
            {
                "source_system": "cspm", "alert_type": "issue", "title": issue["title"], "description": issue["description"], "vendor_severity": severity,
                "vendor_severity_rank": SEVERITY_RANK[severity], "status": status, "detected_at": detected, "techniques": issue["techniques"], "tactic": None,
                "entity_id": resource, "entity_label": label, "hostname": inv.name(resource) if label == "VirtualMachine" else None,
                "user": inv.name(resource) if label in ("IamUser", "HumanUser") else None, "vendor_incident_id": None, "change_ticket": None, "raw": raw,
                "contextual_score": None, "contextual_band": None, "score_breakdown": None, "storyline_id": None, "graph_reasons": [], "ti_actor_ids": [],
                "ioc_match_count": 0, "reaches_crown_jewel": None, "on_attack_path": None, "control_id": issue["control"], "issue_category": issue["category"],
                "remediation": issue["remediation"], "account_id": rp.get("account_id"), "environment": rp.get("environment"),
            },
            source=SOURCE_WIZ, source_id=wiz_id, first_seen=detected, last_seen=raw["updatedAt"], kind="alert", resource=resource,
        )
        inv.add_edge("ON_RESOURCE", alert_id, resource, source=SOURCE_WIZ, first_seen=detected)
        count += 1
    inv.storyline["alert_iss_n002"] = sc.ALERT_N["n002"][0]
    return count


def _native_type(label: str, props: dict[str, Any]) -> str:
    return {
        "VirtualMachine": "ec2Instance", "StorageBucket": "s3Bucket", "Database": f"rds{props.get('engine', '')}", "IamRole": "iamRole", "IamUser": "iamUser",
        "SecurityGroup": "ec2SecurityGroup", "LoadBalancer": "elbv2LoadBalancer", "ServerlessFunction": "lambdaFunction", "Workload": "k8sDeployment",
        "KubernetesCluster": "eksCluster", "AccessKey": "iamAccessKey", "Secret": "secretsManagerSecret", "CloudAccount": "awsAccount",
    }.get(label, label)
