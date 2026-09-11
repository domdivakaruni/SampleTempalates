"""Cloud estate: 8 accounts, ~30 VPCs, subnets, security groups, load balancers, ~650 VMs (incl. EKS nodes),
EKS clusters and workloads, container images, serverless functions, buckets, databases and secrets.

Placement follows the application catalog in ``business.py``; the storyline resources from
``storyline_constants`` are produced through explicit overrides (``NAMED_VMS``) so their ids, IPs, subnets and
security groups are exact.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from throughline.simulator import storyline_constants as sc
from throughline.simulator.common import pick, rng

from throughline.simulator.inventory._base import (
    ANYWHERE,
    INTERNET_ID,
    SOURCE_WIZ,
    VPN_CIDR,
    Inventory,
    IpPlan,
    aws_instance_id,
    aws_resource_id,
    days_ago,
    digits,
    hexid,
    internet_ports,
    pseudo_guid,
    rule,
)
from throughline.simulator.inventory.business import APP_BY_SLUG, AppSpec, Bkt, Db, Sec, Svc
from throughline.simulator.inventory.world import World

# ---------------------------------------------------------------------------- static network plan


@dataclass(frozen=True)
class VpcSpec:
    name: str
    account: str
    cidr: str
    region: str
    subnets: tuple[tuple[str, str, str], ...]  # (suffix, cidr, kind) kind: public | private | isolated | db


def _std(base: str, extra: tuple[tuple[str, str, str], ...] = ()) -> tuple[tuple[str, str, str], ...]:
    return (("a", f"{base}.0.0/24", "public"), ("b", f"{base}.1.0/24", "private"), ("c", f"{base}.2.0/24", "private")) + extra


VPCS: list[VpcSpec] = [
    VpcSpec("prod-payments", "prod", "10.10.0.0/16", "us-east-1", (("a", "10.10.1.0/24", "private"), ("b", "10.10.2.0/24", "private"), ("edge-a", "10.10.3.0/24", "public"), ("db-a", "10.10.4.0/24", "db"))),
    VpcSpec("prod-wallet", "prod", "10.11.0.0/16", "us-east-1", _std("10.11", (("db-a", "10.11.4.0/24", "db"),))),
    VpcSpec("prod-baas", "prod", "10.12.0.0/16", "us-east-1", _std("10.12", (("db-a", "10.12.4.0/24", "db"),))),
    VpcSpec("prod-eks", "prod", "10.13.0.0/16", "us-east-1", (("a", "10.13.0.0/24", "public"), ("b", "10.13.16.0/20", "private"), ("c", "10.13.32.0/20", "private"))),
    VpcSpec("prod-data-services", "prod", "10.14.0.0/16", "us-east-1", _std("10.14", (("db-a", "10.14.4.0/24", "db"),))),
    VpcSpec("prod-dr", "prod", "10.15.0.0/16", "us-west-2", _std("10.15")),
    VpcSpec("prod-edge", "prod", "10.16.0.0/16", "us-east-1", _std("10.16")),
    VpcSpec("prod-ledger", "prod", "10.17.0.0/16", "us-east-1", (("a", "10.17.1.0/24", "private"), ("b", "10.17.2.0/24", "private"), ("db-a", "10.17.4.0/24", "db"))),
    VpcSpec("shared-mgmt", "shared", "10.20.0.0/16", "us-east-1", (("a", "10.20.0.0/24", "public"), ("b", "10.20.1.0/24", "private"), ("c", "10.20.2.0/24", "private"), ("tools-a", "10.20.5.0/24", "private"))),
    VpcSpec("shared-cicd", "shared", "10.21.0.0/16", "us-east-1", _std("10.21")),
    VpcSpec("shared-monitoring", "shared", "10.22.0.0/16", "us-east-1", _std("10.22")),
    VpcSpec("shared-edge", "shared", "10.23.0.0/16", "us-east-1", _std("10.23")),
    VpcSpec("staging-apps", "staging", "10.30.0.0/16", "us-east-1", _std("10.30", (("db-a", "10.30.4.0/24", "db"),))),
    VpcSpec("staging-eks", "staging", "10.31.0.0/16", "us-east-1", (("a", "10.31.0.0/24", "public"), ("b", "10.31.16.0/20", "private"), ("c", "10.31.32.0/20", "private"))),
    VpcSpec("staging-data", "staging", "10.32.0.0/16", "us-east-1", _std("10.32", (("db-a", "10.32.4.0/24", "db"),))),
    VpcSpec("staging-edge", "staging", "10.33.0.0/16", "us-east-1", _std("10.33")),
    VpcSpec("dev-sandbox", "dev", "10.50.0.0/16", "us-east-1", _std("10.50", (("isolated-a", "10.50.9.0/24", "isolated"),))),
    VpcSpec("dev-experiments", "dev", "10.51.0.0/16", "us-east-1", _std("10.51")),
    VpcSpec("dev-isolated", "dev", "10.52.0.0/16", "us-east-2", (("a", "10.52.0.0/24", "isolated"), ("b", "10.52.1.0/24", "isolated"))),
    VpcSpec("dev-mobile", "dev", "10.53.0.0/16", "us-east-1", _std("10.53")),
    VpcSpec("data-lake", "data", "10.60.0.0/16", "us-east-1", _std("10.60")),
    VpcSpec("data-eks", "data", "10.61.0.0/16", "us-east-1", (("a", "10.61.0.0/24", "public"), ("b", "10.61.16.0/20", "private"), ("c", "10.61.32.0/20", "private"))),
    VpcSpec("data-warehouse", "data", "10.62.0.0/16", "us-east-1", _std("10.62", (("db-a", "10.62.4.0/24", "db"),))),
    VpcSpec("data-jobs", "data", "10.63.0.0/16", "us-east-1", _std("10.63", (("db-a", "10.63.4.0/24", "db"),))),
    VpcSpec("corp-it", "corp", "10.70.0.0/16", "us-east-1", _std("10.70")),
    VpcSpec("corp-web", "corp", "10.71.0.0/16", "us-east-1", _std("10.71", (("db-a", "10.71.4.0/24", "db"),))),
    VpcSpec("corp-directory", "corp", "10.72.0.0/16", "us-east-1", (("a", "10.72.1.0/24", "private"), ("b", "10.72.2.0/24", "private"))),
    VpcSpec("ml-fraud-vpc", "gcp_ml", "10.80.0.0/16", "us-central1", _std("10.80")),
    VpcSpec("ml-fraud-data", "gcp_ml", "10.81.0.0/16", "us-central1", (("a", "10.81.1.0/24", "private"), ("b", "10.81.2.0/24", "private"))),
    VpcSpec("corp-azure-vnet", "azure_corp", "10.90.0.0/16", "eastus", _std("10.90", (("db-a", "10.90.4.0/24", "db"),))),
]
VPC_BY_NAME: dict[str, VpcSpec] = {v.name: v for v in VPCS}

CLUSTERS: dict[str, dict[str, Any]] = {
    "prod-eks": {"account": "prod", "vpc": "prod-eks", "version": "1.30", "environment": "prod", "nodes": 56, "public_endpoint": False},
    "staging-eks": {"account": "staging", "vpc": "staging-eks", "version": "1.31", "environment": "staging", "nodes": 28, "public_endpoint": True},
    "data-eks": {"account": "data", "vpc": "data-eks", "version": "1.29", "environment": "prod", "nodes": 36, "public_endpoint": False},
}

ENV_DOMAIN: dict[str, str] = {
    "prod": "prod", "shared": "shared", "staging": "staging", "dev": "dev", "data": "data", "corp": "corp", "gcp_ml": "ml",
    "azure_corp": "corpaz",
}
PROVIDER: dict[str, str] = {k: v["provider"] for k, v in sc.ACCOUNTS.items()}
ACCOUNT_ID: dict[str, str] = {k: v["account_id"] for k, v in sc.ACCOUNTS.items()}
ACCOUNT_ENV: dict[str, str] = {k: v["environment"] for k, v in sc.ACCOUNTS.items()}

OS_BY_STACK: dict[str, dict[str, float]] = {
    "java": {"Amazon Linux 2023": 0.5, "Ubuntu 22.04": 0.3, "RHEL 9": 0.2},
    "node": {"Ubuntu 22.04": 0.5, "Ubuntu 24.04": 0.3, "Amazon Linux 2023": 0.2},
    "python": {"Ubuntu 22.04": 0.4, "Debian 12": 0.3, "Amazon Linux 2023": 0.3},
    "go": {"Amazon Linux 2023": 0.5, "Debian 12": 0.5},
    "os": {"Amazon Linux 2023": 0.6, "Ubuntu 22.04": 0.4},
    "windows": {"Windows Server 2022": 0.7, "Windows Server 2019": 0.3},
    "appliance": {"Appliance OS": 1.0},
}
TYPES_BY_STACK: dict[str, list[str]] = {
    "java": ["m6i.xlarge", "c6i.xlarge", "m6i.2xlarge", "r6i.xlarge"],
    "node": ["t3.large", "m6i.large", "c6i.large"],
    "python": ["r6i.xlarge", "m6i.xlarge", "m6i.2xlarge"],
    "go": ["c6i.large", "m6i.large", "c6i.xlarge"],
    "os": ["t3.medium", "t3.large", "m6i.large"],
    "windows": ["m5.large", "m5.xlarge", "r5.xlarge"],
    "appliance": ["m5.large", "c5.xlarge"],
}
GCP_TYPES = ["n2-standard-4", "n2-standard-8", "a2-highgpu-1g", "e2-standard-4"]
AZURE_TYPES = ["Standard_D4s_v5", "Standard_D8s_v5", "Standard_E4s_v5"]

# (app slug, env, service, index) -> overrides; env is "prod" for the primary placement
NAMED_VMS: dict[tuple[str, str, str, int], dict[str, Any]] = {
    ("platform-ssm-access", "prod", "bastion", 1): {
        "id": sc.BASTION_VM, "name": sc.BASTION_NAME, "hostname": sc.BASTION_HOSTNAME, "private_ip": sc.BASTION_PRIVATE_IP,
        "public_ip": sc.BASTION_PUBLIC_IP, "subnet": sc.BASTION_SUBNET, "sg_role": "bastion-ssh", "os": "Amazon Linux 2023",
        "instance_type": "t3.medium", "tags": {"role": "bastion", "owner": "platform-eng", "env": "prod"}, "criticality": "tier-2",
    },
    ("statement-render", "prod", "stmt-render", 1): {"name": "stmt-render-1a", "sg_id": sc.EDGE_SG, "os": "Ubuntu 22.04"},
    ("statement-render", "prod", "stmt-render", 2): {
        "id": sc.EDGE_VM, "name": sc.EDGE_NAME, "hostname": sc.EDGE_HOSTNAME, "private_ip": sc.EDGE_PRIVATE_IP, "public_ip": sc.EDGE_PUBLIC_IP,
        "sg_id": sc.EDGE_SG, "os": "Ubuntu 22.04", "instance_type": "c6i.xlarge", "criticality": "tier-1",
    },
    ("statement-render", "staging", "stmt-render", 1): {"id": sc.STG_EDGE_VM, "name": sc.STG_EDGE_NAME, "sg_id": "sg:aws:sg-0stg-edge-public-8080", "os": "Ubuntu 22.04"},
    ("dev-sandbox", "prod", "log4j-testbed", 1): {"id": sc.DEV_LOG4J_VM, "name": sc.DEV_LOG4J_NAME, "os": "Ubuntu 22.04"},
    ("dev-sandbox", "prod", "sandbox-runner", 3): {"id": sc.DEV_SANDBOX_VM, "name": sc.DEV_SANDBOX_NAME, "subnet_kind": "isolated", "os": "Ubuntu 22.04", "tags": {"env": "dev", "owner": "platform-eng", "purpose": "ci-runner-experiments"}},
    ("vulnerability-scanning", "prod", "vulnscan", 1): {"id": sc.SCANNER_VM, "name": sc.SCANNER_NAME, "private_ip": sc.SCANNER_IP, "subnet_suffix": "tools-a", "tags": {"role": "vulnerability-scanner", "owner": "security-eng", "env": "prod"}, "os": "Ubuntu 22.04"},
    ("file-services", "prod", "srv-fileshare", 1): {"id": sc.FILESHARE_VM, "name": sc.FILESHARE_NAME, "os": "Windows Server 2022", "tags": {"role": "fileshare", "owner": "corp-it", "env": "corp"}},
    ("remote-access-gateway", "prod", "ns-gw", 1): {"id": "vm:aws:i-0ns1c3d5e7f9a1b3c5", "name": "ns-gw-01"},
    ("corp-vpn", "prod", "vpn-pa", 1): {"id": "vm:aws:i-0pan2d4f6a8c0e2a4b", "name": "vpn-pa-01"},
    ("baas-gateway", "prod", "partner-api", 3): {"id": "vm:aws:i-0spr3e5a7c9b1d3f5e", "name": "partner-api-3", "direct": True},
    ("ci-cd-pipeline", "prod", "ci-jenkins", 1): {"id": "vm:aws:i-0jnk4f6b8d0c2e4a6c", "name": "ci-jenkins-01"},
    ("intranet-wiki", "prod", "wiki-confluence", 1): {"id": "vm:aws:i-0cnf5a7c9e1d3b5f7a", "name": "wiki-confluence-01"},
}

# workloads present in every EKS cluster: (namespace, name, kind, image repo, tag by cluster, exposed)
SYSTEM_WORKLOADS: list[tuple[str, str, str, str, dict[str, str]]] = [
    ("kube-system", "aws-node", "DaemonSet", "ecr-public:eks/amazon-k8s-cni", {"prod-eks": "v1.18.3", "staging-eks": "v1.18.3", "data-eks": "v1.16.0"}),
    ("kube-system", "kube-proxy", "DaemonSet", "ecr-public:eks/kube-proxy", {"prod-eks": "v1.30.0", "staging-eks": "v1.31.0", "data-eks": "v1.29.0"}),
    ("kube-system", "coredns", "Deployment", "ecr-public:eks/coredns", {"prod-eks": "v1.11.1", "staging-eks": "v1.11.1", "data-eks": "v1.10.1"}),
    ("kube-system", "ebs-csi-controller", "Deployment", "ecr-public:ebs-csi-driver/aws-ebs-csi-driver", {"prod-eks": "v1.32.0", "staging-eks": "v1.32.0", "data-eks": "v1.28.0"}),
    ("kube-system", "ebs-csi-node", "DaemonSet", "ecr-public:ebs-csi-driver/aws-ebs-csi-driver", {"prod-eks": "v1.32.0", "staging-eks": "v1.32.0", "data-eks": "v1.28.0"}),
    ("kube-system", "cluster-autoscaler", "Deployment", "registry-k8s:autoscaling/cluster-autoscaler", {"prod-eks": "v1.30.2", "staging-eks": "v1.31.0", "data-eks": "v1.29.3"}),
    ("kube-system", "metrics-server", "Deployment", "registry-k8s:metrics-server/metrics-server", {"prod-eks": "v0.7.1", "staging-eks": "v0.7.1", "data-eks": "v0.6.4"}),
    ("kube-system", "aws-load-balancer-controller", "Deployment", "ecr-public:eks/aws-load-balancer-controller", {"prod-eks": "v2.8.1", "staging-eks": "v2.8.1", "data-eks": "v2.7.2"}),
    ("ingress-nginx", "ingress-nginx-controller", "Deployment", "registry-k8s:ingress-nginx/controller", {"prod-eks": "v1.11.3", "staging-eks": "v1.10.1", "data-eks": "v1.10.1"}),
    ("cert-manager", "cert-manager", "Deployment", "quay:jetstack/cert-manager-controller", {"prod-eks": "v1.15.1", "staging-eks": "v1.15.1", "data-eks": "v1.14.4"}),
    ("monitoring", "prometheus-node-exporter", "DaemonSet", "quay:prometheus/node-exporter", {"prod-eks": "v1.8.1", "staging-eks": "v1.8.1", "data-eks": "v1.8.1"}),
    ("monitoring", "kube-state-metrics", "Deployment", "registry-k8s:kube-state-metrics/kube-state-metrics", {"prod-eks": "v2.12.0", "staging-eks": "v2.12.0", "data-eks": "v2.10.1"}),
    ("logging", "fluent-bit", "DaemonSet", "dockerhub:fluent/fluent-bit", {"prod-eks": "3.0.7", "staging-eks": "3.0.7", "data-eks": "2.2.2"}),
    ("argocd", "argocd-server", "Deployment", "quay:argoproj/argocd", {"prod-eks": "v2.11.4", "staging-eks": "v2.11.4", "data-eks": "v2.10.9"}),
    ("argocd", "argocd-repo-server", "Deployment", "quay:argoproj/argocd", {"prod-eks": "v2.11.4", "staging-eks": "v2.11.4", "data-eks": "v2.10.9"}),
    ("kafka", "kafka-broker", "StatefulSet", "dockerhub:bitnami/kafka", {"prod-eks": "3.7.0", "staging-eks": "3.7.0", "data-eks": "3.6.1"}),
    ("redis", "redis-cache", "StatefulSet", "dockerhub:library/redis", {"prod-eks": "7.2.6", "staging-eks": "7.2.4", "data-eks": "7.2.4"}),
    ("external-dns", "external-dns", "Deployment", "registry-k8s:external-dns/external-dns", {"prod-eks": "v0.14.2", "staging-eks": "v0.14.2", "data-eks": "v0.13.6"}),
    ("external-secrets", "external-secrets", "Deployment", "ghcr:external-secrets/external-secrets", {"prod-eks": "v0.9.20", "staging-eks": "v0.9.20", "data-eks": "v0.9.11"}),
    ("keda", "keda-operator", "Deployment", "ghcr:kedacore/keda", {"prod-eks": "2.14.1", "staging-eks": "2.14.1", "data-eks": "2.13.1"}),
    ("velero", "velero", "Deployment", "dockerhub:velero/velero", {"prod-eks": "v1.14.0", "staging-eks": "v1.14.0", "data-eks": "v1.13.2"}),
    ("kyverno", "kyverno-admission-controller", "Deployment", "ghcr:kyverno/kyverno", {"prod-eks": "v1.12.5", "staging-eks": "v1.12.5", "data-eks": "v1.11.4"}),
    ("monitoring", "otel-collector", "DaemonSet", "ghcr:open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib", {"prod-eks": "0.104.0", "staging-eks": "0.104.0", "data-eks": "0.98.0"}),
    ("karpenter", "karpenter", "Deployment", "ecr-public:karpenter/controller", {"prod-eks": "0.37.0", "staging-eks": "0.37.0", "data-eks": "0.35.4"}),
    ("monitoring", "grafana-agent", "DaemonSet", "dockerhub:grafana/agent", {"prod-eks": "v0.41.1", "staging-eks": "v0.41.1", "data-eks": "v0.40.3"}),
]
SYSTEM_IMAGE_STACK: dict[str, str] = {
    "ingress-nginx/controller": "ingress", "library/redis": "redis", "bitnami/kafka": "java", "argoproj/argocd": "go",
    "grafana/agent": "go", "velero/velero": "go",
}

REGISTRY_HOST: dict[str, str] = {
    "ecr": "222222222222.dkr.ecr.us-east-1.amazonaws.com", "ecr-public": "public.ecr.aws", "registry-k8s": "registry.k8s.io",
    "quay": "quay.io", "dockerhub": "docker.io", "ghcr": "ghcr.io",
}

UTILITY_FUNCTIONS: list[tuple[str, str]] = [
    ("log-shipper", "python3.12"), ("ebs-snapshot-cleanup", "python3.12"), ("cost-report", "python3.11"),
    ("sg-audit", "python3.12"), ("cloudwatch-to-slack", "nodejs20.x"),
]
ACCOUNT_BUCKETS: list[tuple[str, tuple[str, ...], str, float]] = [
    ("cloudtrail", ("INTERNAL",), "medium", 2400.0), ("config-snapshots", ("INTERNAL",), "low", 120.0),
    ("terraform-state", ("SECRETS", "INTERNAL"), "high", 0.6), ("alb-access-logs", ("INTERNAL",), "low", 900.0),
    ("backups", ("INTERNAL",), "medium", 5100.0), ("athena-results", ("INTERNAL",), "low", 33.0), ("flow-logs", ("INTERNAL",), "low", 1700.0),
]


@dataclass
class Estate:
    ip: IpPlan = field(default_factory=IpPlan)
    vpc_ids: dict[str, str] = field(default_factory=dict)
    subnets: dict[str, dict[str, list[str]]] = field(default_factory=dict)  # vpc -> kind -> subnet ids
    subnet_cidr: dict[str, str] = field(default_factory=dict)
    sg: dict[tuple[str, str], str] = field(default_factory=dict)  # (vpc, role) -> sg id
    cluster_ids: dict[str, str] = field(default_factory=dict)
    cluster_nodes: dict[str, list[str]] = field(default_factory=dict)
    vms: list[str] = field(default_factory=list)
    workloads: list[str] = field(default_factory=list)
    images: dict[str, dict[str, Any]] = field(default_factory=dict)
    functions: list[str] = field(default_factory=list)
    buckets: list[str] = field(default_factory=list)
    databases: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    lbs: list[str] = field(default_factory=list)
    service_vms: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)  # (app, env, service) -> vm ids
    service_workloads: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)
    service_functions: dict[tuple[str, str, str], str] = field(default_factory=dict)
    _pub_ip: int = 11

    def public_ip(self) -> str:
        while self._pub_ip in (24, 200, 201, 202, 203, 204, 205) or 240 <= self._pub_ip <= 247 or self._pub_ip > 254:
            self._pub_ip = 11 if self._pub_ip > 254 else self._pub_ip + 1
        ip = f"198.51.100.{self._pub_ip}"
        self._pub_ip += 1
        return ip


# ---------------------------------------------------------------------------- entry point


def build_cloud(inv: Inventory, world: World, apps: list[AppSpec]) -> Estate:
    est = Estate()
    est.ip.reserve(sc.BASTION_PRIVATE_IP)
    est.ip.reserve(sc.EDGE_PRIVATE_IP)
    est.ip.reserve(sc.SCANNER_IP)
    _accounts(inv)
    _network(inv, est)
    _clusters(inv, est, apps)
    for app in apps:
        _place_app(inv, est, app, app.account, "prod")
        if app.staging:
            _place_app(inv, est, app, "staging", "staging")
        if app.dev:
            _place_app(inv, est, app, "dev", "dev")
    _utility(inv, est, apps)
    _registry_tail(inv, est)
    _record_storyline(inv)
    return est


# ---------------------------------------------------------------------------- accounts, network


def _accounts(inv: Inventory) -> None:
    for key, acc in sc.ACCOUNTS.items():
        inv.add_node(
            acc["id"], "CloudAccount", acc["name"],
            {"provider": acc["provider"], "account_id": acc["account_id"], "environment": acc["environment"], "purpose": acc["purpose"], "key": key},
            source=SOURCE_WIZ, source_id=acc["account_id"], first_seen="2022-06-01T00:00:00Z",
        )
    inv.add_node(INTERNET_ID, "Internet", "Internet", {"description": "The public Internet (exposure root)"}, source=SOURCE_WIZ, source_id="internet", first_seen="2022-06-01T00:00:00Z")


def _network(inv: Inventory, est: Estate) -> None:
    r = rng("inventory.cloud.network")
    for v in VPCS:
        provider = PROVIDER[v.account]
        acct = ACCOUNT_ID[v.account]
        vpc_id = f"vpc:{provider}:{aws_resource_id('vpc', v.name)}" if provider == "aws" else f"vpc:{provider}:{v.name}"
        created = days_ago(r, 200, 1100)
        inv.add_node(
            vpc_id, "VPC", v.name,
            {"provider": provider, "account_id": acct, "cidr": v.cidr, "region": v.region, "environment": ACCOUNT_ENV[v.account], "tags": {"Name": v.name, "env": ACCOUNT_ENV[v.account]}},
            source=SOURCE_WIZ, first_seen=created, account=v.account,
        )
        inv.add_edge("CONTAINS", sc.ACCOUNTS[v.account]["id"], vpc_id, source=SOURCE_WIZ, first_seen=created)
        est.vpc_ids[v.name] = vpc_id
        kinds: dict[str, list[str]] = {"public": [], "private": [], "isolated": [], "db": []}
        for suffix, cidr, kind in v.subnets:
            if v.name == "shared-mgmt" and suffix == "a":
                sid = sc.BASTION_SUBNET
            elif provider == "aws":
                sid = f"subnet:aws:subnet-0{v.name}-{suffix}"
            else:
                sid = f"subnet:{provider}:{v.name}-{suffix}"
            az = v.region + suffix[-1]
            inv.add_node(
                sid, "Subnet", f"{v.name}-{suffix}",
                {"provider": provider, "account_id": acct, "cidr": cidr, "region": v.region, "public": kind == "public", "availability_zone": az, "vpc_id": vpc_id, "kind": kind, "has_nat_route": kind != "isolated"},
                source=SOURCE_WIZ, first_seen=created, account=v.account, vpc=v.name,
            )
            inv.add_edge("IN_VPC", sid, vpc_id, source=SOURCE_WIZ, first_seen=created)
            kinds[kind].append(sid)
            est.subnet_cidr[sid] = cidr
        if not kinds["private"]:
            kinds["private"] = kinds["isolated"] or kinds["public"]
        if not kinds["db"]:
            kinds["db"] = kinds["private"]
        est.subnets[v.name] = kinds
        # standard security groups per VPC
        vpc_cidr = v.cidr
        std = {
            "default": [rule(vpc_cidr, 0, 65535, "-1")],
            "app": [rule(vpc_cidr, 8080), rule(vpc_cidr, 8443), rule(vpc_cidr, 443)],
            "db": [rule(vpc_cidr, 5432), rule(vpc_cidr, 3306), rule(vpc_cidr, 6379)],
            "mgmt-ssh": [rule(VPN_CIDR, 22), rule(VPN_CIDR, 3389)],
            "web-public": [rule(ANYWHERE, 443), rule(ANYWHERE, 80)],
        }
        for role_name, rules in std.items():
            if role_name == "web-public" and v.name in ("dev-isolated", "corp-directory", "ml-fraud-data", "prod-ledger"):
                continue
            _sg(inv, est, v, role_name, rules, created)
    # special security groups
    shared = VPC_BY_NAME["shared-mgmt"]
    _sg(inv, est, shared, "bastion-ssh", [rule(VPN_CIDR, 22)], "2025-11-02T10:00:00Z", description="SSH to bastions from the corporate VPN only")
    _sg(inv, est, VPC_BY_NAME["prod-payments"], "stmt-render-public-8080", [rule(ANYWHERE, 8080), rule(VPN_CIDR, 22)], "2025-03-14T09:30:00Z", sg_id=sc.EDGE_SG, description="statement-render HTTP listener (public)")
    _sg(inv, est, VPC_BY_NAME["staging-edge"], "stmt-render-stg-public-8080", [rule(ANYWHERE, 8080), rule(VPN_CIDR, 22)], "2025-06-02T09:30:00Z", sg_id="sg:aws:sg-0stg-edge-public-8080")
    _sg(inv, est, VPC_BY_NAME["dev-sandbox"], "dev-open-ssh-world", [rule(ANYWHERE, 22)], "2026-05-19T15:12:00Z", sg_id="sg:aws:sg-0dev-open-ssh-world", description="Temporary SSH access (ticket DEV-4471)")
    _sg(inv, est, VPC_BY_NAME["dev-experiments"], "dev-open-rdp-world", [rule(ANYWHERE, 3389)], "2026-07-08T11:40:00Z", sg_id="sg:aws:sg-0dev-open-rdp-world")
    _sg(inv, est, VPC_BY_NAME["staging-data"], "staging-db-public", [rule(ANYWHERE, 5432)], "2026-04-21T10:05:00Z", sg_id="sg:aws:sg-0staging-db-public", description="Postgres open for a vendor load test")


def _sg(inv: Inventory, est: Estate, v: VpcSpec, role_name: str, rules: list[dict[str, Any]], created: str, sg_id: str | None = None, description: str | None = None) -> str:
    provider = PROVIDER[v.account]
    if sg_id is None:
        sg_id = f"sg:{provider}:{aws_resource_id('sg', v.name, role_name)}" if provider == "aws" else f"sg:{provider}:{v.name}-{role_name}"
    ports = internet_ports(rules)
    inv.add_node(
        sg_id, "SecurityGroup", f"{v.name}-{role_name}",
        {
            "provider": provider, "account_id": ACCOUNT_ID[v.account], "inbound_rules": rules, "open_to_internet": bool(ports),
            "internet_ports": ports, "vpc_id": est.vpc_ids[v.name], "region": v.region, "description": description or f"{role_name} rules for {v.name}",
        },
        source=SOURCE_WIZ, first_seen=created, account=v.account, vpc=v.name,
    )
    inv.add_edge("CONTAINS", sc.ACCOUNTS[v.account]["id"], sg_id, source=SOURCE_WIZ, first_seen=created)
    est.sg[(v.name, role_name)] = sg_id
    return sg_id


# ---------------------------------------------------------------------------- EKS clusters and nodes


def _clusters(inv: Inventory, est: Estate, apps: list[AppSpec]) -> None:
    r = rng("inventory.cloud.eks")
    platform = APP_BY_SLUG["container-platform"]
    for cname, spec in CLUSTERS.items():
        acct_key = spec["account"]
        cid = f"k8s:aws:{cname}"
        created = days_ago(r, 300, 900)
        inv.add_node(
            cid, "KubernetesCluster", cname,
            {
                "provider": "aws", "account_id": ACCOUNT_ID[acct_key], "version": spec["version"], "environment": spec["environment"],
                "public_endpoint": spec["public_endpoint"], "region": VPC_BY_NAME[spec["vpc"]].region, "vpc_id": est.vpc_ids[spec["vpc"]],
                "logging_enabled": cname != "data-eks", "node_count": spec["nodes"], "tags": {"env": spec["environment"], "owner": "platform-eng"},
            },
            source=SOURCE_WIZ, first_seen=created, account=acct_key, vpc=spec["vpc"], app="container-platform",
        )
        inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], cid, source=SOURCE_WIZ, first_seen=created)
        est.cluster_ids[cname] = cid
        platform.resources.setdefault("cluster", []).append(cid)
        nodes: list[str] = []
        vpc = VPC_BY_NAME[spec["vpc"]]
        groups = [("general", 0.6), ("spot", 0.25), ("memory", 0.15)]
        for i in range(1, spec["nodes"] + 1):
            group = pick(r, dict(groups))
            subnet = est.subnets[vpc.name]["private"][i % len(est.subnets[vpc.name]["private"])]
            ip = est.ip.alloc(est.subnet_cidr[subnet])
            vm_id = f"vm:aws:{aws_instance_id(cname, 'node', i)}"
            name = f"{cname}-ng-{group}-{i}"
            hostname = "ip-" + ip.replace(".", "-") + (".ec2.internal" if vpc.region == "us-east-1" else f".{vpc.region}.compute.internal")
            itype = r.choice(["m6i.xlarge", "m6i.2xlarge", "c6i.2xlarge", "r6i.xlarge"] if group != "memory" else ["r6i.2xlarge", "r6i.4xlarge"])
            inv.add_node(
                vm_id, "VirtualMachine", name,
                {
                    "provider": "aws", "account_id": ACCOUNT_ID[acct_key], "region": vpc.region, "hostname": hostname, "private_ip": ip, "public_ip": None,
                    "os": "Amazon Linux 2023 (EKS optimized)", "os_family": "linux", "instance_type": itype, "environment": spec["environment"],
                    "exposure": "internal", "has_edr_sensor": True, "is_k8s_node": True,
                    "tags": {"Name": name, "eks:cluster-name": cname, "eks:nodegroup-name": f"ng-{group}", "env": spec["environment"], "owner": "platform-eng"},
                    "criticality": "tier-1" if spec["environment"] == "prod" else "tier-2", "ti_exposure_score": None, "crown_jewel_reach": None,
                    "vpc_id": est.vpc_ids[vpc.name], "subnet_id": subnet, "launch_time": days_ago(r, 3, 120), "ami_age_days": r.randint(10, 260), "imdsv2_required": True,
                },
                source=SOURCE_WIZ, first_seen=days_ago(r, 3, 120), account=acct_key, env=spec["environment"], vpc=vpc.name, subnet=subnet,
                sgs=[est.sg[(vpc.name, "default")]], app="container-platform", service=f"{cname}-nodes", stack="k8s-node", cluster=cname, kind="vm",
                direct_ports=[], lb_ports=[], role=True, os_family="linux",
            )
            inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], vm_id, source=SOURCE_WIZ)
            inv.add_edge("IN_SUBNET", vm_id, subnet, source=SOURCE_WIZ)
            inv.add_edge("HAS_SECURITY_GROUP", vm_id, est.sg[(vpc.name, "default")], source=SOURCE_WIZ)
            inv.add_edge("HAS_NODE", cid, vm_id, source=SOURCE_WIZ)
            nodes.append(vm_id)
            est.vms.append(vm_id)
        est.cluster_nodes[cname] = nodes
        platform.resources.setdefault("vm", []).extend(nodes)
        # system workloads
        for ns, wname, kind, repo, tags in SYSTEM_WORKLOADS:
            if cname == "data-eks" and ns == "argocd":
                continue
            registry, repository = repo.split(":", 1)
            image_id = _image(inv, est, registry, repository, tags[cname], stack=SYSTEM_IMAGE_STACK.get(repository, "go"))
            exposed = wname == "ingress-nginx-controller"
            wid = _workload(
                inv, est, cname, ns, wname, kind, image_id, spec["environment"], "container-platform", wname,
                privileged=kind == "DaemonSet" and wname in ("aws-node", "ebs-csi-node", "fluent-bit"),
                expose="lb" if exposed and cname != "data-eks" else ("internal-lb" if exposed else "none"), port=443, role=wname in ("aws-load-balancer-controller", "cluster-autoscaler", "ebs-csi-controller"),
            )
            if exposed:
                _lb(inv, est, acct_key, vpc, f"{cname}-ingress-nlb", "internet-facing" if cname != "data-eks" else "internal", [wid], 443, ["443:TLS", "80:TCP"], app="container-platform", env=spec["environment"], lb_type="network")


# ---------------------------------------------------------------------------- app placement


def _env_ctx(app: AppSpec, acct_key: str, env: str) -> tuple[str, str, str]:
    """Return (vpc name, environment string, name suffix) for a placement."""
    if env == "prod":
        return app.vpc, app.environment if app.account == acct_key else ACCOUNT_ENV[acct_key], ""
    if env == "staging":
        return "staging-apps", "staging", "-stg"
    return "dev-experiments", "dev", "-dev"


def _place_app(inv: Inventory, est: Estate, app: AppSpec, acct_key: str, env: str) -> None:
    r = rng(f"inventory.cloud.app.{app.slug}.{env}")
    vpc_name, environment, suffix = _env_ctx(app, acct_key, env)
    scale = 1.0 if env == "prod" else (0.5 if env == "staging" else 0.3)
    for svc in app.services:
        if svc.kind in ("vm", "appliance"):
            count = svc.count if env == "prod" else max(1, round(svc.count * scale))
            if env != "prod" and svc.kind == "appliance":
                continue
            _vm_service(inv, est, app, svc, acct_key, env, environment, vpc_name, suffix, count, r)
        elif svc.kind == "eks":
            if env == "dev":
                continue
            _eks_service(inv, est, app, svc, acct_key, env, environment, r)
        elif svc.kind == "fn":
            _function(inv, est, app, svc, acct_key, environment, env, r)
    if env == "prod" and app.services:
        _function(inv, est, app, Svc(f"{app.slug}-alarm-handler", "fn", stack="python", role=True), acct_key, environment, env, r)
    for db in app.dbs:
        _database(inv, est, app, db, acct_key, env, environment, vpc_name, r)
    for b in app.buckets:
        _bucket(inv, est, app, b, acct_key, env, environment, r)
    if env == "prod" and app.services and app.account != "azure_corp":
        _bucket(inv, est, app, Bkt(f"larkspur-{app.slug}-logs", ("INTERNAL",), "low", size_gb=round(r.uniform(5, 800), 1)), acct_key, env, environment, r)
        if app.environment == "prod" and app.tier in ("tier-0", "tier-1"):
            _bucket(inv, est, app, Bkt(f"larkspur-{app.slug}-backups", app.classes, "medium", size_gb=round(r.uniform(50, 4000), 1)), acct_key, env, environment, r)
    for s in app.secrets:
        _secret(inv, est, app, s, acct_key, env, r)
    if env == "prod" and app.environment == "prod" and app.tier in ("tier-0", "tier-1") and app.account == "prod":
        _dr_copies(inv, est, app, r)


def _vm_props_common(r: random.Random, acct_key: str, vpc: VpcSpec) -> dict[str, Any]:
    return {"launch_time": days_ago(r, 5, 700), "ami_age_days": r.randint(5, 420), "imdsv2_required": r.random() < 0.7, "ebs_encrypted": r.random() < 0.85}


def _vm_service(inv: Inventory, est: Estate, app: AppSpec, svc: Svc, acct_key: str, env: str, environment: str, vpc_name: str, suffix: str, count: int, r: random.Random) -> None:
    provider = PROVIDER[acct_key]
    padded = svc.stack in ("windows", "appliance", "os") or acct_key in ("shared", "corp", "azure_corp", "gcp_ml")
    if env != "prod" and svc.expose == "direct":
        vpc_name = "staging-edge" if env == "staging" else vpc_name
    vpc = VPC_BY_NAME[vpc_name]
    ids: list[str] = []
    os_choice = svc.os or pick(r, OS_BY_STACK[svc.stack])
    for i in range(1, count + 1):
        ov = NAMED_VMS.get((app.slug, env, svc.name, i), {})
        direct = svc.expose == "direct" or ov.get("direct", False)
        if svc.name == "sandbox-runner":
            name = f"dev-sandbox-runner-{i:02d}"
        elif count == 1 and not padded and svc.expose == "direct" and svc.kind != "appliance":
            name = svc.name
        else:
            name = f"{svc.name}{suffix}-{i:02d}" if padded else f"{svc.name}{suffix}-{i}"
        name = ov.get("name", name)
        os_name = ov.get("os", os_choice)
        os_family = "windows" if os_name.startswith("Windows") else "linux"
        subnet_kind = ov.get("subnet_kind", "public" if direct else "private")
        subnet_pool = est.subnets[vpc.name][subnet_kind] or est.subnets[vpc.name]["private"]
        if "subnet" in ov:
            subnet = ov["subnet"]
        elif "subnet_suffix" in ov:
            subnet = next(s for s in sum(est.subnets[vpc.name].values(), []) if s.endswith("-" + ov["subnet_suffix"]))
        else:
            subnet = subnet_pool[(i - 1) % len(subnet_pool)]
        private_ip = ov.get("private_ip") or est.ip.alloc(est.subnet_cidr[subnet])
        public_ip = ov.get("public_ip") if "public_ip" in ov else (est.public_ip() if direct else None)
        if provider == "aws":
            vm_id = ov.get("id", f"vm:aws:{aws_instance_id(app.slug, env, svc.name, i)}")
            source_id = vm_id.split(":")[-1]
        elif provider == "gcp":
            vm_id = f"vm:gcp:{digits(app.slug, env, svc.name, i)}"
            source_id = vm_id.split(":")[-1]
        else:
            vm_id = f"vm:azure:{pseudo_guid(app.slug, env, svc.name, i)}"
            source_id = vm_id.split(":")[-1]
        domain = f"{ENV_DOMAIN[acct_key]}.larkspur.internal" if os_family == "linux" else "corp.larkspur.example"
        hostname = ov.get("hostname", f"{name}.{domain}")
        sgs = [est.sg[(vpc.name, "default")]]
        direct_ports: list[int] = []
        if direct:
            if "sg_id" in ov:
                sgs.append(ov["sg_id"])
            else:
                sgs.append(_service_public_sg(inv, est, vpc, svc, r))
            direct_ports = [svc.port]
        elif "sg_role" in ov:
            sgs.append(est.sg[(vpc.name, ov["sg_role"])])
        else:
            sgs.append(est.sg[(vpc.name, "app")])
            if svc.stack in ("java", "node", "python", "go", "os") and r.random() < 0.5:
                sgs.append(est.sg[(vpc.name, "mgmt-ssh")])
        if svc.name == "sandbox-runner" and i in (1, 5, 9):
            sgs.append("sg:aws:sg-0dev-open-ssh-world")
            if public_ip is None:
                public_ip = est.public_ip()
            direct_ports = [22]
        if svc.name == "exp-api" and i == 2 and env == "prod":
            sgs.append("sg:aws:sg-0dev-open-rdp-world")
        tier = ov.get("criticality", app.tier if environment == "prod" else ("tier-2" if environment in ("staging", "corp") else "tier-3"))
        itype = ov.get("instance_type", r.choice(TYPES_BY_STACK[svc.stack] if provider == "aws" else (GCP_TYPES if provider == "gcp" else AZURE_TYPES)))
        tags = ov.get("tags", {"Name": name, "app": app.slug, "service": svc.name, "env": environment, "owner": app.team, "cost-center": f"CC-{hexid('cc', app.team, length=4).upper()}"})
        if "Name" not in tags:
            tags = {"Name": name, **tags}
        created = days_ago(r, 5, 700) if "id" not in ov else "2025-11-02T10:00:00Z"
        inv.add_node(
            vm_id, "VirtualMachine", name,
            {
                "provider": provider, "account_id": ACCOUNT_ID[acct_key], "region": vpc.region, "hostname": hostname, "private_ip": private_ip,
                "public_ip": public_ip, "os": os_name, "os_family": os_family, "instance_type": itype, "environment": environment,
                "exposure": "internal", "has_edr_sensor": True, "is_k8s_node": False, "tags": tags, "criticality": tier,
                "ti_exposure_score": None, "crown_jewel_reach": None, "vpc_id": est.vpc_ids[vpc.name], "subnet_id": subnet,
                **_vm_props_common(r, acct_key, vpc), "service": svc.name, "app_id": app.id,
            },
            source=SOURCE_WIZ, source_id=source_id, first_seen=created, account=acct_key, env=environment, vpc=vpc.name, subnet=subnet, sgs=sgs,
            app=app.slug, service=svc.name, stack=svc.stack, os_family=os_family, direct_ports=direct_ports, lb_ports=[], role=svc.role,
            component=svc.component, kind="vm", placement_env=env, port=svc.port,
        )
        if vm_id == sc.BASTION_VM:
            inv.props(vm_id)["imdsv2_required"] = False
            inv.props(vm_id)["ebs_encrypted"] = True
            inv.props(vm_id)["ssh_restricted_to"] = VPN_CIDR
        inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], vm_id, source=SOURCE_WIZ, first_seen=created)
        inv.add_edge("IN_SUBNET", vm_id, subnet, source=SOURCE_WIZ, first_seen=created)
        for sg_id in sgs:
            inv.add_edge("HAS_SECURITY_GROUP", vm_id, sg_id, source=SOURCE_WIZ, first_seen=created)
        ids.append(vm_id)
        est.vms.append(vm_id)
    est.service_vms[(app.slug, env, svc.name)] = ids
    app.resources.setdefault("vm", []).extend(ids)
    if svc.expose in ("lb", "internal-lb"):
        scheme = "internet-facing" if svc.expose == "lb" else "internal"
        listeners = ["443:HTTPS", "80:HTTP"] if scheme == "internet-facing" else [f"{svc.port}:HTTP"]
        lb_id = _lb(inv, est, acct_key, vpc, f"{svc.name}{suffix}-alb".replace("--", "-"), scheme, ids, svc.port, listeners, app=app.slug, env=environment)
        for vm_id in ids:
            inv.meta[vm_id]["lb_ports"] = [svc.port] if scheme == "internet-facing" else []
            inv.meta[vm_id]["lb_id"] = lb_id
    # a container image for the service, run by all its VMs (application stacks only)
    if svc.stack in ("java", "node", "python", "go") and svc.name not in ("log4j-testbed",) and r.random() < 0.75:
        tag = _service_version(app, svc, env)
        image_id = _image(inv, est, "ecr", f"larkspur/{svc.name}", tag, stack=svc.stack, app=app.slug)
        if svc.name == "stmt-render":
            image_id = _image(inv, est, "ecr", "larkspur/statement-render", "3.8.1", stack="java", app=app.slug)
        for vm_id in ids:
            inv.add_edge("RUNS_IMAGE", vm_id, image_id, source=SOURCE_WIZ)
            inv.meta[vm_id]["image"] = image_id


def _service_public_sg(inv: Inventory, est: Estate, vpc: VpcSpec, svc: Svc, r: random.Random) -> str:
    key = (vpc.name, f"{svc.name}-public-{svc.port}")
    if key in est.sg:
        return est.sg[key]
    rules = [rule(ANYWHERE, svc.port)]
    if svc.port == 443:
        rules.append(rule(ANYWHERE, 80))
    rules.append(rule(VPN_CIDR, 22 if svc.stack != "windows" else 3389))
    return _sg(inv, est, vpc, key[1], rules, days_ago(r, 30, 600))


def _service_version(app: AppSpec, svc: Svc, env: str) -> str:
    major = 1 + int(hexid("ver", app.slug, svc.name, length=2), 16) % 4
    minor = int(hexid("verminor", app.slug, svc.name, length=2), 16) % 20
    patch = int(hexid("verpatch", app.slug, svc.name, length=2), 16) % 9
    if env == "prod":
        return f"{major}.{minor}.{patch}"
    if env == "staging":
        return f"{major}.{minor + 1}.0-rc{1 + patch % 3}"
    return f"{major}.{minor + 1}.0-dev"


def _image(inv: Inventory, est: Estate, registry: str, repository: str, tag: str, *, stack: str, app: str | None = None) -> str:
    image_id = f"image:{registry}:{repository}:{tag}"
    if image_id in est.images:
        return image_id
    r = rng(f"inventory.cloud.image.{image_id}")
    inv.add_node(
        image_id, "ContainerImage", f"{repository}:{tag}",
        {
            "registry": REGISTRY_HOST[registry], "repository": repository, "tag": tag, "digest": "sha256:" + hexid("digest", image_id, length=64),
            "vuln_count_critical": 0, "vuln_count_high": 0, "pushed_at": days_ago(r, 2, 400), "size_mb": r.randint(60, 900), "stack": stack,
        },
        source=SOURCE_WIZ, source_id=image_id.split(":", 1)[1], first_seen=days_ago(r, 2, 400), stack=stack, app=app, kind="image", registry=registry,
    )
    est.images[image_id] = {"stack": stack, "app": app, "registry": registry, "repository": repository, "tag": tag}
    return image_id


def _workload(
    inv: Inventory, est: Estate, cname: str, ns: str, wname: str, kind: str, image_id: str, environment: str, app_slug: str, service: str,
    *, privileged: bool = False, expose: str = "none", port: int = 8080, role: bool = True, stack: str | None = None,
) -> str:
    r = rng(f"inventory.cloud.workload.{cname}.{ns}.{wname}")
    wid = f"workload:{cname}:{ns}/{wname}"
    cid = est.cluster_ids[cname]
    inv.add_node(
        wid, "Workload", f"{ns}/{wname}",
        {
            "kind": kind, "namespace": ns, "cluster_id": cid, "image": image_id, "exposure": "internal", "environment": environment,
            "privileged": privileged, "service_account": f"{wname}-sa" if role else "default", "replicas": 1 if kind != "Deployment" else r.choice([2, 3, 3, 4, 6]),
            "port": port, "app_id": f"app:larkspur:{app_slug}", "labels": {"app.kubernetes.io/name": wname, "app.kubernetes.io/part-of": app_slug},
        },
        source=SOURCE_WIZ, first_seen=days_ago(r, 2, 500), account=CLUSTERS[cname]["account"], env=environment, cluster=cname, namespace=ns, app=app_slug,
        service=service, image=image_id, expose=expose, port=port, role=role, kind="workload", stack=stack or est.images[image_id]["stack"],
    )
    inv.add_edge("RUNS_ON", wid, cid, source=SOURCE_WIZ)
    inv.add_edge("RUNS_IMAGE", wid, image_id, source=SOURCE_WIZ)
    # pods land on 1-3 nodes; the node VMs then also run the image (what the scanner reports as the host)
    nodes = est.cluster_nodes[cname]
    for n in sorted(r.sample(range(len(nodes)), min(len(nodes), r.choice([1, 2, 2, 3])))):
        inv.add_edge("RUNS_IMAGE", nodes[n], image_id, {"via": "pod"}, source=SOURCE_WIZ)
    est.workloads.append(wid)
    APP_BY_SLUG[app_slug].resources.setdefault("workload", []).append(wid)
    est.service_workloads.setdefault((app_slug, environment, service), []).append(wid)
    return wid


def _eks_service(inv: Inventory, est: Estate, app: AppSpec, svc: Svc, acct_key: str, env: str, environment: str, r: random.Random) -> None:
    cname = "staging-eks" if env == "staging" else ("data-eks" if acct_key == "data" else "prod-eks")
    ns = app.slug
    tag = _service_version(app, svc, env)
    image_id = _image(inv, est, "ecr", f"larkspur/{svc.name}", tag, stack=svc.stack, app=app.slug)
    ids = [_workload(inv, est, cname, ns, svc.name, "Deployment", image_id, environment, app.slug, svc.name, expose=svc.expose, port=svc.port, role=svc.role)]
    worker_names = [f"{svc.name}-worker", f"{svc.name}-consumer", f"{svc.name}-scheduler"]
    for w in range(svc.workers):
        wimg = _image(inv, est, "ecr", f"larkspur/{worker_names[w]}", tag, stack=svc.stack, app=app.slug)
        ids.append(_workload(inv, est, cname, ns, worker_names[w], "Deployment", wimg, environment, app.slug, svc.name, port=svc.port, role=svc.role))
    if r.random() < 0.35:
        ids.append(_workload(inv, est, cname, ns, f"{svc.name}-nightly", "Job", image_id, environment, app.slug, svc.name, role=svc.role))
    if r.random() < 0.55:
        ids.append(_workload(inv, est, cname, ns, f"{svc.name}-migrate", "Job", image_id, environment, app.slug, svc.name, role=svc.role))
    if env == "prod" and r.random() < 0.45:
        canary_img = _image(inv, est, "ecr", f"larkspur/{svc.name}", _service_version(app, svc, "staging"), stack=svc.stack, app=app.slug)
        ids.append(_workload(inv, est, cname, ns, f"{svc.name}-canary", "Deployment", canary_img, environment, app.slug, svc.name, port=svc.port, role=svc.role))
    if svc.expose in ("lb", "internal-lb"):
        scheme = "internet-facing" if svc.expose == "lb" else "internal"
        vpc = VPC_BY_NAME[CLUSTERS[cname]["vpc"]]
        _lb(inv, est, CLUSTERS[cname]["account"], vpc, f"{svc.name}-{environment}-alb", scheme, ids[:1], svc.port, ["443:HTTPS", "80:HTTP"] if scheme == "internet-facing" else [f"{svc.port}:HTTP"], app=app.slug, env=environment)


def _lb(inv: Inventory, est: Estate, acct_key: str, vpc: VpcSpec, name: str, scheme: str, targets: list[str], port: int, listeners: list[str], *, app: str, env: str, lb_type: str = "application") -> str:
    r = rng(f"inventory.cloud.lb.{name}")
    provider = PROVIDER[acct_key]
    lb_id = f"lb:{provider}:{name}"
    if inv.has(lb_id):
        return lb_id
    sub_kind = "public" if scheme == "internet-facing" else "private"
    subnet = (est.subnets[vpc.name][sub_kind] or est.subnets[vpc.name]["private"])[0]
    dns = f"{name}-{digits('lb', name, length=9)}.{vpc.region}.elb.amazonaws.com" if provider == "aws" else f"{name}.{vpc.region}.cloudapp.{provider}.example"
    sg_id = est.sg.get((vpc.name, "web-public" if scheme == "internet-facing" else "app"), est.sg[(vpc.name, "default")])
    inv.add_node(
        lb_id, "LoadBalancer", name,
        {
            "provider": provider, "account_id": ACCOUNT_ID[acct_key], "scheme": scheme, "dns_name": dns, "listeners": listeners, "lb_type": lb_type,
            "region": vpc.region, "vpc_id": est.vpc_ids[vpc.name], "environment": env, "tls_policy": r.choice(["ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-2016-08"]),
            "access_logs_enabled": r.random() < 0.7, "waf_attached": scheme == "internet-facing" and r.random() < 0.8, "app_id": f"app:larkspur:{app}",
        },
        source=SOURCE_WIZ, first_seen=days_ago(r, 20, 600), account=acct_key, env=env, vpc=vpc.name, app=app, kind="lb", port=port, targets=list(targets),
    )
    inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], lb_id, source=SOURCE_WIZ)
    inv.add_edge("IN_SUBNET", lb_id, subnet, source=SOURCE_WIZ)
    inv.add_edge("HAS_SECURITY_GROUP", lb_id, sg_id, source=SOURCE_WIZ)
    for t in targets:
        inv.add_edge("ROUTES_TO", lb_id, t, {"port": port}, source=SOURCE_WIZ)
        if scheme == "internet-facing":
            inv.meta[t]["lb_ports"] = sorted(set(inv.meta[t].get("lb_ports", []) + [port]))
    est.lbs.append(lb_id)
    APP_BY_SLUG[app].resources.setdefault("lb", []).append(lb_id)
    return lb_id


RUNTIMES: dict[str, list[str]] = {"python": ["python3.12", "python3.11", "python3.9"], "node": ["nodejs20.x", "nodejs18.x"], "java": ["java17", "java11"], "go": ["provided.al2023"]}


def _function(inv: Inventory, est: Estate, app: AppSpec, svc: Svc, acct_key: str, environment: str, env: str, r: random.Random) -> str:
    provider = PROVIDER[acct_key]
    name = f"{svc.name}-{environment}" if not svc.name.endswith("alarm-handler") else f"{svc.name}-{environment}"
    fid = f"function:{provider}:{ACCOUNT_ID[acct_key]}:{name}"
    runtime = r.choice(RUNTIMES.get(svc.stack, RUNTIMES["python"]))
    inv.add_node(
        fid, "ServerlessFunction", name,
        {
            "provider": provider, "account_id": ACCOUNT_ID[acct_key], "runtime": runtime, "exposure": "internet" if svc.url else "internal", "environment": environment,
            "url_enabled": svc.url, "url_auth_type": ("NONE" if r.random() < 0.6 else "AWS_IAM") if svc.url else None, "memory_mb": r.choice([256, 512, 1024, 2048]),
            "timeout_s": r.choice([30, 60, 300, 900]), "region": VPC_BY_NAME[app.vpc].region if app.account == acct_key else "us-east-1", "app_id": app.id,
            "last_invoked": days_ago(r, 0, 20), "env_var_secrets": r.random() < 0.15,
        },
        source=SOURCE_WIZ, first_seen=days_ago(r, 10, 600), account=acct_key, env=environment, app=app.slug, service=svc.name, stack=svc.stack,
        role=svc.role, url=svc.url, kind="function",
    )
    inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], fid, source=SOURCE_WIZ)
    est.functions.append(fid)
    app.resources.setdefault("function", []).append(fid)
    est.service_functions[(app.slug, env, svc.name)] = fid
    return fid


ENGINE_PORT = {"aurora-postgresql": 5432, "postgres": 5432, "mysql": 3306, "redshift": 5439, "dynamodb": 443, "bigquery": 443, "azure-sql": 1433, "cloud-sql-postgres": 5432}


def _database(inv: Inventory, est: Estate, app: AppSpec, db: Db, acct_key: str, env: str, environment: str, vpc_name: str, r: random.Random) -> str:
    provider = PROVIDER[acct_key]
    name = db.name if env == "prod" else f"{db.name}-{env}"
    did = f"database:{provider}:{ACCOUNT_ID[acct_key]}:{name}"
    real_copy = env != "prod" and r.random() < 0.2
    classes = list(db.classes) if env == "prod" or real_copy else ["INTERNAL"]
    sens = db.sensitivity if env == "prod" else ("medium" if real_copy else "low")
    public = db.public or (env == "staging" and db.engine in ("postgres", "aurora-postgresql") and r.random() < 0.12)
    vpc = VPC_BY_NAME[vpc_name if env == "prod" else ("staging-data" if env == "staging" else "dev-experiments")]
    subnet = est.subnets[vpc.name]["db"][0]
    inv.add_node(
        did, "Database", name,
        {
            "provider": provider, "account_id": ACCOUNT_ID[acct_key], "engine": db.engine, "public": public, "encrypted": db.encrypted and (env == "prod" or r.random() < 0.8),
            "data_classifications": classes, "sensitivity": sens, "crown_jewel": db.crown_jewel and env == "prod", "environment": environment,
            "exposure": "internet" if public else "internal", "region": vpc.region, "vpc_id": est.vpc_ids[vpc.name], "port": ENGINE_PORT.get(db.engine, 5432),
            "backup_retention_days": r.choice([0, 7, 14, 35]), "multi_az": env == "prod" and r.random() < 0.8, "app_id": app.id, "endpoint": f"{name}.{hexid('rds', did, length=12)}.{vpc.region}.rds.amazonaws.com" if provider == "aws" and db.engine not in ("dynamodb",) else None,
        },
        source=SOURCE_WIZ, first_seen=days_ago(r, 30, 900), account=acct_key, env=environment, vpc=vpc.name, app=app.slug, kind="database", public=public,
    )
    inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], did, source=SOURCE_WIZ)
    if db.engine not in ("dynamodb", "bigquery"):
        inv.add_edge("IN_SUBNET", did, subnet, source=SOURCE_WIZ)
        sg_id = "sg:aws:sg-0staging-db-public" if public and env == "staging" else est.sg[(vpc.name, "db")]
        inv.add_edge("HAS_SECURITY_GROUP", did, sg_id, source=SOURCE_WIZ)
        if public and env != "staging":
            inv.add_edge("HAS_SECURITY_GROUP", did, est.sg[(vpc.name, "web-public")], source=SOURCE_WIZ)
    est.databases.append(did)
    app.resources.setdefault("database", []).append(did)
    return did


def _bucket(inv: Inventory, est: Estate, app: AppSpec, b: Bkt, acct_key: str, env: str, environment: str, r: random.Random) -> str:
    provider = PROVIDER[acct_key]
    if env == "prod":
        name = b.name
    elif b.name.startswith("larkspur-prod-"):
        name = b.name.replace("larkspur-prod-", f"larkspur-{env}-", 1)
    else:
        name = b.name.replace("larkspur-", f"larkspur-{env}-", 1)
    bid = f"bucket:{provider}:{name}"
    if inv.has(bid):
        return bid
    real_copy = env != "prod" and r.random() < 0.15 and "SECRETS" not in b.classes
    classes = list(b.classes) if env == "prod" or real_copy else ["INTERNAL"]
    sens = b.sensitivity if env == "prod" else ("medium" if real_copy and b.sensitivity in ("high", "critical") else "low")
    region = VPC_BY_NAME[app.vpc].region if env == "prod" else "us-east-1"
    inv.add_node(
        bid, "StorageBucket", name,
        {
            "provider": provider, "account_id": ACCOUNT_ID[acct_key], "region": region, "public": b.public, "encrypted": b.encrypted if env == "prod" else r.random() < 0.8,
            "versioning": r.random() < 0.6 or (b.crown_jewel and env == "prod"), "data_classifications": classes, "sensitivity": sens, "crown_jewel": b.crown_jewel and env == "prod",
            "size_gb": b.size_gb if env == "prod" else round(b.size_gb * r.uniform(0.02, 0.2), 2), "environment": environment,
            "contains_credentials_for": list(b.contains_credentials_for) if env == "prod" else [], "access_logging": r.random() < 0.55, "block_public_access": not b.public,
            "object_count": int(b.size_gb * r.uniform(200, 20000)) if b.size_gb else r.randint(10, 5000), "app_id": app.id,
        },
        source=SOURCE_WIZ, first_seen=days_ago(r, 30, 1000), account=acct_key, env=environment, app=app.slug, kind="bucket",
    )
    inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], bid, source=SOURCE_WIZ)
    est.buckets.append(bid)
    app.resources.setdefault("bucket", []).append(bid)
    return bid


def _secret(inv: Inventory, est: Estate, app: AppSpec, s: Sec, acct_key: str, env: str, r: random.Random) -> str:
    provider = PROVIDER[acct_key]
    path = s.path if env == "prod" else s.path.replace("prod/", f"{env}/", 1).replace("shared/", f"{env}/", 1)
    sid = f"secret:{provider}:{ACCOUNT_ID[acct_key]}:{path}"
    if inv.has(sid):
        return sid
    unlocks = None
    if s.unlocks:
        unlocks = s.unlocks if env == "prod" else s.unlocks.replace(":111111111111:", f":{ACCOUNT_ID[acct_key]}:").replace(":555555555555:", f":{ACCOUNT_ID[acct_key]}:") + f"-{env}"
        if not inv.has(unlocks):
            unlocks = None
    sens = s.sensitivity if env == "prod" else "low"
    rotated = r.choice([12, 30, 45, 60, 88, 120, 200, 365, 410, 700])
    inv.add_node(
        sid, "Secret", path,
        {
            "provider": provider, "account_id": ACCOUNT_ID[acct_key], "secret_type": s.secret_type, "sensitivity": sens, "rotated_days_ago": rotated,
            "grants_access_to": [unlocks] if unlocks else [], "environment": ACCOUNT_ENV[acct_key] if env == "prod" else env, "rotation_enabled": rotated <= 90,
            "kms_key": "aws/secretsmanager" if r.random() < 0.6 else f"arn:aws:kms:us-east-1:{ACCOUNT_ID[acct_key]}:key/{pseudo_guid('kms', sid)}", "app_id": app.id,
        },
        source=SOURCE_WIZ, first_seen=days_ago(r, 30, 900), account=acct_key, env=env, app=app.slug, kind="secret",
    )
    inv.add_edge("CONTAINS", sc.ACCOUNTS[acct_key]["id"], sid, source=SOURCE_WIZ)
    if unlocks:
        ctype = "db_credentials" if inv.label(unlocks) == "Database" else "access_key"
        inv.add_edge("UNLOCKS", sid, unlocks, {"credential_type": ctype}, source=SOURCE_WIZ)
    est.secrets.append(sid)
    app.resources.setdefault("secret", []).append(sid)
    return sid


def _dr_copies(inv: Inventory, est: Estate, app: AppSpec, r: random.Random) -> None:
    """Warm standby copies of tier-0/1 prod VM services in us-west-2 (prod-dr VPC)."""
    for svc in app.services:
        if svc.kind != "vm" or svc.expose == "direct" or svc.stack in ("windows", "appliance"):
            continue
        count = max(1, svc.count // 2)
        dr_svc = Svc(f"{svc.name}-dr", "vm", count=count, expose="none", port=svc.port, stack=svc.stack, os=svc.os, role=svc.role)
        _vm_service(inv, est, app, dr_svc, "prod", "prod", "prod", "prod-dr", "", count, r)


# ---------------------------------------------------------------------------- long tail


def _utility(inv: Inventory, est: Estate, apps: list[AppSpec]) -> None:
    r = rng("inventory.cloud.utility")
    util_apps = {"prod": "observability", "shared": "observability", "staging": "observability", "dev": "dev-sandbox", "data": "observability", "corp": "endpoint-management", "gcp_ml": "fraud-model-training", "azure_corp": "collaboration-tools"}
    for v in VPCS:
        if v.name in ("dev-isolated", "ml-fraud-data"):
            continue
        app = APP_BY_SLUG[util_apps[v.account]]
        specs = [Svc(f"mon-collector-{v.name}", "vm", count=1, stack="go", port=9100), Svc(f"jump-{v.name}", "vm", count=1, stack="os", port=22)]
        if v.account in ("prod", "data", "shared", "staging"):
            specs.append(Svc(f"nat-{v.name}", "vm", count=1, stack="os", role=False, port=443))
            specs.append(Svc(f"backup-agent-{v.name}", "vm", count=1, stack="os", port=443))
        if v.account in ("prod", "shared", "corp"):
            specs.append(Svc(f"dns-forwarder-{v.name}", "vm", count=1, stack="os", role=False, port=53))
        if v.account == "azure_corp":
            specs.append(Svc("avd-host", "vm", count=10, stack="windows", os="Windows 11 Enterprise multi-session", role=False, port=3389))
        if v.account == "gcp_ml":
            specs.append(Svc("ml-notebook", "vm", count=6, stack="python", port=8888))
        if v.account == "corp" and v.name == "corp-it":
            specs.append(Svc("srv-legacy-app", "vm", count=3, stack="windows", os="Windows Server 2019", role=False, port=443))
        for svc in specs:
            _vm_service(inv, est, app, svc, v.account, "prod", ACCOUNT_ENV[v.account], v.name, "", svc.count, r)
    # account-level buckets and utility functions
    for key, acc in sc.ACCOUNTS.items():
        provider = acc["provider"]
        owner = APP_BY_SLUG["siem-forwarders"] if key not in ("corp", "azure_corp") else APP_BY_SLUG["endpoint-management"]
        for suffix, classes, sens, size in ACCOUNT_BUCKETS:
            if provider != "aws" and suffix in ("alb-access-logs", "athena-results", "flow-logs", "config-snapshots"):
                continue
            name = f"{acc['name']}-{suffix}" if provider != "azure" else f"larkspurcorp{suffix.replace('-', '')}"
            _bucket(inv, est, owner, Bkt(name, classes, sens, size_gb=size), key, "prod", acc["environment"], r)
        if provider == "aws":
            for fname, runtime in UTILITY_FUNCTIONS:
                stack = "python" if runtime.startswith("python") else "node"
                _function(inv, est, APP_BY_SLUG["iam-tooling"], Svc(fname, "fn", stack=stack), key, acc["environment"], "prod", r)
    # a few public snapshots / public dev buckets as CSPM material
    _bucket(inv, est, APP_BY_SLUG["dev-sandbox"], Bkt("larkspur-dev-public-share", ("INTERNAL",), "low", public=True, encrypted=False, size_gb=3.2), "dev", "prod", "dev", r)
    _bucket(inv, est, APP_BY_SLUG["developer-portal"], Bkt("larkspur-api-docs-public", ("PUBLIC",), "none", public=True, size_gb=0.8), "prod", "prod", "prod", r)


def _registry_tail(inv: Inventory, est: Estate) -> None:
    """Older tags left in the registry (nothing runs them) so the image catalog looks like a real registry."""
    r = rng("inventory.cloud.registry")
    repos = sorted({(m["repository"], m["stack"], m["app"]) for m in est.images.values() if m["registry"] == "ecr"})
    for repository, stack, app in repos:
        for k in range(r.choice([1, 1, 2, 2, 3, 4])):
            major = 1 + int(hexid("oldver", repository, k, length=2), 16) % 4
            tag = f"{major}.{int(hexid('oldminor', repository, k, length=2), 16) % 20}.{k}"
            _image(inv, est, "ecr", repository, tag, stack=stack, app=app)


def _record_storyline(inv: Inventory) -> None:
    inv.storyline.update({
        "bastion_vm": sc.BASTION_VM, "bastion_subnet": sc.BASTION_SUBNET, "edge_vm": sc.EDGE_VM, "edge_sg": sc.EDGE_SG, "edge_image": sc.EDGE_IMAGE,
        "stg_edge_vm": sc.STG_EDGE_VM, "dev_log4j_vm": sc.DEV_LOG4J_VM, "marketing_bucket": sc.MARKETING_BUCKET, "dev_sandbox_vm": sc.DEV_SANDBOX_VM,
        "scanner_vm": sc.SCANNER_VM, "fileshare_vm": sc.FILESHARE_VM, "cardholder_vault": sc.CARDHOLDER_VAULT, "kyc_docs": sc.KYC_DOCS,
        "db_reader_secret": sc.DB_READER_SECRET, "hsm_secret": sc.HSM_SECRET, "cardholder_db": sc.CARDHOLDER_DB, "app_config_bucket": sc.APP_CONFIG_BUCKET,
        "statements_out_bucket": sc.STATEMENTS_OUT_BUCKET, "shared_logs_bucket": sc.SHARED_LOGS_BUCKET, "internet": INTERNET_ID,
        "ns_gw_vm": "vm:aws:i-0ns1c3d5e7f9a1b3c5", "vpn_pa_vm": "vm:aws:i-0pan2d4f6a8c0e2a4b", "partner_api_vm": "vm:aws:i-0spr3e5a7c9b1d3f5e",
        "jenkins_vm": "vm:aws:i-0jnk4f6b8d0c2e4a6c", "confluence_vm": "vm:aws:i-0cnf5a7c9e1d3b5f7a",
        **{f"account_{k}": v["id"] for k, v in sc.ACCOUNTS.items()},
    })
    for required in (sc.BASTION_VM, sc.EDGE_VM, sc.STG_EDGE_VM, sc.DEV_LOG4J_VM, sc.MARKETING_BUCKET, sc.DEV_SANDBOX_VM, sc.SCANNER_VM, sc.FILESHARE_VM,
                     sc.CARDHOLDER_VAULT, sc.KYC_DOCS, sc.DB_READER_SECRET, sc.HSM_SECRET, sc.CARDHOLDER_DB, sc.APP_CONFIG_BUCKET, sc.STATEMENTS_OUT_BUCKET,
                     sc.SHARED_LOGS_BUCKET, sc.EDGE_IMAGE, sc.EDGE_SG, sc.BASTION_SUBNET):
        if not inv.has(required):
            raise RuntimeError(f"storyline resource missing after cloud pass: {required}")
