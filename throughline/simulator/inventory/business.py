"""Business context: the ~46 applications of Larkspur Financial, their teams, tiers, data classifications and
their placement in the cloud estate (which services run where). ``build_apps`` creates the Application nodes;
``emit_business_edges`` (run after the cloud/identity passes) adds PART_OF, OWNED_BY and DEPENDS_ON.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from throughline.simulator import storyline_constants as sc
from throughline.simulator.inventory._base import SOURCE_WIZ, Inventory
from throughline.simulator.inventory.world import TEAM_BY_SLUG, World


@dataclass(frozen=True)
class Svc:
    """A deployable service of an application.

    kind: vm | eks | fn | appliance. ``expose``: none | lb | direct | internal-lb. ``count`` is the prod instance
    count for VMs (functions and workloads are one each, workloads may have ``workers`` companions).
    """

    name: str
    kind: str
    count: int = 1
    expose: str = "none"
    port: int = 443
    stack: str = "java"  # java | node | python | go | os | windows | appliance
    os: str | None = None
    workers: int = 0
    role: bool = True  # gets an IAM role (instance profile / IRSA / function role)
    component: str | None = None  # a specific CVE catalog component always installed (appliances)
    url: bool = False  # functions: function URL enabled


@dataclass(frozen=True)
class Db:
    name: str
    engine: str
    classes: tuple[str, ...]
    sensitivity: str
    crown_jewel: bool = False
    public: bool = False
    encrypted: bool = True


@dataclass(frozen=True)
class Bkt:
    name: str  # full bucket name
    classes: tuple[str, ...]
    sensitivity: str
    crown_jewel: bool = False
    public: bool = False
    encrypted: bool = True
    size_gb: float = 0.0
    contains_credentials_for: tuple[str, ...] = ()


@dataclass(frozen=True)
class Sec:
    path: str
    secret_type: str
    sensitivity: str
    unlocks: str | None = None  # node id the secret unlocks (db id or bucket id), resolved later


@dataclass
class AppSpec:
    slug: str
    name: str
    tier: str
    team: str
    account: str  # account key in storyline_constants.ACCOUNTS
    vpc: str  # prod placement VPC name
    classes: tuple[str, ...]
    description: str
    services: tuple[Svc, ...] = ()
    dbs: tuple[Db, ...] = ()
    buckets: tuple[Bkt, ...] = ()
    secrets: tuple[Sec, ...] = ()
    staging: bool = False  # deploy a staging copy in larkspur-staging
    dev: bool = False  # deploy a small dev copy in larkspur-dev-sandbox
    depends_on: tuple[tuple[str, str], ...] = ()  # (node id or app slug, dependency_type)
    environment: str = "prod"
    resources: dict[str, list[str]] = field(default_factory=dict)  # filled by cloud: kind -> node ids

    @property
    def id(self) -> str:
        return f"app:larkspur:{self.slug}"

    @property
    def team_id(self) -> str:
        return f"team:larkspur:{self.team}"


def _s(name: str, kind: str, **kw) -> Svc:  # type: ignore[no-untyped-def]
    return Svc(name, kind, **kw)


APPS: list[AppSpec] = [
    # ------------------------------------------------------------------ payments platform
    AppSpec(
        "card-issuing", "Card Issuing", "tier-0", "payments-platform", "prod", "prod-payments", ("PCI", "PII"),
        "Card issuance, authorization and tokenization for the consumer card program (cardholder data environment).",
        services=(_s("card-issuing-api", "eks", workers=1), _s("card-issuing-worker", "eks", workers=2), _s("card-auth", "eks", workers=1), _s("tokenization", "vm", count=3, stack="java", port=8443), _s("card-batch", "vm", count=3, stack="java", port=8080), _s("hsm-proxy", "vm", count=2, stack="go", port=8443)),
        dbs=(Db("cardholder-db", "aurora-postgresql", ("PCI",), "critical", crown_jewel=True), Db("card-auth-db", "aurora-postgresql", ("PCI",), "high")),
        buckets=(
            Bkt("larkspur-cardholder-vault", ("PCI",), "critical", crown_jewel=True, size_gb=4100.0),
            Bkt("larkspur-kyc-documents", ("PII",), "high", crown_jewel=True, size_gb=860.0),
            Bkt("larkspur-card-issuing-exports", ("PCI", "PII"), "high", size_gb=120.0),
        ),
        secrets=(
            Sec("prod/cardholder-db/reader", "db_credentials", "critical", unlocks="database:aws:111111111111:cardholder-db"),
            Sec("prod/cardholder-db/app", "db_credentials", "critical", unlocks="database:aws:111111111111:cardholder-db"),
            Sec("prod/hsm/partner-signing-key", "signing_key", "critical"),
            Sec("prod/card-auth-db/app", "db_credentials", "high", unlocks="database:aws:111111111111:card-auth-db"),
            Sec("prod/card-network/api-key", "api_key", "high"),
        ),
        staging=True,
    ),
    AppSpec(
        "statement-render", "Statement Render", "tier-1", "payments-platform", "prod", "prod-payments", ("PII", "FINANCIAL"),
        "Renders monthly cardholder statements to PDF and publishes them for download.",
        services=(_s("stmt-render", "vm", count=2, expose="direct", port=8080, stack="java", os="Ubuntu 22.04"), _s("stmt-scheduler", "fn", stack="python")),
        buckets=(
            Bkt("larkspur-prod-app-config", ("SECRETS",), "high", size_gb=0.4, contains_credentials_for=("database:aws:111111111111:cardholder-db",)),
            Bkt("larkspur-statements-out", ("PII", "FINANCIAL"), "high", size_gb=930.0),
        ),
        secrets=(Sec("prod/statement-render/pdf-signing", "signing_key", "medium"),),
        staging=True,
    ),
    AppSpec(
        "ledger", "Ledger", "tier-0", "payments-platform", "prod", "prod-ledger", ("FINANCIAL", "PCI"),
        "Double-entry ledger of record for wallet balances and card transactions.",
        services=(_s("ledger-api", "eks", workers=2), _s("ledger-batch", "vm", count=6, stack="java", port=8080), _s("ledger-reconciler", "vm", count=2, stack="java", port=8080)),
        dbs=(Db("ledger-db-primary", "aurora-postgresql", ("FINANCIAL", "PCI"), "critical", crown_jewel=True), Db("ledger-db-replica", "aurora-postgresql", ("FINANCIAL", "PCI"), "critical")),
        buckets=(Bkt("larkspur-ledger-archive", ("FINANCIAL", "PCI"), "critical", crown_jewel=True, size_gb=12800.0),),
        secrets=(Sec("prod/ledger-db/app", "db_credentials", "critical", unlocks="database:aws:111111111111:ledger-db-primary"), Sec("prod/ledger-db/readonly", "db_credentials", "high", unlocks="database:aws:111111111111:ledger-db-replica")),
        staging=True,
    ),
    AppSpec(
        "settlement-engine", "Settlement Engine", "tier-1", "payments-platform", "prod", "prod-payments", ("FINANCIAL",),
        "Nightly settlement and reconciliation with card networks and sponsor bank.",
        services=(_s("settlement-batch", "vm", count=4, stack="java", port=8080), _s("settlement-api", "eks", workers=1)),
        dbs=(Db("settlement-db", "aurora-postgresql", ("FINANCIAL",), "high"),),
        buckets=(Bkt("larkspur-settlement-reports", ("FINANCIAL",), "high", size_gb=210.0),),
        secrets=(Sec("prod/settlement-db/app", "db_credentials", "high", unlocks="database:aws:111111111111:settlement-db"), Sec("prod/sponsor-bank/sftp-key", "ssh_key", "high")),
        staging=True,
    ),
    AppSpec(
        "disputes-service", "Disputes Service", "tier-2", "payments-platform", "prod", "prod-payments", ("PII", "FINANCIAL"),
        "Chargeback and dispute case handling.",
        services=(_s("disputes-api", "eks", workers=1), _s("disputes-evidence-fn", "fn", stack="python")),
        dbs=(Db("disputes-db", "postgres", ("PII", "FINANCIAL"), "medium"),),
        buckets=(Bkt("larkspur-disputes-evidence", ("PII",), "medium", size_gb=64.0),),
        secrets=(Sec("prod/disputes-db/app", "db_credentials", "medium", unlocks="database:aws:111111111111:disputes-db"),),
        staging=True,
    ),
    # ------------------------------------------------------------------ wallet
    AppSpec(
        "wallet-api", "Wallet API", "tier-0", "wallet-eng", "prod", "prod-wallet", ("PII", "FINANCIAL"),
        "Consumer wallet backend: balances, transfers, funding sources.",
        services=(_s("wallet-api", "vm", count=12, expose="lb", port=8080, stack="java"), _s("wallet-worker", "eks", workers=3), _s("wallet-batch", "vm", count=4, stack="java", port=8080), _s("wallet-cache", "vm", count=3, stack="os", role=False, component="redis")),
        dbs=(Db("wallet-db", "aurora-postgresql", ("PII", "FINANCIAL"), "high", crown_jewel=True), Db("wallet-events", "dynamodb", ("PII",), "medium")),
        buckets=(Bkt("larkspur-wallet-exports", ("PII", "FINANCIAL"), "high", size_gb=310.0), Bkt("larkspur-wallet-static", ("PUBLIC",), "none", public=False, size_gb=2.0)),
        secrets=(Sec("prod/wallet-db/app", "db_credentials", "high", unlocks="database:aws:111111111111:wallet-db"), Sec("prod/wallet/jwt-signing", "signing_key", "high")),
        staging=True, dev=True,
    ),
    AppSpec(
        "wallet-mobile-backend", "Wallet Mobile Backend", "tier-1", "wallet-eng", "prod", "prod-wallet", ("PII",),
        "Backend-for-frontend and push notification gateway for the mobile apps.",
        services=(_s("mobile-bff", "eks", expose="lb", stack="node", workers=1), _s("push-gateway", "eks", stack="node", workers=1), _s("mobile-config-fn", "fn", stack="node", url=True)),
        buckets=(Bkt("larkspur-mobile-assets", ("PUBLIC",), "none", size_gb=6.0),),
        secrets=(Sec("prod/push/apns-key", "api_key", "medium"), Sec("prod/push/fcm-key", "api_key", "medium")),
        staging=True,
    ),
    AppSpec(
        "p2p-transfers", "P2P Transfers", "tier-1", "wallet-eng", "prod", "prod-wallet", ("PII", "FINANCIAL"),
        "Peer-to-peer transfers and request-money flows.",
        services=(_s("p2p-api", "eks", workers=2), _s("p2p-limits-fn", "fn", stack="python")),
        dbs=(Db("p2p-db", "aurora-postgresql", ("PII", "FINANCIAL"), "high"),),
        secrets=(Sec("prod/p2p-db/app", "db_credentials", "high", unlocks="database:aws:111111111111:p2p-db"),),
        staging=True,
    ),
    AppSpec(
        "rewards-service", "Rewards Service", "tier-2", "wallet-eng", "prod", "prod-wallet", ("PII",),
        "Cashback and rewards accrual.",
        services=(_s("rewards-api", "eks", workers=1), _s("rewards-batch", "vm", count=2, stack="python")),
        dbs=(Db("rewards-db", "mysql", ("PII",), "medium"),),
        secrets=(Sec("prod/rewards-db/app", "db_credentials", "medium", unlocks="database:aws:111111111111:rewards-db"),),
        staging=True,
    ),
    # ------------------------------------------------------------------ BaaS
    AppSpec(
        "baas-gateway", "BaaS Gateway", "tier-0", "baas-api", "prod", "prod-baas", ("PII", "FINANCIAL"),
        "Banking-as-a-Service partner API gateway and partner-facing REST API.",
        services=(_s("baas-gateway", "eks", expose="lb", workers=2), _s("partner-api", "vm", count=3, expose="lb", port=443, stack="java"), _s("baas-batch", "vm", count=3, stack="java", port=8080)),
        dbs=(Db("baas-partners-db", "aurora-postgresql", ("PII", "FINANCIAL"), "high"),),
        buckets=(Bkt("larkspur-partner-data", ("PII",), "high", size_gb=540.0), Bkt("larkspur-baas-audit-logs", ("INTERNAL",), "medium", size_gb=1900.0)),
        secrets=(Sec("prod/baas-partners-db/app", "db_credentials", "high", unlocks="database:aws:111111111111:baas-partners-db"), Sec("prod/baas/partner-oauth-signing", "signing_key", "high")),
        staging=True,
    ),
    AppSpec(
        "partner-onboarding", "Partner Onboarding", "tier-1", "baas-api", "prod", "prod-baas", ("PII",),
        "KYB onboarding workflow for BaaS partners.",
        services=(_s("onboarding-api", "eks", expose="lb", workers=1), _s("onboarding-callback", "fn", stack="node", url=True)),
        dbs=(Db("onboarding-db", "postgres", ("PII",), "medium"),),
        buckets=(Bkt("larkspur-partner-kyb-docs", ("PII",), "high", size_gb=140.0),),
        secrets=(Sec("prod/onboarding-db/app", "db_credentials", "medium", unlocks="database:aws:111111111111:onboarding-db"),),
        staging=True,
    ),
    AppSpec(
        "webhook-dispatcher", "Webhook Dispatcher", "tier-2", "baas-api", "prod", "prod-baas", ("INTERNAL",),
        "Delivers event webhooks to partner endpoints with retries.",
        services=(_s("webhook-dispatcher", "eks", workers=1), _s("webhook-receiver", "fn", stack="node", url=True), _s("webhook-retry", "fn", stack="node")),
        dbs=(Db("webhook-queue-db", "dynamodb", ("INTERNAL",), "low"),),
        staging=True,
    ),
    AppSpec(
        "developer-portal", "Developer Portal", "tier-3", "baas-api", "prod", "prod-edge", ("PUBLIC",),
        "Public API documentation and sandbox sign-up portal.",
        services=(_s("devportal-web", "vm", count=2, expose="lb", port=3000, stack="node"), _s("devportal-signup", "fn", stack="node", url=True)),
        buckets=(Bkt("larkspur-devportal-static", ("PUBLIC",), "none", public=True, size_gb=1.2),),
        staging=True,
    ),
    # ------------------------------------------------------------------ platform engineering
    AppSpec(
        "platform-ssm-access", "Platform SSM Access", "tier-2", "platform-eng", "shared", "shared-mgmt", ("INTERNAL",),
        "Bastion and Session Manager access path used by platform engineering to reach private prod networks.",
        services=(_s("bastion", "vm", count=1, stack="os", os="Amazon Linux 2023"),),
        depends_on=((sc.BASTION_VM, "compute"),),
    ),
    AppSpec(
        "ci-cd-pipeline", "CI/CD Pipeline", "tier-1", "platform-eng", "shared", "shared-cicd", ("INTERNAL", "SECRETS"),
        "Jenkins controllers, build runners and the artifact registry.",
        services=(_s("ci-jenkins", "vm", count=1, expose="direct", port=8443, stack="java", component="jenkins"), _s("ci-runner", "vm", count=16, stack="go", port=8080), _s("artifact-registry", "vm", count=2, stack="java", port=8081), _s("ci-cache", "vm", count=2, stack="os", port=6379, component="redis"), _s("sonarqube", "vm", count=1, stack="java", port=9000)),
        buckets=(Bkt("larkspur-ci-artifacts", ("INTERNAL",), "medium", size_gb=2200.0), Bkt("larkspur-prod-deploy-artifacts", ("INTERNAL",), "medium", size_gb=380.0)),
        secrets=(Sec("shared/ci/github-app-key", "api_key", "high"), Sec("shared/ci/signing-key", "signing_key", "high")),
    ),
    AppSpec(
        "observability", "Observability", "tier-2", "platform-eng", "shared", "shared-monitoring", ("INTERNAL",),
        "Prometheus, Grafana and Loki stack.",
        services=(_s("prometheus", "vm", count=2, stack="go", port=9090), _s("grafana", "vm", count=2, expose="internal-lb", port=3000, stack="go", component="grafana"), _s("loki", "vm", count=4, stack="go", port=3100), _s("alertmanager", "vm", count=2, stack="go", port=9093), _s("thanos-store", "vm", count=3, stack="go", port=10901), _s("alert-router-fn", "fn", stack="python")),
        buckets=(Bkt("larkspur-loki-chunks", ("INTERNAL",), "medium", size_gb=5400.0), Bkt("larkspur-shared-logs", ("INTERNAL",), "medium", size_gb=8100.0)),
        secrets=(Sec("shared/grafana/admin", "api_key", "medium"), Sec("shared/pagerduty/integration-key", "api_key", "low")),
    ),
    AppSpec(
        "remote-access-gateway", "Remote Access Gateway", "tier-1", "platform-eng", "shared", "shared-edge", ("INTERNAL",),
        "NetScaler gateways fronting internal engineering tools for remote staff.",
        services=(_s("ns-gw", "appliance", count=2, expose="direct", port=443, stack="appliance", component="citrix-netscaler-gateway", os="NetScaler 13.1"),),
        secrets=(Sec("shared/ns-gw/tls-cert", "signing_key", "medium"),),
    ),
    AppSpec(
        "container-platform", "Container Platform", "tier-1", "platform-eng", "prod", "prod-eks", ("INTERNAL",),
        "EKS clusters, ingress and cluster add-ons.",
        buckets=(Bkt("larkspur-eks-velero-backups", ("INTERNAL", "SECRETS"), "high", size_gb=760.0),),
        secrets=(Sec("prod/eks/argocd-admin", "api_key", "high"),),
    ),
    AppSpec(
        "dns-and-edge", "DNS and Edge Proxy", "tier-1", "platform-eng", "prod", "prod-edge", ("SECRETS",),
        "Edge reverse proxies terminating TLS for public APIs.",
        services=(_s("edge-proxy", "vm", count=6, expose="direct", port=443, stack="os", os="Debian 12", component="nginx"),),
        buckets=(Bkt("larkspur-prod-tls-certs", ("SECRETS",), "high", size_gb=0.1),),
        secrets=(Sec("prod/edge/origin-tls-key", "signing_key", "high"),),
        staging=True,
    ),
    AppSpec(
        "secrets-management", "Secrets Management", "tier-1", "platform-eng", "shared", "shared-mgmt", ("SECRETS",),
        "HashiCorp Vault cluster for application secrets.",
        services=(_s("vault", "vm", count=3, stack="go", port=8200), _s("vault-agent-proxy", "vm", count=2, stack="go", port=8200)),
        buckets=(Bkt("larkspur-vault-storage", ("SECRETS",), "critical", crown_jewel=True, size_gb=3.0),),
        secrets=(Sec("shared/vault/unseal-key", "signing_key", "critical"),),
    ),
    AppSpec(
        "dev-sandbox", "Developer Sandbox", "tier-3", "platform-eng", "dev", "dev-sandbox", ("INTERNAL",),
        "Throwaway developer experiments and CI runner trials in the dev-sandbox account.",
        services=(_s("sandbox-runner", "vm", count=16, stack="os", role=False, os="Ubuntu 22.04"), _s("exp-api", "vm", count=8, stack="node", port=3000), _s("exp-notebook", "vm", count=4, stack="python", port=8888), _s("dev-k3s", "vm", count=6, stack="os", os="Ubuntu 24.04", port=6443), _s("log4j-testbed", "vm", count=1, expose="direct", port=8080, stack="java", role=False, os="Ubuntu 22.04")),
        buckets=(Bkt("larkspur-dev-scratch", ("INTERNAL",), "low", size_gb=45.0),),
        environment="dev",
    ),
    # ------------------------------------------------------------------ data platform
    AppSpec(
        "data-lake", "Data Lake", "tier-1", "data-platform", "data", "data-lake", ("PII", "FINANCIAL"),
        "Raw and curated data lake zones on S3 with Glue catalog.",
        services=(_s("lake-ingest", "eks", workers=3), _s("lake-api", "eks", stack="go"), _s("lake-loader", "vm", count=6, stack="python", port=8080), _s("lake-compaction-fn", "fn", stack="python")),
        buckets=(
            Bkt("larkspur-data-lake-raw", ("PII", "FINANCIAL"), "high", size_gb=41000.0),
            Bkt("larkspur-data-lake-curated", ("PII", "FINANCIAL"), "high", crown_jewel=True, size_gb=18700.0),
            Bkt("larkspur-data-lake-sandbox", ("INTERNAL",), "low", size_gb=900.0),
        ),
        secrets=(Sec("prod/data-lake/glue-crawler-key", "api_key", "medium"),),
    ),
    AppSpec(
        "warehouse", "Warehouse", "tier-1", "data-platform", "data", "data-warehouse", ("PII", "FINANCIAL"),
        "Redshift warehouse feeding finance and BI.",
        services=(_s("warehouse-loader", "vm", count=4, stack="python", port=8080), _s("trino", "eks", workers=2, stack="java")),
        dbs=(Db("warehouse-redshift", "redshift", ("PII", "FINANCIAL"), "high", crown_jewel=True), Db("warehouse-metadata", "postgres", ("INTERNAL",), "low")),
        secrets=(Sec("prod/warehouse/loader", "db_credentials", "high", unlocks="database:aws:555555555555:warehouse-redshift"), Sec("prod/warehouse/bi-readonly", "db_credentials", "high", unlocks="database:aws:555555555555:warehouse-redshift")),
    ),
    AppSpec(
        "analytics-jobs", "Analytics Jobs", "tier-2", "data-platform", "data", "data-jobs", ("PII",),
        "Airflow-orchestrated Spark jobs.",
        services=(_s("airflow", "vm", count=3, expose="internal-lb", port=8080, stack="python"), _s("spark-worker", "vm", count=24, stack="java", port=7077), _s("kafka-broker", "vm", count=6, stack="java", port=9092), _s("zookeeper", "vm", count=3, stack="java", port=2181), _s("notebook", "vm", count=6, stack="python", port=8888), _s("job-trigger-fn", "fn", stack="python")),
        dbs=(Db("airflow-metadb", "postgres", ("INTERNAL",), "low"),),
        buckets=(Bkt("larkspur-analytics-scratch", ("PII",), "medium", size_gb=3200.0),),
        secrets=(Sec("prod/airflow/metadb", "db_credentials", "low", unlocks="database:aws:555555555555:airflow-metadb"),),
    ),
    AppSpec(
        "reporting-bi", "Reporting and BI", "tier-2", "data-platform", "data", "data-warehouse", ("PII", "FINANCIAL"),
        "BI dashboards and scheduled report delivery.",
        services=(_s("bi-server", "vm", count=2, expose="internal-lb", port=8088, stack="java"), _s("report-mailer-fn", "fn", stack="python")),
        buckets=(Bkt("larkspur-bi-exports", ("FINANCIAL", "PII"), "medium", size_gb=84.0),),
    ),
    # ------------------------------------------------------------------ fraud ml
    AppSpec(
        "fraud-scoring", "Fraud Scoring", "tier-0", "fraud-ml", "prod", "prod-data-services", ("PII", "FINANCIAL"),
        "Real-time fraud scoring service on the payment path.",
        services=(_s("fraud-scorer", "eks", workers=3, stack="python"), _s("feature-pipeline", "eks", workers=1, stack="python"), _s("feature-store", "vm", count=4, stack="python", port=6379, component="redis"), _s("model-server", "vm", count=6, stack="python", port=8501)),
        dbs=(Db("feature-store-db", "aurora-postgresql", ("PII",), "high"),),
        buckets=(Bkt("larkspur-fraud-models", ("INTERNAL",), "medium", size_gb=230.0),),
        secrets=(Sec("prod/fraud/feature-store", "db_credentials", "high", unlocks="database:aws:111111111111:feature-store-db"),),
        staging=True,
    ),
    AppSpec(
        "fraud-model-training", "Fraud Model Training", "tier-1", "fraud-ml", "gcp_ml", "ml-fraud-vpc", ("PII",),
        "Model training pipelines on GCP with BigQuery feature datasets.",
        services=(_s("fraud-train", "vm", count=14, stack="python", port=8888), _s("vertex-endpoint", "vm", count=4, stack="python", port=8080)),
        dbs=(Db("fraud-features-bq", "bigquery", ("PII",), "high", crown_jewel=True),),
        buckets=(Bkt("larkspur-fraud-training-data", ("PII",), "high", crown_jewel=True, size_gb=9800.0), Bkt("larkspur-fraud-model-registry", ("INTERNAL",), "medium", size_gb=410.0)),
        secrets=(Sec("prod/ml/bq-service-account", "api_key", "high"),),
    ),
    AppSpec(
        "device-intelligence", "Device Intelligence", "tier-2", "fraud-ml", "prod", "prod-data-services", ("PII",),
        "Device fingerprinting and risk signals.",
        services=(_s("device-intel-api", "eks", stack="go", workers=1), _s("device-enrich-fn", "fn", stack="python")),
        dbs=(Db("device-intel-db", "dynamodb", ("PII",), "medium"),),
        staging=True,
    ),
    # ------------------------------------------------------------------ security engineering
    AppSpec(
        "vulnerability-scanning", "Vulnerability Scanning", "tier-2", "security-eng", "shared", "shared-mgmt", ("INTERNAL",),
        "Authenticated network vulnerability scanning from the shared-services account.",
        services=(_s("vulnscan", "vm", count=1, stack="os", os="Ubuntu 22.04"),),
        buckets=(Bkt("larkspur-vulnscan-reports", ("INTERNAL",), "medium", size_gb=19.0),),
        secrets=(Sec("shared/vulnscan/ssh-scan-key", "ssh_key", "high"),),
    ),
    AppSpec(
        "siem-forwarders", "SIEM Forwarders", "tier-1", "security-eng", "shared", "shared-monitoring", ("INTERNAL",),
        "Log forwarders shipping telemetry to the SIEM.",
        services=(_s("log-forwarder", "vm", count=6, stack="go", port=9997), _s("siem-heavy-forwarder", "vm", count=2, stack="go", port=9997), _s("cloudtrail-fanout-fn", "fn", stack="python")),
        buckets=(Bkt("larkspur-siem-staging", ("INTERNAL",), "medium", size_gb=3300.0),),
        secrets=(Sec("shared/siem/hec-token", "api_key", "medium"),),
    ),
    AppSpec(
        "iam-tooling", "IAM Tooling", "tier-2", "security-eng", "shared", "shared-mgmt", ("INTERNAL",),
        "Access review automation and key-rotation lambdas.",
        services=(_s("access-review-fn", "fn", stack="python"), _s("key-rotation-fn", "fn", stack="python"), _s("iam-report-fn", "fn", stack="python")),
        buckets=(Bkt("larkspur-iam-reports", ("INTERNAL",), "medium", size_gb=4.0),),
    ),
    # ------------------------------------------------------------------ mobile
    AppSpec(
        "mobile-release-tooling", "Mobile Release Tooling", "tier-3", "mobile-eng", "dev", "dev-mobile", ("INTERNAL",),
        "Build farm and release tooling for iOS and Android apps.",
        services=(_s("mobile-build", "vm", count=8, stack="os", os="Ubuntu 22.04", port=8080), _s("release-notes-fn", "fn", stack="node")),
        buckets=(Bkt("larkspur-mobile-builds", ("INTERNAL",), "low", size_gb=680.0),),
        environment="dev",
    ),
    # ------------------------------------------------------------------ corporate IT
    AppSpec(
        "marketing-site", "Marketing Site", "tier-3", "marketing", "corp", "corp-web", ("PUBLIC",),
        "Public marketing website and static assets.",
        services=(_s("marketing-web", "vm", count=2, expose="lb", port=80, stack="node"), _s("marketing-form-fn", "fn", stack="node", url=True)),
        buckets=(Bkt("larkspur-marketing-assets", ("PUBLIC",), "none", public=True, encrypted=False, size_gb=38.0),),
        environment="corp",
    ),
    AppSpec(
        "intranet-wiki", "Intranet Wiki", "tier-3", "corp-it", "corp", "corp-web", ("INTERNAL",),
        "Confluence wiki for internal documentation.",
        services=(_s("wiki-confluence", "vm", count=1, expose="direct", port=443, stack="java", role=False, component="confluence-server"),),
        dbs=(Db("wiki-db", "postgres", ("INTERNAL",), "low"),),
        environment="corp",
    ),
    AppSpec(
        "file-services", "File Services", "tier-2", "corp-it", "corp", "corp-it", ("INTERNAL", "PII"),
        "Windows file shares and print services for offices.",
        services=(_s("srv-fileshare", "vm", count=2, stack="windows", os="Windows Server 2022", role=False), _s("srv-print", "vm", count=1, stack="windows", os="Windows Server 2019", role=False, component="papercut-mf")),
        buckets=(Bkt("larkspur-fileshare-backups", ("INTERNAL", "PII"), "medium", size_gb=2600.0),),
        environment="corp",
    ),
    AppSpec(
        "corp-vpn", "Corporate VPN", "tier-1", "corp-it", "corp", "corp-it", ("INTERNAL",),
        "GlobalProtect VPN gateways for staff remote access.",
        services=(_s("vpn-pa", "appliance", count=1, expose="direct", port=443, stack="appliance", component="pan-os-globalprotect", os="PAN-OS 11.1.0"), _s("vpn-gw", "appliance", count=1, expose="direct", port=443, stack="appliance", component="vpn-gateway-firmware", os="SSL VPN Gateway 4.2.1")),
        environment="corp",
    ),
    AppSpec(
        "identity-integrations", "Identity Integrations", "tier-1", "corp-it", "corp", "corp-directory", ("SECRETS",),
        "Okta AD agents, SCIM connectors and directory sync.",
        services=(_s("okta-ad-agent", "vm", count=2, stack="windows", os="Windows Server 2022"), _s("scim-connector-fn", "fn", stack="node")),
        secrets=(Sec("corp/okta/api-token", "oauth_token", "critical"), Sec("corp/ad/sync-account", "db_credentials", "high")),
        environment="corp",
    ),
    AppSpec(
        "directory-services", "Directory Services", "tier-1", "corp-it", "corp", "corp-directory", ("SECRETS", "PII"),
        "Active Directory domain controllers for corp.larkspur.example.",
        services=(_s("dc", "vm", count=3, stack="windows", os="Windows Server 2022", role=False), _s("dc-legacy", "vm", count=1, stack="windows", os="Windows Server 2019", role=False, component="windows-netlogon")),
        environment="corp",
    ),
    AppSpec(
        "endpoint-management", "Endpoint Management", "tier-2", "corp-it", "corp", "corp-it", ("INTERNAL",),
        "MDM connectors, patch management and remote support tooling.",
        services=(_s("mdm-connector", "vm", count=1, stack="windows", os="Windows Server 2022"), _s("rmm-screenconnect", "vm", count=1, stack="windows", os="Windows Server 2022", role=False, component="connectwise-screenconnect"), _s("patch-report-fn", "fn", stack="python")),
        environment="corp",
    ),
    AppSpec(
        "collaboration-tools", "Collaboration Tools", "tier-3", "corp-it", "azure_corp", "corp-azure-vnet", ("INTERNAL",),
        "Entra-connected corporate services hosted in Azure.",
        services=(_s("intranet-portal", "vm", count=3, stack="windows", os="Windows Server 2022", port=443), _s("exch-hybrid", "vm", count=1, stack="windows", os="Windows Server 2019", role=False, component="exchange-server"), _s("print-relay", "vm", count=1, stack="windows", os="Windows Server 2022", role=False)),
        dbs=(Db("intranet-sql", "azure-sql", ("INTERNAL",), "low"),),
        buckets=(Bkt("larkspurcorpfiles", ("INTERNAL", "PII"), "medium", size_gb=1400.0),),
        environment="corp",
    ),
    # ------------------------------------------------------------------ operations, support, finance, compliance
    AppSpec(
        "settlement-sftp", "Settlement File SFTP", "tier-2", "finance-treasury", "shared", "shared-mgmt", ("FINANCIAL",),
        "Settlement-file SFTP pickup for Finance Treasury via the shared bastion (svc-finops-sftp).",
        buckets=(Bkt("larkspur-settlement-files", ("FINANCIAL",), "high", size_gb=57.0),),
        depends_on=((sc.BASTION_VM, "compute"),),
    ),
    AppSpec(
        "ops-dashboards", "Operations Dashboards", "tier-2", "payment-operations", "prod", "prod-data-services", ("PII", "FINANCIAL"),
        "Back-office console for payment operations (refunds, holds).",
        services=(_s("ops-console", "eks", expose="internal-lb", workers=1), _s("ops-export-fn", "fn", stack="python")),
        buckets=(Bkt("larkspur-ops-exports", ("PII", "FINANCIAL"), "medium", size_gb=32.0),),
        staging=True,
    ),
    AppSpec(
        "case-management", "Fraud Case Management", "tier-2", "fraud-operations", "prod", "prod-data-services", ("PII",),
        "Fraud investigation case tooling.",
        services=(_s("case-api", "eks", workers=1), _s("case-attachments-fn", "fn", stack="python")),
        dbs=(Db("case-db", "postgres", ("PII",), "medium"),),
        buckets=(Bkt("larkspur-case-attachments", ("PII",), "medium", size_gb=78.0),),
        secrets=(Sec("prod/case-db/app", "db_credentials", "medium", unlocks="database:aws:111111111111:case-db"),),
        staging=True,
    ),
    AppSpec(
        "support-desk", "Support Desk", "tier-2", "customer-support", "prod", "prod-data-services", ("PII",),
        "Customer support ticketing integration and agent tooling.",
        services=(_s("support-api", "eks", stack="node", workers=1), _s("support-sync-fn", "fn", stack="node")),
        dbs=(Db("support-db", "postgres", ("PII",), "medium"),),
        secrets=(Sec("prod/support-db/app", "db_credentials", "medium", unlocks="database:aws:111111111111:support-db"), Sec("prod/support/zendesk-token", "oauth_token", "medium")),
        staging=True,
    ),
    AppSpec(
        "erp-finance", "ERP Finance", "tier-1", "finance-accounting", "azure_corp", "corp-azure-vnet", ("FINANCIAL",),
        "General ledger ERP and close automation.",
        services=(_s("erp-app", "vm", count=2, stack="windows", os="Windows Server 2022", port=443), _s("erp-integration", "vm", count=1, stack="java", port=8080)),
        dbs=(Db("erp-sql", "azure-sql", ("FINANCIAL",), "high"),),
        buckets=(Bkt("larkspurerpexports", ("FINANCIAL",), "high", size_gb=210.0),),
        environment="corp",
    ),
    AppSpec(
        "treasury-reporting", "Treasury Reporting", "tier-2", "finance-treasury", "data", "data-warehouse", ("FINANCIAL",),
        "Liquidity and settlement reporting for Treasury.",
        services=(_s("treasury-report-fn", "fn", stack="python"),),
        buckets=(Bkt("larkspur-treasury-reports", ("FINANCIAL",), "high", size_gb=12.0),),
    ),
    AppSpec(
        "regulatory-reporting", "Regulatory Reporting", "tier-1", "compliance-risk", "data", "data-jobs", ("FINANCIAL", "PII"),
        "Regulatory filings and SAR/CTR report generation.",
        services=(_s("regrep-batch", "vm", count=2, stack="java", port=8080), _s("regrep-worker", "vm", count=3, stack="java", port=8080), _s("regrep-submit-fn", "fn", stack="python")),
        buckets=(Bkt("larkspur-regulatory-filings", ("FINANCIAL", "PII"), "high", size_gb=95.0),),
    ),
    AppSpec(
        "aml-monitoring", "AML Monitoring", "tier-1", "compliance-risk", "data", "data-jobs", ("PII", "FINANCIAL"),
        "Transaction monitoring rules engine and alert queue.",
        services=(_s("aml-engine", "vm", count=6, stack="java", port=8080), _s("aml-batch", "vm", count=4, stack="java", port=8080), _s("aml-console", "vm", count=2, expose="internal-lb", port=8443, stack="java")),
        dbs=(Db("aml-db", "aurora-postgresql", ("PII", "FINANCIAL"), "high"),),
        secrets=(Sec("prod/aml-db/app", "db_credentials", "high", unlocks="database:aws:555555555555:aml-db"),),
    ),
    AppSpec(
        "crm-integrations", "CRM Integrations", "tier-3", "sales", "corp", "corp-web", ("PII",),
        "CRM sync jobs and lead-capture handlers.",
        services=(_s("crm-sync-fn", "fn", stack="node"), _s("lead-capture-fn", "fn", stack="node", url=True)),
        environment="corp",
    ),
]
APP_BY_SLUG: dict[str, AppSpec] = {a.slug: a for a in APPS}


def build_apps(inv: Inventory, world: World) -> list[AppSpec]:
    for a in APPS:
        team = TEAM_BY_SLUG[a.team]
        inv.add_node(
            a.id, "Application", a.name,
            {
                "criticality": a.tier, "environment": a.environment, "owner_team_id": a.team_id, "description": a.description,
                "data_classifications": list(a.classes), "slug": a.slug, "primary_account_id": sc.ACCOUNTS[a.account]["account_id"],
                "owner_team_name": team.name, "service_owner_id": world.leads[a.team].id,
            },
            source=SOURCE_WIZ, source_id=f"app-{a.slug}", first_seen="2023-03-01T09:00:00Z",
        )
        inv.add_edge("OWNED_BY", a.id, a.team_id, source=SOURCE_WIZ)
    # statement-render is owned by the Payments Platform team; Lin Chen is its service owner
    inv.props(sc.APP_STMT_RENDER)["service_owner_id"] = sc.USER_LCHEN
    inv.storyline.update({
        "app_card_issuing": sc.APP_CARD_ISSUING, "app_stmt_render": sc.APP_STMT_RENDER, "app_marketing": sc.APP_MARKETING,
        "app_settlement_sftp": sc.APP_SETTLEMENT_SFTP, "app_platform_ssm_access": "app:larkspur:platform-ssm-access",
    })
    return APPS


def emit_business_edges(inv: Inventory, apps: list[AppSpec]) -> None:
    """PART_OF for every resource placed by the cloud pass, OWNED_BY for VMs/buckets/databases, DEPENDS_ON."""
    for a in apps:
        team_id = a.team_id
        for kind, ids in a.resources.items():
            for rid in ids:
                inv.add_edge("PART_OF", rid, a.id, {"resource_kind": kind}, source=SOURCE_WIZ)
                if kind in ("vm", "bucket", "database"):
                    inv.add_edge("OWNED_BY", rid, team_id, source=SOURCE_WIZ)
        for did in a.resources.get("database", []):
            if inv.props(did)["environment"] == a.environment:
                inv.add_edge("DEPENDS_ON", a.id, did, {"dependency_type": "database"}, source=SOURCE_WIZ)
        for bid in a.resources.get("bucket", []):
            p = inv.props(bid)
            if p.get("crown_jewel") or "SECRETS" in p.get("data_classifications", []):
                inv.add_edge("DEPENDS_ON", a.id, bid, {"dependency_type": "storage"}, source=SOURCE_WIZ)
        for sid in a.resources.get("secret", []):
            if inv.props(sid).get("secret_type") in ("db_credentials", "signing_key"):
                inv.add_edge("DEPENDS_ON", a.id, sid, {"dependency_type": "credential"}, source=SOURCE_WIZ)
        for target, dep_type in a.depends_on:
            tid = target if ":" in target else f"app:larkspur:{target}"
            inv.add_edge("DEPENDS_ON", a.id, tid, {"dependency_type": dep_type}, source=SOURCE_WIZ)
    # application-to-application dependencies (used by the containment simulation)
    app_deps = [
        ("card-issuing", "ledger", "service"), ("card-issuing", "fraud-scoring", "service"), ("card-issuing", "secrets-management", "secrets"),
        ("statement-render", "card-issuing", "data"), ("statement-render", "ledger", "data"),
        ("wallet-api", "ledger", "service"), ("wallet-api", "fraud-scoring", "service"), ("wallet-api", "card-issuing", "service"),
        ("wallet-mobile-backend", "wallet-api", "service"), ("p2p-transfers", "wallet-api", "service"), ("p2p-transfers", "ledger", "service"),
        ("rewards-service", "wallet-api", "service"), ("baas-gateway", "ledger", "service"), ("baas-gateway", "wallet-api", "service"),
        ("partner-onboarding", "baas-gateway", "service"), ("webhook-dispatcher", "baas-gateway", "service"),
        ("settlement-engine", "ledger", "data"), ("settlement-sftp", "settlement-engine", "data"), ("disputes-service", "card-issuing", "data"),
        ("fraud-scoring", "fraud-model-training", "model"), ("device-intelligence", "fraud-scoring", "service"),
        ("data-lake", "ledger", "data"), ("warehouse", "data-lake", "data"), ("analytics-jobs", "data-lake", "data"),
        ("reporting-bi", "warehouse", "data"), ("treasury-reporting", "warehouse", "data"), ("regulatory-reporting", "warehouse", "data"),
        ("aml-monitoring", "data-lake", "data"), ("ops-dashboards", "wallet-api", "service"), ("ops-dashboards", "card-issuing", "service"),
        ("case-management", "fraud-scoring", "service"), ("support-desk", "wallet-api", "service"),
        ("ci-cd-pipeline", "secrets-management", "secrets"), ("container-platform", "observability", "telemetry"),
        ("platform-ssm-access", "secrets-management", "secrets"), ("identity-integrations", "directory-services", "directory"),
        ("file-services", "directory-services", "directory"), ("corp-vpn", "directory-services", "directory"),
        ("erp-finance", "directory-services", "directory"), ("marketing-site", "crm-integrations", "service"),
    ]
    for src, dst, dep_type in app_deps:
        inv.add_edge("DEPENDS_ON", APP_BY_SLUG[src].id, APP_BY_SLUG[dst].id, {"dependency_type": dep_type}, source=SOURCE_WIZ)
