"""Inventory index consumed by the events stage, plus a deterministic fallback stub.

The events stage does not own cloud/identity/business/endpoint *nodes* -- the inventory stage
(``out/inventory.json``) does. This module only provides an in-memory *index* of the ids those nodes
carry, so the event generators can target endpoints/VMs/roles/buckets and so tests can assert that every
edge endpoint the events stage emits resolves either to something the events stage produced or to an id
the inventory declares.

Two ways an :class:`Inventory` is obtained (see :func:`resolve_inventory`):

* the real ``out/inventory.json`` written by the inventory stage (production),
* the hand-written ``tests/fixtures/mini_inventory.json`` (tests) -- both are augmented with a synthesized
  background fleet when they are too thin to spread noise over,
* nothing at all -> :func:`build_stub_inventory` synthesizes the named storyline entities plus a fleet and
  ``generate`` logs a warning.

Everything is derived deterministically from ``rng("events.inventory-stub")`` so two runs are byte-identical.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from throughline.simulator import storyline_constants as S
from throughline.simulator.common import rng, stable_hex

# A thin inventory (the mini fixture, or the pure fallback) is padded up to this many endpoints so the
# noise generators have a fleet to spread detections/logons across. A real inventory.json has ~2,000
# endpoints already and is never padded.
FLEET_ENDPOINT_FLOOR = 320

_DEPARTMENTS = {
    "Engineering": 0.35, "Operations": 0.20, "Sales/Marketing": 0.12, "Support": 0.12,
    "Finance": 0.08, "Compliance/Risk": 0.08, "Exec/Other": 0.05,
}
_SITES = ["Boston office", "New York office", "London office", "Austin office", "Remote"]
_WKS_OS = {"Windows 11": "windows", "Windows 10": "windows", "macOS 14": "mac"}
_SRV_OS = {"Amazon Linux 2023": "linux", "Ubuntu 22.04": "linux", "Windows Server 2022": "windows"}


@dataclass
class Inventory:
    """An index over the entities the inventory stage declares."""

    vms: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    users: list[dict[str, Any]] = field(default_factory=list)
    roles: list[dict[str, Any]] = field(default_factory=list)
    buckets: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    databases: list[dict[str, Any]] = field(default_factory=list)
    apps: list[dict[str, Any]] = field(default_factory=list)
    teams: list[dict[str, Any]] = field(default_factory=list)
    service_accounts: list[dict[str, Any]] = field(default_factory=list)
    account_ids: list[str] = field(default_factory=list)
    storyline: dict[str, Any] = field(default_factory=dict)
    source: str = "stub"

    _by_id: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._reindex()

    def _reindex(self) -> None:
        self._by_id = {}
        for coll in (self.vms, self.endpoints, self.users, self.roles, self.buckets,
                     self.secrets, self.databases, self.apps, self.teams, self.service_accounts):
            for rec in coll:
                self._by_id[rec["id"]] = rec

    # ------------------------------------------------------------------ lookups
    def get(self, node_id: str) -> dict[str, Any] | None:
        return self._by_id.get(node_id)

    def endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        rec = self._by_id.get(endpoint_id)
        return rec if rec and rec["id"].startswith("endpoint:") else None

    def user(self, user_id: str) -> dict[str, Any] | None:
        rec = self._by_id.get(user_id)
        return rec if rec and rec["id"].startswith("user:") else None

    def workstations(self) -> list[dict[str, Any]]:
        return [e for e in self.endpoints if e.get("device_type") == "workstation"]

    def servers(self) -> list[dict[str, Any]]:
        return [e for e in self.endpoints if e.get("device_type") in ("server", "k8s-node")]

    def internet_vms(self) -> list[dict[str, Any]]:
        return [v for v in self.vms if v.get("exposure") == "internet"]

    def prod_vms(self) -> list[dict[str, Any]]:
        return [v for v in self.vms if v.get("environment") == "prod"]

    def all_node_ids(self) -> set[str]:
        """Every id the inventory declares (targets that events edges may reference)."""
        ids = set(self._by_id)
        ids.update(self.account_ids)
        for v in self.storyline.values():
            if isinstance(v, str) and ":" in v:
                ids.add(v)
        return ids


# --------------------------------------------------------------------- named storyline entities


def _named_vms() -> list[dict[str, Any]]:
    return [
        {"id": S.BASTION_VM, "name": S.BASTION_NAME, "hostname": S.BASTION_HOSTNAME, "private_ip": S.BASTION_PRIVATE_IP,
         "public_ip": S.BASTION_PUBLIC_IP, "os": "Amazon Linux 2023", "os_family": "linux", "account_id": "222222222222",
         "environment": "prod", "exposure": "internal", "has_edr_sensor": True, "endpoint_id": S.EP_BASTION,
         "role_ids": [S.BASTION_ROLE], "app_id": None},
        {"id": S.EDGE_VM, "name": S.EDGE_NAME, "hostname": S.EDGE_HOSTNAME, "private_ip": S.EDGE_PRIVATE_IP,
         "public_ip": S.EDGE_PUBLIC_IP, "os": "Ubuntu 22.04", "os_family": "linux", "account_id": "111111111111",
         "environment": "prod", "exposure": "internet", "has_edr_sensor": True, "endpoint_id": S.EP_EDGE,
         "role_ids": [S.EDGE_ROLE], "app_id": S.APP_STMT_RENDER},
        {"id": S.STG_EDGE_VM, "name": S.STG_EDGE_NAME, "hostname": "stmt-render-stg-1.staging.larkspur.internal",
         "private_ip": "10.30.3.24", "public_ip": "198.51.100.64", "os": "Ubuntu 22.04", "os_family": "linux",
         "account_id": "333333333333", "environment": "staging", "exposure": "internet", "has_edr_sensor": True,
         "endpoint_id": "endpoint:falcon:aid-stgedge1", "role_ids": [], "app_id": None},
        {"id": S.DEV_LOG4J_VM, "name": S.DEV_LOG4J_NAME, "hostname": "log4j-testbed.dev.larkspur.internal",
         "private_ip": "10.50.9.11", "public_ip": "198.51.100.88", "os": "Ubuntu 22.04", "os_family": "linux",
         "account_id": "444444444444", "environment": "dev", "exposure": "internet", "has_edr_sensor": True,
         "endpoint_id": "endpoint:falcon:aid-log4jtb", "role_ids": [], "app_id": None},
        {"id": S.DEV_SANDBOX_VM, "name": S.DEV_SANDBOX_NAME, "hostname": "dev-sandbox-runner-03.dev.larkspur.internal",
         "private_ip": "10.50.1.33", "public_ip": None, "os": "Ubuntu 22.04", "os_family": "linux",
         "account_id": "444444444444", "environment": "dev", "exposure": "isolated", "has_edr_sensor": True,
         "endpoint_id": S.EP_DEV_SANDBOX, "role_ids": [], "app_id": None},
        {"id": S.SCANNER_VM, "name": S.SCANNER_NAME, "hostname": "vulnscan-01.shared.larkspur.internal",
         "private_ip": S.SCANNER_IP, "public_ip": None, "os": "Ubuntu 22.04", "os_family": "linux",
         "account_id": "222222222222", "environment": "prod", "exposure": "internal", "has_edr_sensor": True,
         "endpoint_id": "endpoint:falcon:aid-scan01", "role_ids": [], "app_id": None},
        {"id": S.FILESHARE_VM, "name": S.FILESHARE_NAME, "hostname": "srv-fileshare-01.corp.larkspur.internal",
         "private_ip": "10.60.2.20", "public_ip": None, "os": "Windows Server 2022", "os_family": "windows",
         "account_id": "666666666666", "environment": "corp", "exposure": "internal", "has_edr_sensor": True,
         "endpoint_id": S.EP_FILESHARE, "role_ids": [], "app_id": None},
    ]


def _named_endpoints() -> list[dict[str, Any]]:
    return [
        {"id": S.WKS_DANA, "hostname": S.WKS_DANA_HOSTNAME, "device_type": "workstation", "os": "Windows 11",
         "os_family": "windows", "private_ip": S.WKS_DANA_IP, "primary_user_id": S.USER_DANA, "vm_id": None, "site": "Boston office"},
        {"id": S.EP_BASTION, "hostname": "bas-01", "device_type": "server", "os": "Amazon Linux 2023",
         "os_family": "linux", "private_ip": S.BASTION_PRIVATE_IP, "primary_user_id": None, "vm_id": S.BASTION_VM, "site": "aws-shared-services"},
        {"id": S.EP_EDGE, "hostname": "stmt-render-2a", "device_type": "server", "os": "Ubuntu 22.04",
         "os_family": "linux", "private_ip": S.EDGE_PRIVATE_IP, "primary_user_id": None, "vm_id": S.EDGE_VM, "site": "aws-prod"},
        {"id": S.EP_DEV_SANDBOX, "hostname": S.DEV_SANDBOX_NAME, "device_type": "server", "os": "Ubuntu 22.04",
         "os_family": "linux", "private_ip": "10.50.1.33", "primary_user_id": None, "vm_id": S.DEV_SANDBOX_VM, "site": "aws-dev"},
        {"id": S.EP_FILESHARE, "hostname": S.FILESHARE_NAME, "device_type": "server", "os": "Windows Server 2022",
         "os_family": "windows", "private_ip": "10.60.2.20", "primary_user_id": None, "vm_id": S.FILESHARE_VM, "site": "aws-corp-it"},
        {"id": S.EP_MREYES, "hostname": S.EP_MREYES_HOSTNAME, "device_type": "workstation", "os": "Windows 11",
         "os_family": "windows", "private_ip": "10.40.9.21", "primary_user_id": S.USER_MREYES, "vm_id": None, "site": "New York office"},
        {"id": S.EP_PKAUR, "hostname": S.EP_PKAUR_HOSTNAME, "device_type": "workstation", "os": "macOS 14",
         "os_family": "mac", "private_ip": "10.40.7.5", "primary_user_id": S.USER_PKAUR, "vm_id": None, "site": "New York office"},
    ]


def _named_users() -> list[dict[str, Any]]:
    return [
        {"id": S.USER_DANA, "login": "dwhitfield", "display_name": "Dana Whitfield", "title": "Treasury Operations Analyst",
         "department": "Finance", "team_id": S.TEAM_TREASURY, "is_privileged": False, "is_executive": False,
         "endpoint_id": S.WKS_DANA, "location": "Boston"},
        {"id": S.USER_MREYES, "login": "mreyes", "display_name": "Marcus Reyes", "title": "IT Systems Administrator",
         "department": "Compliance/Risk", "team_id": S.TEAM_CORP_IT, "is_privileged": True, "is_executive": False,
         "endpoint_id": S.EP_MREYES, "location": "New York"},
        {"id": S.USER_PKAUR, "login": "pkaur", "display_name": "Priya Kaur", "title": "Chief Financial Officer",
         "department": "Exec/Other", "team_id": S.TEAM_TREASURY, "is_privileged": True, "is_executive": True,
         "endpoint_id": S.EP_PKAUR, "location": "New York"},
        {"id": S.USER_JOKAFOR, "login": "jokafor", "display_name": "Jide Okafor", "title": "Platform Engineering Lead",
         "department": "Engineering", "team_id": S.TEAM_PLATFORM, "is_privileged": True, "is_executive": False,
         "endpoint_id": None, "location": "Austin"},
        {"id": S.USER_LCHEN, "login": "lchen", "display_name": "Lin Chen", "title": "Statement-render Service Owner",
         "department": "Engineering", "team_id": S.TEAM_PAYMENTS, "is_privileged": False, "is_executive": False,
         "endpoint_id": None, "location": "Remote"},
    ]


def _named_roles() -> list[dict[str, Any]]:
    return [
        {"id": S.BASTION_ROLE, "name": "LarkspurBastionSSMRole", "account_id": "222222222222", "arn": S.BASTION_ROLE_ARN,
         "role_type": "instance", "attached_vm_ids": [S.BASTION_VM]},
        {"id": S.PROD_READER_ROLE, "name": "LarkspurProdDataReader", "account_id": "111111111111", "arn": S.PROD_READER_ROLE_ARN,
         "role_type": "cross-account", "attached_vm_ids": []},
        {"id": S.EDGE_ROLE, "name": "LarkspurStmtRenderRole", "account_id": "111111111111", "arn": S.EDGE_ROLE_ARN,
         "role_type": "instance", "attached_vm_ids": [S.EDGE_VM]},
        {"id": S.CORP_IT_ADMIN_ROLE, "name": "LarkspurCorpItAdmin", "account_id": "666666666666",
         "arn": "arn:aws:iam::666666666666:role/LarkspurCorpItAdmin", "role_type": "sso", "attached_vm_ids": []},
    ]


def _named_buckets() -> list[dict[str, Any]]:
    return [
        {"id": S.CARDHOLDER_VAULT, "name": "larkspur-cardholder-vault", "account_id": "111111111111",
         "sensitivity": "critical", "crown_jewel": True, "public": False, "data_classifications": ["PCI"]},
        {"id": S.KYC_DOCS, "name": "larkspur-kyc-documents", "account_id": "111111111111",
         "sensitivity": "high", "crown_jewel": True, "public": False, "data_classifications": ["PII"]},
        {"id": S.APP_CONFIG_BUCKET, "name": "larkspur-prod-app-config", "account_id": "111111111111",
         "sensitivity": "high", "crown_jewel": False, "public": False, "data_classifications": ["SECRETS"]},
        {"id": S.STATEMENTS_OUT_BUCKET, "name": "larkspur-statements-out", "account_id": "111111111111",
         "sensitivity": "medium", "crown_jewel": False, "public": False, "data_classifications": ["PII"]},
        {"id": S.SHARED_LOGS_BUCKET, "name": "larkspur-shared-logs", "account_id": "222222222222",
         "sensitivity": "low", "crown_jewel": False, "public": False, "data_classifications": ["INTERNAL"]},
        {"id": S.MARKETING_BUCKET, "name": "larkspur-marketing-assets", "account_id": "666666666666",
         "sensitivity": "none", "crown_jewel": False, "public": True, "data_classifications": ["PUBLIC"]},
    ]


def _named_secrets() -> list[dict[str, Any]]:
    return [
        {"id": S.DB_READER_SECRET, "name": "prod/cardholder-db/reader", "account_id": "111111111111",
         "secret_type": "db_credentials", "sensitivity": "critical"},
        {"id": S.HSM_SECRET, "name": "prod/hsm/partner-signing-key", "account_id": "111111111111",
         "secret_type": "signing_key", "sensitivity": "critical"},
    ]


def _named_databases() -> list[dict[str, Any]]:
    return [
        {"id": S.CARDHOLDER_DB, "name": "cardholder-db", "account_id": "111111111111", "engine": "postgres",
         "sensitivity": "critical", "crown_jewel": True, "public": False, "data_classifications": ["PCI"]},
    ]


def _named_apps() -> list[dict[str, Any]]:
    return [
        {"id": S.APP_CARD_ISSUING, "name": "card-issuing", "criticality": "tier-0"},
        {"id": S.APP_STMT_RENDER, "name": "statement-render", "criticality": "tier-1"},
        {"id": S.APP_MARKETING, "name": "marketing-site", "criticality": "tier-3"},
        {"id": S.APP_SETTLEMENT_SFTP, "name": "settlement-sftp", "criticality": "tier-2"},
    ]


def _named_teams() -> list[dict[str, Any]]:
    return [
        {"id": S.TEAM_PLATFORM, "name": "platform-eng", "department": "Engineering"},
        {"id": S.TEAM_PAYMENTS, "name": "payments-platform", "department": "Engineering"},
        {"id": S.TEAM_TREASURY, "name": "finance-treasury", "department": "Finance"},
        {"id": S.TEAM_CORP_IT, "name": "corp-it", "department": "Compliance/Risk"},
    ]


def _named_service_accounts() -> list[dict[str, Any]]:
    return [
        {"id": S.SVC_FINOPS_SFTP, "system": "linux", "host_id": S.EP_BASTION, "purpose": "settlement-file SFTP", "privileged": False},
    ]


def _storyline_index() -> dict[str, Any]:
    return {
        "bastion_vm": S.BASTION_VM, "bastion_endpoint": S.EP_BASTION, "bastion_role": S.BASTION_ROLE,
        "prod_reader_role": S.PROD_READER_ROLE, "edge_vm": S.EDGE_VM, "edge_endpoint": S.EP_EDGE, "edge_role": S.EDGE_ROLE,
        "wks_dana": S.WKS_DANA, "user_dana": S.USER_DANA, "svc_finops_sftp": S.SVC_FINOPS_SFTP,
        "cardholder_vault": S.CARDHOLDER_VAULT, "kyc_docs": S.KYC_DOCS, "db_reader_secret": S.DB_READER_SECRET,
        "hsm_secret": S.HSM_SECRET, "cardholder_db": S.CARDHOLDER_DB, "app_config_bucket": S.APP_CONFIG_BUCKET,
        "marketing_bucket": S.MARKETING_BUCKET, "dev_sandbox_vm": S.DEV_SANDBOX_VM, "scanner_vm": S.SCANNER_VM,
        "fileshare_vm": S.FILESHARE_VM, "user_mreyes": S.USER_MREYES, "user_pkaur": S.USER_PKAUR,
    }


def _account_ids() -> list[str]:
    return [a["id"] for a in S.ACCOUNTS.values()]


# --------------------------------------------------------------------- synthesized background fleet


def _pick_weighted(r: Any, weighted: dict[str, float]) -> str:
    return r.choices(list(weighted), weights=list(weighted.values()), k=1)[0]


def synthesize_fleet(existing: Inventory, target_endpoints: int = FLEET_ENDPOINT_FLOOR) -> None:
    """Pad ``existing`` with a deterministic background fleet until it has ``target_endpoints`` endpoints.

    Adds workstation endpoints (each with a human user) and a smaller number of server VMs (each with a
    server endpoint), a slice of them internet-exposed, so the noise generators have material. Ids are
    stable across runs because they derive from ``rng`` seeded by index only.
    """
    r = rng("events.inventory-stub")
    have = len(existing.endpoints)
    need = max(0, target_endpoints - have)
    n_servers = max(20, need // 6)
    n_wks = need - n_servers
    login_seen = {u["login"] for u in existing.users}

    for i in range(n_wks):
        h = stable_hex("wks", i, length=8)
        aid = f"aid-w{h}"
        eid = f"endpoint:falcon:aid-w{h}"
        dept = _pick_weighted(r, _DEPARTMENTS)
        first = r.choice(["alex", "sam", "jordan", "taylor", "morgan", "casey", "riley", "jamie", "avery",
                          "quinn", "reese", "devon", "harper", "rowan", "sasha", "noor", "kai", "iris", "leo", "mira"])
        login = f"{first}{h[:5]}"
        while login in login_seen:
            login = f"{first}{stable_hex('u', i, login, length=5)}"
        login_seen.add(login)
        uid = f"user:okta:{login}"
        os_name = _pick_weighted(r, {"Windows 11": 0.6, "Windows 10": 0.25, "macOS 14": 0.15})
        existing.users.append({
            "id": uid, "login": login, "display_name": login.title(), "title": f"{dept} staff",
            "department": dept, "team_id": None, "is_privileged": r.random() < 0.05,
            "is_executive": False, "endpoint_id": eid, "location": r.choice(_SITES).split()[0]})
        existing.endpoints.append({
            "id": eid, "hostname": f"WKS-{1000 + i}", "device_type": "workstation", "os": os_name,
            "os_family": _WKS_OS[os_name], "private_ip": f"10.40.{20 + i // 250}.{i % 250 + 2}",
            "primary_user_id": uid, "vm_id": None, "site": r.choice(_SITES)})

    for i in range(n_servers):
        h = stable_hex("srv", i, length=12)
        vm_id = f"vm:aws:i-{h}"
        eid = f"endpoint:falcon:aid-s{stable_hex('srv-ep', i, length=8)}"
        os_name = _pick_weighted(r, {"Amazon Linux 2023": 0.5, "Ubuntu 22.04": 0.3, "Windows Server 2022": 0.2})
        env = _pick_weighted(r, {"prod": 0.5, "staging": 0.2, "dev": 0.2, "corp": 0.1})
        exposure = "internet" if i < max(12, n_servers // 5) else _pick_weighted(r, {"internal": 0.8, "isolated": 0.2})
        acct = r.choice(["111111111111", "222222222222", "333333333333", "444444444444", "555555555555", "666666666666"])
        existing.vms.append({
            "id": vm_id, "name": f"srv-{h[:6]}", "hostname": f"srv-{h[:6]}.{env}.larkspur.internal",
            "private_ip": f"10.{10 + i % 40}.{i % 250}.{(i * 7) % 250 + 2}",
            "public_ip": f"198.51.100.{130 + i % 120}" if exposure == "internet" else None,
            "os": os_name, "os_family": _SRV_OS[os_name], "account_id": acct, "environment": env,
            "exposure": exposure, "has_edr_sensor": True, "endpoint_id": eid, "role_ids": [], "app_id": None})
        existing.endpoints.append({
            "id": eid, "hostname": f"srv-{h[:6]}", "device_type": "server", "os": os_name,
            "os_family": _SRV_OS[os_name], "private_ip": existing.vms[-1]["private_ip"],
            "primary_user_id": None, "vm_id": vm_id, "site": f"aws-{env}"})

    existing._reindex()


def build_stub_inventory(target_endpoints: int = FLEET_ENDPOINT_FLOOR) -> Inventory:
    """The pure fallback: named storyline entities plus a synthesized background fleet."""
    inv = Inventory(
        vms=_named_vms(), endpoints=_named_endpoints(), users=_named_users(), roles=_named_roles(),
        buckets=_named_buckets(), secrets=_named_secrets(), databases=_named_databases(), apps=_named_apps(),
        teams=_named_teams(), service_accounts=_named_service_accounts(), account_ids=_account_ids(),
        storyline=_storyline_index(), source="stub",
    )
    synthesize_fleet(inv, target_endpoints)
    return inv


def inventory_from_json(path: Path) -> Inventory:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    inv = Inventory(
        vms=data.get("vms", []), endpoints=data.get("endpoints", []), users=data.get("users", []),
        roles=data.get("roles", []), buckets=data.get("buckets", []), secrets=data.get("secrets", []),
        databases=data.get("databases", []), apps=data.get("apps", []), teams=data.get("teams", []),
        service_accounts=data.get("service_accounts", []),
        account_ids=data.get("account_ids") or _account_ids(),
        storyline=data.get("storyline", {}), source=str(path),
    )
    return inv


def write_mini_fixture(path: Path) -> Path:
    """Materialize the hand-authored named-entity fixture (named entities only, no synthesized fleet)."""
    payload = {
        "vms": _named_vms(), "endpoints": _named_endpoints(), "users": _named_users(), "roles": _named_roles(),
        "buckets": _named_buckets(), "secrets": _named_secrets(), "databases": _named_databases(),
        "apps": _named_apps(), "teams": _named_teams(), "service_accounts": _named_service_accounts(),
        "account_ids": _account_ids(), "storyline": _storyline_index(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
