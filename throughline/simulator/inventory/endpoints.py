"""Endpoint (EDR device) inventory: one workstation per human user, one server endpoint for ~90% of cloud VMs
(EKS nodes included, appliances and a handful of deliberate prod gaps excluded), entity resolution ``SAME_AS`` edges
with method/confidence per docs/03 section 5, and ``PRIMARY_USER`` edges.
"""
from __future__ import annotations

import ipaddress
import random

from throughline.simulator import storyline_constants as sc
from throughline.simulator.common import rng
from throughline.simulator.inventory._base import (
    SOURCE_DERIVED,
    SOURCE_FALCON,
    Inventory,
    days_ago,
    hexid,
    minutes_ago,
)
from throughline.simulator.inventory.cloud import ACCOUNT_ID, Estate
from throughline.simulator.inventory.names import LOCATION_EGRESS, LOCATION_NET, LOCATION_OU, LOCATION_SITE
from throughline.simulator.inventory.world import World

NAMED_ENDPOINTS: dict[str, str] = {  # vm id -> endpoint id
    sc.BASTION_VM: sc.EP_BASTION, sc.EDGE_VM: sc.EP_EDGE, sc.DEV_SANDBOX_VM: sc.EP_DEV_SANDBOX, sc.FILESHARE_VM: sc.EP_FILESHARE,
}
NAMED_WORKSTATIONS: dict[str, int] = {"dwhitfield": 3391, "mreyes": 2210, "pkaur": 1042}
# prod VMs deliberately left without a sensor (coverage gap shown on the dashboard)
PROD_GAPS: set[str] = {"edge-proxy-3", "feature-store-2", "wallet-api-11", "spark-worker-17", "tokenization-3", "ledger-batch-5"}
MUST_HAVE_SENSOR: set[str] = {sc.BASTION_VM, sc.EDGE_VM, sc.DEV_SANDBOX_VM, sc.FILESHARE_VM, sc.STG_EDGE_VM, sc.DEV_LOG4J_VM, sc.SCANNER_VM,
                              "vm:aws:i-0spr3e5a7c9b1d3f5e", "vm:aws:i-0jnk4f6b8d0c2e4a6c", "vm:aws:i-0cnf5a7c9e1d3b5f7a"}
NAT_EGRESS: dict[str, str] = {
    "111111111111": "198.51.100.240", "222222222222": "198.51.100.241", "333333333333": "198.51.100.242", "444444444444": "198.51.100.243",
    "555555555555": "198.51.100.244", "666666666666": "198.51.100.245", "larkspur-ml-fraud": "198.51.100.246", "7a1c9e2b-4d3f-4a8e-9b1c-2f3e4d5a6b7c": "198.51.100.247",
}
SENSOR_VERSIONS = ["7.24.19607.0", "7.23.19508.0", "7.22.19410.0", "7.21.19306.0", "7.19.19104.0"]
MAC_VERSIONS = ["7.24.19607.0", "7.23.19508.0", "7.22.19410.0"]
WINDOWS_11 = ["Windows 11 24H2", "Windows 11 23H2", "Windows 11 23H2", "Windows 11 22H2"]
MACOS = ["macOS 15.1 (Sequoia)", "macOS 15.0 (Sequoia)", "macOS 14.6 (Sonoma)"]
PROVIDER_META: dict[str, str] = {"aws": "AWS_EC2_V2", "gcp": "GCP", "azure": "AZURE"}


def build_endpoints(inv: Inventory, world: World, est: Estate) -> None:
    _workstations(inv, world)
    _servers(inv, est)
    inv.storyline.update({
        "wks_dana": sc.WKS_DANA, "ep_bastion": sc.EP_BASTION, "ep_edge": sc.EP_EDGE, "ep_dev_sandbox": sc.EP_DEV_SANDBOX, "ep_fileshare": sc.EP_FILESHARE,
        "ep_mreyes": sc.EP_MREYES, "ep_pkaur": sc.EP_PKAUR,
    })


def _workstations(inv: Inventory, world: World) -> None:
    r = rng("inventory.endpoints.workstations")
    numbers = [n for n in range(1000, 10000) if n not in NAMED_WORKSTATIONS.values()]
    r.shuffle(numbers)
    ip_counters: dict[str, int] = {}
    for idx, p in enumerate(world.people):
        if p.status == "deprovisioned":
            continue
        num = NAMED_WORKSTATIONS.get(p.login, numbers[idx])
        aid = f"aid-wks{num}"
        eid = f"endpoint:falcon:{aid}"
        hostname = f"WKS-{num}"
        net = ipaddress.ip_network(LOCATION_NET[p.location])
        if p.login == "dwhitfield":
            ip = sc.WKS_DANA_IP
        else:
            k = ip_counters.get(p.location, 0)
            ip_counters[p.location] = k + 1
            # spread across /24s inside the office /16, skip Dana's address
            ip = str(net.network_address + 256 * (10 + k // 200) + 20 + k % 200)
            if ip == sc.WKS_DANA_IP:
                ip = str(net.network_address + 256 * 60 + 5)
        mac = p.mac
        os_name = r.choice(MACOS) if mac else r.choice(WINDOWS_11)
        stale = r.random() < 0.03 or p.status == "suspended"
        last_seen = days_ago(r, 3, 25) if stale else minutes_ago(r, 1, 240)
        ou = f"OU=Workstations,OU={LOCATION_OU[p.location]},DC=corp,DC=larkspur,DC=example" if not mac else f"Jamf/{LOCATION_OU[p.location]}/Staff"
        inv.add_node(
            eid, "Endpoint", hostname,
            {
                "hostname": hostname, "device_type": "workstation", "os": os_name, "os_family": "macos" if mac else "windows", "private_ip": ip,
                "public_ip": LOCATION_EGRESS[p.location], "site": LOCATION_SITE[p.location], "sensor_version": r.choice(MAC_VERSIONS if mac else SENSOR_VERSIONS),
                "last_seen_sensor": last_seen, "cloud_provider": None, "cloud_instance_id": None, "cloud_account_id": None, "primary_user_id": p.id,
                "containment_status": "normal", "ou": ou, "machine_domain": None if mac else "corp.larkspur.example", "mac_address": _mac(aid),
                "serial_number": ("C02" if mac else "5CG") + hexid("serial", aid, length=9).upper(), "manufacturer": "Apple" if mac else r.choice(["Dell Inc.", "Dell Inc.", "Lenovo", "HP"]),
                "agent_local_time": last_seen, "reduced_functionality_mode": False, "prevention_policy": "Workstations - Aggressive" if not p.executive else "Executives - Balanced",
                "tags": ["FalconGroupingTags/Workstations", f"FalconGroupingTags/{LOCATION_OU[p.location]}"] + (["FalconGroupingTags/Executives"] if p.executive else []) + (["FalconGroupingTags/PrivilegedUsers"] if p.privileged else []),
            },
            source=SOURCE_FALCON, source_id=aid, first_seen=days_ago(r, 40, 900), last_seen=last_seen, kind="endpoint", user=p.id,
        )
        inv.add_edge("PRIMARY_USER", eid, p.id, source=SOURCE_FALCON, first_seen=days_ago(r, 40, 900))
        inv.props(p.id)["workstation_id"] = eid
        inv.meta[p.id]["endpoint_id"] = eid


def _servers(inv: Inventory, est: Estate) -> None:
    r = rng("inventory.endpoints.servers")
    for vm in est.vms:
        p = inv.props(vm)
        meta = inv.meta[vm]
        name = inv.name(vm)
        if meta.get("stack") == "appliance":
            p["has_edr_sensor"] = False
            meta["sensor_gap_reason"] = "appliance (no sensor support)"
            continue
        if name in PROD_GAPS:
            p["has_edr_sensor"] = False
            meta["sensor_gap_reason"] = "not enrolled"
            continue
        if vm not in MUST_HAVE_SENSOR:
            gap_rate = 0.04 if p["is_k8s_node"] else 0.07
            if r.random() < gap_rate:
                p["has_edr_sensor"] = False
                meta["sensor_gap_reason"] = r.choice(["not enrolled", "sensor uninstalled", "image without sensor"])
                continue
        p["has_edr_sensor"] = True
        eid = NAMED_ENDPOINTS.get(vm, f"endpoint:falcon:aid-{hexid('aid', vm, length=12)}")
        aid = eid.split(":")[-1]
        if vm in NAMED_ENDPOINTS:
            method = "instance_id"
        else:
            roll = r.random()
            method = "instance_id" if roll < 0.84 else ("hostname_ip" if roll < 0.95 else "hostname_only")
        confidence = {"instance_id": 0.99, "hostname_ip": 0.9, "hostname_only": 0.6}[method]
        provider = p["provider"]
        has_cloud_meta = method == "instance_id"
        private_ip = p["private_ip"]
        if method == "hostname_only":
            # the sensor reports a stale DHCP address: hostname matches, IP does not
            octets = private_ip.split(".")
            private_ip = ".".join(octets[:3] + [str((int(octets[3]) + 37) % 200 + 20)])
        stale = r.random() < 0.03
        last_seen = days_ago(r, 3, 20) if stale else minutes_ago(r, 1, 90)
        if vm == sc.BASTION_VM:
            last_seen = "2026-09-11T13:58:12Z"
        windows = p["os_family"] == "windows"
        inv.add_node(
            eid, "Endpoint", name,
            {
                "hostname": name, "device_type": "k8s-node" if p["is_k8s_node"] else "server", "os": p["os"], "os_family": p["os_family"], "private_ip": private_ip,
                "public_ip": p.get("public_ip") or NAT_EGRESS.get(p["account_id"]), "site": f"{provider.upper()} {p['region']}", "sensor_version": r.choice(SENSOR_VERSIONS),
                "last_seen_sensor": last_seen, "cloud_provider": provider if has_cloud_meta else None, "cloud_instance_id": inv.nodes[vm]["source_id"] if has_cloud_meta else None,
                "cloud_account_id": p["account_id"] if has_cloud_meta else None, "primary_user_id": None, "containment_status": "normal",
                "ou": "OU=Servers,OU=Cloud,DC=corp,DC=larkspur,DC=example" if windows else None, "machine_domain": "corp.larkspur.example" if windows else None,
                "mac_address": _mac(aid), "agent_local_time": last_seen, "reduced_functionality_mode": r.random() < 0.02,
                "prevention_policy": "Servers - Balanced" if not p["is_k8s_node"] else "Kubernetes Nodes", "resolution_method": method,
                "tags": [f"FalconGroupingTags/{'K8sNodes' if p['is_k8s_node'] else 'Servers'}", f"FalconGroupingTags/{p['environment']}", f"FalconGroupingTags/{provider.upper()}-{p['account_id'][:12]}"],
            },
            source=SOURCE_FALCON, source_id=aid, first_seen=inv.nodes[vm]["first_seen"], last_seen=last_seen, kind="endpoint", vm_id=vm, method=method,
        )
        edge_props = {"method": method, "confidence": confidence}
        if method == "hostname_only":
            edge_props["needs_review"] = True
            edge_props["reason"] = "hostname match only; sensor IP differs from cloud inventory"
        elif method == "hostname_ip":
            edge_props["reason"] = "sensor lacks cloud metadata; hostname and private IP match"
        inv.add_edge("SAME_AS", eid, vm, edge_props, source=SOURCE_DERIVED, confidence=confidence, first_seen=inv.nodes[vm]["first_seen"])
        meta["endpoint_id"] = eid


def _mac(seed: str) -> str:
    h = hexid("mac", seed, length=10)
    return "02:" + ":".join(h[i:i + 2] for i in range(0, 10, 2))


def account_key_of(account_id: str) -> str | None:
    for k, v in ACCOUNT_ID.items():
        if v == account_id:
            return k
    return None


def _unused(r: random.Random) -> None:  # pragma: no cover - keeps the random import honest for type checkers
    r.random()
