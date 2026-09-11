"""``inventory.json``: the compact index consumed by the events stage (docs/06 section 2.1)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from throughline.simulator import storyline_constants as sc
from throughline.simulator.inventory._base import Inventory


def build_index(inv: Inventory, counts: dict[str, Any]) -> dict[str, Any]:
    vms = []
    for vm in inv.ids("VirtualMachine"):
        p = inv.props(vm)
        m = inv.meta[vm]
        vms.append({
            "id": vm, "name": inv.name(vm), "hostname": p["hostname"], "private_ip": p["private_ip"], "public_ip": p.get("public_ip"), "os": p["os"],
            "os_family": p["os_family"], "account_id": p["account_id"], "environment": p["environment"], "exposure": p["exposure"], "has_edr_sensor": p["has_edr_sensor"],
            "endpoint_id": m.get("endpoint_id"), "role_ids": inv.out(vm, "HAS_ROLE"), "app_id": p.get("app_id"), "is_k8s_node": p["is_k8s_node"], "region": p["region"],
            "public_ports": p.get("public_ports", []), "tags": p.get("tags", {}), "criticality": p.get("criticality"), "crown_jewel_reach": p.get("crown_jewel_reach", 0),
            "cve_ids": inv.out(vm, "VULNERABLE_TO"), "service": m.get("service"), "cluster": m.get("cluster"),
        })
    endpoints = []
    for eid in inv.ids("Endpoint"):
        p = inv.props(eid)
        m = inv.meta[eid]
        endpoints.append({
            "id": eid, "hostname": p["hostname"], "device_type": p["device_type"], "os": p["os"], "os_family": p["os_family"], "private_ip": p["private_ip"],
            "public_ip": p.get("public_ip"), "primary_user_id": p.get("primary_user_id"), "vm_id": m.get("vm_id"), "site": p["site"], "last_seen_sensor": p["last_seen_sensor"],
            "sensor_version": p["sensor_version"], "resolution_method": m.get("method"), "aid": inv.nodes[eid]["source_id"],
        })
    users = []
    for uid in inv.ids("HumanUser"):
        p = inv.props(uid)
        users.append({
            "id": uid, "login": p["login"], "email": p["email"], "display_name": p["display_name"], "title": p["title"], "department": p["department"], "team_id": p["team_id"],
            "is_privileged": p["is_privileged"], "is_executive": p["is_executive"], "endpoint_id": inv.meta[uid].get("endpoint_id"), "location": p["location"],
            "status": p["status"], "groups": p.get("groups", []), "role_ids": [x for x in inv.out(uid, "MAPS_TO") if inv.label(x) == "IamRole"], "manager_id": p.get("manager_id"),
        })
    roles = []
    for rid in inv.ids("IamRole"):
        p = inv.props(rid)
        roles.append({
            "id": rid, "name": inv.name(rid), "account_id": p["account_id"], "arn": p["arn"], "role_type": p["role_type"], "attached_vm_ids": [x for x in inv.inn(rid, "HAS_ROLE") if inv.label(x) == "VirtualMachine"],
            "attached_workload_ids": [x for x in inv.inn(rid, "HAS_ROLE") if inv.label(x) == "Workload"], "attached_function_ids": [x for x in inv.inn(rid, "HAS_ROLE") if inv.label(x) == "ServerlessFunction"],
            "is_admin": p["is_admin"], "privilege_score": p["privilege_score"], "can_assume": inv.out(rid, "CAN_ASSUME"), "policy_ids": inv.out(rid, "HAS_POLICY"),
            "can_access": [{"id": t, "access_level": inv.get_edge("CAN_ACCESS", rid, t)["props"]["access_level"], "path_length": inv.get_edge("CAN_ACCESS", rid, t)["props"]["path_length"]} for t in inv.out(rid, "CAN_ACCESS")],
            "environment": p.get("environment"), "last_used": p.get("last_used"), "mapped_user_ids": [x for x in inv.inn(rid, "MAPS_TO") if inv.label(x) == "HumanUser"],
        })
    iam_users = []
    for uid in inv.ids("IamUser"):
        p = inv.props(uid)
        iam_users.append({"id": uid, "name": inv.name(uid), "account_id": p["account_id"], "arn": p["arn"], "is_admin": p["is_admin"], "mfa_enabled": p["mfa_enabled"], "console_access": p["console_access"], "access_key_ids": [inv.name(k) for k in inv.out(uid, "HAS_ACCESS_KEY")], "access_key_node_ids": inv.out(uid, "HAS_ACCESS_KEY")})
    buckets = [
        {"id": b, "name": inv.name(b), "account_id": inv.props(b)["account_id"], "sensitivity": inv.props(b)["sensitivity"], "crown_jewel": inv.props(b)["crown_jewel"], "public": inv.props(b)["public"],
         "data_classifications": inv.props(b)["data_classifications"], "environment": inv.props(b)["environment"], "app_id": inv.props(b).get("app_id"), "region": inv.props(b)["region"]}
        for b in inv.ids("StorageBucket")
    ]
    secrets = [
        {"id": s, "name": inv.name(s), "account_id": inv.props(s)["account_id"], "secret_type": inv.props(s)["secret_type"], "sensitivity": inv.props(s)["sensitivity"], "grants_access_to": inv.props(s)["grants_access_to"], "app_id": inv.props(s).get("app_id")}
        for s in inv.ids("Secret")
    ]
    databases = [
        {"id": d, "name": inv.name(d), "account_id": inv.props(d)["account_id"], "engine": inv.props(d)["engine"], "sensitivity": inv.props(d)["sensitivity"], "crown_jewel": inv.props(d)["crown_jewel"], "public": inv.props(d)["public"],
         "data_classifications": inv.props(d)["data_classifications"], "environment": inv.props(d)["environment"], "app_id": inv.props(d).get("app_id")}
        for d in inv.ids("Database")
    ]
    apps = [
        {"id": a, "name": inv.name(a), "slug": inv.props(a)["slug"], "criticality": inv.props(a)["criticality"], "environment": inv.props(a)["environment"], "owner_team_id": inv.props(a)["owner_team_id"],
         "data_classifications": inv.props(a)["data_classifications"], "resource_ids": inv.inn(a, "PART_OF"), "depends_on": inv.out(a, "DEPENDS_ON"), "service_owner_id": inv.props(a).get("service_owner_id")}
        for a in inv.ids("Application")
    ]
    teams = [
        {"id": t, "name": inv.name(t), "slug": inv.props(t)["slug"], "department": inv.props(t)["department"], "lead_user_id": inv.props(t)["lead_user_id"], "oncall_channel": inv.props(t)["oncall_channel"], "member_count": inv.props(t)["member_count"], "app_ids": inv.inn(t, "OWNED_BY")}
        for t in inv.ids("Team")
    ]
    service_accounts = [
        {"id": s, "name": inv.name(s), "system": inv.props(s)["system"], "host_id": inv.props(s)["host_id"], "purpose": inv.props(s)["purpose"], "privileged": inv.props(s)["privileged"]}
        for s in inv.ids("ServiceAccount")
    ]
    functions = [
        {"id": f, "name": inv.name(f), "account_id": inv.props(f)["account_id"], "runtime": inv.props(f)["runtime"], "exposure": inv.props(f)["exposure"], "url_enabled": inv.props(f)["url_enabled"], "role_ids": inv.out(f, "HAS_ROLE"), "app_id": inv.props(f).get("app_id")}
        for f in inv.ids("ServerlessFunction")
    ]
    workloads = [
        {"id": w, "name": inv.name(w), "cluster_id": inv.props(w)["cluster_id"], "namespace": inv.props(w)["namespace"], "exposure": inv.props(w)["exposure"], "image": inv.props(w)["image"], "role_ids": inv.out(w, "HAS_ROLE"), "app_id": inv.props(w).get("app_id")}
        for w in inv.ids("Workload")
    ]
    accounts = [{"id": a, "name": inv.name(a), "account_id": inv.props(a)["account_id"], "provider": inv.props(a)["provider"], "environment": inv.props(a)["environment"]} for a in inv.ids("CloudAccount")]
    alerts = [{"id": a, "title": inv.name(a), "vendor_severity": inv.props(a)["vendor_severity"], "entity_id": inv.props(a)["entity_id"], "detected_at": inv.props(a)["detected_at"]} for a in inv.ids("Alert")]
    return {
        "seed": sc.SEED, "now": sc.NOW, "stage": "inventory", "counts": counts,
        "vms": vms, "endpoints": endpoints, "users": users, "roles": roles, "iam_users": iam_users, "buckets": buckets, "secrets": secrets, "databases": databases,
        "apps": apps, "teams": teams, "service_accounts": service_accounts, "functions": functions, "workloads": workloads, "accounts": accounts, "cspm_alerts": alerts,
        "storyline": dict(sorted(inv.storyline.items())),
    }


def write_index(inv: Inventory, out_dir: Path, counts: dict[str, Any]) -> Path:
    path = out_dir / "inventory.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_index(inv, counts), indent=1, sort_keys=False), encoding="utf-8")
    return path
