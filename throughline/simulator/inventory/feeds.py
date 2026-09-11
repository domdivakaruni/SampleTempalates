"""Raw vendor-shaped feeds derived from the graph records: Wiz-like cloud/IAM/network/vulnerability/issue/business
exports, Falcon-like device records and Okta-like user records. These loosely mimic real API objects so the
demo can show the "flat" vendor view next to the graph view.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from throughline.simulator.catalog.cves import CVES
from throughline.simulator.common import write_jsonl
from throughline.simulator.inventory._base import Inventory, hexid

PLATFORM = {"aws": "AWS", "gcp": "GCP", "azure": "Azure"}
WIZ_TYPE = {
    "CloudAccount": "SUBSCRIPTION", "VirtualMachine": "VIRTUAL_MACHINE", "KubernetesCluster": "KUBERNETES_CLUSTER", "Workload": "CONTAINER_WORKLOAD",
    "ContainerImage": "CONTAINER_IMAGE", "ServerlessFunction": "SERVERLESS", "StorageBucket": "BUCKET", "Database": "DATABASE", "Secret": "SECRET",
    "VPC": "VIRTUAL_NETWORK", "Subnet": "SUBNET", "SecurityGroup": "FIREWALL", "LoadBalancer": "LOAD_BALANCER", "IamRole": "SERVICE_ACCOUNT",
    "IamUser": "USER_ACCOUNT", "IamPolicy": "ACCESS_ROLE_POLICY", "AccessKey": "ACCESS_KEY",
}
PLATFORM_NAME = {"windows": "Windows", "linux": "Linux", "macos": "Mac"}


def write_feeds(inv: Inventory, out_dir: Path) -> list[Path]:
    raw = out_dir / "raw"
    written: list[Path] = []
    written.append(_write(raw / "wiz" / "cloud_resources.jsonl", _cloud_resources(inv)))
    written.append(_write(raw / "wiz" / "iam.jsonl", _iam(inv)))
    written.append(_write(raw / "wiz" / "network.jsonl", _network(inv)))
    written.append(_write(raw / "wiz" / "vulnerabilities.jsonl", _vulnerabilities(inv)))
    written.append(_write(raw / "wiz" / "issues.jsonl", _issues(inv)))
    written.append(_write(raw / "wiz" / "business_context.jsonl", _business(inv)))
    written.append(_write(raw / "falcon" / "devices.jsonl", _devices(inv)))
    written.append(_write(raw / "okta" / "users.jsonl", _okta_users(inv)))
    written.append(_write(raw / "business" / "applications.jsonl", [r for r in _business(inv) if r["type"] == "APPLICATION"]))
    written.append(_write(raw / "business" / "teams.jsonl", [r for r in _business(inv) if r["type"] == "TEAM"]))
    return written


def _write(path: Path, rows: list[dict[str, Any]]) -> Path:
    write_jsonl(path, rows)
    return path


def _entity(inv: Inventory, nid: str) -> dict[str, Any]:
    rec = inv.nodes[nid]
    p = rec["props"]
    return {
        "id": rec["source_id"], "graphEntityId": nid, "name": rec["name"], "type": WIZ_TYPE.get(rec["label"], rec["label"].upper()),
        "cloudPlatform": PLATFORM.get(p.get("provider", "aws"), "AWS"), "subscriptionExternalId": p.get("account_id"), "region": p.get("region"),
        "status": "Active", "creationDate": rec["first_seen"], "lastSeen": rec["last_seen"],
    }


def _cloud_resources(inv: Inventory) -> list[dict[str, Any]]:
    rows = []
    for label in ("CloudAccount", "VirtualMachine", "KubernetesCluster", "Workload", "ContainerImage", "ServerlessFunction", "StorageBucket", "Database", "Secret"):
        for nid in inv.ids(label):
            p = inv.props(nid)
            row = _entity(inv, nid)
            row["nativeType"] = {"VirtualMachine": "ec2Instance", "StorageBucket": "s3Bucket", "Database": p.get("engine"), "Secret": "secretsManagerSecret", "ServerlessFunction": "lambdaFunction", "KubernetesCluster": "eksCluster", "Workload": p.get("kind"), "ContainerImage": "containerImage", "CloudAccount": "account"}.get(label)
            row["properties"] = {k: v for k, v in p.items() if k not in ("tags", "ti_exposure_score", "crown_jewel_reach")}
            row["tags"] = p.get("tags") if isinstance(p.get("tags"), dict) else {}
            if label == "VirtualMachine":
                row["properties"]["securityGroups"] = [inv.name(sg) for sg in inv.out(nid, "HAS_SECURITY_GROUP")]
                row["properties"]["instanceProfileRoles"] = [inv.props(r)["arn"] for r in inv.out(nid, "HAS_ROLE")]
                row["properties"]["subnetId"] = p.get("subnet_id")
            if label == "Workload":
                row["properties"]["irsaRoles"] = [inv.props(r)["arn"] for r in inv.out(nid, "HAS_ROLE")]
            rows.append(row)
    return rows


def _iam(inv: Inventory) -> list[dict[str, Any]]:
    rows = []
    for rid in inv.ids("IamRole"):
        p = inv.props(rid)
        row = _entity(inv, rid)
        row.update({
            "arn": p["arn"], "roleType": p["role_type"], "isAdmin": p["is_admin"], "privilegeScore": p["privilege_score"], "lastUsed": p.get("last_used"),
            "trustPolicy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": _principal(tp), "Action": "sts:AssumeRole"} for tp in p.get("trust_principals", [])]},
            "attachedPolicies": [inv.props(pid)["arn"] for pid in inv.out(rid, "HAS_POLICY")],
            "canAssume": [inv.props(t)["arn"] for t in inv.out(rid, "CAN_ASSUME")],
        })
        rows.append(row)
    for uid in inv.ids("IamUser"):
        p = inv.props(uid)
        row = _entity(inv, uid)
        row.update({
            "arn": p["arn"], "isAdmin": p["is_admin"], "mfaEnabled": p["mfa_enabled"], "consoleAccess": p["console_access"], "passwordLastUsed": p.get("password_last_used"),
            "attachedPolicies": [inv.props(pid)["arn"] for pid in inv.out(uid, "HAS_POLICY")],
            "accessKeys": [{"accessKeyId": inv.name(k), "status": inv.props(k)["status"].capitalize(), "ageDays": inv.props(k)["age_days"], "lastUsed": inv.props(k).get("last_used"), "lastUsedService": inv.props(k).get("last_used_service")} for k in inv.out(uid, "HAS_ACCESS_KEY")],
        })
        rows.append(row)
    for pid in inv.ids("IamPolicy"):
        p = inv.props(pid)
        row = _entity(inv, pid)
        row.update({"arn": p["arn"], "isAwsManaged": p.get("aws_managed", False), "attachmentCount": len(inv.inn(pid, "HAS_POLICY")), "document": {"Version": "2012-10-17", "Statement": p["statements"]}, "accessLevels": p["access_levels"]})
        rows.append(row)
    return rows


def _principal(tp: str) -> dict[str, Any]:
    if tp.endswith(".amazonaws.com") or tp.endswith(".googleapis.com") or tp.startswith("Microsoft."):
        return {"Service": tp}
    if ":saml-provider/" in tp or ":oidc-provider/" in tp:
        return {"Federated": tp}
    return {"AWS": tp}


def _network(inv: Inventory) -> list[dict[str, Any]]:
    rows = []
    for label in ("VPC", "Subnet", "SecurityGroup", "LoadBalancer"):
        for nid in inv.ids(label):
            p = inv.props(nid)
            row = _entity(inv, nid)
            row["properties"] = dict(p)
            if label == "SecurityGroup":
                row["attachedTo"] = [inv.name(x) for x in inv.inn(nid, "HAS_SECURITY_GROUP")]
            if label == "LoadBalancer":
                row["targets"] = [{"id": t, "name": inv.name(t), "port": (inv.get_edge("ROUTES_TO", nid, t) or {}).get("props", {}).get("port")} for t in inv.out(nid, "ROUTES_TO")]
            rows.append(row)
    for e in inv.edges_of_type("EXPOSES"):
        dst = e["dst"]
        rows.append({"type": "NETWORK_EXPOSURE", "id": "exp-" + hexid("exp", dst, length=12), "resource": {"id": inv.nodes[dst]["source_id"], "graphEntityId": dst, "name": inv.name(dst), "type": WIZ_TYPE.get(inv.label(dst), inv.label(dst))}, "ports": e["props"]["ports"], "via": e["props"]["via"], "protocol": e["props"].get("protocol"), "firstSeen": e["first_seen"], "lastSeen": e["last_seen"]})
    return rows


def _vulnerabilities(inv: Inventory) -> list[dict[str, Any]]:
    rows = []
    for e in inv.edges_of_type("HAS_VULNERABILITY"):
        pkg = e["src"]
        cve = CVES[e["dst"].split(":", 1)[1]]
        pp = inv.props(pkg)
        scope = pp["scope"]
        sp = inv.props(scope)
        rows.append({
            "id": "vuln-" + hexid("vuln", pkg, cve.cve_id, length=16), "name": cve.cve_id, "CVSSSeverity": cve.severity.upper(), "score": cve.cvss, "exploitabilityScore": cve.epss,
            "hasExploit": cve.kev or cve.epss >= 0.5, "hasCisaKevExploit": cve.kev, "detectionMethod": "PACKAGE", "status": "OPEN", "firstDetectedAt": e["first_seen"], "lastDetectedAt": e["last_seen"],
            "vulnerableAsset": {"id": inv.nodes[scope]["source_id"], "graphEntityId": scope, "type": WIZ_TYPE.get(inv.label(scope), inv.label(scope)), "name": inv.name(scope), "cloudPlatform": PLATFORM.get(sp.get("provider", "aws"), "AWS"), "subscriptionExternalId": sp.get("account_id"), "region": sp.get("region"), "isInternetFacing": sp.get("exposure") == "internet"},
            "detailedName": pp["package_name"], "version": pp["version"], "fixedVersion": e["props"].get("fixed_version"), "ecosystem": pp["ecosystem"], "description": cve.description, "link": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
        })
    return rows


def _issues(inv: Inventory) -> list[dict[str, Any]]:
    return [inv.props(a)["raw"] for a in inv.ids("Alert") if inv.props(a)["source_system"] == "cspm"]


def _business(inv: Inventory) -> list[dict[str, Any]]:
    rows = []
    for tid in inv.ids("Team"):
        p = inv.props(tid)
        rows.append({"type": "TEAM", "id": tid, "name": inv.name(tid), "department": p["department"], "lead": p["lead_user_id"], "oncallChannel": p["oncall_channel"], "memberCount": p.get("member_count")})
    for aid in inv.ids("Application"):
        p = inv.props(aid)
        rows.append({
            "type": "APPLICATION", "id": aid, "name": inv.name(aid), "criticality": p["criticality"], "environment": p["environment"], "ownerTeam": p["owner_team_id"],
            "serviceOwner": p.get("service_owner_id"), "dataClassifications": p["data_classifications"], "description": p["description"],
            "resources": [{"id": x, "type": inv.label(x), "name": inv.name(x)} for x in inv.inn(aid, "PART_OF")],
            "dependsOn": [{"id": x, "type": inv.label(x), "dependencyType": (inv.get_edge("DEPENDS_ON", aid, x) or {}).get("props", {}).get("dependency_type")} for x in inv.out(aid, "DEPENDS_ON")],
        })
    return rows


def _devices(inv: Inventory) -> list[dict[str, Any]]:
    rows = []
    for eid in inv.ids("Endpoint"):
        rec = inv.nodes[eid]
        p = rec["props"]
        provider = p.get("cloud_provider")
        rows.append({
            "device_id": rec["source_id"], "cid": "c1d5f0e2b3a4c5d6e7f8091a2b3c4d5e", "hostname": p["hostname"], "local_ip": p["private_ip"], "external_ip": p["public_ip"],
            "mac_address": p.get("mac_address"), "os_version": p["os"], "platform_name": PLATFORM_NAME.get(p["os_family"], "Linux"), "agent_version": p["sensor_version"],
            "first_seen": rec["first_seen"], "last_seen": p["last_seen_sensor"], "service_provider": {"aws": "AWS_EC2_V2", "gcp": "GCP", "azure": "AZURE"}.get(provider) if provider else None,
            "service_provider_account_id": p.get("cloud_account_id"), "instance_id": p.get("cloud_instance_id"), "site_name": p["site"], "ou": p.get("ou"),
            "machine_domain": p.get("machine_domain"), "product_type_desc": "Workstation" if p["device_type"] == "workstation" else "Server", "system_manufacturer": p.get("manufacturer"),
            "serial_number": p.get("serial_number"), "status": p["containment_status"], "reduced_functionality_mode": "yes" if p.get("reduced_functionality_mode") else "no",
            "tags": p.get("tags", []), "groups": [], "policies": [{"policy_type": "prevention", "policy_name": p.get("prevention_policy")}], "primary_user": p.get("primary_user_id"),
        })
    return rows


def _okta_users(inv: Inventory) -> list[dict[str, Any]]:
    rows = []
    status_map = {"active": "ACTIVE", "suspended": "SUSPENDED", "deprovisioned": "DEPROVISIONED"}
    for uid in inv.ids("HumanUser"):
        rec = inv.nodes[uid]
        p = rec["props"]
        manager = p.get("manager_id")
        rows.append({
            "id": p["okta_id"], "status": status_map.get(p["status"], "ACTIVE"), "created": rec["first_seen"], "activated": rec["first_seen"], "lastLogin": p.get("last_login"),
            "lastUpdated": rec["last_seen"], "type": {"id": "oty-employee" if p.get("employment_type") == "employee" else "oty-contractor"},
            "profile": {
                "login": p["login"], "email": p["email"], "firstName": p["first_name"], "lastName": p["last_name"], "displayName": p["display_name"], "title": p["title"],
                "department": p["department"], "division": p["team_id"].split(":")[-1], "manager": inv.props(manager)["display_name"] if manager else None, "managerId": manager,
                "city": p["location"], "employeeNumber": p["employee_id"], "userType": p.get("employment_type"),
            },
            "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}, "mfa": ["OKTA_VERIFY_PUSH", "WEBAUTHN"] if p["mfa_enabled"] else []},
            "groups": p.get("groups", []),
        })
    return rows
