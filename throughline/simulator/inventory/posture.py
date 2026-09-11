"""Posture derivations (``source: derived``): EXPOSES from the Internet singleton, VULNERABLE_TO roll-ups from
packages, and CAN_ACCESS effective access (policy GRANTS -> resources, propagated over CAN_ASSUME chains up to
4 hops and over HAS_ROLE / MAPS_TO to compute assets and people).
"""
from __future__ import annotations

from collections import deque
from typing import Any

from throughline.simulator.catalog.cves import CVES
from throughline.simulator.inventory._base import (
    ACCESS_RANK,
    INTERNET_ID,
    SOURCE_DERIVED,
    Inventory,
    best_access,
    internet_ports,
)
from throughline.simulator.inventory.cloud import Estate

DATA_LABELS = ("StorageBucket", "Database", "Secret")
MAX_CHAIN = 4


def derive_posture(inv: Inventory, est: Estate) -> dict[str, int]:
    counts = {"EXPOSES": _exposure(inv, est), "VULNERABLE_TO": _vulnerable_to(inv, est), "CAN_ACCESS": _can_access(inv)}
    _crown_jewel_reach(inv)
    return counts


# ---------------------------------------------------------------------------- exposure


def _expose(inv: Inventory, dst: str, ports: list[str], via: str, protocol: str = "tcp") -> None:
    existing = inv.get_edge("EXPOSES", INTERNET_ID, dst)
    if existing:
        merged = sorted(set(existing["props"]["ports"]) | set(ports), key=lambda p: int(str(p).split("-")[0]))
        existing["props"]["ports"] = merged
        if via not in existing["props"]["via"].split(","):
            existing["props"]["via"] = existing["props"]["via"] + "," + via
        return
    inv.add_edge("EXPOSES", INTERNET_ID, dst, {"ports": ports, "via": via, "protocol": protocol}, source=SOURCE_DERIVED, confidence=0.98)


def _exposure(inv: Inventory, est: Estate) -> int:
    before = inv.count_edges("EXPOSES")
    for vm in inv.ids("VirtualMachine"):
        p = inv.props(vm)
        meta = inv.meta[vm]
        ports: list[str] = []
        if p.get("public_ip"):
            rules: list[dict[str, Any]] = []
            for sg in inv.out(vm, "HAS_SECURITY_GROUP"):
                rules.extend(inv.props(sg)["inbound_rules"])
            ports = internet_ports(rules)
        if ports:
            _expose(inv, vm, ports, "security_group")
        lb_ports = [str(x) for x in meta.get("lb_ports", [])]
        if lb_ports:
            _expose(inv, vm, lb_ports, "lb")
        if ports or lb_ports:
            p["exposure"] = "internet"
        else:
            subnet = meta.get("subnet")
            p["exposure"] = "isolated" if subnet and inv.props(subnet).get("kind") == "isolated" else "internal"
        p["public_ports"] = sorted(set(ports) | set(lb_ports), key=lambda x: int(x.split("-")[0]))
    for lb in inv.ids("LoadBalancer"):
        p = inv.props(lb)
        if p["scheme"] == "internet-facing":
            ports = [ls.split(":")[0] for ls in p["listeners"]]
            _expose(inv, lb, ports, "lb")
            p["exposure"] = "internet"
        else:
            p["exposure"] = "internal"
    for wid in inv.ids("Workload"):
        p = inv.props(wid)
        lb_ports = inv.meta[wid].get("lb_ports", [])
        if lb_ports:
            _expose(inv, wid, [str(x) for x in lb_ports], "lb")
            p["exposure"] = "internet"
        else:
            p["exposure"] = "internal"
    for bid in inv.ids("StorageBucket"):
        if inv.props(bid)["public"]:
            _expose(inv, bid, ["443"], "public_acl", "https")
    for did in inv.ids("Database"):
        p = inv.props(did)
        if p["public"]:
            _expose(inv, did, [str(p.get("port", 5432))], "security_group")
            p["exposure"] = "internet"
    for fid in inv.ids("ServerlessFunction"):
        p = inv.props(fid)
        if p["url_enabled"]:
            _expose(inv, fid, ["443"], "function_url", "https")
            p["exposure"] = "internet"
    for cid in inv.ids("KubernetesCluster"):
        if inv.props(cid)["public_endpoint"]:
            _expose(inv, cid, ["443"], "public_acl", "https")
    return inv.count_edges("EXPOSES") - before


# ---------------------------------------------------------------------------- vulnerabilities


def _cves_of_packages(inv: Inventory, scope: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for pid in inv.out(scope, "HAS_PACKAGE"):
        for cve in inv.out(pid, "HAS_VULNERABILITY"):
            out.append((cve, pid))
    return out


def _exploitable(cve_id: str, exposure: str | None) -> bool:
    c = CVES[cve_id.split(":", 1)[1]]
    return bool(c.kev or c.epss >= 0.5) and exposure != "isolated"


def _vulnerable_to(inv: Inventory, est: Estate) -> int:
    before = inv.count_edges("VULNERABLE_TO")
    image_cves: dict[str, list[tuple[str, str]]] = {}
    for image_id in inv.ids("ContainerImage"):
        pairs = _cves_of_packages(inv, image_id)
        image_cves[image_id] = pairs
        for cve, pid in pairs:
            inv.add_edge("VULNERABLE_TO", image_id, cve, {"via_package": pid, "exploitable": _exploitable(cve, None)}, source=SOURCE_DERIVED, confidence=0.95)
    for label in ("VirtualMachine", "ServerlessFunction", "Workload"):
        for asset in inv.ids(label):
            exposure = inv.props(asset).get("exposure")
            seen: set[str] = set()
            for cve, pid in _cves_of_packages(inv, asset):
                if cve in seen:
                    continue
                seen.add(cve)
                inv.add_edge("VULNERABLE_TO", asset, cve, {"via_package": pid, "exploitable": _exploitable(cve, exposure)}, source=SOURCE_DERIVED, confidence=0.95)
            for image_id in inv.out(asset, "RUNS_IMAGE"):
                for cve, pid in image_cves.get(image_id, []):
                    if cve in seen:
                        continue
                    seen.add(cve)
                    inv.add_edge("VULNERABLE_TO", asset, cve, {"via_package": pid, "via_image": image_id, "exploitable": _exploitable(cve, exposure)}, source=SOURCE_DERIVED, confidence=0.9)
    return inv.count_edges("VULNERABLE_TO") - before


# ---------------------------------------------------------------------------- effective access


class Access:
    __slots__ = ("level", "path_length", "via")

    def __init__(self, level: str, path_length: int, via: list[str]) -> None:
        self.level = level
        self.path_length = path_length
        self.via = via

    def better_than(self, other: Access | None) -> bool:
        if other is None:
            return True
        if self.path_length != other.path_length:
            return self.path_length < other.path_length
        return ACCESS_RANK.get(self.level, 0) > ACCESS_RANK.get(other.level, 0)


def _direct_access(inv: Inventory, data_by_account: dict[tuple[str, str], list[str]], principal: str) -> dict[str, Access]:
    out: dict[str, Access] = {}
    for pid in inv.out(principal, "HAS_POLICY"):
        for dst in inv.out(pid, "GRANTS"):
            e = inv.get_edge("GRANTS", pid, dst)
            level = e["props"].get("access_level", "read") if e else "read"
            label = inv.label(dst)
            targets: list[str]
            if label in DATA_LABELS:
                targets = [dst]
            elif label == "CloudAccount":
                if ACCESS_RANK.get(level, 0) < ACCESS_RANK["read"]:
                    continue  # list/describe on the whole account is inventory visibility, not data access
                scope = (e["props"].get("scope_labels") if e else None) or list(DATA_LABELS)
                acct = inv.props(dst)["account_id"]
                targets = [t for lbl in scope for t in data_by_account.get((acct, lbl), [])]
            else:
                continue
            for t in targets:
                cand = Access(level, 1, [pid])
                cur = out.get(t)
                if cur is None:
                    out[t] = cand
                elif cand.path_length == cur.path_length:
                    cur.level = best_access(cur.level, level)
    return out


def _can_access(inv: Inventory) -> int:
    before = inv.count_edges("CAN_ACCESS")
    data_by_account: dict[tuple[str, str], list[str]] = {}
    for label in DATA_LABELS:
        for nid in inv.ids(label):
            data_by_account.setdefault((inv.props(nid)["account_id"], label), []).append(nid)
    principals = inv.ids("IamRole") + inv.ids("IamUser")
    direct: dict[str, dict[str, Access]] = {p: _direct_access(inv, data_by_account, p) for p in principals}
    # propagate over CAN_ASSUME chains (breadth-first, shortest path wins)
    effective: dict[str, dict[str, Access]] = {}
    for p in principals:
        acc: dict[str, Access] = {t: Access(a.level, a.path_length, list(a.via)) for t, a in direct[p].items()}
        q: deque[tuple[str, int, list[str]]] = deque([(p, 0, [])])
        visited = {p}
        while q:
            cur, depth, chain = q.popleft()
            if depth >= MAX_CHAIN - 1:
                continue
            for nxt in inv.out(cur, "CAN_ASSUME"):
                if nxt in visited:
                    continue
                visited.add(nxt)
                new_chain = chain + [nxt]
                for t, a in direct.get(nxt, {}).items():
                    cand = Access(a.level, depth + 2, new_chain + a.via)
                    if cand.better_than(acc.get(t)):
                        acc[t] = cand
                q.append((nxt, depth + 1, new_chain))
        effective[p] = acc
    emitted = 0
    for p in principals:
        for t, a in sorted(effective[p].items()):
            transitive = a.path_length > 1
            inv.add_edge(
                "CAN_ACCESS", p, t,
                {"access_level": a.level, "path_length": a.path_length, "via": ",".join(a.via), "transitive": transitive},
                source=SOURCE_DERIVED, confidence=1.0 if not transitive else 0.9,
            )
            emitted += 1
    # compute assets inherit their roles' access; people inherit SSO-mapped roles
    for label, etype in (("VirtualMachine", "HAS_ROLE"), ("Workload", "HAS_ROLE"), ("ServerlessFunction", "HAS_ROLE"), ("HumanUser", "MAPS_TO")):
        for asset in inv.ids(label):
            merged: dict[str, Access] = {}
            for role in inv.out(asset, etype):
                if inv.label(role) not in ("IamRole", "IamUser"):
                    continue
                for t, a in effective.get(role, {}).items():
                    cand = Access(a.level, a.path_length + 1, [role] + a.via)
                    if cand.better_than(merged.get(t)):
                        merged[t] = cand
            for t, a in sorted(merged.items()):
                inv.add_edge(
                    "CAN_ACCESS", asset, t,
                    {"access_level": a.level, "path_length": a.path_length, "via": ",".join(a.via), "transitive": True},
                    source=SOURCE_DERIVED, confidence=0.9,
                )
                emitted += 1
    return inv.count_edges("CAN_ACCESS") - before


def _crown_jewel_reach(inv: Inventory) -> None:
    for vm in inv.ids("VirtualMachine"):
        reach = 0
        for t in inv.out(vm, "CAN_ACCESS"):
            if inv.props(t).get("crown_jewel"):
                reach += 1
        # secrets that unlock a crown jewel count too
        for t in inv.out(vm, "CAN_ACCESS"):
            if inv.label(t) == "Secret":
                for u in inv.out(t, "UNLOCKS"):
                    if inv.props(u).get("crown_jewel") and not inv.has_edge("CAN_ACCESS", vm, u):
                        reach += 1
        inv.props(vm)["crown_jewel_reach"] = reach
