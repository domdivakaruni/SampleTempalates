"""Shared state and helpers for the inventory stage.

Every sub-module receives the same :class:`Inventory` sink, adds nodes and edges to it and records
generator-internal facts in ``inv.meta[node_id]`` (things the graph does not carry, such as the subnet a VM was
placed in or the CVE components an image was given). Nothing here touches the wall clock; all randomness comes
from ``common.rng(namespace)``.
"""
from __future__ import annotations

import ipaddress
import random
from collections import defaultdict
from datetime import timedelta
from typing import Any

from throughline.simulator.common import NOW, edge, node, stable_hex, ts

SOURCE_WIZ = "wiz-sim"
SOURCE_FALCON = "falcon-sim"
SOURCE_OKTA = "okta-sim"
SOURCE_DERIVED = "derived"

INTERNET_ID = "internet:global:internet"
VPN_CIDR = "10.99.0.0/16"
ANYWHERE = "0.0.0.0/0"
CORP_DOMAIN = "corp.larkspur.example"

TIERS = ("tier-0", "tier-1", "tier-2", "tier-3")
ACCESS_RANK = {"list": 0, "read": 1, "write": 2, "admin": 3}


class Inventory:
    """Accumulates node and edge records plus lookup indexes for the derivation passes."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self._edge_pos: dict[tuple[str, str, str], int] = {}
        self.by_label: dict[str, list[str]] = defaultdict(list)
        self._out: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._in: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.meta: dict[str, dict[str, Any]] = defaultdict(dict)
        self.storyline: dict[str, str] = {}

    # ------------------------------------------------------------------ nodes

    def add_node(
        self,
        id: str,
        label: str,
        name: str,
        props: dict[str, Any] | None = None,
        *,
        source: str,
        source_id: str | None = None,
        first_seen: str | None = None,
        last_seen: str | None = None,
        confidence: float = 1.0,
        **meta: Any,
    ) -> dict[str, Any]:
        if id in self.nodes:
            raise ValueError(f"duplicate node id {id}")
        rec = node(
            id, label, name, props, source=source, source_id=source_id, first_seen=first_seen,
            last_seen=last_seen, confidence=confidence,
        )
        self.nodes[id] = rec
        self.by_label[label].append(id)
        if meta:
            self.meta[id].update(meta)
        return rec

    def has(self, node_id: str) -> bool:
        return node_id in self.nodes

    def props(self, node_id: str) -> dict[str, Any]:
        return self.nodes[node_id]["props"]

    def label(self, node_id: str) -> str:
        return self.nodes[node_id]["label"]

    def name(self, node_id: str) -> str:
        return self.nodes[node_id]["name"]

    def ids(self, label: str) -> list[str]:
        return list(self.by_label.get(label, ()))

    # ------------------------------------------------------------------ edges

    def add_edge(
        self,
        type: str,
        src: str,
        dst: str,
        props: dict[str, Any] | None = None,
        *,
        source: str,
        first_seen: str | None = None,
        last_seen: str | None = None,
        confidence: float = 1.0,
    ) -> dict[str, Any]:
        key = (type, src, dst)
        pos = self._edge_pos.get(key)
        if pos is not None:
            return self.edges[pos]
        rec = edge(type, src, dst, props, source=source, first_seen=first_seen, last_seen=last_seen, confidence=confidence)
        self._edge_pos[key] = len(self.edges)
        self.edges.append(rec)
        self._out[(src, type)].append(dst)
        self._in[(dst, type)].append(src)
        return rec

    def has_edge(self, type: str, src: str, dst: str) -> bool:
        return (type, src, dst) in self._edge_pos

    def get_edge(self, type: str, src: str, dst: str) -> dict[str, Any] | None:
        pos = self._edge_pos.get((type, src, dst))
        return self.edges[pos] if pos is not None else None

    def out(self, src: str, type: str) -> list[str]:
        return list(self._out.get((src, type), ()))

    def inn(self, dst: str, type: str) -> list[str]:
        return list(self._in.get((dst, type), ()))

    def edges_of_type(self, type: str) -> list[dict[str, Any]]:
        return [e for e in self.edges if e["type"] == type]

    def count_edges(self, type: str) -> int:
        return sum(1 for e in self.edges if e["type"] == type)


# ---------------------------------------------------------------------- id helpers


def hexid(*parts: Any, length: int = 16) -> str:
    return stable_hex("inventory", *parts, length=length)


def aws_instance_id(*parts: Any) -> str:
    return "i-0" + hexid("instance", *parts, length=16)


def aws_resource_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}-0{hexid(prefix, *parts, length=16)}"


def pseudo_guid(*parts: Any) -> str:
    h = hexid("guid", *parts, length=32)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{h[16:20]}-{h[20:32]}"


def digits(*parts: Any, length: int = 19) -> str:
    h = hexid("digits", *parts, length=length + 4)
    return str(int(h, 16))[:length].rjust(length, "7")


# ---------------------------------------------------------------------- time helpers


def days_ago(r: random.Random, lo: int, hi: int) -> str:
    """A timestamp between ``lo`` and ``hi`` days before NOW (whole minutes)."""
    minutes = r.randint(lo * 1440, hi * 1440)
    return ts(NOW - timedelta(minutes=minutes))


def minutes_ago(r: random.Random, lo: int, hi: int) -> str:
    return ts(NOW - timedelta(minutes=r.randint(lo, hi)))


def scan_time() -> str:
    """Wiz-style 'last scanned' time: five minutes before the simulation clock."""
    return ts(NOW - timedelta(minutes=5))


# ---------------------------------------------------------------------- network helpers


class IpPlan:
    """Sequential private-IP allocator per subnet with reserved addresses honoured."""

    def __init__(self) -> None:
        self._next: dict[str, int] = {}
        self._reserved: set[str] = set()

    def reserve(self, ip: str) -> None:
        self._reserved.add(ip)

    def alloc(self, cidr: str) -> str:
        net = ipaddress.ip_network(cidr)
        idx = self._next.get(cidr, 10)
        while True:
            ip = str(net.network_address + idx)
            idx += 1
            if ip not in self._reserved:
                self._next[cidr] = idx
                return ip


def cidr_contains(cidr: str, ip: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)


def rule(cidr: str, port_from: int, port_to: int | None = None, protocol: str = "tcp") -> dict[str, Any]:
    return {"cidr": cidr, "port_from": port_from, "port_to": port_to if port_to is not None else port_from, "protocol": protocol}


def internet_ports(rules: list[dict[str, Any]]) -> list[str]:
    ports: list[str] = []
    for rl in rules:
        if rl["cidr"] in (ANYWHERE, "::/0"):
            if rl["port_from"] == rl["port_to"]:
                ports.append(str(rl["port_from"]))
            elif rl["port_from"] == 0 and rl["port_to"] == 65535:
                ports.append("0-65535")
            else:
                ports.append(f"{rl['port_from']}-{rl['port_to']}")
    return sorted(set(ports), key=lambda p: int(p.split("-")[0]))


def best_access(a: str, b: str) -> str:
    return a if ACCESS_RANK.get(a, 0) >= ACCESS_RANK.get(b, 0) else b


def short_host(name: str) -> str:
    return name.split(".")[0].lower()
