"""External-host telemetry: ``IpAddress`` / ``Domain`` nodes, ``CONNECTED_TO`` and ``RESOLVES_TO`` edges.

The EDR/cloud feeds do **not** know which hosts are malicious, so every node this module emits carries
``reputation: "unknown"`` -- the threat-intel stage is what later plants ``Indicator`` nodes and
``MATCHES_IOC`` edges against these ids. Named campaign infrastructure (C2, attacker egress, the SALTWORKS
host) is registered with its fictional ASN/country from ``storyline_constants``; everything else comes from a
deterministic background pool so WAF/IDS/general-EDR noise and background CloudTrail have source IPs.
"""
from __future__ import annotations

from throughline.simulator import storyline_constants as S
from throughline.simulator.common import ago
from throughline.simulator.events.ctx import Ctx, domain_id, ip_id


def is_private_ip(addr: str) -> bool:
    if addr.startswith(("10.", "192.168.", "169.254.")):
        return True
    if addr.startswith("172."):
        try:
            return 16 <= int(addr.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def ip_node(ctx: Ctx, addr: str, *, source: str = "falcon-sim", asn: str | None = None,
            asn_org: str | None = None, country: str | None = None, reputation: str = "unknown",
            first_seen: str | None = None) -> str:
    nid = ip_id(addr)
    if not ctx.has_node(nid):
        ctx.n(nid, "IpAddress", addr, {
            "address": addr, "is_private": is_private_ip(addr), "asn": asn, "asn_org": asn_org,
            "country": country, "reputation": reputation,
        }, source=source, source_id=addr, first_seen=first_seen)
    return nid


def domain_node(ctx: Ctx, fqdn: str, *, source: str = "falcon-sim", reputation: str = "unknown",
                registered_days_ago: int | None = None, first_seen: str | None = None) -> str:
    nid = domain_id(fqdn)
    if not ctx.has_node(nid):
        ctx.n(nid, "Domain", fqdn, {
            "fqdn": fqdn, "registered_days_ago": registered_days_ago, "reputation": reputation,
        }, source=source, source_id=fqdn, first_seen=first_seen)
    return nid


def resolves_to(ctx: Ctx, fqdn: str, addr: str, *, source: str = "falcon-sim", when: str | None = None) -> None:
    ctx.e("RESOLVES_TO", domain_id(fqdn), ip_id(addr), source=source, first_seen=when, last_seen=when)


def connected_to(ctx: Ctx, src_id: str, dst_id: str, *, port: int, protocol: str = "tcp",
                 direction: str = "outbound", count: int = 1, bytes_out: int = 0, first_time: str,
                 last_time: str | None = None, source: str = "falcon-sim") -> None:
    ctx.e("CONNECTED_TO", src_id, dst_id, {
        "port": port, "protocol": protocol, "direction": direction, "count": count,
        "bytes_out": bytes_out, "first_time": first_time, "last_time": last_time or first_time,
    }, source=source, first_seen=first_time, last_seen=last_time or first_time)


def register_named_infrastructure(ctx: Ctx) -> None:
    """Pre-create the campaign infrastructure nodes with their canonical ASN/country (reputation unknown)."""
    ip_node(ctx, S.ATTACKER_EGRESS_IP, source="cloudtrail-sim", asn=S.ATTACKER_ASN,
            asn_org=S.ATTACKER_ASN_ORG, country="NL", first_seen=ago(days=2))
    ip_node(ctx, S.C2_IP, source="falcon-sim", asn=S.ATTACKER_ASN, asn_org=S.ATTACKER_ASN_ORG,
            country="DE", first_seen=ago(days=2))
    domain_node(ctx, S.C2_DOMAIN, source="falcon-sim", registered_days_ago=38, first_seen=ago(days=2))
    resolves_to(ctx, S.C2_DOMAIN, S.C2_IP, source="falcon-sim", when=ago(days=2))
    ip_node(ctx, S.SALTWORKS_IP, source="waf-sim", asn="AS64511", asn_org="Brackwater Networks (fictional)",
            country="RU", first_seen=ago(days=1))
    ip_node(ctx, S.VPN_EGRESS_IP, source="okta-sim", asn="AS64512", asn_org="Larkspur Corporate VPN",
            country="US", first_seen=ago(days=90))
    # internal / link-local hosts the storyline references
    ip_node(ctx, "169.254.169.254", source="falcon-sim", first_seen=ago(days=2))
    ip_node(ctx, S.WKS_DANA_IP, source="falcon-sim", first_seen=ago(days=90))
    ip_node(ctx, S.SCANNER_IP, source="ids-sim", first_seen=ago(days=120))


_NAMED_PUBLIC = {S.ATTACKER_EGRESS_IP, S.C2_IP, S.SALTWORKS_IP, S.VPN_EGRESS_IP,
                 S.BASTION_PUBLIC_IP, S.EDGE_PUBLIC_IP, "198.51.100.64", "198.51.100.88"}


def doc_public_ips(n: int) -> list[str]:
    """A deterministic ordered list of up to ~750 distinct documentation-range public IPs (RFC 5737),
    excluding the named campaign/infra addresses. Noise generators index into this for source IPs."""
    out: list[str] = []
    for octet in range(2, 255):
        for block in ("192.0.2", "198.51.100", "203.0.113"):
            addr = f"{block}.{octet}"
            if addr not in _NAMED_PUBLIC:
                out.append(addr)
            if len(out) >= n:
                return out
    return out


