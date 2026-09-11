"""Correlation: lateral-movement derivation and storyline construction (docs/02 section 4(e), docs/03 section 6).

Lateral movement: a logon onto endpoint B whose source IP is endpoint A's private IP, preceded by an alert on A
within 48 h (or an SSH/RDP alert on B naming A's IP) -> ``LATERAL_MOVEMENT_TO A -> B``.

Storylines: union-find over *members* - detections that are not benign-explained (posture findings are state, not
events, and never join) plus anomalous / stolen-credential / IOC-matching cloud events - that share a pivot within
a time window:

* host (an endpoint and its SAME_AS VM are one pivot; 24 h): detections chain with each other, while a WAF / IDS
  alert only joins a detection that follows or precedes it within ``WINDOW_NETWORK_H`` - repeated probes of a
  public host are the WAF's job to aggregate;
* identity anchor / credential lineage / campaign of a high-confidence indicator / a cloud event the alert cites
  (7 days);
* shared external ip, only when the ip carries threat intelligence or a bad reputation (24 h);
* a derived ``LATERAL_MOVEMENT_TO`` edge (detections on the source host before it, on the target host after it).

Hub pivots (Internet, scanner, VPN, NAT, > 200 links) never link anything and vendor incident grouping is not used
as evidence. A cluster becomes a ``Storyline`` (with ``IN_STORYLINE`` and ``NEXT_STAGE`` edges) when it contains a
stolen credential whose lineage reaches a crown jewel, or when it is a multi-stage narrative - >= 3 members, at
least one host / cloud / identity detection, >= 2 kill-chain stages - corroborated by at least one of: two data
sources, an active-campaign indicator, lateral movement, a credential pivot, or an anchor that reaches a crown
jewel. Attribution uses high-confidence votes only, with a technique-overlap fallback.
"""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from throughline.analytics import semantics as sem
from throughline.analytics.context import NOW, AnalyticsContext, as_dict, as_list, fmt_time, parse_time
from throughline.analytics.ti import actor_of, campaign_of, campaign_techniques, relevance_of
from throughline.graph.context_graph import ContextGraph
from throughline.models import GraphFragment, StageOut, StorylineOut

DERIVED = "derived"
LM_LOOKBACK_HOURS = 48.0
LM_FOLLOW_HOURS = 1.0
WINDOW_HOST_H = 24.0
WINDOW_IDENTITY_H = 24.0 * 7
WINDOW_NETWORK_H = 2.0  # a WAF / IDS alert joins a host detection only this close in time
MIN_IOC_PIVOT_CONFIDENCE = 0.7
MIN_IP_PIVOT_CONFIDENCE = 0.5  # a shared external ip is a pivot only with an indicator at least this confident
MIN_VOTE_CONFIDENCE = 0.7  # attribution votes below this never name a storyline
MIN_TTP_TECHNIQUES = 4  # technique-overlap attribution needs this many shared techniques ...
MIN_TTP_RATIO = 0.6  # ... covering this share of the storyline's techniques
MAX_STORYLINE_MEMBERS = 50
ROUTINE_LOGON_MIN = 5  # a (principal, host, type, source ip) logon seen this often is a baseline, not movement
NETWORK_SOURCES = frozenset({"waf", "ids"})
HUB_MEMBER_LIMIT = 200
LATERAL_TECHNIQUE_PREFIXES = ("T1021", "T1550")
LOGON_PROTOCOL = {"ssh": "ssh", "remote_interactive": "rdp", "rdp": "rdp", "network": "smb", "smb": "smb", "winrm": "winrm", "psexec": "psexec"}


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "storyline"


# ---------------------------------------------------------------------- lateral movement


def derive_lateral_movement(ctx: AnalyticsContext) -> dict[str, int]:
    g = ctx.graph
    ctx._ensure()
    existing: set[tuple[str, str, str]] = set()
    for u, v, d in g.G.edges(data=True):
        if d.get("type") == "LATERAL_MOVEMENT_TO":
            existing.add((u, v, str(d.get("time") or "")[:16]))
    added = 0

    def add(a: str, b: str, protocol: str, account: str | None, when: datetime | None, alert_id: str | None) -> None:
        nonlocal added
        t = fmt_time(when) or ""
        key = (a, b, t[:16])
        if a == b or key in existing:
            return
        existing.add(key)
        g.add_edge_record({"type": "LATERAL_MOVEMENT_TO", "src": a, "dst": b, "source": DERIVED, "first_seen": t or None, "last_seen": t or None,
                           "confidence": 0.8, "props": {"protocol": protocol, "account": account, "time": t or None, "alert_id": alert_id}})
        added += 1

    def endpoints_at(ip: str) -> list[str]:
        out = list(ctx.endpoints_by_ip.get(ip, []))
        for vm in ctx.vms_by_ip.get(ip, []):
            ep = ctx.endpoint_of_vm.get(vm)
            if ep and ep not in out:
                out.append(ep)
        return out

    # rule 1: logon onto B from A's ip, alert on A in the preceding 48h. A logon that belongs to a routine baseline
    # (the same principal, host, logon type and source ip seen ROUTINE_LOGON_MIN+ times, e.g. a nightly SFTP
    # transfer) only counts as movement when a detection on B follows it within LM_FOLLOW_HOURS.
    logons = [(u, v, dd) for u, v, dd in g.G.edges(data=True) if dd.get("type") == "LOGGED_ON"]
    baseline: dict[tuple[str, str, str, str], int] = defaultdict(int)
    for user, b, d in logons:
        baseline[(user, b, str(d.get("logon_type") or "").lower(), str(d.get("source_ip") or ""))] += 1
    for user, b, d in logons:
        ip = d.get("source_ip")
        if not ip or ip in ctx.scanner_ips or ip in ctx.vpn_ips or ip in ctx.nat_ips:
            continue
        when = parse_time(d.get("logon_time")) or parse_time(d.get("first_seen"))
        if when is None:
            continue
        routine = baseline[(user, b, str(d.get("logon_type") or "").lower(), str(ip))] >= ROUTINE_LOGON_MIN
        for a in endpoints_at(str(ip)):
            if a == b:
                continue
            trigger = ctx.recent_alert_on(a, when, LM_LOOKBACK_HOURS)
            if not trigger:
                continue
            follow = None
            for cand in ctx.alerts_on(b):
                t = ctx.alert_time(cand)
                if t is not None and when <= t <= when + timedelta(hours=LM_FOLLOW_HOURS):
                    follow = cand
                    break
            if routine and not follow:
                continue
            protocol = LOGON_PROTOCOL.get(str(d.get("logon_type") or "").lower(), str(d.get("logon_type") or "network").lower())
            add(a, b, protocol, ctx.short(user), when, follow or trigger)
    # rule 2: an SSH/RDP alert on B naming A's ip as source
    for alert in ctx.alerts:
        techs = [str(t) for t in as_list(g.get(alert, "techniques"))]
        if not any(t.startswith(LATERAL_TECHNIQUE_PREFIXES) for t in techs):
            continue
        b = ctx.anchor_of(alert)
        if not b:
            continue
        b_ep = ctx.endpoint_for(b) or b
        ips: set[str] = set()
        src_ip = g.get(alert, "source_ip")
        if src_ip:
            ips.add(str(src_ip))
        for ip_node in ctx.alert_involves(alert, {"IpAddress"}):
            addr = g.get(ip_node, "address")
            if addr:
                ips.add(str(addr))
        when = ctx.alert_time(alert)
        protocol = next((p for p, t in sem.LATERAL_TECHNIQUES.items() if t in techs), "network")
        for ip in ips:
            if ip in ctx.scanner_ips or ip in ctx.vpn_ips or ip in ctx.nat_ips:
                continue
            for a in endpoints_at(ip):
                if a != b_ep:
                    add(a, b_ep, protocol, g.get(alert, "user"), when, alert)
    ctx.invalidate()
    return {"lateral_movement_edges": added}


# ---------------------------------------------------------------------- storylines


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self.parent.setdefault(x, x)

    def find(self, x: str) -> str:
        self.add(x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            if ra < rb:
                self.parent[rb] = ra
            else:
                self.parent[ra] = rb


def root_credential(ctx: AnalyticsContext, cred: str) -> str:
    g = ctx.graph
    seen = {cred}
    cur = cred
    while True:
        parents = [p for p, _ in g.out_edges(cur, ("DERIVED_FROM",))]
        if not parents:
            df = g.get(cur, "derived_from")
            parents = [str(df)] if df and df in g else []
        if not parents or parents[0] in seen:
            return cur
        cur = parents[0]
        seen.add(cur)


def credential_lineage(ctx: AnalyticsContext, cred: str) -> list[str]:
    """The credential, its ancestors and all credentials derived from them."""
    g = ctx.graph
    root = root_credential(ctx, cred)
    out = [root]
    queue = [root]
    while queue:
        c = queue.pop()
        for child, _ in g.in_edges(c, ("DERIVED_FROM",)):
            if child not in out:
                out.append(child)
                queue.append(child)
    return out


def stolen_credentials(ctx: AnalyticsContext) -> set[str]:
    g = ctx.graph
    out: set[str] = set()
    for c in g.nodes_by_label("Credential"):
        if g.out_edges(c, ("STOLEN_BY",)):
            out.update(credential_lineage(ctx, c))
    return out


def _ioc_campaigns(ctx: AnalyticsContext, node: str) -> list[str]:
    g = ctx.graph
    out = []
    for ind, d in g.out_edges(node, ("MATCHES_IOC",)):
        conf = float(d.get("confidence") or g.get(ind, "confidence") or 0)
        if conf < MIN_IOC_PIVOT_CONFIDENCE or g.get(ind, "active") is False:
            continue
        c = campaign_of(ctx, ind)
        if c and str(g.get(c, "status") or "active") != "historical":
            out.append(c)
    return out


def _is_network(g: ContextGraph, m: str) -> bool:
    return g.label_of(m) == "Alert" and str(g.get(m, "source_system") or "") in NETWORK_SOURCES


def _member_source(g: ContextGraph, m: str) -> str:
    if g.label_of(m) == "CloudEvent":
        return "cloudtrail"
    return str(g.get(m, "source_system") or "unknown")


def _ip_is_pivot(ctx: AnalyticsContext, ip: str) -> bool:
    """An external ip links members only when it carries threat intelligence (an active indicator with confidence
    >= MIN_IP_PIVOT_CONFIDENCE) or a bad reputation; arbitrary shared internet addresses (scanners, CDNs) do not."""
    g = ctx.graph
    a = g.node(ip) or {}
    if a.get("is_private") or ctx.is_hub(ip):
        return False
    if str(a.get("reputation") or "").lower() in ("suspicious", "malicious"):
        return True
    for ind, d in g.out_edges(ip, ("MATCHES_IOC",)):
        conf = float(d.get("confidence") or g.get(ind, "confidence") or 0)
        if conf >= MIN_IP_PIVOT_CONFIDENCE and g.get(ind, "active") is not False:
            return True
    return False


def _alert_ips(ctx: AnalyticsContext, m: str) -> set[str]:
    """Addresses an alert involves (INVOLVES ip nodes, source_ip, the vendor's remote address fields)."""
    g = ctx.graph
    ips = {str(g.get(ip, "address") or "") for ip in ctx.alert_involves(m, {"IpAddress"})}
    raw = as_dict(g.get(m, "raw"))
    for key in ("source_ip", "remote_address", "src_ip"):
        for val in (g.get(m, key), raw.get(key)):
            if val:
                ips.add(str(val))
    ips.discard("")
    return ips


def _network_corroborated(ctx: AnalyticsContext, n: str, c: str) -> bool:
    """A WAF / IDS alert is tied to a host detection when its source is known campaign infrastructure (an active
    indicator with confidence >= MIN_IOC_PIVOT_CONFIDENCE) or the host's own telemetry involved the same address."""
    g = ctx.graph
    for ind, d in g.out_edges(n, ("MATCHES_IOC",)):
        conf = float(d.get("confidence") or g.get(ind, "confidence") or 0)
        if conf >= MIN_IOC_PIVOT_CONFIDENCE and g.get(ind, "active") is not False:
            return True
    return bool(_alert_ips(ctx, n) & _alert_ips(ctx, c))


def _union_group(uf: _UnionFind, ctx: AnalyticsContext, kind: str, ms: list[str], times: dict[str, datetime | None]) -> None:
    """Union the members of one pivot group under the kind's time window.

    Detections chain with their nearest neighbour in time. A WAF / IDS alert joins a host detection only when the
    two are within WINDOW_NETWORK_H and the probe is corroborated (see :func:`_network_corroborated`); through a
    threat-intel pivot (shared campaign infrastructure) the full window applies. Network alerts never chain with
    each other except through such a pivot.
    """
    g = ctx.graph
    ordered = sorted((m for m in ms if times[m] is not None), key=lambda m: times[m])  # type: ignore[arg-type,return-value]
    if kind == "lm":
        for x in ordered[1:]:
            uf.union(ordered[0], x)
        return
    # identities (roles, credential lineages, the cloud events an alert cites) correlate over 7 days; hosts and
    # shared infrastructure over 24 h (docs/02 section 4(e))
    window = timedelta(hours=WINDOW_IDENTITY_H if kind in ("cred", "identity", "event") else WINDOW_HOST_H)
    core = [m for m in ordered if not _is_network(g, m)]
    net = [m for m in ordered if _is_network(g, m)]
    for x, y in zip(core, core[1:], strict=False):
        if times[y] - times[x] <= window:  # type: ignore[operator]
            uf.union(x, y)
    join = timedelta(hours=WINDOW_NETWORK_H) if kind == "host" else window
    for n in net:
        for c in core:
            if abs(times[c] - times[n]) <= join and (kind != "host" or _network_corroborated(ctx, n, c)):  # type: ignore[operator]
                uf.union(n, c)
    if kind in ("ip", "campaign"):
        for x, y in zip(net, net[1:], strict=False):
            if times[y] - times[x] <= window:  # type: ignore[operator]
                uf.union(x, y)


def _accept_cluster(ctx: AnalyticsContext, ms: list[str], kinds_of: dict[str, set[str]]) -> tuple[bool, list[str]]:
    """Decide whether a cluster is a storyline; returns (accepted, corroborating signals)."""
    g = ctx.graph
    signals: list[str] = []
    if _has_crown_jewel_credential_chain(ctx, ms):
        signals.append("credential_chain")
    if not signals:
        if len(ms) < 3:
            return False, signals
        if not any(not _is_network(g, m) for m in ms):
            return False, signals  # probes alone: aggregating scanner traffic is the WAF's job
        techs = [t for m in ms for t in _member_techniques(ctx, m)]
        stages = sem.stages_covered(techs) | {s for s in (_member_stage(ctx, m) for m in ms) if s}
        if len(stages) < 2:
            return False, signals
    if len({_member_source(g, m) for m in ms}) >= 2:
        signals.append("cross_source")
    for kind, name in (("campaign", "ioc_campaign"), ("lm", "lateral_movement"), ("cred", "credential")):
        if any(kind in kinds_of.get(m, ()) for m in ms):
            signals.append(name)
    anchors = {ctx.anchor_of(m) for m in ms if g.label_of(m) == "Alert"}
    if any(ctx.reaches_crown_jewel(a, 4, "access") for a in anchors if a):
        signals.append("crown_jewel_reach")
    return bool(signals), list(dict.fromkeys(signals))


def build_storylines(ctx: AnalyticsContext, is_benign: Callable[[str], bool]) -> list[str]:
    """Correlate alerts and cloud events into ``Storyline`` nodes (see the module docstring for the rules)."""
    g = ctx.graph
    ctx.invalidate()
    ctx._ensure()
    stolen = stolen_credentials(ctx)
    members: list[str] = [a for a in ctx.alerts if str(g.get(a, "alert_type") or "") != "issue" and not is_benign(a)]
    for ev in ctx.cloud_events:
        creds = [c for c, _ in g.out_edges(ev, ("USED_CREDENTIAL",))]
        if g.get(ev, "anomalous") or any(c in stolen for c in creds) or g.out_edges(ev, ("MATCHES_IOC",)):
            members.append(ev)
    times = {m: ctx.member_time(m) for m in members}
    member_set = set(members)
    pivots: dict[tuple[str, str], list[str]] = defaultdict(list)  # (kind, key) -> members
    kinds_of: dict[str, set[str]] = defaultdict(set)

    def pivot(kind: str, key: str, m: str) -> None:
        if m in member_set:
            pivots[(kind, key)].append(m)
            kinds_of[m].add(kind)

    for m in members:
        label = g.label_of(m)
        if label == "Alert":
            anchor = ctx.anchor_of(m)
            if anchor and not ctx.is_hub(anchor):
                canon = ctx.vm_or_self(anchor)
                kind = "identity" if g.label_of(canon) in sem.IDENTITY_LABELS else "host"
                pivot(kind, canon, m)
            for c, _ in g.in_edges(m, ("STOLEN_BY",)):
                pivot("cred", root_credential(ctx, c), m)
            for c in ctx.alert_involves(m, {"Credential"}):
                pivot("cred", root_credential(ctx, c), m)
            for ip in ctx.alert_involves(m, {"IpAddress"}):
                if _ip_is_pivot(ctx, ip):
                    pivot("ip", ip, m)
            for c in _ioc_campaigns(ctx, m):
                pivot("campaign", c, m)
            for ev in ctx.alert_involves(m, {"CloudEvent"}):
                pivot("event", ev, m)
                pivot("event", ev, ev)
        else:
            for c, _ in g.out_edges(m, ("USED_CREDENTIAL",)):
                pivot("cred", root_credential(ctx, c), m)
            for ip, _ in g.out_edges(m, ("FROM_IP",)):
                if _ip_is_pivot(ctx, ip):
                    pivot("ip", ip, m)
            for c in _ioc_campaigns(ctx, m):
                pivot("campaign", c, m)
            for role, _ in g.out_edges(m, ("PERFORMED_BY", "ASSUMED")):
                if not ctx.is_hub(role):
                    pivot("identity", role, m)
    # lateral-movement pivots: detections on the source host before the move, on the target host after it
    for a, b, d in [(u, v, dd) for u, v, dd in g.G.edges(data=True) if dd.get("type") == "LATERAL_MOVEMENT_TO"]:
        when = parse_time(d.get("time"))
        if when is None:
            continue
        key = f"{a}|{b}|{fmt_time(when)}"
        for m in ctx.alerts_on(a):
            t = times.get(m)
            if t is not None and when - timedelta(hours=LM_LOOKBACK_HOURS) <= t <= when + timedelta(minutes=5):
                pivot("lm", key, m)
        for m in ctx.alerts_on(b):
            t = times.get(m)
            if t is not None and when - timedelta(minutes=5) <= t <= when + timedelta(hours=WINDOW_HOST_H):
                pivot("lm", key, m)
    uf = _UnionFind()
    for m in members:
        uf.add(m)
    for (kind, _key), ms in pivots.items():
        ms = list(dict.fromkeys(ms))
        if len(ms) < 2 or len(ms) > HUB_MEMBER_LIMIT:
            continue
        _union_group(uf, ctx, kind, ms, times)
    clusters: dict[str, list[str]] = defaultdict(list)
    for m in members:
        clusters[uf.find(m)].append(m)
    accepted: list[tuple[list[str], list[str]]] = []
    for ms in clusters.values():
        ok, signals = _accept_cluster(ctx, ms, kinds_of)
        if ok:
            ordered = sorted(ms, key=lambda m: (times[m] or NOW, m))[:MAX_STORYLINE_MEMBERS]
            accepted.append((ordered, signals))
    accepted.sort(key=lambda item: (times[item[0][0]] or NOW, item[0][0]))
    used_slugs: dict[str, int] = defaultdict(int)
    created: list[str] = []
    for ms, signals in accepted:
        created.append(_materialize_storyline(ctx, ms, times, used_slugs, signals))
    ctx.invalidate()
    return created


def _has_crown_jewel_credential_chain(ctx: AnalyticsContext, members: list[str]) -> bool:
    g = ctx.graph
    for m in members:
        creds = [c for c, _ in g.in_edges(m, ("STOLEN_BY",))] + [c for c, _ in g.out_edges(m, ("USED_CREDENTIAL",))]
        for c in creds:
            if not g.out_edges(root_credential(ctx, c), ("STOLEN_BY",)):
                continue
            if ctx.reaches_crown_jewel(c, 4, "access"):
                return True
    return False


def _member_stage(ctx: AnalyticsContext, m: str) -> int:
    g = ctx.graph
    if g.label_of(m) == "Alert":
        return sem.alert_stage(g.node(m))
    return sem.event_stage(g.node(m))


def _member_techniques(ctx: AnalyticsContext, m: str) -> list[str]:
    g = ctx.graph
    if g.label_of(m) == "Alert":
        return [str(t) for t in as_list(g.get(m, "techniques"))]
    return sem.event_techniques(g.node(m))


def _attribute(ctx: AnalyticsContext, members: list[str]) -> tuple[str | None, str | None, float, float]:
    """Campaign attribution of a cluster: (campaign, basis, confidence, ttp_overlap).

    Votes come from high-confidence attribution edges and indicator matches (>= MIN_VOTE_CONFIDENCE, active
    indicators, non-historical campaigns). Without votes, a campaign whose TTPs cover >= MIN_TTP_RATIO of the
    storyline's techniques (at least MIN_TTP_TECHNIQUES of them) is attributed on a ``ttp`` basis.
    """
    g = ctx.graph
    votes: dict[str, float] = defaultdict(float)
    basis_of: dict[str, str] = {}

    def live(c: str) -> bool:
        return str(g.get(c, "status") or "active") != "historical"

    for m in members:
        for who, d in g.out_edges(m, ("ATTRIBUTED_TO",)):
            conf = float(d.get("confidence") or 0.0)
            if g.label_of(who) == "Campaign" and conf >= MIN_VOTE_CONFIDENCE and live(who):
                votes[who] += conf
                basis_of.setdefault(who, str(d.get("basis") or "ioc"))
        for ind, d in g.out_edges(m, ("MATCHES_IOC",)):
            conf = float(d.get("confidence") or g.get(ind, "confidence") or 0.0)
            c = campaign_of(ctx, ind)
            if c and conf >= MIN_VOTE_CONFIDENCE and g.get(ind, "active") is not False and live(c):
                votes[c] += conf * 0.5
                basis_of.setdefault(c, "ioc")
    member_techs = {t for m in members for t in _member_techniques(ctx, m)}
    if votes:
        campaign = max(votes.items(), key=lambda kv: (kv[1], kv[0]))[0]
        ttps = campaign_techniques(ctx, campaign)
        overlap = len(member_techs & ttps) / len(member_techs) if member_techs else 0.0
        return campaign, basis_of.get(campaign, "ioc"), round(min(0.95, votes[campaign]), 3), round(overlap, 3)
    if len(member_techs) >= MIN_TTP_TECHNIQUES:
        best: tuple[float, float, str] | None = None
        for c in g.nodes_by_label("Campaign"):
            if not live(c):
                continue
            ttps = campaign_techniques(ctx, c)
            shared = member_techs & ttps
            overlap = len(shared) / len(member_techs)
            if len(shared) >= MIN_TTP_TECHNIQUES and overlap >= MIN_TTP_RATIO:
                cand = (overlap, relevance_of(ctx, c), c)
                if best is None or cand > best:
                    best = cand
        if best is not None:
            return best[2], "ttp", round(0.3 + 0.4 * best[0], 3), round(best[0], 3)
    return None, None, 0.0, 0.0


def _materialize_storyline(ctx: AnalyticsContext, members: list[str], times: dict[str, datetime | None], used_slugs: dict[str, int],
                           signals: list[str] | None = None) -> str:
    g = ctx.graph
    alerts = [m for m in members if g.label_of(m) == "Alert"]
    events = [m for m in members if g.label_of(m) == "CloudEvent"]
    campaign, att_basis, att_conf, ttp_overlap = _attribute(ctx, members)
    actor = actor_of(ctx, campaign) if campaign else None
    # anchors, credentials, hosts
    anchors: list[str] = []
    hosts: list[str] = []
    creds: list[str] = []
    ips: list[str] = []
    for a in alerts:
        anc = ctx.anchor_of(a)
        if anc:
            anchors.append(anc)
            if g.label_of(anc) in ("Endpoint", "VirtualMachine"):
                hosts.append(anc)
                twin = ctx.vm_of_endpoint.get(anc) or ctx.endpoint_of_vm.get(anc)
                if twin:
                    anchors.append(twin)
        for c, _ in g.in_edges(a, ("STOLEN_BY",)):
            creds.append(c)
        creds.extend(ctx.alert_involves(a, {"Credential"}))
        ips.extend(ip for ip in ctx.alert_involves(a, {"IpAddress"}) if not g.get(ip, "is_private") and not ctx.is_hub(ip))
    for ev in events:
        creds.extend(c for c, _ in g.out_edges(ev, ("USED_CREDENTIAL",)))
        anchors.extend(r for r, _ in g.out_edges(ev, ("PERFORMED_BY", "ASSUMED")))
        ips.extend(ip for ip, _ in g.out_edges(ev, ("FROM_IP",)) if not g.get(ip, "is_private") and not ctx.is_hub(ip))
    anchors = list(dict.fromkeys(anchors))
    creds = list(dict.fromkeys(creds))
    ips = list(dict.fromkeys(ips))
    # crown jewels (and secrets) reached: union of access-mode reach from anchors and credentials + confirmed targets
    reached: set[str] = set()
    confirmed: set[str] = set()
    for root in anchors + creds:
        r = ctx.reach(root, 4, "access")
        for nid in r.ids():
            a = g.node(nid) or {}
            if sem.is_crown_jewel(a) or a.get("label") == "Secret":
                reached.add(nid)
    for ev in events:
        for t, _ in g.out_edges(ev, ("TARGETED",)):
            a = g.node(t) or {}
            if sem.is_crown_jewel(a) or a.get("label") == "Secret":
                reached.add(t)
                confirmed.add(t)
    # stages
    all_techs: list[str] = []
    for m in members:
        all_techs.extend(_member_techniques(ctx, m))
    covered = sem.stages_covered(all_techs) | {s for s in (_member_stage(ctx, m) for m in members) if s}
    stages_json: list[dict[str, Any]] = []
    for s in sorted(covered):
        s_members = [m for m in members if _member_stage(ctx, m) == s or s in sem.stages_covered(_member_techniques(ctx, m))]
        s_techs = sorted({t for m in s_members for t in _member_techniques(ctx, m) if t in sem.TECHNIQUES and int(sem.TECHNIQUES[t]["kill_chain_stage"]) == s})
        node_ids: list[str] = []
        for m in s_members:
            if g.label_of(m) == "Alert":
                anc = ctx.anchor_of(m)
                if anc:
                    node_ids.append(anc)
            else:
                node_ids.extend(t for t, _ in g.out_edges(m, ("TARGETED", "ASSUMED")))
        first = min((times[m] for m in s_members if times[m] is not None), default=None)
        stages_json.append({
            "stage": s, "name": sem.stage_label(s), "technique_ids": s_techs, "alert_ids": s_members,
            "node_ids": list(dict.fromkeys(node_ids)), "time": fmt_time(first),
            "summary": _stage_summary(ctx, s, s_members),
        })
    first_t = min((t for t in (times[m] for m in members) if t is not None), default=None)
    last_t = max((t for t in (times[m] for m in members) if t is not None), default=None)
    # id
    if campaign:
        base = _slug(ctx.name(campaign)) + "-larkspur"
    else:
        host = hosts[0] if hosts else (anchors[0] if anchors else members[0])
        base = _slug(ctx.short(host)) + "-" + (fmt_time(first_t) or "")[:10].replace("-", "")
    used_slugs[base] += 1
    slug = base if used_slugs[base] == 1 else f"{base}-{used_slugs[base]}"
    sid = f"storyline:derived:{slug}"
    host_names = list(dict.fromkeys(ctx.short(h) for h in hosts))
    top_jewels = sorted(reached, key=lambda n: (not sem.is_crown_jewel(g.node(n)), n))
    if campaign:
        title = f"{ctx.name(campaign)}: {ctx.name(actor) if actor else 'unknown actor'} intrusion via {' and '.join(host_names[:2]) or ctx.short(anchors[0])}"
    else:
        title = f"Correlated activity on {' and '.join(host_names[:2]) or ctx.short(anchors[0]) if anchors else 'multiple assets'}"
    if top_jewels:
        title += f" reaching {ctx.short(top_jewels[0])}"
    summary = (
        f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''} and {len(events)} cloud event{'s' if len(events) != 1 else ''} across "
        f"{len(host_names) or len(anchors)} asset{'s' if (len(host_names) or len(anchors)) != 1 else ''} between {fmt_time(first_t)} and {fmt_time(last_t)}, "
        f"covering {len(covered)} kill-chain stage{'s' if len(covered) != 1 else ''}"
        + (f"; attributed to {ctx.name(actor)} ({ctx.name(campaign)})" if actor and campaign else "")
        + (f"; {'confirmed' if confirmed else 'potential'} reach of {len(reached)} sensitive target{'s' if len(reached) != 1 else ''}: "
           + ", ".join(ctx.short(j) for j in top_jewels[:5]) if reached else "; no crown jewel reachable")
        + "."
    )
    g.add_node_record({
        "id": sid, "label": "Storyline", "name": title, "source": DERIVED, "source_id": None, "first_seen": fmt_time(first_t), "last_seen": fmt_time(last_t),
        "confidence": 0.9 if campaign else 0.7,
        "props": {
            "title": title, "summary": summary, "actor_id": actor, "campaign_id": campaign, "stage_count": len(covered), "alert_ids": alerts,
            "event_ids": events, "member_count": len(members), "crown_jewels_reached": sorted(reached), "confirmed_targets": sorted(confirmed),
            "confirmed_reach": bool(confirmed), "first_event": fmt_time(first_t), "last_event": fmt_time(last_t), "contextual_score": 0,
            "stages": stages_json, "anchor_ids": anchors, "credential_ids": creds, "host_ids": list(dict.fromkeys(hosts)), "ip_ids": ips,
            "attribution_basis": att_basis, "attribution_confidence": att_conf, "ttp_overlap": ttp_overlap,
            "correlation_signals": list(signals or []),
        },
    })
    for m in members:
        g.add_edge_record({"type": "IN_STORYLINE", "src": m, "dst": sid, "source": DERIVED, "first_seen": fmt_time(times[m]), "last_seen": fmt_time(times[m]),
                           "confidence": 0.9, "props": {"stage": _member_stage(ctx, m), "role": "member"}})
        g.set_node_props(m, storyline_id=sid)
    for role, ids in (("anchor", anchors), ("credential", creds), ("crown_jewel", sorted(reached)), ("infrastructure", ips)):
        for nid in ids:
            if g.label_of(nid) in sem_storyline_member_labels() and nid not in members:
                g.add_edge_record({"type": "IN_STORYLINE", "src": nid, "dst": sid, "source": DERIVED, "first_seen": fmt_time(first_t), "last_seen": fmt_time(last_t),
                                   "confidence": 0.9, "props": {"stage": None, "role": role}})
    for x, y in zip(members, members[1:], strict=False):
        g.add_edge_record({"type": "NEXT_STAGE", "src": x, "dst": y, "source": DERIVED, "first_seen": fmt_time(times[x]), "last_seen": fmt_time(times[y]),
                           "confidence": 0.9, "props": {"storyline_id": sid, "stage": _member_stage(ctx, y)}})
    for who, basis in ((campaign, att_basis or "ioc"), (actor, "derived")):
        if who:
            g.add_edge_record({"type": "ATTRIBUTED_TO", "src": sid, "dst": who, "source": DERIVED, "first_seen": fmt_time(first_t), "last_seen": fmt_time(last_t),
                               "confidence": att_conf, "props": {"basis": basis, "confidence": att_conf}})
    return sid


def sem_storyline_member_labels() -> set[str]:
    from throughline.schema.registry import STORYLINE_MEMBERS

    return set(STORYLINE_MEMBERS)


def _stage_summary(ctx: AnalyticsContext, stage: int, members: list[str]) -> str:
    g = ctx.graph
    alerts = [m for m in members if g.label_of(m) == "Alert"]
    events = [m for m in members if g.label_of(m) == "CloudEvent"]
    parts = []
    if alerts:
        hosts = list(dict.fromkeys(str(g.get(a, "hostname") or ctx.short(ctx.anchor_of(a) or a)) for a in alerts))
        parts.append(f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''} on {', '.join(hosts[:3])}")
    if events:
        names = list(dict.fromkeys(str(g.get(e, "event_name") or e) for e in events))
        parts.append(f"{len(events)} cloud event{'s' if len(events) != 1 else ''} ({', '.join(names[:4])})")
    return f"{sem.stage_label(stage)}: " + "; ".join(parts)


# ---------------------------------------------------------------------- output


def storyline_out(ctx: AnalyticsContext, sid: str, with_fragment: bool = True) -> StorylineOut:
    g = ctx.graph
    a = g.node(sid)
    if a is None:
        raise KeyError(sid)
    stages: list[StageOut] = []
    for i, s in enumerate(as_list(a.get("stages"))):
        if not isinstance(s, dict):
            continue
        edge_ids = []
        stages.append(StageOut(
            order=i + 1, stage=str(s.get("name") or sem.stage_label(int(s.get("stage") or 0))), technique_ids=[str(t) for t in as_list(s.get("technique_ids"))],
            node_ids=[str(n) for n in as_list(s.get("node_ids"))], edge_ids=edge_ids, alert_ids=[str(x) for x in as_list(s.get("alert_ids"))],
            time=s.get("time"), summary=str(s.get("summary") or ""),
        ))
    actor = a.get("actor_id")
    campaign = a.get("campaign_id")
    out = StorylineOut(
        id=sid, title=str(a.get("title") or a.get("name") or sid), summary=str(a.get("summary") or ""),
        actor_id=actor if actor in g else None, actor_name=ctx.name(actor) if actor in g else None,
        campaign_id=campaign if campaign in g else None, campaign_name=ctx.name(campaign) if campaign in g else None,
        contextual_score=int(a.get("contextual_score") or 0), stage_count=int(a.get("stage_count") or len(stages)),
        alert_ids=[str(x) for x in as_list(a.get("alert_ids"))], crown_jewels_reached=[str(x) for x in as_list(a.get("crown_jewels_reached"))],
        first_event=a.get("first_event"), last_event=a.get("last_event"), stages=stages,
    )
    if with_fragment:
        out.fragment = storyline_fragment(ctx, sid)
    return out


def storyline_path_nodes(ctx: AnalyticsContext, sid: str) -> list[str]:
    """Members in time order interleaved with the assets they sit on (the evidence path of the storyline)."""
    g = ctx.graph
    a = g.node(sid) or {}
    members = [m for m in as_list(a.get("alert_ids")) + as_list(a.get("event_ids")) if m in g]
    members.sort(key=lambda m: (ctx.member_time(m) or NOW, m))
    ordered: list[str] = []
    for m in members:
        ordered.append(m)
        if g.label_of(m) == "Alert":
            anc = ctx.anchor_of(m)
            if anc:
                ordered.append(anc)
                twin = ctx.vm_of_endpoint.get(anc)
                if twin:
                    ordered.append(twin)
        else:
            ordered.extend(c for c, _ in g.out_edges(m, ("USED_CREDENTIAL",)))
            ordered.extend(r for r, _ in g.out_edges(m, ("PERFORMED_BY", "ASSUMED", "TARGETED")))
    for c in as_list(a.get("credential_ids")):
        if c in g:
            ordered.append(c)
    ordered.extend(x for x in as_list(a.get("crown_jewels_reached")) if x in g)
    ordered.extend(x for x in as_list(a.get("ip_ids")) if x in g)
    return list(dict.fromkeys(ordered))


def storyline_fragment(ctx: AnalyticsContext, sid: str, max_nodes: int = 150) -> GraphFragment:
    g = ctx.graph
    nodes = storyline_path_nodes(ctx, sid) + [sid]
    a = g.node(sid) or {}
    members = [m for m in as_list(a.get("alert_ids")) + as_list(a.get("event_ids")) if m in g]
    members.sort(key=lambda m: (ctx.member_time(m) or NOW, m))
    frag = g.fragment(nodes, highlight_ids=set(members) | set(as_list(a.get("crown_jewels_reached"))), focus=[sid], layout_hint="storyline", max_nodes=max_nodes)
    if members:
        path = g.path_out(members, label="timeline")
        path.stages = [sem.stage_label(_member_stage(ctx, m)) for m in members]
        frag.paths = [path]
    frag.meta = {"members": len(members), "stage_count": int(a.get("stage_count") or 0)}
    return frag
