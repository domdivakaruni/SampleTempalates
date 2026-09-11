"""Graph-advantage insights: bounded path templates that only the fused graph can produce (docs/02 section 4(f)).

Every insight records the hop count of its evidence path and the data sources it crosses; only results with
``hops >= 2`` and ``sources >= 2`` are kept - a one-source, one-hop fact is something the originating console
already shows.
"""
from __future__ import annotations

from typing import Any

from throughline.analytics import semantics as sem
from throughline.analytics.blast import _path_out
from throughline.analytics.context import AnalyticsContext, as_dict, as_list, fmt_time
from throughline.models import Insight

BASE_IMPORTANCE = {
    "credential_join": 0.95, "blast_radius": 0.9, "exposure": 0.85, "ti_match": 0.8, "correlation": 0.75,
    "lateral": 0.7, "noise": 0.6, "identity": 0.5, "ownership": 0.4,
}


class InsightBuilder:
    def __init__(self, ctx: AnalyticsContext) -> None:
        self.ctx = ctx
        self.g = ctx.graph

    # ------------------------------------------------------------------ helpers

    def make(self, kind: str, statement: str, path: list[str], extra: list[str] | None = None, bonus: float = 0.0) -> Insight | None:
        path = [n for n in dict.fromkeys(path) if n in self.g]
        if len(path) < 3:
            return None
        extra_ids = [n for n in dict.fromkeys(extra or []) if n in self.g and n not in path]
        sources = sem.sources_crossed(self.g, path + extra_ids)
        hops = len(path) - 1
        if hops < 2 or len(sources) < 2:
            return None
        po = _path_out(self.ctx, path)
        importance = min(1.0, BASE_IMPORTANCE.get(kind, 0.5) + 0.02 * min(hops, 6) + 0.05 * (len(sources) - 2) + bonus)
        return Insight(kind=kind, statement=statement, hops=hops, sources=sources, importance=round(importance, 3),
                       evidence_node_ids=path + extra_ids, evidence_edge_ids=po.edge_ids)

    def app_of(self, node_id: str) -> str | None:
        for app, _ in self.g.out_edges(node_id, ("PART_OF",)):
            return app
        return None

    def team_of(self, node_id: str) -> str | None:
        for team, _ in self.g.out_edges(node_id, ("OWNED_BY",)):
            return team
        owner = self.g.get(node_id, "owner_team_id")
        return str(owner) if owner and owner in self.g else None

    def describe_step(self, a: str, b: str) -> str:
        g, ctx = self.g, self.ctx
        d = g.first_edge(a, b) or g.first_edge(b, a) or {"type": "UNLOCKS"}
        et = d.get("type")
        nb = ctx.short(b)
        lb = g.label_of(b)
        if et == "SAME_AS":
            return f"is cloud instance {nb}" if lb == "VirtualMachine" else f"is the sensor host {nb}"
        if et == "HAS_ROLE":
            return f"carries instance role {nb}"
        if et == "CAN_ASSUME":
            return f"can assume {nb}" + (" across accounts" if d.get("cross_account") else "")
        if et == "CAN_ACCESS":
            return f"has {d.get('access_level') or 'read'} access to {nb}"
        if et == "UNLOCKS":
            return f"holds credentials for {nb}"
        if et == "MAPS_TO":
            return f"maps by SSO to {nb}"
        if et == "PRIMARY_USER":
            return f"is used by {nb}"
        if et == "CREDENTIAL_FOR":
            return f"authenticates as {nb}"
        if et == "DERIVED_FROM":
            return f"issued session {nb}"
        if et == "LATERAL_MOVEMENT_TO":
            return f"moved laterally to {nb} over {d.get('protocol') or 'the network'}"
        if et == "ON_ENDPOINT" or et == "ON_RESOURCE":
            return f"sits on {nb}"
        return f"-> {nb}"

    # ------------------------------------------------------------------ templates

    def blast_radius(self, alert_id: str, anchor: str) -> Insight | None:
        g, ctx = self.g, self.ctx
        reach = ctx.reach(anchor, 4, "access")
        best: tuple[float, int, str] | None = None
        for nid in reach.ids():
            a = g.node(nid) or {}
            if not sem.is_crown_jewel(a) or a.get("label") == "IamRole":
                continue
            value = 1.0 if sem.is_regulated(a) else 0.7
            cand = (-value, reach.nodes[nid].hops, nid)
            if best is None or cand < best:
                best = cand
        if best is None:
            for nid in reach.ids():
                a = g.node(nid) or {}
                if a.get("label") == "IamRole" and a.get("is_admin"):
                    best = (-0.6, reach.nodes[nid].hops, nid)
                    break
        if best is None:
            return None
        jewel = best[2]
        path = reach.nodes[jewel].path
        steps = [self.describe_step(a, b) for a, b in zip(path, path[1:], strict=False)]
        jattrs = g.node(jewel) or {}
        classes = "/".join(sem.data_classes(jattrs)) or ("admin role" if jattrs.get("is_admin") else jattrs.get("label", ""))
        app = self.app_of(jewel)
        tail = f" ({classes}, crown jewel"
        extra: list[str] = []
        if app:
            tail += f" of {ctx.short(app)} {g.get(app, 'criticality') or ''}".rstrip()
            extra.append(app)
        tail += ")"
        head = f"{g.label_of(anchor)} {ctx.short(anchor)}"
        statement = f"{head} {'; '.join(steps)}{tail}."
        return self.make("blast_radius", statement, [alert_id] + list(path), extra, bonus=0.05 if sem.is_regulated(jattrs) else 0.0)

    def credential_join(self, alert_id: str) -> list[Insight]:
        g, ctx = self.g, self.ctx
        out: list[Insight] = []
        for cred, _ in g.in_edges(alert_id, ("STOLEN_BY",)):
            uses = sorted((ev for ev, _ in g.in_edges(cred, ("USED_CREDENTIAL",))), key=lambda e: str(g.get(e, "event_time") or ""))
            derived = [c for c, _ in g.in_edges(cred, ("DERIVED_FROM",))]
            derived_uses = sorted((ev for c in derived for ev, _ in g.in_edges(c, ("USED_CREDENTIAL",))), key=lambda e: str(g.get(e, "event_time") or ""))
            if uses or derived_uses:
                names = list(dict.fromkeys(str(g.get(e, "event_name") or "") for e in uses))
                ips = sorted({str(g.get(e, "source_ip") or "") for e in uses + derived_uses} - {""})
                first, last = (uses + derived_uses)[0], (uses + derived_uses)[-1]
                statement = (
                    f"Credential {ctx.short(cred)} stolen by this alert was used in {len(uses)} cloud API call{'s' if len(uses) != 1 else ''}"
                    f" ({', '.join(names[:4])}) from {', '.join(ips) or 'unknown ips'} between {g.get(first, 'event_time')} and {g.get(last, 'event_time')}"
                )
                if derived:
                    targets = sorted({ctx.short(t) for e in derived_uses for t, _ in g.out_edges(e, ("TARGETED",))})
                    statement += f"; the derived session {', '.join(ctx.short(c) for c in derived)} then made {len(derived_uses)} call{'s' if len(derived_uses) != 1 else ''}"
                    if targets:
                        statement += f" against {', '.join(targets[:4])}"
                statement += "."
                path = [alert_id, cred, (uses or derived_uses)[0]]
                ins = self.make("credential_join", statement, path, extra=uses[1:4] + derived + derived_uses[:4], bonus=0.05)
                if ins:
                    out.append(ins)
            # what the stolen credential authenticates as
            for principal, _ in g.out_edges(cred, ("CREDENTIAL_FOR",)):
                host = g.get(principal, "host_id")
                extra = [host] if host and host in g else []
                purpose = g.get(principal, "purpose")
                statement = (
                    f"Stolen {str(g.get(cred, 'credential_type') or 'credential').replace('_', ' ')} {ctx.short(cred)} authenticates as {ctx.short(principal)}"
                    + (f" on {ctx.short(host)}" if extra else "") + (f" ({purpose})" if purpose else "") + "."
                )
                path = [alert_id, cred, principal] + extra
                ins = self.make("identity", statement, path)
                if ins:
                    out.append(ins)
        return out

    def ti_matches(self, alert_id: str) -> list[Insight]:
        g, ctx = self.g, self.ctx
        out: list[Insight] = []
        for ind, d in g.out_edges(alert_id, ("MATCHES_IOC",)):
            via = d.get("via")
            entity = via if via and via in g else None
            if entity is None:
                for e, _ in g.out_edges(alert_id, ("INVOLVES",)):
                    if any(i == ind for i, _ in g.out_edges(e, ("MATCHES_IOC",))):
                        entity = e
                        break
            bridge: str | None = None
            if entity is not None and g.first_edge(alert_id, entity) is None:
                # the match sits one hop behind an involved process (a file it wrote, a host it contacted)
                bridge = next((e for e, _ in g.out_edges(alert_id, ("INVOLVES",)) if g.first_edge(e, entity) is not None), None)
            chain: list[str] = [alert_id] + ([bridge] if bridge else []) + ([entity] if entity else []) + [ind]
            malware = next((t for t, _ in g.out_edges(ind, ("INDICATES",)) if g.label_of(t) == "Malware"), None)
            campaign = g.get(ind, "campaign_id") if g.get(ind, "campaign_id") in g else next((t for t, _ in g.out_edges(ind, ("INDICATES",)) if g.label_of(t) == "Campaign"), None)
            actor = g.get(ind, "actor_id") if g.get(ind, "actor_id") in g else None
            if actor is None and campaign:
                actor = g.get(campaign, "actor_id") if g.get(campaign, "actor_id") in g else None
            for x in (malware, campaign, actor):
                if x:
                    chain.append(x)
            conf = float(d.get("confidence") or g.get(ind, "confidence") or 0)
            ioc_type = g.get(ind, "ioc_type")
            what = {"sha256": "hash", "ipv4": "ip", "domain": "domain", "filename": "file name", "url": "url"}.get(str(ioc_type), str(ioc_type))
            ent_desc = f"{g.label_of(entity)} {ctx.short(entity)}" if entity else "the alert"
            statement = f"{ent_desc} {what} matches indicator {g.get(ind, 'value')} (confidence {conf:.2f})"
            if malware:
                statement += f" for {ctx.name(malware)}"
            if campaign:
                statement += f" used in {ctx.name(campaign)}"
            if actor:
                rel = float(g.get(actor, "sector_targeting_relevance") or 0)
                sectors = ", ".join(str(s) for s in as_list(g.get(actor, "targeted_sectors"))[:2])
                statement += f" by {ctx.name(actor)}, {'active' if g.get(actor, 'active') else 'known'} against {sectors or 'our sector'} (relevance {rel:.2f})"
            report = g.get(ind, "report_id")
            extra = [report] if report and report in g else []
            statement += "."
            ins = self.make("ti_match", statement, chain, extra, bonus=0.05 if conf >= 0.85 else -0.1)
            if ins:
                out.append(ins)
        return out

    def exposure(self, alert_id: str, anchor: str, asset: str) -> Insight | None:
        g, ctx = self.g, self.ctx
        exposes = [u for u, _ in g.in_edges(asset, ("EXPOSES",))]
        if not exposes and str(g.get(asset, "exposure") or "") != "internet":
            return None
        best: tuple[int, float, str] | None = None
        for cve, _ in g.out_edges(asset, ("VULNERABLE_TO",)):
            status = str(g.get(cve, "exploitation_status") or "none")
            rank = sem.EXPLOITATION_RANK.get(status, 0)
            rel = float(g.get(cve, "sector_targeting_relevance") or 0)
            if best is None or (rank, rel) > (best[0], best[1]):
                best = (rank, rel, cve)
        if best is None:
            return None
        cve = best[2]
        status = str(g.get(cve, "exploitation_status") or "none")
        campaign = next((c for c, _ in g.in_edges(cve, ("EXPLOITS",)) if g.label_of(c) == "Campaign"), None)
        actors = [a for a in as_list(g.get(cve, "actor_interest")) if a in g]
        actor = actors[0] if actors else None
        ports = ", ".join(str(p) for p in as_list((g.first_edge(exposes[0], asset, "EXPOSES") or {}).get("ports"))) if exposes else ""
        path = [alert_id] + ([anchor] if anchor != asset else []) + [asset, cve] + ([campaign] if campaign else []) + ([actor] if actor else [])
        statement = f"Host {ctx.short(asset)} is internet-exposed{(' on ' + ports) if ports else ''} and vulnerable to {g.get(cve, 'cve_id') or ctx.short(cve)}"
        if status in sem.EXPLOITED_STATUSES:
            statement += f", under {status.replace('_', ' ')}"
            if actor:
                rel = float(g.get(actor, "sector_targeting_relevance") or 0)
                statement += f" by {ctx.name(actor)}" + (f" ({ctx.name(campaign)})" if campaign else "") + f" targeting our sector (relevance {rel:.2f})"
        elif g.get(cve, "kev"):
            statement += " (listed as known exploited)"
        else:
            statement += f" (no exploitation reported; CVSS {g.get(cve, 'cvss')})"
        statement += "."
        extra = [exposes[0]] if exposes else []
        return self.make("exposure", statement, path, extra, bonus=0.05 if status in sem.EXPLOITED_STATUSES else -0.15)

    def lateral(self, alert_id: str, anchor: str) -> list[Insight]:
        g, ctx = self.g, self.ctx
        out: list[Insight] = []
        ep = ctx.endpoint_for(anchor) or anchor
        for b, d in g.out_edges(ep, ("LATERAL_MOVEMENT_TO",)):
            others = [a for a in ctx.alerts_on(b) if a != alert_id]
            vm = ctx.vm_of_endpoint.get(b)
            when = d.get("time")
            statement = f"This device moved laterally to {ctx.short(b)} over {d.get('protocol') or 'the network'} as {d.get('account') or 'an unknown account'}"
            if when:
                statement += f" at {when}"
            if vm:
                statement += f"; {ctx.short(b)} is cloud instance {g.get(vm, 'source_id') or ctx.short(vm)}"
            if others:
                titles = list(dict.fromkeys(str(g.get(a, "title") or a) for a in others[:2]))
                statement += f"; {len(others)} alert{'s' if len(others) != 1 else ''} followed there ({'; '.join(titles)})"
            statement += "."
            path = [alert_id, ep, b] + ([vm] if vm else []) + (others[:1] if others else [])
            ins = self.make("lateral", statement, path, extra=others[1:3])
            if ins:
                out.append(ins)
        for a_ep, d in g.in_edges(ep, ("LATERAL_MOVEMENT_TO",)):
            prior = [a for a in ctx.alerts_on(a_ep)]
            statement = f"This host was reached from {ctx.short(a_ep)} over {d.get('protocol') or 'the network'} as {d.get('account') or 'an unknown account'}"
            if d.get("time"):
                statement += f" at {d.get('time')}"
            if prior:
                statement += f"; {ctx.short(a_ep)} had {len(prior)} earlier alert{'s' if len(prior) != 1 else ''} ({str(g.get(prior[0], 'title'))})"
            user = next((u for u, _ in g.out_edges(a_ep, ("PRIMARY_USER",))), None)
            if user:
                statement += f"; its primary user is {ctx.name(user)} ({g.get(user, 'department') or g.get(user, 'title') or 'user'})"
            statement += "."
            path = [alert_id, ep, a_ep] + (prior[:1] if prior else []) + ([user] if user else [])
            ins = self.make("lateral", statement, path, extra=prior[1:3])
            if ins:
                out.append(ins)
        return out

    def correlation(self, alert_id: str) -> Insight | None:
        g, ctx = self.g, self.ctx
        sid = next((s for s, _ in g.out_edges(alert_id, ("IN_STORYLINE",))), None)
        if not sid:
            return None
        a = g.node(sid) or {}
        alerts = [x for x in as_list(a.get("alert_ids")) if x in g]
        events = [x for x in as_list(a.get("event_ids")) if x in g]
        hosts = [ctx.short(h) for h in as_list(a.get("host_ids")) if h in g]
        jewels = [x for x in as_list(a.get("crown_jewels_reached")) if x in g]
        actor = a.get("actor_id") if a.get("actor_id") in g else None
        statement = f"Part of storyline '{a.get('title') or sid}': {len(alerts)} alert{'s' if len(alerts) != 1 else ''} and {len(events)} cloud event{'s' if len(events) != 1 else ''} across {', '.join(dict.fromkeys(hosts)) or 'several assets'}"
        if actor:
            statement += f", attributed to {ctx.name(actor)}"
        if jewels:
            statement += f"; {'confirmed' if a.get('confirmed_reach') else 'potential'} reach of {', '.join(ctx.short(j) for j in jewels[:3])}"
        statement += "."
        other = [x for x in alerts if x != alert_id]
        path = [alert_id, sid] + (events[:1] or other[:1])
        extra = other[:3] + events[1:3] + jewels[:3] + ([actor] if actor else [])
        return self.make("correlation", statement, path, extra, bonus=0.1 if a.get("confirmed_reach") else 0.0)

    def change_window(self, alert_id: str, attrs: dict[str, Any]) -> Insight | None:
        g, ctx = self.g, self.ctx
        ticket = attrs.get("change_ticket")
        if not ticket:
            return None
        users = ctx.alert_involves(alert_id, {"HumanUser"})
        user = users[0] if users else None
        wks = next((ep for ep, _ in g.in_edges(user, ("PRIMARY_USER",))), None) if user else None
        src_ip = attrs.get("source_ip")
        own = bool(wks and src_ip and str(g.get(wks, "private_ip")) == str(src_ip))
        statement = f"Executed inside approved change window {ticket}"
        if user:
            statement += f" by {ctx.name(user)} ({g.get(user, 'title') or g.get(user, 'department') or 'user'})"
        if wks:
            statement += f" from {'their own workstation ' if own else ''}{ctx.short(wks)}"
        statement += "."
        path = [alert_id] + ([user] if user else []) + ([wks] if wks else [])
        return self.make("noise", statement, path)

    def public_data(self, alert_id: str, anchor: str) -> Insight | None:
        g, ctx = self.g, self.ctx
        a = g.node(anchor) or {}
        if a.get("label") not in ("StorageBucket", "Database"):
            return None
        classes = sem.data_classes(a)
        if classes and set(classes) - {"PUBLIC"}:
            return None
        app = self.app_of(anchor)
        team = self.team_of(anchor) or (self.team_of(app) if app else None)
        statement = f"Bucket {ctx.short(anchor)} holds only {'/'.join(classes) or 'unclassified'} data (sensitivity {a.get('sensitivity') or 'none'})"
        if app:
            statement += f" for application {ctx.short(app)} ({g.get(app, 'criticality') or 'no tier'})"
        if team:
            statement += f", owned by {ctx.name(team)}"
        statement += "; no actor interest and no privilege reach from the bucket."
        path = [alert_id, anchor] + ([app] if app else []) + ([team] if team and not app else [])
        return self.make("noise", statement, path, extra=[team] if team else [])

    def scanner(self, alert_id: str, attrs: dict[str, Any]) -> Insight | None:
        g, ctx = self.g, self.ctx
        for ip in ctx.alert_involves(alert_id, {"IpAddress"}):
            addr = str(g.get(ip, "address") or "")
            if addr in ctx.scanner_ips:
                vms = ctx.vms_by_ip.get(addr, [])
                vm = vms[0] if vms else None
                statement = f"Source {addr} is {ctx.short(vm) if vm else 'the internal vulnerability scanner'}"
                if vm:
                    tags = as_dict(g.get(vm, "tags"))
                    statement += f", the internal vulnerability scanner (tag role={tags.get('role')})" if tags.get("role") else ", the internal vulnerability scanner"
                statement += "."
                path = [alert_id, ip] + ([vm] if vm else [])
                return self.make("noise", statement, path)
        return None

    def vpn_egress(self, alert_id: str, attrs: dict[str, Any], anchor: str) -> Insight | None:
        g, ctx = self.g, self.ctx
        for ip in ctx.alert_involves(alert_id, {"IpAddress"}):
            addr = str(g.get(ip, "address") or "")
            if addr in ctx.vpn_ips:
                user = anchor if g.label_of(anchor) == "HumanUser" else None
                wks = next((ep for ep, _ in g.in_edges(user, ("PRIMARY_USER",))), None) if user else None
                mfa = attrs.get("mfa_satisfied") or str(as_dict(attrs.get("raw")).get("mfa") or "").lower() == "satisfied"
                statement = f"Second login egress {addr} is the corporate VPN ({g.get(ip, 'asn_org') or 'corporate'})"
                if mfa:
                    statement += "; MFA satisfied"
                if user:
                    statement += f"; {ctx.name(user)}'s registered workstation is {ctx.short(wks) if wks else 'unknown'}"
                statement += "."
                path = [alert_id, ip] + ([user] if user else []) + ([wks] if wks else [])
                if len(path) < 3 and user:
                    path = [alert_id, user, ip]
                return self.make("noise", statement, path)
        return None

    def ownership(self, alert_id: str, anchor: str, asset: str) -> Insight | None:
        g, ctx = self.g, self.ctx
        app = self.app_of(asset) or self.app_of(anchor)
        team = self.team_of(asset) or self.team_of(anchor) or (self.team_of(app) if app else None)
        if not app and not team:
            return None
        parts = []
        if app:
            parts.append(f"belongs to application {ctx.short(app)} ({g.get(app, 'criticality') or 'no tier'})")
        if team:
            oncall = g.get(team, "oncall_channel")
            parts.append(f"owned by {ctx.name(team)}" + (f" ({oncall})" if oncall else ""))
        statement = f"{g.label_of(asset)} {ctx.short(asset)} " + ", ".join(parts) + "."
        path = [alert_id] + ([anchor] if anchor != asset else []) + [asset] + ([app] if app else []) + ([team] if team else [])
        return self.make("ownership", statement, path)

    def primary_user(self, alert_id: str, anchor: str) -> Insight | None:
        g, ctx = self.g, self.ctx
        if g.label_of(anchor) != "Endpoint":
            return None
        user = next((u for u, _ in g.out_edges(anchor, ("PRIMARY_USER",))), None)
        if not user:
            return None
        team = next((t for t, _ in g.out_edges(user, ("MEMBER_OF",)) if g.label_of(t) == "Team"), None)
        roles = [r for r, _ in g.out_edges(user, ("MAPS_TO",))]
        statement = f"Primary user {ctx.name(user)} ({g.get(user, 'title') or g.get(user, 'department') or 'user'})"
        if team:
            statement += f" of {ctx.name(team)}"
        if roles:
            admin = [r for r in roles if g.get(r, "is_admin")]
            statement += f"; SSO maps to {', '.join(ctx.short(r) for r in roles[:2])}" + (" (admin)" if admin else "")
        if g.get(user, "is_executive"):
            statement += "; executive"
        if g.get(user, "is_privileged"):
            statement += "; privileged account"
        statement += "."
        path = [alert_id, anchor, user] + (roles[:1] if roles else [team] if team else [])
        return self.make("identity", statement, path, bonus=0.2 if any(g.get(r, "is_admin") for r in roles) else 0.0)


def insights_for_alert(ctx: AnalyticsContext, alert_id: str) -> list[Insight]:
    g = ctx.graph
    if alert_id not in g:
        return []
    attrs = g.node(alert_id) or {}
    anchor = ctx.anchor_of(alert_id)
    b = InsightBuilder(ctx)
    found: list[Insight | None] = []
    if anchor:
        asset = ctx.vm_or_self(anchor)
        found.append(b.blast_radius(alert_id, anchor))
        found.append(b.exposure(alert_id, anchor, asset))
        found.extend(b.lateral(alert_id, anchor))
        found.append(b.public_data(alert_id, anchor))
        found.append(b.vpn_egress(alert_id, attrs, anchor))
        found.append(b.ownership(alert_id, anchor, asset))
        found.append(b.primary_user(alert_id, anchor))
    found.extend(b.credential_join(alert_id))
    found.extend(b.ti_matches(alert_id))
    found.append(b.correlation(alert_id))
    found.append(b.change_window(alert_id, attrs))
    found.append(b.scanner(alert_id, attrs))
    out: list[Insight] = []
    seen: set[str] = set()
    for ins in found:
        if ins is None or ins.statement in seen:
            continue
        seen.add(ins.statement)
        out.append(ins)
    out.sort(key=lambda i: (-len(i.sources), -i.importance, -i.hops, i.statement))
    return out[:12]


__all__ = ["InsightBuilder", "insights_for_alert", "fmt_time"]
