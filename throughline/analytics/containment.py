"""Containment simulation (question 12): what an action contains and what it breaks.

Actions remove semantic moves from a *view* of the graph (the graph itself is never mutated), storyline
reachability is recomputed with and without the cuts, and operational breakage is read from ``DEPENDS_ON``,
``PART_OF`` and ``OWNED_BY``.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from throughline.analytics import semantics as sem
from throughline.analytics.context import NOW, AnalyticsContext, as_dict, as_list, parse_time
from throughline.analytics.correlation import storyline_path_nodes
from throughline.analytics.semantics import Move
from throughline.models import BreakItem, ContainmentSimulation, GraphFragment

ACTIONS = ("isolate_endpoint", "rotate_role_credentials", "tighten_trust_policy", "block_ip", "disable_user", "revoke_sessions")
REACH_DEPTH = 6


def _sensitive(attrs: dict[str, Any] | None) -> bool:
    return bool(attrs) and (sem.is_crown_jewel(attrs) or attrs.get("label") == "Secret")


class _Plan:
    def __init__(self, ctx: AnalyticsContext, target_ids: list[str], actions: list[str]) -> None:
        self.ctx = ctx
        self.g = ctx.graph
        self.targets = [t for t in dict.fromkeys(target_ids) if t in self.g]
        self.actions = [a for a in dict.fromkeys(actions) if a in ACTIONS]
        self.isolated: set[str] = set()
        self.revoked_credentials: set[str] = set()
        self.trust_cut_roles: set[str] = set()
        self.disabled_users: set[str] = set()
        self.blocked_ips: set[str] = set()
        self.notes: list[str] = []
        self.residual: list[str] = []
        self.recommendations: list[str] = []
        self._expand()

    # ------------------------------------------------------------------ planning

    def _hosts(self) -> list[str]:
        out = []
        for t in self.targets:
            if self.g.label_of(t) in ("Endpoint", "VirtualMachine"):
                out.append(t)
        return out

    def _roles(self) -> list[str]:
        return [t for t in self.targets if self.g.label_of(t) in ("IamRole", "IamUser")]

    def _users(self) -> list[str]:
        return [t for t in self.targets if self.g.label_of(t) in ("HumanUser", "ServiceAccount", "IamUser")]

    def _expand(self) -> None:
        g, ctx = self.g, self.ctx
        for action in self.actions:
            if action == "isolate_endpoint":
                hosts = self._hosts()
                if not hosts:
                    self.notes.append("isolate_endpoint: no endpoint or VM among the targets")
                for h in hosts:
                    self.isolated.add(h)
                    twin = ctx.vm_of_endpoint.get(h) or ctx.endpoint_of_vm.get(h)
                    if twin:
                        self.isolated.add(twin)
            elif action in ("rotate_role_credentials", "revoke_sessions"):
                principals = self._roles() + ([u for u in self._users() if action == "revoke_sessions"])
                if not principals:
                    self.notes.append(f"{action}: no role or user among the targets")
                for p in principals:
                    for cred, _ in g.in_edges(p, ("CREDENTIAL_FOR",)):
                        ctype = str(g.get(cred, "credential_type") or "")
                        if action == "revoke_sessions" and ctype not in ("aws_temporary_key", "session_token", "kerberos_ticket", "api_token", ""):
                            continue
                        self.revoked_credentials.add(cred)
                        self._derived_residual(cred, p, action)
                    if action == "rotate_role_credentials" and g.label_of(p) == "IamRole":
                        if not any(g.out_edges(p, ("CAN_ASSUME",))) and any(g.in_edges(p, ("CAN_ASSUME",))) and "tighten_trust_policy" not in self.actions:
                            self.residual.append(f"trust policy of {ctx.short(p)} still allows assumption; rotation alone does not stop a new AssumeRole")
                        assumable = [r for r, _ in g.out_edges(p, ("CAN_ASSUME",))]
                        for r in assumable:
                            if "tighten_trust_policy" not in self.actions:
                                self.residual.append(f"trust policy of {ctx.short(r)} still allows {ctx.short(p)} to assume it; tighten it so a re-stolen instance credential cannot pivot again")
                                self.recommendations.append(f"tighten_trust_policy on {r}")
                        hosts_using = [v for v, _ in g.in_edges(p, ("HAS_ROLE",))]
                        if hosts_using and not any(h in self.isolated or ctx.endpoint_of_vm.get(h) in self.isolated for h in hosts_using):
                            self.residual.append(f"{ctx.short(p)} stays attached to {', '.join(ctx.short(h) for h in hosts_using[:3])}; an attacker still on the host can re-read fresh credentials from IMDS")
            elif action == "tighten_trust_policy":
                roles = [r for r in self._roles() if g.label_of(r) == "IamRole"]
                # also roles that the target roles can assume (the natural remediation for a role-chain pivot)
                for r in list(roles):
                    roles.extend(x for x, _ in g.out_edges(r, ("CAN_ASSUME",)))
                if not roles:
                    self.notes.append("tighten_trust_policy: no IAM role among the targets")
                self.trust_cut_roles.update(roles)
            elif action == "disable_user":
                users = self._users()
                if not users:
                    self.notes.append("disable_user: no user among the targets")
                self.disabled_users.update(users)
                for u in users:
                    for cred, _ in g.in_edges(u, ("CREDENTIAL_FOR",)):
                        self.revoked_credentials.add(cred)
            elif action == "block_ip":
                ips = [t for t in self.targets if g.label_of(t) == "IpAddress"]
                if not ips:
                    self.notes.append("block_ip: no ip address among the targets")
                self.blocked_ips.update(ips)
                for ip in ips:
                    self.residual.append(f"blocking {ctx.short(ip)} stops the current egress only; the actor can rotate infrastructure")

    def _derived_residual(self, cred: str, principal: str, action: str) -> None:
        g, ctx = self.g, self.ctx
        for child, _ in g.in_edges(cred, ("DERIVED_FROM",)):
            exp = parse_time(g.get(child, "expires_at"))
            status = str(g.get(child, "status") or "unknown")
            for target_role, _ in g.out_edges(child, ("CREDENTIAL_FOR",)):
                if exp is not None and exp <= NOW:
                    self.residual.append(
                        f"derived session {ctx.short(child)} for {ctx.short(target_role)} is not invalidated by rotating {ctx.short(principal)}; it expired at {g.get(child, 'expires_at')} (status {status}), so no live access remains from it"
                    )
                else:
                    self.residual.append(
                        f"derived session {ctx.short(child)} for {ctx.short(target_role)} is NOT invalidated by rotating {ctx.short(principal)} and is still valid (expires {g.get(child, 'expires_at') or 'unknown'}); revoke it explicitly"
                    )
                    self.recommendations.append(f"revoke_sessions on {target_role}")

    # ------------------------------------------------------------------ the cut

    def blocked(self, m: Move) -> bool:
        g = self.g
        if m.etype in ("ON_ENDPOINT", "ON_RESOURCE"):
            return False
        if m.src in self.isolated or m.dst in self.isolated:
            return True
        if m.etype == "CREDENTIAL_FOR" and m.src in self.revoked_credentials:
            return True
        if m.etype == "CAN_ASSUME" and m.dst in self.trust_cut_roles:
            return True
        if m.src in self.disabled_users or m.dst in self.disabled_users:
            return True
        if g.label_of(m.src) == "Credential" and m.src in self.revoked_credentials and m.etype != "DERIVED_FROM":
            return True
        return False


def simulate_containment(ctx: AnalyticsContext, target_ids: list[str], actions: list[str]) -> ContainmentSimulation:
    g = ctx.graph
    plan = _Plan(ctx, target_ids, actions)
    blocked: Callable[[Move], bool] = plan.blocked

    # storyline reachability before / after
    paths_cut = 0
    contained: list[str] = []
    protected: set[str] = set()
    partially: list[str] = []
    story_nodes: list[str] = []
    for sid in g.nodes_by_label("Storyline"):
        roots = _storyline_roots(ctx, sid)
        before: set[str] = set()
        after: set[str] = set()
        pairs_before = 0
        pairs_after = 0
        for root in roots:
            rb = ctx.reach(root, REACH_DEPTH, "full", 800)
            ra = ctx.reach(root, REACH_DEPTH, "full", 800, blocked=blocked)
            sb = {n for n in rb.ids() if _sensitive(g.node(n))}
            sa = {n for n in ra.ids() if _sensitive(g.node(n))}
            before |= sb
            after |= sa
            pairs_before += len(sb)
            pairs_after += len(sa)
        if not before:
            continue
        cut = pairs_before - pairs_after
        if cut > 0:
            paths_cut += cut
        if before and not after:
            contained.append(sid)
            protected |= before
            story_nodes.extend(storyline_path_nodes(ctx, sid))
        elif cut > 0:
            partially.append(sid)
            protected |= before - after
            plan.residual.append(f"{g.get(sid, 'title') or sid}: {len(after)} sensitive target{'s' if len(after) != 1 else ''} still reachable ({', '.join(ctx.short(x) for x in sorted(after)[:3])})")
    # direct protection from the targets themselves (works without storylines too)
    for t in plan.targets:
        rb = ctx.reach(t, 4, "full")
        ra = ctx.reach(t, 4, "full", blocked=blocked)
        sb = {n for n in rb.ids() if _sensitive(g.node(n))}
        sa = {n for n in ra.ids() if _sensitive(g.node(n))}
        if sb - sa:
            protected |= sb - sa
            if not any(g.nodes_by_label("Storyline")):
                paths_cut += len(sb - sa)

    breaks = _breaks(ctx, plan)
    recommendations = _recommendations(ctx, plan, contained, protected)
    residual = list(dict.fromkeys(plan.residual + plan.notes))
    frag = _fragment(ctx, plan, contained, story_nodes, sorted(protected), breaks)
    return ContainmentSimulation(
        target_ids=plan.targets, actions=plan.actions, paths_cut=paths_cut, storylines_contained=contained,
        crown_jewels_protected=sorted(protected), breaks=breaks, residual_risks=residual,
        recommendations=list(dict.fromkeys(recommendations)), fragment=frag,
    )


def _storyline_roots(ctx: AnalyticsContext, sid: str) -> list[str]:
    """Attacker footholds of a storyline: alerts on hosts / users (not on the identities they abused) and stolen
    credentials that are still valid at NOW."""
    g = ctx.graph
    roots: list[str] = []
    for a in as_list(g.get(sid, "alert_ids")):
        if a not in g:
            continue
        anchor = ctx.anchor_of(a)
        if anchor and g.label_of(anchor) in ("IamRole", "IamUser", "AccessKey"):
            continue
        roots.append(a)
    for cred in as_list(g.get(sid, "credential_ids")):
        if cred not in g:
            continue
        status = str(g.get(cred, "status") or "unknown").lower()
        exp = parse_time(g.get(cred, "expires_at"))
        if status in ("revoked", "expired") or (exp is not None and exp <= NOW):
            continue
        roots.append(cred)
    return list(dict.fromkeys(roots))


def _team_of(ctx: AnalyticsContext, node_id: str | None) -> str | None:
    if not node_id:
        return None
    g = ctx.graph
    for team, _ in g.out_edges(node_id, ("OWNED_BY",)):
        return team
    owner = g.get(node_id, "owner_team_id")
    if owner and owner in g:
        return str(owner)
    tags = as_dict(g.get(node_id, "tags"))
    owner_tag = tags.get("owner")
    if owner_tag:
        cand = f"team:larkspur:{owner_tag}"
        if cand in g:
            return cand
    return None


def _breaks(ctx: AnalyticsContext, plan: _Plan) -> list[BreakItem]:
    g = ctx.graph
    items: dict[str, BreakItem] = {}

    def add(node_id: str, impact: str, owner: str | None) -> None:
        if node_id in items:
            items[node_id].impact += f"; {impact}"
            return
        items[node_id] = BreakItem(node_id=node_id, name=ctx.short(node_id), label=g.label_of(node_id) or "Unknown", impact=impact, owner_team_id=owner)

    hosts = {ctx.vm_or_self(h) for h in plan.isolated} | {h for h in plan.isolated}
    for host in sorted(hosts):
        if g.label_of(host) == "Endpoint" and ctx.vm_of_endpoint.get(host) in hosts:
            continue  # the VM item covers the resolved endpoint
        for app, d in g.in_edges(host, ("DEPENDS_ON",)):
            add(app, f"{str(d.get('dependency_type') or 'runtime').replace('_', ' ')} dependency on {ctx.short(host)} is cut while it is isolated ({g.get(app, 'criticality') or 'no tier'})", _team_of(ctx, app))
        for app, _ in g.out_edges(host, ("PART_OF",)):
            if app not in items:
                add(app, f"hosted on {ctx.short(host)}; unavailable while isolated ({g.get(app, 'criticality') or 'no tier'})", _team_of(ctx, app))
        team = _team_of(ctx, host)
        tags = as_dict(g.get(host, "tags"))
        roles = [r for r, _ in g.out_edges(host, ("HAS_ROLE",))]
        if tags.get("role") == "bastion" or any("bastion" in ctx.short(r).lower() for r in roles) or "bas" in ctx.short(host).lower():
            add(host, f"bastion / SSM session access via {ctx.short(host)} is unavailable for {ctx.name(team) if team else 'its operators'} while isolated", team)
        elif team:
            add(host, f"operators of {ctx.name(team)} lose access to {ctx.short(host)} while isolated", team)
    for role in [t for t in plan.targets if g.label_of(t) == "IamRole"] if ("rotate_role_credentials" in plan.actions or "revoke_sessions" in plan.actions) else []:
        users_of = [v for v, _ in g.in_edges(role, ("HAS_ROLE",))]
        for vm in users_of:
            add(vm, f"instance credentials for {ctx.short(role)} are refreshed; in-flight sessions using the old key fail until the SDK retries", _team_of(ctx, vm))
        for app, _ in g.out_edges(role, ("PART_OF",)):
            add(app, f"uses role {ctx.short(role)}; brief credential refresh", _team_of(ctx, app))
        for user, d in g.in_edges(role, ("MAPS_TO",)):
            add(user, f"SSO mapping to {ctx.short(role)} interrupted while credentials rotate", _team_of(ctx, g.get(user, "team_id")))
    for user in plan.disabled_users:
        add(user, "account disabled; active sessions and SSO mappings stop working", _team_of(ctx, g.get(user, "team_id")) or (g.get(user, "team_id") if g.get(user, "team_id") in g else None))
    return sorted(items.values(), key=lambda b: (b.label != "Application", b.node_id))


def _recommendations(ctx: AnalyticsContext, plan: _Plan, contained: list[str], protected: set[str]) -> list[str]:
    g = ctx.graph
    recs: list[str] = list(plan.recommendations)
    for sid in g.nodes_by_label("Storyline"):
        if sid not in contained and sid not in [s for s in g.nodes_by_label("Storyline")]:
            continue
        for ev in as_list(g.get(sid, "event_ids")):
            if str(g.get(ev, "event_name") or "") == "GetSecretValue":
                for t, _ in g.out_edges(ev, ("TARGETED",)):
                    recs.append(f"rotate secret {ctx.short(t)}: its value was read by the attacker ({ev})")
            if str(g.get(ev, "event_name") or "") == "GetObject" and int(g.get(ev, "count") or 0) > 100:
                for t, _ in g.out_edges(ev, ("TARGETED",)):
                    recs.append(f"treat {ctx.short(t)} as exfiltrated ({g.get(ev, 'count')} objects, {g.get(ev, 'bytes') or 'unknown'} bytes): start breach assessment")
        for cred in as_list(g.get(sid, "credential_ids")):
            if str(g.get(cred, "credential_type") or "") == "ssh_private_key":
                for principal, _ in g.out_edges(cred, ("CREDENTIAL_FOR",)):
                    recs.append(f"replace the authorized key for {ctx.short(principal)} ({ctx.short(cred)} was stolen) and review the user's workstation")
        for ip in as_list(g.get(sid, "ip_ids")):
            if ip not in plan.blocked_ips:
                recs.append(f"block attacker egress {ctx.short(ip)} at the perimeter and in cloud IAM conditions")
    if "isolate_endpoint" in plan.actions and plan.isolated:
        recs.append("preserve forensic state of the isolated host (memory, shell history, IMDS access logs) before rebuilding")
    if not recs:
        recs.append("no additional actions required beyond the simulated ones")
    return recs


def _fragment(ctx: AnalyticsContext, plan: _Plan, contained: list[str], story_nodes: list[str], protected: list[str], breaks: list[BreakItem]) -> GraphFragment:
    g = ctx.graph
    nodes = list(plan.targets) + story_nodes + protected + [b.node_id for b in breaks] + contained
    cut_edges: set[str] = set()
    for u, v, d in g.G.edges(data=True):
        et = d.get("type")
        if et in ("ON_ENDPOINT", "ON_RESOURCE"):
            continue
        if (u in plan.isolated or v in plan.isolated) and et in sem.TRAVERSED_EDGE_TYPES:
            cut_edges.add(f"{u}|{et}|{v}")
        if et == "CREDENTIAL_FOR" and u in plan.revoked_credentials:
            cut_edges.add(f"{u}|{et}|{v}")
        if et == "CAN_ASSUME" and v in plan.trust_cut_roles:
            cut_edges.add(f"{u}|{et}|{v}")
    frag = g.fragment(nodes, highlight_ids=set(plan.targets) | set(protected), highlight_edge_ids=cut_edges, focus=list(plan.targets), layout_hint="path", max_nodes=150)
    frag.meta = {"cut_edges": sorted(cut_edges), "actions": plan.actions}
    return frag
