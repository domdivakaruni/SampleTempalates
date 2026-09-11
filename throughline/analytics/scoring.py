"""Contextual risk scoring (docs/01 section 5.2 formula with the rails from docs/06 section 3.2).

Six normalized factors, each with evidence ids and a reason string::

    context = 0.15 E + 0.20 P + 0.25 D + 0.20 T + 0.20 C
    raw     = 100 (0.30 S + 0.70 context)

Rails (weights.yaml): attack-path floor 90 (+2 credential-pivot bonus) for alerts on a storyline whose cloud
activity *confirmed* reach of a crown jewel; TI booster floor 80 for assets under active / mass exploitation by
an actor targeting our sector; no-context ceiling 25; benign-context ceilings (change ticket, known scanner, VPN
egress, blocked pre-execution, test file, exploit attempt against a non-vulnerable target).

The scorer reads everything from the graph (post-enrichment edges and props) so a request-time explanation is
identical to the build-time score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from throughline.analytics import semantics as sem
from throughline.analytics.context import AnalyticsContext, Reach, as_dict, as_list
from throughline.graph.context_graph import edge_id
from throughline.models import RiskBreakdown, RiskFactor, band_for_score

WEIGHTS_PATH = Path(__file__).with_name("weights.yaml")


@lru_cache(maxsize=1)
def load_weights() -> dict[str, Any]:
    with WEIGHTS_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


@dataclass
class Explanation:
    kind: str
    reason: str
    cap: int
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class ScoreResult:
    breakdown: RiskBreakdown
    reaches_crown_jewel: bool
    on_attack_path: bool
    pivot: bool
    storyline_id: str | None
    ti_actor_ids: list[str]
    ioc_match_count: int
    crown_jewels: list[str]
    benign: list[Explanation]

    @property
    def score(self) -> int:
        return self.breakdown.contextual_score


@dataclass
class _StorylineInfo:
    id: str
    confirmed: bool
    members: int
    stage_count: int
    crown_jewels: list[str]
    actor_id: str | None
    relevance: float
    privilege: float = 0.0
    privilege_evidence: list[str] = field(default_factory=list)
    data: float = 0.0
    data_evidence: list[str] = field(default_factory=list)
    data_reason: str = ""


class Scorer:
    """Scores alerts (and assets) over an AnalyticsContext with per-storyline caches."""

    def __init__(self, ctx: AnalyticsContext, weights: dict[str, Any] | None = None) -> None:
        self.ctx = ctx
        self.w = weights or load_weights()
        self._storylines: dict[str, _StorylineInfo] = {}
        self._internet_path: dict[str, bool] | None = None

    # ------------------------------------------------------------------ public

    def score_alert(self, alert_id: str) -> ScoreResult:
        ctx, g, w = self.ctx, self.ctx.graph, self.w
        attrs = g.node(alert_id) or {}
        anchor = ctx.anchor_of(alert_id)
        asset = ctx.vm_or_self(anchor) if anchor else None
        story = self._storyline_of(alert_id)

        s_val, s_factor = self._severity(alert_id, attrs)
        e_val, e_factor = self._exposure(alert_id, anchor, asset)
        reach = ctx.reach(anchor, int(w["privilege"]["reach_depth"]), "access") if anchor else None
        p_val, p_factor, crown = self._privilege(anchor, reach, story)
        d_val, d_factor = self._data(anchor, reach, story)
        t_val, t_factor, actor_ids, ioc_count, exploited_sector = self._threat_intel(alert_id, attrs, asset, story)
        c_val, c_factor, pivot = self._correlation(alert_id, attrs, anchor, story)

        fw = w["factor_weights"]
        context = (
            fw["exposure"] * e_val + fw["privilege"] * p_val + fw["data"] * d_val
            + fw["threat_intel"] * t_val + fw["correlation"] * c_val
        )
        raw = 100.0 * (w["severity_weight"] * s_val + w["context_weight"] * context)
        factors = [s_factor, e_factor, p_factor, d_factor, t_factor, c_factor]

        rails: list[str] = []
        benign = self.benign_explanations(alert_id, attrs, anchor, asset, ioc_count)
        final = raw
        r = w["rails"]
        if benign:
            cap = min(b.cap for b in benign)
            for b in benign:
                rails.append(f"benign_ceiling:{b.kind}:{b.cap}")
            final = min(final, float(cap))
        else:
            floored = False
            if story is not None and story.confirmed:
                final = max(final, float(r["attack_path_floor"]))
                rails.append(f"attack_path_floor:{r['attack_path_floor']}")
                floored = True
                if pivot:
                    final += float(r["credential_pivot_bonus"])
                    rails.append(f"credential_pivot_bonus:+{r['credential_pivot_bonus']}")
            elif exploited_sector and str(attrs.get("alert_type") or "detection") != "issue":
                # activity on an internet-exposed asset under active exploitation by a sector-targeting actor;
                # posture issues on such hosts are ranked by their real reach (and carry ti_exposure_score)
                final = max(final, float(r["ti_booster_floor"]))
                rails.append(f"ti_booster_floor:{r['ti_booster_floor']}")
                floored = True
            th = r["no_context_thresholds"]
            if not floored and d_val <= th["data"] and t_val < th["threat_intel"] and p_val < th["privilege"]:
                if final > r["no_context_ceiling"]:
                    rails.append(f"no_context_ceiling:{r['no_context_ceiling']}")
                final = min(final, float(r["no_context_ceiling"]))
        score = int(round(max(0.0, min(100.0, final))))

        story_cj = list(story.crown_jewels) if story else []
        reaches = bool(crown) or bool(story_cj)
        on_path = bool(story_cj) or (asset is not None and self._on_internet_path(asset)) or (
            anchor is not None and anchor != asset and self._on_internet_path(anchor)
        )
        reasons = self._reasons(attrs, story, crown, d_factor, t_factor, actor_ids, pivot, exploited_sector, benign, e_val, p_val)
        breakdown = RiskBreakdown(
            subject_id=alert_id,
            vendor_severity=attrs.get("vendor_severity"),
            vendor_severity_rank=attrs.get("vendor_severity_rank"),
            contextual_score=score,
            band=band_for_score(score),
            raw_score=round(raw, 2),
            factors=factors,
            rails=rails,
            reasons=reasons,
        )
        return ScoreResult(
            breakdown=breakdown, reaches_crown_jewel=reaches, on_attack_path=on_path, pivot=pivot,
            storyline_id=story.id if story else None, ti_actor_ids=actor_ids, ioc_match_count=ioc_count,
            crown_jewels=sorted(set(crown) | set(story_cj)), benign=benign,
        )

    def score_asset(self, asset_id: str) -> tuple[int, list[RiskFactor]]:
        """A contextual score for an asset without an alert (used by the TI exposure table)."""
        ctx, g, w = self.ctx, self.ctx.graph, self.w
        worst_sev = 0.0
        cves: list[str] = []
        for cve, _ in g.out_edges(asset_id, ("VULNERABLE_TO",)):
            cves.append(cve)
            worst_sev = max(worst_sev, w["severity"].get(str(g.get(cve, "severity") or "medium"), 0.5))
        s_factor = RiskFactor(key="severity", label="Vulnerability severity", value=worst_sev, weight=w["severity_weight"],
                              contribution=round(100 * w["severity_weight"] * worst_sev, 1),
                              reason=f"worst vulnerability severity on the asset ({len(cves)} CVEs)", evidence_ids=cves[:5])
        e_val, e_factor = self._exposure(asset_id, asset_id, asset_id)
        reach = ctx.reach(asset_id, int(w["privilege"]["reach_depth"]), "access")
        p_val, p_factor, _ = self._privilege(asset_id, reach, None)
        d_val, d_factor = self._data(asset_id, reach, None)
        t_val, t_factor, _, _, _ = self._threat_intel(asset_id, {}, asset_id, None)
        fw = w["factor_weights"]
        context = fw["exposure"] * e_val + fw["privilege"] * p_val + fw["data"] * d_val + fw["threat_intel"] * t_val
        raw = 100.0 * (w["severity_weight"] * worst_sev + w["context_weight"] * context)
        c_factor = RiskFactor(key="correlation", label="Incident correlation", value=0.0, weight=fw["correlation"], contribution=0.0, reason="no alert on this asset")
        return int(round(max(0.0, min(100.0, raw)))), [s_factor, e_factor, p_factor, d_factor, t_factor, c_factor]

    # ------------------------------------------------------------------ factors

    def _factor(self, key: str, label: str, value: float, reason: str, evidence: list[str]) -> RiskFactor:
        weight = self.w["factor_weights"].get(key, self.w["severity_weight"])
        scale = self.w["context_weight"] if key in self.w["factor_weights"] else 1.0
        return RiskFactor(
            key=key, label=label, value=round(value, 3), weight=weight,
            contribution=round(100 * scale * weight * value, 1), reason=reason,
            evidence_ids=list(dict.fromkeys(e for e in evidence if e)),
        )

    def _severity(self, alert_id: str, attrs: dict[str, Any]) -> tuple[float, RiskFactor]:
        sev = str(attrs.get("vendor_severity") or "medium").lower()
        val = float(self.w["severity"].get(sev, 0.5))
        return val, self._factor("severity", "Vendor severity", val, f"vendor severity {sev}", [alert_id])

    def _exposure(self, alert_id: str, anchor: str | None, asset: str | None) -> tuple[float, RiskFactor]:
        g, ew = self.ctx.graph, self.w["exposure"]
        if not anchor:
            return ew["unknown"], self._factor("exposure", "Exposure", ew["unknown"], "no anchor asset", [])
        a = g.node(asset or anchor) or {}
        label = a.get("label")
        evidence = [asset or anchor]
        exposes = [u for u, _ in g.in_edges(asset or anchor, ("EXPOSES",))]
        if exposes:
            evidence.append(edge_id(exposes[0], "EXPOSES", asset or anchor))
        if label in sem.COMPUTE_LABELS or label in ("LoadBalancer",):
            exposure = str(a.get("exposure") or "").lower()
            if exposure == "internet" or exposes:
                ports = ", ".join(str(p) for p in as_list((g.first_edge(exposes[0], asset or anchor, "EXPOSES") or {}).get("ports"))) if exposes else ""
                return ew["internet"], self._factor("exposure", "Exposure", ew["internet"], f"internet-exposed{(' on ' + ports) if ports else ''}", evidence)
            if a.get("public_ip") and exposure != "isolated":
                return ew["public_ip_restricted"], self._factor("exposure", "Exposure", ew["public_ip_restricted"], "public IP with restricted ingress", evidence)
            if exposure == "isolated":
                return ew["isolated"], self._factor("exposure", "Exposure", ew["isolated"], "isolated network placement", evidence)
            if label == "Endpoint":
                return ew["internal"], self._factor("exposure", "Exposure", ew["internal"], "internal endpoint (no cloud VM resolved)", evidence)
            return ew["internal"], self._factor("exposure", "Exposure", ew["internal"], "internal network placement", evidence)
        if label in sem.DATA_HOLDER_LABELS:
            if a.get("public") is True or exposes:
                return ew["internet"], self._factor("exposure", "Exposure", ew["internet"], "publicly readable data store", evidence)
            return ew["internal"], self._factor("exposure", "Exposure", ew["internal"], "private data store", evidence)
        if label == "SecurityGroup":
            if a.get("open_to_internet"):
                return ew["internet"], self._factor("exposure", "Exposure", ew["internet"], "security group open to the internet", evidence)
            return ew["internal"], self._factor("exposure", "Exposure", ew["internal"], "security group without internet rules", evidence)
        if label in sem.IDENTITY_LABELS:
            return ew["identity"], self._factor("exposure", "Exposure", ew["identity"], "identity-anchored alert (assumed internal)", evidence)
        return ew["unknown"], self._factor("exposure", "Exposure", ew["unknown"], "exposure unknown", evidence)

    def _privilege(self, anchor: str | None, reach: Reach | None, story: _StorylineInfo | None) -> tuple[float, RiskFactor, list[str]]:
        pw = self.w["privilege"]
        val, evidence, crown, parts = self._privilege_of_reach(reach) if reach else (0.0, [], [], [])
        reason = ", ".join(parts) if parts else "no identity or sensitive resource reachable from the asset"
        if story is not None:
            self._ensure_storyline_reach(story)
            if story.privilege > val:
                val = story.privilege
                evidence = list(story.privilege_evidence)
                reason = f"via storyline: {reason}" if parts else "via storyline: attacker demonstrably reached privileged identities"
        val = min(1.0, val)
        if val >= pw["admin"] and any(self.ctx.graph.get(e, "is_admin") for e in evidence):
            reason = "admin identity reachable; " + reason
        return val, self._factor("privilege", "Privilege reach", val, reason, evidence), crown

    def _privilege_of_reach(self, reach: Reach) -> tuple[float, list[str], list[str], list[str]]:
        g, pw = self.ctx.graph, self.w["privilege"]
        total = 0.0
        evidence: list[str] = []
        crown: list[str] = []
        n_ident = n_cj = n_secret = n_high = n_other = 0
        admin = False
        for nid in reach.ids():
            a = g.node(nid) or {}
            label = a.get("label")
            if sem.is_crown_jewel(a):
                crown.append(nid)
                if label == "IamRole":
                    admin = True
                    n_ident += 1
                else:
                    n_cj += 1
                total += pw["crown_jewel"]
                evidence.append(nid)
            elif label == "Secret":
                n_secret += 1
                total += pw["secret"]
                evidence.append(nid)
            elif label in sem.DATA_HOLDER_LABELS:
                if sem.sensitivity_rank(a) >= 3:
                    n_high += 1
                    total += pw["high_sensitivity_data"]
                else:
                    n_other += 1
                    total += pw["other_data"]
                evidence.append(nid)
            elif label in sem.IDENTITY_LABELS:
                n_ident += 1
                total += pw["identity"]
                if a.get("is_admin"):
                    admin = True
                evidence.append(nid)
        if admin:
            total = max(total, pw["admin"])
        parts = []
        if n_ident:
            parts.append(f"{n_ident} identit{'y' if n_ident == 1 else 'ies'}")
        if n_cj:
            parts.append(f"{n_cj} crown jewel{'s' if n_cj != 1 else ''}")
        if n_secret:
            parts.append(f"{n_secret} secret{'s' if n_secret != 1 else ''}")
        if n_high:
            parts.append(f"{n_high} high-sensitivity store{'s' if n_high != 1 else ''}")
        if n_other:
            parts.append(f"{n_other} other data store{'s' if n_other != 1 else ''}")
        if parts:
            parts = [f"reaches {', '.join(parts)} within {reach.depth} moves"]
        return min(1.0, total), evidence, sorted(crown), parts

    def _data(self, anchor: str | None, reach: Reach | None, story: _StorylineInfo | None) -> tuple[float, RiskFactor]:
        val, evidence, reason = self._data_of_reach(anchor, reach) if anchor else (0.0, [], "no data reachable")
        if story is not None:
            self._ensure_storyline_reach(story)
            if story.data > val:
                val, evidence, reason = story.data, list(story.data_evidence), f"via storyline: {story.data_reason}"
        return val, self._factor("data", "Data sensitivity reachable", val, reason, evidence)

    def _data_value(self, a: dict[str, Any]) -> tuple[float, str]:
        dw = self.w["data"]
        classes = sem.data_classes(a)
        if a.get("label") == "Secret":
            classes = classes or ["SECRETS"]
        if classes:
            best = max(classes, key=lambda c: dw["classes"].get(c, 0.0))
            return float(dw["classes"].get(best, 0.0)), best
        sens = str(a.get("sensitivity") or "none").lower()
        return float(dw["sensitivity"].get(sens, 0.0)), f"sensitivity {sens}"

    def _data_of_reach(self, anchor: str, reach: Reach | None) -> tuple[float, list[str], str]:
        g, dw = self.ctx.graph, self.w["data"]
        candidates: list[tuple[float, str, str]] = []
        a0 = g.node(anchor) or {}
        if sem.is_data_holder(a0):
            v, cls = self._data_value(a0)
            candidates.append((v, anchor, cls))
        if reach is not None:
            for nid, info in reach.nodes.items():
                if nid == anchor:
                    continue
                a = g.node(nid) or {}
                if not sem.is_data_holder(a):
                    continue
                v, cls = self._data_value(a)
                if info.access_level == "credential":
                    v *= dw["indirect_factor"]
                candidates.append((v, nid, cls))
        if not candidates:
            if sem.is_data_holder(a0):
                return 0.0, [anchor], "public data only"
            return 0.0, [], "no data store reachable from the asset"
        candidates.sort(key=lambda c: (-c[0], c[1]))
        best = candidates[0]
        if best[0] <= 0:
            return 0.0, [best[1]], "public data only"
        regulated = [(v, nid, cls) for v, nid, cls in candidates if cls in sem.REGULATED_CLASSES]
        top = regulated[:4] if regulated else candidates[:3]
        desc = ", ".join(f"{cls} ({self.ctx.short(nid)})" for _, nid, cls in top)
        return best[0], [nid for _, nid, _ in top], f"reaches {desc}"

    def _threat_intel(self, alert_id: str, attrs: dict[str, Any], asset: str | None, story: _StorylineInfo | None) -> tuple[float, RiskFactor, list[str], int, bool]:
        g, tw, rails = self.ctx.graph, self.w["threat_intel"], self.w["rails"]
        components: list[tuple[float, str, list[str]]] = []
        actor_ids: list[str] = []
        evidence: list[str] = []
        ioc_count = 0
        # IOC matches recorded on the alert itself
        for ind, d in g.out_edges(alert_id, ("MATCHES_IOC",)):
            ioc_count += 1
            conf = float(d.get("confidence") or g.get(ind, "confidence") or 0.5)
            actor = self._actor_of_indicator(ind)
            rel = float(g.get(actor, "sector_targeting_relevance") or 0.0) if actor else 0.0
            val = conf * (tw["ioc_base"] + (1 - tw["ioc_base"]) * rel)
            name = self.ctx.name(actor) if actor else "unattributed"
            components.append((val, f"matches {name} IOC {g.get(ind, 'value')} (confidence {conf:.2f})", [ind] + ([actor] if actor else [])))
            if actor and actor not in actor_ids:
                actor_ids.append(actor)
        # attribution edges (ioc or ttp)
        for who, d in g.out_edges(alert_id, ("ATTRIBUTED_TO",)):
            if g.label_of(who) == "ThreatActor" and who not in actor_ids:
                actor_ids.append(who)
            if d.get("basis") == "ttp":
                rel = float(g.get(who, "sector_targeting_relevance") or 0.0)
                components.append((tw["ttp_overlap"] * max(rel, 0.25), f"TTP overlap with {self.ctx.name(who)} ({float(d.get('confidence') or 0):.2f})", [who]))
        # exploitation status on the asset's vulnerabilities
        exploited_sector = False
        cves: list[str] = []
        if asset:
            cves.extend(c for c, _ in g.out_edges(asset, ("VULNERABLE_TO",)))
        cves.extend(self.ctx.alert_involves(alert_id, {"Vulnerability"}))
        for cve in dict.fromkeys(cves):
            status = str(g.get(cve, "exploitation_status") or "none")
            rel = float(g.get(cve, "sector_targeting_relevance") or 0.0)
            interest = [a for a in as_list(g.get(cve, "actor_interest")) if a in g]
            if status in sem.EXPLOITED_STATUSES:
                if rel >= rails["ti_booster_min_relevance"]:
                    exploited_sector = True
                    val = tw["exploited_sector"]
                else:
                    val = tw["exploited_other"]
                names = ", ".join(self.ctx.name(a) for a in interest[:2]) or "unattributed"
                components.append((val, f"{g.get(cve, 'cve_id') or cve} under {status.replace('_', ' ')} by {names} (sector relevance {rel:.2f})", [cve] + interest[:2]))
                for a in interest:
                    if a not in actor_ids:
                        actor_ids.append(a)
            elif status == "poc_public":
                components.append((tw["poc_public"], f"{g.get(cve, 'cve_id') or cve} has a public exploit", [cve]))
            elif g.get(cve, "kev"):
                components.append((tw["kev_only"], f"{g.get(cve, 'cve_id') or cve} is a known exploited vulnerability", [cve]))
        # storyline attribution
        if story is not None and story.actor_id:
            val = tw["storyline_attribution_sector"] if story.relevance >= rails["ti_booster_min_relevance"] else tw["storyline_attribution_other"]
            components.append((val, f"storyline attributed to {self.ctx.name(story.actor_id)} (sector relevance {story.relevance:.2f})", [story.actor_id, story.id]))
            if story.actor_id not in actor_ids:
                actor_ids.append(story.actor_id)
        if not components:
            return 0.0, self._factor("threat_intel", "Threat-intel relevance", 0.0, "no IOC match, no exploited vulnerability, no actor interest", []), [], 0, False
        components.sort(key=lambda c: -c[0])
        best = components[0]
        for c in components[:3]:
            evidence.extend(c[2])
        reason = best[1] if len(components) == 1 else f"{best[1]}; +{len(components) - 1} more signal{'s' if len(components) > 2 else ''}"
        return min(1.0, best[0]), self._factor("threat_intel", "Threat-intel relevance", min(1.0, best[0]), reason, evidence), actor_ids, ioc_count, exploited_sector

    def _actor_of_indicator(self, ind: str) -> str | None:
        g = self.ctx.graph
        actor = g.get(ind, "actor_id")
        if actor and actor in g:
            return str(actor)
        for tgt, _ in g.out_edges(ind, ("INDICATES",)):
            label = g.label_of(tgt)
            if label == "ThreatActor":
                return tgt
            if label == "Campaign":
                a = g.get(tgt, "actor_id")
                if a and a in g:
                    return str(a)
                for who, _ in g.out_edges(tgt, ("ATTRIBUTED_TO",)):
                    if g.label_of(who) == "ThreatActor":
                        return who
        return None

    def _correlation(self, alert_id: str, attrs: dict[str, Any], anchor: str | None, story: _StorylineInfo | None) -> tuple[float, RiskFactor, bool]:
        cw = self.w["correlation"]
        pivot, pivot_evidence = self._credential_pivot(alert_id)
        if story is not None:
            if story.confirmed:
                val = cw["confirmed_path"]
                reason = f"on confirmed {story.stage_count}-stage storyline reaching {len(story.crown_jewels)} crown jewel{'s' if len(story.crown_jewels) != 1 else ''}"
            else:
                stage = sem.alert_stage(attrs)
                val = min(cw["member_cap"], cw["per_member"] * max(0, story.members - 1)) + cw["per_stage"] * stage
                reason = f"on {story.stage_count}-stage storyline with {story.members} correlated members (potential crown-jewel reach)" if story.crown_jewels else f"on storyline with {story.members} correlated members"
            evidence = [story.id] + pivot_evidence
            if pivot:
                reason += "; credential stolen here was reused in cloud API calls"
            return min(1.0, val), self._factor("correlation", "Incident correlation", min(1.0, val), reason, evidence), pivot
        related = self._related_alerts(alert_id, anchor)
        if related:
            val = min(cw["related_cap"], cw["per_related_alert"] * len(related))
            return val, self._factor("correlation", "Incident correlation", val, f"{len(related)} other alert{'s' if len(related) != 1 else ''} on the same asset within 24h", related[:5]), pivot
        return 0.0, self._factor("correlation", "Incident correlation", 0.0, "no correlated alerts", []), pivot

    def _related_alerts(self, alert_id: str, anchor: str | None) -> list[str]:
        if not anchor:
            return []
        t0 = self.ctx.alert_time(alert_id)
        out = []
        for other in self.ctx.alerts_on(anchor):
            if other == alert_id:
                continue
            t1 = self.ctx.alert_time(other)
            if t0 is None or t1 is None or abs(t0 - t1) <= timedelta(hours=24):
                if not self.is_benign(other):
                    out.append(other)
        return out

    def _credential_pivot(self, alert_id: str) -> tuple[bool, list[str]]:
        """True when a credential stolen by this alert (or a credential derived from it) was used in cloud events."""
        g = self.ctx.graph
        evidence: list[str] = []
        creds = [c for c, _ in g.in_edges(alert_id, ("STOLEN_BY",))]
        seen = set(creds)
        queue = list(creds)
        while queue:
            c = queue.pop()
            uses = [ev for ev, _ in g.in_edges(c, ("USED_CREDENTIAL",))]
            if uses:
                evidence.append(c)
                evidence.extend(sorted(uses)[:3])
            for child, _ in g.in_edges(c, ("DERIVED_FROM",)):
                if child not in seen:
                    seen.add(child)
                    queue.append(child)
        return bool(evidence), evidence

    # ------------------------------------------------------------------ storyline helpers

    def _storyline_of(self, alert_id: str) -> _StorylineInfo | None:
        g = self.ctx.graph
        sid = None
        for s, _ in g.out_edges(alert_id, ("IN_STORYLINE",)):
            sid = s
            break
        if sid is None:
            sid = g.get(alert_id, "storyline_id")
            if not sid or sid not in g:
                return None
        info = self._storylines.get(sid)
        if info is None:
            a = g.node(sid) or {}
            actor = a.get("actor_id") or None
            rel = float(g.get(actor, "sector_targeting_relevance") or 0.0) if actor and actor in g else 0.0
            members = int(a.get("member_count") or len(as_list(a.get("alert_ids"))) + len(as_list(a.get("event_ids"))))
            info = _StorylineInfo(
                id=sid, confirmed=bool(a.get("confirmed_reach")), members=members,
                stage_count=int(a.get("stage_count") or 0), crown_jewels=[c for c in as_list(a.get("crown_jewels_reached")) if c in g],
                actor_id=actor if actor in g else None, relevance=rel,
            )
            self._storylines[sid] = info
        return info

    def _ensure_storyline_reach(self, story: _StorylineInfo) -> None:
        if story.privilege_evidence or story.data_evidence or story.privilege > 0 or story.data > 0:
            return
        g = self.ctx.graph
        depth = int(self.w["privilege"]["reach_depth"])
        best_p, best_d = 0.0, 0.0
        for aid in as_list(g.get(story.id, "alert_ids")):
            anchor = self.ctx.anchor_of(aid) if aid in g else None
            if not anchor:
                continue
            reach = self.ctx.reach(anchor, depth, "access")
            p, ev, _, _ = self._privilege_of_reach(reach)
            if p > best_p:
                best_p, story.privilege_evidence = p, ev
            d, dev, reason = self._data_of_reach(anchor, reach)
            if d > best_d:
                best_d, story.data_evidence, story.data_reason = d, dev, reason
        # crown jewels confirmed by cloud events count as reached data even when no anchor chain exists
        for cj in story.crown_jewels:
            v, cls = self._data_value(g.node(cj) or {})
            if v > best_d:
                best_d, story.data_evidence, story.data_reason = v, [cj], f"reaches {cls} ({self.ctx.short(cj)})"
        story.privilege = min(1.0, best_p)
        story.data = best_d

    # ------------------------------------------------------------------ attack path membership

    def _on_internet_path(self, node_id: str) -> bool:
        if self._internet_path is None:
            self._internet_path = self._compute_internet_paths()
        return self._internet_path.get(node_id, False)

    def _compute_internet_paths(self) -> dict[str, bool]:
        import networkx as nx

        D = self.ctx.digraph("full")
        if sem.INTERNET_ID not in D:
            return {}
        fwd = nx.single_source_shortest_path_length(D, sem.INTERNET_ID, cutoff=8)
        R = D.reverse(copy=False)
        bwd: dict[str, int] = {}
        for cj in self.ctx.crown_jewels:
            if cj not in R:
                continue
            for n, d in nx.single_source_shortest_path_length(R, cj, cutoff=8).items():
                if n not in bwd or d < bwd[n]:
                    bwd[n] = d
        return {n: (fwd[n] + bwd.get(n, 99)) <= 8 for n in fwd}

    # ------------------------------------------------------------------ benign explanations

    def is_benign(self, alert_id: str) -> bool:
        attrs = self.ctx.graph.node(alert_id) or {}
        anchor = self.ctx.anchor_of(alert_id)
        asset = self.ctx.vm_or_self(anchor) if anchor else None
        return bool(self.benign_explanations(alert_id, attrs, anchor, asset, None))

    def benign_explanations(self, alert_id: str, attrs: dict[str, Any], anchor: str | None, asset: str | None, ioc_count: int | None) -> list[Explanation]:
        g, caps = self.ctx.graph, self.w["rails"]["benign_ceilings"]
        out: list[Explanation] = []
        ticket = attrs.get("change_ticket")
        if ticket:
            out.append(Explanation("change_ticket", f"inside approved change window {ticket}", caps["change_ticket"], [alert_id]))
        involved_ips = self.ctx.alert_involves(alert_id, {"IpAddress"})
        addrs = {str(g.get(ip, "address") or "") for ip in involved_ips}
        src_ip = attrs.get("source_ip")
        if src_ip:
            addrs.add(str(src_ip))
        scanner_hits = sorted(a for a in addrs if a in self.ctx.scanner_ips)
        if scanner_hits:
            ev = [ip for ip in involved_ips if str(g.get(ip, "address")) in self.ctx.scanner_ips]
            ev += [vm for a in scanner_hits for vm in self.ctx.vms_by_ip.get(a, [])]
            out.append(Explanation("known_scanner", f"source {', '.join(scanner_hits)} is the internal vulnerability scanner", caps["known_scanner"], [alert_id] + ev))
        if str(attrs.get("source_system") or "") == "okta" or str(attrs.get("alert_type") or "") == "identity":
            vpn_hits = sorted(a for a in addrs if a in self.ctx.vpn_ips)
            if vpn_hits:
                ev = [ip for ip in involved_ips if str(g.get(ip, "address")) in self.ctx.vpn_ips]
                mfa = attrs.get("mfa_satisfied") or str(as_dict(attrs.get("raw")).get("mfa") or "").lower() == "satisfied"
                out.append(Explanation("vpn_egress", f"login egress {', '.join(vpn_hits)} is the corporate VPN{'; MFA satisfied' if mfa else ''}", caps["vpn_egress"], [alert_id] + ev))
        title = str(attrs.get("title") or "").lower()
        action = str(attrs.get("action_taken") or attrs.get("disposition") or "").lower()
        raw = as_dict(attrs.get("raw"))
        raw_action = str(raw.get("action_taken") or raw.get("action") or raw.get("disposition") or "").lower()
        blocked = bool(attrs.get("blocked") or attrs.get("prevented") or raw.get("blocked") or raw.get("prevented"))
        if blocked or any(w in action or w in raw_action for w in ("quarantin", "blocked", "prevent", "killed")) or "blocked pre-execution" in title or "quarantined" in title:
            out.append(Explanation("blocked_pre_execution", "blocked / quarantined before execution", caps["blocked_pre_execution"], [alert_id]))
        files = self.ctx.alert_involves(alert_id, {"File"})
        if "eicar" in title or any("eicar" in str(g.get(f, "file_name") or g.get(f, "malware_family") or "").lower() for f in files):
            out.append(Explanation("test_file", "EICAR anti-virus test file", caps["test_file"], [alert_id] + files))
        if str(attrs.get("alert_type") or "") == "network" and attrs.get("source_system") in ("waf", "ids") and not out:
            if ioc_count is None:
                ioc_count = len(g.out_edges(alert_id, ("MATCHES_IOC",)))
            if ioc_count == 0 and asset is not None and not self.ctx.sem.asset_exploitable(asset) and not any(
                self.ctx.sem.asset_exploitable(v) for v, _ in g.out_edges(asset, ("ROUTES_TO",))
            ):
                out.append(Explanation("unmatched_exploit_attempt", "exploit pattern against a target with no matching vulnerability and no IOC match", caps["unmatched_exploit_attempt"], [alert_id, asset]))
        return out

    # ------------------------------------------------------------------ reasons

    def _reasons(self, attrs: dict[str, Any], story: _StorylineInfo | None, crown: list[str], d_factor: RiskFactor, t_factor: RiskFactor,
                 actor_ids: list[str], pivot: bool, exploited_sector: bool, benign: list[Explanation], e_val: float, p_val: float) -> list[str]:
        g = self.ctx.graph
        chips: list[str] = []
        for b in benign:
            if b.kind == "change_ticket":
                chips.append(f"change ticket {attrs.get('change_ticket')}")
            elif b.kind == "known_scanner":
                chips.append("internal scanner")
            elif b.kind == "vpn_egress":
                chips.append("corporate VPN egress")
            elif b.kind == "blocked_pre_execution":
                chips.append("blocked pre-execution")
            elif b.kind == "test_file":
                chips.append("EICAR test file")
            elif b.kind == "unmatched_exploit_attempt":
                chips.append("target not vulnerable")
        jewels = list(dict.fromkeys(crown + (story.crown_jewels if story else [])))
        regulated = [j for j in jewels if sem.is_regulated(g.node(j))]
        if regulated:
            j = regulated[0]
            cls = "/".join(sem.data_classes(g.node(j)))
            chips.append(f"reaches {cls} ({self.ctx.short(j)})")
        elif jewels:
            chips.append(f"reaches crown jewel ({self.ctx.short(jewels[0])})")
        elif d_factor.value >= 0.7:
            chips.append("reaches sensitive data")
        if pivot:
            chips.append("credential reused in cloud")
        if story is not None:
            chips.append(f"on {story.stage_count}-stage storyline" if story.stage_count else "on storyline")
        for a in actor_ids[:2]:
            name = self.ctx.name(a)
            if any(e.startswith("ioc:") for e in t_factor.evidence_ids):
                chips.append(f"matches {name} IOC")
            elif story is not None and story.actor_id == a:
                chips.append(f"attributed to {name}")
        if exploited_sector:
            chips.append("internet-exposed + mass-exploited CVE" if e_val >= 1.0 else "actively exploited CVE")
        if not benign and not jewels and d_factor.value == 0 and t_factor.value < 0.1 and p_val < 0.2:
            anchor_label = attrs.get("entity_label")
            if anchor_label in ("StorageBucket", "Database") and "public data only" in d_factor.reason:
                chips.append("public data only")
            chips.append("no privilege reach")
            chips.append("no actor interest")
            if str(attrs.get("entity_label") or "") in ("Endpoint", "VirtualMachine") and e_val <= 0.1:
                chips.append("isolated dev asset")
        return list(dict.fromkeys(chips))[:6]
