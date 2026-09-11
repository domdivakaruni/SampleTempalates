"""EDR incident grouping (the flat-view console grouping, not Throughline's correlation).

The three scripted incidents group the storyline alerts exactly as docs/04 says the EDR console would --
crucially it does **not** connect WKS-3391 to bas-01 (different hosts/users). Plus a background of incidents
grouping general EDR detections, for ~45 incidents total. Throughline's storyline correlation (analytics
stage) is what later stitches these into a single kill chain.
"""
from __future__ import annotations

from throughline.simulator.common import at, rng
from throughline.simulator.events.ctx import SEV_RANK, Ctx

_SEV_BY_RANK = {v: k for k, v in SEV_RANK.items()}


def _alert_records(ctx: Ctx) -> dict[str, dict]:
    return {rec["id"]: rec for rec in ctx.nodes if rec["label"] == "Alert"}


def _make_incident(ctx: Ctx, *, incident_id: str, member_ids: list[str], records: dict[str, dict],
                   description: str, status: str = "new") -> None:
    members = [records[m] for m in member_ids if m in records]
    if not members:
        return
    times = sorted(at(m["props"]["detected_at"]) for m in members)
    max_rank = max(SEV_RANK.get(m["props"]["vendor_severity"], 0) for m in members)
    hosts = list(dict.fromkeys(m["props"].get("hostname") for m in members if m["props"].get("hostname")))
    vendor_vid = incident_id.split(":")[-1]
    ctx.n(incident_id, "Incident", vendor_vid, {
        "vendor_severity": _SEV_BY_RANK[max_rank], "status": status, "start_time": times[0],
        "end_time": times[-1], "alert_count": len(members), "hosts": hosts, "description": description,
    }, source="falcon-sim", source_id=vendor_vid, first_seen=times[0], last_seen=times[-1])
    for m in members:
        ctx.e("PART_OF_INCIDENT", m["id"], incident_id, source="falcon-sim",
              first_seen=at(m["props"]["detected_at"]))
        m["props"]["vendor_incident_id"] = vendor_vid
        if isinstance(m["props"].get("raw"), dict) and "incident_id" in m["props"]["raw"]:
            m["props"]["raw"]["incident_id"] = vendor_vid


def generate_incidents(ctx: Ctx) -> int:
    records = _alert_records(ctx)
    # scripted storyline incidents (exactly as the EDR console groups them)
    _make_incident(ctx, incident_id="incident:falcon:inc-0091",
                   member_ids=[f"alert:falcon:ldt-a00{i}" for i in range(1, 7)], records=records,
                   description="Suspicious activity cluster on WKS-3391 (dwhitfield).")
    _make_incident(ctx, incident_id="incident:falcon:inc-0094",
                   member_ids=["alert:falcon:ldt-a007", "alert:falcon:ldt-a008x", "alert:falcon:ldt-a009"],
                   records=records, description="Interactive session and credential access on bas-01.")
    _make_incident(ctx, incident_id="incident:falcon:inc-0096",
                   member_ids=["alert:falcon:ldt-b002", "alert:falcon:ldt-b003"], records=records,
                   description="Web-facing exploitation activity on stmt-render-2a.")
    n_incidents = 3

    # background incidents grouping general EDR detections (not every detection lands in an incident)
    general = sorted(aid for aid in records if aid.startswith("alert:falcon:ldt-g"))
    r = rng("events.incidents.background")
    i = 0
    inc_seq = 200
    while i < len(general) and inc_seq <= 241:
        group_size = r.randint(2, 6)
        group = general[i:i + group_size]
        i += group_size
        if len(group) < 2:
            break
        _make_incident(ctx, incident_id=f"incident:falcon:inc-{inc_seq:04d}", member_ids=group,
                       records=records, description="Grouped endpoint detections on shared hosts.",
                       status=r.choice(["new", "new", "in_progress"]))
        inc_seq += 1
        n_incidents += 1
    return n_incidents
