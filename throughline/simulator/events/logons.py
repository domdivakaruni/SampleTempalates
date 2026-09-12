"""``LOGGED_ON`` edges: the baseline that makes the storyline's anomalous logon stand out.

* Dana's daily interactive logons to WKS-3391.
* The legitimate daily 03:00 **non-interactive** SFTP logons of ``svc-finops-sftp`` to bas-01 from
  ``10.40.12.77`` over the previous 30 days (this is the "SFTP-only account" baseline).
* The **anomalous interactive SSH** logon at A7 (``logon_type: ssh``, 2026-09-10T02:05:17Z) -- the event the
  analytics layer turns into ``LATERAL_MOVEMENT_TO``.
* mreyes / pkaur logons, and a background of ~3,000 fleet logons.

Represented as edges only (the ``LogonSession`` node is optional per docs/03 section 3.5).
"""
from __future__ import annotations

from datetime import timedelta

from throughline.simulator import storyline_constants as S
from throughline.simulator.common import NOW, rng, stable_hex, ts
from throughline.simulator.events.ctx import Ctx

# the A7 anomalous SSH logon (also referenced by storyline_a for alert ldt-a007)
SSH_LOGON_TIME = "2026-09-10T02:05:17Z"


def _logged_on(ctx: Ctx, principal_id: str, endpoint_id: str, *, logon_type: str, logon_time: str,
               source_ip: str, session_id: str) -> None:
    ctx.e("LOGGED_ON", principal_id, endpoint_id, {
        "logon_type": logon_type, "logon_time": logon_time, "source_ip": source_ip, "session_id": session_id,
    }, source="falcon-sim", first_seen=logon_time, last_seen=logon_time)


def add_storyline_logons(ctx: Ctx) -> None:
    """Dana's interactive baseline, the SFTP baseline, and the anomalous A7 SSH logon."""
    # Dana's weekday interactive logons to her workstation over the previous 30 days
    for d in range(1, 31):
        day = NOW - timedelta(days=d)
        if day.weekday() >= 5:  # skip weekends for the interactive baseline
            continue
        t = ts(day.replace(hour=8, minute=52, second=(d * 7) % 60))
        _logged_on(ctx, S.USER_DANA, S.WKS_DANA, logon_type="interactive", logon_time=t,
                   source_ip=S.WKS_DANA_IP, session_id=stable_hex("dana-int", d, length=12))

    # svc-finops-sftp daily 03:00 non-interactive SFTP to bas-01 from Dana's workstation egress
    for d in range(1, 31):
        day = NOW - timedelta(days=d)
        t = ts(day.replace(hour=3, minute=0, second=0))
        _logged_on(ctx, S.SVC_FINOPS_SFTP, S.EP_BASTION, logon_type="network", logon_time=t,
                   source_ip=S.WKS_DANA_IP, session_id=stable_hex("sftp", d, length=12))

    # THE anomaly: interactive SSH as the SFTP-only account (A7)
    _logged_on(ctx, S.SVC_FINOPS_SFTP, S.EP_BASTION, logon_type="ssh", logon_time=SSH_LOGON_TIME,
               source_ip=S.WKS_DANA_IP, session_id=stable_hex("ssh-anomaly", length=12))

    # mreyes: his own workstation, and the PsExec source->fileshare service logon (change window)
    _logged_on(ctx, S.USER_MREYES, S.EP_MREYES, logon_type="interactive",
               logon_time="2026-09-11T00:58:00Z", source_ip="10.40.9.21", session_id=stable_hex("mreyes-int", length=12))
    _logged_on(ctx, S.USER_MREYES, S.EP_FILESHARE, logon_type="network",
               logon_time="2026-09-11T01:12:00Z", source_ip="10.40.9.21", session_id=stable_hex("mreyes-psexec", length=12))
    # pkaur interactive to her workstation (the impossible-travel is an Okta identity event, not a host logon)
    _logged_on(ctx, S.USER_PKAUR, S.EP_PKAUR, logon_type="interactive",
               logon_time="2026-09-11T07:04:00Z", source_ip="10.40.7.5", session_id=stable_hex("pkaur-int", length=12))


def add_background_logons(ctx: Ctx, n: int) -> int:
    """A background of ~n fleet logons.

    Every principal is an existing inventory id (a workstation's primary user, or a random human user for
    server logons) so the edges resolve; ``svc-finops-sftp`` also contributes ordinary service logons.
    """
    r = rng("events.logons.background")
    workstations = [w for w in ctx.inv.workstations() if w.get("primary_user_id")]
    servers = ctx.inv.servers()
    user_ids = [u["id"] for u in ctx.inv.users]
    if not workstations and not user_ids:
        return 0
    count = 0
    for i in range(n):
        day = NOW - timedelta(days=r.randint(1, 30), hours=r.randint(0, 10), minutes=r.randint(0, 59))
        if servers and user_ids and r.random() < 0.18:
            ep = r.choice(servers)
            principal = r.choice(user_ids)
            ltype = r.choice(["network", "remote_interactive", "network"])
            src = f"10.{r.randint(10, 60)}.{r.randint(0, 250)}.{r.randint(2, 250)}"
        elif workstations:
            ep = r.choice(workstations)
            principal = ep["primary_user_id"]
            ltype = r.choice(["interactive", "interactive", "remote_interactive"])
            src = ep.get("private_ip") or "10.40.0.2"
        else:
            continue
        _logged_on(ctx, principal, ep["id"], logon_type=ltype, logon_time=ts(day), source_ip=src,
                   session_id=stable_hex("bg-logon", i, length=12))
        count += 1
    return count
