"""The credential nodes that join endpoint theft to cloud use (the crux of storyline A).

Three credentials, created with the exact ids/times/status docs/04 section 2.1 specifies:

* ``CRED_SSH_KEY`` -- Dana's SSH private key, stolen on the workstation by QUILLDROP (alert a005).
* ``CRED_BASTION_KEY`` -- the bastion instance-role temporary key, lifted from IMDS (alert a009); this is
  what the cloud events a010-a012 later authenticate with.
* ``CRED_PROD_KEY`` -- the prod-reader temporary key minted by ``sts:AssumeRole`` (a012), derived from the
  bastion key; the cloud events a013-a016 authenticate with it.

``USED_CREDENTIAL`` edges from the cloud events are added in :mod:`cloudtrail`.
"""
from __future__ import annotations

from throughline.simulator import storyline_constants as S
from throughline.simulator.common import at
from throughline.simulator.events.ctx import Ctx


def add_ssh_key(ctx: Ctx, *, alert_id: str, quilldrop_proc: str) -> str:
    cid = S.CRED_SSH_KEY
    ctx.n(cid, "Credential", "svc-finops-sftp id_ed25519", {
        "credential_type": "ssh_private_key", "principal_id": S.SVC_FINOPS_SFTP,
        "issued_at": None, "expires_at": None, "status": "valid", "derived_from": None,
    }, source="falcon-sim", source_id="dwhitfield-id_ed25519")
    ctx.e("CREDENTIAL_FOR", cid, S.SVC_FINOPS_SFTP, source="falcon-sim")
    ctx.e("STOLEN_BY", cid, alert_id, {"method": "file_read"}, source="falcon-sim")
    ctx.e("STOLEN_BY", cid, quilldrop_proc, {"method": "file_read"}, source="falcon-sim")
    ctx.e("ACCESSED_CREDENTIAL", quilldrop_proc, cid, {"method": "file_read"}, source="falcon-sim")
    return cid


def add_bastion_key(ctx: Ctx, *, alert_id: str, curl_proc: str) -> str:
    cid = S.CRED_BASTION_KEY
    issued, expires = at("2026-09-10T02:11:45Z"), at("2026-09-10T08:11:45Z")
    ctx.n(cid, "Credential", S.CRED_BASTION_KEY_ID, {
        "credential_type": "aws_temporary_key", "principal_id": S.BASTION_ROLE,
        "issued_at": issued, "expires_at": expires, "status": "expired", "derived_from": None,
    }, source="falcon-sim", source_id=S.CRED_BASTION_KEY_ID, first_seen=issued, last_seen=expires)
    ctx.e("CREDENTIAL_FOR", cid, S.BASTION_ROLE, source="falcon-sim", first_seen=issued)
    ctx.e("STOLEN_BY", cid, alert_id, {"method": "imds"}, source="falcon-sim", first_seen=issued)
    ctx.e("STOLEN_BY", cid, curl_proc, {"method": "imds"}, source="falcon-sim", first_seen=issued)
    ctx.e("ACCESSED_CREDENTIAL", curl_proc, cid, {"method": "imds"}, source="falcon-sim", first_seen=issued)
    return cid


def add_prod_key(ctx: Ctx) -> str:
    cid = S.CRED_PROD_KEY
    issued, expires = at("2026-09-10T02:24:15Z"), at("2026-09-10T03:24:15Z")
    ctx.n(cid, "Credential", S.CRED_PROD_KEY_ID, {
        "credential_type": "aws_temporary_key", "principal_id": S.PROD_READER_ROLE,
        "issued_at": issued, "expires_at": expires, "status": "expired", "derived_from": S.CRED_BASTION_KEY,
    }, source="cloudtrail-sim", source_id=S.CRED_PROD_KEY_ID, first_seen=issued, last_seen=expires)
    ctx.e("CREDENTIAL_FOR", cid, S.PROD_READER_ROLE, source="cloudtrail-sim", first_seen=issued)
    ctx.e("DERIVED_FROM", cid, S.CRED_BASTION_KEY, {"via": "assume_role"}, source="cloudtrail-sim", first_seen=issued)
    return cid
