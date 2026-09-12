"""``CloudEvent`` nodes: the cloud side of the credential join, plus benign background API activity.

The storyline events a010-a016 are produced with the exact ids/times/names/keys/success/error/count from
``CLOUDEVENTS_A`` (a014 carries ``bytes = EXFIL_BYTES``), all from ``ATTACKER_EGRESS_IP`` with the scripted
``aws-cli`` user agent and ``anomalous: true`` with reasons. Their edges wire the cloud activity back to the
stolen credentials (``USED_CREDENTIAL``), the acting roles (``PERFORMED_BY`` / ``ASSUMED``), the targeted
crown jewels (``TARGETED``) and the source ip (``FROM_IP``). ~2,500 aggregated background events by fleet
roles from AWS-internal / VPN IPs carry ``anomalous: false``.
"""
from __future__ import annotations

from datetime import timedelta

from throughline.simulator import storyline_constants as S
from throughline.simulator.common import NOW, at, rng, stable_hex, ts
from throughline.simulator.events.ctx import Ctx
from throughline.simulator.events.network import ip_node

USER_AGENT = "aws-cli/2.17.0 Python/3.11.9 Linux/6.1 exe/x86_64.ubuntu.22"

_EVENT_SOURCE_UA = [
    "aws-cli/2.15.0 Python/3.11 Linux/5.15 exe/x86_64",
    "Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 os/linux md/arch#x86_64 lang/python#3.11",
    "aws-sdk-go/1.51.0 (go1.22; linux; amd64)",
    "console.amazonaws.com",
    "cloudformation.amazonaws.com",
]

# benign background event_name -> event_source
_BG_EVENTS: dict[str, str] = {
    "DescribeInstances": "ec2.amazonaws.com", "DescribeSecurityGroups": "ec2.amazonaws.com",
    "DescribeVolumes": "ec2.amazonaws.com", "ListBucket": "s3.amazonaws.com", "GetObject": "s3.amazonaws.com",
    "PutObject": "s3.amazonaws.com", "ListObjectsV2": "s3.amazonaws.com", "HeadObject": "s3.amazonaws.com",
    "AssumeRole": "sts.amazonaws.com", "GetCallerIdentity": "sts.amazonaws.com",
    "DescribeDBInstances": "rds.amazonaws.com", "GetSecretValue": "secretsmanager.amazonaws.com",
    "CreateLogStream": "logs.amazonaws.com", "PutLogEvents": "logs.amazonaws.com",
    "DescribeLogGroups": "logs.amazonaws.com",
}


def _cloud_event(ctx: Ctx, *, event_id: str, event_name: str, event_source: str, event_time: str,
                 principal_id: str, principal_arn: str, access_key_id: str, source_ip: str, user_agent: str,
                 success: bool, error_code: str | None, target_id: str | None, count: int, bytes_: int,
                 anomalous: bool, anomaly_reasons: list[str], account_id: str = "111111111111") -> str:
    t = at(event_time)
    ctx.n(event_id, "CloudEvent", event_name, {
        "provider": "aws", "account_id": account_id, "event_name": event_name, "event_source": event_source,
        "event_time": t, "principal_id": principal_id, "principal_arn": principal_arn,
        "access_key_id": access_key_id, "source_ip": source_ip, "user_agent": user_agent, "success": success,
        "error_code": error_code, "target_id": target_id, "count": count, "bytes": bytes_,
        "anomalous": anomalous, "anomaly_reasons": anomaly_reasons,
    }, source="cloudtrail-sim", source_id=event_id.split(":")[-1], first_seen=t, last_seen=t)
    return event_id


def add_storyline_events(ctx: Ctx) -> list[str]:
    """Cloud events a010-a016 with their exact props and PERFORMED_BY/ASSUMED/TARGETED/FROM_IP/USED_CREDENTIAL."""
    egress = ip_node(ctx, S.ATTACKER_EGRESS_IP, source="cloudtrail-sim", asn=S.ATTACKER_ASN,
                     asn_org=S.ATTACKER_ASN_ORG, country="NL")
    prod_session_arn = "arn:aws:sts::111111111111:assumed-role/LarkspurProdDataReader/ember-sync"
    bastion_session_arn = "arn:aws:sts::222222222222:assumed-role/LarkspurBastionSSMRole/i-0b4571e2c9a8f3d01"

    reasons = {
        "a010": ["instance-role credentials used outside originating VPC", "source ASN AS64500 not previously seen for role"],
        "a011": ["denied enumeration attempts (ListAllMyBuckets, ListRoles) from instance role", "source ASN AS64500 not previously seen for role"],
        "a012": ["AssumeRole to prod data-reader from bastion role outside any change window", "cross-account privilege chain from shared-services to prod"],
        "a013": ["prod-reader role used from external ASN AS64500", "first S3 ListBucket on cardholder vault by this role"],
        "a014": ["bulk GetObject (1247 objects, ~38 GB) from PCI cardholder vault", "large egress to external ASN AS64500"],
        "a015": ["secret retrieval by prod-reader role from external ASN AS64500", "first access to prod/cardholder-db/reader by this role"],
        "a016": ["secret retrieval by prod-reader role from external ASN AS64500", "first access to prod/hsm/partner-signing-key by this role"],
    }
    targets = {"a013": S.CARDHOLDER_VAULT, "a014": S.CARDHOLDER_VAULT, "a015": S.DB_READER_SECRET, "a016": S.HSM_SECRET}
    bytes_map = {"a014": S.EXFIL_BYTES}
    ids: list[str] = []
    for key, (eid, etime, ename, esrc, akid, success, err, count) in S.CLOUDEVENTS_A.items():
        bastion_phase = akid == S.CRED_BASTION_KEY_ID
        principal = S.BASTION_ROLE if bastion_phase else S.PROD_READER_ROLE
        principal_arn = bastion_session_arn if bastion_phase else prod_session_arn
        cred = S.CRED_BASTION_KEY if bastion_phase else S.CRED_PROD_KEY
        acct = "222222222222" if bastion_phase else "111111111111"
        target = targets.get(key)
        _cloud_event(ctx, event_id=eid, event_name=ename, event_source=esrc, event_time=etime,
                     principal_id=principal, principal_arn=principal_arn, access_key_id=akid,
                     source_ip=S.ATTACKER_EGRESS_IP, user_agent=USER_AGENT, success=success, error_code=err,
                     target_id=(S.PROD_READER_ROLE if key == "a012" else target), count=count,
                     bytes_=bytes_map.get(key, 0), anomalous=True, anomaly_reasons=reasons[key], account_id=acct)
        ctx.e("PERFORMED_BY", eid, principal, source="cloudtrail-sim", first_seen=at(etime))
        ctx.e("USED_CREDENTIAL", eid, cred, source="cloudtrail-sim", first_seen=at(etime))
        ctx.e("FROM_IP", eid, egress, source="cloudtrail-sim", first_seen=at(etime))
        if key == "a012":
            ctx.e("ASSUMED", eid, S.PROD_READER_ROLE, source="cloudtrail-sim", first_seen=at(etime))
        if target:
            ctx.e("TARGETED", eid, target, source="cloudtrail-sim", first_seen=at(etime))
        ids.append(eid)
    return ids


def add_background_events(ctx: Ctx, n: int) -> int:
    """~n aggregated benign CloudEvents by fleet roles from AWS-internal / VPN IPs (anomalous: false)."""
    r = rng("events.cloudtrail.background")
    role_ids = [role["id"] for role in ctx.inv.roles]
    if not role_ids:
        return 0
    buckets = [b["id"] for b in ctx.inv.buckets if not b.get("crown_jewel")]
    secrets = [s["id"] for s in ctx.inv.secrets]
    dbs = [d["id"] for d in ctx.inv.databases]
    # a small reused pool of AWS-internal source IPs plus the corporate VPN egress
    internal_ips = [ip_node(ctx, f"10.{r.randint(10, 40)}.{r.randint(0, 250)}.{r.randint(2, 250)}",
                            source="cloudtrail-sim") for _ in range(40)]
    internal_ips.append(ip_node(ctx, S.VPN_EGRESS_IP, source="cloudtrail-sim", asn="AS64512",
                                asn_org="Larkspur Corporate VPN", country="US"))
    event_names = list(_BG_EVENTS)
    count = 0
    for i in range(n):
        when = NOW - timedelta(days=r.randint(0, 6), hours=r.randint(0, 23), minutes=r.randint(0, 59))
        ename = r.choice(event_names)
        esrc = _BG_EVENTS[ename]
        role = r.choice(role_ids)
        akid = "ASIA" + stable_hex("bg-key", i, length=16).upper()[:16]
        success = r.random() > 0.04
        target = None
        if ename in ("ListBucket", "GetObject", "PutObject", "ListObjectsV2", "HeadObject") and buckets:
            target = r.choice(buckets)
        elif ename == "GetSecretValue" and secrets:
            target = r.choice(secrets)
        elif ename == "DescribeDBInstances" and dbs:
            target = r.choice(dbs)
        eid = f"cloudevent:aws:evt-bg-{stable_hex('bg', i, length=10)}"
        src_ip_id = r.choice(internal_ips)
        _cloud_event(ctx, event_id=eid, event_name=ename, event_source=esrc, event_time=ts(when),
                     principal_id=role, principal_arn=f"arn:aws:sts::{role.split(':')[2]}:assumed-role/{role.split(':')[-1]}/session",
                     access_key_id=akid, source_ip=src_ip_id.split(":")[-1],
                     user_agent=r.choice(_EVENT_SOURCE_UA), success=success,
                     error_code=None if success else "AccessDenied", target_id=target,
                     count=r.randint(1, 25), bytes_=0, anomalous=False, anomaly_reasons=[],
                     account_id=role.split(":")[2])
        ctx.e("PERFORMED_BY", eid, role, source="cloudtrail-sim", first_seen=ts(when))
        ctx.e("FROM_IP", eid, src_ip_id, source="cloudtrail-sim", first_seen=ts(when))
        if target:
            ctx.e("TARGETED", eid, target, source="cloudtrail-sim", first_seen=ts(when))
        count += 1
    return count
