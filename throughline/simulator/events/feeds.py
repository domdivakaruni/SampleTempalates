"""Raw vendor-shaped feeds under ``out/raw/`` -- the flat objects a Falcon / CloudTrail / WAF / IDS / Okta
analyst console would show, with **no** cloud-graph context. These are derived from the canonical event
nodes/edges so there is a single source of truth: alert ``raw`` views, Process/Incident/CloudEvent nodes,
and CONNECTED_TO / LOGGED_ON edges.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from throughline.simulator.common import write_jsonl
from throughline.simulator.events.ctx import Ctx

REGION = "us-east-1"


def _by_id(ctx: Ctx) -> dict[str, dict]:
    return {rec["id"]: rec for rec in ctx.nodes}


def _alerts(ctx: Ctx, source_system: str) -> list[dict]:
    return [rec for rec in ctx.nodes if rec["label"] == "Alert" and rec["props"].get("source_system") == source_system]


def _falcon_detections(ctx: Ctx) -> list[dict]:
    return [a["props"]["raw"] for a in _alerts(ctx, "falcon")]


def _falcon_incidents(ctx: Ctx) -> list[dict]:
    rows = []
    for rec in ctx.nodes:
        if rec["label"] != "Incident":
            continue
        p = rec["props"]
        rows.append({
            "incident_id": rec["source_id"], "state": p.get("status"), "severity": p.get("vendor_severity"),
            "start": p.get("start_time"), "end": p.get("end_time"), "host_count": len(p.get("hosts", [])),
            "hosts": p.get("hosts", []), "alert_count": p.get("alert_count"), "description": p.get("description"),
        })
    return rows


def _falcon_processes(ctx: Ctx) -> list[dict]:
    rows = []
    for rec in ctx.nodes:
        if rec["label"] != "Process":
            continue
        p = rec["props"]
        rows.append({
            "device_id": p["endpoint_id"].split(":")[-1], "process_id": rec["id"], "pid": p.get("pid"),
            "parent_process_id": p.get("parent_process_id"), "file_name": rec["name"],
            "image_file_name": p.get("image_path"), "command_line": p.get("command_line"),
            "user_name": p.get("user"), "sha256": p.get("sha256"), "timestamp": p.get("start_time"),
            "integrity_level": p.get("integrity_level"),
        })
    return rows


def _falcon_network(ctx: Ctx, by_id: dict[str, dict]) -> list[dict]:
    rows = []
    for e in ctx.edges:
        if e["type"] != "CONNECTED_TO":
            continue
        src = by_id.get(e["src"])
        if not src or src["label"] != "Process":
            continue
        dst_id = e["dst"]
        remote = dst_id.split(":")[-1]
        pr = e.get("props", {})
        rows.append({
            "device_id": src["props"]["endpoint_id"].split(":")[-1], "context_process_id": e["src"],
            "remote_address": remote, "remote_is_domain": dst_id.startswith("domain:"),
            "remote_port": pr.get("port"), "protocol": pr.get("protocol"), "direction": pr.get("direction"),
            "connection_count": pr.get("count"), "bytes_out": pr.get("bytes_out"),
            "first_time": pr.get("first_time"), "last_time": pr.get("last_time"),
        })
    return rows


def _falcon_logons(ctx: Ctx) -> list[dict]:
    rows = []
    for e in ctx.edges:
        if e["type"] != "LOGGED_ON":
            continue
        pr = e.get("props", {})
        rows.append({
            "device_id": e["dst"].split(":")[-1], "user_name": e["src"].split(":")[-1],
            "principal_id": e["src"], "logon_type": pr.get("logon_type"), "logon_time": pr.get("logon_time"),
            "source_ip": pr.get("source_ip"), "session_id": pr.get("session_id"), "success": True,
        })
    return rows


def _cloudtrail(ctx: Ctx) -> list[dict]:
    rows = []
    for rec in ctx.nodes:
        if rec["label"] != "CloudEvent":
            continue
        p = rec["props"]
        req: dict[str, Any] = {}
        if p.get("target_id"):
            tid = p["target_id"]
            if tid.startswith("bucket:"):
                req["bucketName"] = tid.split(":")[-1]
            elif tid.startswith("secret:"):
                req["secretId"] = tid.split(":", 3)[-1]
            elif tid.startswith("role:"):
                req["roleArn"] = f"arn:aws:iam::{tid.split(':')[2]}:role/{tid.split(':')[-1]}"
        rows.append({
            "eventVersion": "1.09",
            "userIdentity": {
                "type": "AssumedRole", "arn": p.get("principal_arn"), "accountId": p.get("account_id"),
                "accessKeyId": p.get("access_key_id"),
                "sessionContext": {"sessionIssuer": {"type": "Role", "principalId": p.get("principal_id"),
                                                     "arn": p.get("principal_arn")}},
            },
            "eventTime": p.get("event_time"), "eventSource": p.get("event_source"), "eventName": p.get("event_name"),
            "awsRegion": REGION, "sourceIPAddress": p.get("source_ip"), "userAgent": p.get("user_agent"),
            "requestParameters": req or None,
            "responseElements": {"count": p.get("count")} if p.get("success") else None,
            "errorCode": p.get("error_code"),
        })
    return rows


def write_feeds(ctx: Ctx, out_dir: Path) -> list[Path]:
    by_id = _by_id(ctx)
    raw = out_dir / "raw"
    written: list[Path] = []
    plan = [
        (raw / "falcon" / "detections.jsonl", _falcon_detections(ctx)),
        (raw / "falcon" / "incidents.jsonl", _falcon_incidents(ctx)),
        (raw / "falcon" / "processes.jsonl", _falcon_processes(ctx)),
        (raw / "falcon" / "network_connections.jsonl", _falcon_network(ctx, by_id)),
        (raw / "falcon" / "logons.jsonl", _falcon_logons(ctx)),
        (raw / "cloudtrail" / "events.jsonl", _cloudtrail(ctx)),
        (raw / "waf" / "alerts.jsonl", [a["props"]["raw"] for a in _alerts(ctx, "waf")]),
        (raw / "ids" / "alerts.jsonl", [a["props"]["raw"] for a in _alerts(ctx, "ids")]),
        (raw / "okta" / "alerts.jsonl", [a["props"]["raw"] for a in _alerts(ctx, "okta")]),
    ]
    for path, rows in plan:
        write_jsonl(path, rows)
        written.append(path)
    return written
