"""Campaign A -- EMBERCAST (Cinder Jackal): the scripted targeted intrusion, docs/04 section 2.1 rows A1-A15.

Builds the EDR side (alerts a001-a009 with their exact process trees, files, network beacons, credential
theft) and the cloud-anomaly alert ca-a017. The cloud events a010-a016 are emitted by :mod:`cloudtrail`; the
anomalous SSH logon at A7 by :mod:`logons`; this module wires the alerts to all of them by id.
"""
from __future__ import annotations

from throughline.simulator import storyline_constants as S
from throughline.simulator.events import credentials, processes
from throughline.simulator.events.ctx import Ctx, add_alert, falcon_raw, involves
from throughline.simulator.events.network import connected_to, domain_node, ip_node
from throughline.simulator.events.processes import add_process, executed, file_node, ran_as, spawn

DANA = "CORP\\dwhitfield"
INC_WKS = "inc-0091"
INC_BASTION = "inc-0094"
TMP = "C:\\Users\\dwhitfield\\AppData\\Local\\Temp"


def generate_storyline_a(ctx: Ctx) -> None:
    wks = ctx.inv.endpoint(S.WKS_DANA)
    bas = ctx.inv.endpoint(S.EP_BASTION)
    assert wks and bas, "storyline A requires WKS-3391 and bas-01 endpoints in the inventory"
    _wks3391(ctx, wks)
    _bastion(ctx, bas)
    _cloud_anomaly(ctx)


# --------------------------------------------------------------------- WKS-3391 (rows A1-A6)


def _wks3391(ctx: Ctx, wks: dict) -> None:
    ep = S.WKS_DANA

    # --- A1: LNK-in-ISO -> powershell -> rundll32 (MAPLELOADER) --------------------------------------
    a1_id, a1_ts, a1_sev = S.ALERT_A["a001"]
    explorer = add_process(ctx, endpoint_id=ep, pid=4120, image_path="C:\\Windows\\explorer.exe",
                           command_line="C:\\Windows\\Explorer.EXE", user=DANA, start_time="2026-09-09T09:11:00Z",
                           signer="Microsoft Corporation", integrity_level="medium")
    ran_as(ctx, explorer, S.USER_DANA)
    powershell = add_process(ctx, endpoint_id=ep, pid=6820,
                             image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                             command_line="powershell.exe -w hidden -enc SQBFAFgAKABJAFcAUgApAA==",
                             user=DANA, start_time="2026-09-09T09:12:00Z", parent_id=explorer,
                             signer="Microsoft Corporation", integrity_level="medium")
    ran_as(ctx, powershell, S.USER_DANA)
    spawn(ctx, explorer, powershell, when="2026-09-09T09:12:00Z")
    rundll = add_process(ctx, endpoint_id=ep, pid=7010, image_path="C:\\Windows\\System32\\rundll32.exe",
                         command_line=f"rundll32.exe {TMP}\\mpl.dll,Start", user=DANA,
                         start_time=a1_ts, parent_id=powershell, signed=False, integrity_level="medium")
    ran_as(ctx, rundll, S.USER_DANA)
    spawn(ctx, powershell, rundll, when=a1_ts)
    mpl = file_node(ctx, sha256=S.HASH_MAPLELOADER, file_name="mpl.dll", file_path=f"{TMP}\\mpl.dll",
                    verdict="malicious", size_bytes=286_720)
    executed(ctx, rundll, mpl, action="loaded", when=a1_ts)
    lnk = file_node(ctx, sha256="a1" + S.HASH_MAPLELOADER[2:], file_name="Remittance_Viewer.lnk",
                    file_path="E:\\Remittance_Viewer.lnk", verdict="suspicious", size_bytes=2048)
    executed(ctx, explorer, lnk, action="executed", when="2026-09-09T09:11:40Z")
    a1_raw = falcon_raw(alert_id=a1_id, endpoint=wks, severity=a1_sev, techniques=["T1566.001", "T1204.002", "T1059.001", "T1218.011"],
                        display_name="Malicious file execution via LNK in mounted ISO",
                        description="A LNK inside a mounted ISO launched a hidden PowerShell that ran a DLL via rundll32.",
                        disposition="detected", filename="mpl.dll", filepath=f"{TMP}\\mpl.dll",
                        cmdline=f"rundll32.exe {TMP}\\mpl.dll,Start", sha256=S.HASH_MAPLELOADER, user_name=DANA,
                        timestamp=a1_ts, incident_id=INC_WKS,
                        parent={"process_id": powershell, "cmdline": "powershell.exe -w hidden -enc ...", "filename": "powershell.exe"})
    add_alert(ctx, alert_id=a1_id, source_system="falcon", alert_type="detection",
              title="Malicious file execution via LNK in mounted ISO",
              description="A LNK inside a mounted ISO launched a hidden PowerShell that ran a DLL via rundll32 (MAPLELOADER).",
              severity=a1_sev, detected_at=a1_ts, techniques=["T1566.001", "T1204.002", "T1059.001", "T1218.011"],
              entity_id=ep, entity_label="Endpoint", on_endpoint=ep, hostname=wks["hostname"], user=DANA,
              vendor_incident_id=INC_WKS, raw=a1_raw)
    involves(ctx, a1_id, rundll, "subject", when=a1_ts)
    involves(ctx, a1_id, powershell, "subject", when=a1_ts)
    involves(ctx, a1_id, mpl, "object", when=a1_ts)

    # --- A2: Run-key persistence, synchost.exe (NIGHTFERRY) written ----------------------------------
    a2_id, a2_ts, a2_sev = S.ALERT_A["a002"]
    synchost_path = "C:\\ProgramData\\Microsoft\\SyncHost\\synchost.exe"
    reg = add_process(ctx, endpoint_id=ep, pid=7220, image_path="C:\\Windows\\System32\\reg.exe",
                      command_line="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SyncHost "
                                   f"/t REG_SZ /d {synchost_path} /f",
                      user=DANA, start_time=a2_ts, parent_id=rundll, signer="Microsoft Corporation")
    ran_as(ctx, reg, S.USER_DANA)
    spawn(ctx, rundll, reg, when=a2_ts)
    synchost_file = file_node(ctx, sha256=S.HASH_NIGHTFERRY, file_name="synchost.exe", file_path=synchost_path,
                              verdict="malicious", size_bytes=421_888)
    executed(ctx, rundll, synchost_file, action="wrote", when=a2_ts)
    a2_raw = falcon_raw(alert_id=a2_id, endpoint=wks, severity=a2_sev, techniques=["T1547.001", "T1055"],
                        display_name="Run-key persistence by recently written binary",
                        description="A recently written binary (synchost.exe) was registered under the HKCU Run key.",
                        disposition="detected", filename="synchost.exe", filepath=synchost_path,
                        cmdline=f"reg add ...\\Run /v SyncHost /d {synchost_path} /f", sha256=S.HASH_NIGHTFERRY,
                        user_name=DANA, timestamp=a2_ts, incident_id=INC_WKS,
                        parent={"process_id": rundll, "cmdline": f"rundll32.exe {TMP}\\mpl.dll,Start", "filename": "rundll32.exe"})
    add_alert(ctx, alert_id=a2_id, source_system="falcon", alert_type="detection",
              title="Run-key persistence by recently written binary",
              description="A recently written binary was registered for autostart under the HKCU Run key (NIGHTFERRY).",
              severity=a2_sev, detected_at=a2_ts, techniques=["T1547.001", "T1055"], entity_id=ep,
              entity_label="Endpoint", on_endpoint=ep, hostname=wks["hostname"], user=DANA,
              vendor_incident_id=INC_WKS, raw=a2_raw)
    involves(ctx, a2_id, rundll, "subject", when=a2_ts)
    involves(ctx, a2_id, synchost_file, "object", when=a2_ts)

    # --- A3: NIGHTFERRY C2 beacons to a rare domain --------------------------------------------------
    a3_id, a3_ts, a3_sev = S.ALERT_A["a003"]
    synchost = add_process(ctx, endpoint_id=ep, pid=5300, image_path=synchost_path,
                           command_line="synchost.exe", user=DANA, start_time="2026-09-09T09:15:00Z",
                           parent_id=explorer, sha256=S.HASH_NIGHTFERRY, signed=False)
    ran_as(ctx, synchost, S.USER_DANA)
    executed(ctx, synchost, synchost_file, action="executed", when="2026-09-09T09:15:00Z")
    dom = domain_node(ctx, S.C2_DOMAIN)
    c2ip = ip_node(ctx, S.C2_IP, asn=S.ATTACKER_ASN, asn_org=S.ATTACKER_ASN_ORG, country="DE")
    connected_to(ctx, synchost, dom, port=443, protocol="tls", count=29, bytes_out=184_320,
                 first_time="2026-09-09T09:15:00Z", last_time=a3_ts)
    connected_to(ctx, synchost, c2ip, port=443, protocol="tls", count=29, bytes_out=184_320,
                 first_time="2026-09-09T09:15:00Z", last_time=a3_ts)
    a3_raw = falcon_raw(alert_id=a3_id, endpoint=wks, severity=a3_sev, techniques=["T1071.001", "T1573.002"],
                        display_name="Periodic outbound connections to rare domain",
                        description=f"synchost.exe made periodic TLS beacons to {S.C2_DOMAIN} (rarely seen in the environment).",
                        disposition="detected", filename="synchost.exe", filepath=synchost_path,
                        cmdline="synchost.exe", sha256=S.HASH_NIGHTFERRY, user_name=DANA, timestamp=a3_ts,
                        incident_id=INC_WKS, parent={"process_id": explorer, "filename": "explorer.exe"})
    a3_raw["domain"] = S.C2_DOMAIN
    a3_raw["remote_address"] = S.C2_IP
    add_alert(ctx, alert_id=a3_id, source_system="falcon", alert_type="detection",
              title="Periodic outbound connections to rare domain",
              description=f"Periodic TLS beacons to the rarely-seen domain {S.C2_DOMAIN}.",
              severity=a3_sev, detected_at=a3_ts, techniques=["T1071.001", "T1573.002"], entity_id=ep,
              entity_label="Endpoint", on_endpoint=ep, hostname=wks["hostname"], user=DANA,
              vendor_incident_id=INC_WKS, raw=a3_raw)
    involves(ctx, a3_id, synchost, "subject", when=a3_ts)
    involves(ctx, a3_id, dom, "destination", when=a3_ts)
    involves(ctx, a3_id, c2ip, "destination", when=a3_ts)

    # --- A4: QUILLDROP LSASS read --------------------------------------------------------------------
    a4_id, a4_ts, a4_sev = S.ALERT_A["a004"]
    qd = add_process(ctx, endpoint_id=ep, pid=6110, image_path=f"{TMP}\\qd.exe",
                     command_line="qd.exe", user=DANA, start_time=a4_ts, parent_id=explorer,
                     sha256=S.HASH_QUILLDROP, signed=False, integrity_level="high")
    ran_as(ctx, qd, S.USER_DANA)
    qd_file = file_node(ctx, sha256=S.HASH_QUILLDROP, file_name="qd.exe", file_path=f"{TMP}\\qd.exe",
                        verdict="malicious", size_bytes=198_144)
    executed(ctx, qd, qd_file, action="executed", when=a4_ts)
    lsass = add_process(ctx, endpoint_id=ep, pid=780, image_path="C:\\Windows\\System32\\lsass.exe",
                        command_line="C:\\Windows\\system32\\lsass.exe", user="NT AUTHORITY\\SYSTEM",
                        start_time="2026-09-09T08:00:00Z", signer="Microsoft Corporation", integrity_level="system")
    a4_raw = falcon_raw(alert_id=a4_id, endpoint=wks, severity=a4_sev, techniques=["T1003.001"],
                        display_name="Credential dumping technique observed (LSASS memory read)",
                        description="An unsigned process opened lsass.exe with PROCESS_VM_READ and read its memory.",
                        disposition="detected", filename="qd.exe", filepath=f"{TMP}\\qd.exe", cmdline="qd.exe",
                        sha256=S.HASH_QUILLDROP, user_name=DANA, timestamp=a4_ts, incident_id=INC_WKS,
                        parent={"process_id": explorer, "filename": "explorer.exe"})
    add_alert(ctx, alert_id=a4_id, source_system="falcon", alert_type="detection",
              title="Credential dumping technique observed (LSASS memory read)",
              description="An unsigned process read lsass.exe memory (QUILLDROP).", severity=a4_sev,
              detected_at=a4_ts, techniques=["T1003.001"], entity_id=ep, entity_label="Endpoint",
              on_endpoint=ep, hostname=wks["hostname"], user=DANA, vendor_incident_id=INC_WKS, raw=a4_raw)
    involves(ctx, a4_id, qd, "subject", when=a4_ts)
    involves(ctx, a4_id, lsass, "object", when=a4_ts)

    # --- A5: SSH private-key read -> credential theft ------------------------------------------------
    a5_id, a5_ts, a5_sev = S.ALERT_A["a005"]
    key_file = file_node(ctx, sha256="e5" + S.HASH_QUILLDROP[2:], file_name="id_ed25519",
                         file_path="C:\\Users\\dwhitfield\\.ssh\\id_ed25519", verdict="clean", size_bytes=464)
    executed(ctx, qd, key_file, action="read", when=a5_ts)
    cred_ssh = credentials.add_ssh_key(ctx, alert_id=a5_id, quilldrop_proc=qd)
    a5_raw = falcon_raw(alert_id=a5_id, endpoint=wks, severity=a5_sev, techniques=["T1552.001"],
                        display_name="Access to SSH private key by unsigned process",
                        description="An unsigned process read an OpenSSH private key and a FinOpsSync config file.",
                        disposition="detected", filename="id_ed25519", filepath="C:\\Users\\dwhitfield\\.ssh\\id_ed25519",
                        cmdline="qd.exe", sha256=S.HASH_QUILLDROP, user_name=DANA, timestamp=a5_ts,
                        incident_id=INC_WKS, parent={"process_id": explorer, "filename": "explorer.exe"})
    add_alert(ctx, alert_id=a5_id, source_system="falcon", alert_type="detection",
              title="Access to SSH private key by unsigned process",
              description="An unsigned process read C:\\Users\\dwhitfield\\.ssh\\id_ed25519 and FinOpsSync\\config.ini.",
              severity=a5_sev, detected_at=a5_ts, techniques=["T1552.001"], entity_id=ep, entity_label="Endpoint",
              on_endpoint=ep, hostname=wks["hostname"], user=DANA, vendor_incident_id=INC_WKS, raw=a5_raw)
    involves(ctx, a5_id, qd, "subject", when=a5_ts)
    involves(ctx, a5_id, key_file, "object", when=a5_ts)
    involves(ctx, a5_id, cred_ssh, "credential", when=a5_ts)

    # --- A6: discovery -------------------------------------------------------------------------------
    a6_id, a6_ts, a6_sev = S.ALERT_A["a006"]
    cmd = add_process(ctx, endpoint_id=ep, pid=6980, image_path="C:\\Windows\\System32\\cmd.exe",
                      command_line="cmd.exe /c", user=DANA, start_time=a6_ts, parent_id=explorer,
                      signer="Microsoft Corporation")
    ran_as(ctx, cmd, S.USER_DANA)
    spawn(ctx, explorer, cmd, when=a6_ts)
    disc_specs = [
        (7100, "C:\\Windows\\System32\\net.exe", 'net group "Domain Admins" /domain'),
        (7104, "C:\\Windows\\System32\\nltest.exe", "nltest /dclist:corp"),
        (7108, "C:\\Windows\\System32\\arp.exe", "arp -a"),
        (7112, "C:\\Windows\\System32\\nslookup.exe", f"nslookup {S.BASTION_HOSTNAME}"),
    ]
    disc_procs = []
    for pid, img, cl in disc_specs:
        p = add_process(ctx, endpoint_id=ep, pid=pid, image_path=img, command_line=cl, user=DANA,
                        start_time=a6_ts, parent_id=cmd, signer="Microsoft Corporation")
        ran_as(ctx, p, S.USER_DANA)
        spawn(ctx, cmd, p, when=a6_ts)
        disc_procs.append(p)
    a6_raw = falcon_raw(alert_id=a6_id, endpoint=wks, severity=a6_sev, techniques=["T1087.002", "T1018"],
                        display_name="Account and remote-system discovery",
                        description="Domain account and remote-system discovery commands executed in sequence.",
                        disposition="detected", filename="net.exe", filepath="C:\\Windows\\System32\\net.exe",
                        cmdline='net group "Domain Admins" /domain', sha256=processes.SYS_HASHES["net.exe"],
                        user_name=DANA, timestamp=a6_ts, incident_id=INC_WKS,
                        parent={"process_id": cmd, "filename": "cmd.exe"})
    add_alert(ctx, alert_id=a6_id, source_system="falcon", alert_type="detection",
              title="Account and remote-system discovery",
              description="Domain-account and remote-system discovery commands (net group, nltest, arp, nslookup).",
              severity=a6_sev, detected_at=a6_ts, techniques=["T1087.002", "T1018"], entity_id=ep,
              entity_label="Endpoint", on_endpoint=ep, hostname=wks["hostname"], user=DANA,
              vendor_incident_id=INC_WKS, raw=a6_raw)
    for p in disc_procs:
        involves(ctx, a6_id, p, "subject", when=a6_ts)


# --------------------------------------------------------------------- bas-01 (rows A7-A9) + credentials


def _bastion(ctx: Ctx, bas: dict) -> None:
    ep = S.EP_BASTION
    svc = S.SVC_FINOPS_SFTP

    # --- A7: interactive SSH session as the SFTP-only account ---------------------------------------
    a7_id, a7_ts, a7_sev = S.ALERT_A["a007"]
    sshd = add_process(ctx, endpoint_id=ep, pid=1122, image_path="/usr/sbin/sshd",
                       command_line="sshd: svc-finops-sftp [priv]", user="root", start_time="2026-09-10T02:05:16Z",
                       signer="Amazon Linux", source="falcon-sim")
    bash = add_process(ctx, endpoint_id=ep, pid=20455, image_path="/bin/bash", command_line="-bash",
                       user="svc-finops-sftp", start_time=a7_ts, parent_id=sshd, integrity_level="medium")
    ran_as(ctx, bash, svc)
    spawn(ctx, sshd, bash, when=a7_ts)
    src_ip = ip_node(ctx, S.WKS_DANA_IP)
    a7_raw = falcon_raw(alert_id=a7_id, endpoint=bas, severity=a7_sev, techniques=["T1021.004", "T1078"],
                        display_name="Interactive SSH session from user workstation to bastion outside business hours",
                        description="The SFTP-only account svc-finops-sftp opened an interactive shell over SSH at 02:05 UTC "
                                    "from a user workstation IP -- it normally only runs non-interactive SFTP.",
                        disposition="detected", filename="bash", filepath="/bin/bash", cmdline="-bash",
                        sha256=processes.SYS_HASHES["bash"], user_name="svc-finops-sftp", timestamp=a7_ts,
                        incident_id=INC_BASTION, parent={"process_id": sshd, "filename": "sshd"})
    a7_raw["source_ip"] = S.WKS_DANA_IP
    a7_raw["logon_type"] = "ssh-interactive"
    add_alert(ctx, alert_id=a7_id, source_system="falcon", alert_type="detection",
              title="Interactive SSH session from user workstation to bastion outside business hours",
              description="Interactive SSH shell as svc-finops-sftp (SFTP-only) from a workstation IP, out of hours.",
              severity=a7_sev, detected_at=a7_ts, techniques=["T1021.004", "T1078"], entity_id=ep,
              entity_label="Endpoint", on_endpoint=ep, hostname=bas["hostname"], user="svc-finops-sftp",
              vendor_incident_id=INC_BASTION, raw=a7_raw)
    involves(ctx, a7_id, bash, "subject", when=a7_ts)
    involves(ctx, a7_id, svc, "subject", when=a7_ts)
    involves(ctx, a7_id, src_ip, "source", when=a7_ts)

    # --- A8: /etc/shadow read via sudo --------------------------------------------------------------
    a8_id, a8_ts, a8_sev = S.ALERT_A["a008x"]
    sudo = add_process(ctx, endpoint_id=ep, pid=20460, image_path="/usr/bin/sudo",
                       command_line="sudo cat /etc/shadow", user="svc-finops-sftp", start_time=a8_ts,
                       parent_id=bash, signer="Amazon Linux")
    ran_as(ctx, sudo, svc)
    spawn(ctx, bash, sudo, when=a8_ts)
    cat = add_process(ctx, endpoint_id=ep, pid=20461, image_path="/usr/bin/cat",
                      command_line="cat /etc/shadow", user="root", start_time=a8_ts, parent_id=sudo,
                      signer="Amazon Linux", integrity_level="system")
    spawn(ctx, sudo, cat, when=a8_ts)
    shadow = file_node(ctx, sha256="5ha00", file_name="shadow", file_path="/etc/shadow", verdict="clean", size_bytes=1420)
    executed(ctx, cat, shadow, action="read", when=a8_ts)
    a8_raw = falcon_raw(alert_id=a8_id, endpoint=bas, severity=a8_sev, techniques=["T1003.008"],
                        display_name="Read of /etc/shadow via sudo",
                        description="sudo (NOPASSWD) was used to read /etc/shadow.", disposition="detected",
                        filename="cat", filepath="/usr/bin/cat", cmdline="cat /etc/shadow",
                        sha256=processes.SYS_HASHES["cat"], user_name="root", timestamp=a8_ts,
                        incident_id=INC_BASTION, parent={"process_id": sudo, "cmdline": "sudo cat /etc/shadow", "filename": "sudo"})
    add_alert(ctx, alert_id=a8_id, source_system="falcon", alert_type="detection",
              title="Read of /etc/shadow via sudo",
              description="sudo (misconfigured NOPASSWD) used to read /etc/shadow.", severity=a8_sev,
              detected_at=a8_ts, techniques=["T1003.008"], entity_id=ep, entity_label="Endpoint",
              on_endpoint=ep, hostname=bas["hostname"], user="root", vendor_incident_id=INC_BASTION, raw=a8_raw)
    involves(ctx, a8_id, cat, "subject", when=a8_ts)
    involves(ctx, a8_id, sudo, "subject", when=a8_ts)

    # --- A9: IMDS credential access (PIVOTAL) -------------------------------------------------------
    a9_id, a9_ts, a9_sev = S.ALERT_A["a009"]
    curl = add_process(ctx, endpoint_id=ep, pid=20470, image_path="/usr/bin/curl",
                       command_line="curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole",
                       user="svc-finops-sftp", start_time=a9_ts, parent_id=bash, signer="Amazon Linux")
    ran_as(ctx, curl, svc)
    spawn(ctx, bash, curl, when=a9_ts)
    imds_ip = ip_node(ctx, "169.254.169.254")
    connected_to(ctx, curl, imds_ip, port=80, protocol="http", count=1, bytes_out=512, first_time=a9_ts)
    cred_bastion = credentials.add_bastion_key(ctx, alert_id=a9_id, curl_proc=curl)
    credentials.add_prod_key(ctx)  # minted at A12; created here so the credential-join node exists
    a9_raw = falcon_raw(alert_id=a9_id, endpoint=bas, severity=a9_sev, techniques=["T1552.005"],
                        display_name="Cloud instance metadata service credential access from interactive shell",
                        description="An interactive shell queried the IMDS endpoint for the bastion instance role's "
                                    "temporary credentials.", disposition="detected", filename="curl",
                        filepath="/usr/bin/curl",
                        cmdline="curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/LarkspurBastionSSMRole",
                        sha256=processes.SYS_HASHES["curl"], user_name="svc-finops-sftp", timestamp=a9_ts,
                        incident_id=INC_BASTION, parent={"process_id": bash, "cmdline": "-bash", "filename": "bash"})
    add_alert(ctx, alert_id=a9_id, source_system="falcon", alert_type="detection",
              title="Cloud instance metadata service credential access from interactive shell",
              description="Interactive shell read the bastion instance role credentials from the IMDS endpoint.",
              severity=a9_sev, detected_at=a9_ts, techniques=["T1552.005"], entity_id=ep, entity_label="Endpoint",
              on_endpoint=ep, hostname=bas["hostname"], user="svc-finops-sftp", vendor_incident_id=INC_BASTION, raw=a9_raw)
    involves(ctx, a9_id, curl, "subject", when=a9_ts)
    involves(ctx, a9_id, cred_bastion, "credential", when=a9_ts)
    involves(ctx, a9_id, imds_ip, "destination", when=a9_ts)


# --------------------------------------------------------------------- ca-a017 (row A15)


def _cloud_anomaly(ctx: Ctx) -> None:
    a17_id, a17_ts, a17_sev = S.ALERT_A["a017"]
    egress = ip_node(ctx, S.ATTACKER_EGRESS_IP, source="cloudtrail-sim", asn=S.ATTACKER_ASN,
                     asn_org=S.ATTACKER_ASN_ORG, country="NL")
    raw = {
        "detector": "role-usage-geo-anomaly",
        "role_arn": S.PROD_READER_ROLE_ARN,
        "principal": "LarkspurProdDataReader/ember-sync",
        "source_ip": S.ATTACKER_EGRESS_IP,
        "source_asn": S.ATTACKER_ASN,
        "source_asn_org": S.ATTACKER_ASN_ORG,
        "source_country": "NL",
        "baseline_geo": "us-east-1 (AWS internal)",
        "first_seen_new_geo": True,
        "event_count": 1250,
        "window": "2026-09-10T02:26:00Z/2026-09-10T03:42:00Z",
        "mfa_present": False,
        "note": "API calls for role LarkspurProdDataReader from a new geolocation/ASN",
    }
    add_alert(ctx, alert_id=a17_id, source_system="cloud-anomaly", alert_type="cloud",
              title="API calls for role LarkspurProdDataReader from a new geolocation/ASN",
              description="Cloud-anomaly detector flagged prod-reader role activity from a previously unseen "
                          "geolocation/ASN (looks like a VPN/travel anomaly).",
              severity=a17_sev, detected_at=a17_ts, techniques=["T1078.004"], entity_id=S.PROD_READER_ROLE,
              entity_label="IamRole", on_resource=S.PROD_READER_ROLE, raw=raw)
    involves(ctx, a17_id, S.CRED_PROD_KEY, "credential", source="cloudtrail-sim", when=a17_ts)
    involves(ctx, a17_id, egress, "source", source="cloudtrail-sim", when=a17_ts)
    for key in ("a013", "a014", "a015", "a016"):
        involves(ctx, a17_id, S.CLOUDEVENTS_A[key][0], "object", source="cloudtrail-sim", when=a17_ts)
