"""Background noise so prioritization matters (docs/04 section 4).

Named benign/noise alerts with their exact ids (ldt-n001, ldt-n003, idp-n004, the 12 quarantine alerts),
~120 IDS alerts from the internal scanner, ~400 aggregated WAF alerts from many non-TI IPs, ~500 general EDR
detections across random endpoints, and small backgrounds of cloud-anomaly / Okta alerts so the section-7
category counts are met. ``iss-n002`` (the public-bucket CSPM finding) is **not** produced here -- the
inventory stage owns CSPM issues.
"""
from __future__ import annotations

from throughline.simulator import storyline_constants as S
from throughline.simulator.common import at, pick, rng
from throughline.simulator.events import processes
from throughline.simulator.events.ctx import Ctx, add_alert, falcon_raw, involves
from throughline.simulator.events.network import connected_to, doc_public_ips, domain_node, ip_node

# category sizes (see the section-4 vs section-7 note in the module/report)
N_IDS = 120
N_WAF = 400
N_GENERAL_EDR = 500
N_BG_CLOUD_ANOMALY = 9
N_BG_OKTA = 9

_GENERAL_TITLES = [
    ("Potentially unwanted program detected", ["T1204.002"], "medium"),
    ("Suspicious PowerShell in IT automation script", ["T1059.001"], "medium"),
    ("Office macro warning: external content", ["T1204.002"], "low"),
    ("LOLBin usage: certutil download", ["T1105"], "medium"),
    ("LOLBin usage: mshta remote content", ["T1218.005"], "medium"),
    ("Commodity malware quarantined", ["T1204.002"], "high"),
    ("Renamed system utility executed", ["T1036.003"], "low"),
    ("Scheduled task created by script", ["T1053.005"], "low"),
    ("Suspicious cron entry added", ["T1053.003"], "low"),
    ("Curl to uncategorized host", ["T1105"], "informational"),
]


def _login_of(user_id: str | None) -> str | None:
    return user_id.split(":")[-1] if user_id else None


# --------------------------------------------------------------------- named noise


def add_named_noise(ctx: Ctx) -> None:
    _ldt_n001(ctx)
    _ldt_n003(ctx)
    _idp_n004(ctx)
    _quarantine_alerts(ctx)


def _ldt_n001(ctx: Ctx) -> None:
    aid_ep = ctx.inv.endpoint(S.EP_DEV_SANDBOX)
    if not aid_ep:
        return
    nid, ts_, sev = S.ALERT_N["n001"]
    ep = S.EP_DEV_SANDBOX
    runner = processes.add_process(ctx, endpoint_id=ep, pid=3120, image_path="/usr/bin/wget",
                                   command_line="wget https://eicar.example/eicar.com -O /tmp/eicar.com",
                                   user="cirunner", start_time=ts_, signer="distro")
    eicar = processes.file_node(ctx, sha256=processes.fake_sha256("eicar"), file_name="eicar.com",
                                file_path="/tmp/eicar.com", verdict="malicious", size_bytes=68)
    processes.executed(ctx, runner, eicar, action="wrote", when=ts_)
    raw = falcon_raw(alert_id=nid, endpoint=aid_ep, severity=sev, techniques=[],
                     display_name="EICAR test file detected", description="EICAR anti-malware test file written and quarantined.",
                     disposition="quarantined", filename="eicar.com", filepath="/tmp/eicar.com",
                     cmdline="wget https://eicar.example/eicar.com -O /tmp/eicar.com",
                     sha256=eicar.split(":")[-1], user_name="cirunner", timestamp=ts_)
    add_alert(ctx, alert_id=nid, source_system="falcon", alert_type="detection", title="EICAR test file detected and quarantined",
              description="EICAR anti-malware test file detected on an isolated dev sandbox runner and quarantined.",
              severity=sev, detected_at=ts_, techniques=[], entity_id=ep, entity_label="Endpoint",
              on_endpoint=ep, hostname=aid_ep["hostname"], user="cirunner", raw=raw)
    involves(ctx, nid, eicar, "object", when=ts_)


def _ldt_n003(ctx: Ctx) -> None:
    ep_rec = ctx.inv.endpoint(S.EP_FILESHARE)
    if not ep_rec:
        return
    nid, ts_, sev = S.ALERT_N["n003"]
    ep = S.EP_FILESHARE
    psexe = processes.add_process(ctx, endpoint_id=ep, pid=4880, image_path="C:\\Windows\\PSEXESVC.exe",
                                  command_line="C:\\Windows\\PSEXESVC.exe", user="CORP\\mreyes", start_time=ts_,
                                  signer="Microsoft Corporation")
    processes.ran_as(ctx, psexe, S.USER_MREYES)
    raw = falcon_raw(alert_id=nid, endpoint=ep_rec, severity=sev, techniques=["T1569.002"],
                     display_name="PsExec service execution", description="PSEXESVC service executed by an administrator.",
                     disposition="detected", filename="PSEXESVC.exe", filepath="C:\\Windows\\PSEXESVC.exe",
                     cmdline="C:\\Windows\\PSEXESVC.exe", sha256=processes.SYS_HASHES["PSEXESVC.exe"],
                     user_name="CORP\\mreyes", timestamp=ts_)
    raw["change_ticket"] = S.CHANGE_TICKET
    raw["source_host"] = S.EP_MREYES_HOSTNAME
    add_alert(ctx, alert_id=nid, source_system="falcon", alert_type="detection",
              title="PsExec service execution", description="PsExec service execution by mreyes from WKS-2210 during an approved change window.",
              severity=sev, detected_at=ts_, techniques=["T1569.002"], entity_id=ep, entity_label="Endpoint",
              on_endpoint=ep, hostname=ep_rec["hostname"], user="CORP\\mreyes", change_ticket=S.CHANGE_TICKET, raw=raw)
    involves(ctx, nid, psexe, "subject", when=ts_)
    involves(ctx, nid, S.USER_MREYES, "subject", when=ts_)


def _idp_n004(ctx: Ctx) -> None:
    nid, ts_, sev = S.ALERT_N["n004"]
    vpn_ip = ip_node(ctx, S.VPN_EGRESS_IP, source="okta-sim", asn="AS64512",
                     asn_org="Larkspur Corporate VPN", country="US")
    raw = {
        "eventType": "policy.evaluate_sign_on",
        "displayMessage": "Impossible travel detected",
        "actor": {"id": S.USER_PKAUR, "alternateId": "pkaur@corp.larkspur.example", "displayName": "Priya Kaur"},
        "first_login": {"time": "2026-09-11T07:02:00Z", "city": "London", "country": "GB", "ip": "198.18.7.42"},
        "second_login": {"time": "2026-09-11T07:48:00Z", "city": "New York", "country": "US", "ip": S.VPN_EGRESS_IP},
        "outcome": {"result": "SUCCESS"}, "mfa": "satisfied",
        "note": "second login egress is the corporate VPN concentrator",
    }
    add_alert(ctx, alert_id=nid, source_system="okta", alert_type="identity",
              title="Impossible travel: London then New York", description="Two sign-ons 46 minutes apart from London then New York; second egress is the corporate VPN and MFA was satisfied.",
              severity=sev, detected_at=ts_, techniques=["T1078"], entity_id=S.USER_PKAUR, entity_label="HumanUser",
              on_resource=S.USER_PKAUR, user="pkaur", raw=raw)
    involves(ctx, nid, S.USER_PKAUR, "subject", source="okta-sim", when=ts_)
    involves(ctx, nid, vpn_ip, "source", source="okta-sim", when=ts_)


def _quarantine_alerts(ctx: Ctx) -> int:
    r = rng("events.noise.quarantine")
    workstations = ctx.inv.workstations()
    if not workstations:
        return 0
    n = 0
    for i, aid_full in enumerate(S.QUARANTINE_ALERT_IDS):
        ep_rec = workstations[i % len(workstations)]
        ep = ep_rec["id"]
        ts_ = at(f"2026-09-1{i % 2}T{8 + i % 8:02d}:{(i * 5) % 60:02d}:00Z")
        login = _login_of(ep_rec.get("primary_user_id")) or "user"
        user_str = f"CORP\\{login}" if ep_rec.get("os_family") == "windows" else login
        att_name = r.choice(["invoice.xlsm", "shipping_label.docm", "resume.doc", "statement.html", "order.iso"])
        outlook = processes.add_process(ctx, endpoint_id=ep, pid=3000 + i, image_path="C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE",
                                        command_line="OUTLOOK.EXE", user=user_str, start_time=ts_, signer="Microsoft Corporation")
        if ep_rec.get("primary_user_id"):
            processes.ran_as(ctx, outlook, ep_rec["primary_user_id"])
        att = processes.file_node(ctx, sha256=processes.fake_sha256("quarantine", i), file_name=att_name,
                                  file_path=f"C:\\Users\\{login}\\AppData\\Local\\Temp\\{att_name}",
                                  verdict="malicious", size_bytes=r.randint(20_000, 800_000))
        processes.executed(ctx, outlook, att, action="wrote", when=ts_)
        raw = falcon_raw(alert_id=aid_full, endpoint=ep_rec, severity="low", techniques=["T1204.002"],
                         display_name="Quarantined malicious attachment", description="Malicious email attachment blocked before execution.",
                         disposition="quarantined", filename=att_name,
                         filepath=f"C:\\Users\\{login}\\AppData\\Local\\Temp\\{att_name}", cmdline="OUTLOOK.EXE",
                         sha256=att.split(":")[-1], user_name=user_str, timestamp=ts_)
        add_alert(ctx, alert_id=aid_full, source_system="falcon", alert_type="detection",
                  title="Quarantined malicious attachment", description="A malicious email attachment was quarantined before execution.",
                  severity="low", detected_at=ts_, techniques=["T1204.002"], entity_id=ep, entity_label="Endpoint",
                  on_endpoint=ep, hostname=ep_rec["hostname"], user=user_str, raw=raw)
        involves(ctx, aid_full, att, "object", when=ts_)
        n += 1
    return n


# --------------------------------------------------------------------- bulk noise


def add_ids_alerts(ctx: Ctx, n: int = N_IDS) -> int:
    r = rng("events.noise.ids")
    targets = ctx.inv.prod_vms() or ctx.inv.vms
    if not targets:
        return 0
    scanner_ip = ip_node(ctx, S.SCANNER_IP, source="ids-sim")
    sigs = [
        ("2013028", "ET EXPLOIT Possible CVE-2021-44228 Log4j Exploit Attempt", "medium"),
        ("2024897", "ET SCAN Nmap Scripting Engine User-Agent", "low"),
        ("2019401", "ET EXPLOIT Apache Struts OGNL Injection", "medium"),
        ("2016184", "ET WEB_SERVER Generic SQL Injection Attempt", "low"),
        ("2027021", "ET EXPLOIT Spring4Shell Exploitation Attempt", "medium"),
        ("2033452", "ET SCAN Suspicious inbound to MSSQL port 1433", "low"),
    ]
    count = 0
    for i in range(n):
        vm = targets[i % len(targets)]
        sig_id, sig_name, sev = r.choice(sigs)
        ts_ = at(f"2026-09-1{i % 2}T{(6 + i) % 24:02d}:{(i * 13) % 60:02d}:{(i * 7) % 60:02d}Z")
        nid = f"alert:ids:ids-n{100 + i}"
        raw = {"sig_id": sig_id, "sig_name": sig_name, "category": "Attempted Exploitation", "src_ip": S.SCANNER_IP,
               "dst_ip": vm.get("private_ip"), "dst_port": r.choice([80, 443, 8080, 1433, 22]), "severity": sev,
               "action": "alerted", "sensor": "ids-shared-01",
               "note": "source is the internal vulnerability scanner (vulnscan-01)"}
        add_alert(ctx, alert_id=nid, source_system="ids", alert_type="network", title=sig_name,
                  description=f"IDS signature {sig_id} fired; source is the internal vulnerability scanner.",
                  severity=sev, detected_at=ts_, techniques=["T1595.002"], entity_id=vm["id"],
                  entity_label="VirtualMachine", on_resource=vm["id"], hostname=vm.get("name"), raw=raw)
        involves(ctx, nid, scanner_ip, "source", source="ids-sim", when=ts_)
        count += 1
    return count


def add_waf_alerts(ctx: Ctx, n: int = N_WAF) -> int:
    r = rng("events.noise.waf")
    targets = ctx.inv.internet_vms() or ctx.inv.prod_vms() or ctx.inv.vms
    if not targets:
        return 0
    pool = doc_public_ips(n + 8)
    rules = [
        ("942100", "SQL Injection Attack Detected via libinjection", "low"),
        ("941100", "XSS Attack Detected via libinjection", "low"),
        ("930100", "Path Traversal Attack (/../)", "low"),
        ("913100", "Found User-Agent associated with security scanner", "low"),
        ("944130", "Remote Command Execution: Log4j / JNDI lookup", "medium"),
        ("932150", "Remote Command Execution: Direct Unix command", "medium"),
    ]
    count = 0
    for i in range(n):
        vm = targets[i % len(targets)]
        rule_id, rule_name, sev = r.choice(rules)
        addr = pool[i % len(pool)]
        src = ip_node(ctx, addr, source="waf-sim", asn=f"AS{64520 + (i % 40)}",
                      asn_org="Uncategorized Hosting (fictional)", country=r.choice(["US", "CN", "RU", "BR", "IN", "DE", "NL"]))
        ts_ = at(f"2026-09-{9 + i % 3:02d}T{(i * 3) % 24:02d}:{(i * 11) % 60:02d}:{(i * 5) % 60:02d}Z")
        nid = f"alert:waf:waf-n{i + 1:03d}"
        raw = {"rule_id": rule_id, "rule_name": rule_name, "action": "alert", "http_method": r.choice(["GET", "POST"]),
               "uri": r.choice(["/", "/login", "/api/v1/search", "/wp-login.php", "/actuator/env"]),
               "source_ip": addr, "target_host": vm.get("hostname") or vm.get("name"), "count": r.randint(1, 12),
               "note": "generic scanner exploit pattern; target not vulnerable"}
        add_alert(ctx, alert_id=nid, source_system="waf", alert_type="network", title=rule_name,
                  description=f"WAF rule {rule_id} matched a generic scanner pattern against a public host.",
                  severity=sev, detected_at=ts_, techniques=["T1190"], entity_id=vm["id"],
                  entity_label="VirtualMachine", on_resource=vm["id"], hostname=vm.get("name"), raw=raw)
        involves(ctx, nid, src, "source", source="waf-sim", when=ts_)
        count += 1
    return count


def add_general_edr(ctx: Ctx, n: int = N_GENERAL_EDR) -> int:
    r = rng("events.noise.general")
    endpoints = ctx.inv.workstations() + ctx.inv.servers()
    if not endpoints:
        return 0
    ext_pool = doc_public_ips(300)
    sev_weights = {"informational": 0.1, "low": 0.45, "medium": 0.3, "high": 0.1, "critical": 0.05}
    count = 0
    for i in range(n):
        ep_rec = endpoints[(i * 7 + 3) % len(endpoints)]
        ep = ep_rec["id"]
        os_family = ep_rec.get("os_family", "windows")
        title, techs, base_sev = r.choice(_GENERAL_TITLES)
        sev = base_sev if r.random() < 0.5 else pick(r, sev_weights)
        malicious = "Commodity malware" in title or (r.random() < 0.06)
        ts_ = at(f"2026-09-{5 + i % 7:02d}T{(i * 5) % 24:02d}:{(i * 17) % 60:02d}:{(i * 3) % 60:02d}Z")
        login = _login_of(ep_rec.get("primary_user_id"))
        principal = ep_rec.get("primary_user_id")
        if os_family == "windows":
            user_str = f"CORP\\{login}" if login else "CORP\\SYSTEM"
        else:
            user_str = login or "root"
        ext_host = None
        involve_ext = None
        if any(t in ("T1105", "T1218.005") for t in techs) and r.random() < 0.7:
            if r.random() < 0.5:
                ext_host = ext_pool[(i * 3) % len(ext_pool)]
                involve_ext = ip_node(ctx, ext_host, source="falcon-sim", asn=f"AS{64530 + i % 30}",
                                      asn_org="Uncategorized (fictional)", country="US")
            else:
                fqdn = f"dl-{processes.fake_sha256('noise-dom', i)[:8]}.example-cdn.net"
                ext_host = fqdn
                involve_ext = domain_node(ctx, fqdn, source="falcon-sim", registered_days_ago=r.randint(30, 2000))
        tree = processes.generic_tree(ctx, ep, os_family=os_family, user=user_str, detected_at=ts_,
                                      namespace=f"events.noise.general.{i}", malicious=malicious,
                                      external_host=ext_host, principal_id=principal)
        nid = f"alert:falcon:ldt-g{i + 1:03d}"
        raw = falcon_raw(alert_id=nid, endpoint=ep_rec, severity=sev, techniques=tree["techniques"] or techs,
                         display_name=title, description=title, disposition="quarantined" if malicious else "detected",
                         filename=tree["file_name"], filepath=tree["file_path"], cmdline=tree["command_line"],
                         sha256=tree["sha256"], user_name=user_str, timestamp=ts_,
                         parent={"process_id": tree["parent"]})
        add_alert(ctx, alert_id=nid, source_system="falcon", alert_type="detection", title=title,
                  description=title, severity=sev, detected_at=ts_, techniques=tree["techniques"] or techs,
                  entity_id=ep, entity_label="Endpoint", on_endpoint=ep, hostname=ep_rec.get("hostname"),
                  user=user_str, raw=raw)
        involves(ctx, nid, tree["primary"], "subject", when=ts_)
        involves(ctx, nid, tree["file"], "object", when=ts_)
        if involve_ext:
            involves(ctx, nid, involve_ext, "destination", when=ts_)
        count += 1
    return count


_WIN_CHAIN = [
    ("C:\\Windows\\System32\\services.exe", "services.exe", "NT AUTHORITY\\SYSTEM"),
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p", "NT AUTHORITY\\SYSTEM"),
    ("C:\\Windows\\explorer.exe", "explorer.exe", None),
    ("C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE", "OUTLOOK.EXE", None),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer", None),
    ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe", None),
]
_NIX_CHAIN = [
    ("/usr/lib/systemd/systemd", "/sbin/init", "root"),
    ("/usr/sbin/sshd", "sshd: session", "root"),
    ("/usr/bin/containerd-shim", "containerd-shim -namespace moby", "root"),
    ("/usr/bin/node", "node /srv/app/server.js", "app"),
    ("/usr/bin/python3", "python3 /srv/jobs/worker.py", "app"),
    ("/usr/bin/bash", "-bash", None),
]


def add_background_activity(ctx: Ctx, n_trees: int) -> dict:
    """Benign process/file/network telemetry samples across the fleet.

    EDR sensors stream process telemetry continuously; the graph stores a sample so the endpoint-telemetry
    volumes (processes/files/external hosts) match docs/04 section 7 rather than only the alerted trees.
    """
    r = rng("events.noise.telemetry")
    eps = ctx.inv.workstations() + ctx.inv.servers()
    if not eps:
        return {"processes": 0, "files": 0, "external": 0}
    ip_pool = doc_public_ips(760)
    p_count = f_count = x_count = 0
    for i in range(n_trees):
        ep_rec = eps[(i * 13 + 5) % len(eps)]
        ep = ep_rec["id"]
        osf = ep_rec.get("os_family", "windows")
        chain = _WIN_CHAIN if osf == "windows" else _NIX_CHAIN
        depth = r.randint(3, 6)
        ts_ = at(f"2026-09-{5 + i % 7:02d}T{(i * 5) % 24:02d}:{(i * 7) % 60:02d}:{(i * 11) % 60:02d}Z")
        base_pid = r.randint(600, 60000)
        parent = None
        leaf = None
        for depth_i in range(depth):
            img, cmd, fixed_user = chain[depth_i % len(chain)]
            login = _login_of(ep_rec.get("primary_user_id"))
            user = fixed_user or (f"CORP\\{login}" if osf == "windows" and login else (login or "app"))
            proc = processes.add_process(ctx, endpoint_id=ep, pid=base_pid + depth_i, image_path=img,
                                         command_line=cmd, user=user, start_time=ts_, parent_id=parent,
                                         signer="Microsoft Corporation" if osf == "windows" else "distro")
            if parent is not None:
                processes.spawn(ctx, parent, proc, when=ts_)
            parent = proc
            leaf = proc
            p_count += 1
        if leaf and r.random() < 0.62:
            fsha = processes.fake_sha256("bg-telemetry", i)
            fnode = processes.file_node(ctx, sha256=fsha, file_name=f"artifact_{i % 500}.dat",
                                        file_path=f"/var/tmp/artifact_{i % 500}.dat" if osf != "windows"
                                        else f"C:\\Users\\Public\\artifact_{i % 500}.dat",
                                        verdict="clean", size_bytes=r.randint(1024, 5_000_000), signed=True)
            processes.executed(ctx, leaf, fnode, action="wrote", when=ts_)
            f_count += 1
        if leaf and r.random() < 0.45:
            if r.random() < 0.5:
                addr = ip_pool[(400 + i) % len(ip_pool)]
                dst = ip_node(ctx, addr, source="falcon-sim", asn=f"AS{64560 + i % 30}",
                              asn_org="Uncategorized (fictional)", country=r.choice(["US", "GB", "DE", "SG"]))
            else:
                fqdn = f"svc-{processes.fake_sha256('bg-dom', i)[:8]}.example-svc.net"
                dst = domain_node(ctx, fqdn, source="falcon-sim", registered_days_ago=r.randint(60, 3000))
            connected_to(ctx, leaf, dst, port=r.choice([80, 443, 443, 8443]), protocol="tls",
                         count=r.randint(1, 50), bytes_out=r.randint(1024, 2_000_000), first_time=ts_)
            x_count += 1
    return {"processes": p_count, "files": f_count, "external": x_count}


def add_background_cloud_anomaly(ctx: Ctx, n: int = N_BG_CLOUD_ANOMALY) -> int:
    r = rng("events.noise.cloud-anomaly")
    roles = [role["id"] for role in ctx.inv.roles]
    users = [u["id"] for u in ctx.inv.users]
    subjects = [("IamRole", rid) for rid in roles] + [("HumanUser", uid) for uid in users]
    if not subjects:
        return 0
    templates = [
        ("Unusual API call volume for role", "low", ["T1580"]),
        ("Access from new but known corporate ASN", "low", ["T1078.004"]),
        ("First-time region access (benign migration)", "informational", ["T1580"]),
        ("Console login outside usual hours", "low", ["T1078"]),
    ]
    count = 0
    for i in range(n):
        label, subj = subjects[i % len(subjects)]
        title, sev, techs = r.choice(templates)
        ts_ = at(f"2026-09-{7 + i % 4:02d}T{(i * 6) % 24:02d}:{(i * 9) % 60:02d}:00Z")
        nid = f"alert:cloud-anomaly:ca-n{i + 1:03d}"
        raw = {"detector": "role-usage-baseline", "principal": subj, "severity": sev, "anomalous": True,
               "explained": True, "note": "within known corporate ranges / expected change"}
        add_alert(ctx, alert_id=nid, source_system="cloud-anomaly", alert_type="cloud", title=title,
                  description=f"{title} (benign, explained by known baseline).", severity=sev, detected_at=ts_,
                  techniques=techs, entity_id=subj, entity_label=label, on_resource=subj, raw=raw)
        count += 1
    return count


def add_background_okta(ctx: Ctx, n: int = N_BG_OKTA) -> int:
    r = rng("events.noise.okta")
    users = [u["id"] for u in ctx.inv.users]
    if not users:
        return 0
    templates = [
        ("New device sign-on", "low", ["T1078"]),
        ("MFA fatigue: repeated push (denied)", "medium", ["T1621"]),
        ("Sign-on from new geolocation (VPN)", "low", ["T1078"]),
        ("Password reset self-service", "informational", []),
    ]
    count = 0
    for i in range(n):
        uid = users[(i * 5 + 1) % len(users)]
        title, sev, techs = r.choice(templates)
        ts_ = at(f"2026-09-{8 + i % 3:02d}T{(i * 4) % 24:02d}:{(i * 7) % 60:02d}:00Z")
        nid = f"alert:okta:idp-n{i + 5:03d}"
        raw = {"eventType": "policy.evaluate_sign_on", "displayMessage": title,
               "actor": {"id": uid, "alternateId": f"{uid.split(':')[-1]}@corp.larkspur.example"},
               "outcome": {"result": "DENY" if "denied" in title else "SUCCESS"}, "mfa": "satisfied"}
        add_alert(ctx, alert_id=nid, source_system="okta", alert_type="identity", title=title,
                  description=f"{title} (benign background identity signal).", severity=sev, detected_at=ts_,
                  techniques=techs, entity_id=uid, entity_label="HumanUser", on_resource=uid,
                  user=uid.split(":")[-1], raw=raw)
        count += 1
    return count
