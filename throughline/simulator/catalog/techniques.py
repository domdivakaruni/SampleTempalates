"""MITRE ATT&CK technique catalog used by alerts, threat actors and storylines.

Names and tactics follow the public ATT&CK matrix (Enterprise). The kill-chain stage is our own 1-7 mapping used
for ordering storylines: 1 initial access/recon, 2 execution, 3 persistence & evasion, 4 credential access &
discovery, 5 lateral movement & privilege escalation, 6 collection & command-and-control, 7 exfiltration & impact.
"""
from __future__ import annotations

KILL_CHAIN_STAGES: dict[int, str] = {
    1: "Initial Access",
    2: "Execution",
    3: "Persistence & Evasion",
    4: "Credential Access & Discovery",
    5: "Lateral Movement & Privilege Escalation",
    6: "Collection & Command and Control",
    7: "Exfiltration & Impact",
}

TACTIC_STAGE: dict[str, int] = {
    "Reconnaissance": 1,
    "Resource Development": 1,
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Defense Evasion": 3,
    "Privilege Escalation": 5,
    "Credential Access": 4,
    "Discovery": 4,
    "Lateral Movement": 5,
    "Collection": 6,
    "Command and Control": 6,
    "Exfiltration": 7,
    "Impact": 7,
}

# (technique_id, name, tactic)
_TECHNIQUES: list[tuple[str, str, str]] = [
    ("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    ("T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("T1133", "External Remote Services", "Initial Access"),
    ("T1078", "Valid Accounts", "Initial Access"),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    ("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access"),
    ("T1204.001", "User Execution: Malicious Link", "Execution"),
    ("T1204.002", "User Execution: Malicious File", "Execution"),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution"),
    ("T1059.006", "Command and Scripting Interpreter: Python", "Execution"),
    ("T1569.002", "System Services: Service Execution", "Execution"),
    ("T1053.003", "Scheduled Task/Job: Cron", "Execution"),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", "Execution"),
    ("T1648", "Serverless Execution", "Execution"),
    ("T1651", "Cloud Administration Command", "Execution"),
    ("T1610", "Deploy Container", "Execution"),
    ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    ("T1543.003", "Create or Modify System Process: Windows Service", "Persistence"),
    ("T1505.003", "Server Software Component: Web Shell", "Persistence"),
    ("T1136.003", "Create Account: Cloud Account", "Persistence"),
    ("T1098", "Account Manipulation", "Persistence"),
    ("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence"),
    ("T1556.006", "Modify Authentication Process: Multi-Factor Authentication", "Persistence"),
    ("T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    ("T1055", "Process Injection", "Defense Evasion"),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    ("T1036.005", "Masquerading: Match Legitimate Name or Location", "Defense Evasion"),
    ("T1070.004", "Indicator Removal: File Deletion", "Defense Evasion"),
    ("T1070.006", "Indicator Removal: Timestomp", "Defense Evasion"),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    ("T1112", "Modify Registry", "Defense Evasion"),
    ("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", "Privilege Escalation"),
    ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    ("T1484.001", "Domain or Tenant Policy Modification: Group Policy Modification", "Privilege Escalation"),
    ("T1611", "Escape to Host", "Privilege Escalation"),
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    ("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
    ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access"),
    ("T1552.004", "Unsecured Credentials: Private Keys", "Credential Access"),
    ("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access"),
    ("T1621", "Multi-Factor Authentication Request Generation", "Credential Access"),
    ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", "Credential Access"),
    ("T1087.002", "Account Discovery: Domain Account", "Discovery"),
    ("T1018", "Remote System Discovery", "Discovery"),
    ("T1057", "Process Discovery", "Discovery"),
    ("T1082", "System Information Discovery", "Discovery"),
    ("T1083", "File and Directory Discovery", "Discovery"),
    ("T1046", "Network Service Discovery", "Discovery"),
    ("T1580", "Cloud Infrastructure Discovery", "Discovery"),
    ("T1526", "Cloud Service Discovery", "Discovery"),
    ("T1538", "Cloud Service Dashboard", "Discovery"),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    ("T1021.004", "Remote Services: SSH", "Lateral Movement"),
    ("T1021.006", "Remote Services: Windows Remote Management", "Lateral Movement"),
    ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "Lateral Movement"),
    ("T1005", "Data from Local System", "Collection"),
    ("T1530", "Data from Cloud Storage", "Collection"),
    ("T1074.001", "Data Staged: Local Data Staging", "Collection"),
    ("T1114.002", "Email Collection: Remote Email Collection", "Collection"),
    ("T1119", "Automated Collection", "Collection"),
    ("T1560.001", "Archive Collected Data: Archive via Utility", "Collection"),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ("T1573.002", "Encrypted Channel: Asymmetric Cryptography", "Command and Control"),
    ("T1105", "Ingress Tool Transfer", "Command and Control"),
    ("T1090", "Proxy", "Command and Control"),
    ("T1219", "Remote Access Software", "Command and Control"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration"),
    ("T1048.003", "Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol", "Exfiltration"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
    ("T1490", "Inhibit System Recovery", "Impact"),
    ("T1496", "Resource Hijacking", "Impact"),
]

TECHNIQUES: dict[str, dict[str, object]] = {
    tid: {"technique_id": tid, "name": name, "tactic": tactic, "kill_chain_stage": TACTIC_STAGE[tactic]}
    for tid, name, tactic in _TECHNIQUES
}


def technique_node_id(tid: str) -> str:
    return f"technique:attack:{tid}"


def stage_of(technique_ids: list[str]) -> int:
    """Most advanced kill-chain stage among the given techniques (0 if none known)."""
    return max((int(TECHNIQUES[t]["kill_chain_stage"]) for t in technique_ids if t in TECHNIQUES), default=0)


def tactic_of(technique_ids: list[str]) -> str | None:
    for t in technique_ids:
        if t in TECHNIQUES:
            return str(TECHNIQUES[t]["tactic"])
    return None
