"""Canonical schema registry for the Throughline security context graph.

This module is the executable form of docs/03-graph-schema.md. Everything that needs to know a label,
an edge type, a typed column or an allowed (from, to) pair imports it from here:

* the simulator validates the records it emits,
* the LadybugDB/Kuzu store compiles it to DDL (one node table per label, one rel table per edge type
  with all allowed pairs), the Neo4j store to constraints/indexes,
* the API exposes it at GET /v1/schema so agents can plan Cypher queries,
* the web UI mirrors the categories for icons and colours.

Column types: STRING, INT64, DOUBLE, BOOLEAN, TIMESTAMP, STRING[] and JSON (JSON is serialised to a STRING
column named the same; loaders json.dumps the value).
"""
from __future__ import annotations

from dataclasses import dataclass

# ----------------------------------------------------------------------------- core types


@dataclass(frozen=True)
class Column:
    name: str
    type: str  # STRING | INT64 | DOUBLE | BOOLEAN | TIMESTAMP | STRING[] | JSON

    @property
    def ddl_type(self) -> str:
        return "STRING" if self.type == "JSON" else self.type


@dataclass(frozen=True)
class NodeLabel:
    name: str
    category: str
    id_prefix: str
    columns: tuple[Column, ...] = ()
    description: str = ""

    def column_names(self) -> list[str]:
        return [c.name for c in self.columns]


@dataclass(frozen=True)
class EdgeType:
    name: str
    pairs: tuple[tuple[str, str], ...]
    columns: tuple[Column, ...] = ()
    derived: bool = False
    description: str = ""

    def allows(self, src_label: str, dst_label: str) -> bool:
        return (src_label, dst_label) in self.pairs


def C(name: str, type: str = "STRING") -> Column:  # noqa: N802 - terse constructor for tables below
    return Column(name, type)


COMMON_NODE_COLUMNS: tuple[Column, ...] = (
    C("id"),
    C("name"),
    C("source"),
    C("source_id"),
    C("first_seen", "TIMESTAMP"),
    C("last_seen", "TIMESTAMP"),
    C("confidence", "DOUBLE"),
    C("props", "JSON"),
)

COMMON_EDGE_COLUMNS: tuple[Column, ...] = (
    C("source"),
    C("first_seen", "TIMESTAMP"),
    C("last_seen", "TIMESTAMP"),
    C("confidence", "DOUBLE"),
    C("props", "JSON"),
)

CATEGORIES: dict[str, str] = {
    "cloud": "Cloud & infrastructure",
    "identity": "Identity & access",
    "software": "Software & vulnerabilities",
    "business": "Business context",
    "endpoint": "Endpoint & runtime telemetry",
    "alerts": "Alerts, events & storylines",
    "threat_intel": "Threat intelligence",
}

# ----------------------------------------------------------------------------- node labels

_ENV = C("environment")
_PROVIDER = C("provider")
_ACCOUNT = C("account_id")
_SENS = C("sensitivity")
_CLASS = C("data_classifications", "STRING[]")

_LABELS: list[NodeLabel] = [
    # cloud
    NodeLabel("CloudAccount", "cloud", "account", (_PROVIDER, _ACCOUNT, _ENV, C("purpose"))),
    NodeLabel("VPC", "cloud", "vpc", (_PROVIDER, _ACCOUNT, C("cidr"), C("region"))),
    NodeLabel("Subnet", "cloud", "subnet", (_PROVIDER, _ACCOUNT, C("cidr"), C("region"), C("public", "BOOLEAN"))),
    NodeLabel("SecurityGroup", "cloud", "sg", (_PROVIDER, _ACCOUNT, C("inbound_rules", "JSON"), C("open_to_internet", "BOOLEAN"), C("internet_ports", "STRING[]"))),
    NodeLabel("LoadBalancer", "cloud", "lb", (_PROVIDER, _ACCOUNT, C("scheme"), C("dns_name"), C("listeners", "STRING[]"))),
    NodeLabel(
        "VirtualMachine",
        "cloud",
        "vm",
        (
            _PROVIDER, _ACCOUNT, C("region"), C("hostname"), C("private_ip"), C("public_ip"), C("os"), C("os_family"),
            C("instance_type"), _ENV, C("exposure"), C("has_edr_sensor", "BOOLEAN"), C("is_k8s_node", "BOOLEAN"),
            C("tags", "JSON"), C("criticality"), C("ti_exposure_score", "DOUBLE"), C("crown_jewel_reach", "INT64"),
        ),
    ),
    NodeLabel("KubernetesCluster", "cloud", "k8s", (_PROVIDER, _ACCOUNT, C("version"), _ENV, C("public_endpoint", "BOOLEAN"))),
    NodeLabel("Workload", "cloud", "workload", (C("kind"), C("namespace"), C("cluster_id"), C("image"), C("exposure"), _ENV, C("privileged", "BOOLEAN"), C("service_account"))),
    NodeLabel("ContainerImage", "cloud", "image", (C("registry"), C("repository"), C("tag"), C("digest"), C("vuln_count_critical", "INT64"), C("vuln_count_high", "INT64"))),
    NodeLabel("ServerlessFunction", "cloud", "function", (_PROVIDER, _ACCOUNT, C("runtime"), C("exposure"), _ENV, C("url_enabled", "BOOLEAN"))),
    NodeLabel(
        "StorageBucket",
        "cloud",
        "bucket",
        (_PROVIDER, _ACCOUNT, C("region"), C("public", "BOOLEAN"), C("encrypted", "BOOLEAN"), C("versioning", "BOOLEAN"), _CLASS, _SENS,
         C("crown_jewel", "BOOLEAN"), C("size_gb", "DOUBLE"), _ENV, C("contains_credentials_for", "STRING[]")),
    ),
    NodeLabel("Database", "cloud", "database", (_PROVIDER, _ACCOUNT, C("engine"), C("public", "BOOLEAN"), C("encrypted", "BOOLEAN"), _CLASS, _SENS, C("crown_jewel", "BOOLEAN"), _ENV, C("exposure"))),
    NodeLabel("Secret", "cloud", "secret", (_PROVIDER, _ACCOUNT, C("secret_type"), _SENS, C("rotated_days_ago", "INT64"), C("grants_access_to", "STRING[]"))),
    NodeLabel("Internet", "cloud", "internet", ()),
    NodeLabel("IpAddress", "cloud", "ip", (C("address"), C("is_private", "BOOLEAN"), C("asn"), C("asn_org"), C("country"), C("reputation"))),
    NodeLabel("Domain", "cloud", "domain", (C("fqdn"), C("registered_days_ago", "INT64"), C("reputation"))),
    # identity
    NodeLabel("IamRole", "identity", "role", (_PROVIDER, _ACCOUNT, C("arn"), C("role_type"), C("is_admin", "BOOLEAN"), C("privilege_score", "DOUBLE"), C("trust_principals", "STRING[]"), C("last_used", "TIMESTAMP"), _ENV)),
    NodeLabel("IamUser", "identity", "iamuser", (_PROVIDER, _ACCOUNT, C("arn"), C("is_admin", "BOOLEAN"), C("mfa_enabled", "BOOLEAN"), C("console_access", "BOOLEAN"), C("privilege_score", "DOUBLE"))),
    NodeLabel("IamPolicy", "identity", "policy", (_PROVIDER, _ACCOUNT, C("managed", "BOOLEAN"), C("statements", "JSON"), C("access_levels", "STRING[]"), C("wildcard_resource", "BOOLEAN"), C("wildcard_action", "BOOLEAN"))),
    NodeLabel("AccessKey", "identity", "accesskey", (_PROVIDER, _ACCOUNT, C("owner_id"), C("status"), C("age_days", "INT64"), C("last_used", "TIMESTAMP"))),
    NodeLabel("ServiceAccount", "identity", "identity", (C("system"), C("host_id"), C("purpose"), C("privileged", "BOOLEAN"))),
    NodeLabel("HumanUser", "identity", "user", (C("email"), C("display_name"), C("title"), C("department"), C("team_id"), C("location"), C("is_privileged", "BOOLEAN"), C("is_executive", "BOOLEAN"), C("mfa_enabled", "BOOLEAN"), C("status"))),
    NodeLabel("Group", "identity", "group", (C("description"), C("member_count", "INT64"), C("privileged", "BOOLEAN"))),
    NodeLabel("Credential", "identity", "credential", (C("credential_type"), C("principal_id"), C("issued_at", "TIMESTAMP"), C("expires_at", "TIMESTAMP"), C("status"), C("derived_from"))),
    # software
    NodeLabel("Package", "software", "package", (C("package_name"), C("version"), C("ecosystem"), C("scope"))),
    NodeLabel(
        "Vulnerability",
        "software",
        "cve",
        (C("cve_id"), C("cvss", "DOUBLE"), C("epss", "DOUBLE"), C("kev", "BOOLEAN"), C("severity"), C("published", "TIMESTAMP"), C("exploitation_status"),
         C("actor_interest", "STRING[]"), C("sector_targeting_relevance", "DOUBLE"), C("ti_report_ids", "STRING[]"), C("synthetic", "BOOLEAN"), C("description"), C("affected_component")),
    ),
    # business
    NodeLabel("Application", "business", "app", (C("criticality"), _ENV, C("owner_team_id"), C("description"), _CLASS)),
    NodeLabel("Team", "business", "team", (C("department"), C("lead_user_id"), C("oncall_channel"))),
    # endpoint
    NodeLabel(
        "Endpoint",
        "endpoint",
        "endpoint",
        (C("hostname"), C("device_type"), C("os"), C("os_family"), C("private_ip"), C("public_ip"), C("site"), C("sensor_version"), C("last_seen_sensor", "TIMESTAMP"),
         C("cloud_provider"), C("cloud_instance_id"), C("cloud_account_id"), C("primary_user_id"), C("containment_status"), C("ou")),
    ),
    NodeLabel("Process", "endpoint", "process", (C("endpoint_id"), C("pid", "INT64"), C("parent_process_id"), C("image_path"), C("command_line"), C("user"), C("sha256"), C("signed", "BOOLEAN"), C("signer"), C("start_time", "TIMESTAMP"), C("end_time", "TIMESTAMP"), C("integrity_level"))),
    NodeLabel("File", "endpoint", "file", (C("sha256"), C("file_name"), C("file_path"), C("size_bytes", "INT64"), C("signed", "BOOLEAN"), C("malware_family"), C("verdict"))),
    NodeLabel("LogonSession", "endpoint", "logon", (C("endpoint_id"), C("user_id"), C("logon_type"), C("source_ip"), C("success", "BOOLEAN"), C("logon_time", "TIMESTAMP"))),
    # alerts
    NodeLabel(
        "Alert",
        "alerts",
        "alert",
        (C("source_system"), C("alert_type"), C("title"), C("description"), C("vendor_severity"), C("vendor_severity_rank", "INT64"), C("status"), C("detected_at", "TIMESTAMP"),
         C("techniques", "STRING[]"), C("tactic"), C("entity_id"), C("entity_label"), C("hostname"), C("user"), C("vendor_incident_id"), C("change_ticket"), C("raw", "JSON"),
         C("contextual_score", "INT64"), C("contextual_band"), C("score_breakdown", "JSON"), C("storyline_id"), C("graph_reasons", "STRING[]"), C("ti_actor_ids", "STRING[]"),
         C("ioc_match_count", "INT64"), C("reaches_crown_jewel", "BOOLEAN"), C("on_attack_path", "BOOLEAN")),
    ),
    NodeLabel("Incident", "alerts", "incident", (C("vendor_severity"), C("status"), C("start_time", "TIMESTAMP"), C("end_time", "TIMESTAMP"), C("alert_count", "INT64"), C("hosts", "STRING[]"), C("description"))),
    NodeLabel(
        "CloudEvent",
        "alerts",
        "cloudevent",
        (_PROVIDER, _ACCOUNT, C("event_name"), C("event_source"), C("event_time", "TIMESTAMP"), C("principal_id"), C("principal_arn"), C("access_key_id"), C("source_ip"), C("user_agent"),
         C("success", "BOOLEAN"), C("error_code"), C("target_id"), C("count", "INT64"), C("bytes", "INT64"), C("anomalous", "BOOLEAN"), C("anomaly_reasons", "STRING[]")),
    ),
    NodeLabel(
        "Storyline",
        "alerts",
        "storyline",
        (C("title"), C("summary"), C("actor_id"), C("campaign_id"), C("stage_count", "INT64"), C("alert_ids", "STRING[]"), C("crown_jewels_reached", "STRING[]"),
         C("first_event", "TIMESTAMP"), C("last_event", "TIMESTAMP"), C("contextual_score", "INT64"), C("stages", "JSON")),
    ),
    # threat intel
    NodeLabel("ThreatActor", "threat_intel", "actor", (C("aliases", "STRING[]"), C("motivation"), C("origin"), C("sophistication"), C("targeted_sectors", "STRING[]"), C("targeted_regions", "STRING[]"), C("sector_targeting_relevance", "DOUBLE"), C("active", "BOOLEAN"), C("description"))),
    NodeLabel("Campaign", "threat_intel", "campaign", (C("actor_id"), C("status"), C("started", "TIMESTAMP"), C("objective"), C("targeted_sectors", "STRING[]"), C("sector_targeting_relevance", "DOUBLE"), C("description"))),
    NodeLabel("Malware", "threat_intel", "malware", (C("family"), C("malware_type"), C("platforms", "STRING[]"), C("description"))),
    NodeLabel("AttackTechnique", "threat_intel", "technique", (C("technique_id"), C("tactic"), C("kill_chain_stage", "INT64"), C("description"))),
    NodeLabel("Indicator", "threat_intel", "ioc", (C("ioc_type"), C("value"), C("report_id"), C("actor_id"), C("campaign_id"), C("malware_id"), C("kill_chain_stage", "INT64"), C("active", "BOOLEAN"))),
    NodeLabel(
        "IntelReport",
        "threat_intel",
        "report",
        (C("title"), C("published", "TIMESTAMP"), C("publisher"), C("report_confidence"), C("tlp"), C("summary"), C("actor_ids", "STRING[]"), C("campaign_ids", "STRING[]"),
         C("cve_ids", "STRING[]"), C("technique_ids", "STRING[]"), C("indicator_count", "INT64"), C("targeted_sectors", "STRING[]"), C("body")),
    ),
]

LABELS: dict[str, NodeLabel] = {lbl.name: lbl for lbl in _LABELS}
_PREFIX_TO_LABEL: dict[str, str] = {lbl.id_prefix: lbl.name for lbl in _LABELS}

# ----------------------------------------------------------------------------- edge types

COMPUTE = ("VirtualMachine", "Workload", "ServerlessFunction", "KubernetesCluster")
DATA_HOLDERS = ("StorageBucket", "Database", "Secret")
CLOUD_RESOURCES = ("VPC", "VirtualMachine", "StorageBucket", "Database", "Secret", "IamRole", "IamUser", "IamPolicy", "ServerlessFunction", "KubernetesCluster", "SecurityGroup", "LoadBalancer")
PRINCIPALS = ("IamRole", "IamUser", "HumanUser")
ALERT_RESOURCES = ("VirtualMachine", "StorageBucket", "Database", "IamRole", "IamUser", "SecurityGroup", "LoadBalancer", "ServerlessFunction", "Workload", "KubernetesCluster", "HumanUser", "AccessKey", "Secret", "CloudAccount", "Endpoint")
STORYLINE_MEMBERS = ("Alert", "CloudEvent", "Endpoint", "VirtualMachine", "Credential", "IamRole", "StorageBucket", "Secret", "Database", "HumanUser", "Process", "IpAddress", "Domain", "File", "Vulnerability")


def _pairs(srcs: tuple[str, ...] | str, dsts: tuple[str, ...] | str) -> tuple[tuple[str, str], ...]:
    s = (srcs,) if isinstance(srcs, str) else srcs
    d = (dsts,) if isinstance(dsts, str) else dsts
    return tuple((a, b) for a in s for b in d)


_EDGE_TYPES: list[EdgeType] = [
    # cloud structure and network
    EdgeType("CONTAINS", _pairs("CloudAccount", CLOUD_RESOURCES)),
    EdgeType("IN_VPC", _pairs("Subnet", "VPC")),
    EdgeType("IN_SUBNET", _pairs(("VirtualMachine", "LoadBalancer", "Database"), "Subnet")),
    EdgeType("HAS_SECURITY_GROUP", _pairs(("VirtualMachine", "LoadBalancer", "Database"), "SecurityGroup")),
    EdgeType("ROUTES_TO", _pairs("LoadBalancer", ("VirtualMachine", "Workload")), (C("port", "INT64"),)),
    EdgeType("EXPOSES", _pairs("Internet", ("VirtualMachine", "LoadBalancer", "StorageBucket", "Database", "ServerlessFunction", "Workload", "KubernetesCluster")), (C("ports", "STRING[]"), C("via"), C("protocol")), derived=True),
    EdgeType("HAS_NODE", _pairs("KubernetesCluster", "VirtualMachine")),
    EdgeType("RUNS_ON", _pairs("Workload", "KubernetesCluster")),
    EdgeType("RUNS_IMAGE", _pairs(("Workload", "VirtualMachine"), "ContainerImage")),
    EdgeType("HAS_PACKAGE", _pairs(("VirtualMachine", "ContainerImage", "ServerlessFunction"), "Package")),
    EdgeType("HAS_VULNERABILITY", _pairs("Package", "Vulnerability"), (C("fixed_version"),)),
    EdgeType("VULNERABLE_TO", _pairs(("VirtualMachine", "ContainerImage", "ServerlessFunction", "Workload"), "Vulnerability"), (C("via_package"), C("exploitable", "BOOLEAN")), derived=True),
    EdgeType("RESOLVES_TO", _pairs("Domain", "IpAddress")),
    # identity and access
    EdgeType("HAS_ROLE", _pairs(COMPUTE, "IamRole"), (C("via"),)),
    EdgeType("HAS_POLICY", _pairs(("IamRole", "IamUser", "Group"), "IamPolicy"), (C("attachment"),)),
    EdgeType("GRANTS", _pairs("IamPolicy", ("StorageBucket", "Database", "Secret", "IamRole", "ServerlessFunction", "CloudAccount")), (C("actions", "STRING[]"), C("access_level"), C("resource_pattern"))),
    EdgeType("CAN_ASSUME", _pairs(PRINCIPALS, "IamRole"), (C("via"), C("cross_account", "BOOLEAN"))),
    EdgeType("HAS_ACCESS_KEY", _pairs("IamUser", "AccessKey")),
    EdgeType("MEMBER_OF", _pairs("HumanUser", ("Group", "Team"))),
    EdgeType("MAPS_TO", _pairs(("HumanUser", "Group"), ("IamRole", "IamUser")), (C("via"),)),
    EdgeType("CAN_ACCESS", _pairs(PRINCIPALS + ("VirtualMachine", "Workload", "ServerlessFunction"), DATA_HOLDERS), (C("access_level"), C("path_length", "INT64"), C("via"), C("transitive", "BOOLEAN")), derived=True),
    EdgeType("UNLOCKS", _pairs("Secret", ("Database", "StorageBucket", "IamUser", "IamRole")), (C("credential_type"),)),
    EdgeType("CREDENTIAL_FOR", _pairs("Credential", ("IamRole", "IamUser", "ServiceAccount", "HumanUser", "AccessKey"))),
    EdgeType("DERIVED_FROM", _pairs("Credential", "Credential"), (C("via"),), derived=True),
    # business
    EdgeType("PART_OF", _pairs(("VirtualMachine", "Workload", "StorageBucket", "Database", "ServerlessFunction", "Secret", "KubernetesCluster", "IamRole", "LoadBalancer"), "Application")),
    EdgeType("OWNED_BY", _pairs(("Application", "VirtualMachine", "StorageBucket", "Database"), "Team")),
    EdgeType("LEADS", _pairs("HumanUser", "Team")),
    EdgeType("DEPENDS_ON", _pairs("Application", ("Application", "VirtualMachine", "Database", "StorageBucket", "Secret")), (C("dependency_type"),)),
    # endpoint telemetry
    EdgeType("SAME_AS", _pairs("Endpoint", "VirtualMachine"), (C("method"),), derived=True),
    EdgeType("PRIMARY_USER", _pairs("Endpoint", "HumanUser")),
    EdgeType("LOGGED_ON", _pairs(("HumanUser", "ServiceAccount"), "Endpoint"), (C("logon_type"), C("logon_time", "TIMESTAMP"), C("source_ip"), C("session_id"))),
    EdgeType("RAN_ON", _pairs("Process", "Endpoint")),
    EdgeType("RAN_AS", _pairs("Process", ("HumanUser", "ServiceAccount"))),
    EdgeType("SPAWNED", _pairs("Process", "Process")),
    EdgeType("EXECUTED", _pairs("Process", "File"), (C("action"),)),
    EdgeType("CONNECTED_TO", _pairs(("Process", "Endpoint"), ("IpAddress", "Domain")), (C("port", "INT64"), C("protocol"), C("direction"), C("count", "INT64"), C("bytes_out", "INT64"), C("first_time", "TIMESTAMP"), C("last_time", "TIMESTAMP"))),
    EdgeType("LATERAL_MOVEMENT_TO", _pairs("Endpoint", "Endpoint"), (C("protocol"), C("account"), C("time", "TIMESTAMP"), C("alert_id")), derived=True),
    EdgeType("ACCESSED_CREDENTIAL", _pairs("Process", "Credential"), (C("method"),)),
    # alerts, events, incidents, storylines
    EdgeType("ON_ENDPOINT", _pairs("Alert", "Endpoint")),
    EdgeType("ON_RESOURCE", _pairs("Alert", ALERT_RESOURCES)),
    EdgeType("INVOLVES", _pairs("Alert", ("Process", "File", "IpAddress", "Domain", "Credential", "HumanUser", "ServiceAccount", "IamRole", "AccessKey", "CloudEvent", "Vulnerability")), (C("role"),)),
    EdgeType("USES_TECHNIQUE", _pairs(("Alert", "ThreatActor", "Campaign", "Malware"), "AttackTechnique")),
    EdgeType("PART_OF_INCIDENT", _pairs("Alert", "Incident")),
    EdgeType("STOLEN_BY", _pairs("Credential", ("Alert", "Process")), (C("method"),), derived=True),
    EdgeType("USED_CREDENTIAL", _pairs("CloudEvent", "Credential")),
    EdgeType("PERFORMED_BY", _pairs("CloudEvent", ("IamRole", "IamUser"))),
    EdgeType("TARGETED", _pairs("CloudEvent", ("StorageBucket", "Database", "Secret", "IamRole", "CloudAccount", "IamUser"))),
    EdgeType("FROM_IP", _pairs("CloudEvent", "IpAddress")),
    EdgeType("ASSUMED", _pairs("CloudEvent", "IamRole")),
    EdgeType("IN_STORYLINE", _pairs(STORYLINE_MEMBERS, "Storyline"), (C("stage", "INT64"), C("role")), derived=True),
    EdgeType("NEXT_STAGE", _pairs(("Alert", "CloudEvent"), ("Alert", "CloudEvent")), (C("storyline_id"), C("stage", "INT64")), derived=True),
    # threat intel
    EdgeType("ATTRIBUTED_TO", _pairs(("Campaign", "Alert", "Storyline"), ("ThreatActor", "Campaign")), (C("basis"),)),
    EdgeType("USES_MALWARE", _pairs(("ThreatActor", "Campaign"), "Malware")),
    EdgeType("INDICATES", _pairs("Indicator", ("Malware", "Campaign", "ThreatActor"))),
    EdgeType("EXPLOITS", _pairs(("ThreatActor", "Campaign"), "Vulnerability"), (C("status"),)),
    EdgeType("REPORTS_ON", _pairs("IntelReport", ("ThreatActor", "Campaign", "Malware", "Vulnerability", "Indicator", "AttackTechnique"))),
    EdgeType("MATCHES_IOC", _pairs(("IpAddress", "Domain", "File", "Process", "Alert", "CloudEvent"), "Indicator"), (C("match_type"),), derived=True),
    EdgeType("TARGETS", _pairs(("ThreatActor", "Campaign"), ("Application", "CloudAccount")), (C("basis"),), derived=True),
]

EDGE_TYPES: dict[str, EdgeType] = {e.name: e for e in _EDGE_TYPES}

# ----------------------------------------------------------------------------- helpers


def label(name: str) -> NodeLabel:
    return LABELS[name]


def edge_type(name: str) -> EdgeType:
    return EDGE_TYPES[name]


def category_of(label_name: str) -> str:
    lbl = LABELS.get(label_name)
    return lbl.category if lbl else "unknown"


def label_for_id(node_id: str) -> str | None:
    """Infer the label from the id prefix (``vm:aws:i-...`` -> VirtualMachine)."""
    prefix = node_id.split(":", 1)[0]
    return _PREFIX_TO_LABEL.get(prefix)


def validate_node(record: dict) -> list[str]:
    """Return a list of problems (empty if valid)."""
    problems: list[str] = []
    lbl = LABELS.get(record.get("label", ""))
    if lbl is None:
        return [f"unknown label {record.get('label')!r} for {record.get('id')!r}"]
    nid = record.get("id", "")
    if not nid.startswith(lbl.id_prefix + ":"):
        problems.append(f"id {nid!r} does not start with {lbl.id_prefix + ':'!r} for label {lbl.name}")
    for key in ("name", "source"):
        if not record.get(key):
            problems.append(f"{nid}: missing {key}")
    return problems


def validate_edge(record: dict, label_of: dict[str, str] | None = None) -> list[str]:
    et = EDGE_TYPES.get(record.get("type", ""))
    if et is None:
        return [f"unknown edge type {record.get('type')!r}"]
    problems: list[str] = []
    if label_of is not None:
        s, d = label_of.get(record["src"]), label_of.get(record["dst"])
        if s is None or d is None:
            problems.append(f"{et.name}: dangling endpoint {record['src'] if s is None else record['dst']!r}")
        elif not et.allows(s, d):
            problems.append(f"{et.name}: pair ({s} -> {d}) not allowed")
    return problems
