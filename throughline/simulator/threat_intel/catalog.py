"""Static, hand-authored fictional threat-intelligence content for the simulated estate.

This module is *data only* (no randomness, no I/O). ``generate.py`` turns these specs into graph nodes and
edges and STIX-like raw feeds. Everything here is fictional: no real threat-actor names, victims, or people.
Real CVE identifiers from ``catalog/cves.py`` are attributed to fictional actors purely for the prototype.

The two flagship campaigns (EMBERCAST / Cinder Jackal and SALTWORKS / Hollow Tide) and their ids come from
``storyline_constants`` so every generator agrees on the same strings.
"""
from __future__ import annotations

from dataclasses import dataclass

from throughline.simulator import storyline_constants as SC


@dataclass(frozen=True)
class ActorSpec:
    id: str
    name: str
    motivation: str  # financial | espionage | hacktivism | access-broker
    origin: str
    sophistication: str  # low | medium | high | advanced
    targeted_sectors: tuple[str, ...]
    targeted_regions: tuple[str, ...]
    relevance: float  # sector_targeting_relevance for the customer (Larkspur, financial-services)
    active: bool
    description: str
    aliases: tuple[str, ...] = ()
    malware: tuple[str, ...] = ()  # malware node ids used by this actor
    techniques: tuple[str, ...] = ()  # ATT&CK technique ids used at the actor level


@dataclass(frozen=True)
class CampaignSpec:
    id: str
    name: str
    actor_id: str
    status: str  # active | dormant | historical
    started: str  # YYYY-MM-DD
    objective: str
    targeted_sectors: tuple[str, ...]
    relevance: float
    description: str
    techniques: tuple[str, ...] = ()  # empty -> inherit the actor's techniques
    malware: tuple[str, ...] = ()  # empty -> inherit the actor's malware


@dataclass(frozen=True)
class MalwareSpec:
    id: str
    name: str
    malware_type: str  # loader | stealer | implant | webshell | ransomware | tool
    platforms: tuple[str, ...]
    description: str
    techniques: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExploitSpec:
    kind: str  # actor | campaign
    source_id: str
    cve_id: str
    status: str  # poc_public | active | mass_exploitation
    first_seen: str  # YYYY-MM-DD


@dataclass(frozen=True)
class PlantSpec:
    """A low-confidence indicator whose value the inventory/events lead plants on random hosts later."""

    ioc_type: str
    value: str
    confidence: float
    campaign_id: str
    kill_chain_stage: int
    first_seen: str
    last_seen: str


# ------------------------------------------------------------------ actor ids (invented ones)

ACTOR_SAFFRON = "actor:ti:saffron-heron"
ACTOR_BASALT = "actor:ti:basalt-choir"
ACTOR_VERDANT = "actor:ti:verdant-mantis"
ACTOR_COBALT = "actor:ti:cobalt-drifter"
ACTOR_POWDER = "actor:ti:powder-vireo"
ACTOR_TIN = "actor:ti:tin-marimba"
ACTOR_GLASS = "actor:ti:glass-petrel"
ACTOR_UMBER = "actor:ti:umber-lantern"

# ------------------------------------------------------------------ malware ids (invented ones)

MAL_CINDERLOCK = "malware:ti:cinderlock"
MAL_SALTRIG = "malware:ti:saltrig"
MAL_TIDEHOOK = "malware:ti:tidehook"
MAL_HERONBEAK = "malware:ti:heronbeak"
MAL_BASALTON = "malware:ti:basalton"
MAL_VERDIGRIS = "malware:ti:verdigris"
MAL_DRIFTNET = "malware:ti:driftnet"
MAL_PETRICHOR = "malware:ti:petrichor"

# ------------------------------------------------------------------ malware (12)

MALWARE: list[MalwareSpec] = [
    MalwareSpec(SC.MALWARE_MAPLELOADER, "MAPLELOADER", "loader", ("Windows",),
                "ISO/LNK-delivered first-stage loader; runs a DLL via rundll32 and stages follow-on tooling.",
                ("T1204.002", "T1218.011", "T1055", "T1059.001")),
    MalwareSpec(SC.MALWARE_QUILLDROP, "QUILLDROP", "stealer", ("Windows",),
                "Credential stealer targeting LSASS memory, browser stores and on-disk SSH keys.",
                ("T1003.001", "T1552.001", "T1003.008", "T1555.003")),
    MalwareSpec(SC.MALWARE_NIGHTFERRY, "NIGHTFERRY", "implant", ("Windows",),
                "HTTPS command-and-control implant with Run-key persistence and asymmetric channel encryption.",
                ("T1071.001", "T1573.002", "T1547.001", "T1105")),
    MalwareSpec(SC.MALWARE_BRACKISH, "BRACKISH", "webshell", ("Linux", "Web"),
                "Minimal JSP/Unix web shell dropped after exploitation of public-facing Java services.",
                ("T1505.003", "T1059.004", "T1105", "T1071.001")),
    MalwareSpec(MAL_CINDERLOCK, "CINDERLOCK", "ransomware", ("Windows",),
                "Data-encrypting ransomware with recovery inhibition and defense tampering.",
                ("T1486", "T1490", "T1562.001", "T1055", "T1070.004")),
    MalwareSpec(MAL_SALTRIG, "SALTRIG", "tool", ("Linux", "Windows"),
                "Reconnaissance and tunnelling utility used to enumerate and proxy into exploited networks.",
                ("T1046", "T1018", "T1090", "T1105")),
    MalwareSpec(MAL_TIDEHOOK, "TIDEHOOK", "loader", ("Windows",),
                "Second-stage loader that side-loads follow-on payloads for access-broker operations.",
                ("T1204.002", "T1059.001", "T1055", "T1105")),
    MalwareSpec(MAL_HERONBEAK, "HERONBEAK", "stealer", ("Windows", "macOS"),
                "Cross-platform stealer focused on browser secrets, mailbox tokens and credential files.",
                ("T1003.001", "T1555.003", "T1552.001", "T1114.002")),
    MalwareSpec(MAL_BASALTON, "BASALTON", "implant", ("Windows", "Linux"),
                "Modular implant with web-protocol C2 and cloud instance-metadata credential theft.",
                ("T1071.001", "T1573.002", "T1547.001", "T1552.005", "T1530")),
    MalwareSpec(MAL_VERDIGRIS, "VERDIGRIS", "ransomware", ("Windows",),
                "Ransomware variant used in disruptive intrusions; inhibits recovery and hijacks resources.",
                ("T1486", "T1490", "T1496", "T1562.001")),
    MalwareSpec(MAL_DRIFTNET, "DRIFTNET", "tool", ("Linux",),
                "Scanning and exploitation harness used to spray public-facing services at scale.",
                ("T1046", "T1595.002", "T1018", "T1105")),
    MalwareSpec(MAL_PETRICHOR, "PETRICHOR", "implant", ("Windows",),
                "Low-and-slow espionage implant using web protocols and a proxy chain for exfiltration.",
                ("T1071.001", "T1573.002", "T1090", "T1105", "T1041")),
]

# ------------------------------------------------------------------ actors (10)

ACTORS: list[ActorSpec] = [
    ActorSpec(
        SC.ACTOR_CJ, "Cinder Jackal", "financial", "Eastern Europe (suspected)", "high",
        ("financial-services", "payment-processing"), ("North America", "Western Europe"),
        0.9, True,
        "Financially motivated eCrime group specialising in intrusions at fintechs and payment processors, "
        "increasingly pivoting from workstation footholds into cloud estates to steal cardholder data for extortion.",
        aliases=("Ember Lynx", "TA-Crimson"),
        malware=(SC.MALWARE_MAPLELOADER, SC.MALWARE_QUILLDROP, SC.MALWARE_NIGHTFERRY),
        techniques=tuple(SC.CJ_TECHNIQUES),
    ),
    ActorSpec(
        SC.ACTOR_HT, "Hollow Tide", "access-broker", "unknown", "medium",
        ("financial-services", "insurance", "legal"), ("North America", "Western Europe"),
        0.8, True,
        "Opportunistic access broker that mass-exploits internet-facing services and resells footholds to "
        "ransomware affiliates, with a persistent interest in financial-services and insurance targets.",
        aliases=("Brine Spider", "Access-Merchant-07"),
        malware=(SC.MALWARE_BRACKISH, MAL_SALTRIG, MAL_TIDEHOOK),
        techniques=tuple(SC.HT_TECHNIQUES),
    ),
    ActorSpec(
        ACTOR_SAFFRON, "Saffron Heron", "espionage", "East Asia (suspected)", "high",
        ("financial-services", "technology"), ("North America", "East Asia"),
        0.75, True,
        "Espionage actor conducting long-dwell collection against fintech product and payments roadmaps, "
        "favouring spearphishing links and edge-service exploitation for initial access.",
        aliases=("APT-Heron", "Amber Egret"),
        malware=(MAL_HERONBEAK,),
        techniques=("T1566.002", "T1190", "T1133", "T1059.001", "T1053.005", "T1078", "T1003.001",
                    "T1552.001", "T1087.002", "T1018", "T1021.001", "T1114.002", "T1071.001", "T1567.002"),
    ),
    ActorSpec(
        ACTOR_BASALT, "Basalt Choir", "financial", "Eastern Europe (suspected)", "high",
        ("financial-services", "retail"), ("Western Europe", "North America"),
        0.7, True,
        "eCrime group behind ransomware-precursor intrusions at retail-banking back offices, staging "
        "credential theft and cloud data collection before deploying encryptors.",
        aliases=("Obsidian Motet",),
        malware=(MAL_BASALTON, MAL_CINDERLOCK),
        techniques=("T1190", "T1059.003", "T1547.001", "T1055", "T1003.001", "T1552.005", "T1078.004",
                    "T1580", "T1530", "T1486", "T1490", "T1071.001", "T1105", "T1048.003"),
    ),
    ActorSpec(
        ACTOR_VERDANT, "Verdant Mantis", "espionage", "East Asia (suspected)", "medium",
        ("healthcare",), ("North America", "East Asia"),
        0.25, True,
        "Espionage group targeting hospital research programmes and claims data, using phishing attachments "
        "and slow, quiet collection.",
        aliases=("Jade Katydid",),
        malware=(MAL_VERDIGRIS,),
        techniques=("T1566.001", "T1204.002", "T1059.001", "T1027", "T1547.001", "T1003.001", "T1082",
                    "T1083", "T1021.002", "T1005", "T1071.001", "T1041"),
    ),
    ActorSpec(
        ACTOR_COBALT, "Cobalt Drifter", "hacktivism", "unknown (hacktivist collective)", "low",
        ("energy",), ("Western Europe", "North America"),
        0.2, True,
        "Hacktivist collective that defaces and disrupts energy-utility web portals, opportunistically "
        "exploiting known edge-device vulnerabilities.",
        aliases=("GridStatic",),
        malware=(MAL_DRIFTNET,),
        techniques=("T1595.002", "T1190", "T1133", "T1059.004", "T1505.003", "T1046", "T1018",
                    "T1021.004", "T1490", "T1496", "T1071.001", "T1105"),
    ),
    ActorSpec(
        ACTOR_POWDER, "Powder Vireo", "espionage", "Middle East (suspected)", "high",
        ("public-sector",), ("Middle East", "Western Europe"),
        0.3, True,
        "Espionage actor collecting against public-sector policy, procurement and diplomatic mailboxes, "
        "with a focus on MFA-fatigue and valid-account tradecraft.",
        aliases=("Sand Vireo", "APT-Powder"),
        malware=(MAL_PETRICHOR,),
        techniques=("T1566.002", "T1078", "T1190", "T1059.001", "T1053.005", "T1556.006", "T1621",
                    "T1003.001", "T1087.002", "T1114.002", "T1071.001", "T1573.002", "T1567.002"),
    ),
    ActorSpec(
        ACTOR_TIN, "Tin Marimba", "financial", "West Africa (suspected)", "medium",
        ("technology",), ("North America", "West Africa"),
        0.2, True,
        "eCrime group experimenting with software supply-chain compromise of SaaS build pipelines to reach "
        "downstream technology customers.",
        aliases=("Rattle Marimba",),
        malware=(MAL_HERONBEAK, MAL_TIDEHOOK),
        techniques=("T1195.002", "T1204.001", "T1059.006", "T1053.003", "T1027", "T1552.001",
                    "T1555.003", "T1082", "T1219", "T1105", "T1071.001", "T1041"),
    ),
    ActorSpec(
        ACTOR_GLASS, "Glass Petrel", "espionage", "South Asia (suspected)", "medium",
        ("telecommunications",), ("South Asia", "Southeast Asia"),
        0.15, True,
        "Espionage actor collecting telecom metadata through edge-device access and cloud service abuse.",
        aliases=("Sea Petrel",),
        malware=(MAL_PETRICHOR,),
        techniques=("T1190", "T1133", "T1078.004", "T1651", "T1098.001", "T1580", "T1526", "T1538",
                    "T1530", "T1071.001", "T1567.002", "T1090"),
    ),
    ActorSpec(
        ACTOR_UMBER, "Umber Lantern", "hacktivism", "unknown (hacktivist collective)", "low",
        ("manufacturing",), ("Latin America", "Western Europe"),
        0.1, False,
        "Hacktivist collective that has periodically disrupted manufacturing OT dashboards; currently dormant.",
        aliases=("Lantern Front",),
        malware=(MAL_DRIFTNET, MAL_CINDERLOCK),
        techniques=("T1595.002", "T1190", "T1059.004", "T1505.003", "T1070.004", "T1046", "T1018",
                    "T1486", "T1490", "T1496", "T1071.001", "T1105"),
    ),
]

# ------------------------------------------------------------------ campaigns (16)

CAMPAIGNS: list[CampaignSpec] = [
    CampaignSpec(
        SC.CAMPAIGN_EMBERCAST, "EMBERCAST", SC.ACTOR_CJ, "active", "2026-07-01",
        "Cloud data theft via bastion-host pivoting against fintech cloud estates",
        ("financial-services", "payment-processing"), 0.9,
        "Active Cinder Jackal campaign that phishes finance staff, harvests SSH and cloud credentials, and "
        "pivots through bastion hosts into cloud data stores holding cardholder data.",
        techniques=tuple(SC.CJ_TECHNIQUES),
        malware=(SC.MALWARE_MAPLELOADER, SC.MALWARE_QUILLDROP, SC.MALWARE_NIGHTFERRY),
    ),
    CampaignSpec(
        "campaign:ti:cinderfall", "CINDERFALL", SC.ACTOR_CJ, "historical", "2025-02-10",
        "Macro-laden invoice lures against regional payment processors",
        ("financial-services", "payment-processing"), 0.7,
        "Earlier Cinder Jackal operation that relied on macro-enabled invoice documents to deliver loaders "
        "to accounts-payable teams.",
    ),
    CampaignSpec(
        SC.CAMPAIGN_SALTWORKS, "SALTWORKS", SC.ACTOR_HT, "active", "2026-08-20",
        "Mass exploitation of Log4Shell in fintech statement and document services for access resale",
        ("financial-services", "insurance"), 0.8,
        "Active Hollow Tide campaign mass-scanning and exploiting CVE-2021-44228 on internet-facing Java "
        "services at financial-services firms, dropping the BRACKISH web shell and selling access.",
        techniques=tuple(SC.HT_TECHNIQUES),
        malware=(SC.MALWARE_BRACKISH,),
    ),
    CampaignSpec(
        "campaign:ti:tidewrack", "TIDEWRACK", SC.ACTOR_HT, "dormant", "2026-03-05",
        "Exploitation of edge appliances at insurers to broker access",
        ("insurance", "financial-services"), 0.7,
        "Hollow Tide operation exploiting VPN and file-transfer appliances at insurers before reselling footholds.",
    ),
    CampaignSpec(
        "campaign:ti:heronwatch", "HERONWATCH", ACTOR_SAFFRON, "active", "2026-05-15",
        "Long-dwell espionage against fintech product roadmaps",
        ("financial-services", "technology"), 0.75,
        "Saffron Heron espionage campaign collecting against payments product plans and engineering documents.",
    ),
    CampaignSpec(
        "campaign:ti:heron-dusk", "HERON DUSK", ACTOR_SAFFRON, "dormant", "2025-09-01",
        "Credential harvesting against banking SSO portals",
        ("financial-services",), 0.7,
        "Saffron Heron operation phishing banking single-sign-on portals to harvest workforce credentials.",
    ),
    CampaignSpec(
        "campaign:ti:basalt-overture", "BASALT OVERTURE", ACTOR_BASALT, "active", "2026-06-20",
        "Ransomware-precursor intrusions at retail-banking back offices",
        ("financial-services", "retail"), 0.7,
        "Basalt Choir intrusions staging credential theft and cloud collection ahead of ransomware deployment.",
    ),
    CampaignSpec(
        "campaign:ti:choir-refrain", "CHOIR REFRAIN", ACTOR_BASALT, "historical", "2025-01-12",
        "Point-of-sale skimming operations",
        ("retail", "financial-services"), 0.7,
        "Earlier Basalt Choir operation deploying point-of-sale memory-scraping malware at retail merchants.",
    ),
    CampaignSpec(
        "campaign:ti:green-fen", "GREEN FEN", ACTOR_VERDANT, "active", "2026-04-02",
        "Espionage against hospital research and claims data",
        ("healthcare",), 0.25,
        "Verdant Mantis collection against hospital research programmes and insurance-claims datasets.",
    ),
    CampaignSpec(
        "campaign:ti:drift-current", "DRIFT CURRENT", ACTOR_COBALT, "historical", "2025-06-18",
        "Hacktivist defacement and disruption of energy utilities",
        ("energy",), 0.2,
        "Cobalt Drifter defacement and denial campaign against regional energy-utility portals.",
    ),
    CampaignSpec(
        "campaign:ti:cobalt-tide", "COBALT TIDE", ACTOR_COBALT, "active", "2026-07-30",
        "Disruptive intrusions against grid-operator web portals",
        ("energy",), 0.2,
        "Cobalt Drifter campaign probing grid-operator web portals for disruptive access.",
    ),
    CampaignSpec(
        "campaign:ti:vireo-signal", "VIREO SIGNAL", ACTOR_POWDER, "active", "2026-03-22",
        "Espionage against public-sector policy and procurement systems",
        ("public-sector",), 0.3,
        "Powder Vireo collection against public-sector policy and procurement systems using valid-account tradecraft.",
    ),
    CampaignSpec(
        "campaign:ti:vireo-echo", "VIREO ECHO", ACTOR_POWDER, "historical", "2025-11-05",
        "Diplomatic mailbox collection",
        ("public-sector",), 0.3,
        "Earlier Powder Vireo operation collecting from diplomatic mailboxes via remote email access.",
    ),
    CampaignSpec(
        "campaign:ti:tin-cadence", "TIN CADENCE", ACTOR_TIN, "dormant", "2026-02-14",
        "Supply-chain compromise of SaaS build pipelines",
        ("technology",), 0.2,
        "Tin Marimba attempts to compromise SaaS build pipelines to reach downstream technology customers.",
    ),
    CampaignSpec(
        "campaign:ti:petrel-watch", "PETREL WATCH", ACTOR_GLASS, "active", "2026-05-28",
        "Telecom metadata collection via edge-device access",
        ("telecommunications",), 0.15,
        "Glass Petrel campaign collecting telecom metadata through edge-device access and cloud service abuse.",
    ),
    CampaignSpec(
        "campaign:ti:lantern-march", "LANTERN MARCH", ACTOR_UMBER, "historical", "2025-08-19",
        "Hacktivist disruption of manufacturing OT dashboards",
        ("manufacturing",), 0.1,
        "Umber Lantern disruption campaign against manufacturing operational-technology dashboards.",
    ),
]

# ------------------------------------------------------------------ EXPLOITS assignments

EXPLOITS: list[ExploitSpec] = [
    # storyline: SALTWORKS / Hollow Tide mass-exploit Log4Shell (campaign + actor)
    ExploitSpec("campaign", SC.CAMPAIGN_SALTWORKS, "CVE-2021-44228", "mass_exploitation", "2026-08-20"),
    ExploitSpec("actor", SC.ACTOR_HT, "CVE-2021-44228", "mass_exploitation", "2026-08-20"),
    # required specific attributions
    ExploitSpec("actor", ACTOR_BASALT, "CVE-2023-4966", "active", "2026-06-25"),  # fin actor (0.7)
    ExploitSpec("actor", ACTOR_COBALT, "CVE-2024-3400", "active", "2026-07-10"),  # non-fin actor
    ExploitSpec("actor", ACTOR_POWDER, "CVE-2022-22965", "poc_public", "2026-03-30"),  # poc only
    ExploitSpec("actor", ACTOR_SAFFRON, "CVE-2024-23897", "active", "2026-05-20"),  # fin actor
    ExploitSpec("actor", ACTOR_GLASS, "CVE-2023-22515", "active", "2026-06-01"),  # non-fin actor
    # 8-12 more active / poc_public over KEV entries
    ExploitSpec("actor", SC.ACTOR_HT, "CVE-2024-21887", "active", "2026-02-15"),
    ExploitSpec("actor", SC.ACTOR_HT, "CVE-2023-46805", "active", "2026-02-15"),
    ExploitSpec("actor", ACTOR_TIN, "CVE-2024-1709", "active", "2026-02-25"),
    ExploitSpec("campaign", "campaign:ti:tidewrack", "CVE-2023-34362", "active", "2026-03-06"),
    ExploitSpec("actor", ACTOR_COBALT, "CVE-2024-21762", "active", "2026-07-12"),
    ExploitSpec("actor", ACTOR_BASALT, "CVE-2026-90022", "active", "2026-04-01"),
    ExploitSpec("actor", ACTOR_SAFFRON, "CVE-2026-90048", "active", "2026-05-22"),
    ExploitSpec("actor", ACTOR_POWDER, "CVE-2026-90088", "active", "2026-04-05"),
    ExploitSpec("actor", ACTOR_GLASS, "CVE-2026-90161", "active", "2026-06-03"),
    ExploitSpec("actor", ACTOR_TIN, "CVE-2026-90035", "poc_public", "2026-03-01"),
    ExploitSpec("actor", ACTOR_UMBER, "CVE-2026-90070", "poc_public", "2026-01-20"),
    ExploitSpec("actor", ACTOR_VERDANT, "CVE-2026-90123", "active", "2026-04-20"),
]

# ------------------------------------------------------------------ low-confidence IOC plants (5-8)
# Fixed, deterministic values the inventory/events lead will scatter on random hosts later so the TI page
# shows confidence-weighted matches. All tied to old (historical/dormant) campaigns.

PLANTS: list[PlantSpec] = [
    PlantSpec("ipv4", "203.0.113.150", 0.45, "campaign:ti:drift-current", 1, "2025-06-20", "2025-09-30"),
    PlantSpec("ipv4", "198.51.100.77", 0.40, "campaign:ti:lantern-march", 6, "2025-08-20", "2025-11-01"),
    PlantSpec("domain", "legacy-update.example", 0.50, "campaign:ti:tin-cadence", 6, "2026-02-15", "2026-05-01"),
    PlantSpec("domain", "metrics-collector.test", 0.35, "campaign:ti:vireo-echo", 6, "2025-11-06", "2026-01-15"),
    PlantSpec("sha256", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", 0.40,
              "campaign:ti:drift-current", 2, "2025-06-25", "2025-09-10"),
    PlantSpec("filename", "wsvc-helper.exe", 0.30, "campaign:ti:tin-cadence", 3, "2026-02-20", "2026-04-10"),
]

# ------------------------------------------------------------------ flagship report bodies

PUBLISHER = "Throughline Labs"

EMBERCAST_SUMMARY = (
    "Throughline Labs assesses with high confidence that the financially motivated eCrime group Cinder Jackal "
    "has shifted from smash-and-grab endpoint theft to deliberate cloud-data theft, pivoting from phished "
    "finance workstations through bastion hosts into cloud accounts that hold cardholder data. This report "
    "documents the EMBERCAST intrusion set against financial-services and payment-processing targets, its "
    "tooling (MAPLELOADER, NIGHTFERRY, QUILLDROP), and the detection opportunities across the intrusion chain."
)

EMBERCAST_BODY = (
    "Executive summary. Cinder Jackal is an established eCrime group that monetises intrusions at fintechs and "
    "payment processors through data theft and extortion. Over the reporting period Throughline Labs observed a "
    "consistent tradecraft change: rather than deploying commodity ransomware on the initial host, the group now "
    "treats the compromised workstation as a stepping stone toward the victim's cloud estate, where the "
    "regulated data actually lives. We track this activity as EMBERCAST and assess it as active.\n\n"
    "Intrusion chain. Initial access is a spearphishing email carrying an ISO attachment. When the recipient "
    "mounts the ISO and opens the enclosed LNK, a hidden PowerShell command launches rundll32 against a bundled "
    "DLL (MAPLELOADER). MAPLELOADER writes a second binary, typically masquerading as a sync helper under "
    "C:\\ProgramData, and establishes NIGHTFERRY, an HTTPS implant that persists via a Run key and beacons to "
    "attacker infrastructure. The group then runs QUILLDROP to read LSASS memory, browser secret stores and any "
    "on-disk SSH private keys and helper configuration files.\n\n"
    "Cloud pivot. The distinguishing behaviour is what follows credential theft. Using a stolen SSH key and a "
    "service-account configuration recovered from the workstation, Cinder Jackal opens an interactive session to "
    "an internal bastion host - an account normally used only for automated file transfer. From the bastion the "
    "operator queries the cloud instance-metadata service to obtain the instance role's temporary credentials, "
    "then calls sts:AssumeRole to reach a higher-privilege data-reader role in the production account. With that "
    "role the group enumerates and bulk-downloads objects from cardholder-data storage and reads database and "
    "signing-key secrets. Interactive cloud API calls originate from hosting-provider egress space rather than "
    "the victim's own ranges.\n\n"
    "Detection opportunities. The chain offers several high-value detections that do not depend on knowing the "
    "specific indicators: execution of rundll32 against a DLL written moments earlier under a user profile; a "
    "newly written binary registering a Run key and injecting into explorer.exe; LSASS handle acquisition by an "
    "unsigned process; access to an SSH private key by a non-SSH process; an interactive shell on a bastion that "
    "normally only services automated transfers; and, most importantly, instance-metadata credential access from "
    "an interactive shell followed by AssumeRole and large-volume object reads from outside the VPC.\n\n"
    "Recommendations. Constrain bastion instance-role trust so that the production data-reader role can only be "
    "assumed by expected principals, and scope its data permissions tightly. Enforce IMDSv2 with a low hop limit "
    "and alert on metadata access from interactive sessions. Treat any interactive login to transfer-only "
    "service accounts as high severity. Rotate exposed instance-role credentials and tighten the reader role's "
    "trust policy; note that short-lived assumed-role sessions expire on their own but the underlying trust "
    "relationship does not. Hunt for the indicators listed below across DNS, proxy, EDR and cloud audit logs."
)

SALTWORKS_SUMMARY = (
    "Throughline Labs assesses with medium-high confidence that the access broker Hollow Tide is mass-exploiting "
    "CVE-2021-44228 (Log4Shell) against internet-facing statement- and document-rendering services at "
    "financial-services firms, dropping the BRACKISH web shell and reselling the resulting access to ransomware "
    "affiliates. This report covers the SALTWORKS campaign, its scanning infrastructure and the follow-on risk."
)

SALTWORKS_BODY = (
    "Executive summary. Hollow Tide is an opportunistic access broker that turns broad exploitation into a "
    "marketplace: it compromises exposed services at scale, installs lightweight persistence, and sells footholds "
    "to ransomware affiliates and other buyers. Throughline Labs tracks its current financial-services activity "
    "as SALTWORKS and assesses the campaign as active.\n\n"
    "Exploitation. SALTWORKS targets internet-facing Java applications that remain vulnerable to CVE-2021-44228. "
    "Observed activity begins with wide scanning and JNDI-injection probes delivered through common HTTP headers. "
    "Where a target's statement- or document-rendering service is vulnerable, the crafted lookup causes the "
    "application server process to fetch and execute a shell script from attacker infrastructure, which in turn "
    "spawns a Unix shell from the Java process - an anomaly that stands out even without indicator knowledge.\n\n"
    "Persistence and follow-on. The script writes a small JSP web shell (BRACKISH) into the application's web "
    "root, adjusts permissions and timestamps to blend in, and beacons briefly before going quiet. Scanning, "
    "exploitation and payload hosting have been observed from the same hosting-provider address. Hollow Tide "
    "typically pauses after establishing the web shell, consistent with an access-broker model in which the "
    "buyer, not Hollow Tide, performs later objectives such as data theft or ransomware.\n\n"
    "Impact and detection. The immediate detection is a shell spawned by an application-server process, followed "
    "by a new executable file appearing in a web root. Because the exploited services often run with roles that "
    "can read application configuration and, transitively, database credentials, the potential blast radius "
    "extends to regulated data even before any hands-on-keyboard activity is seen.\n\n"
    "Recommendations. Patch or virtually patch Log4j on all internet-facing Java services and confirm coverage "
    "on staging and test hosts, which are frequently missed. Alert on application-server processes spawning "
    "shells and on new files in web roots. Given the confirmed active and mass-exploitation status of this "
    "vulnerability against the sector, treat any exposed vulnerable host as high priority regardless of whether "
    "hands-on activity has been observed. Block and hunt for the indicators below."
)
