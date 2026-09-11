"""Org model for Larkspur Financial: departments, 18 teams, ~1,400 human users and ~60 Okta groups.

The named people from docs/04-storyline.md section 1.3 are created first with their exact properties; everyone
else is generated deterministically from the name vocabularies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from throughline.simulator import storyline_constants as sc
from throughline.simulator.common import pick, rng

from throughline.simulator.inventory._base import SOURCE_OKTA, SOURCE_WIZ, Inventory, days_ago, hexid, minutes_ago
from throughline.simulator.inventory.names import FIRST_NAMES, LAST_NAMES, LOCATIONS, TITLES

TARGET_USERS = 1400


@dataclass
class TeamSpec:
    slug: str
    name: str
    department: str
    weight: int
    dept_label: str | None = None  # department string written on users (defaults to department)
    oncall: str | None = None

    @property
    def id(self) -> str:
        return f"team:larkspur:{self.slug}"

    @property
    def user_department(self) -> str:
        return self.dept_label or self.department


TEAMS: list[TeamSpec] = [
    TeamSpec("platform-eng", "Platform Engineering", "Engineering", 12, oncall="#oncall-platform"),
    TeamSpec("payments-platform", "Payments Platform", "Engineering", 16, oncall="#oncall-payments"),
    TeamSpec("wallet-eng", "Wallet Engineering", "Engineering", 16, oncall="#oncall-wallet"),
    TeamSpec("baas-api", "Banking-as-a-Service API", "Engineering", 12, oncall="#oncall-baas"),
    TeamSpec("data-platform", "Data Platform", "Engineering", 12, oncall="#oncall-data"),
    TeamSpec("fraud-ml", "Fraud ML", "Engineering", 10, oncall="#oncall-fraud-ml"),
    TeamSpec("security-eng", "Security Engineering", "Engineering", 8, oncall="#secops"),
    TeamSpec("mobile-eng", "Mobile Engineering", "Engineering", 14, oncall="#oncall-mobile"),
    TeamSpec("corp-it", "Corporate IT", "Operations", 30, dept_label="Corporate IT", oncall="#it-helpdesk"),
    TeamSpec("payment-operations", "Payment Operations", "Operations", 40, oncall="#payment-ops"),
    TeamSpec("fraud-operations", "Fraud Operations", "Operations", 30, oncall="#fraud-ops"),
    TeamSpec("customer-support", "Customer Support", "Support", 100, oncall="#support-escalations"),
    TeamSpec("finance-treasury", "Finance Treasury", "Finance", 40, oncall="#treasury-ops"),
    TeamSpec("finance-accounting", "Finance Accounting", "Finance", 60, oncall="#finance"),
    TeamSpec("sales", "Sales", "Sales & Marketing", 60, oncall="#sales"),
    TeamSpec("marketing", "Marketing", "Sales & Marketing", 40, oncall="#marketing"),
    TeamSpec("compliance-risk", "Compliance & Risk", "Compliance & Risk", 100, oncall="#compliance"),
    TeamSpec("executive-office", "Executive Office", "Executive", 100, oncall="#exec-office"),
]
TEAM_BY_SLUG: dict[str, TeamSpec] = {t.slug: t for t in TEAMS}

DEPARTMENT_WEIGHTS: dict[str, int] = {
    "Engineering": 35, "Operations": 20, "Finance": 8, "Sales & Marketing": 12, "Compliance & Risk": 8, "Support": 12,
    "Executive": 5,
}

LEAD_TITLES: dict[str, str] = {
    "Engineering": "Engineering Manager", "Operations": "Operations Manager", "Finance": "Finance Manager",
    "Sales & Marketing": "Head of Team", "Compliance & Risk": "Head of Compliance", "Support": "Support Director",
    "Executive": "Chief Executive Officer",
}

PRIVILEGED_TEAM_RATE: dict[str, float] = {
    "platform-eng": 0.6, "security-eng": 0.7, "corp-it": 0.5, "data-platform": 0.3, "payments-platform": 0.25,
    "wallet-eng": 0.2, "baas-api": 0.2, "fraud-ml": 0.2, "mobile-eng": 0.1,
}


@dataclass
class Person:
    login: str
    first: str
    last: str
    title: str
    team: TeamSpec
    location: str
    privileged: bool = False
    executive: bool = False
    status: str = "active"
    mac: bool = False
    contractor: bool = False

    @property
    def id(self) -> str:
        return f"user:okta:{self.login}"

    @property
    def display_name(self) -> str:
        return f"{self.first} {self.last}"


@dataclass
class World:
    people: list[Person] = field(default_factory=list)
    by_login: dict[str, Person] = field(default_factory=dict)
    by_team: dict[str, list[Person]] = field(default_factory=dict)
    leads: dict[str, Person] = field(default_factory=dict)  # team slug -> lead
    groups: dict[str, str] = field(default_factory=dict)  # group name -> node id
    group_members: dict[str, list[str]] = field(default_factory=dict)  # group name -> user ids
    user_groups: dict[str, list[str]] = field(default_factory=dict)  # user id -> group names

    def team_members(self, slug: str) -> list[Person]:
        return self.by_team.get(slug, [])

    def person(self, user_id: str) -> Person:
        return self.by_login[user_id.split(":")[-1]]


def _login_for(first: str, last: str, taken: set[str]) -> str:
    base = re.sub(r"[^a-z]", "", (first[0] + last).lower())
    login = base
    n = 2
    while login in taken:
        login = f"{base}{n}"
        n += 1
    taken.add(login)
    return login


def _named_people() -> list[Person]:
    return [
        Person("dwhitfield", "Dana", "Whitfield", "Treasury Operations Analyst", TEAM_BY_SLUG["finance-treasury"], "Boston"),
        Person("mreyes", "Marcus", "Reyes", "IT Systems Administrator", TEAM_BY_SLUG["corp-it"], "Boston", privileged=True),
        Person("pkaur", "Priya", "Kaur", "Chief Financial Officer", TEAM_BY_SLUG["executive-office"], "New York", executive=True, mac=True),
        Person("jokafor", "Jide", "Okafor", "Platform Engineering Lead", TEAM_BY_SLUG["platform-eng"], "New York", privileged=True, mac=True),
        Person("lchen", "Lin", "Chen", "Staff Software Engineer, Statement Rendering", TEAM_BY_SLUG["payments-platform"], "New York", mac=True),
    ]


EXECUTIVES: list[tuple[str, str, str]] = [
    ("Helena", "Marchetti", "Chief Executive Officer"),
    ("Tobias", "Lindqvist", "Chief Technology Officer"),
    ("Amara", "Osei", "Chief Operating Officer"),
    ("Rafael", "Duarte", "Chief Information Security Officer"),
    ("Ingrid", "Sorensen", "Chief Risk & Compliance Officer"),
    ("Desmond", "Callahan", "General Counsel"),
    ("Kavya", "Venkataraman", "Chief Product Officer"),
]


def build_world(inv: Inventory) -> World:
    r = rng("inventory.world")
    world = World()
    taken: set[str] = set()

    def register(p: Person) -> None:
        world.people.append(p)
        world.by_login[p.login] = p
        world.by_team.setdefault(p.team.slug, []).append(p)

    for p in _named_people():
        taken.add(p.login)
        register(p)
    for first, last, title in EXECUTIVES:
        login = _login_for(first, last, taken)
        register(Person(login, first, last, title, TEAM_BY_SLUG["executive-office"], "New York", executive=True, mac=True, privileged=title.startswith("Chief Technology") or title.startswith("Chief Information")))

    teams_by_dept: dict[str, list[TeamSpec]] = {}
    for t in TEAMS:
        teams_by_dept.setdefault(t.department, []).append(t)

    while len(world.people) < TARGET_USERS:
        dept = pick(r, {k: float(v) for k, v in DEPARTMENT_WEIGHTS.items()})
        team = pick_team(r, teams_by_dept[dept])
        first, last = r.choice(FIRST_NAMES), r.choice(LAST_NAMES)
        login = _login_for(first, last, taken)
        title = pick(r, {t: float(w) for t, w in TITLES[dept]})
        location = pick(r, {k: float(v) for k, v in LOCATIONS.items()})
        priv = r.random() < PRIVILEGED_TEAM_RATE.get(team.slug, 0.03)
        executive = dept == "Executive" and title in ("Vice President", "Senior Director")
        status_roll = r.random()
        status = "active" if status_roll < 0.965 else ("suspended" if status_roll < 0.975 else "deprovisioned")
        mac = r.random() < (0.55 if dept == "Engineering" else 0.12)
        contractor = r.random() < 0.05 and dept in ("Engineering", "Support", "Operations")
        register(Person(login, first, last, title, team, location, privileged=priv, executive=executive, status=status, mac=mac, contractor=contractor))

    # team leads: the storyline lead for platform-eng, the CEO for the executive office, first active member otherwise
    for t in TEAMS:
        members = [p for p in world.by_team.get(t.slug, []) if p.status == "active"]
        if t.slug == "platform-eng":
            lead = world.by_login["jokafor"]
        elif t.slug == "executive-office":
            lead = next(p for p in members if p.title == "Chief Executive Officer")
        else:
            lead = next((p for p in members if p.login not in ("dwhitfield", "mreyes", "pkaur", "lchen")), members[0])
            lead.title = f"{LEAD_TITLES[t.department]}, {t.name}" if t.department != "Executive" else lead.title
            lead.privileged = lead.privileged or t.slug in ("corp-it", "security-eng", "data-platform")
        lead.mac = lead.mac or t.department == "Engineering"
        world.leads[t.slug] = lead

    _emit_teams(inv, world)
    _emit_users(inv, world, r)
    _emit_groups(inv, world)
    return world


def pick_team(r, teams: list[TeamSpec]) -> TeamSpec:  # type: ignore[no-untyped-def]
    slug = pick(r, {t.slug: float(t.weight) for t in teams})
    return TEAM_BY_SLUG[slug]


def _emit_teams(inv: Inventory, world: World) -> None:
    for t in TEAMS:
        lead = world.leads[t.slug]
        inv.add_node(
            t.id, "Team", t.name,
            {
                "department": t.department, "lead_user_id": lead.id, "oncall_channel": t.oncall,
                "member_count": len(world.by_team.get(t.slug, [])), "slug": t.slug,
            },
            source=SOURCE_WIZ, source_id=f"team-{t.slug}", first_seen="2023-01-09T09:00:00Z",
        )
    inv.storyline.update({
        "team_platform": sc.TEAM_PLATFORM, "team_payments": sc.TEAM_PAYMENTS, "team_treasury": sc.TEAM_TREASURY,
        "team_corp_it": sc.TEAM_CORP_IT,
    })


def _emit_users(inv: Inventory, world: World, r) -> None:  # type: ignore[no-untyped-def]
    for idx, p in enumerate(world.people):
        lead = world.leads[p.team.slug]
        manager_id = lead.id if lead is not p else None
        hire = days_ago(r, 60, 2400)
        last_login = minutes_ago(r, 5, 3 * 1440) if p.status == "active" else days_ago(r, 20, 200)
        inv.add_node(
            p.id, "HumanUser", p.display_name,
            {
                "email": f"{p.login}@corp.larkspur.example",
                "login": p.login,
                "display_name": p.display_name,
                "first_name": p.first,
                "last_name": p.last,
                "title": p.title,
                "department": p.team.user_department,
                "team_id": p.team.id,
                "location": p.location,
                "is_privileged": p.privileged,
                "is_executive": p.executive,
                "mfa_enabled": p.status != "deprovisioned" and r.random() < 0.985,
                "status": p.status,
                "manager_id": manager_id,
                "employee_id": f"E{100000 + idx:06d}",
                "employment_type": "contractor" if p.contractor else "employee",
                "okta_id": "00u" + hexid("okta", p.login, length=17),
                "last_login": last_login,
            },
            source=SOURCE_OKTA, source_id="00u" + hexid("okta", p.login, length=17), first_seen=hire, last_seen=last_login,
        )
        inv.add_edge("MEMBER_OF", p.id, p.team.id, {"membership": "team"}, source=SOURCE_OKTA, first_seen=hire)
    for slug, lead in world.leads.items():
        inv.add_edge("LEADS", lead.id, TEAM_BY_SLUG[slug].id, source=SOURCE_WIZ)
    inv.storyline.update({
        "user_dana": sc.USER_DANA, "user_mreyes": sc.USER_MREYES, "user_pkaur": sc.USER_PKAUR,
        "user_jokafor": sc.USER_JOKAFOR, "user_lchen": sc.USER_LCHEN,
    })


# group name -> (description, privileged)
STATIC_GROUPS: dict[str, tuple[str, bool]] = {
    "all-employees": ("All active employees", False),
    "okta-admins": ("Okta super administrators", True),
    "aws-prod-admins": ("AWS SSO: AdministratorAccess in larkspur-prod", True),
    "aws-prod-readonly": ("AWS SSO: ReadOnlyAccess in larkspur-prod", False),
    "aws-shared-admins": ("AWS SSO: AdministratorAccess in larkspur-shared-services", True),
    "aws-staging-power": ("AWS SSO: PowerUserAccess in larkspur-staging", False),
    "aws-dev-power": ("AWS SSO: PowerUserAccess in larkspur-dev-sandbox", False),
    "aws-data-admins": ("AWS SSO: AdministratorAccess in larkspur-data-platform", True),
    "aws-corp-admins": ("AWS SSO: AdministratorAccess in larkspur-corp-it", True),
    "corp-it-admins": ("Corporate IT administrators (AD Domain Admins, MDM, corp AWS)", True),
    "gcp-ml-admins": ("GCP project owners for larkspur-ml-fraud", True),
    "azure-corp-admins": ("Azure subscription owners for larkspur-corp-azure", True),
    "github-org-owners": ("GitHub organization owners", True),
    "k8s-cluster-admins": ("EKS cluster-admin binding", True),
    "pci-cardholder-access": ("Approved for access to cardholder data environment", True),
    "breakglass-approvers": ("Approvers for break-glass access requests", True),
    "wallet-admin-console": ("Wallet back-office console administrators", True),
    "payments-ops-console": ("Payments operations console with refund authority", True),
    "vpn-users": ("Remote access VPN entitlement", False),
    "github-org-members": ("GitHub organization members", False),
    "mac-users": ("macOS fleet (Jamf managed)", False),
    "contractors": ("External contractors with limited entitlements", False),
    "oncall-payments": ("Payments on-call rotation", False),
    "oncall-platform": ("Platform on-call rotation", False),
    "oncall-wallet": ("Wallet on-call rotation", False),
    "oncall-data": ("Data platform on-call rotation", False),
    "finance-approvers": ("Wire and settlement approvers", False),
    "treasury-sftp-users": ("Settlement-file SFTP access on bas-01 (svc-finops-sftp)", False),
    "exec-leadership": ("Executive leadership team", False),
    "hr-confidential": ("HR confidential records access", False),
    "legal-privileged": ("Legal privileged matters", False),
    "sales-crm-users": ("CRM licensed users", False),
    "support-tooling": ("Support desk tooling", False),
    "fraud-case-tools": ("Fraud case management tooling", False),
    "aml-monitoring-users": ("AML transaction monitoring console", False),
    "data-lake-readers": ("Read access to curated data lake zones", False),
    "bi-dashboard-viewers": ("BI dashboards viewer entitlement", False),
    "mdm-pilot": ("MDM policy pilot ring", False),
    "beta-features": ("Internal beta features ring", False),
    "security-champions": ("Security champions program", False),
    "compliance-evidence-readers": ("Compliance evidence repository readers", False),
}


def _emit_groups(inv: Inventory, world: World) -> None:
    r = rng("inventory.groups")
    names: list[str] = list(STATIC_GROUPS)
    descriptions: dict[str, tuple[str, bool]] = dict(STATIC_GROUPS)
    for t in TEAMS:
        names.append(t.slug)
        descriptions[t.slug] = (f"{t.name} team", False)
    for dept in DEPARTMENT_WEIGHTS:
        slug = "dept-" + re.sub(r"[^a-z]+", "-", dept.lower()).strip("-")
        names.append(slug)
        descriptions[slug] = (f"{dept} department", False)
    names.append("dept-corporate-it")
    descriptions["dept-corporate-it"] = ("Corporate IT department", False)

    members: dict[str, list[str]] = {n: [] for n in names}
    user_groups: dict[str, list[str]] = {}

    def join(p: Person, *group_names: str) -> None:
        for g in group_names:
            if p.id not in members[g]:
                members[g].append(p.id)
                user_groups.setdefault(p.id, []).append(g)

    for p in world.people:
        if p.status == "deprovisioned":
            continue
        dept_slug = "dept-" + re.sub(r"[^a-z]+", "-", p.team.user_department.lower()).strip("-")
        join(p, "all-employees", p.team.slug, dept_slug)
        if p.mac:
            join(p, "mac-users")
        if p.contractor:
            join(p, "contractors")
        if p.location == "Remote" or r.random() < 0.55:
            join(p, "vpn-users")
        if p.executive:
            join(p, "exec-leadership")
        dept = p.team.department
        slug = p.team.slug
        if dept == "Engineering":
            join(p, "github-org-members")
            if r.random() < 0.35:
                join(p, "beta-features")
            if r.random() < 0.08:
                join(p, "security-champions")
        if slug == "platform-eng":
            join(p, "aws-shared-admins" if p.privileged else "aws-staging-power", "aws-dev-power")
            if p.privileged:
                join(p, "k8s-cluster-admins", "aws-prod-readonly")
            if r.random() < 0.5:
                join(p, "oncall-platform")
        elif slug in ("payments-platform", "wallet-eng", "baas-api"):
            join(p, "aws-staging-power", "aws-dev-power")
            if p.privileged:
                join(p, "aws-prod-readonly", "pci-cardholder-access")
            if r.random() < 0.4:
                join(p, "oncall-payments" if slug != "wallet-eng" else "oncall-wallet")
        elif slug in ("data-platform", "fraud-ml"):
            join(p, "aws-dev-power", "data-lake-readers")
            if p.privileged:
                join(p, "aws-data-admins")
            if slug == "fraud-ml" and p.privileged:
                join(p, "gcp-ml-admins")
            if r.random() < 0.4:
                join(p, "oncall-data")
        elif slug == "security-eng":
            join(p, "aws-prod-readonly", "aws-staging-power", "aws-dev-power")
            if p.privileged:
                join(p, "aws-prod-admins", "breakglass-approvers", "okta-admins")
        elif slug == "mobile-eng":
            join(p, "aws-dev-power")
        elif slug == "corp-it":
            join(p, "support-tooling")
            if p.privileged:
                join(p, "corp-it-admins", "aws-corp-admins", "azure-corp-admins", "okta-admins")
        elif slug == "payment-operations":
            join(p, "payments-ops-console")
            if r.random() < 0.3:
                join(p, "pci-cardholder-access")
        elif slug == "fraud-operations":
            join(p, "fraud-case-tools")
        elif slug == "customer-support":
            join(p, "support-tooling")
            if r.random() < 0.2:
                join(p, "wallet-admin-console")
        elif slug == "finance-treasury":
            join(p, "finance-approvers", "treasury-sftp-users", "bi-dashboard-viewers")
        elif slug == "finance-accounting":
            join(p, "bi-dashboard-viewers")
            if r.random() < 0.3:
                join(p, "finance-approvers")
        elif slug == "sales":
            join(p, "sales-crm-users")
        elif slug == "marketing":
            join(p, "sales-crm-users", "bi-dashboard-viewers")
        elif slug == "compliance-risk":
            join(p, "aml-monitoring-users", "compliance-evidence-readers")
            if r.random() < 0.25:
                join(p, "pci-cardholder-access")
        elif slug == "executive-office":
            if "Counsel" in p.title:
                join(p, "legal-privileged")
            if "HR" in p.title or "People" in p.title or "Talent" in p.title:
                join(p, "hr-confidential")
            if p.executive:
                join(p, "bi-dashboard-viewers")
        if r.random() < 0.06:
            join(p, "mdm-pilot")

    # storyline pins
    dana = world.by_login["dwhitfield"]
    join(dana, "finance-treasury", "all-employees", "treasury-sftp-users", "vpn-users")
    marcus = world.by_login["mreyes"]
    join(marcus, "corp-it-admins", "aws-corp-admins", "okta-admins", "vpn-users")
    for lead in world.leads.values():
        if lead.team.department == "Engineering":
            join(lead, "github-org-owners")

    for gname in names:
        gid = f"group:okta:{gname}"
        desc, priv = descriptions[gname]
        inv.add_node(
            gid, "Group", gname,
            {"description": desc, "member_count": len(members[gname]), "privileged": priv, "okta_id": "00g" + hexid("okta-group", gname, length=17)},
            source=SOURCE_OKTA, source_id="00g" + hexid("okta-group", gname, length=17), first_seen="2023-01-09T09:00:00Z",
        )
        world.groups[gname] = gid
        for uid in members[gname]:
            inv.add_edge("MEMBER_OF", uid, gid, {"membership": "group"}, source=SOURCE_OKTA)
    world.group_members = members
    world.user_groups = user_groups
    for uid, groups in user_groups.items():
        inv.props(uid)["groups"] = list(groups)
    inv.storyline.update({"group_treasury": sc.GROUP_TREASURY, "group_all": sc.GROUP_ALL})
