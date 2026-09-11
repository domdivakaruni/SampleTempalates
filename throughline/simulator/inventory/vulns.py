"""Software inventory: Package nodes per container image, host and function, attached to CVE catalog components.

Only ``HAS_PACKAGE`` and ``HAS_VULNERABILITY`` are emitted here (``VULNERABLE_TO`` roll-ups live in posture.py).
``Vulnerability`` nodes are owned by the threat-intel stage; we only reference ``cve:<id>`` ids from the catalog.
Components tied to the storyline's internet-exposed hosts are *restricted*: they never appear on other assets, so
the "actively exploited + internet exposed" result set stays under control.
"""
from __future__ import annotations

import random
from typing import Any

from throughline.simulator import storyline_constants as sc
from throughline.simulator.catalog.cves import CVES
from throughline.simulator.common import rng
from throughline.simulator.inventory._base import SOURCE_WIZ, Inventory
from throughline.simulator.inventory.cloud import Estate

# component -> [(version, [cve ids])]; the last entry of each list is a fixed version
VERSIONS: dict[str, list[tuple[str, list[str]]]] = {
    "log4j-core": [("2.14.1", ["CVE-2021-44228"]), ("2.17.1", [])],
    "citrix-netscaler-gateway": [("13.1-48.47", ["CVE-2023-4966"]), ("13.1-49.15", [])],
    "pan-os-globalprotect": [("11.1.0", ["CVE-2024-3400"]), ("11.1.2-h3", [])],
    "confluence-server": [("8.5.1", ["CVE-2023-22515"]), ("8.5.2", [])],
    "spring-beans": [("5.3.17", ["CVE-2022-22965"]), ("5.3.18", [])],
    "jenkins": [("2.426.2", ["CVE-2024-23897"]), ("2.452.3", [])],
    "windows-print-spooler": [("10.0.20348.887", ["CVE-2021-34527"]), ("10.0.20348.2700", [])],
    "openssh-server": [("9.6p1", ["CVE-2024-6387"]), ("8.9p1", ["CVE-2024-6387"]), ("9.8p1", [])],
    "exchange-server": [("15.2.858.5", ["CVE-2021-26855"]), ("15.2.1258.12", [])],
    "connectwise-screenconnect": [("23.9.7", ["CVE-2024-1709"]), ("23.9.8", [])],
    "papercut-mf": [("20.1.6", ["CVE-2023-27350"]), ("20.1.7", [])],
    "sudo": [("1.9.5p1", ["CVE-2021-3156"]), ("1.9.15p5", [])],
    "linux-kernel": [("5.15.0-1052-aws", ["CVE-2022-0847"]), ("6.5.0-1020-aws", ["CVE-2026-90104"]), ("6.8.0-1015-aws", ["CVE-2026-90104"]), ("6.10.2-1004-aws", [])],
    "nginx": [("1.24.0", ["CVE-2023-44487"]), ("1.26.1", ["CVE-2026-90014"]), ("1.27.2", [])],
    "commons-text": [("1.9", ["CVE-2022-42889"]), ("1.10.0", [])],
    "windows-netlogon": [("10.0.17763.1339", ["CVE-2020-1472"]), ("10.0.20348.2700", [])],
    "openssl": [("3.2.1", ["CVE-2026-90011"]), ("3.0.13", []), ("3.2.5", [])],
    "envoy": [("1.30.1", ["CVE-2026-90022"]), ("1.31.3", [])],
    "jackson-databind": [("2.16.1", ["CVE-2026-90031"]), ("2.17.2", [])],
    "spring-security": [("6.2.4", ["CVE-2026-90035"]), ("6.3.4", [])],
    "tomcat-embed": [("10.1.24", ["CVE-2026-90040"]), ("10.1.31", [])],
    "next": [("14.2.5", ["CVE-2026-90048"]), ("14.2.15", [])],
    "lodash": [("4.17.21", ["CVE-2026-90052"]), ("4.17.22", [])],
    "express": [("4.19.2", ["CVE-2026-90057"]), ("4.21.1", [])],
    "axios": [("1.7.2", ["CVE-2026-90063"]), ("1.7.7", [])],
    "pillow": [("10.3.0", ["CVE-2026-90070"]), ("10.4.1", [])],
    "requests": [("2.31.0", ["CVE-2026-90074"]), ("2.32.3", [])],
    "cryptography": [("42.0.5", ["CVE-2026-90081"]), ("43.0.1", [])],
    "kubernetes-ingress-nginx": [("1.10.1", ["CVE-2026-90088"]), ("1.11.3", [])],
    "containerd": [("1.7.18", ["CVE-2026-90093"]), ("1.7.21", [])],
    "runc": [("1.1.12", ["CVE-2026-90099"]), ("1.1.14", [])],
    "glibc": [("2.35-0ubuntu3.8", ["CVE-2026-90110"]), ("2.40", [])],
    "curl": [("8.5.0", ["CVE-2026-90117"]), ("8.9.1", [])],
    "grafana": [("11.0.0", ["CVE-2026-90130"]), ("11.1.5", [])],
    "keycloak": [("24.0.4", ["CVE-2026-90136"]), ("25.0.3", [])],
    "redis": [("7.2.4", ["CVE-2026-90142"]), ("7.2.6", [])],
    "postgresql": [("16.2", ["CVE-2026-90149"]), ("16.4", [])],
    "elasticsearch": [("8.14.1", ["CVE-2026-90155"]), ("8.15.1", [])],
    "vpn-gateway-firmware": [("4.2.1", ["CVE-2026-90161"]), ("4.3.3", [])],
    "windows-smb": [("10.0.20348.2461", ["CVE-2026-90180"]), ("10.0.20348.2700", [])],
    "gitlab": [("17.2.1", ["CVE-2026-90123"]), ("17.3.2", [])],
}
# components that only appear where the storyline/host spec puts them
RESTRICTED: set[str] = {
    "log4j-core", "citrix-netscaler-gateway", "pan-os-globalprotect", "confluence-server", "spring-beans", "jenkins", "exchange-server",
    "connectwise-screenconnect", "papercut-mf", "windows-netlogon", "vpn-gateway-firmware", "kubernetes-ingress-nginx", "grafana", "keycloak",
    "elasticsearch", "gitlab", "redis", "postgresql", "envoy",
}

# Components whose catalog CVEs carry an exploitation status in the threat-intel stage (active, mass_exploitation
# or poc_public). They stay off internet-exposed assets other than the eight scripted hosts, so question 5
# ("internet-exposed hosts with an actively exploited vulnerability") returns exactly those eight rows; internal
# assets may still carry them and feed the TI exposure panel at a lower exposure. Cross-checked against the TI
# catalog in tests/unit/test_inventory.py.
TI_TRACKED_COMPONENTS: set[str] = {
    "log4j-core", "citrix-netscaler-gateway", "pan-os-globalprotect", "spring-beans", "jenkins", "confluence-server",
    "ivanti-connect-secure", "connectwise-screenconnect", "moveit-transfer", "fortios-sslvpn", "envoy", "next",
    "kubernetes-ingress-nginx", "vpn-gateway-firmware", "gitlab", "spring-security", "pillow",
}
# the five scripted non-Log4Shell exposed hosts carry these; their siblings run the fixed build
NAMED_HOST_COMPONENTS: tuple[str, ...] = ("citrix-netscaler-gateway", "pan-os-globalprotect", "spring-beans", "jenkins", "confluence-server")
# internet-facing prod/staging services are biased towards a vulnerable OpenSSL build so the estate carries a few
# dozen natural toxic combinations (exposed + critical CVE + sensitive data reach); the storyline hosts stay strongest
TOXIC_IMAGE_RATE = 0.7
TOXIC_HOST_RATE = 0.7

# benign filler packages (never vulnerable): ecosystem -> [(name, version)]
FILLER: dict[str, list[tuple[str, str]]] = {
    "maven": [("guava", "33.2.1-jre"), ("slf4j-api", "2.0.13"), ("logback-classic", "1.5.6"), ("micrometer-core", "1.13.1"), ("hibernate-core", "6.5.2.Final"), ("postgresql-jdbc", "42.7.3"), ("aws-sdk-java", "2.26.3"), ("netty-all", "4.1.111.Final"), ("kafka-clients", "3.7.0"), ("bouncycastle-bcprov", "1.78.1")],
    "npm": [("react", "18.3.1"), ("typescript", "5.5.3"), ("pg", "8.12.0"), ("winston", "3.13.1"), ("aws-sdk", "2.1650.0"), ("prisma", "5.16.1"), ("fastify", "4.28.1"), ("zod", "3.23.8"), ("dayjs", "1.11.11")],
    "pypi": [("boto3", "1.34.140"), ("numpy", "1.26.4"), ("pandas", "2.2.2"), ("fastapi", "0.111.0"), ("sqlalchemy", "2.0.31"), ("pydantic", "2.8.2"), ("scikit-learn", "1.5.1"), ("torch", "2.3.1"), ("uvicorn", "0.30.1"), ("pyjwt", "2.8.0")],
    "go": [("golang.org/x/net", "0.27.0"), ("github.com/aws/aws-sdk-go-v2", "1.30.1"), ("google.golang.org/grpc", "1.65.0"), ("github.com/gin-gonic/gin", "1.10.0"), ("github.com/prometheus/client_golang", "1.19.1"), ("golang.org/x/crypto", "0.25.0")],
    "os": [("bash", "5.2.21"), ("systemd", "255.4"), ("zlib", "1.3.1"), ("libxml2", "2.12.7"), ("ca-certificates", "20240203"), ("coreutils", "9.4"), ("libssh2", "1.11.0"), ("python3-minimal", "3.12.3")],
}

STACK_ECOSYSTEM: dict[str, str] = {"java": "maven", "node": "npm", "python": "pypi", "go": "go", "os": "os", "ingress": "go", "redis": "os", "windows": "os", "appliance": "os", "k8s-node": "os"}
# stack -> weighted vulnerable-capable components
STACK_COMPONENTS: dict[str, dict[str, float]] = {
    "java": {"jackson-databind": 3, "spring-security": 3, "tomcat-embed": 3, "commons-text": 2},
    "node": {"next": 2, "lodash": 3, "express": 3, "axios": 3},
    "python": {"pillow": 2, "requests": 3, "cryptography": 3},
    "go": {"curl": 1, "openssl": 1},
    "ingress": {"kubernetes-ingress-nginx": 5, "nginx": 3},
    "redis": {"redis": 5},
    "os": {"openssl": 3, "glibc": 2, "curl": 3},
}
IMAGE_BASE: dict[str, float] = {"openssl": 3, "glibc": 2, "curl": 3}
HOST_LINUX: dict[str, float] = {"openssh-server": 4, "sudo": 2, "linux-kernel": 3, "glibc": 2, "curl": 2, "openssl": 2}
HOST_WINDOWS: dict[str, float] = {"windows-print-spooler": 3, "windows-smb": 3}
NODE_COMPONENTS: dict[str, float] = {"linux-kernel": 3, "containerd": 3, "runc": 2, "openssh-server": 1}

VULN_RATE = 0.65


def ecosystem_of(component: str, fallback: str) -> str:
    cves = [c for c in CVES.values() if c.component == component]
    if not cves:
        return fallback
    eco = cves[0].ecosystem
    return "os" if eco == "appliance" else eco


def package_id(scope_id: str, name: str, version: str) -> str:
    return f"package:{scope_id.split(':', 1)[1]}:{name}:{version}"


def is_exposed(inv: Inventory, asset: str) -> bool:
    """Internet reachability from the raw facts the cloud pass left behind (posture.py later derives the ``EXPOSES``
    edges from the same facts): a public IP behind a security group open to 0.0.0.0/0, an internet-facing load
    balancer target, or an enabled function URL."""
    label = inv.label(asset)
    p = inv.props(asset)
    meta = inv.meta[asset]
    if label == "VirtualMachine":
        if meta.get("lb_ports"):
            return True
        return bool(p.get("public_ip")) and any(inv.props(sg)["open_to_internet"] for sg in inv.out(asset, "HAS_SECURITY_GROUP"))
    if label == "Workload":
        return bool(meta.get("lb_ports"))
    if label == "ServerlessFunction":
        return bool(p.get("url_enabled"))
    return False


def component_pool(base: dict[str, float], exposed: bool, *, allow_restricted: bool = False) -> dict[str, float]:
    return {k: v for k, v in base.items() if (allow_restricted or k not in RESTRICTED) and not (exposed and k in TI_TRACKED_COMPONENTS)}


def _has_component(inv: Inventory, scope_id: str, component: str) -> bool:
    return any(inv.props(pid).get("component") == component for pid in inv.out(scope_id, "HAS_PACKAGE"))


def build_vulns(inv: Inventory, est: Estate) -> None:
    _storyline_packages(inv)
    _image_packages(inv, est)
    _host_packages(inv, est)
    _function_packages(inv, est)
    inv.storyline["edge_log4j_package"] = sc.EDGE_LOG4J_PACKAGE
    inv.storyline["log4shell"] = sc.LOG4SHELL


def add_package(inv: Inventory, scope_id: str, name: str, version: str, ecosystem: str, cve_ids: list[str], *, component: str | None = None) -> str:
    pid = package_id(scope_id, name, version)
    if inv.has(pid):
        return pid
    fixed = None
    if cve_ids:
        fixed = CVES[cve_ids[0]].fixed_version
    inv.add_node(
        pid, "Package", f"{name} {version}",
        {"package_name": name, "version": version, "ecosystem": ecosystem, "scope": scope_id, "component": component or name, "cve_ids": [f"cve:{c}" for c in cve_ids], "fixed_version": fixed, "vulnerable": bool(cve_ids)},
        source=SOURCE_WIZ, source_id=pid.split(":", 1)[1], first_seen=inv.nodes[scope_id]["first_seen"], scope=scope_id, kind="package",
    )
    inv.add_edge("HAS_PACKAGE", scope_id, pid, source=SOURCE_WIZ, first_seen=inv.nodes[scope_id]["first_seen"])
    for cid in cve_ids:
        inv.add_edge("HAS_VULNERABILITY", pid, f"cve:{cid}", {"fixed_version": CVES[cid].fixed_version}, source=SOURCE_WIZ, first_seen=inv.nodes[scope_id]["first_seen"])
    return pid


def _pick_version(r: random.Random, component: str, vulnerable: bool) -> tuple[str, list[str]]:
    options = VERSIONS[component]
    vuln_opts = [o for o in options if o[1]]
    fixed_opts = [o for o in options if not o[1]]
    if vulnerable and vuln_opts:
        return r.choice(vuln_opts)
    return r.choice(fixed_opts or options)


def _component_package(inv: Inventory, r: random.Random, scope_id: str, component: str, *, force_vulnerable: bool | None = None) -> str:
    vulnerable = (r.random() < VULN_RATE) if force_vulnerable is None else force_vulnerable
    version, cves = _pick_version(r, component, vulnerable)
    return add_package(inv, scope_id, component, version, ecosystem_of(component, "os"), cves, component=component)


def _storyline_packages(inv: Inventory) -> None:
    add_package(inv, sc.EDGE_VM, "log4j-core", "2.14.1", "maven", ["CVE-2021-44228"])
    assert inv.has(sc.EDGE_LOG4J_PACKAGE), "storyline package id mismatch"
    add_package(inv, sc.EDGE_VM, "curl", "8.5.0", "os", ["CVE-2026-90117"])
    add_package(inv, sc.EDGE_VM, "openssh-server", "9.8p1", "os", [])
    add_package(inv, sc.EDGE_IMAGE, "log4j-core", "2.14.1", "maven", ["CVE-2021-44228"])
    add_package(inv, sc.EDGE_IMAGE, "jackson-databind", "2.17.2", "maven", [])
    add_package(inv, sc.EDGE_IMAGE, "openssl", "3.0.13", "os", [])
    add_package(inv, sc.EDGE_IMAGE, "glibc", "2.35-0ubuntu3.8", "os", ["CVE-2026-90110"])
    add_package(inv, sc.STG_EDGE_VM, "log4j-core", "2.14.1", "maven", ["CVE-2021-44228"])
    add_package(inv, sc.STG_EDGE_VM, "openssh-server", "9.8p1", "os", [])
    add_package(inv, sc.DEV_LOG4J_VM, "log4j-core", "2.14.1", "maven", ["CVE-2021-44228"])
    add_package(inv, sc.DEV_LOG4J_VM, "openssh-server", "9.6p1", "os", ["CVE-2024-6387"])
    # patched sibling of stmt-render-2a (host and image)
    for vm in inv.ids("VirtualMachine"):
        if inv.name(vm) == "stmt-render-1a":
            add_package(inv, vm, "log4j-core", "2.17.1", "maven", [])
            add_package(inv, vm, "openssh-server", "9.8p1", "os", [])
    if inv.has("image:ecr:larkspur/statement-render:3.8.2"):
        add_package(inv, "image:ecr:larkspur/statement-render:3.8.2", "log4j-core", "2.17.1", "maven", [])
        add_package(inv, "image:ecr:larkspur/statement-render:3.8.2", "jackson-databind", "2.17.2", "maven", [])
        add_package(inv, "image:ecr:larkspur/statement-render:3.8.2", "openssl", "3.0.13", "os", [])
        add_package(inv, "image:ecr:larkspur/statement-render:3.8.2", "glibc", "2.40", "os", [])
    add_package(inv, sc.BASTION_VM, "openssh-server", "9.6p1", "os", ["CVE-2024-6387"])
    add_package(inv, sc.BASTION_VM, "sudo", "1.9.15p5", "os", [])
    add_package(inv, sc.BASTION_VM, "linux-kernel", "6.1.94-99.176.amzn2023", "os", [])
    add_package(inv, sc.SCANNER_VM, "openssh-server", "9.8p1", "os", [])
    add_package(inv, sc.DEV_SANDBOX_VM, "sudo", "1.9.15p5", "os", [])
    add_package(inv, sc.DEV_SANDBOX_VM, "openssh-server", "9.6p1", "os", ["CVE-2024-6387"])
    add_package(inv, sc.FILESHARE_VM, "windows-print-spooler", "10.0.20348.887", "os", ["CVE-2021-34527"])
    add_package(inv, sc.FILESHARE_VM, "windows-smb", "10.0.20348.2700", "os", [])
    # the five other internet-exposed hosts and the named internal legacy hosts
    add_package(inv, "vm:aws:i-0ns1c3d5e7f9a1b3c5", "citrix-netscaler-gateway", "13.1-48.47", "os", ["CVE-2023-4966"])
    add_package(inv, "vm:aws:i-0pan2d4f6a8c0e2a4b", "pan-os-globalprotect", "11.1.0", "os", ["CVE-2024-3400"])
    add_package(inv, "vm:aws:i-0spr3e5a7c9b1d3f5e", "spring-beans", "5.3.17", "maven", ["CVE-2022-22965"])
    add_package(inv, "vm:aws:i-0spr3e5a7c9b1d3f5e", "openssh-server", "9.8p1", "os", [])
    add_package(inv, "vm:aws:i-0jnk4f6b8d0c2e4a6c", "jenkins", "2.426.2", "maven", ["CVE-2024-23897"])
    add_package(inv, "vm:aws:i-0jnk4f6b8d0c2e4a6c", "openssh-server", "9.8p1", "os", [])
    add_package(inv, "vm:aws:i-0cnf5a7c9e1d3b5f7a", "confluence-server", "8.5.1", "maven", ["CVE-2023-22515"])
    add_package(inv, "vm:aws:i-0cnf5a7c9e1d3b5f7a", "postgresql", "16.4", "os", [])
    for vm in inv.ids("VirtualMachine"):
        name = inv.name(vm)
        comp = inv.meta[vm].get("component")
        if comp in ("citrix-netscaler-gateway", "pan-os-globalprotect", "spring-beans", "jenkins", "confluence-server") and not inv.out(vm, "HAS_PACKAGE"):
            # siblings of the named hosts run the fixed version
            fixed = VERSIONS[comp][-1][0]
            add_package(inv, vm, comp, fixed, ecosystem_of(comp, "os"), [])
        elif comp in ("vpn-gateway-firmware", "exchange-server", "connectwise-screenconnect", "papercut-mf", "windows-netlogon") and not inv.out(vm, "HAS_PACKAGE"):
            # legacy appliances/servers run the vulnerable build unless they face the Internet (question 5 stays at eight rows)
            version, cves = VERSIONS[comp][-1] if is_exposed(inv, vm) else VERSIONS[comp][0]
            add_package(inv, vm, comp, version, ecosystem_of(comp, "os"), cves)
        elif name.startswith("partner-api-") and not any(inv.props(p)["package_name"] == "spring-beans" for p in inv.out(vm, "HAS_PACKAGE")):
            add_package(inv, vm, "spring-beans", "5.3.18", "maven", [])


def _image_packages(inv: Inventory, est: Estate) -> None:
    for image_id in sorted(est.images):
        if inv.out(image_id, "HAS_PACKAGE"):
            continue  # storyline image already populated
        r = rng(f"inventory.vulns.image.{image_id}")
        meta = est.images[image_id]
        stack = meta["stack"]
        eco = STACK_ECOSYSTEM.get(stack, "os")
        runners = inv.inn(image_id, "RUNS_IMAGE")
        exposed = any(is_exposed(inv, a) for a in runners)
        pool = component_pool(STACK_COMPONENTS.get(stack, {}), exposed, allow_restricted=stack in ("ingress", "redis"))
        n_stack = r.choice([1, 2, 2, 3]) if pool else 0
        for comp in _weighted_sample(r, pool, n_stack):
            _component_package(inv, r, image_id, comp)
        # base image package (toxic-combination bias for internet-facing prod/staging services)
        toxic = exposed and any(inv.meta[a].get("env") in ("prod", "staging") for a in runners) and r.random() < TOXIC_IMAGE_RATE
        if toxic:
            _component_package(inv, r, image_id, "openssl", force_vulnerable=True)
        else:
            for comp in _weighted_sample(r, IMAGE_BASE, 1):
                _component_package(inv, r, image_id, comp)
        # filler
        fillers = FILLER.get(eco, FILLER["os"])
        for name, version in r.sample(fillers, 1):
            add_package(inv, image_id, name, version, eco, [])
        _update_image_counts(inv, image_id)
    _update_image_counts(inv, sc.EDGE_IMAGE)


def _update_image_counts(inv: Inventory, image_id: str) -> None:
    crit = high = 0
    for pid in inv.out(image_id, "HAS_PACKAGE"):
        for cve in inv.out(pid, "HAS_VULNERABILITY"):
            sev = CVES[cve.split(":", 1)[1]].severity
            crit += sev == "critical"
            high += sev == "high"
    inv.props(image_id)["vuln_count_critical"] = crit
    inv.props(image_id)["vuln_count_high"] = high


def _host_packages(inv: Inventory, est: Estate) -> None:
    for vm in est.vms:
        if inv.out(vm, "HAS_PACKAGE"):
            continue
        r = rng(f"inventory.vulns.host.{vm}")
        meta = inv.meta[vm]
        stack = meta.get("stack")
        exposed = is_exposed(inv, vm)
        if stack == "appliance":
            comp = meta.get("component")
            if comp and comp in VERSIONS:
                _component_package(inv, r, vm, comp, force_vulnerable=False)
            continue
        if stack == "k8s-node":
            for comp in _weighted_sample(r, NODE_COMPONENTS, r.choice([1, 2, 2])):
                _component_package(inv, r, vm, comp)
            continue
        if meta.get("os_family") == "windows":
            if r.random() < 0.7:
                for comp in _weighted_sample(r, HOST_WINDOWS, 1):
                    _component_package(inv, r, vm, comp)
            comp = meta.get("component")
            if comp and comp in VERSIONS and comp not in ("exchange-server", "connectwise-screenconnect", "papercut-mf", "windows-netlogon"):
                _component_package(inv, r, vm, comp)
            continue
        pool = dict(HOST_LINUX)
        if exposed and meta.get("env") in ("prod", "staging") and r.random() < TOXIC_HOST_RATE:
            _component_package(inv, r, vm, "openssl", force_vulnerable=True)  # toxic-combination bias
            pool.pop("openssl")
        n = 1 if r.random() < 0.55 else 2
        for comp in _weighted_sample(r, pool, n):
            _component_package(inv, r, vm, comp)
        comp = meta.get("component")
        if comp and comp in VERSIONS and comp not in NAMED_HOST_COMPONENTS and not _has_component(inv, vm, comp):
            if exposed and comp in TI_TRACKED_COMPONENTS:
                add_package(inv, vm, comp, VERSIONS[comp][-1][0], ecosystem_of(comp, "os"), [], component=comp)
            else:
                _component_package(inv, r, vm, comp)
        if stack == "os" and r.random() < 0.25:
            add_package(inv, vm, *r.choice(FILLER["os"]), "os", [])


def _function_packages(inv: Inventory, est: Estate) -> None:
    for fid in est.functions:
        r = rng(f"inventory.vulns.fn.{fid}")
        stack = inv.meta[fid].get("stack", "python")
        eco = STACK_ECOSYSTEM.get(stack, "pypi")
        if r.random() < 0.2:
            continue
        pool = component_pool(STACK_COMPONENTS.get(stack, STACK_COMPONENTS["python"]), is_exposed(inv, fid))
        for comp in _weighted_sample(r, pool, 1):
            _component_package(inv, r, fid, comp)
        if r.random() < 0.5:
            add_package(inv, fid, *r.choice(FILLER.get(eco, FILLER["pypi"])), eco, [])


def _weighted_sample(r: random.Random, pool: dict[str, float], n: int) -> list[str]:
    items = dict(pool)
    out: list[str] = []
    while items and len(out) < n:
        keys = list(items)
        weights = [items[k] for k in keys]
        choice = r.choices(keys, weights=weights, k=1)[0]
        out.append(choice)
        del items[choice]
    return out


def cve_ids_of(inv: Inventory, scope_id: str) -> list[tuple[str, str]]:
    """(cve node id, package id) pairs for the packages of an asset."""
    out: list[tuple[str, str]] = []
    for pid in inv.out(scope_id, "HAS_PACKAGE"):
        for cve in inv.out(pid, "HAS_VULNERABILITY"):
            out.append((cve, pid))
    return out


def cve_meta(cve_node_id: str) -> Any:
    return CVES[cve_node_id.split(":", 1)[1]]
