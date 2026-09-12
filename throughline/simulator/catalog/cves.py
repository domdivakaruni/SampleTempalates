"""CVE catalog for the simulated estate.

Real identifiers are included for realism (CVSS values are the public base scores; EPSS values are illustrative
approximations, and KEV flags reflect the public catalog as commonly known). Every attribution of a CVE to a
threat actor in this prototype is fictional. Synthetic identifiers use the CVE-2026-9xxxx range and are flagged
``synthetic=True``. ``component`` is the package/product name the simulator uses to attach the CVE to
packages, images and hosts; ``exposure_surface`` says whether the component is typically internet-reachable.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CVE:
    cve_id: str
    cvss: float
    epss: float
    kev: bool
    component: str
    ecosystem: str  # maven | npm | pypi | os | go | appliance
    affected_versions: str
    fixed_version: str
    published: str
    description: str
    synthetic: bool = False
    exposure_surface: str = "internal"  # internet | internal | local

    @property
    def node_id(self) -> str:
        return f"cve:{self.cve_id}"

    @property
    def severity(self) -> str:
        if self.cvss >= 9.0:
            return "critical"
        if self.cvss >= 7.0:
            return "high"
        if self.cvss >= 4.0:
            return "medium"
        return "low"


_REAL: list[CVE] = [
    CVE("CVE-2021-44228", 10.0, 0.97, True, "log4j-core", "maven", "2.0-beta9 - 2.14.1", "2.17.1", "2021-12-10T00:00:00Z", "Apache Log4j2 JNDI lookup remote code execution (Log4Shell).", exposure_surface="internet"),
    CVE("CVE-2023-4966", 9.4, 0.96, True, "citrix-netscaler-gateway", "appliance", "13.1 < 13.1-49.15", "13.1-49.15", "2023-10-10T00:00:00Z", "Citrix NetScaler ADC/Gateway sensitive information disclosure enabling session hijack (Citrix Bleed).", exposure_surface="internet"),
    CVE("CVE-2024-3400", 10.0, 0.96, True, "pan-os-globalprotect", "appliance", "10.2, 11.0, 11.1 unpatched", "11.1.2-h3", "2024-04-12T00:00:00Z", "PAN-OS GlobalProtect command injection.", exposure_surface="internet"),
    CVE("CVE-2023-22515", 10.0, 0.95, True, "confluence-server", "maven", "8.0.0 - 8.5.1", "8.5.2", "2023-10-04T00:00:00Z", "Atlassian Confluence broken access control allowing admin account creation.", exposure_surface="internet"),
    CVE("CVE-2024-21887", 9.1, 0.95, True, "ivanti-connect-secure", "appliance", "9.x, 22.x", "22.6R2.2", "2024-01-12T00:00:00Z", "Ivanti Connect Secure command injection.", exposure_surface="internet"),
    CVE("CVE-2023-46805", 8.2, 0.94, True, "ivanti-connect-secure", "appliance", "9.x, 22.x", "22.6R2.2", "2024-01-12T00:00:00Z", "Ivanti Connect Secure authentication bypass.", exposure_surface="internet"),
    CVE("CVE-2022-22965", 9.8, 0.95, True, "spring-beans", "maven", "5.3.0 - 5.3.17", "5.3.18", "2022-04-01T00:00:00Z", "Spring Framework RCE via data binding (Spring4Shell).", exposure_surface="internet"),
    CVE("CVE-2021-34527", 8.8, 0.94, True, "windows-print-spooler", "os", "Windows unpatched", "KB5004945", "2021-07-02T00:00:00Z", "Windows Print Spooler remote code execution (PrintNightmare).", exposure_surface="internal"),
    CVE("CVE-2023-34362", 9.8, 0.95, True, "moveit-transfer", "appliance", "< 2023.0.1", "2023.0.1", "2023-06-02T00:00:00Z", "MOVEit Transfer SQL injection leading to RCE.", exposure_surface="internet"),
    CVE("CVE-2024-6387", 8.1, 0.31, False, "openssh-server", "os", "8.5p1 - 9.7p1", "9.8p1", "2024-07-01T00:00:00Z", "OpenSSH signal handler race condition (regreSSHion).", exposure_surface="internet"),
    CVE("CVE-2023-38831", 7.8, 0.92, True, "winrar", "os", "< 6.23", "6.23", "2023-08-23T00:00:00Z", "WinRAR arbitrary code execution via crafted archives.", exposure_surface="local"),
    CVE("CVE-2022-30190", 7.8, 0.93, True, "windows-msdt", "os", "Windows unpatched", "KB5014699", "2022-06-01T00:00:00Z", "Microsoft Support Diagnostic Tool RCE (Follina).", exposure_surface="local"),
    CVE("CVE-2021-26855", 9.8, 0.97, True, "exchange-server", "os", "2013/2016/2019 unpatched", "KB5000871", "2021-03-02T00:00:00Z", "Microsoft Exchange SSRF (ProxyLogon).", exposure_surface="internet"),
    CVE("CVE-2023-20198", 10.0, 0.95, True, "cisco-ios-xe", "appliance", "16.x/17.x web UI", "17.9.4a", "2023-10-16T00:00:00Z", "Cisco IOS XE web UI privilege escalation.", exposure_surface="internet"),
    CVE("CVE-2024-1709", 10.0, 0.96, True, "connectwise-screenconnect", "appliance", "< 23.9.8", "23.9.8", "2024-02-21T00:00:00Z", "ConnectWise ScreenConnect authentication bypass.", exposure_surface="internet"),
    CVE("CVE-2022-26134", 9.8, 0.96, True, "confluence-server", "maven", "1.3.0 - 7.18.0", "7.18.1", "2022-06-03T00:00:00Z", "Atlassian Confluence OGNL injection RCE.", exposure_surface="internet"),
    CVE("CVE-2023-27350", 9.8, 0.95, True, "papercut-mf", "appliance", "< 20.1.7", "20.1.7", "2023-04-20T00:00:00Z", "PaperCut MF/NG improper access control RCE.", exposure_surface="internet"),
    CVE("CVE-2021-3156", 7.8, 0.90, True, "sudo", "os", "1.8.2 - 1.9.5p1", "1.9.5p2", "2021-01-26T00:00:00Z", "Sudo heap-based buffer overflow (Baron Samedit).", exposure_surface="local"),
    CVE("CVE-2022-0847", 7.8, 0.85, False, "linux-kernel", "os", "5.8 - 5.16.10", "5.16.11", "2022-03-07T00:00:00Z", "Linux kernel pipe page cache overwrite (Dirty Pipe).", exposure_surface="local"),
    CVE("CVE-2024-4577", 9.8, 0.94, True, "php-cgi", "os", "8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8", "8.3.8", "2024-06-07T00:00:00Z", "PHP CGI argument injection on Windows.", exposure_surface="internet"),
    CVE("CVE-2023-44487", 7.5, 0.80, True, "nginx", "os", "HTTP/2 implementations unpatched", "1.25.3", "2023-10-10T00:00:00Z", "HTTP/2 Rapid Reset denial of service.", exposure_surface="internet"),
    CVE("CVE-2022-42889", 9.8, 0.60, False, "commons-text", "maven", "1.5 - 1.9", "1.10.0", "2022-10-13T00:00:00Z", "Apache Commons Text variable interpolation RCE (Text4Shell).", exposure_surface="internet"),
    CVE("CVE-2023-2033", 8.8, 0.88, True, "google-chrome", "os", "< 112.0.5615.121", "112.0.5615.121", "2023-04-14T00:00:00Z", "Chrome V8 type confusion.", exposure_surface="local"),
    CVE("CVE-2024-21762", 9.8, 0.95, True, "fortios-sslvpn", "appliance", "7.4.0-7.4.2, 7.2.0-7.2.6", "7.4.3", "2024-02-08T00:00:00Z", "FortiOS SSL VPN out-of-bounds write.", exposure_surface="internet"),
    CVE("CVE-2023-3519", 9.8, 0.95, True, "citrix-netscaler-gateway", "appliance", "13.1 < 13.1-49.13", "13.1-49.13", "2023-07-18T00:00:00Z", "Citrix NetScaler ADC/Gateway unauthenticated RCE.", exposure_surface="internet"),
    CVE("CVE-2021-40444", 8.8, 0.93, True, "windows-mshtml", "os", "Windows unpatched", "KB5005565", "2021-09-07T00:00:00Z", "MSHTML remote code execution via crafted Office documents.", exposure_surface="local"),
    CVE("CVE-2023-23397", 9.8, 0.94, True, "microsoft-outlook", "os", "Outlook unpatched", "March 2023 update", "2023-03-14T00:00:00Z", "Microsoft Outlook elevation of privilege via NTLM leak.", exposure_surface="local"),
    CVE("CVE-2020-1472", 10.0, 0.96, True, "windows-netlogon", "os", "Domain controllers unpatched", "KB4571729", "2020-08-11T00:00:00Z", "Netlogon elevation of privilege (Zerologon).", exposure_surface="internal"),
    CVE("CVE-2024-23897", 9.8, 0.94, True, "jenkins", "maven", "<= 2.441", "2.442", "2024-01-24T00:00:00Z", "Jenkins CLI arbitrary file read leading to RCE.", exposure_surface="internet"),
    CVE("CVE-2019-19781", 9.8, 0.97, True, "citrix-netscaler-gateway", "appliance", "10.5-13.0 unpatched", "13.0-47.24", "2019-12-17T00:00:00Z", "Citrix ADC/Gateway directory traversal RCE.", exposure_surface="internet"),
]

_SYNTHETIC_SPEC: list[tuple[str, float, float, bool, str, str, str, str, str]] = [
    # cve_id, cvss, epss, kev, component, ecosystem, affected, fixed, description
    ("CVE-2026-90011", 9.8, 0.62, False, "openssl", "os", "3.2.0 - 3.2.4", "3.2.5", "TLS handshake heap overflow in OpenSSL allowing remote code execution."),
    ("CVE-2026-90014", 8.6, 0.41, False, "nginx", "os", "1.25.0 - 1.27.1", "1.27.2", "Request smuggling in the nginx HTTP/3 module."),
    ("CVE-2026-90022", 9.1, 0.78, True, "envoy", "go", "1.28.0 - 1.31.2", "1.31.3", "Envoy proxy authorization bypass via header normalization."),
    ("CVE-2026-90031", 7.5, 0.22, False, "jackson-databind", "maven", "2.15.0 - 2.17.1", "2.17.2", "Jackson deserialization gadget leading to denial of service."),
    ("CVE-2026-90035", 9.8, 0.71, True, "spring-security", "maven", "6.2.0 - 6.3.3", "6.3.4", "Spring Security authorization bypass on path-pattern matching."),
    ("CVE-2026-90040", 8.1, 0.35, False, "tomcat-embed", "maven", "10.1.0 - 10.1.30", "10.1.31", "Tomcat request handling race enabling session confusion."),
    ("CVE-2026-90048", 9.6, 0.83, True, "next", "npm", "14.0.0 - 14.2.14", "14.2.15", "Next.js middleware authentication bypass."),
    ("CVE-2026-90052", 7.8, 0.18, False, "lodash", "npm", "< 4.17.22", "4.17.22", "Prototype pollution in lodash merge helpers."),
    ("CVE-2026-90057", 8.8, 0.44, False, "express", "npm", "4.18.0 - 4.21.0", "4.21.1", "Express open redirect and header injection."),
    ("CVE-2026-90063", 9.0, 0.55, False, "axios", "npm", "1.6.0 - 1.7.6", "1.7.7", "Axios SSRF via protocol-relative URL handling."),
    ("CVE-2026-90070", 9.8, 0.66, True, "pillow", "pypi", "10.0.0 - 10.4.0", "10.4.1", "Pillow image parsing heap overflow leading to code execution."),
    ("CVE-2026-90074", 7.5, 0.29, False, "requests", "pypi", "2.31.0 - 2.32.2", "2.32.3", "Requests credential leakage on cross-origin redirect."),
    ("CVE-2026-90081", 8.2, 0.38, False, "cryptography", "pypi", "42.0.0 - 43.0.0", "43.0.1", "Timing side channel in RSA decryption."),
    ("CVE-2026-90088", 9.9, 0.74, True, "kubernetes-ingress-nginx", "go", "1.9.0 - 1.11.2", "1.11.3", "ingress-nginx annotation injection allowing cluster secret disclosure."),
    ("CVE-2026-90093", 8.8, 0.47, False, "containerd", "go", "1.7.0 - 1.7.20", "1.7.21", "containerd host filesystem escape via crafted OCI image."),
    ("CVE-2026-90099", 7.8, 0.20, False, "runc", "go", "1.1.0 - 1.1.13", "1.1.14", "runc file descriptor leak allowing container breakout."),
    ("CVE-2026-90104", 9.8, 0.58, False, "linux-kernel", "os", "6.1 - 6.8.11", "6.8.12", "Linux kernel netfilter use-after-free."),
    ("CVE-2026-90110", 8.4, 0.33, False, "glibc", "os", "2.35 - 2.39", "2.40", "glibc iconv buffer overflow."),
    ("CVE-2026-90117", 7.2, 0.12, False, "curl", "os", "8.4.0 - 8.9.0", "8.9.1", "curl cookie handling out-of-bounds read."),
    ("CVE-2026-90123", 9.8, 0.69, True, "gitlab", "appliance", "16.8 - 17.3.1", "17.3.2", "GitLab pipeline impersonation allowing arbitrary job execution."),
    ("CVE-2026-90130", 8.8, 0.40, False, "grafana", "go", "10.0 - 11.1.4", "11.1.5", "Grafana SQL expression injection via data source proxy."),
    ("CVE-2026-90136", 9.1, 0.51, False, "keycloak", "maven", "22.0 - 25.0.2", "25.0.3", "Keycloak token exchange privilege escalation."),
    ("CVE-2026-90142", 8.6, 0.36, False, "redis", "os", "7.0 - 7.2.5", "7.2.6", "Redis Lua sandbox escape."),
    ("CVE-2026-90149", 9.8, 0.60, False, "postgresql", "os", "15.0 - 16.3", "16.4", "PostgreSQL extension loading privilege escalation."),
    ("CVE-2026-90155", 7.5, 0.25, False, "elasticsearch", "maven", "8.10 - 8.15.0", "8.15.1", "Elasticsearch information disclosure via aggregations."),
    ("CVE-2026-90161", 9.8, 0.80, True, "vpn-gateway-firmware", "appliance", "4.1 - 4.3.2", "4.3.3", "SSL VPN gateway pre-auth RCE in the web portal."),
    ("CVE-2026-90168", 8.1, 0.30, False, "okta-verify-agent", "os", "9.10 - 9.14", "9.15", "Local privilege escalation in the desktop agent updater."),
    ("CVE-2026-90174", 7.8, 0.15, False, "microsoft-office", "os", "Office unpatched", "September 2026 update", "Office document parsing remote code execution."),
    ("CVE-2026-90180", 9.3, 0.57, False, "windows-smb", "os", "Windows unpatched", "KB5060000", "SMB server remote code execution."),
    ("CVE-2026-90186", 8.8, 0.28, False, "chromium", "os", "< 129.0.6668.58", "129.0.6668.58", "Chromium use-after-free in the rendering pipeline."),
]

_SYNTHETIC: list[CVE] = [
    CVE(cid, cvss, epss, kev, comp, eco, aff, fixed, f"2026-0{1 + i % 8}-1{i % 9}T00:00:00Z", desc, synthetic=True,
        exposure_surface="internet" if comp in {"openssl", "nginx", "envoy", "spring-security", "tomcat-embed", "next", "express", "kubernetes-ingress-nginx", "gitlab", "grafana", "keycloak", "vpn-gateway-firmware"} else ("local" if comp in {"microsoft-office", "chromium", "okta-verify-agent"} else "internal"))
    for i, (cid, cvss, epss, kev, comp, eco, aff, fixed, desc) in enumerate(_SYNTHETIC_SPEC)
]

CVES: dict[str, CVE] = {c.cve_id: c for c in _REAL + _SYNTHETIC}


def by_component(component: str) -> list[CVE]:
    return [c for c in CVES.values() if c.component == component]


def components() -> list[str]:
    return sorted({c.component for c in CVES.values()})
