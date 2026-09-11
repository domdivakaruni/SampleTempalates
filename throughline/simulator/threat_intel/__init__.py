"""Threat-intelligence stage (Agent A3) of the Throughline data simulator.

Produces the fictional threat-intel layer of the security context graph: threat actors, campaigns, malware
families, ATT&CK technique nodes, indicators, intel reports, ``EXPLOITS`` relationships, and the
``Vulnerability`` (CVE) nodes for the estate, plus STIX-2.1-like raw feeds under ``raw/ti/``.

Public entry point::

    from throughline.simulator.threat_intel import generate
    result = generate(Path("data/generated"))
"""
from __future__ import annotations

from throughline.simulator.threat_intel.generate import build_model, generate

__all__ = ["build_model", "generate"]
