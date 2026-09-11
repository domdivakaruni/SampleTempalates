"""Inventory stage of the Throughline data simulator (Agent A1).

Generates Larkspur Financial's simulated cloud estate, identities, business context, endpoint device inventory,
software/vulnerability inventory, posture derivations (EXPOSES, VULNERABLE_TO, CAN_ACCESS) and CSPM issue alerts.

    from throughline.simulator.inventory import generate
    result = generate(Path("data/generated"))   # -> {"nodes": Path, "edges": Path, "raw": [Path...], "counts": {...}}
"""
from throughline.simulator.inventory.generate import build_inventory, generate

__all__ = ["build_inventory", "generate"]
