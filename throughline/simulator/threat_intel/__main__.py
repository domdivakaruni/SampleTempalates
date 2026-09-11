"""CLI: ``python -m throughline.simulator.threat_intel [--out data/generated]``."""
from __future__ import annotations

import argparse
from pathlib import Path

from throughline.simulator.threat_intel.generate import generate


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m throughline.simulator.threat_intel",
        description="Generate the threat-intelligence stage of the Throughline data simulator.",
    )
    parser.add_argument("--out", type=Path, default=Path("data/generated"), help="output directory")
    args = parser.parse_args()

    result = generate(args.out)
    counts = result["counts"]
    print(f"threat_intel: wrote {counts['nodes']} nodes and {counts['edges']} edges under {result['nodes'].parent}")
    for key in ("actors", "campaigns", "malware", "techniques", "vulnerabilities", "indicators", "reports",
                "exploits", "low_confidence_plants"):
        print(f"  {key}: {counts[key]}")
    print(f"raw feeds: {', '.join(sorted(p.name for p in result['raw']))}")


if __name__ == "__main__":
    main()
