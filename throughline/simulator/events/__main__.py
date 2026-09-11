"""CLI: ``python -m throughline.simulator.events [--out data/generated] [--inventory PATH]``."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from throughline.simulator.events import generate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m throughline.simulator.events",
                                     description="Generate the events-stage graph fragment and raw feeds.")
    parser.add_argument("--out", default="data/generated", type=Path, help="output directory (default: data/generated)")
    parser.add_argument("--inventory", default=None, type=Path,
                        help="path to inventory.json (default: <out>/inventory.json, else synthesized stub)")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s %(name)s: %(message)s")
    result = generate(args.out, inventory_path=args.inventory)
    summary = {"nodes": str(result["nodes"]), "edges": str(result["edges"]),
               "raw": [str(p) for p in result["raw"]], "counts": result["counts"]}
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
