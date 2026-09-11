"""``python -m throughline.simulator.inventory [--out data/generated]``"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from throughline.config import settings
from throughline.simulator.inventory.generate import generate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m throughline.simulator.inventory", description="Generate the Larkspur Financial inventory stage.")
    parser.add_argument("--out", type=Path, default=settings.data_dir, help="output directory (default: settings.data_dir)")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print the counts JSON")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    started = time.perf_counter()
    result = generate(args.out)
    elapsed = time.perf_counter() - started
    summary = {"out": str(args.out), "seconds": round(elapsed, 2), "counts": result["counts"], "raw": [str(p) for p in result["raw"]]}
    json.dump(summary, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
