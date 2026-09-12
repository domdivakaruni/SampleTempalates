#!/usr/bin/env bash
# Build the static snapshot edition (docs/10-static-snapshot.md section 4):
#   1. export the precomputed payloads into web/snapshot-out (skipped when a manifest exists, unless --export is passed)
#   2. VITE_STATIC=1 npm run build            -> web/dist-static (relative assets, hash routing, snapshot transport)
#   3. copy web/snapshot-out -> web/dist-static/snapshot
#   4. print the file count and total size
# Usage: scripts/build_static.sh [--export | --skip-export]
#   --export       always rerun scripts/export_snapshot.py (the Pages workflow does this)
#   --skip-export  never run the exporter (e.g. after `node web/scripts/make-fixture-snapshot.mjs`)
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PY:-.venv/bin/python}"
[ -x "$PY" ] || PY="python3"
EXPORT="auto"
for arg in "$@"; do
  case "$arg" in
    --export) EXPORT="yes" ;;
    --skip-export|--no-export) EXPORT="no" ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ "$EXPORT" = "yes" ] || { [ "$EXPORT" = "auto" ] && [ ! -f web/snapshot-out/manifest.json ]; }; then
  if [ ! -f scripts/export_snapshot.py ]; then
    echo "scripts/export_snapshot.py is missing; generate a fixture with 'node web/scripts/make-fixture-snapshot.mjs' or pass --skip-export" >&2
    exit 1
  fi
  echo "==> exporting the snapshot with $PY scripts/export_snapshot.py --out web/snapshot-out"
  "$PY" scripts/export_snapshot.py --out web/snapshot-out
else
  echo "==> reusing web/snapshot-out ($(find web/snapshot-out -type f | wc -l | tr -d ' ') files; pass --export to regenerate)"
fi
[ -f web/snapshot-out/manifest.json ] || { echo "web/snapshot-out/manifest.json is missing after export" >&2; exit 1; }

echo "==> building the web UI (VITE_STATIC=1 npm run build)"
( cd web && VITE_STATIC=1 npm run build )

echo "==> copying web/snapshot-out -> web/dist-static/snapshot"
rm -rf web/dist-static/snapshot
cp -r web/snapshot-out web/dist-static/snapshot

FILES=$(find web/dist-static -type f | wc -l | tr -d ' ')
SIZE=$(du -sh web/dist-static | cut -f1)
SNAP=$(du -sh web/dist-static/snapshot | cut -f1)
echo "==> web/dist-static: ${FILES} files, ${SIZE} total (snapshot ${SNAP})"
echo "    serve with: python3 -m http.server -d web/dist-static 4174   # then open http://127.0.0.1:4174/#/"
echo "    verify with: node web/scripts/check-static.mjs http://127.0.0.1:4174/"
