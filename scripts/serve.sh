#!/usr/bin/env bash
# Start the Throughline API (and the built UI) detached from the calling shell. Usage: scripts/serve.sh [port] [logfile]
set -euo pipefail
PORT="${1:-8000}"
LOG="${2:-/tmp/throughline-serve-${PORT}.log}"
cd "$(dirname "$0")/.."
PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
setsid nohup "$PY" -m throughline.cli serve --port "$PORT" > "$LOG" 2>&1 < /dev/null &
for _ in $(seq 1 90); do
  if curl -sf "http://127.0.0.1:${PORT}/api/v1/health" > /dev/null 2>&1; then echo "throughline serving on http://127.0.0.1:${PORT} (log: ${LOG})"; exit 0; fi
  sleep 1
done
echo "server did not become healthy; see ${LOG}" >&2; exit 1
