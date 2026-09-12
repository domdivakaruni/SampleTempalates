#!/usr/bin/env bash
# Stop a Throughline API started with scripts/serve.sh. Usage: scripts/stop.sh [port]
PORT="${1:-8000}"
PIDS=$(pgrep -f "throughline.cli serve --port ${PORT}" || true)
[ -z "$PIDS" ] && { echo "nothing listening for port ${PORT}"; exit 0; }
kill $PIDS && echo "stopped ${PIDS}"
