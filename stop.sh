#!/usr/bin/env bash
# Stop the full RLS demo stack: Rust API + PostgreSQL container.
set -euo pipefail

CONTAINER=postgres-rls-demo
API_PORT="${API_PORT:-8081}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_PIDFILE="$SCRIPT_DIR/api/api.pid"

# --- Stop the API (pidfile first, then port lookup) ---
if [ -f "$API_PIDFILE" ]; then
  pid=$(cat "$API_PIDFILE" 2>/dev/null || true)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    echo "==> Stopping API (pid $pid)"
    kill "$pid" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$API_PIDFILE"
fi
pid=$(lsof -nP -iTCP:"$API_PORT" -sTCP:LISTEN -t 2>/dev/null || true)
if [ -n "$pid" ]; then
  echo "==> Stopping API on port $API_PORT (pid $pid)"
  kill "$pid" 2>/dev/null || true
  sleep 1
fi

# --- Stop the container ---
if podman ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "==> Removing container '$CONTAINER'"
  podman rm -f --volumes "$CONTAINER" >/dev/null
fi

echo "==> Stack stopped."
