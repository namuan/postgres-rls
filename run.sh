#!/usr/bin/env bash
# Start (or restart) the full RLS demo stack: PostgreSQL container + Rust API.
#
# Idempotent: running this again stops the running API (pidfile or port
# lookup) and the container, then rebuilds and restarts everything.
#
# The container is intentionally created WITHOUT a persistent volume:
# removing it forces the /docker-entrypoint-initdb.d init scripts to
# re-run, so the schema is always rebuilt from sql/00-init.sql.
set -euo pipefail

CONTAINER=postgres-rls-demo
IMAGE=postgres:16
DB=rls_demo
HOST_PORT=54329
POSTGRES_PASSWORD=postgres_demo_password
API_PORT="${API_PORT:-8081}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_BIN="$SCRIPT_DIR/api/target/debug/rls-api"
API_PIDFILE="$SCRIPT_DIR/api/api.pid"
API_LOG="$SCRIPT_DIR/api/api.log"

# ---------------------------------------------------------------------------
# API lifecycle
# ---------------------------------------------------------------------------

stop_api() {
  local pid=""

  if [ -f "$API_PIDFILE" ]; then
    pid=$(cat "$API_PIDFILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo "==> Stopping API (pid $pid)"
      kill "$pid" 2>/dev/null || true
      sleep 1
    fi
    rm -f "$API_PIDFILE"
  fi

  # Fallback: anything still listening on the API port.
  pid=$(lsof -nP -iTCP:"$API_PORT" -sTCP:LISTEN -t 2>/dev/null || true)
  if [ -n "$pid" ]; then
    echo "==> Stopping API on port $API_PORT (pid $pid)"
    kill "$pid" 2>/dev/null || true
    sleep 1
  fi
}

start_api() {
  echo "==> Building the API (cargo build)"
  (cd "$SCRIPT_DIR/api" && cargo build)

  echo "==> Starting the API on 127.0.0.1:$API_PORT"
  nohup "$API_BIN" >"$API_LOG" 2>&1 &
  echo $! >"$API_PIDFILE"

  for _ in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1; then
      echo "==> API healthy."
      return 0
    fi
    sleep 1
  done

  echo "ERROR: API did not become healthy. Log: $API_LOG" >&2
  cat "$API_LOG" >&2 || true
  exit 1
}

# ---------------------------------------------------------------------------
# Database lifecycle
# ---------------------------------------------------------------------------

if ! podman image exists "$IMAGE"; then
  echo "==> Pulling $IMAGE"
  podman pull "$IMAGE"
fi

echo "==> Removing any previous '$CONTAINER' container"
podman rm -f --volumes "$CONTAINER" >/dev/null 2>&1 || true

echo "==> Starting '$CONTAINER' (database '$DB', host port 127.0.0.1:$HOST_PORT)"
podman run -d \
  --name "$CONTAINER" \
  -p "127.0.0.1:${HOST_PORT}:5432" \
  -e POSTGRES_DB="$DB" \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -v "$SCRIPT_DIR/sql:/docker-entrypoint-initdb.d:ro" \
  "$IMAGE" >/dev/null

echo "==> Waiting for PostgreSQL to accept connections"
ready=0
for _ in $(seq 1 90); do
  if podman exec "$CONTAINER" pg_isready -U postgres -d "$DB" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "ERROR: PostgreSQL did not become ready in time." >&2
  podman logs "$CONTAINER" >&2 || true
  exit 1
fi

echo "==> Waiting for init scripts to finish (role app_user must exist)"
for _ in $(seq 1 60); do
  if podman exec "$CONTAINER" psql -U postgres -d "$DB" -tA -c \
       "SELECT count(*) FROM pg_roles WHERE rolname = 'app_user'" 2>/dev/null | grep -q '^1$'; then
    echo "==> Init complete."
    break
  fi
  sleep 1
done
if ! podman exec "$CONTAINER" psql -U postgres -d "$DB" -tA -c \
     "SELECT count(*) FROM pg_roles WHERE rolname = 'app_user'" 2>/dev/null | grep -q '^1$'; then
  echo "ERROR: init scripts did not complete in time." >&2
  podman logs "$CONTAINER" >&2 || true
  exit 1
fi

# ---------------------------------------------------------------------------
# API: stop any previous instance, then start a fresh one
# ---------------------------------------------------------------------------
stop_api
start_api

# ---------------------------------------------------------------------------
echo

echo "=========================================="
echo "RLS demo stack is up:"
echo "  PostgreSQL : 127.0.0.1:$HOST_PORT (container '$CONTAINER')"
echo "  API + WebUI: http://127.0.0.1:$API_PORT/   (pid $(cat "$API_PIDFILE"))"
echo "  API log    : $API_LOG"
echo
echo "  IntelliJ database client (Database tool window / DataGrip):"
echo "    JDBC URL : jdbc:postgresql://127.0.0.1:$HOST_PORT/$DB"
echo "    with auth: jdbc:postgresql://127.0.0.1:$HOST_PORT/$DB?user=app_user&password=app_user_demo_password"
echo "    user     : app_user  (least privilege - RLS filters its rows)"
echo "    user     : postgres  (superuser - bypasses RLS, demo/exploration only)"
echo "    passwords: app_user_demo_password / postgres_demo_password"
echo "    (In IntelliJ: Database tool window -> + -> PostgreSQL -> paste the"
echo "     URL into the 'URL' field, or fill Host/Port/Database/User.)"
echo
echo "  Next       : ./test.sh  ./api_test.sh  ./property_test.sh"
echo "  Teardown   : ./stop.sh"
echo "  Re-run     : ./run.sh  (restarts everything)"
echo "=========================================="
