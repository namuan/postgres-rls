#!/usr/bin/env bash
# Start (or recreate) the PostgreSQL RLS demo container with Podman.
#
# The container is intentionally created WITHOUT a persistent volume: removing
# it forces the /docker-entrypoint-initdb.d init scripts to re-run, so the
# schema is always rebuilt from sql/00-init.sql.
set -euo pipefail

CONTAINER=postgres-rls-demo
IMAGE=postgres:16
DB=rls_demo
HOST_PORT=54329
POSTGRES_PASSWORD=postgres_demo_password
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    echo "==> Init complete. Demo ready."
    podman ps --filter "name=$CONTAINER" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    exit 0
  fi
  sleep 1
done

echo "ERROR: init scripts did not complete in time." >&2
podman logs "$CONTAINER" >&2 || true
exit 1
