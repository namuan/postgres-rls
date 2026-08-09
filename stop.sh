#!/usr/bin/env bash
# Remove the demo container (schema changes are re-applied on next ./run.sh).
set -euo pipefail

if podman rm -f --volumes postgres-rls-demo >/dev/null 2>&1; then
  echo "Removed container postgres-rls-demo"
else
  echo "No container named postgres-rls-demo"
fi
