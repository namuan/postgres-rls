#!/usr/bin/env bash
# Property-based test runner for the RLS demo.
#
# Requires the demo container (./run.sh) AND the API server running
# (cd api && cargo run). The suite is differential: it compares the
# RLS-filtered views against a model predicate computed from the superuser
# "teacher" view, over thousands of randomized states and operations.
# Exits non-zero if any property fails (proptest prints a minimal
# counterexample).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! podman ps --format '{{.Names}}' | grep -qx postgres-rls-demo; then
  echo "ERROR: container 'postgres-rls-demo' is not running. Run ./run.sh first." >&2
  exit 1
fi

if ! curl -sf http://127.0.0.1:8081/health >/dev/null; then
  echo "ERROR: API not reachable on 127.0.0.1:8081. Run 'cd api && cargo run' first." >&2
  exit 1
fi

echo "==> Running the property suite (container + API detected)"
cd api/properties
cargo run --release
