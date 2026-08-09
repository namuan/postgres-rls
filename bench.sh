#!/usr/bin/env bash
# Benchmark the RLS demo's auth-inside-PostgreSQL design.
#
# Layer 1 — DB-side primitives (pgbench inside the container):
#   * app.login()           bcrypt cost 10 — the expensive primitive
#   * session verify + RLS  one authenticated request as the DB sees it
#                           (app.session_verify + app.session_claim +
#                            one RLS-filtered SELECT, all in one tx)
#
# Layer 2 — end-to-end API load (k6, bench/load.js):
#   realistic mix (85% reads / 10% writes / 5% logins), peak DB CPU
#   sampled during the run, per-endpoint latency from the k6 JSON trace.
#
# Usage: ./bench.sh [--vus N] [--duration 30s] [--no-writes] [--keep-data]
#   --vus N        k6 virtual users          (default 50)
#   --duration S   k6 steady-state duration  (default 30s, e.g. 60s)
#   --no-writes    drop the write share from the mix (no rows inserted)
#   --keep-data    do not delete bench-* rows after the run
#
# Requires the stack to be up (./run.sh) and k6 on PATH.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER=postgres-rls-demo
DB=rls_demo
APP_USER=app_user
APP_PASSWORD=app_user_demo_password
API_BASE="http://127.0.0.1:${API_PORT:-8081}"
K6_SCRIPT="$SCRIPT_DIR/bench/load.js"

VUS=50
DURATION=30s
INCLUDE_WRITES=1
KEEP_DATA=0

while [ $# -gt 0 ]; do
  case "$1" in
    --vus)       VUS="$2"; shift 2 ;;
    --duration)  DURATION="$2"; shift 2 ;;
    --no-writes) INCLUDE_WRITES=0; shift ;;
    --keep-data) KEEP_DATA=1; shift ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see ./bench.sh --help)" >&2; exit 1 ;;
  esac
done

echo "==> Preflight"
command -v k6 >/dev/null 2>&1 || { echo "ERROR: k6 not found on PATH" >&2; exit 1; }
curl -sf "$API_BASE/health" >/dev/null 2>&1 || {
  echo "ERROR: API not healthy at $API_BASE — start the stack with ./run.sh first" >&2
  exit 1
}
podman ps --format '{{.Names}}' | grep -qx "$CONTAINER" || {
  echo "ERROR: container '$CONTAINER' not running — start the stack with ./run.sh first" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Layer 1: DB-side primitives
# ---------------------------------------------------------------------------
echo "==> Layer 1: DB-side primitives (pgbench in container, 15s each)"

TOKEN=$(curl -sf -X POST "$API_BASE/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@alpha.example","password":"alice-password"}' | jq -r .token)
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || {
  echo "ERROR: could not mint a token for the pgbench session script" >&2
  exit 1
}

LOGIN_SQL="SELECT token FROM app.login('alice@alpha.example', 'alice-password');"
SESSION_SQL="SELECT user_id FROM app.session_verify('$TOKEN');
SELECT app.session_claim('tenant_id');
SELECT count(*) FROM app.documents;"

run_pgbench() { # $1=clients, $2=sql  -> prints tps
  local clients="$1" sql="$2"
  printf '%s\n' "$sql" | podman exec -i \
    -e PGPASSWORD="$APP_PASSWORD" "$CONTAINER" pgbench \
    -h 127.0.0.1 -p 5432 -U "$APP_USER" -d "$DB" \
    -c "$clients" -j "$clients" -T 15 -f - 2>/dev/null \
    | awk '/^tps =/{print $3; exit}'
}

LOGIN_TPS=$(run_pgbench 4 "$LOGIN_SQL")
SESSION_TPS=$(run_pgbench 8 "$SESSION_SQL")
echo "  app.login() .......... ${LOGIN_TPS} tps"
echo "  session verify + RLS .. ${SESSION_TPS} tps"

# ---------------------------------------------------------------------------
# Layer 2: end-to-end k6 load
# ---------------------------------------------------------------------------
echo "==> Layer 2: k6 load test (${VUS} VUs, ${DURATION} steady state)"
OUT=$(mktemp /tmp/rls-k6-XXXXXX).json

k6 run \
  --env VUS="$VUS" --env DURATION="$DURATION" --env INCLUDE_WRITES="$INCLUDE_WRITES" \
  --out "json=$OUT" \
  --summary-trend-stats="avg,p(50),p(90),p(95),p(99)" \
  "$K6_SCRIPT" &
K6_PID=$!

# Sample container CPU while the test runs.
PEAK_CPU=0
while kill -0 "$K6_PID" 2>/dev/null; do
  CPU=$(podman stats --no-stream --format '{{.CPUPerc}}' "$CONTAINER" 2>/dev/null | tr -d '%' | head -1)
  if [ -n "$CPU" ] && awk -v a="$CPU" -v b="$PEAK_CPU" 'BEGIN{exit !(a>b)}'; then
    PEAK_CPU=$CPU
  fi
  sleep 2
done
wait "$K6_PID"

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
read -r TOTAL_RPS TOTAL_REQS FAIL_RATE <<< "$(python3 - "$OUT" "$API_BASE" <<'PY'
import datetime, json, math, sys, collections

base = sys.argv[2]
total = failed = 0
first = last = None
by = collections.defaultdict(list)
with open(sys.argv[1]) as f:
    for line in f:
        d = json.loads(line)
        if d.get('type') != 'Point':
            continue
        m = d['metric']
        if m == 'http_reqs':
            total += 1          # k6 emits one counter point per request
        elif m == 'http_req_failed':
            failed += d['data']['value']
        elif m == 'http_req_duration':
            t = datetime.datetime.fromisoformat(d['data']['time'])
            first = first or t
            last = t
            tag = d['data']['tags']
            name = f"{tag.get('method', '?')} {tag.get('name', '?').replace(base, '')}"
            by[name].append(d['data']['value'])

elapsed = (last - first).total_seconds() if first and last else 1.0
print(f"{total/elapsed:.1f} {total} {failed*100/total:.2f}")

def pct(vs, q):
    vs = sorted(vs)
    k = (len(vs) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return vs[lo] if lo == hi else vs[lo] + (vs[hi] - vs[lo]) * (k - lo)

for name in sorted(by):
    vs = by[name]
    print(f"{name}\t{len(vs)}\t{pct(vs, .5):.1f}\t{pct(vs, .95):.1f}\t{pct(vs, .99):.1f}")
PY
)"

LATENCY_ROWS=$(python3 - "$OUT" "$API_BASE" <<'PY'
import datetime, json, math, sys, collections

base = sys.argv[2]
by = collections.defaultdict(list)
with open(sys.argv[1]) as f:
    for line in f:
        d = json.loads(line)
        if d.get('type') != 'Point' or d.get('metric') != 'http_req_duration':
            continue
        tag = d['data']['tags']
        name = f"{tag.get('method', '?')} {tag.get('name', '?').replace(base, '')}"
        by[name].append(d['data']['value'])

def pct(vs, q):
    vs = sorted(vs)
    k = (len(vs) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return vs[lo] if lo == hi else vs[lo] + (vs[hi] - vs[lo]) * (k - lo)

for name in sorted(by):
    vs = by[name]
    print(f"{name}\t{len(vs)}\t{pct(vs, .5):.1f}\t{pct(vs, .95):.1f}\t{pct(vs, .99):.1f}")
PY
)

INSERTED=0
if [ "$INCLUDE_WRITES" = "1" ]; then
  INSERTED=$(podman exec "$CONTAINER" psql -U postgres -d "$DB" -tA -c \
    "SELECT count(*) FROM app.documents WHERE title LIKE 'bench-%'" | tr -d ' ')
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n============================================================\n'
printf 'RLS auth-in-DB benchmark summary\n'
printf '============================================================\n'
printf '\nLayer 1 — DB-side primitives (pgbench, 15s, in container)\n'
printf '  %-28s %10s\n' 'app.login() (bcrypt 10)' "${LOGIN_TPS} tps"
printf '  %-28s %10s\n' 'session verify + RLS req' "${SESSION_TPS} tps"
printf '\nLayer 2 — end-to-end API (k6: %s VUs, %s steady)\n' "$VUS" "$DURATION"
printf '  %-28s %10s\n' 'throughput' "${TOTAL_RPS} req/s"
printf '  %-28s %10s\n' 'total requests' "$TOTAL_REQS"
printf '  %-28s %10s\n' 'failed requests' "${FAIL_RATE}%"
printf '  %-28s %10s\n' 'peak container CPU' "${PEAK_CPU}%"
printf '\n  latency p50 / p95 / p99 (ms)\n'
while IFS=$'\t' read -r name n p50 p95 p99; do
  printf '    %-24s %8s %8s %8s\n' "$name" "$p50" "$p95" "$p99"
done <<< "$LATENCY_ROWS"

printf '\nRead this as:\n'
printf '  * login primitives are the CPU bottleneck — bcrypt cost 10 in the DB\n'
printf '    (measured: %s logins/s on this machine, roughly 1 core). If the login\n' "$LOGIN_TPS"
printf '    p95 above is high, move bcrypt to the app tier or lower the cost.\n'
printf '  * session verify + RLS is cheap (thousands/s) — not a bottleneck.\n'
printf '  * if peak DB CPU ~100%% and req/s plateaued, the DB is the ceiling:\n'
printf '    raise it with read replicas, PgBouncer, or bigger instance.\n'
printf '  * the API pool is capped at 5 connections (api/src/main.rs) — it is the\n'
printf '    real scaling unit per replica; raise it before raising VUs.\n'

if [ "$INCLUDE_WRITES" = "1" ]; then
  printf '\nNote: %s bench-* rows were inserted into app.documents.\n' "$INSERTED"
  if [ "$KEEP_DATA" = "0" ]; then
    podman exec "$CONTAINER" psql -U postgres -d "$DB" -q -c \
      "DELETE FROM app.documents WHERE title LIKE 'bench-%'" >/dev/null
    printf '      Deleted them (use --keep-data to keep, or ./run.sh to reset fully).\n'
  else
    printf '      Kept (--keep-data). Reset with ./run.sh.\n'
  fi
fi
printf '============================================================\n'
