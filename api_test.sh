#!/usr/bin/env bash
# End-to-end assertions against the running Rust API server (api/).
#
# Proves the authentication flow end to end: login, JWT issuance, tenant
# isolation through RLS, and policy-driven write rejection.  Requires the
# full stack from ./run.sh (container + API server).  Exits non-zero if any
# check fails.
set -uo pipefail

BASE="${BASE:-http://127.0.0.1:8081}"
TENANT_A=11111111-1111-1111-1111-111111111111
TENANT_B=22222222-2222-2222-2222-222222222222

PASS=0
FAIL=0
FAILED_DESCS=()

pass() { PASS=$((PASS + 1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); FAILED_DESCS+=("$*"); echo "FAIL: $*"; }

# req <method> <path> <curl args...>; sets HTTP_CODE and RESP
req() {
  local method="$1" path="$2"
  shift 2
  local tmp
  tmp=$(mktemp)
  HTTP_CODE=$(curl -s -X "$method" -o "$tmp" -w '%{http_code}' "$@" "$BASE$path")
  RESP=$(cat "$tmp")
  rm -f "$tmp"
}

# check <description> <actual> <expected>
check() {
  if [ "$2" = "$3" ]; then
    pass "$1"
  else
    fail "$1 (got '$2', expected '$3')"
  fi
}

# ---------------------------------------------------------------------------
echo "== health"
req GET /health
check "health returns 200" "$HTTP_CODE" "200"

# ---------------------------------------------------------------------------
echo "== webui (served from the same server)"
req GET /
check "webui index is served at / (200)" "$HTTP_CODE" "200"
check "index is the tenancy ledger page" "$(grep -c 'Tenancy Ledger' <<<"$RESP")" "1"

req GET /demo/truth
check "teacher endpoint without token is rejected with 401" "$HTTP_CODE" "401"

# ---------------------------------------------------------------------------
echo "== login"
req POST /login -H 'Content-Type: application/json' \
  -d '{"email":"alice@alpha.example","password":"alice-password"}'
check "alice login returns 200" "$HTTP_CODE" "200"
ALICE_TOKEN=$(jq -r '.token // empty' <<<"$RESP")
check "alice receives a token" "$([ -n "$ALICE_TOKEN" ] && echo yes || echo no)" "yes"
check "alice token carries tenant A" \
  "$(jq -r '.tenant_id // empty' <<<"$RESP")" "$TENANT_A"

req POST /login -H 'Content-Type: application/json' \
  -d '{"email":"bob@beta.example","password":"bob-password"}'
BOB_TOKEN=$(jq -r '.token // empty' <<<"$RESP")
check "bob login returns 200" "$HTTP_CODE" "200"
check "bob token carries tenant B" \
  "$(jq -r '.tenant_id // empty' <<<"$RESP")" "$TENANT_B"

req POST /login -H 'Content-Type: application/json' \
  -d '{"email":"alice@alpha.example","password":"wrong-password"}'
check "wrong password is rejected with 401" "$HTTP_CODE" "401"

req POST /login -H 'Content-Type: application/json' \
  -d '{"email":"mallory@evil.example","password":"anything"}'
check "unknown user is rejected with 401" "$HTTP_CODE" "401"

# ---------------------------------------------------------------------------
echo "== authorization"
req GET /documents
check "request without token is rejected with 401" "$HTTP_CODE" "401"

req GET /documents -H "Authorization: Bearer ${ALICE_TOKEN}corrupted"
check "tampered token is rejected with 401" "$HTTP_CODE" "401"

req GET /me -H "Authorization: Bearer $ALICE_TOKEN"
check "/me returns the authenticated identity" "$HTTP_CODE" "200"
check "/me reports tenant A" "$(jq -r '.tenant_id // empty' <<<"$RESP")" "$TENANT_A"

# ---------------------------------------------------------------------------
echo "== tenant isolation through RLS"
req GET /documents -H "Authorization: Bearer $ALICE_TOKEN"
check "alice sees 3 documents" "$(jq -r '.count // empty' <<<"$RESP")" "3"
check "alice sees only tenant A rows" \
  "$(jq -r '[.documents[].title] | sort | join(",")' <<<"$RESP")" \
  "Alpha Budget,Alpha Hiring,Alpha Roadmap"

req GET /documents -H "Authorization: Bearer $BOB_TOKEN"
check "bob sees 2 documents" "$(jq -r '.count // empty' <<<"$RESP")" "2"
check "bob sees only tenant B rows" \
  "$(jq -r '[.documents[].title] | sort | join(",")' <<<"$RESP")" \
  "Beta Launch,Beta Metrics"

req GET /demo/truth -H "Authorization: Bearer $ALICE_TOKEN"
check "teacher endpoint shows all 7 rows to the superuser pool" "$(jq -r '.total // empty' <<<"$RESP")" "7"

# ---------------------------------------------------------------------------
echo "== writes"
req POST /documents -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Alpha Retro","body":"created through the API"}'
check "alice creates a document (201)" "$HTTP_CODE" "201"
check "created document belongs to tenant A" \
  "$(jq -r '.tenant_id // empty' <<<"$RESP")" "$TENANT_A"

req GET /documents -H "Authorization: Bearer $ALICE_TOKEN"
check "alice now sees 4 documents" "$(jq -r '.count // empty' <<<"$RESP")" "4"

req GET /documents -H "Authorization: Bearer $BOB_TOKEN"
check "bob still sees 2 (no cross-tenant leak)" "$(jq -r '.count // empty' <<<"$RESP")" "2"

req POST /documents -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Alpha Draft","body":"nope","published":false}'
check "unpublished insert rejected by WITH CHECK (403)" "$HTTP_CODE" "403"

req POST /documents -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"","body":""}'
check "blank title accepted by schema (no app-level validation)" "$HTTP_CODE" "201"

req GET /demo/truth -H "Authorization: Bearer $ALICE_TOKEN"
check "teacher endpoint sees the rows created via the API too" "$(jq -r '.total // empty' <<<"$RESP")" "9"

# ---------------------------------------------------------------------------
echo
echo "=============================="
echo "PASS: $PASS   FAIL: $FAIL"
echo "=============================="
if [ "$FAIL" -gt 0 ]; then
  printf 'Failed checks:\n'
  printf '  - %s\n' "${FAILED_DESCS[@]}"
  exit 1
fi
exit 0
