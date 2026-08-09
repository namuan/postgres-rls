#!/usr/bin/env bash
# End-to-end assertions of PostgreSQL RLS behaviour against the demo container.
#
# Tenant context is now established through verified sessions only:
# app.establish() mints AND verifies a JWT inside the database, and policies
# read app.session_claim(), which re-verifies the signature.  Raw
# set_config() no longer grants access.  Every expected outcome is checked:
# both "should succeed" and "must fail" cases.  Exits non-zero if any check
# fails.  Run ./run.sh first.
set -uo pipefail

CONTAINER=postgres-rls-demo
DB=rls_demo
HOST=127.0.0.1
APP_USER=app_user
APP_PASSWORD=app_user_demo_password
POSTGRES_PASSWORD=postgres_demo_password

TENANT_A=11111111-1111-1111-1111-111111111111
TENANT_B=22222222-2222-2222-2222-222222222222

ALICE=alice@alpha.example
ALICE_PASS=alice-password
BOB=bob@beta.example
BOB_PASS=bob-password

PASS=0
FAIL=0
FAILED_DESCS=()

pass() { PASS=$((PASS + 1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); FAILED_DESCS+=("$*"); echo "FAIL: $*"; }

# SQL prefix that authenticates a user and establishes the verified session
# inside the transaction (BEGIN..COMMIT are added by the caller).
ctx() { printf "SELECT * FROM app.establish('%s','%s');" "$1" "$2"; }

# Run one SQL string as app_user (TCP, password auth).  Exit code lands in
# APP_EXIT, stdout is printed.
app_sql() {
  APP_EXIT=0
  out=$(podman exec -e PGPASSWORD="$APP_PASSWORD" -e ON_ERROR_STOP=1 "$CONTAINER" \
        psql -q -h "$HOST" -U "$APP_USER" -d "$DB" -tA -c "$1" 2>/dev/null) || APP_EXIT=$?
  printf '%s\n' "$out"
}

# Run one SQL string as the superuser (may include SET ROLE ...).  Exit code
# lands in PG_EXIT, stdout is printed.
postgres_sql() {
  PG_EXIT=0
  out=$(podman exec -e PGPASSWORD="$POSTGRES_PASSWORD" -e ON_ERROR_STOP=1 "$CONTAINER" \
        psql -q -h "$HOST" -U postgres -d "$DB" -tA -c "$1" 2>/dev/null) || PG_EXIT=$?
  printf '%s\n' "$out"
}

# Assert that a statement returns a specific single count (last output line).
assert_count() {
  local desc="$1" expected="$2" sql="$3" tmpfile got line
  tmpfile=$(mktemp) || {
    fail "$desc (could not create temp file)"
    return
  }
  app_sql "$sql" >"$tmpfile"
  got=
  while IFS= read -r line; do
    got="$line"
  done <"$tmpfile"
  rm -f "$tmpfile"
  if [ "$APP_EXIT" -eq 0 ] && [ "$got" = "$expected" ]; then
    pass "$desc"
  else
    fail "$desc (expected '$expected', got '$got', exit $APP_EXIT)"
  fi
}

# Assert that a postgres_sql statement returns a specific single count.
assert_pg_count() {
  local desc="$1" expected="$2" sql="$3" tmpfile got line
  tmpfile=$(mktemp) || {
    fail "$desc (could not create temp file)"
    return
  }
  postgres_sql "$sql" >"$tmpfile"
  got=
  while IFS= read -r line; do
    got="$line"
  done <"$tmpfile"
  rm -f "$tmpfile"
  if [ "$PG_EXIT" -eq 0 ] && [ "$got" = "$expected" ]; then
    pass "$desc"
  else
    fail "$desc (expected '$expected', got '$got', exit $PG_EXIT)"
  fi
}

# Assert that a statement succeeds (exit 0) as the superuser.
assert_pg_ok() {
  local desc="$1" sql="$2"
  postgres_sql "$sql" >/dev/null
  if [ "$PG_EXIT" -eq 0 ]; then
    pass "$desc"
  else
    fail "$desc (statement failed, exit $PG_EXIT)"
  fi
}

# Assert that a statement fails (nonzero psql exit, i.e. an SQL error).
assert_denied() {
  local desc="$1" sql="$2"
  app_sql "$sql" >/dev/null
  if [ "$APP_EXIT" -ne 0 ]; then
    pass "$desc"
  else
    fail "$desc (statement unexpectedly succeeded)"
  fi
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
if ! podman ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "ERROR: container '$CONTAINER' is not running. Run ./run.sh first." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 1. Default deny: no verified session, no rows
# ---------------------------------------------------------------------------
assert_count "app_user with no session sees 0 documents" "0" \
  "SELECT count(*) FROM app.documents;"

# ---------------------------------------------------------------------------
# 2. The classic hole is closed: set_config no longer grants tenant access
# ---------------------------------------------------------------------------
assert_count "raw set_config('app.tenant_id', ...) grants nothing" "0" \
  "BEGIN; SELECT set_config('app.tenant_id','$TENANT_A',true); SELECT count(*) FROM app.documents; COMMIT;"

assert_count "a forged token cannot establish a session" "0" \
  "BEGIN; SELECT * FROM app.establish('$ALICE','wrong-password'); SELECT count(*) FROM app.documents; COMMIT;"

assert_count "session_verify rejects a garbage token" "0" \
  "SELECT count(*) FROM app.session_verify('not.a.jwt');"

# ---------------------------------------------------------------------------
# 3. Tenant isolation through verified sessions (permissive policy)
# ---------------------------------------------------------------------------
assert_count "tenant A sees its 3 published documents" "3" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") SELECT count(*) FROM app.documents; COMMIT;"

assert_count "tenant B sees its 2 published documents" "2" \
  "BEGIN; $(ctx "$BOB" "$BOB_PASS") SELECT count(*) FROM app.documents; COMMIT;"

assert_count "tenant A sees zero of tenant B's rows" "0" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") SELECT count(*) FROM app.documents WHERE title LIKE 'Beta%'; COMMIT;"

# ---------------------------------------------------------------------------
# 4. Restrictive policy: unpublished rows hidden even for the owning tenant
# ---------------------------------------------------------------------------
assert_count "tenant A's unpublished draft is hidden by the restrictive policy" "0" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") SELECT count(*) FROM app.documents WHERE published = false; COMMIT;"

# ---------------------------------------------------------------------------
# 5. WITH CHECK: out-of-policy writes are rejected
# ---------------------------------------------------------------------------
assert_denied "INSERT into another tenant's ID is rejected" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") INSERT INTO app.documents (tenant_id,title,body) VALUES ('$TENANT_B','Sneak','x'); COMMIT;"

assert_denied "UPDATE reassigning a row to another tenant is rejected" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") UPDATE app.documents SET tenant_id='$TENANT_B' WHERE title='Alpha Roadmap'; COMMIT;"

assert_denied "INSERT with published=false is rejected by the restrictive WITH CHECK" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") INSERT INTO app.documents (tenant_id,title,body,published) VALUES ('$TENANT_A','Draft','x',false); COMMIT;"

# ---------------------------------------------------------------------------
# 6. Positive controls: in-tenant writes work (proves privileges exist and
#    that the denials above are policy-driven, not privilege-driven)
# ---------------------------------------------------------------------------
assert_count "in-tenant UPDATE succeeds (positive control)" "1" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") UPDATE app.documents SET body='updated in demo' WHERE title='Alpha Roadmap' RETURNING id; ROLLBACK;"

assert_count "in-tenant INSERT succeeds and is visible (positive control)" "1" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") INSERT INTO app.documents (tenant_id,title,body) VALUES ('$TENANT_A','Alpha Notes','x') RETURNING id; SELECT count(*) FROM app.documents WHERE title='Alpha Notes'; ROLLBACK;"

# ---------------------------------------------------------------------------
# 7. FORCE RLS: the table owner (migration_runner) is no longer exempt
# ---------------------------------------------------------------------------
assert_pg_count "migration_runner with FORCE RLS sees 0 documents" "0" \
  "SET ROLE migration_runner; SELECT count(*) FROM app.documents;"

# ---------------------------------------------------------------------------
# 8. Owner exemption WITHOUT FORCE RLS: owner_bypass_probe
# ---------------------------------------------------------------------------
assert_pg_count "migration_runner bypasses RLS on owner_bypass_probe (no FORCE RLS)" "2" \
  "SET ROLE migration_runner; SELECT count(*) FROM app.owner_bypass_probe;"

assert_count "app_user sees 0 rows in owner_bypass_probe (deny policy)" "0" \
  "SELECT count(*) FROM app.owner_bypass_probe;"

# ---------------------------------------------------------------------------
# 9. BYPASSRLS role stays exempt even when FORCE RLS is on
# ---------------------------------------------------------------------------
assert_pg_count "rls_auditor (BYPASSRLS) sees all 7 documents despite FORCE RLS" "7" \
  "SET ROLE rls_auditor; SELECT count(*) FROM app.documents;"

# ---------------------------------------------------------------------------
# 10. Superuser remains exempt
# ---------------------------------------------------------------------------
assert_pg_count "superuser sees all 7 documents" "7" \
  "SELECT count(*) FROM app.documents;"

# ---------------------------------------------------------------------------
# 11. No DDL for application principals (the ownership limitation, closed)
# ---------------------------------------------------------------------------
assert_denied "app_user cannot ALTER POLICY (no ownership)" \
  "ALTER POLICY tenant_isolation ON app.documents RENAME TO tenant_isolation_x;"

assert_denied "app_user cannot DROP TABLE (no ownership)" \
  "DROP TABLE app.documents;"

assert_denied "app_user cannot CREATE TABLE (no CREATE on schema)" \
  "CREATE TABLE app.sneaky (id int);"

assert_pg_ok "migration_runner CAN alter policies (positive control)" \
  "SET ROLE migration_runner; ALTER POLICY tenant_isolation ON app.documents RENAME TO tenant_isolation_v2; ALTER POLICY tenant_isolation_v2 ON app.documents RENAME TO tenant_isolation; RESET ROLE;"

# ---------------------------------------------------------------------------
# 12. Views over RLS tables: security_invoker vs definer rights
# ---------------------------------------------------------------------------
assert_count "security_invoker view applies the invoker's RLS (3 rows)" "3" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") SELECT count(*) FROM app.v_documents_safe; COMMIT;"

assert_count "view owned by a BYPASSRLS role leaks all 7 rows (the danger)" "7" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") SELECT count(*) FROM app.v_documents_leaky; COMMIT;"

# ---------------------------------------------------------------------------
# 13. Leaky policy functions: the error-message lesson
# ---------------------------------------------------------------------------
assert_denied "policy function that RAISEs leaks existence via an error" \
  "SELECT count(*) FROM app.secret_notes;"

assert_count "the same table is readable once a session is established" "3" \
  "BEGIN; $(ctx "$ALICE" "$ALICE_PASS") SELECT count(*) FROM app.secret_notes; COMMIT;"

# ---------------------------------------------------------------------------
# Summary
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
