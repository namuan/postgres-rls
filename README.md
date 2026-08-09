# PostgreSQL Row Level Security demo (Podman + Rust API)

[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-dea584?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Podman](https://img.shields.io/badge/Podman-4%2B-892CA0?logo=podman&logoColor=white)](https://podman.io/)
[![Tests](https://img.shields.io/badge/tests-26%20SQL%20%E2%9C%93%2027%20HTTP%20%E2%9C%93-brightgreen)](test.sh)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A self-contained demonstration of PostgreSQL Row Level Security (RLS) with a
**real authentication boundary** — and the classic RLS pitfalls actually
closed, not just documented. The database runs in a single ephemeral
`postgres:16` container managed with **Podman** — no Docker, no Compose. A
Rust API server serves a WebUI and talks to the database.

## What the demo proves (with real running assertions)

| Behaviour | Where |
| --- | --- |
| Default deny — no verified session, no rows | `test.sh` 1 |
| **Raw `set_config('app.tenant_id', …)` grants nothing** (the classic hole, closed) | `test.sh` 2 |
| Forged/garbage tokens cannot establish a session | `test.sh` 2 |
| Tenant isolation through database-verified sessions | `test.sh` 3 |
| Restrictive policy ANDs with permissive ones (unpublished rows hidden) | `test.sh` 4 |
| `WITH CHECK` blocks cross-tenant writes | `test.sh` 5 |
| In-tenant writes succeed (positive controls) | `test.sh` 6 |
| `FORCE ROW LEVEL SECURITY` closes the owner bypass | `test.sh` 7 |
| Without FORCE, the owner still bypasses RLS | `test.sh` 8 |
| `BYPASSRLS` roles and superusers remain exempt | `test.sh` 9–10 |
| **`app_user` cannot `ALTER POLICY` / `DROP` / `CREATE` (no ownership, no DDL)** | `test.sh` 11 |
| **Views: `security_invoker` applies RLS; a `BYPASSRLS`-owned view leaks everything** | `test.sh` 12 |
| **Policy functions that `RAISE` leak row existence via errors** | `test.sh` 13 |
| Login, JWT issuance, 401s, tenant isolation **through the HTTP API** | `api_test.sh` |

## Files

```
sql/00-init.sql         Roles, schema, tables, seed data, RLS policies, auth, grants
run.sh                  Recreates and starts the demo container (Podman)
stop.sh                 Removes the demo container
test.sh                 SQL-level RLS assertions (positive and expected-failure)
property_test.sh        Property-based security suite (proptest, differential)
api/                    Rust API server (axum + tokio-postgres) and static/ WebUI
api/env.example         Documented env vars for the API (copy to .env locally)
api/properties/         proptest crate: 5 randomized security properties
api_test.sh             HTTP-level end-to-end assertions against the API
api.http                IntelliJ HTTP Client requests — try every endpoint from the IDE
postgres-rls-process.html   Visual walkthrough of the whole system (open in a browser)
README.md               This file
```

## Try it in IntelliJ IDEA

Open `api.http` in any JetBrains IDE (HTTP Client is bundled) and press
**Run All** — the two login requests capture their JWTs into client
variables, and every request carries inline assertions (the same properties
as the shell suites). Start the stack first: `./run.sh` then
`cd api && cargo run`.

## Property-based testing

Example-based suites (`test.sh`, `api_test.sh`) check fixed inputs. The
property suite (`property_test.sh` → `api/properties/`) checks *invariants*
over thousands of randomized states and operations, using differential
testing: every RLS-filtered view is compared against a model predicate
(`tenant = T AND published`) computed from the superuser ground truth.

| Property | Invariant checked | Cases |
| --- | --- | --- |
| `visible_set_matches_model` | For any tenant and any document set, the API returns exactly the model's rows | 128 |
| `cross_tenant_isolation` | Random sequences of login/create/list ops never break the model; unauthenticated probes are always 401 (no pooled-session leaks) | 64 |
| `write_check_enforced` | `POST /documents` → 201 iff `published`; rows stamped with the session tenant; no cross-tenant visibility after writes | 128 |
| `token_forgery_rejected` | Every mutation of a valid token (bit flips, truncation, forged signatures, expired claims) → 401 | 128 |
| `auth_and_claims` | Login succeeds iff the password matches; JWT claims (sub, tenant, 24 h TTL) match the users table | 128 |

It already earned its keep: on the first run it caught a real defect — a
bit-flipped signature containing a non-base64 character made PostgreSQL
raise, turning a should-be-401 into a **500**. `app.url_decode()` and the
verify functions now swallow malformed input (`NULL` → clean denial). The
fix is covered by the same property that found it.

## Visual walkthrough

`postgres-rls-process.html` is a self-contained, interactive diagram page that
plots the whole process — architecture, the trust boundary, the database
internals, **three user journeys** (Alice, Bob, and an attacker), the closed
holes, and the full test matrix. Open it in any browser.

## Prerequisites

- Podman 4+ with a running machine (`podman machine list`; on macOS start it
  with `podman machine start`).
- Rust 1.75+ (for the API server; `cargo --version`).
- The demo binds port `54329` on `127.0.0.1` only. The API binds `8081` by
  default (change with the `BIND` env var).

## Quick start

```bash
./run.sh                          # pull image if needed, start container, wait for init
./test.sh                         # SQL-level assertions (expect PASS: 26, FAIL: 0)

cd api && cargo run               # start the API server
# in another shell:
./api_test.sh                     # HTTP-level assertions (expect PASS: 27, FAIL: 0)
./property_test.sh                # randomized security properties (576 cases, all held)
```

Open **http://127.0.0.1:8081/** for the WebUI (see below).

Demo credentials:

| Email | Password | Tenant |
| --- | --- | --- |
| `alice@alpha.example` | `alice-password` | A (`11111111-…`) |
| `bob@beta.example` | `bob-password` | B (`22222222-…`) |

### Manual exploration (SQL)

Sessions are established with `app.establish()` — password verified, token
minted AND verified, all inside PostgreSQL:

```bash
podman exec -e PGPASSWORD=app_user_demo_password -it postgres-rls-demo \
  psql -h 127.0.0.1 -U app_user -d rls_demo
```

```sql
BEGIN;
SELECT * FROM app.establish('alice@alpha.example', 'alice-password');
SELECT id, title, published FROM app.documents;   -- only tenant A's published rows
COMMIT;
```

Outside a verified session, nothing is visible — and `SET app.tenant_id`
changes nothing, because policies read `app.session_claim('tenant_id')`,
which re-verifies the token's signature on every call.

### Manual exploration (HTTP)

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8081/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@alpha.example","password":"alice-password"}' | jq -r .token)
curl -s http://127.0.0.1:8081/documents -H "Authorization: Bearer $TOKEN" | jq .
```

## The WebUI

The server serves a single-page demo UI (`api/static/index.html`) styled as a
paper "tenancy ledger":

- **01 Identity** — sign in (or one-click as Alice/Bob), showing the session
  claims (`sub`, `tenant_id`, token) the database verified.
- **02 Compose entry** — create a document; flip *published* off to watch
  the restrictive policy's `WITH CHECK` reject the write with HTTP 403.
- **03 app.documents** — the ledger as the signed-in tenant sees it.
  Teacher mode (a superuser-only endpoint, see below) draws **redacted
  bars over exactly the rows RLS hides** — switch between Alice and Bob and
  watch the redaction swap sides.
- **04 Request journal** — every API call the page makes, with its HTTP
  status, including the database's own rejection message on 403s.

## Design

### Roles

| Role | Attributes | Purpose |
| --- | --- | --- |
| `migration_runner` | `NOLOGIN`, no `BYPASSRLS` | Owns the `app` schema, tables, policies and functions. DDL only — never used at runtime |
| `app_user` | `LOGIN`, password, no `BYPASSRLS` | The API server's least-privilege login: DML + EXECUTE on auth functions, nothing else |
| `rls_auditor` | `NOLOGIN`, `BYPASSRLS` | Demonstrates why `BYPASSRLS` is dangerous (and owns the "leaky" demo view) |
| `postgres` | superuser | Bootstrap, tests, teacher-mode endpoint, always exempt |

### Authentication: sessions are minted AND verified in PostgreSQL

The API server holds **no secret**. JWT minting and verification are
SECURITY DEFINER functions owned by `migration_runner`, reading the HMAC
secret from `app.jwt_secret` (a table only those functions can access):

1. `app.login(email, password)` — checks the bcrypt hash (`pgcrypto`,
   cost 10) and returns a signed JWT (`sub`, `tenant_id`, `display_name`,
   `iat`, `exp` — 24h TTL). A caller can only mint a token for an account
   whose password it knows.
2. `app.session_verify(token)` — re-checks the HMAC signature and expiry,
   then stores the token in the session GUC `app.jwt`. Must run inside a
   transaction (the GUC is transaction-local, so pooled connections never
   leak sessions between requests).
3. **`app.session_claim(name)`** — what the RLS policies call. It
   re-verifies the signature of whatever sits in the `app.jwt` GUC and
   returns the claim only if it is genuine. A client that sets the GUC by
   hand, or presents a forged or expired token, gets `NULL` → the row is
   denied.

Because policies trust only verified claims, the classic hole — a connected
client running `SET app.tenant_id = …` — is closed (proven by `test.sh` 2).

### Policies on `app.documents` (RLS enabled **and** forced)

1. `tenant_isolation` — **permissive**, `FOR ALL`:
   `tenant_id = app.session_claim('tenant_id')::uuid` (USING and WITH
   CHECK). Permissive policies are OR-ed.
2. `published_only` — **restrictive**, `FOR ALL`:
   `published` (USING and WITH CHECK). Restrictive policies are AND-ed with
   the permissive set, so an unpublished draft is invisible even to its own
   tenant, and cannot be inserted.

`FORCE ROW LEVEL SECURITY` makes the policies apply to the table owner too —
normally table owners bypass RLS entirely. `app.owner_bypass_probe` exists
(with RLS enabled but **not** forced) to prove that default owner bypass.

### Endpoints

| Endpoint | Auth | Behaviour |
| --- | --- | --- |
| `GET /health` | none | liveness |
| `POST /login` | none | verifies credentials, returns JWT |
| `GET /me` | Bearer | returns the authenticated identity |
| `GET /documents` | Bearer | RLS-filtered list for the token's tenant |
| `POST /documents` | Bearer | insert; `WITH CHECK` policies validated by RLS (403 on rejection) |
| `GET /demo/truth` | Bearer | **demo-only teacher mode**: unfiltered table via a second superuser connection — powers the WebUI's redacted rows |
| `GET /` + static | none | the WebUI (`api/static/index.html`) |

Config via environment: `DATABASE_URL` (app_user), `AUDITOR_DATABASE_URL`
(superuser connection for `/demo/truth`), `BIND` (default `127.0.0.1:8081`).

## The critical limitations — and how this demo addresses them

The RLS literature warns of five traps. This repo does not just warn: each
one is either closed or demonstrated with running assertions.

1. **"The tenant variable is client-settable."** Closed. The tenant context
   is a *verified claim*, not a setting: policies call `app.session_claim()`,
   which re-verifies the token signature in the database. `SET` by hand,
   forged tokens and expired tokens all yield `NULL` (`test.sh` 2). The API
   holds no secret at all, so a compromised API server cannot mint tokens
   either — only the database can, and only for accounts whose passwords it
   checked.
2. **"Ownership means the app principal can alter policies / disable RLS."**
   Closed by role separation: `migration_runner` (NOLOGIN) owns everything;
   `app_user` has DML only, no `CREATE ON SCHEMA`, no ownership. `test.sh`
   11 proves `app_user` cannot `ALTER POLICY`, `DROP TABLE` or `CREATE
   TABLE`, while the migration role still can.
3. **"Views over RLS tables can leak."** Demonstrated both ways (`test.sh`
   12): `app.v_documents_safe` uses `security_invoker = true` and the
   invoker's RLS applies (3 rows); `app.v_documents_leaky` is owned by the
   `BYPASSRLS` auditor role, so its definer rights bypass RLS underneath and
   it exposes all 7 rows to anyone with SELECT. Rule: views that sit over
   RLS tables must be `security_invoker`, and privileged roles must never
   own objects application users can query.
4. **"Policy functions can leak through errors or timing."** Demonstrated
   (`test.sh` 13): `app.secret_notes`' policy uses `app.note_allowed()`,
   which `RAISE`s for restricted rows — a full scan without a session
   *errors*, revealing that restricted rows exist. The fix is in the design:
   never raise, never branch on hidden data in error messages, never mark
   application functions `LEAKPROOF` (only `LEAKPROOF` functions move ahead
   of the security barrier), never put volatile or side-effecting functions
   in a policy. Prefer plain column comparisons, as `app.documents` does.
5. **"Superusers and `BYPASSRLS` roles remain exempt."** True, by design —
   this cannot be closed, only contained: nobody at runtime holds those
   attributes. `rls_auditor` exists solely to demonstrate the danger, and
   the teacher-mode endpoint is the only superuser connection, clearly
   marked demo-only.

Remaining production notes (not closed in a demo, by nature):

- **Credentials are demo-grade**: passwords (`alice-password`), the seeded
  HMAC secret (`app.jwt_secret`) and bcrypt cost 10 are for demonstration.
  Rotate the secret, use real password policies, and store the secret
  outside the schema (e.g. injected at migration time from a vault).
- **JWT revocation**: tokens are stateless (24h TTL). For revocation, add a
  denylist table checked inside `app.session_claim()`, or shorten TTLs.
- **TLS**: the API and the database connection should be TLS in production
  (`sslmode=require` + certificates); the demo is localhost-only.

## Troubleshooting

- `test.sh` / `api_test.sh` say the container is not running → run
  `./run.sh` and wait for `Init complete`.
- Init fails → `podman logs postgres-rls-demo` (the init script runs before
  the server accepts connections; errors are in the log).
- Port conflicts → `run.sh` uses `54329`, the API defaults to `8081`
  (`BIND=127.0.0.1:PORT cargo run`).
- Changes to `sql/00-init.sql` require a recreate: `./stop.sh && ./run.sh`
  (the container deliberately has no persistent volume, so init re-runs).

## License

[MIT](LICENSE) — free to use, modify and redistribute.

## Contributing

This is a demonstration project — the best contributions are new RLS
pitfalls (and their fixes), each backed by a running assertion in `test.sh`
or `api_test.sh`. Open an issue or PR.
