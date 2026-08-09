-- ============================================================================
-- 00-init.sql - PostgreSQL Row Level Security demo schema
--
-- Runs automatically when the container is first created
-- (mounted at /docker-entrypoint-initdb.d).  Executed as the superuser
-- (postgres).  Objects are created under the migration runner role so that
-- privilege boundaries reflect a real deployment.
--
-- Trust model (addresses the classic RLS limitations):
--   * Session claims are minted AND verified inside PostgreSQL.  The tenant
--     context is not a free-form setting: policies call app.session_claim(),
--     which re-verifies the HMAC signature of the token stored in the
--     session.  A raw SET or a forged token yields NULL -> default deny.
--   * The API server holds no secret: app.login() (SECURITY DEFINER) mints
--     tokens after checking the password hash, and app.session_verify()
--     validates them per request.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Roles
-- ---------------------------------------------------------------------------
-- The migration runner owns the schema, tables, policies and functions.
-- It is NOLOGIN: it exists only for DDL (init scripts and migrations).
-- Application principals have DML grants only and no ownership, so they can
-- neither alter policies nor disable RLS.
CREATE ROLE migration_runner NOLOGIN NOSUPERUSER NOBYPASSRLS;

-- The application login role: only the privileges it needs.
CREATE ROLE app_user LOGIN PASSWORD 'app_user_demo_password'
  NOSUPERUSER NOBYPASSRLS;

-- Deliberately privileged role used only to demonstrate why BYPASSRLS is a
-- dangerous attribute to hand out (and why views owned by privileged roles
-- leak).
CREATE ROLE rls_auditor NOLOGIN BYPASSRLS;

-- ---------------------------------------------------------------------------
-- 2. Schema owned by the migration runner
-- ---------------------------------------------------------------------------
CREATE SCHEMA app AUTHORIZATION migration_runner;

-- ---------------------------------------------------------------------------
-- 3. Main table: tenant-scoped documents
-- ---------------------------------------------------------------------------
-- pgcrypto (bcrypt + HMAC for the auth section below) needs superuser, so
-- it is created before switching to the migration runner.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

SET ROLE migration_runner;

CREATE TABLE app.documents (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid        NOT NULL,
  title       text        NOT NULL,
  body        text        NOT NULL,
  published   boolean     NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO app.documents (tenant_id, title, body, published) VALUES
  ('11111111-1111-1111-1111-111111111111', 'Alpha Roadmap', 'Tenant A document 1', true),
  ('11111111-1111-1111-1111-111111111111', 'Alpha Budget',  'Tenant A document 2', true),
  ('11111111-1111-1111-1111-111111111111', 'Alpha Hiring',  'Tenant A document 3', true),
  ('11111111-1111-1111-1111-111111111111', 'Alpha Draft',   'Tenant A unpublished draft', false),
  ('22222222-2222-2222-2222-222222222222', 'Beta Launch',   'Tenant B document 1', true),
  ('22222222-2222-2222-2222-222222222222', 'Beta Metrics',  'Tenant B document 2', true),
  ('22222222-2222-2222-2222-222222222222', 'Beta Draft',    'Tenant B unpublished draft', false);

-- ---------------------------------------------------------------------------
-- 4. Authentication: users, secrets, and in-database JWT mint/verify
-- ---------------------------------------------------------------------------
-- The API server never sees a secret.  Tokens are signed and verified by
-- these SECURITY DEFINER functions, which are the only objects that may read
-- app.jwt_secret.

CREATE TABLE app.users (
  id            bigserial PRIMARY KEY,
  email         text NOT NULL UNIQUE,
  password_hash text NOT NULL,   -- bcrypt via pgcrypto crypt(), cost 10
  tenant_id     uuid NOT NULL,
  display_name  text NOT NULL
);

INSERT INTO app.users (email, password_hash, tenant_id, display_name) VALUES
  ('alice@alpha.example',
   crypt('alice-password', gen_salt('bf', 10)),
   '11111111-1111-1111-1111-111111111111', 'Alice (Tenant A)'),
  ('bob@beta.example',
   crypt('bob-password', gen_salt('bf', 10)),
   '22222222-2222-2222-2222-222222222222', 'Bob (Tenant B)');

-- Single-row secret table; only SECURITY DEFINER functions owned by
-- migration_runner can read it.  Dev value only - rotate in production.
CREATE TABLE app.jwt_secret (
  id     int  PRIMARY KEY CHECK (id = 1),
  secret text NOT NULL
);
INSERT INTO app.jwt_secret (id, secret) VALUES
  (1, 'demo-jwt-secret-0123456789abcdef-change-me');

-- base64url helpers (JWT uses URL-safe alphabet, no padding).  NB:
-- PostgreSQL's encode(..., 'base64') wraps output in newlines every 76
-- characters (MIME style) — they must be stripped.
CREATE FUNCTION app.url_encode(p bytea) RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT rtrim(translate(replace(replace(encode(p, 'base64'), E'\r', ''), E'\n', ''), '+/', '-_'), '=')
$$;

CREATE FUNCTION app.url_decode(p text) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
  RETURN decode(rpad(translate(p, '-_', '+/'), ((length(p) + 3) / 4) * 4, '='), 'base64');
EXCEPTION WHEN others THEN
  RETURN NULL;  -- malformed input is a clean NULL, never an error
END
$$;

-- Mint a signed token for a user whose password matches.  Returns one row
-- on success, zero rows on failure.  The password is checked inside
-- PostgreSQL (pgcrypto); hashes never leave the database.
CREATE FUNCTION app.login(p_email text, p_password text)
RETURNS TABLE (token text, user_id bigint, tenant_id uuid, display_name text, expires_in bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_temp
AS $$
DECLARE
  v_id          bigint;
  v_tenant      uuid;
  v_name        text;
  v_iat         bigint;
  v_exp         bigint;
  v_header      text;
  v_payload     text;
  v_sig         text;
  v_secret      text;
BEGIN
  SELECT u.id, u.tenant_id, u.display_name
    INTO v_id, v_tenant, v_name
    FROM app.users AS u
   WHERE u.email = p_email
     AND u.password_hash = public.crypt(p_password, u.password_hash);

  IF NOT FOUND THEN
    RETURN;  -- zero rows: bad credentials
  END IF;

  SELECT secret INTO v_secret FROM app.jwt_secret WHERE id = 1;

  v_iat := extract(epoch FROM now())::bigint;
  v_exp := v_iat + 86400;  -- 24h TTL

  v_header  := app.url_encode(convert_to('{"alg":"HS256","typ":"JWT"}', 'UTF8'));
  v_payload := app.url_encode(convert_to(
    jsonb_build_object(
      'sub',          v_id::text,
      'tenant_id',    v_tenant::text,
      'display_name', v_name,
      'iat',          v_iat,
      'exp',          v_exp
    )::text, 'UTF8'));
  v_sig := app.url_encode(public.hmac(v_header || '.' || v_payload, v_secret, 'sha256'));

  token := v_header || '.' || v_payload || '.' || v_sig;
  RETURN QUERY SELECT token, v_id, v_tenant, v_name, v_exp - v_iat;
END
$$;

-- Verify a token: check signature (HMAC against the DB-held secret), check
-- expiry, then store the token in the session GUC 'app.jwt'.  Returns one
-- row with the claims on success, zero rows on failure.  Must run inside a
-- transaction (the GUC is set transaction-locally).
CREATE FUNCTION app.session_verify(p_token text)
RETURNS TABLE (user_id bigint, tenant_id uuid, display_name text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_temp
AS $$
DECLARE
  parts     text[];
  payload   jsonb;
  computed  bytea;
  sig       bytea;
  v_secret  text;
  v_exp     bigint;
BEGIN
  parts := string_to_array(p_token, '.');
  IF cardinality(parts) <> 3 THEN
    RETURN;
  END IF;

  SELECT secret INTO v_secret FROM app.jwt_secret WHERE id = 1;
  computed := public.hmac(parts[1] || '.' || parts[2], v_secret, 'sha256');
  sig      := app.url_decode(parts[3]);
  IF sig IS NULL OR computed <> sig THEN
    RETURN;  -- undecodable, forged or corrupted
  END IF;

  payload := convert_from(app.url_decode(parts[2]), 'UTF8')::jsonb;
  v_exp   := (payload ->> 'exp')::bigint;
  IF v_exp IS NULL OR to_timestamp(v_exp) < now() THEN
    RETURN;  -- missing or expired
  END IF;
  IF NOT (payload ? 'sub' AND payload ? 'tenant_id') THEN
    RETURN;
  END IF;

  -- Install the verified session.  The GUC itself is not trusted by any
  -- policy: app.session_claim() re-verifies it on every call.
  PERFORM set_config('app.jwt', p_token, true);

  RETURN QUERY
    SELECT (payload ->> 'sub')::bigint,
           (payload ->> 'tenant_id')::uuid,
           payload ->> 'display_name';
EXCEPTION WHEN others THEN
  RETURN;  -- any malformed token is a clean denial (401), never an error
END
$$;

-- Read one claim from the verified session, or NULL if there is no verified
-- session.  This is what policies call.  Because it re-verifies the HMAC
-- signature of whatever sits in the 'app.jwt' GUC, a client that sets the
-- GUC by hand (or forges a token) gets NULL, not a tenant.
CREATE FUNCTION app.session_claim(p_name text) RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_temp
AS $$
DECLARE
  tok       text := current_setting('app.jwt', true);
  parts     text[];
  payload   jsonb;
  computed  bytea;
  sig       bytea;
  v_secret  text;
  v_exp     bigint;
BEGIN
  IF tok IS NULL THEN
    RETURN NULL;
  END IF;

  parts := string_to_array(tok, '.');
  IF cardinality(parts) <> 3 THEN
    RETURN NULL;
  END IF;

  SELECT secret INTO v_secret FROM app.jwt_secret WHERE id = 1;
  computed := public.hmac(parts[1] || '.' || parts[2], v_secret, 'sha256');
  sig      := app.url_decode(parts[3]);
  IF sig IS NULL OR computed <> sig THEN
    RETURN NULL;
  END IF;

  payload := convert_from(app.url_decode(parts[2]), 'UTF8')::jsonb;
  v_exp   := (payload ->> 'exp')::bigint;
  IF v_exp IS NULL OR to_timestamp(v_exp) < now() THEN
    RETURN NULL;
  END IF;

  RETURN payload ->> p_name;
EXCEPTION WHEN others THEN
  RETURN NULL;  -- malformed session value is a clean NULL, never an error
END
$$;

-- Convenience: authenticate AND establish the verified session in one call.
CREATE FUNCTION app.establish(p_email text, p_password text)
RETURNS TABLE (token text, user_id bigint, tenant_id uuid, display_name text, expires_in bigint)
LANGUAGE sql
SET search_path = pg_temp
AS $$
  SELECT l.token, s.user_id, s.tenant_id, s.display_name, l.expires_in
    FROM app.login(p_email, p_password) AS l
    CROSS JOIN LATERAL app.session_verify(l.token) AS s
$$;

REVOKE ALL ON FUNCTION app.login(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.session_verify(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.session_claim(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.establish(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.url_encode(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.url_decode(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.login(text, text) TO app_user;
GRANT EXECUTE ON FUNCTION app.session_verify(text) TO app_user;
GRANT EXECUTE ON FUNCTION app.session_claim(text) TO app_user;
GRANT EXECUTE ON FUNCTION app.establish(text, text) TO app_user;

-- ---------------------------------------------------------------------------
-- 5. Row Level Security on app.documents
-- ---------------------------------------------------------------------------
ALTER TABLE app.documents ENABLE ROW LEVEL SECURITY;

-- FORCE RLS makes the policies apply to the table owner too, closing the
-- default "owner bypasses RLS" loophole.
ALTER TABLE app.documents FORCE ROW LEVEL SECURITY;

-- Permissive policy (the default kind): tenant isolation.  The tenant is not
-- read from a free-form setting: app.session_claim('tenant_id') re-verifies
-- the HMAC signature of the JWT stored in the session GUC and returns the
-- claim only if it is genuine.  Raw SET / forged tokens -> NULL -> deny.
CREATE POLICY tenant_isolation ON app.documents
  FOR ALL
  TO app_user
  USING (tenant_id = app.session_claim('tenant_id')::uuid)
  WITH CHECK (tenant_id = app.session_claim('tenant_id')::uuid);

-- Restrictive policy: visibility/insertability of published rows.
-- Restrictive policies are AND-ed with the permissive ones, so an
-- unpublished row stays hidden even for its own tenant.
CREATE POLICY published_only ON app.documents
  AS RESTRICTIVE
  FOR ALL
  TO app_user
  USING (published)
  WITH CHECK (published);

-- ---------------------------------------------------------------------------
-- 6. Grants to the application login role (least privilege, no DDL)
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.documents TO app_user;
GRANT USAGE, SELECT ON SEQUENCE app.documents_id_seq TO app_user;

-- The auditor needs ordinary privileges too: BYPASSRLS only removes the row
-- security filter, it does not grant schema or table access.
GRANT USAGE ON SCHEMA app TO rls_auditor;
GRANT SELECT ON app.documents TO rls_auditor;

-- ---------------------------------------------------------------------------
-- 7. Views over the RLS table: the security_invoker lesson
-- ---------------------------------------------------------------------------
-- Safe: the view runs with the *invoker's* rights, so the invoker's RLS
-- policies apply underneath.
CREATE VIEW app.v_documents_safe
WITH (security_invoker = true) AS
SELECT id, tenant_id, title, body, published, created_at
  FROM app.documents;

-- Dangerous: owned by the BYPASSRLS auditor role, so the view runs with the
-- *definer's* rights and RLS never applies underneath.  Anyone with SELECT
-- on this view sees every tenant's rows.  (CREATE is granted to the auditor
-- for exactly one statement, then revoked.)
GRANT CREATE ON SCHEMA app TO rls_auditor;
SET ROLE rls_auditor;
CREATE VIEW app.v_documents_leaky AS
SELECT id, tenant_id, title, body, published, created_at
  FROM app.documents;
RESET ROLE;
REVOKE CREATE ON SCHEMA app FROM rls_auditor;

GRANT SELECT ON app.v_documents_safe  TO app_user;
GRANT SELECT ON app.v_documents_leaky TO app_user;

-- ---------------------------------------------------------------------------
-- 8. Leaky policy functions: the error-message lesson
-- ---------------------------------------------------------------------------
SET ROLE migration_runner;  -- re-establish the DDL role after the view demo

-- This table's policy uses a function that RAISEs for restricted rows
-- instead of returning false.  A full scan therefore *errors* when a
-- restricted row exists, leaking its existence through the error message.
-- The fix is to return false: never raise, never branch on hidden data in
-- errors, never mark application functions LEAKPROOF, never put volatile
-- or side-effecting functions in a policy.
CREATE TABLE app.secret_notes (
  id           int  PRIMARY KEY,
  note         text NOT NULL,
  access_group text NOT NULL
);

INSERT INTO app.secret_notes (id, note, access_group) VALUES
  (1, 'Q3 report',          'public'),
  (2, 'Launch plans',       'internal'),
  (3, 'Customer key store', 'secret');

CREATE FUNCTION app.note_allowed(p_group text) RETURNS boolean
LANGUAGE plpgsql
AS $$
BEGIN
  IF p_group = 'public' THEN
    RETURN true;
  END IF;
  IF app.session_claim('tenant_id') IS NULL THEN
    RAISE EXCEPTION 'classified: a restricted note exists (this error leaks existence!)';
  END IF;
  RETURN true;
END
$$;

ALTER TABLE app.secret_notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_policy ON app.secret_notes
  USING (app.note_allowed(access_group));

GRANT SELECT ON app.secret_notes TO app_user;

-- ---------------------------------------------------------------------------
-- 9. Probe table: RLS enabled but NOT forced
-- ---------------------------------------------------------------------------
-- Shows the default behaviour: the table owner bypasses RLS unless FORCE RLS
-- is used.  app_user is locked out completely by the deny policy below.
CREATE TABLE app.owner_bypass_probe (
  id    bigserial PRIMARY KEY,
  note  text NOT NULL
);

INSERT INTO app.owner_bypass_probe (note) VALUES
  ('owner sees me'),
  ('owner sees me too');

ALTER TABLE app.owner_bypass_probe ENABLE ROW LEVEL SECURITY;
-- deliberately NO "FORCE ROW LEVEL SECURITY" here

CREATE POLICY deny_app_user ON app.owner_bypass_probe
  FOR ALL
  TO app_user
  USING (false)
  WITH CHECK (false);

GRANT SELECT, INSERT, UPDATE, DELETE ON app.owner_bypass_probe TO app_user;
GRANT USAGE, SELECT ON SEQUENCE app.owner_bypass_probe_id_seq TO app_user;

RESET ROLE;

-- ---------------------------------------------------------------------------
-- 10. Sanity check (superuser view; RLS never applies to superusers)
-- ---------------------------------------------------------------------------
SELECT 'init complete: ' || count(*) || ' documents seeded' AS status
  FROM app.documents;
