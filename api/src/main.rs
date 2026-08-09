//! RLS demo API server — the trusted boundary in front of PostgreSQL Row
//! Level Security.
//!
//! Trust model: clients never talk to PostgreSQL directly, and **this server
//! holds no secret**.  JWT minting and verification happen inside PostgreSQL
//! (SECURITY DEFINER functions, HMAC secret stored only in the database):
//!
//!   1. `POST /login` calls `app.login()`, which checks the password hash
//!      (pgcrypto bcrypt) and returns a signed JWT carrying `tenant_id`;
//!   2. every authenticated request calls `app.session_verify()`, which
//!      re-verifies the signature/expiry and installs the verified session;
//!   3. RLS policies read `app.session_claim('tenant_id')`, which re-verifies
//!      the signature on every evaluation — a raw `SET` or a forged token
//!      yields NULL and the row is denied.
//!
//! The API never sees the tenant id from the client, and it cannot mint
//! tokens for tenants whose passwords it does not know.

use std::env;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_postgres::NoTls;
use tower_http::services::ServeDir;

type ApiError = (StatusCode, Json<Value>);
type ApiResult = Result<(StatusCode, Json<Value>), ApiError>;

#[derive(Clone)]
struct AppState {
    pool: Pool,        // app_user: the real application connection
    truth_pool: Pool,  // superuser: demo-only "teacher mode" view
}

/// Claims returned by `app.session_verify()` — they come from the
/// database after it verified the token signature itself.
struct SessionClaims {
    user_id: String,
    tenant_id: String,
    display_name: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct NewDocument {
    title: String,
    body: String,
    #[serde(default = "default_true")]
    published: bool,
}

fn default_true() -> bool {
    true
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dsn = env::var("DATABASE_URL").unwrap_or_else(|_| {
        "host=127.0.0.1 port=54329 user=app_user password=app_user_demo_password dbname=rls_demo"
            .to_string()
    });
    let bind = env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8081".to_string());

    let cfg = dsn.parse::<tokio_postgres::Config>()?;
    let mgr = Manager::from_config(cfg, NoTls, ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    let pool = Pool::builder(mgr).max_size(5).build()?;

    // Second pool for the demo-only teacher endpoint: connects as the
    // superuser, to whom RLS never applies.
    let auditor_dsn = env::var("AUDITOR_DATABASE_URL").unwrap_or_else(|_| {
        "host=127.0.0.1 port=54329 user=postgres password=postgres_demo_password dbname=rls_demo"
            .to_string()
    });
    let truth_cfg = auditor_dsn.parse::<tokio_postgres::Config>()?;
    let truth_mgr = Manager::from_config(truth_cfg, NoTls, ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    let truth_pool = Pool::builder(truth_mgr).max_size(2).build()?;

    let static_dir = format!("{}/static", env!("CARGO_MANIFEST_DIR"));

    let app = Router::new()
        .route("/health", get(health))
        .route("/login", post(login))
        .route("/me", get(me))
        .route("/documents", get(list_documents).post(create_document))
        .route("/demo/truth", get(table_truth))
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
        .with_state(AppState { pool, truth_pool });

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("RLS demo API listening on http://{bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

// ---------------------------------------------------------------------------
// POST /login  { "email": "...", "password": "..." }
// ---------------------------------------------------------------------------
// Password verification AND token minting happen inside PostgreSQL via
// app.login() (SECURITY DEFINER, pgcrypto bcrypt, DB-held HMAC secret).
// This server never sees a secret and cannot mint tokens for accounts whose
// passwords it does not know.
async fn login(State(state): State<AppState>, Json(body): Json<LoginRequest>) -> ApiResult {
    let client = state
        .pool
        .get()
        .await
        .map_err(|e| internal("could not get a database connection", &e))?;

    let row = client
        .query_opt(
            "SELECT token, user_id, tenant_id::text, display_name, expires_in
               FROM app.login($1, $2)",
            &[&body.email, &body.password],
        )
        .await
        .map_err(|e| internal("login query failed", &e))?;

    let Some(row) = row else {
        return Err(unauthorized("invalid email or password"));
    };

    let token: String = row.get(0);
    let tenant_id: String = row.get(2);
    let display_name: String = row.get(3);
    let expires_in: i64 = row.get(4);

    Ok((
        StatusCode::OK,
        Json(json!({
            "token": token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "tenant_id": tenant_id,
            "display_name": display_name,
        })),
    ))
}

// ---------------------------------------------------------------------------
// GET /me
// ---------------------------------------------------------------------------
async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let mut client = state
        .pool
        .get()
        .await
        .map_err(|e| internal("could not get a database connection", &e))?;

    let mut tx = client
        .transaction()
        .await
        .map_err(|e| internal("could not start transaction", &e))?;

    let claims = authorize(&mut tx, &headers).await?;

    tx.commit()
        .await
        .map_err(|e| internal("could not commit", &e))?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "user_id": claims.user_id,
            "tenant_id": claims.tenant_id,
            "display_name": claims.display_name,
        })),
    ))
}

// ---------------------------------------------------------------------------
// GET /documents
// ---------------------------------------------------------------------------
// The trusted boundary in action: the token is verified inside PostgreSQL
// (app.session_verify), which also installs the verified session that the
// RLS policies read.  The client cannot influence which tenant's rows come
// back — not even by setting session variables directly.
async fn list_documents(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let mut client = state
        .pool
        .get()
        .await
        .map_err(|e| internal("could not get a database connection", &e))?;

    let mut tx = client
        .transaction()
        .await
        .map_err(|e| internal("could not start transaction", &e))?;

    let claims = authorize(&mut tx, &headers).await?;

    let rows = tx
        .query(
            "SELECT id, title, body, published, created_at::text
               FROM app.documents
              ORDER BY id",
            &[],
        )
        .await
        .map_err(|e| internal("query failed", &e))?;

    tx.commit()
        .await
        .map_err(|e| internal("could not commit", &e))?;

    let documents: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<_, i64>(0),
                "title": r.get::<_, String>(1),
                "body": r.get::<_, String>(2),
                "published": r.get::<_, bool>(3),
                "created_at": r.get::<_, String>(4),
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(json!({
            "tenant_id": claims.tenant_id,
            "count": documents.len(),
            "documents": documents,
        })),
    ))
}

// ---------------------------------------------------------------------------
// POST /documents  { "title": "...", "body": "...", "published": true }
// ---------------------------------------------------------------------------
// tenant_id is taken from the database-verified session, never from the
// request body.  The RLS WITH CHECK clauses then validate the write (e.g.
// published=false is rejected with 403 by the restrictive policy).
async fn create_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewDocument>,
) -> ApiResult {
    let mut client = state
        .pool
        .get()
        .await
        .map_err(|e| internal("could not get a database connection", &e))?;

    let mut tx = client
        .transaction()
        .await
        .map_err(|e| internal("could not start transaction", &e))?;

    let claims = authorize(&mut tx, &headers).await?;

    let tenant_uuid = uuid::Uuid::parse_str(&claims.tenant_id)
        .map_err(|e| internal("session carries a malformed tenant id", &e))?;

    let inserted = tx
        .query_opt(
            "INSERT INTO app.documents (tenant_id, title, body, published)
             VALUES ($1, $2, $3, $4)
             RETURNING id, created_at::text",
            &[&tenant_uuid, &body.title, &body.body, &body.published],
        )
        .await;

    let row = match inserted {
        Ok(Some(r)) => r,
        Ok(None) => return Err(internal("insert returned no row", &"unreachable")),
        Err(e) if is_rls_rejection(&e) => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "row-level security policy rejected this write",
                    "detail": e.to_string(),
                })),
            ));
        }
        Err(e) => return Err(internal("insert failed", &e)),
    };

    tx.commit()
        .await
        .map_err(|e| internal("could not commit", &e))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": row.get::<_, i64>(0),
            "title": body.title,
            "body": body.body,
            "published": body.published,
            "tenant_id": claims.tenant_id,
            "created_at": row.get::<_, String>(1),
        })),
    ))
}

// ---------------------------------------------------------------------------
// GET /demo/truth  (demo-only "teacher mode")
// ---------------------------------------------------------------------------
// Returns the unfiltered contents of app.documents through a second
// connection that runs as the superuser — the role RLS never applies to.
// The web UI uses it to draw redacted bars over exactly the rows the
// signed-in tenant cannot see.  This endpoint would never exist in
// production; it is the demo equivalent of running psql as postgres.
async fn table_truth(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    // Verify the session through the normal path first.
    let mut client = state
        .pool
        .get()
        .await
        .map_err(|e| internal("could not get a database connection", &e))?;

    let mut tx = client
        .transaction()
        .await
        .map_err(|e| internal("could not start transaction", &e))?;

    authorize(&mut tx, &headers).await?;
    drop(tx); // rollback: nothing to commit here

    let truth_client = state
        .truth_pool
        .get()
        .await
        .map_err(|e| internal("could not get the auditor connection", &e))?;

    let rows = truth_client
        .query(
            "SELECT id, tenant_id::text, title, body, published, created_at::text
               FROM app.documents
              ORDER BY id",
            &[],
        )
        .await
        .map_err(|e| internal("auditor query failed", &e))?;

    let documents: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<_, i64>(0),
                "tenant_id": r.get::<_, String>(1),
                "title": r.get::<_, String>(2),
                "body": r.get::<_, String>(3),
                "published": r.get::<_, bool>(4),
                "created_at": r.get::<_, String>(5),
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(json!({
            "note": "superuser view — RLS never applies to superusers. Demo-only endpoint.",
            "total": documents.len(),
            "documents": documents,
        })),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Verify the Bearer token against the database inside the caller's
/// transaction.  app.session_verify() checks the HMAC signature and expiry
/// with a secret that only PostgreSQL holds, then installs the verified
/// session that RLS policies read.  Returns 401 if the token is missing,
/// malformed, forged or expired.
async fn authorize(
    tx: &mut tokio_postgres::Transaction<'_>,
    headers: &HeaderMap,
) -> Result<SessionClaims, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| unauthorized("missing or malformed Authorization: Bearer <token>"))?;

    let row = tx
        .query_opt(
            "SELECT user_id, tenant_id::text, display_name
               FROM app.session_verify($1)",
            &[&token],
        )
        .await
        .map_err(|e| internal("session verification failed", &e))?;

    row.map(|r| SessionClaims {
        user_id: r.get::<_, i64>(0).to_string(),
        tenant_id: r.get::<_, String>(1),
        display_name: r.get::<_, String>(2),
    })
    .ok_or_else(|| unauthorized("invalid or expired token"))
}

/// RLS WITH CHECK violations surface as SQLSTATE 42501 (insufficient
/// privilege) — map them to 403 so the caller can distinguish "policy says
/// no" from "server is broken".
fn is_rls_rejection(e: &tokio_postgres::Error) -> bool {
    e.code() == Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
}

fn unauthorized(detail: &str) -> ApiError {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized", "detail": detail })),
    )
}

fn internal(detail: &str, cause: &dyn std::fmt::Display) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "error": "internal error",
            "detail": detail,
            "cause": cause.to_string(),
        })),
    )
}
