//! Property-based tests for the RLS demo's security properties.
//!
//! Requires the demo container (`./run.sh`) and the API server
//! (`cd api && cargo run`). Every property is *differential*: the
//! RLS-filtered view is compared against a model predicate computed from the
//! superuser "teacher" view, over many randomized states and operations.
//! On failure, proptest shrinks to a minimal counterexample automatically.
//!
//! Properties:
//!   1. visible_set_matches_model      — for any tenant and any document set,
//!      the API returns exactly { d | d.tenant == tenant ∧ d.published }.
//!   2. cross_tenant_isolation         — stateful: random op sequences
//!      (login / create / list) never break the model; unauthenticated
//!      probes are always 401 (no session leakage across pooled connections).
//!   3. write_check_enforced           — POST /documents returns 201 iff
//!      published; created rows are stamped with the session tenant, never
//!      the request body; the other tenant never sees them.
//!   4. token_forgery_rejected         — every mutation of a valid token
//!      (garbage, truncation, bit flips, forged signatures, expired claims)
//!      is rejected with 401.
//!   5. auth_and_claims                — login succeeds iff the password
//!      matches; claims (sub, tenant_id, 24h TTL) match the users table.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use reqwest::blocking::{Client, Response};
use serde_json::Value;

const BASE: &str = "http://127.0.0.1:8081";
const TENANT_A: &str = "11111111-1111-1111-1111-111111111111";
const TENANT_B: &str = "22222222-2222-2222-2222-222222222222";
const ALICE: (&str, &str) = ("alice@alpha.example", "alice-password");
const BOB: (&str, &str) = ("bob@beta.example", "bob-password");
const TTL_SECS: i64 = 86400;

fn cfg(cases: u32) -> Config {
    Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    }
}

static SEQ: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

fn client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("http client")
}

#[derive(Clone, Debug)]
struct Session {
    token: String,
    tenant: String,
}

fn login(c: &Client, email: &str, password: &str) -> Option<Session> {
    let resp = c
        .post(format!("{BASE}/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .expect("login request failed");
    if resp.status().as_u16() != 200 {
        return None;
    }
    let v: Value = resp.json().expect("login json");
    Some(Session {
        token: v["token"].as_str().expect("token").to_string(),
        tenant: v["tenant_id"].as_str().expect("tenant_id").to_string(),
    })
}

fn documents(c: &Client, s: &Session) -> Vec<Value> {
    let resp = c
        .get(format!("{BASE}/documents"))
        .bearer_auth(&s.token)
        .send()
        .expect("documents request failed");
    assert_eq!(resp.status().as_u16(), 200, "valid session must get 200");
    resp.json::<Value>().expect("documents json")["documents"]
        .as_array()
        .expect("documents array")
        .clone()
}

/// Superuser "teacher" view — the ground truth used as the model.
fn truth(c: &Client, s: &Session) -> Vec<Value> {
    let resp = c
        .get(format!("{BASE}/demo/truth"))
        .bearer_auth(&s.token)
        .send()
        .expect("truth request failed");
    assert_eq!(resp.status().as_u16(), 200, "teacher view must be reachable");
    resp.json::<Value>().expect("truth json")["documents"]
        .as_array()
        .expect("documents array")
        .clone()
}

fn create(c: &Client, s: &Session, title: &str, body: &str, published: bool) -> u16 {
    c.post(format!("{BASE}/documents"))
        .bearer_auth(&s.token)
        .json(&serde_json::json!({
            "title": title,
            "body": body,
            "published": published,
        }))
        .send()
        .expect("create request failed")
        .status()
        .as_u16()
}

fn unique(prefix: &str) -> String {
    format!("pbt-{prefix}-{}", SEQ.fetch_add(1, Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// The model: what any tenant MUST be able to see
// ---------------------------------------------------------------------------

/// For every session, the RLS-filtered view must equal the model predicate
/// `tenant_id == T AND published` applied to the ground truth. Also: a
/// request with no token is always 401 (sessions never leak across pooled
/// connections, because the session GUC is transaction-local).
fn assert_consistent(c: &Client, sessions: &[Session]) -> Result<(), TestCaseError> {
    let all = truth(c, &sessions[0]);
    for s in sessions {
        let mut actual: Vec<i64> = documents(c, s)
            .iter()
            .map(|d| d["id"].as_i64().expect("id"))
            .collect();
        let mut expected: Vec<i64> = all
            .iter()
            .filter(|d| {
                d["tenant_id"].as_str() == Some(s.tenant.as_str())
                    && d["published"].as_bool() == Some(true)
            })
            .map(|d| d["id"].as_i64().expect("id"))
            .collect();
        actual.sort_unstable();
        expected.sort_unstable();
        prop_assert_eq!(
            actual,
            expected,
            "visible set must equal the model predicate for tenant {}",
            s.tenant
        );
    }
    let probe = c
        .get(format!("{BASE}/documents"))
        .send()
        .expect("unauthenticated probe");
    prop_assert_eq!(
        probe.status().as_u16(),
        401,
        "no-auth request must always be 401 (session leak?)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Property 1 — visible set matches the model, over randomized doc sets
// ---------------------------------------------------------------------------


fn visible_set_matches_model() {
    let c = client();
    let alice = login(&c, ALICE.0, ALICE.1).expect("alice login");
    let bob = login(&c, BOB.0, BOB.1).expect("bob login");

    let strategy = (0..8usize, 0..8usize);
    run_cases(
        "visible_set_matches_model",
        cfg(128),
        strategy,
        |(na, nb)| {
            let sessions = vec![alice.clone(), bob.clone()];
            for _ in 0..na {
                let status = create(&c, &sessions[0], &unique("vs-a"), "body", true);
                prop_assert_eq!(status, 201);
            }
            for _ in 0..nb {
                let status = create(&c, &sessions[1], &unique("vs-b"), "body", true);
                prop_assert_eq!(status, 201);
            }
            assert_consistent(&c, &sessions)
        },
    );
}

// ---------------------------------------------------------------------------
// Property 2 — stateful: random op sequences never break the invariants
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Op {
    LoginA,
    LoginB,
    CreateA(bool),
    CreateB(bool),
    ListA,
    ListB,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        Just(Op::LoginA),
        Just(Op::LoginB),
        any::<bool>().prop_map(Op::CreateA),
        any::<bool>().prop_map(Op::CreateB),
        Just(Op::ListA),
        Just(Op::ListB),
    ]
}


fn cross_tenant_isolation_stateful() {
    let c = client();

    let strategy = prop::collection::vec(op_strategy(), 0..12);
    run_cases("cross_tenant_isolation (stateful)", cfg(64), strategy, |ops| {
        let mut sessions = vec![
            login(&c, ALICE.0, ALICE.1).expect("alice login"),
            login(&c, BOB.0, BOB.1).expect("bob login"),
        ];
        for op in ops {
            match op {
                Op::LoginA => {
                    sessions[0] = login(&c, ALICE.0, ALICE.1).expect("alice login");
                }
                Op::LoginB => {
                    sessions[1] = login(&c, BOB.0, BOB.1).expect("bob login");
                }
                Op::CreateA(published) => {
                    let status = create(&c, &sessions[0], &unique("st-a"), "body", published);
                    prop_assert_eq!(status, if published { 201 } else { 403 });
                }
                Op::CreateB(published) => {
                    let status = create(&c, &sessions[1], &unique("st-b"), "body", published);
                    prop_assert_eq!(status, if published { 201 } else { 403 });
                }
                Op::ListA => {
                    let _ = documents(&c, &sessions[0]);
                }
                Op::ListB => {
                    let _ = documents(&c, &sessions[1]);
                }
            }
            assert_consistent(&c, &sessions)?;
        }
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Property 3 — write path: 201 iff published; tenant stamped from the
// session; no cross-tenant visibility after writes
// ---------------------------------------------------------------------------


fn write_check_enforced() {
    let c = client();
    let alice = login(&c, ALICE.0, ALICE.1).expect("alice login");

    let strategy = (
        "[a-zA-Z0-9 _-]{0,40}",
        r"\PC{0,60}", // any non-control characters, including unicode
        any::<bool>(),
    );
    run_cases("write_check_enforced", cfg(128), strategy, |(title, body, published)| {
        let title = format!("{title}-{}", SEQ.fetch_add(1, Ordering::Relaxed));
        let status = create(&c, &alice, &title, &body, published);
        prop_assert_eq!(
            status == 201,
            published,
            "WITH CHECK must reject unpublished writes (got {})",
            status
        );
        if published {
            let all = truth(&c, &alice);
            let mine: Vec<&Value> = all
                .iter()
                .filter(|d| d["tenant_id"].as_str() == Some(TENANT_A) && d["title"] == title)
                .collect();
            prop_assert_eq!(
                mine.len(),
                1,
                "created doc must exist exactly once, stamped with the session tenant"
            );
            let bob = login(&c, BOB.0, BOB.1).expect("bob login");
            let bob_docs = documents(&c, &bob);
            prop_assert!(
                !bob_docs.iter().any(|d| d["title"] == title),
                "cross-tenant leak after write"
            );
        }
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Property 4 — no token mutation is ever accepted
// ---------------------------------------------------------------------------

fn forged_tokens(token: String) -> impl Strategy<Value = String> {
    let parts: Vec<String> = token.split('.').map(String::from).collect();
    let offsets: Vec<usize> = parts.iter().map(|p| p.len()).collect();
    let header = parts[0].clone();
    let payload = parts[1].clone();

    // An "expired" claim: same structure, exp in the past, unsigned.
    let expired_payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "sub": "1",
            "tenant_id": TENANT_A,
            "display_name": "Alice (Tenant A)",
            "iat": 1,
            "exp": 2,
        })
        .to_string(),
    );

    prop_oneof![
        Just("garbage".to_string()),
        Just("not.a.jwt".to_string()),
        Just(format!("{header}.{payload}")),        // signature stripped
        Just(format!("{header}.{payload}.AAAA")),   // forged signature
        Just(format!("{header}.{expired_payload}.AAAA")), // expired claims
        Just(token.clone() + "."),                  // trailing junk
        // flip one bit inside each of the three parts
        (0..3usize).prop_flat_map(move |i| {
            let token = token.clone();
            let offsets = offsets.clone();
            let len = offsets[i];
            (0..len).prop_map(move |pos| {
                let offset: usize = offsets[..i].iter().sum::<usize>() + i + pos;
                let mut bytes = token.clone().into_bytes();
                bytes[offset] ^= 0x01;
                String::from_utf8(bytes).unwrap_or_else(|_| "broken-utf8".to_string())
            })
        }),
    ]
}


fn token_forgery_rejected() {
    let c = client();
    let alice = login(&c, ALICE.0, ALICE.1).expect("alice login");

    run_cases(
        "token_forgery_rejected",
        cfg(128),
        forged_tokens(alice.token.clone()),
        |forged| {
            let resp = c
                .get(format!("{BASE}/me"))
                .bearer_auth(&forged)
                .send()
                .expect("me request");
            prop_assert_eq!(
                resp.status().as_u16(),
                401,
                "forged/mutated token must be rejected: {}",
                forged
            );
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Property 5 — authentication and claim correctness
// ---------------------------------------------------------------------------


fn auth_and_claims() {
    let c = client();

    let strategy = any::<[u8; 8]>();
    run_cases("auth_and_claims", cfg(128), strategy, |seed| {
        let password: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        let ok = login(&c, ALICE.0, &password).is_some();
        prop_assert!(!ok, "a random password must never authenticate");

        let s = login(&c, ALICE.0, ALICE.1).expect("seeded password must authenticate");
        prop_assert_eq!(s.tenant, TENANT_A);

        // claims structure: header.payload.signature, payload is JSON
        let parts: Vec<&str> = s.token.split('.').collect();
        prop_assert_eq!(parts.len(), 3, "JWT must have 3 dot-parts");
        let payload: Vec<u8> = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload decodes");
        let claims: Value = serde_json::from_slice(&payload).expect("payload is JSON");
        prop_assert_eq!(claims["sub"].as_str(), Some("1"), "alice is user 1");
        prop_assert_eq!(claims["tenant_id"].as_str(), Some(TENANT_A));
        let iat = claims["iat"].as_i64().expect("iat");
        let exp = claims["exp"].as_i64().expect("exp");
        prop_assert_eq!(exp - iat, TTL_SECS, "TTL must be exactly 24h");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        prop_assert!(exp > now, "issued token must not be expired");
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

fn run_cases<V, F>(name: &str, config: Config, strategy: impl Strategy<Value = V>, f: F)
where
    V: std::fmt::Debug,
    F: Fn(V) -> Result<(), TestCaseError>,
{
    let cases = config.cases;
    let mut runner = TestRunner::new(config);
    match runner.run(&strategy, |v| f(v)) {
        Ok(()) => println!("PASS  {name:<38} {cases} cases"),
        Err(e) => {
            eprintln!("FAIL  {name}");
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    println!("RLS property suite — target {BASE}");
    let c = client();
    let h: Response = c
        .get(format!("{BASE}/health"))
        .send()
        .expect("API not reachable — run ./run.sh and cd api && cargo run");
    assert_eq!(h.status().as_u16(), 200, "API not reachable");

    visible_set_matches_model();
    cross_tenant_isolation_stateful();
    write_check_enforced();
    token_forgery_rejected();
    auth_and_claims();

    println!("\nAll security properties held.");
}
