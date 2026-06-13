//! Phase G3 — codex Responses API body fixup integration tests.
//!
//! End-to-end coverage: agent POSTs a request through locksmith with
//! a generic OpenAI-responses body shape; locksmith inspects + fixes
//! up the body for codex's strict requirements; mock upstream
//! receives the corrected body. The wiremock matcher asserts the
//! exact body shape — if locksmith doesn't fix up, mock returns 404
//! and the test fails.
//!
//! Audit assertions verify `details.codex_body_fixup` presence/absence
//! per scenario.
//!
//! Mirrors the harness pattern from `tests/phase_f_oauth_proxy_test.rs`
//! G2 tests.

use agent_locksmith::app::{OauthRuntime, build_app_full_with_oauth};
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::oauth::refresh::RefreshLockMap;
use agent_locksmith::oauth::sealing::SealingKey;
use agent_locksmith::oauth::session::OauthSessionRepository;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Harness {
    _dir: TempDir,
    server: TestServer,
    bearer_header: String,
    audit: AuditRepository,
    mock: MockServer,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Build a fake JWT carrying `chatgpt_account_id` so the OAuth session
/// row carries an account_id (G2 still injects the header alongside
/// G3's body fixup; both are codex-pattern hooks). Same shape as the
/// G2 tests in phase_f_oauth_proxy_test.rs.
fn jwt_with_account_id(account_id: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
            },
        })
        .to_string()
        .as_bytes(),
    );
    let sig = URL_SAFE_NO_PAD.encode(b"sig");
    format!("{header}.{payload}.{sig}")
}

/// Spin up a Harness with two registrations:
/// - `codex` — codex-shaped upstream (`<mock>/backend-api/codex`),
///   OAuth, has an active session.
/// - `noncodex` — plain OAuth registration with a non-codex upstream
///   path (`<mock>/v1`), used for the "skip when not codex" scenario.
async fn setup() -> Harness {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let sessions = OauthSessionRepository::new(pool.clone());
    let sealing_key = SealingKey::generate().unwrap();

    let mock = MockServer::start().await;
    let token_url = format!("{}/token", mock.uri());

    // codex-shaped registration (matches is_chatgpt_codex_upstream).
    let codex_reg = Registration::new(
        "codex".to_string(),
        Kind::Model,
        "G3 codex test".to_string(),
        format!("{}/backend-api/codex", mock.uri()),
        AuthSpec::OauthDeviceCode {
            client_id: "test-client".to_string(),
            scopes: vec!["openai-api".to_string()],
            device_url: format!("{}/device", mock.uri()),
            token_url: token_url.clone(),
            session_label: None,
        },
    );
    registrations.create(&codex_reg).await.unwrap();

    // Non-codex OAuth registration. Same auth shape, different path —
    // used to verify body fixup is gated by is_chatgpt_codex_upstream.
    let noncodex_reg = Registration::new(
        "noncodex".to_string(),
        Kind::Model,
        "G3 non-codex control".to_string(),
        format!("{}/v1", mock.uri()),
        AuthSpec::OauthDeviceCode {
            client_id: "test-client".to_string(),
            scopes: vec!["openai-api".to_string()],
            device_url: format!("{}/device", mock.uri()),
            token_url,
            session_label: None,
        },
    );
    registrations.create(&noncodex_reg).await.unwrap();

    // Pre-populate sessions for both registrations so OAuth resolution
    // succeeds in the proxy hot path.
    let access_token = jwt_with_account_id("acct_g3_test");
    sessions
        .create(
            &sealing_key,
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            "rt-codex",
            Some(&access_token),
            Some(unix_now() + 3600),
            "",
        )
        .await
        .unwrap();
    sessions
        .create(
            &sealing_key,
            "noncodex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            "rt-noncodex",
            Some(&access_token),
            Some(unix_now() + 3600),
            "",
        )
        .await
        .unwrap();

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));

    let (pid, secret) = agents
        .create(
            "g3-test",
            None,
            Some(&["codex".to_string(), "noncodex".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());
    let bearer_header = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    let runtime = OauthRuntime {
        sessions,
        sealing_key,
        locks: RefreshLockMap::new(),
        refresh_client: reqwest::Client::new(),
    };

    let app = build_app_full_with_oauth(
        cfg_arc,
        Some(audit.clone()),
        Arc::new(ArcSwap::from_pointee(Default::default())),
        None,
        Some(bearer),
        Some(registrations),
        catalog_arc,
        Some(runtime),
    );
    let server = TestServer::new(app);

    Harness {
        _dir: dir,
        server,
        bearer_header,
        audit,
        mock,
    }
}

/// Read the most recent `proxy_request` audit row's `details` JSON.
async fn latest_proxy_request_details(audit: &AuditRepository) -> Value {
    let rows = audit
        .query(
            &AuditFilter::default(),
            AuditPage {
                limit: 5,
                offset: 0,
            },
        )
        .await
        .expect("audit query");
    let row = rows
        .into_iter()
        .find(|r| r.event == "proxy_request")
        .expect("at least one proxy_request audit row");
    row.details.unwrap_or(Value::Null)
}

#[tokio::test]
async fn g3_proxy_injects_required_fields_when_missing() {
    let h = setup().await;

    // Mock upstream demands the post-fixup body shape: store=false,
    // stream=true, instructions present. Agent will only send model+input.
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(body_partial_json(json!({
            "store": false,
            "stream": true,
            "instructions": "You are a helpful assistant.",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({
            "model": "gpt-5.5",
            "input": [{"type": "message", "role": "user", "content": "hi"}],
        }))
        .await;
    resp.assert_status_ok();

    let details = latest_proxy_request_details(&h.audit).await;
    let fixup = details
        .get("codex_body_fixup")
        .expect("codex_body_fixup present");
    let added: Vec<&str> = fixup["fields_added"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(added.contains(&"store"), "store added");
    assert!(added.contains(&"stream"), "stream added");
    assert!(added.contains(&"instructions"), "instructions added");
}

#[tokio::test]
async fn g3_proxy_overrides_store_and_stream_user_values() {
    let h = setup().await;

    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(body_partial_json(json!({
            "store": false,
            "stream": true,
            "instructions": "be terse",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({
            "model": "gpt-5.5",
            "input": [{"type": "message", "role": "user", "content": "hi"}],
            "instructions": "be terse",
            "store": true,
            "stream": false,
        }))
        .await;
    resp.assert_status_ok();

    let details = latest_proxy_request_details(&h.audit).await;
    let fixup = &details["codex_body_fixup"];
    let overridden: Vec<&str> = fixup["fields_overridden"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        overridden.contains(&"store"),
        "store overridden, got {overridden:?}"
    );
    assert!(
        overridden.contains(&"stream"),
        "stream overridden, got {overridden:?}"
    );
    // instructions was set by user; should NOT appear in either list.
    let added: Vec<&str> = fixup["fields_added"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        !added.contains(&"instructions"),
        "user instructions preserved (not added)"
    );
    assert!(
        !overridden.contains(&"instructions"),
        "user instructions preserved (not overridden)"
    );
}

#[tokio::test]
async fn g3_proxy_preserves_user_instructions_verbatim() {
    let h = setup().await;
    let user_instructions = "You answer in haiku only.";

    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(body_partial_json(json!({
            "instructions": user_instructions,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({
            "model": "gpt-5.5",
            "input": [{"type": "message", "role": "user", "content": "hi"}],
            "instructions": user_instructions,
            // store + stream missing — fixup adds them.
        }))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn g3_proxy_skips_munge_when_path_not_responses() {
    let h = setup().await;

    // Agent posts to a non-/responses codex path (sessions, etc.).
    // Mock matcher requires the body to come through UNCHANGED — no
    // store/stream/instructions injection.
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/sessions"))
        // The body must NOT contain the fixup defaults. body_partial_json
        // matches when the listed fields are present with these values;
        // we use a marker the agent sets to confirm the body arrived.
        .and(body_partial_json(json!({"marker": "raw"})))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/sessions")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({"marker": "raw"}))
        .await;
    resp.assert_status_ok();

    let details = latest_proxy_request_details(&h.audit).await;
    assert!(
        details.get("codex_body_fixup").is_none(),
        "non-/responses path: no fixup field on audit, got {details:?}"
    );
}

#[tokio::test]
async fn g3_proxy_skips_munge_when_upstream_is_not_codex() {
    let h = setup().await;

    // noncodex registration, /responses path. Even though the path
    // suffix matches, the upstream URL doesn't match the codex pattern,
    // so fixup is gated off.
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(body_partial_json(json!({"marker": "raw"})))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/noncodex/responses")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({"marker": "raw"}))
        .await;
    resp.assert_status_ok();

    let details = latest_proxy_request_details(&h.audit).await;
    assert!(
        details.get("codex_body_fixup").is_none(),
        "non-codex upstream: no fixup field on audit, got {details:?}"
    );
}

// Phase G5 — codex /responses returns 400 with body
// `{"detail":"Unsupported parameter: max_output_tokens"}` when the param
// is set. OpenAI SDK clients (openclaw's openai-transport-stream,
// hermes-agent's embedded OpenAI/JS) emit it from per-model maxTokens
// config without knowing the codex-specific rejection. Locksmith strips
// it on the way out so agents stay generic.
#[tokio::test]
async fn g5_proxy_strips_max_output_tokens_for_codex() {
    let h = setup().await;

    // Mock matches the post-fixup body shape (G3 fields present);
    // wire-side absence of max_output_tokens is verified via the
    // captured request body assertion below. body_partial_json
    // would silently pass with extra fields, so the strip itself is
    // verified through the audit row's fields_removed entry.
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(body_partial_json(json!({
            "store": false,
            "stream": true,
            "instructions": "You are a helpful assistant.",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({
            "model": "gpt-5.5",
            "input": [{"type": "message", "role": "user", "content": "hi"}],
            "max_output_tokens": 16384,
        }))
        .await;
    resp.assert_status_ok();

    let details = latest_proxy_request_details(&h.audit).await;
    let fixup = details
        .get("codex_body_fixup")
        .expect("codex_body_fixup present (G5 strip happened)");
    let removed: Vec<&str> = fixup["fields_removed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        removed.contains(&"max_output_tokens"),
        "audit must report max_output_tokens removed; got fixup={fixup:?}"
    );

    // Belt + suspenders: pull the actual request bytes wiremock
    // captured and confirm max_output_tokens isn't in there.
    let received = h.mock.received_requests().await.expect("mock recorded");
    let last = received.last().expect("at least one request");
    let body_str = std::str::from_utf8(&last.body).expect("utf8");
    assert!(
        !body_str.contains("max_output_tokens"),
        "forwarded body must not contain max_output_tokens; got: {body_str}"
    );
}
