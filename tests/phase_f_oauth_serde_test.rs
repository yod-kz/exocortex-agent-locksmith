//! Phase F.2 — AuthSpec OAuth variant serde + DB round-trip tests.
//!
//! TS-200..TS-205. Covers ADR-0005 D1 (variant shape) and the
//! `migrations/0003_oauth_sessions.sql` schema.

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{AuthSpec, Kind, Registration, RegistrationRepository};
use sqlx::Row;
use tempfile::TempDir;

// ─── TS-200: AuthSpec::OauthPkce serializes with kind="oauth_pkce" ─────────
#[test]
fn ts200_oauth_pkce_serde_roundtrip() {
    let spec = AuthSpec::OauthPkce {
        client_id: "anthropic-cli-public".to_string(),
        redirect_uri: "http://127.0.0.1:54321/callback".to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        auth_url: "https://console.anthropic.com/oauth/authorize".to_string(),
        token_url: "https://console.anthropic.com/oauth/token".to_string(),
        session_label: None,
    };
    let json = serde_json::to_string(&spec).unwrap();

    // The kind discriminator MUST be `oauth_pkce` (snake_case), per
    // ADR-0005 D1. Operator-facing CLI parses this exact string.
    assert!(
        json.contains("\"kind\":\"oauth_pkce\""),
        "expected kind=oauth_pkce in {json}"
    );
    assert!(json.contains("\"client_id\":\"anthropic-cli-public\""));
    assert!(json.contains("\"redirect_uri\":\"http://127.0.0.1:54321/callback\""));

    let back: AuthSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ─── TS-201: AuthSpec::OauthDeviceCode serializes with kind="oauth_device_code" ─
#[test]
fn ts201_oauth_device_code_serde_roundtrip() {
    let spec = AuthSpec::OauthDeviceCode {
        client_id: "openai-codex-cli".to_string(),
        scopes: vec!["openai-api".to_string()],
        device_url: "https://chatgpt.com/auth/device/code".to_string(),
        token_url: "https://chatgpt.com/auth/device/token".to_string(),
        session_label: None,
    };
    let json = serde_json::to_string(&spec).unwrap();

    assert!(
        json.contains("\"kind\":\"oauth_device_code\""),
        "expected kind=oauth_device_code in {json}"
    );
    assert!(json.contains("\"client_id\":\"openai-codex-cli\""));
    assert!(json.contains("\"device_url\":\"https://chatgpt.com/auth/device/code\""));

    let back: AuthSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ─── TS-202: deny_unknown_fields rejects extra keys ────────────────────────
#[test]
fn ts202_oauth_pkce_rejects_unknown_fields() {
    let bad = r#"{
        "kind": "oauth_pkce",
        "client_id": "x",
        "redirect_uri": "http://localhost",
        "scopes": [],
        "auth_url": "https://x",
        "token_url": "https://y",
        "secret": "should-not-be-here"
    }"#;
    let err = serde_json::from_str::<AuthSpec>(bad).unwrap_err();
    assert!(
        err.to_string().contains("unknown field") || err.to_string().contains("secret"),
        "expected unknown-field error; got: {err}"
    );
}

// ─── TS-203: AuthSpec::is_oauth() correctly identifies OAuth variants ──────
#[test]
fn ts203_is_oauth_predicate() {
    assert!(!AuthSpec::None.is_oauth());
    assert!(
        !AuthSpec::Header {
            header: "x-api-key".into(),
            env_var: "FOO".into(),
            force_replace: false,
        }
        .is_oauth()
    );
    assert!(
        !AuthSpec::Bearer {
            env_var: "FOO".into(),
            force_replace: false,
        }
        .is_oauth()
    );
    assert!(
        AuthSpec::OauthPkce {
            client_id: "x".into(),
            redirect_uri: "http://l".into(),
            scopes: vec![],
            auth_url: "https://a".into(),
            token_url: "https://t".into(),
            session_label: None,
        }
        .is_oauth()
    );
    assert!(
        AuthSpec::OauthDeviceCode {
            client_id: "x".into(),
            scopes: vec![],
            device_url: "https://d".into(),
            token_url: "https://t".into(),
            session_label: None,
        }
        .is_oauth()
    );
}

// ─── TS-204: to_secret_ref() returns None for OAuth variants ───────────────
#[test]
fn ts204_oauth_variants_have_no_secret_ref() {
    let pkce = AuthSpec::OauthPkce {
        client_id: "x".into(),
        redirect_uri: "http://l".into(),
        scopes: vec![],
        auth_url: "https://a".into(),
        token_url: "https://t".into(),
        session_label: None,
    };
    assert!(
        pkce.to_secret_ref().is_none(),
        "OAuth tokens live in oauth_sessions, not resolved_creds"
    );

    let device = AuthSpec::OauthDeviceCode {
        client_id: "x".into(),
        scopes: vec![],
        device_url: "https://d".into(),
        token_url: "https://t".into(),
        session_label: None,
    };
    assert!(device.to_secret_ref().is_none());
}

// ─── TS-205: Registration with OAuth AuthSpec round-trips through repo ─────
#[tokio::test]
async fn ts205_oauth_registration_db_roundtrip() {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let repo = RegistrationRepository::new(pool.clone());

    let spec_pkce = AuthSpec::OauthPkce {
        client_id: "anthropic-cli-public".to_string(),
        redirect_uri: "http://127.0.0.1:54321/callback".to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        auth_url: "https://console.anthropic.com/oauth/authorize".to_string(),
        token_url: "https://console.anthropic.com/oauth/token".to_string(),
        session_label: None,
    };
    let r = Registration::new(
        "anthropic-oauth".to_string(),
        Kind::Model,
        "Anthropic OAuth".to_string(),
        "https://api.anthropic.com".to_string(),
        spec_pkce.clone(),
    );
    repo.create(&r).await.unwrap();

    let back = repo.get("anthropic-oauth").await.unwrap().unwrap();
    assert_eq!(back.auth, spec_pkce);
    assert_eq!(back.kind, Kind::Model);

    // Migration `0003_oauth_sessions.sql` must have applied — the
    // `oauth_sessions` table should exist and be empty (Phase F.4
    // bootstrap CLI populates it).
    let count: i64 = sqlx::query("SELECT COUNT(*) FROM oauth_sessions")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "oauth_sessions table exists and starts empty");

    // The schedule index must exist.
    let idx_count: i64 = sqlx::query(
        "SELECT COUNT(*) FROM sqlite_master \
         WHERE type='index' AND name='idx_oauth_sessions_refresh_schedule'",
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .get(0);
    assert_eq!(idx_count, 1, "refresh-schedule index exists");
}
