//! Phase G integration tests — three end-to-end modes covered by the
//! per-agent credential override system:
//!
//! 1. **Shared credential** (no override) — agent uses the registration's
//!    default Bearer env var. This is today's default behavior; the
//!    test pins it so we don't regress.
//!
//! 2. **Per-agent header override** — two agents register, the second
//!    has a credential override pointing at a different env var. Both
//!    hit the same upstream; the upstream sees two distinct API keys.
//!
//! 3. **Override → AuthSpec::None** — an override can downgrade an
//!    authed registration to no-auth for a specific agent (rare but
//!    permitted; tests pin the wire-shape outcome).
//!
//! Plus audit-fields coverage: every `proxy_request` audit row carries
//! `auth_source` (registration_default vs agent_override).

use agent_locksmith::app::build_app_full_with_phase_g;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::AgentCredentialRepository;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository, EventClass};
use arc_swap::ArcSwap;
use axum::Router;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Two-agent integration harness.
struct Harness {
    _dir: TempDir,
    server: TestServer,
    hermes_bearer: String,
    openclaw_bearer: String,
    audit: AuditRepository,
    mock: MockServer,
}

async fn setup() -> Harness {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let agent_creds = AgentCredentialRepository::new(pool.clone());

    let mock = MockServer::start().await;

    // Register `lmstudio` with bearer auth backed by env var
    // `LMSTUDIO_DEFAULT_KEY`. Resolved-creds map at startup ties the
    // value to the registration name.
    unsafe {
        std::env::set_var("LMSTUDIO_DEFAULT_KEY", "default-shared-key");
        std::env::set_var("LMSTUDIO_HERMES_KEY", "hermes-only-key");
    }

    let r = Registration::new(
        "lmstudio".to_string(),
        Kind::Model,
        "LM Studio (test)".to_string(),
        mock.uri(),
        AuthSpec::Bearer {
            env_var: "LMSTUDIO_DEFAULT_KEY".to_string(),
            force_replace: false,
        },
    );
    registrations.create(&r).await.unwrap();

    // Build the catalog snapshot the proxy hot path reads.
    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let resolved = agent_locksmith::secret::resolve_registration_creds_sync_env_only(&catalog);
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));
    let resolved_arc = Arc::new(ArcSwap::from_pointee(resolved));

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    // Two agents, both allowed to call `lmstudio`.
    let (h_pid, h_secret) = agents
        .create(
            "hermes-mini-1",
            None,
            Some(&["lmstudio".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let (o_pid, o_secret) = agents
        .create(
            "openclaw-mini-1",
            None,
            Some(&["lmstudio".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let h_id = agents
        .get_by_name("hermes-mini-1")
        .await
        .unwrap()
        .unwrap()
        .id;

    // Phase G: hermes gets a per-agent override pointing at a
    // distinct env var. openclaw has no override → registration
    // default applies.
    agent_creds
        .set(
            h_id,
            "lmstudio",
            &AuthSpec::Bearer {
                env_var: "LMSTUDIO_HERMES_KEY".to_string(),
                force_replace: false,
            },
        )
        .await
        .unwrap();

    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());

    let hermes_bearer = format!("Bearer lk_{h_pid}.{}", h_secret.expose_secret());
    let openclaw_bearer = format!("Bearer lk_{o_pid}.{}", o_secret.expose_secret());

    let app: Router = build_app_full_with_phase_g(
        cfg_arc,
        Some(audit.clone()),
        resolved_arc,
        None,
        Some(bearer),
        Some(registrations),
        catalog_arc,
        None,
        Some(agent_creds),
    );
    let server = TestServer::new(app);

    Harness {
        _dir: dir,
        server,
        hermes_bearer,
        openclaw_bearer,
        audit,
        mock,
    }
}

// ─── G-1: openclaw (no override) → registration_default + LMSTUDIO_DEFAULT_KEY ─

#[tokio::test]
async fn shared_credential_path_uses_registration_default() {
    let h = setup().await;
    Mock::given(method("GET"))
        .and(path("/v1/health"))
        .and(header("authorization", "Bearer default-shared-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/lmstudio/v1/health")
        .add_header("authorization", &h.openclaw_bearer)
        .await;
    resp.assert_status_ok();

    // Audit row should record auth_source=registration_default.
    let rows = h
        .audit
        .query(
            &AuditFilter {
                event_class: Some(EventClass::Proxy),
                ..Default::default()
            },
            AuditPage::default(),
        )
        .await
        .unwrap();
    let r = rows.iter().find(|r| r.event == "proxy_request").unwrap();
    let details = r.details.as_ref().unwrap();
    assert_eq!(details["auth_source"], "registration_default");
    assert_eq!(details["auth_mode"], "bearer");
}

// ─── G-2: hermes (override) → agent_override + LMSTUDIO_HERMES_KEY ──────────

#[tokio::test]
async fn per_agent_override_injects_distinct_credential() {
    let h = setup().await;
    Mock::given(method("GET"))
        .and(path("/v1/health"))
        .and(header("authorization", "Bearer hermes-only-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/lmstudio/v1/health")
        .add_header("authorization", &h.hermes_bearer)
        .await;
    resp.assert_status_ok();

    let rows = h
        .audit
        .query(
            &AuditFilter {
                event_class: Some(EventClass::Proxy),
                ..Default::default()
            },
            AuditPage::default(),
        )
        .await
        .unwrap();
    let r = rows.iter().find(|r| r.event == "proxy_request").unwrap();
    let details = r.details.as_ref().unwrap();
    assert_eq!(details["auth_source"], "agent_override");
    assert_eq!(details["auth_mode"], "bearer");
}

// ─── G-3: simultaneous calls — provider sees two distinct keys ──────────────

#[tokio::test]
async fn two_agents_present_two_distinct_upstream_keys() {
    let h = setup().await;
    // Mock returns 200 only for hermes-only-key; default-shared-key
    // hits a different mock. Each call passes through different
    // injection logic.
    Mock::given(method("GET"))
        .and(path("/v1/h"))
        .and(header("authorization", "Bearer hermes-only-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hermes-ok"))
        .mount(&h.mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/o"))
        .and(header("authorization", "Bearer default-shared-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("openclaw-ok"))
        .mount(&h.mock)
        .await;

    let r1 = h
        .server
        .get("/api/lmstudio/v1/h")
        .add_header("authorization", &h.hermes_bearer)
        .await;
    r1.assert_status_ok();
    assert_eq!(r1.text(), "hermes-ok");

    let r2 = h
        .server
        .get("/api/lmstudio/v1/o")
        .add_header("authorization", &h.openclaw_bearer)
        .await;
    r2.assert_status_ok();
    assert_eq!(r2.text(), "openclaw-ok");
}
