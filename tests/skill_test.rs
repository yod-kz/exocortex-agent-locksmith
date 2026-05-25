//! M9 / B1 follow-up — agent skill endpoints (`/skill` unauthenticated,
//! `/agent/skill` authenticated).

use agent_locksmith::app::build_app_full;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::secret::resolve_tool_creds_sync_env_only;
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tempfile::TempDir;

const YAML: &str = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "things"
    description: "Things service for tests"
    upstream: "http://example.invalid"
    timeouts: { request_seconds: 5, idle_seconds: 5 }
  - name: "secret-tool"
    description: "Tool the test agent shouldn't see"
    upstream: "http://example.invalid"
    timeouts: { request_seconds: 5, idle_seconds: 5 }
"#;

async fn server_with_agent(
    allowlist: Option<Vec<String>>,
) -> (TempDir, TestServer, String /* bearer header value */) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool);
    let allow_ref = allowlist.as_deref();
    let (pid, secret) = agents
        .create("skill-test-agent", None, allow_ref, None, None, None)
        .await
        .unwrap();
    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());
    let cfg = parse_config_str(YAML).unwrap();
    let resolved = resolve_tool_creds_sync_env_only(&cfg);
    let shared = Arc::new(ArcSwap::from_pointee(cfg));
    let app = build_app_full(
        shared,
        Some(audit),
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(bearer),
    );
    let server = TestServer::new(app);
    let header = format!("Bearer lk_{pid}.{}", secret.expose_secret());
    (dir, server, header)
}

// /skill (unauthenticated) returns the generic markdown with no
// tool/model leak, advertises the personalized form, and uses
// public/cacheable Cache-Control.
#[tokio::test]
async fn unauthenticated_skill_returns_generic_markdown() {
    let (_dir, server, _bearer) = server_with_agent(Some(vec!["things".into()])).await;
    let resp = server.get("/skill").await;
    resp.assert_status_ok();

    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "text/markdown; charset=utf-8");

    let cache = resp
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cache.contains("public") && cache.contains("max-age"),
        "unauth /skill must be cacheable; got Cache-Control={cache}"
    );

    let body = resp.text();
    assert!(
        body.starts_with("---\n"),
        "agentskills.io frontmatter present"
    );
    assert!(body.contains("name: locksmith"));
    // Must NOT leak tool names from the active deployment.
    assert!(
        !body.contains("things"),
        "unauth /skill must not include tool names"
    );
    assert!(
        !body.contains("secret-tool"),
        "unauth /skill must not include tool names"
    );
    // Must advertise the personalized form so callers know to upgrade.
    assert!(
        body.contains("personalized"),
        "unauth form must advertise the personalized form"
    );
    assert!(
        body.contains("Authorization: Bearer"),
        "unauth form must show how to authenticate"
    );
}

// /skill with a valid bearer returns the personalized form (single
// auth-optional route — was previously /agent/skill, collapsed in the
// M9 follow-up so the documented "GET /skill with your bearer" recipe
// actually works).
#[tokio::test]
async fn skill_with_valid_bearer_returns_personalized_markdown() {
    let (_dir, server, bearer) = server_with_agent(Some(vec!["things".into()])).await;
    let resp = server
        .get("/skill")
        .add_header("Authorization", bearer)
        .await;
    resp.assert_status_ok();

    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "text/markdown; charset=utf-8");

    let cache = resp
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cache.contains("private") && cache.contains("no-cache"),
        "personalized /skill must NOT be cacheable; got Cache-Control={cache}"
    );

    let body = resp.text();
    // Generic template at the top.
    assert!(body.contains("name: locksmith"));
    // Personalized section with the agent's name.
    assert!(body.contains("skill-test-agent"));
    assert!(body.contains("Personalized for"));
    // Allowed tool appears with description.
    assert!(body.contains("`things`"));
    assert!(body.contains("Things service for tests"));
    // Tool the agent ISN'T allowed to see must NOT appear.
    assert!(
        !body.contains("secret-tool"),
        "personalized form must filter by ACL; got body containing secret-tool"
    );
    // Audit-debug recipe scoped to this agent.
    assert!(body.contains("locksmith audit query"));
}

// /skill with a malformed/invalid bearer → 401. We don't silently
// downgrade to the generic form: that would let an attacker probe
// valid token formats by checking content variation.
#[tokio::test]
async fn skill_with_invalid_bearer_returns_401() {
    let (_dir, server, _bearer) = server_with_agent(Some(vec!["things".into()])).await;
    let resp = server
        .get("/skill")
        .add_header("Authorization", "Bearer not_a_valid_token")
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    // §4.7.9 envelope (consistent with /api/... and /tools).
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["type"], "auth_error");
    assert_eq!(body["error"]["code"], "invalid_credential");
}

// Sanity: /agent/skill is gone (the route was collapsed into auth-
// optional /skill). Should 404, not silently fall through.
#[tokio::test]
async fn legacy_agent_skill_route_is_removed() {
    let (_dir, server, bearer) = server_with_agent(Some(vec!["things".into()])).await;
    let resp = server
        .get("/agent/skill")
        .add_header("Authorization", bearer)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// WEM-334 regression — personalized /skill must list tools sourced
// from the registrations table (catalog), not the legacy config.tools
// block. Pre-fix, every Phase-E+ deployment (the documented v2 default)
// rendered "_No tools currently available to you._" because
// render_authenticated walked the always-empty config.tools intersection.
//
// The fixture below mirrors phase_e_discovery_test::setup_with_seed:
// wires a populated RegistrationRepository through
// build_app_full_with_registrations and leaves config.tools empty,
// matching the production catalog deployment shape.
#[tokio::test]
async fn skill_personalized_lists_catalog_tools_not_config_tools() {
    use agent_locksmith::app::build_app_full_with_registrations;
    use agent_locksmith::registrations::{AuthSpec, Kind, Registration, RegistrationRepository};

    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool));

    // Catalog: two tools. Agent's allowlist will permit one and exclude
    // the other so the test also verifies catalog_listing's ACL filter
    // flows through render_authenticated unchanged.
    for r in [
        Registration::new(
            "wikipedia".into(),
            Kind::Tool,
            "Wikipedia REST API v1 (authless)".into(),
            "https://en.wikipedia.org".into(),
            AuthSpec::None,
        ),
        Registration::new(
            "secret-tool".into(),
            Kind::Tool,
            "Tool the test agent shouldn't see".into(),
            "https://example.invalid".into(),
            AuthSpec::None,
        ),
    ] {
        registrations.create(&r).await.unwrap();
    }

    // Agent allowlists wikipedia; deliberately omits secret-tool.
    let allow = vec!["wikipedia".to_string()];
    let (pid, secret) = agents
        .create("catalog-test-agent", None, Some(&allow), None, None, None)
        .await
        .unwrap();

    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());

    // YAML deliberately leaves `tools:` empty — the production catalog
    // shape. Pre-fix this would have produced an empty effective list
    // and the "_No tools_" explainer.
    let cfg = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
"#,
    )
    .unwrap();
    let resolved = resolve_tool_creds_sync_env_only(&cfg);
    let shared = Arc::new(ArcSwap::from_pointee(cfg));
    let app = build_app_full_with_registrations(
        shared,
        Some(audit),
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(bearer),
        Some(registrations),
    );
    let server = TestServer::new(app);
    let bearer_header = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let resp = server
        .get("/skill")
        .add_header("Authorization", bearer_header)
        .await;
    resp.assert_status_ok();

    let body = resp.text();
    // Catalog tool the agent IS allowlisted for must appear with its
    // description.
    assert!(
        body.contains("`wikipedia`"),
        "personalized /skill must render the catalog tool the agent is allowed to call; \
         got body without `wikipedia`"
    );
    assert!(
        body.contains("Wikipedia REST API v1"),
        "personalized /skill must render the catalog tool's description"
    );
    // Catalog tool NOT in the agent's allowlist must be filtered out
    // (catalog_listing applies AgentIdentity::allows_tool before
    // returning).
    assert!(
        !body.contains("secret-tool"),
        "personalized /skill must filter catalog by ACL; got body containing secret-tool"
    );
    // The empty-list explainer must NOT fire — the regression we're
    // guarding against. Pre-WEM-334-fix this assertion would have
    // failed because the renderer's tool list came from the always-
    // empty config.tools intersection.
    assert!(
        !body.contains("No tools currently available to you"),
        "personalized /skill must source tools from the catalog (regressions to \
         config.tools-only sourcing reproduce the WEM-334 bug); got body containing \
         the empty-list explainer despite a populated catalog"
    );
}
