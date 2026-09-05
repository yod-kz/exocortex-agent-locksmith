//! Phase E.3 — public discovery `/tools` and `/models`.
//!
//! TS-130..TS-134. Replaces the M9-era homogeneous /tools handler with a
//! kind-discriminated split that reads from the registrations table when
//! wired and falls back to `config.tools` for M0/M1 / M9 test paths.

use agent_locksmith::app::build_app_full_with_registrations;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{AuthSpec, Kind, Registration, RegistrationRepository};
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
"#;

struct Harness {
    server: TestServer,
    bearer_header: String,
}

/// Set up an agent listener with the registrations repo wired and a
/// pre-registered agent. The agent's allowlist is `tool_allowlist`. Seed
/// rows are inserted directly via the repo (Phase E.7's loader will
/// replace this dance once it lands).
async fn setup_with_seed(
    tool_allowlist: Option<Vec<String>>,
    seed: Vec<Registration>,
) -> (TempDir, Harness) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool));

    // Seed registrations for the test.
    for r in &seed {
        registrations.create(r).await.unwrap();
    }

    // Register the test agent.
    let allow_ref = tool_allowlist.as_deref();
    let (pid, secret) = agents
        .create("disc-test", None, allow_ref, None, None, None)
        .await
        .unwrap();

    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());

    let cfg = parse_config_str(YAML).unwrap();
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

    (
        dir,
        Harness {
            server,
            bearer_header,
        },
    )
}

fn tool(name: &str) -> Registration {
    Registration::new(
        name.to_string(),
        Kind::Tool,
        format!("{name} description"),
        format!("https://example.com/{name}"),
        AuthSpec::None,
    )
}

fn model(name: &str) -> Registration {
    Registration::new(
        name.to_string(),
        Kind::Model,
        format!("{name} description"),
        format!("https://example.com/{name}"),
        AuthSpec::Bearer {
            env_var: format!("{}_API_KEY", name.to_uppercase()),
            force_replace: false,
        },
    )
}

fn infra(name: &str) -> Registration {
    Registration::new(
        name.to_string(),
        Kind::Infra,
        format!("{name} description"),
        format!("http://{name}:8080"),
        AuthSpec::Header {
            header: "X-Internal-Token".to_string(),
            env_var: format!("{}_INTERNAL_TOKEN", name.to_uppercase()),
            force_replace: false,
        },
    )
}

// ─── TS-130: GET /tools returns kind=tool only ──────────────────────────────
#[tokio::test]
async fn ts130_tools_returns_only_kind_tool() {
    let (_dir, h) = setup_with_seed(
        None,
        vec![
            tool("github"),
            tool("tavily"),
            model("anthropic"),
            model("openai"),
            infra("lf-scan"),
        ],
    )
    .await;

    let resp = h
        .server
        .get("/tools")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let tools = body["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["github", "tavily"]);
}

// ─── TS-131: GET /tools filtered by agent ACL ───────────────────────────────
#[tokio::test]
async fn ts131_tools_filtered_by_acl() {
    let (_dir, h) = setup_with_seed(
        Some(vec!["github".to_string()]),
        vec![tool("github"), tool("tavily"), tool("duckduckgo")],
    )
    .await;

    let resp = h
        .server
        .get("/tools")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let tools = body["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "github");
}

// ─── TS-132: GET /models returns kind=model only ────────────────────────────
#[tokio::test]
async fn ts132_models_returns_only_kind_model() {
    let (_dir, h) = setup_with_seed(
        None,
        vec![
            tool("github"),
            model("anthropic"),
            model("openai"),
            infra("lf-scan"),
        ],
    )
    .await;

    let resp = h
        .server
        .get("/models")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let models = body["models"].as_array().unwrap();
    let names: Vec<&str> = models.iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["anthropic", "openai"]);
}

// ─── TS-133: GET /models filtered by agent ACL ──────────────────────────────
#[tokio::test]
async fn ts133_models_filtered_by_acl() {
    let (_dir, h) = setup_with_seed(
        Some(vec!["openai".to_string()]),
        vec![model("anthropic"), model("openai"), model("openrouter")],
    )
    .await;

    let resp = h
        .server
        .get("/models")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let models = body["models"].as_array().unwrap();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0]["name"], "openai");
}

// ─── TS-134: kind=infra has NO agent-facing endpoint ───────────────────────
#[tokio::test]
async fn ts134_infra_not_in_tools_or_models() {
    let (_dir, h) = setup_with_seed(
        None,
        vec![
            tool("foo"),
            model("bar"),
            infra("lf-scan"),
            infra("scanner-x"),
        ],
    )
    .await;

    let tools_resp = h
        .server
        .get("/tools")
        .add_header("authorization", &h.bearer_header)
        .await;
    let tools_body: serde_json::Value = tools_resp.json();
    let tools = tools_body["tools"].as_array().unwrap();
    let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(!tool_names.contains(&"lf-scan"));
    assert!(!tool_names.contains(&"scanner-x"));

    let models_resp = h
        .server
        .get("/models")
        .add_header("authorization", &h.bearer_header)
        .await;
    let models_body: serde_json::Value = models_resp.json();
    let models = models_body["models"].as_array().unwrap();
    let model_names: Vec<&str> = models.iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert!(!model_names.contains(&"lf-scan"));

    // Sanity: there's no public `GET /infra` endpoint at all.
    let infra_resp = h
        .server
        .get("/infra")
        .add_header("authorization", &h.bearer_header)
        .await;
    infra_resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// ─── TS-134b: disabled rows hidden from public discovery ────────────────────
#[tokio::test]
async fn ts134b_disabled_hidden_from_discovery() {
    let mut t = tool("github");
    t.disabled = true;
    let (_dir, h) = setup_with_seed(None, vec![t, tool("tavily")]).await;

    let resp = h
        .server
        .get("/tools")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let tools = body["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["tavily"]);
    assert!(!names.contains(&"github"));
}
