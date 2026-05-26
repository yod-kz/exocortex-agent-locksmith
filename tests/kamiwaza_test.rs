use agent_locksmith::app::{build_app, build_app_full};
use agent_locksmith::auth_v2::{AgentAuthenticator, AgentIdentity, AuthError};
use agent_locksmith::config::AppConfig;
use agent_locksmith::secret::resolve_tool_creds_sync_env_only;
use arc_swap::ArcSwap;
use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

async fn mount_mcp_handshake(mock: &MockServer, mcp_path: &str, tool_description: &str) {
    mount_mcp_handshake_inner(mock, mcp_path, tool_description, None).await;
}

async fn mount_mcp_handshake_with_delegation(
    mock: &MockServer,
    mcp_path: &str,
    tool_description: &str,
    expected_sub: &str,
    signing_secret: &str,
) {
    mount_mcp_handshake_inner(
        mock,
        mcp_path,
        tool_description,
        Some((expected_sub.to_string(), signing_secret.to_string())),
    )
    .await;
}

async fn mount_mcp_handshake_inner(
    mock: &MockServer,
    mcp_path: &str,
    tool_description: &str,
    expected_delegation: Option<(String, String)>,
) {
    let tool_description = tool_description.to_string();
    Mock::given(method("POST"))
        .and(path(mcp_path))
        .and(header("authorization", "Bearer kamiwaza-token"))
        .respond_with(move |request: &Request| {
            let payload: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or_else(|_| serde_json::json!({}));
            match payload.get("method").and_then(|value| value.as_str()) {
                Some("initialize") => ResponseTemplate::new(200)
                    .insert_header("mcp-session-id", "test-session")
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {"tools": {"listChanged": false}},
                            "serverInfo": {"name": "tool-z", "version": "1.0.0"}
                        }
                    })),
                Some("notifications/initialized") => {
                    ResponseTemplate::new(202).set_body_json(serde_json::json!({}))
                }
                Some("tools/list") => ResponseTemplate::new(200)
                    .insert_header("mcp-session-id", "test-session")
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "result": {
                            "tools": [{
                                "name": "search",
                                "description": tool_description,
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "query": {"type": "string"},
                                        "gl": {"type": "string"}
                                    },
                                    "required": ["query"]
                                }
                            }]
                        }
                    })),
                Some("tools/call") => {
                    if let Some((expected_sub, signing_secret)) = expected_delegation.as_ref() {
                        let claims = match delegation_claims(request, signing_secret) {
                            Ok(claims) => claims,
                            Err(message) => {
                                return ResponseTemplate::new(400)
                                    .set_body_json(serde_json::json!({"error": message}));
                            }
                        };
                        if claims["sub"] != expected_sub.as_str()
                            || claims["agent_name"] != "research-agent"
                            || claims["scope"] != "kamiwaza.tool.invoke"
                            || claims["tool"] != "kamiwaza_tool_z_19607be6_search"
                            || claims["extension"] != "tool-z-19607be6"
                            || claims["mcp_tool"] != "search"
                        {
                            return ResponseTemplate::new(400).set_body_json(
                                serde_json::json!({"error": "unexpected delegation claims", "claims": claims}),
                            );
                        }
                    }
                    let query = payload
                        .pointer("/params/arguments/query")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default();
                    if query != "latest openclaw news" {
                        return ResponseTemplate::new(400)
                            .set_body_json(serde_json::json!({"error": "unexpected query"}));
                    }
                    ResponseTemplate::new(200)
                        .insert_header("mcp-session-id", "test-session")
                        .set_body_json(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 3,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": "{\"organic\":[{\"title\":\"OpenClaw news\"}]}"
                                }]
                            }
                        }))
                }
                _ => ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "unexpected MCP method"})),
            }
        })
        .mount(mock)
        .await;
}

fn delegation_claims(request: &Request, signing_secret: &str) -> Result<serde_json::Value, String> {
    let value = request
        .headers
        .get("x-kamiwaza-agent-delegation")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "missing delegation header".to_string())?;
    let jwt = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| "delegation header is not a bearer JWT".to_string())?;
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("delegation JWT must have three segments".to_string());
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(signing_secret.as_bytes())
        .map_err(|e| e.to_string())?;
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|error| error.to_string())?;
    mac.verify_slice(&signature)
        .map_err(|_| "delegation JWT signature mismatch".to_string())?;
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&payload).map_err(|error| error.to_string())
}

fn build_config(mock: &MockServer) -> AppConfig {
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
kamiwaza:
  enabled: true
  api_url: "{api_url}"
  api_token: "kamiwaza-token"
  verify_tls: true
  timeout_seconds: 5
tools: []
"#,
        api_url = mock.uri()
    );
    serde_yaml::from_str(&yaml).unwrap()
}

fn build_config_with_delegation(mock: &MockServer) -> AppConfig {
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
kamiwaza:
  enabled: true
  api_url: "{api_url}"
  api_token: "kamiwaza-token"
  verify_tls: true
  timeout_seconds: 5
  delegation:
    enabled: true
    required: true
    signing_secret: "delegation-secret"
tools: []
"#,
        api_url = mock.uri()
    );
    serde_yaml::from_str(&yaml).unwrap()
}

struct StaticAgentAuthenticator;

#[async_trait::async_trait]
impl AgentAuthenticator for StaticAgentAuthenticator {
    async fn authenticate_bearer(&self, header: &str) -> Result<AgentIdentity, AuthError> {
        if header != "Bearer agent-token" {
            return Err(AuthError::InvalidCredential);
        }
        Ok(AgentIdentity {
            id: 42,
            public_id: "agent-public-id".to_string(),
            name: "research-agent".to_string(),
            tool_allowlist: None,
            tool_denylist: None,
        })
    }
}

fn build_delegation_server(config: AppConfig) -> TestServer {
    let resolved = resolve_tool_creds_sync_env_only(&config);
    let shared = std::sync::Arc::new(ArcSwap::from_pointee(config));
    let auth: std::sync::Arc<dyn AgentAuthenticator> =
        std::sync::Arc::new(StaticAgentAuthenticator);
    let app = build_app_full(
        shared,
        None,
        std::sync::Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(auth),
    );
    TestServer::new(app)
}

async fn mount_extensions(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/extensions"))
        .and(header("authorization", "Bearer kamiwaza-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "name": "tool-z-19607be6",
                "type": "tool",
                "version": "1.0.0",
                "phase": "Running",
                "services": [{"name": "primary", "ready": true, "available_replicas": 1}],
                "endpoints": {"external": format!("{}/runtime/tools/tool-z-19607be6", mock.uri())}
            },
            {
                "name": "stopped-tool",
                "type": "tool",
                "version": "1.0.0",
                "phase": "Failed",
                "services": [{"name": "primary", "ready": true, "available_replicas": 1}],
                "endpoints": {"external": format!("{}/runtime/tools/stopped-tool", mock.uri())}
            }
        ])))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn test_kamiwaza_tools_are_discovered_without_exposing_token() {
    let mock = MockServer::start().await;
    mount_extensions(&mock).await;
    mount_mcp_handshake(
        &mock,
        "/runtime/tools/tool-z-19607be6/mcp/",
        "Search Google using Serper API.",
    )
    .await;

    let app = build_app(build_config(&mock));
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/tools").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let tools = body["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "kamiwaza_tool_z_19607be6_search");
    assert_eq!(tools[0]["type"], "mcp");
    assert_eq!(tools[0]["path"], "/api/kamiwaza_tool_z_19607be6_search");
    assert_eq!(tools[0]["mcpTool"], "search");
    assert_eq!(tools[0]["inputSchema"]["required"][0], "query");

    let rendered = body.to_string();
    assert!(!rendered.contains("kamiwaza-token"));
}

#[tokio::test]
async fn test_kamiwaza_tool_invocation_calls_mcp_with_injected_bearer() {
    let mock = MockServer::start().await;
    mount_extensions(&mock).await;
    mount_mcp_handshake(
        &mock,
        "/runtime/tools/tool-z-19607be6/mcp/",
        "Search Google using Serper API.",
    )
    .await;

    Mock::given(method("DELETE"))
        .and(path("/runtime/tools/tool-z-19607be6/mcp/"))
        .and(header("authorization", "Bearer kamiwaza-token"))
        .and(header("mcp-session-id", "test-session"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;

    let app = build_app(build_config(&mock));
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .post("/api/kamiwaza_tool_z_19607be6_search")
        .json(&serde_json::json!({
            "query": "latest openclaw news",
            "category": "search",
            "gl": "us"
        }))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["content"][0]["type"], "text");
    assert!(
        body["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("OpenClaw news")
    );
}

#[tokio::test]
async fn test_kamiwaza_tool_invocation_adds_signed_agent_delegation() {
    let mock = MockServer::start().await;
    mount_extensions(&mock).await;
    mount_mcp_handshake_with_delegation(
        &mock,
        "/runtime/tools/tool-z-19607be6/mcp/",
        "Search Google using Serper API.",
        "agent-public-id",
        "delegation-secret",
    )
    .await;

    let server = build_delegation_server(build_config_with_delegation(&mock));
    let resp: TestResponse = server
        .post("/api/kamiwaza_tool_z_19607be6_search")
        .add_header("Authorization", "Bearer agent-token")
        .json(&serde_json::json!({
            "query": "latest openclaw news",
            "category": "search",
            "gl": "us"
        }))
        .await;

    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["content"][0]["type"], "text");
}

#[tokio::test]
async fn test_kamiwaza_delegation_required_without_agent_identity_fails_closed() {
    let mock = MockServer::start().await;
    mount_extensions(&mock).await;
    mount_mcp_handshake(
        &mock,
        "/runtime/tools/tool-z-19607be6/mcp/",
        "Search Google using Serper API.",
    )
    .await;

    let app = build_app(build_config_with_delegation(&mock));
    let server = TestServer::new(app);
    let resp: TestResponse = server
        .post("/api/kamiwaza_tool_z_19607be6_search")
        .json(&serde_json::json!({"query": "latest openclaw news"}))
        .await;

    resp.assert_status(StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = resp.json();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no authenticated agent identity")
    );
}

#[tokio::test]
async fn test_kamiwaza_missing_token_fails_closed_for_proxy_calls() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
kamiwaza:
  enabled: true
  api_url: "http://127.0.0.1:1"
tools: []
"#;
    let app = build_app(serde_yaml::from_str(yaml).unwrap());
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .post("/api/kamiwaza_tool_z_19607be6_search")
        .json(&serde_json::json!({"query": "latest openclaw news"}))
        .await;
    resp.assert_status(StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["type"], "upstream_error");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no API token")
    );
}
