use agent_locksmith::app::build_app;
use agent_locksmith::config::parse_config_str;
use axum_test::{TestResponse, TestServer};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_proxy_injects_credentials() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/test"))
        .and(header("Authorization", "Bearer injected-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id": 1, "name": "test-repo"})),
        )
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub"
    upstream: "{}"
    auth:
      header: "Authorization"
      value: "Bearer injected-token"
    timeout_seconds: 30
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/api/github/repos/test").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["name"], "test-repo");
}

#[tokio::test]
async fn test_proxy_forwards_query_string() {
    // Regression: axum's `{*path}` capture excludes the query string, so the
    // proxy must re-attach it. Without forwarding, ComfyUI `/view?filename=…`
    // (and any query-driven GET) reaches the upstream stripped and 404s.
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/view"))
        .and(query_param("filename", "img_00001_.png"))
        .and(query_param("type", "output"))
        .respond_with(ResponseTemplate::new(200).set_body_string("PNGBYTES"))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "comfyui"
    description: "ComfyUI"
    upstream: "{}"
    auth:
      header: "Authorization"
      value: "Bearer x"
    timeout_seconds: 30
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .get("/api/comfyui/view?filename=img_00001_.png&type=output")
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "PNGBYTES");
}

#[tokio::test]
async fn test_proxy_strips_agent_auth_header() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/test"))
        .and(header("Authorization", "Bearer injected"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "svc"
    description: "Test service"
    upstream: "{}"
    auth:
      header: "Authorization"
      value: "Bearer injected"
    timeout_seconds: 30
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .get("/api/svc/test")
        .add_header("Authorization", "Bearer agent-token")
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn test_force_replace_strips_placeholder_and_injects_config_credential() {
    unsafe {
        std::env::set_var("LOCKSMITH_FORCE_REPLACE_TEST_TOKEN", "real-token");
    }

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auth.test"))
        .and(header("Authorization", "Bearer real-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "slack"
    description: "Slack"
    upstream: "{}"
    auth:
      header: "Authorization"
      force_replace: true
      value:
        from_env:
          var: "LOCKSMITH_FORCE_REPLACE_TEST_TOKEN"
          prefix: "Bearer "
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .get("/api/slack/auth.test")
        .add_header("Authorization", "Bearer NA")
        .await;
    resp.assert_status_ok();
    resp.assert_text("ok");

    unsafe {
        std::env::remove_var("LOCKSMITH_FORCE_REPLACE_TEST_TOKEN");
    }
}

#[tokio::test]
async fn test_force_replace_missing_credential_fails_closed() {
    unsafe {
        std::env::remove_var("LOCKSMITH_FORCE_REPLACE_MISSING_TOKEN");
    }

    let mock = MockServer::start().await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "slack"
    description: "Slack"
    upstream: "{}"
    auth:
      header: "Authorization"
      force_replace: true
      value:
        from_env:
          var: "LOCKSMITH_FORCE_REPLACE_MISSING_TOKEN"
          prefix: "Bearer "
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .get("/api/slack/auth.test")
        .add_header("Authorization", "Bearer NA")
        .await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "credential_unavailable");

    let received = mock.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "force_replace should not contact upstream"
    );
}

#[tokio::test]
async fn test_credential_transport_accepts_fake_handle_and_injects_config_credential() {
    unsafe {
        std::env::set_var("LOCKSMITH_TRANSPORT_TEST_TOKEN", "real-slack-token");
    }

    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth.test"))
        .and(header("Authorization", "Bearer real-slack-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "locksmith-agent-token"
tools:
  - name: "slack-bot"
    description: "Slack bot Web API"
    upstream: "{}"
    credential_handles:
      - "xoxb-locksmith-fake"
    auth:
      header: "Authorization"
      force_replace: true
      value:
        from_env:
          var: "LOCKSMITH_TRANSPORT_TEST_TOKEN"
          prefix: "Bearer "
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .post("/transport/slack-bot/auth.test")
        .add_header("Authorization", "Bearer xoxb-locksmith-fake")
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["ok"], true);

    unsafe {
        std::env::remove_var("LOCKSMITH_TRANSPORT_TEST_TOKEN");
    }
}

#[tokio::test]
async fn test_credential_transport_rejects_unknown_fake_handle() {
    unsafe {
        std::env::set_var("LOCKSMITH_TRANSPORT_REJECT_TEST_TOKEN", "real-slack-token");
    }

    let mock = MockServer::start().await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "slack-bot"
    description: "Slack bot Web API"
    upstream: "{}"
    credential_handles:
      - "xoxb-locksmith-fake"
    auth:
      header: "Authorization"
      force_replace: true
      value:
        from_env:
          var: "LOCKSMITH_TRANSPORT_REJECT_TEST_TOKEN"
          prefix: "Bearer "
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .post("/transport/slack-bot/auth.test")
        .add_header("Authorization", "Bearer xoxb-wrong")
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "credential_handle_rejected");

    let received = mock.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "rejected handle should not hit upstream"
    );

    unsafe {
        std::env::remove_var("LOCKSMITH_TRANSPORT_REJECT_TEST_TOKEN");
    }
}

#[tokio::test]
async fn test_credential_transport_force_replace_missing_credential_fails_closed() {
    unsafe {
        std::env::remove_var("LOCKSMITH_TRANSPORT_MISSING_TEST_TOKEN");
    }

    let mock = MockServer::start().await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "slack-bot"
    description: "Slack bot Web API"
    upstream: "{}"
    credential_handles:
      - "xoxb-locksmith-fake"
    auth:
      header: "Authorization"
      force_replace: true
      value:
        from_env:
          var: "LOCKSMITH_TRANSPORT_MISSING_TEST_TOKEN"
          prefix: "Bearer "
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .post("/transport/slack-bot/auth.test")
        .add_header("Authorization", "Bearer xoxb-locksmith-fake")
        .await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "credential_unavailable");

    let received = mock.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "missing credential should not hit upstream"
    );
}

#[tokio::test]
async fn test_proxy_unknown_tool_404() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config = parse_config_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/api/unknown/test").await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unknown tool")
    );
}

#[tokio::test]
async fn test_proxy_post_with_body() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("x-api-key", "tavily-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"results": []})))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "tavily"
    description: "Tavily"
    upstream: "{}"
    auth:
      header: "x-api-key"
      value: "tavily-key"
    timeout_seconds: 15
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .post("/api/tavily/v1/search")
        .json(&serde_json::json!({"query": "test"}))
        .await;
    resp.assert_status_ok();
}
