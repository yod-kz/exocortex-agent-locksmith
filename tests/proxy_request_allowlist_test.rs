use agent_locksmith::{app::build_app, config::parse_config_str};
use axum::{Router, body::Body, http::Request};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn guarded_app(upstream_prefix: &str, policy: &str) -> (Router, MockServer) {
    let upstream = MockServer::start().await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "agent-test-token"
tools:
  - name: "guard"
    description: "Pipeline only"
    upstream: "{}{upstream_prefix}"
    credential_handles: ["transport-test-handle"]
    request_allowlist: {policy}
"#,
        upstream.uri()
    );
    (build_app(parse_config_str(&yaml).unwrap()), upstream)
}

async fn send(app: &Router, namespace: &str, verb: &str, suffix: &str) -> axum::response::Response {
    let credential = if namespace == "transport" {
        "transport-test-handle"
    } else {
        "agent-test-token"
    };
    app.clone()
        .oneshot(
            Request::builder()
                .method(verb)
                .uri(format!("/{namespace}/guard{suffix}"))
                .header("Authorization", format!("Bearer {credential}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"content":"untrusted test input"}"#))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn exact_pipeline_is_forwarded_through_api_and_transport() {
    let (app, upstream) =
        guarded_app("", "[{method: POST, path: /v1/pipelines/default/run}]").await;
    Mock::given(method("POST"))
        .and(path("/v1/pipelines/default/run"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&upstream)
        .await;
    for namespace in ["api", "transport"] {
        assert_eq!(
            send(&app, namespace, "POST", "/v1/pipelines/default/run")
                .await
                .status(),
            200
        );
    }
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_none())
    );
}

#[tokio::test]
async fn forbidden_paths_and_methods_never_reach_upstream() {
    let (app, upstream) =
        guarded_app("", "[{method: POST, path: /v1/pipelines/default/run}]").await;
    // Build raw in-process HTTP requests: browser/reqwest URL normalization must
    // not erase traversal probes before they reach the proxy's router.
    for namespace in ["api", "transport"] {
        for (verb, suffix) in [
            ("GET", "/v1/pipelines/default/run"),
            ("HEAD", "/v1/pipelines/default/run"),
            ("DELETE", "/v1/pipelines/default/run"),
            ("GET", "/v1/quarantine/secret-id"),
            ("POST", "/v1/quarantine/secret-id"),
            ("POST", "/v1/pipelines/other/run"),
            ("POST", "/v1/pipelines/default/run/"),
            ("POST", "/extra/../v1/pipelines/default/run"),
            ("POST", "/./v1/pipelines/default/run"),
            ("POST", "/%2e/v1/pipelines/default/run"),
            ("POST", "/v1%2fpipelines/default/run"),
            ("POST", "/v1%2Fpipelines/default/run"),
            ("POST", "/v1%252fpipelines/default/run"),
            ("POST", "/v1%5cpipelines/default/run"),
            ("POST", "/v1//pipelines/default/run"),
            (
                "POST",
                "/v1/pipelines/default/run?path=/v1/quarantine/secret-id",
            ),
            (
                "POST",
                "/v1/pipelines/default/run%3Fpath=/v1/quarantine/secret-id",
            ),
            ("POST", ""),
        ] {
            let response = send(&app, namespace, verb, suffix).await;
            assert_eq!(response.status(), 403, "{namespace} {verb} {suffix}");
        }
    }
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn policy_matches_complete_upstream_path_including_base_prefix() {
    let (app, upstream) =
        guarded_app("/v1", "[{method: POST, path: /v1/pipelines/default/run}]").await;
    Mock::given(method("POST"))
        .and(path("/v1/pipelines/default/run"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&upstream)
        .await;
    assert_eq!(
        send(&app, "api", "POST", "/pipelines/default/run")
            .await
            .status(),
        200
    );
    assert_eq!(
        send(&app, "api", "POST", "/v1/pipelines/default/run")
            .await
            .status(),
        403
    );
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn empty_allowlist_denies_all_requests() {
    let (app, upstream) = guarded_app("", "[]").await;
    for namespace in ["api", "transport"] {
        assert_eq!(
            send(&app, namespace, "POST", "/v1/pipelines/default/run")
                .await
                .status(),
            403
        );
    }
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn restricted_requests_do_not_follow_redirects_after_config_reload() {
    use agent_locksmith::app::build_app_with_shared_config;
    use arc_swap::ArcSwap;
    use std::sync::Arc;

    let upstream = MockServer::start().await;
    Mock::given(path("/v1/pipelines/default/run"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", "/v1/quarantine/raw"))
        .mount(&upstream)
        .await;
    Mock::given(path("/v1/quarantine/raw"))
        .respond_with(ResponseTemplate::new(200).set_body_string("raw content must remain private"))
        .mount(&upstream)
        .await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: guard
    description: Pipeline only
    upstream: "{}"
    credential_handles: [transport-test-handle]
"#,
        upstream.uri()
    );
    let shared = Arc::new(ArcSwap::from_pointee(parse_config_str(&yaml).unwrap()));
    let app = build_app_with_shared_config(shared.clone());
    // Populate the pool with a legacy unrestricted client first.
    assert_eq!(
        send(&app, "api", "POST", "/v1/pipelines/default/run")
            .await
            .status(),
        200
    );
    assert_eq!(upstream.received_requests().await.unwrap().len(), 2);
    shared.store(Arc::new(
        parse_config_str(&format!(
            "{yaml}    request_allowlist: [{{method: POST, path: /v1/pipelines/default/run}}]\n"
        ))
        .unwrap(),
    ));
    for namespace in ["api", "transport"] {
        assert_eq!(
            send(&app, namespace, "POST", "/v1/pipelines/default/run")
                .await
                .status(),
            307
        );
    }
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        4,
        "restricted requests must not follow redirects"
    );
    assert!(
        requests[2..]
            .iter()
            .all(|request| request.url.path() == "/v1/pipelines/default/run")
    );
}
