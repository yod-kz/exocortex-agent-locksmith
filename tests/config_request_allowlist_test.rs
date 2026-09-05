use agent_locksmith::config::parse_config_str;

fn config_with(policy: &str) -> String {
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "guard"
    description: "Pipeline only"
    upstream: "http://127.0.0.1:8787"
    {policy}
"#
    )
}

#[test]
fn request_allowlist_preserves_absent_and_empty_policies() {
    let config = parse_config_str(&config_with("")).unwrap();
    assert!(config.tools[0].request_allowlist.is_none());
    let config = parse_config_str(&config_with("request_allowlist: []")).unwrap();
    assert!(
        config.tools[0]
            .request_allowlist
            .as_ref()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn request_allowlist_accepts_exact_method_and_upstream_path() {
    let config = parse_config_str(&config_with(
        r#"request_allowlist: [{method: "POST", path: "/v1/pipelines/default/run"}]"#,
    ))
    .unwrap();
    let rule = &config.tools[0].request_allowlist.as_ref().unwrap()[0];
    assert_eq!(rule.method, "POST");
    assert_eq!(rule.path, "/v1/pipelines/default/run");
}

#[test]
fn request_allowlist_rejects_ambiguous_rules() {
    for (method, path) in [
        ("post", "/run"),
        ("PO ST", "/run"),
        ("", "/run"),
        ("POST", "run"),
        ("POST", "/v1/../run"),
        ("POST", "/v1/./run"),
        ("POST", "/v1//run"),
        ("POST", "/v1%2Frun"),
        ("POST", "/run?path=/quarantine"),
        ("POST", "/run#quarantine"),
        ("POST", "/run path"),
    ] {
        let policy = format!("request_allowlist: [{{method: {method:?}, path: {path:?}}}]");
        assert!(
            parse_config_str(&config_with(&policy)).is_err(),
            "{method} {path}"
        );
    }
    assert!(
        parse_config_str(&config_with(
            r#"request_allowlist: [{method: POST, path: /run, allow_query: true}]"#,
        ))
        .is_err()
    );
}
