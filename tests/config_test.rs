use agent_locksmith::config::{EgressMode, parse_config_str};

#[test]
fn test_parse_minimal_config() {
    // Uses the legacy `cloud: true` field, which T1.6 translates to
    // `egress: proxied` via the deprecation registry. Asserts the
    // translation result, not the legacy field.
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub REST API"
    upstream: "https://api.github.com"
    cloud: true
    auth:
      header: "Authorization"
      value: "Bearer test-token-123"
    timeout_seconds: 30
"#;
    let config = parse_config_str(yaml).unwrap();
    assert_eq!(config.listen.port, 9200);
    assert_eq!(config.tools.len(), 1);
    assert_eq!(config.tools[0].name, "github");
    assert_eq!(config.tools[0].upstream, "https://api.github.com");
    assert_eq!(config.tools[0].egress, EgressMode::Proxied);
}

#[test]
fn test_empty_tools_list() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config = parse_config_str(yaml).unwrap();
    assert!(config.tools.is_empty());
}

#[test]
fn test_optional_fields_default() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config = parse_config_str(yaml).unwrap();
    assert!(config.egress_proxy.is_none());
    assert!(config.inbound_auth.is_none());
    assert!(config.logging.is_none());
    assert!(config.tls.is_none());
}

#[test]
fn test_tls_upstream_ca_bundle_parses() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tls:
  upstream_ca_bundle: "/etc/locksmith/ca/kamiwaza-ca.pem"
tools: []
"#;
    let config = parse_config_str(yaml).unwrap();
    let tls = config.tls.expect("tls section present");
    assert_eq!(
        tls.upstream_ca_bundle.as_deref(),
        Some(std::path::Path::new("/etc/locksmith/ca/kamiwaza-ca.pem")),
    );
}
