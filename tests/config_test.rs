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

#[test]
fn test_kamiwaza_delegation_config_defaults_and_overrides() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
kamiwaza:
  enabled: true
  api_url: "https://kamiwaza.local/api"
  api_token: "pat"
  delegation:
    enabled: true
    required: true
    signing_secret: "delegation-secret"
    header: "x-custom-delegation"
    issuer: "locksmith-test"
    audience: "kamiwaza-test"
    ttl_seconds: 120
tools: []
"#;
    let config = parse_config_str(yaml).unwrap();
    let kamiwaza = config.kamiwaza.as_ref().unwrap();
    assert!(kamiwaza.delegation.enabled);
    assert!(kamiwaza.delegation.required);
    assert_eq!(kamiwaza.delegation.header, "x-custom-delegation");
    assert_eq!(kamiwaza.delegation.issuer, "locksmith-test");
    assert_eq!(kamiwaza.delegation.audience, "kamiwaza-test");
    assert_eq!(kamiwaza.delegation.ttl_seconds, 120);

    let defaults = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
kamiwaza:
  enabled: true
  api_token: "pat"
tools: []
"#,
    )
    .unwrap();
    let defaults = defaults.kamiwaza.as_ref().unwrap();
    assert!(!defaults.delegation.enabled);
    assert!(!defaults.delegation.required);
    assert_eq!(defaults.delegation.header, "x-kamiwaza-agent-delegation");
    assert_eq!(defaults.delegation.ttl_seconds, 60);
}
