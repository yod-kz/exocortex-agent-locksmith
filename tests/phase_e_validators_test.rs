//! Phase E.1 — Kind enum + AuthSpec + name validators.
//!
//! TS-100..TS-106. See artifact at
//! `~/.kz-eng-mp/devloop/agents-stack/loop-states/phase-e-catalog-substrate-artifact.md`.

use agent_locksmith::registrations::{AuthSpec, Kind, RegistrationError, validate_name};

// ─── TS-100: Kind enum serializes as lowercase ─────────────────────────────
#[test]
fn ts100_kind_serializes_lowercase() {
    assert_eq!(serde_json::to_string(&Kind::Model).unwrap(), "\"model\"");
    assert_eq!(serde_json::to_string(&Kind::Tool).unwrap(), "\"tool\"");
    assert_eq!(serde_json::to_string(&Kind::Infra).unwrap(), "\"infra\"");

    // Round-trip
    let back: Kind = serde_json::from_str("\"model\"").unwrap();
    assert_eq!(back, Kind::Model);

    // url_segment returns plural form for endpoint routing
    assert_eq!(Kind::Model.url_segment(), "models");
    assert_eq!(Kind::Tool.url_segment(), "tools");
    assert_eq!(Kind::Infra.url_segment(), "infra");
}

// ─── TS-101: Reserved name rejected at validator ────────────────────────────
#[test]
fn ts101_reserved_name_rejected() {
    for reserved in [
        "livez", "readyz", "version", "health", "skill", "tools", "models", "admin", "api",
        "metrics", "audit",
    ] {
        let err = validate_name(reserved).unwrap_err();
        assert!(
            matches!(err, RegistrationError::ReservedName),
            "name {reserved:?} should be reserved; got {err:?}"
        );
    }

    // Plausible non-reserved names pass.
    for ok in ["anthropic", "openai", "lf-scan", "duckduckgo", "tavily"] {
        validate_name(ok).expect("expected validation to pass");
    }
}

// ─── TS-102: Charset violation rejected (uppercase, dots, slashes, unicode) ─
#[test]
fn ts102_charset_violation_rejected() {
    for bad in [
        "Anthropic",       // uppercase
        "openai_v2",       // underscore
        "tool.api",        // dot
        "vendor/name",     // slash
        "tévily",          // unicode
        "name with space", // whitespace
        "",                // empty
        "-leading-dash",   // dash placement is allowed; this passes
                           // (but empty above is the real edge to test).
    ] {
        if bad == "-leading-dash" {
            // Validator allows leading dash. Sanity check.
            validate_name(bad).expect("dash anywhere in name is permitted");
            continue;
        }
        let err = validate_name(bad).unwrap_err();
        assert!(
            matches!(err, RegistrationError::InvalidName(_)),
            "name {bad:?} should be invalid; got {err:?}"
        );
    }
}

// ─── TS-103: Length > 64 rejected ───────────────────────────────────────────
#[test]
fn ts103_length_64_max() {
    // 64 chars: ok
    let sixty_four = "a".repeat(64);
    validate_name(&sixty_four).expect("exactly 64 chars is the upper bound, allowed");

    // 65 chars: rejected
    let sixty_five = "a".repeat(65);
    let err = validate_name(&sixty_five).unwrap_err();
    assert!(
        matches!(err, RegistrationError::InvalidName(_)),
        "65 chars should be rejected; got {err:?}"
    );

    // 1 char: ok
    validate_name("a").expect("1 char is the lower bound, allowed");
}

// ─── TS-104: AuthSpec::None serializes as {"kind":"none"} ───────────────────
#[test]
fn ts104_authspec_none_serializes() {
    let none = AuthSpec::None;
    let json = serde_json::to_string(&none).unwrap();
    assert_eq!(json, "{\"kind\":\"none\"}");

    // Round-trip
    let back: AuthSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, AuthSpec::None);

    // Implicit absence (e.g., a YAML object with no `auth:` key) is NOT
    // AuthSpec::None — that's caught by the registration-level validator,
    // which sees the field as missing. Here we're verifying that explicit
    // `auth: none` deserializes correctly.
}

// ─── TS-105: AuthSpec::Header round-trips through serde ─────────────────────
#[test]
fn ts105_authspec_header_round_trips() {
    let header = AuthSpec::Header {
        header: "x-api-key".to_string(),
        env_var: "ANTHROPIC_API_KEY".to_string(),
        force_replace: false,
    };
    let json = serde_json::to_string(&header).unwrap();
    let back: AuthSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, header);

    // The deserialization shape we accept from the seed catalog YAML and
    // admin PUT bodies. Internal tag is "kind".
    assert!(json.contains("\"kind\":\"header\""));
    assert!(json.contains("\"header\":\"x-api-key\""));
    assert!(json.contains("\"env_var\":\"ANTHROPIC_API_KEY\""));
}

// ─── TS-106: AuthSpec::Bearer round-trips through serde ─────────────────────
#[test]
fn ts106_authspec_bearer_round_trips() {
    let bearer = AuthSpec::Bearer {
        env_var: "OPENAI_API_KEY".to_string(),
        force_replace: false,
    };
    let json = serde_json::to_string(&bearer).unwrap();
    let back: AuthSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bearer);

    assert!(json.contains("\"kind\":\"bearer\""));
    assert!(json.contains("\"env_var\":\"OPENAI_API_KEY\""));
}

// ─── TS-106b: AuthSpec → SecretRef translation ──────────────────────────────
#[test]
fn ts106b_authspec_to_secret_ref() {
    use agent_locksmith::secret::SecretRef;

    assert!(AuthSpec::None.to_secret_ref().is_none());

    let header = AuthSpec::Header {
        header: "x-api-key".to_string(),
        env_var: "ANTHROPIC_API_KEY".to_string(),
        force_replace: false,
    };
    match header.to_secret_ref().unwrap() {
        SecretRef::FromEnv { var, prefix } => {
            assert_eq!(var, "ANTHROPIC_API_KEY");
            assert_eq!(prefix, None);
        }
        other => panic!("expected FromEnv, got {other:?}"),
    }

    let bearer = AuthSpec::Bearer {
        env_var: "OPENAI_API_KEY".to_string(),
        force_replace: false,
    };
    match bearer.to_secret_ref().unwrap() {
        SecretRef::FromEnv { var, prefix } => {
            assert_eq!(var, "OPENAI_API_KEY");
            assert_eq!(prefix, None);
        }
        other => panic!("expected FromEnv, got {other:?}"),
    }

    // Bearer prefix is added by the proxy-side header injection, not by
    // SecretRef. The env var contains just the token — convention preserved.
    assert!(!AuthSpec::None.injects_header());
    assert!(header.injects_header());
}
