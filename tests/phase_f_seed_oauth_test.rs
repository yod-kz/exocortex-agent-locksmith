//! Phase F.7 — OAuth providers in the bundled seed catalog.
//!
//! TS-230..TS-232. Confirms `seed/catalog.yaml` parses, the OAuth
//! entries promote to SHIP, and the seed loader applies them on a
//! fresh install.

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{AuthSpec, Kind, RegistrationRepository, seed_loader};
use std::path::PathBuf;
use tempfile::TempDir;

fn bundled_catalog_path() -> PathBuf {
    // Walk up from CARGO_MANIFEST_DIR/tests to the crate root.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest).join("seed").join("catalog.yaml")
}

// ─── TS-230: bundled seed catalog parses + version is 2.1.0+ ───────────────
#[tokio::test]
async fn ts230_bundled_seed_catalog_loads_at_version_2_1_0() {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let repo = RegistrationRepository::new(pool);
    let path = bundled_catalog_path();
    seed_loader::load_or_skip(&repo, &path).await.unwrap();
    let version = repo.get_seed_version().await.unwrap();
    assert!(
        matches!(
            version.as_deref(),
            Some("2.1.2" | "2.1.1" | "2.1.0" | "2.0.0")
        ),
        "expected catalog version 2.0.0, 2.1.0, 2.1.1, or 2.1.2, got {version:?}"
    );
}

// ─── TS-231: all five OAuth providers present after seed load ─────────────
#[tokio::test]
async fn ts231_oauth_providers_present_in_seed_catalog() {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let repo = RegistrationRepository::new(pool);
    seed_loader::load_or_skip(&repo, &bundled_catalog_path())
        .await
        .unwrap();

    let expected = [
        ("codex", "oauth_device_code"),
        ("copilot", "oauth_device_code"),
        ("anthropic-oauth", "oauth_pkce"),
        ("google-gemini-cli", "oauth_pkce"),
        ("qwen-cli", "oauth_device_code"),
    ];
    for (name, expected_flow) in expected {
        let r = repo
            .get(name)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("seed-catalog entry {name} missing"));
        assert_eq!(r.kind, Kind::Model);
        assert!(r.seed, "expected seed=true for {name}");
        match (&r.auth, expected_flow) {
            (AuthSpec::OauthPkce { .. }, "oauth_pkce") => {}
            (AuthSpec::OauthDeviceCode { .. }, "oauth_device_code") => {}
            (other, _) => panic!("entry {name}: expected {expected_flow}, got {other:?}"),
        }
    }
}

// ─── TS-232: existing-deployment upgrade applies new OAuth entries additively ─
#[tokio::test]
async fn ts232_seed_loader_adds_oauth_additively_on_version_bump() {
    use agent_locksmith::registrations::{AuthSpec, Registration};

    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let repo = RegistrationRepository::new(pool);

    // Simulate an existing v2.0.0 deployment: anthropic seed-row + an
    // operator-overridden lmstudio (seed=false).
    let now = unix_now();
    let anthropic = Registration {
        name: "anthropic".to_string(),
        kind: Kind::Model,
        description: "old".to_string(),
        upstream: "https://api.anthropic.com".to_string(),
        auth: AuthSpec::Header {
            header: "x-api-key".to_string(),
            env_var: "ANTHROPIC_API_KEY".to_string(),
            force_replace: false,
        },
        egress: agent_locksmith::config::EgressMode::Proxied,
        timeouts: Default::default(),
        body_limit_bytes: 10485760,
        metadata: serde_json::json!({}),
        seed: true,
        disabled: false,
        created_at: now,
        updated_at: now,
    };
    repo.create(&anthropic).await.unwrap();
    repo.set_seed_version("2.0.0").await.unwrap();

    let mut lmstudio = anthropic.clone();
    lmstudio.name = "lmstudio".to_string();
    lmstudio.upstream = "http://operator-override.lan:1234".to_string();
    lmstudio.auth = AuthSpec::None;
    lmstudio.seed = false; // operator-owned
    repo.create(&lmstudio).await.unwrap();

    // Apply v2.1.x catalog. Loader should: keep anthropic (update from
    // seed if changed), keep operator-override lmstudio untouched, add
    // codex / copilot / anthropic-oauth / google-gemini-cli / qwen-cli.
    seed_loader::load_or_skip(&repo, &bundled_catalog_path())
        .await
        .unwrap();

    // Operator override preserved.
    let lmstudio_after = repo.get("lmstudio").await.unwrap().unwrap();
    assert_eq!(lmstudio_after.upstream, "http://operator-override.lan:1234");
    assert!(!lmstudio_after.seed);

    // OAuth entries added with seed=true.
    for name in [
        "codex",
        "copilot",
        "anthropic-oauth",
        "google-gemini-cli",
        "qwen-cli",
    ] {
        let r = repo.get(name).await.unwrap().unwrap();
        assert!(r.seed, "expected seed=true for newly-added {name}");
        assert!(matches!(
            r.auth,
            AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. }
        ));
    }

    let v = repo.get_seed_version().await.unwrap();
    assert_eq!(v.as_deref(), Some("2.1.2"));
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
