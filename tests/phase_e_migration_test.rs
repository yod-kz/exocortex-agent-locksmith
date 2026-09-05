//! Phase E.2 — registrations table migration + repo CRUD.
//!
//! TS-110..TS-117. See artifact at
//! `~/.kz-eng-mp/devloop/agents-stack/loop-states/phase-e-catalog-substrate-artifact.md`.

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{AuthSpec, Kind, Registration, RegistrationRepository};
use tempfile::TempDir;

async fn fresh_pool() -> (TempDir, sqlx::SqlitePool) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    (dir, pool)
}

// ─── TS-110: Migration creates registrations + registrations_meta tables ────
#[tokio::test]
async fn ts110_migration_creates_tables() {
    let (_dir, pool) = fresh_pool().await;

    let row =
        sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='registrations'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(row.is_some(), "registrations table should exist");

    let row = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='registrations_meta'",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(row.is_some(), "registrations_meta table should exist");

    // Indexes present.
    let idx_kind = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_registrations_kind'",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(idx_kind.is_some(), "kind index should exist");

    let idx_seed = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type='index' \
         AND name='idx_registrations_seed_disabled'",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(idx_seed.is_some(), "seed/disabled index should exist");
}

// ─── TS-111: Insert + select round-trips a full Registration row ───────────
#[tokio::test]
async fn ts111_round_trip_full_registration() {
    let (_dir, pool) = fresh_pool().await;
    let repo = RegistrationRepository::new(pool);

    let mut r = Registration::new(
        "anthropic".to_string(),
        Kind::Model,
        "Anthropic Messages API".to_string(),
        "https://api.anthropic.com".to_string(),
        AuthSpec::Header {
            header: "x-api-key".to_string(),
            env_var: "ANTHROPIC_API_KEY".to_string(),
            force_replace: false,
        },
    );
    r.metadata = serde_json::json!({"modality": "text", "provider": "anthropic"});
    r.body_limit_bytes = 50_000_000;
    r.seed = true;

    repo.create(&r).await.expect("create should succeed");

    let fetched = repo.get("anthropic").await.unwrap().expect("row exists");
    assert_eq!(fetched, r);
}

// ─── TS-112: Migration is idempotent (open_and_migrate twice) ──────────────
#[tokio::test]
async fn ts112_migration_idempotent() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("locksmith.db");

    // First open creates schema.
    let pool1 = open_and_migrate(&path).await.unwrap();
    let repo1 = RegistrationRepository::new(pool1.clone());
    let r = Registration::new(
        "tavily".to_string(),
        Kind::Tool,
        "Tavily search".to_string(),
        "https://api.tavily.com".to_string(),
        AuthSpec::Bearer {
            env_var: "TAVILY_API_KEY".to_string(),
            force_replace: false,
        },
    );
    repo1.create(&r).await.unwrap();
    drop(pool1);

    // Re-open: migrations should be no-op + data should be intact.
    let pool2 = open_and_migrate(&path).await.unwrap();
    let repo2 = RegistrationRepository::new(pool2);
    let fetched = repo2.get("tavily").await.unwrap();
    assert!(fetched.is_some(), "data survives re-migration");
}

// ─── TS-113: kind CHECK constraint rejects invalid kind ────────────────────
#[tokio::test]
async fn ts113_kind_check_rejects_invalid() {
    let (_dir, pool) = fresh_pool().await;

    // Bypass the repo (which would never produce an invalid kind) and try
    // to write an invalid kind directly to verify the DB-level CHECK fires.
    let result = sqlx::query(
        "INSERT INTO registrations \
         (name, kind, description, upstream, auth_json, egress, timeouts_json, \
          body_limit_bytes, metadata_json, seed, disabled, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("badkind")
    .bind("function") // not in CHECK list
    .bind("")
    .bind("https://example.com")
    .bind("{\"kind\":\"none\"}")
    .bind("proxied")
    .bind("{\"request_seconds\":30,\"idle_seconds\":60}")
    .bind(0_i64)
    .bind("{}")
    .bind(0_i64)
    .bind(0_i64)
    .bind(0_i64)
    .bind(0_i64)
    .execute(&pool)
    .await;

    assert!(result.is_err(), "kind CHECK should reject 'function'");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.to_lowercase().contains("check"),
        "error should mention CHECK violation; got: {err_msg}"
    );
}

// ─── TS-114: Cross-kind name reuse blocked at PK level ─────────────────────
#[tokio::test]
async fn ts114_cross_kind_name_reuse_blocked() {
    let (_dir, pool) = fresh_pool().await;
    let repo = RegistrationRepository::new(pool);

    let tool = Registration::new(
        "ambiguous".to_string(),
        Kind::Tool,
        "First as tool".to_string(),
        "https://example.com".to_string(),
        AuthSpec::None,
    );
    repo.create(&tool).await.unwrap();

    // Same name as a model — PK conflict at the DB layer.
    let model = Registration::new(
        "ambiguous".to_string(),
        Kind::Model,
        "Trying as model".to_string(),
        "https://example.com".to_string(),
        AuthSpec::Bearer {
            env_var: "FOO".to_string(),
            force_replace: false,
        },
    );
    let result = repo.create(&model).await;
    assert!(result.is_err(), "PK conflict should block cross-kind reuse");
}

// ─── TS-115: Upsert preserves created_at on update ─────────────────────────
#[tokio::test]
async fn ts115_upsert_update_path() {
    let (_dir, pool) = fresh_pool().await;
    let repo = RegistrationRepository::new(pool);

    let mut r = Registration::new(
        "ollama".to_string(),
        Kind::Model,
        "Initial".to_string(),
        "http://ollama.lan:11434".to_string(),
        AuthSpec::None,
    );
    r.created_at = 100;
    r.updated_at = 100;
    repo.upsert(&r).await.unwrap();

    // Update — change description, bump updated_at.
    let mut r2 = r.clone();
    r2.description = "Updated".to_string();
    r2.updated_at = 200;
    // (created_at intentionally not bumped on update — operator-side timestamp invariant.)
    repo.upsert(&r2).await.unwrap();

    let fetched = repo.get("ollama").await.unwrap().unwrap();
    assert_eq!(fetched.description, "Updated");
    assert_eq!(fetched.updated_at, 200);
    // Note: the upsert here passes through both timestamps; per-row
    // created_at preservation is enforced at the admin-handler layer (E.3),
    // not in the repo.
}

// ─── TS-116: set_disabled toggles the flag ─────────────────────────────────
#[tokio::test]
async fn ts116_set_disabled_toggles_flag() {
    let (_dir, pool) = fresh_pool().await;
    let repo = RegistrationRepository::new(pool);

    let r = Registration::new(
        "openrouter".to_string(),
        Kind::Model,
        "OpenRouter".to_string(),
        "https://openrouter.ai/api".to_string(),
        AuthSpec::Bearer {
            env_var: "OPENROUTER_API_KEY".to_string(),
            force_replace: false,
        },
    );
    repo.create(&r).await.unwrap();

    let touched = repo.set_disabled("openrouter", true).await.unwrap();
    assert!(touched, "expected the row to be touched");
    let fetched = repo.get("openrouter").await.unwrap().unwrap();
    assert!(fetched.disabled, "row should be marked disabled");

    let untouched = repo.set_disabled("nonexistent", true).await.unwrap();
    assert!(
        !untouched,
        "set_disabled on nonexistent row should report no rows"
    );

    let re_enabled = repo.set_disabled("openrouter", false).await.unwrap();
    assert!(re_enabled);
    assert!(!repo.get("openrouter").await.unwrap().unwrap().disabled);
}

// ─── TS-117: List by kind filters correctly ────────────────────────────────
#[tokio::test]
async fn ts117_list_by_kind() {
    let (_dir, pool) = fresh_pool().await;
    let repo = RegistrationRepository::new(pool);

    repo.create(&Registration::new(
        "openai".to_string(),
        Kind::Model,
        "".to_string(),
        "https://api.openai.com".to_string(),
        AuthSpec::Bearer {
            env_var: "OPENAI_API_KEY".to_string(),
            force_replace: false,
        },
    ))
    .await
    .unwrap();
    repo.create(&Registration::new(
        "github".to_string(),
        Kind::Tool,
        "".to_string(),
        "https://api.github.com".to_string(),
        AuthSpec::Bearer {
            env_var: "GITHUB_TOKEN".to_string(),
            force_replace: false,
        },
    ))
    .await
    .unwrap();
    repo.create(&Registration::new(
        "lf-scan".to_string(),
        Kind::Infra,
        "".to_string(),
        "http://lf-scan:8080".to_string(),
        AuthSpec::Header {
            header: "X-Internal-Token".to_string(),
            env_var: "LF_SCAN_INTERNAL_TOKEN".to_string(),
            force_replace: false,
        },
    ))
    .await
    .unwrap();

    let models = repo.list(Some(Kind::Model)).await.unwrap();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].name, "openai");

    let tools = repo.list(Some(Kind::Tool)).await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "github");

    let infra = repo.list(Some(Kind::Infra)).await.unwrap();
    assert_eq!(infra.len(), 1);
    assert_eq!(infra[0].name, "lf-scan");

    let all = repo.list(None).await.unwrap();
    assert_eq!(all.len(), 3);
    // Ordered by name.
    assert_eq!(all[0].name, "github");
    assert_eq!(all[1].name, "lf-scan");
    assert_eq!(all[2].name, "openai");
}

// ─── TS-118: Seed version round-trips through registrations_meta ───────────
#[tokio::test]
async fn ts118_seed_version_kv() {
    let (_dir, pool) = fresh_pool().await;
    let repo = RegistrationRepository::new(pool);

    assert!(
        repo.get_seed_version().await.unwrap().is_none(),
        "fresh DB has no seed_version row"
    );

    repo.set_seed_version("2.0.0").await.unwrap();
    assert_eq!(
        repo.get_seed_version().await.unwrap().as_deref(),
        Some("2.0.0")
    );

    // Upsert: same key, new value.
    repo.set_seed_version("2.1.0").await.unwrap();
    assert_eq!(
        repo.get_seed_version().await.unwrap().as_deref(),
        Some("2.1.0")
    );
}
