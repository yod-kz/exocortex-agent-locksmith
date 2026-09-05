//! Phase E (transitional) — migrate pre-Phase-E `config.tools` YAML
//! entries into the `registrations` table at daemon startup.
//!
//! Pre-Phase-E deployments stored their tool catalog in YAML loaded
//! into `AppConfig.tools`. Phase E moved the catalog to the
//! `registrations` table. To keep existing deployments running without
//! requiring a hand-edit, this shim runs at startup AFTER the seed
//! loader and BEFORE the daemon binds:
//!
//! - For each `config.tools` entry whose name isn't already in the
//!   registrations table: insert as `kind=tool`, `seed=false`
//!   (operator-authored).
//! - For each entry whose name IS already in the table (e.g., loaded
//!   by the seed catalog or previously written by admin PUT): skip.
//!   The DB row is the source of truth.
//!
//! Auth-shape translation:
//! - `auth: None` (no `auth:` block) → `AuthSpec::None`. Preserves
//!   pre-Phase-E "implicit absence means authless" semantics for
//!   tools migrated from existing site repos.
//! - `auth: { header, value: from_env { var } }` → `AuthSpec::Header
//!   { header, env_var: var }`. Most operator configs use this shape.
//! - `auth: { header: "Authorization", value: "Bearer ${VAR}" }`
//!   (legacy string) → `AuthSpec::Bearer { env_var: VAR }` when the
//!   prefix matches and the value contains exactly one `${...}`. Other
//!   legacy-string shapes fall back to `AuthSpec::Header` with the
//!   variable extracted (best-effort).
//! - `from_file_sealed` / `from_vault` / `from_aws_secrets_manager` /
//!   `Inline`: SKIPPED with a WARN log. AuthSpec at v2.0.0 only
//!   supports env-var indirection. Operators using these shapes need
//!   to either switch to env vars or wait for v0.2's richer
//!   admin-side AuthSpec.
//!
//! Deprecated. Removed in v0.3. By then operators are expected to have
//! either migrated to the seed catalog (E.7) or to the override-only
//! site-repo flow (E.8).

use crate::config::{AppConfig, ToolAuthConfig};
use crate::registrations::{
    AuthSpec, Kind, Registration, RegistrationError, RegistrationRepository,
};
use crate::secret::SecretRef;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Walk `cfg.tools` and migrate entries not already in the
/// registrations table. Returns a count of (inserted, skipped_existing,
/// skipped_unsupported_auth) for diagnostic logging.
pub async fn bootstrap_from_config_tools(
    repo: &RegistrationRepository,
    cfg: &AppConfig,
) -> Result<(usize, usize, usize), RegistrationError> {
    let mut inserted = 0;
    let mut skipped_existing = 0;
    let mut skipped_unsupported = 0;

    for tool in &cfg.tools {
        if repo.get(&tool.name).await?.is_some() {
            // Already in the table (seed loader or earlier admin PUT).
            // Don't clobber.
            skipped_existing += 1;
            continue;
        }

        let auth = match &tool.auth {
            None => AuthSpec::None,
            Some(ta) => match translate_auth(&tool.name, ta) {
                Some(spec) => spec,
                None => {
                    skipped_unsupported += 1;
                    continue;
                }
            },
        };

        let now = unix_now();
        let r = Registration {
            name: tool.name.clone(),
            kind: Kind::Tool,
            description: tool.description.clone(),
            upstream: tool.upstream.clone(),
            auth,
            egress: tool.egress,
            timeouts: tool.timeouts,
            body_limit_bytes: tool.body_limit_bytes,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            seed: false,
            disabled: false,
            created_at: now,
            updated_at: now,
        };
        repo.create(&r).await?;
        inserted += 1;
    }

    if inserted > 0 || skipped_unsupported > 0 {
        info!(
            inserted,
            skipped_existing,
            skipped_unsupported,
            "legacy bootstrap migrated config.tools entries into registrations"
        );
    }

    Ok((inserted, skipped_existing, skipped_unsupported))
}

/// Translate a pre-Phase-E `ToolAuthConfig` to a v2.0.0 `AuthSpec`.
/// Returns `None` for shapes we can't represent (sealed file, Vault,
/// AWS, Inline, legacy strings without a single `${VAR}`).
///
/// Always emits `AuthSpec::Header` (never `AuthSpec::Bearer`). Reason:
/// pre-Phase-E configs commonly wrote
/// `auth: { header: "Authorization", value: from_env { var: X, prefix: "Bearer " } }`
/// — the `prefix` was applied at resolve time, so `resolved_creds[name]`
/// already carries the full `Bearer <token>` header value. Using
/// `AuthSpec::Bearer` would have the proxy hot path prepend "Bearer "
/// a second time. Header injection takes the value verbatim, which is
/// what the pre-Phase-E proxy did. AuthSpec::Bearer is reserved for
/// seed-catalog entries where the env var is unambiguously just the
/// token.
fn translate_auth(tool_name: &str, ta: &ToolAuthConfig) -> Option<AuthSpec> {
    match &ta.value {
        SecretRef::FromEnv { var, .. } => Some(AuthSpec::Header {
            header: ta.header.clone(),
            env_var: var.clone(),
            force_replace: ta.force_replace,
        }),
        SecretRef::LegacyString(s) => {
            // Pre-Phase-E "Bearer ${VAR}" or "${VAR}" form. Best-effort
            // parse: find the first ${...} reference.
            let var = extract_single_env_var(s)?;
            Some(AuthSpec::Header {
                header: ta.header.clone(),
                env_var: var,
                force_replace: ta.force_replace,
            })
        }
        SecretRef::FromFileSealed { .. }
        | SecretRef::FromVault { .. }
        | SecretRef::FromAwsSecretsManager { .. }
        | SecretRef::Inline(_) => {
            warn!(
                tool = %tool_name,
                shape = %ta.value,
                "legacy bootstrap: unsupported auth shape; tool not migrated to registrations \
                 (use admin PUT once v0.2 admin-side AuthSpec lands, or switch to env-var auth)"
            );
            None
        }
    }
}

/// Extract a single `${VAR}` reference from a legacy-string value.
/// Returns `None` if the string contains zero or multiple `${...}`
/// references.
fn extract_single_env_var(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut found: Option<String> = None;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' {
            let close = s[i + 2..].find('}')?;
            let name = &s[i + 2..i + 2 + close];
            if found.is_some() {
                return None; // Multiple references; refuse to guess.
            }
            found = Some(name.to_string());
            i += 2 + close + 1;
        } else {
            i += 1;
        }
    }
    found
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
