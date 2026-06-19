//! Secret reference types and backend trait (C-14, SPEC §4.2.16).
//!
//! `SecretRef` is the typed shape stored in `tool.auth.value`. Two
//! deserialization shapes are accepted to keep M0/M1 configs working:
//!
//! - **Legacy plain string** (`value: "Bearer ${TOKEN}"`) → `LegacyString`.
//!   Resolved via the textual `${VAR}` expander, with a one-shot INF-24
//!   deprecation warning per field.
//! - **Tagged map** (`value: { from_env: { var: "TOKEN" } }`) → typed
//!   variant. No textual expansion; the variant carries the resolution
//!   contract.
//!
//! At daemon startup the `SecretBackend` registry walks every tool's
//! `auth.value` once and produces a per-tool resolved `SecretString` map
//! that the proxy hot path reads. Unresolved tools are degraded
//! (inactive) per INF-4 / Q-17 — never fail-closed for a single tool's
//! misconfig if other tools resolve.

pub mod aws;
pub mod backend;
pub mod env;
pub mod file_sealed;
pub mod vault;

pub use aws::AwsSecretsManagerBackend;
pub use backend::{BackendError, SecretBackend, SecretResolver};
pub use env::EnvBackend;
pub use file_sealed::FileSealedBackend;
pub use vault::VaultBackend;

use std::collections::HashMap;
use tracing::warn;

/// Map of `tool.name` → resolved credential, produced once at startup.
/// Daemon owns one `Arc<ArcSwap<ResolvedCreds>>` and shares it with
/// proxy + admin so both surfaces see the same view.
pub type ResolvedCreds = HashMap<String, SecretString>;

/// Async resolver for the daemon path. Walks every tool's auth.value
/// through the supplied `SecretResolver`. Tools whose credential fails
/// to resolve are **omitted from the map** — degraded-mode per INF-4
/// / Q-17. Caller decides whether absence is fatal (fail-closed) or
/// degraded (tool inactive but daemon up).
pub async fn resolve_tool_creds(
    config: &crate::config::AppConfig,
    resolver: &SecretResolver,
) -> ResolvedCreds {
    let mut out = HashMap::new();
    for tool in &config.tools {
        let Some(auth) = &tool.auth else {
            continue;
        };
        match resolver.resolve(&auth.value).await {
            Ok(value) => {
                if !secrecy::ExposeSecret::expose_secret(&value).is_empty() {
                    out.insert(tool.name.clone(), value);
                } else {
                    warn!(
                        tool = %tool.name,
                        "tool credential resolved to empty string; tool will be inactive"
                    );
                }
            }
            Err(e) => {
                warn!(
                    tool = %tool.name,
                    error = %e,
                    secret_ref = %auth.value,
                    "tool credential failed to resolve; tool will be inactive"
                );
            }
        }
    }
    out
}

/// Phase E.6 — resolve env-var references in a registrations
/// catalog into the same `ResolvedCreds` shape used by config.tools.
/// Walks every entry; for `AuthSpec::Header { env_var, .. }` and
/// `AuthSpec::Bearer { env_var, .. }`, reads the env var and inserts under
/// the registration's name. Empty values and missing vars are
/// skipped (proxy hot path treats absence as "tool inactive" same
/// as for config.tools). `AuthSpec::None` entries skip credential
/// resolution entirely — the proxy path handles them via the
/// AuthSpec dispatch.
///
/// v2.0.0 deliberately limits AuthSpec to env-var indirection. Sealed
/// file / Vault / AWS richness lives only on `tool.auth.value`
/// (config.tools) for now; v0.3 lifts that limitation.
pub fn resolve_registration_creds_sync_env_only(
    catalog: &crate::registrations::Catalog,
) -> ResolvedCreds {
    use crate::registrations::AuthSpec;
    use crate::registrations::Kind;
    let mut out = HashMap::new();
    for kind in [Kind::Tool, Kind::Model, Kind::Infra] {
        for r in catalog.iter_enabled_by_kind(kind) {
            let env_var = match &r.auth {
                AuthSpec::None => continue,
                AuthSpec::Header { env_var, .. } => env_var,
                AuthSpec::Bearer { env_var, .. } => env_var,
                // OAuth variants don't resolve via env-var indirection — their
                // tokens live in the oauth_sessions cache, populated by the
                // bootstrap CLI (Phase F.4) and refreshed by the daemon's
                // background task (Phase F.3). Skip here.
                AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. } => continue,
            };
            let Ok(value) = std::env::var(env_var) else {
                warn!(
                    name = %r.name,
                    env_var = %env_var,
                    "registration credential env var not set; tool will be inactive"
                );
                continue;
            };
            if value.is_empty() {
                warn!(
                    name = %r.name,
                    env_var = %env_var,
                    "registration credential env var is empty; tool will be inactive"
                );
                continue;
            }
            out.insert(r.name.clone(), SecretString::from(value));
        }
    }
    out
}

/// Sync resolver for non-daemon code paths (test helpers,
/// `build_app_with_audit` convenience). Only handles `LegacyString`
/// and `FromEnv` variants — sealed / vault / aws are skipped silently
/// (they need the async path with a configured backend). M0/M1
/// configs work unchanged through this entry.
pub fn resolve_tool_creds_sync_env_only(config: &crate::config::AppConfig) -> ResolvedCreds {
    let backend = EnvBackend::new();
    let mut out = HashMap::new();
    for tool in &config.tools {
        let Some(auth) = &tool.auth else {
            continue;
        };
        let resolved = match &auth.value {
            SecretRef::Inline(s) => Some(s.clone()),
            SecretRef::LegacyString(_) | SecretRef::FromEnv { .. } => {
                backend.resolve_sync(&auth.value).ok()
            }
            // Skip variants that need the async path; those tools
            // become inactive in the sync convenience path.
            _ => None,
        };
        if let Some(value) = resolved
            && !secrecy::ExposeSecret::expose_secret(&value).is_empty()
        {
            out.insert(tool.name.clone(), value);
        }
    }
    out
}

use secrecy::SecretString;
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::path::PathBuf;

/// A reference to a secret, deserialized from operator-supplied YAML.
///
/// Variants:
/// - `Inline` is post-resolution only — never deserialized directly.
///   Daemon code that constructs a fully-resolved config (e.g. for
///   tests) can build it with `SecretRef::inline(...)`.
/// - `LegacyString` is the M0/M1 path. Carries the raw text; the
///   `EnvBackend` does `${VAR}` expansion at resolve time.
/// - `FromEnv`, `FromFileSealed` are M5 production paths.
/// - `FromVault`, `FromAwsSecretsManager` are stubs (T5.3) — backends
///   exist but `resolve()` returns `BackendError::NotImplemented`.
#[derive(Debug, Clone)]
pub enum SecretRef {
    Inline(SecretString),
    LegacyString(String),
    FromEnv {
        var: String,
        prefix: Option<String>,
    },
    FromFileSealed {
        path: PathBuf,
    },
    FromVault {
        mount: String,
        path: String,
        field: String,
    },
    FromAwsSecretsManager {
        secret_id: String,
        version_stage: Option<String>,
        field: Option<String>,
    },
}

impl SecretRef {
    /// Construct a fully-resolved inline reference. Used by tests and
    /// by post-resolve code that wants to swap a raw form for a
    /// resolved one.
    pub fn inline(value: SecretString) -> Self {
        Self::Inline(value)
    }

    /// True iff this ref carries a resolved value (Inline) or carries
    /// a non-empty legacy string. Used by the M2 admin tool listing
    /// (`credential_present`) — it should report tools whose value
    /// will resolve to something.
    pub fn looks_present(&self) -> bool {
        match self {
            Self::Inline(s) => !secrecy::ExposeSecret::expose_secret(s).is_empty(),
            Self::LegacyString(s) => !s.is_empty(),
            // Typed variants are "present" structurally — actual
            // resolution success is reported by the resolver.
            _ => true,
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(_) => f.write_str("<inline>"),
            Self::LegacyString(_) => f.write_str("<legacy_string>"),
            Self::FromEnv { var, .. } => write!(f, "from_env({var})"),
            Self::FromFileSealed { path } => write!(f, "from_file_sealed({})", path.display()),
            Self::FromVault { mount, path, field } => {
                write!(f, "from_vault({mount}/{path}#{field})")
            }
            Self::FromAwsSecretsManager { secret_id, .. } => {
                write!(f, "from_aws_secrets_manager({secret_id})")
            }
        }
    }
}

// Custom Deserialize: accept either a plain string (legacy) or a
// single-key tagged map (typed). The map is rejected if it has an
// unknown tag or more than one key.
impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SecretRefVisitor)
    }
}

struct SecretRefVisitor;

impl<'de> serde::de::Visitor<'de> for SecretRefVisitor {
    type Value = SecretRef;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "either a plain string (legacy form) or a single-key tagged map: \
             from_env / from_file_sealed / from_vault / from_aws_secrets_manager",
        )
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(SecretRef::LegacyString(v.to_string()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(SecretRef::LegacyString(v))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let key: String = map
            .next_key()?
            .ok_or_else(|| serde::de::Error::custom("expected one of from_env / from_file_sealed / from_vault / from_aws_secrets_manager"))?;

        let value = match key.as_str() {
            "from_env" => {
                let v: FromEnvForm = map.next_value()?;
                SecretRef::FromEnv {
                    var: v.var,
                    prefix: v.prefix,
                }
            }
            "from_file_sealed" => {
                let v: FromFileSealedForm = map.next_value()?;
                SecretRef::FromFileSealed { path: v.path }
            }
            "from_vault" => {
                let v: FromVaultForm = map.next_value()?;
                SecretRef::FromVault {
                    mount: v.mount,
                    path: v.path,
                    field: v.field,
                }
            }
            "from_aws_secrets_manager" => {
                let v: FromAwsForm = map.next_value()?;
                SecretRef::FromAwsSecretsManager {
                    secret_id: v.secret_id,
                    version_stage: v.version_stage,
                    field: v.field,
                }
            }
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown SecretRef variant tag: {other}"
                )));
            }
        };

        // No second key permitted.
        if let Some(extra) = map.next_key::<String>()? {
            return Err(serde::de::Error::custom(format!(
                "SecretRef map must have exactly one key; found extra key {extra}"
            )));
        }
        Ok(value)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FromEnvForm {
    var: String,
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FromFileSealedForm {
    path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FromVaultForm {
    mount: String,
    path: String,
    field: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FromAwsForm {
    secret_id: String,
    #[serde(default)]
    version_stage: Option<String>,
    #[serde(default)]
    field: Option<String>,
}
