//! Authentication shape for a registration (wire + DB form).
//!
//! Locked at devloop `phase-e-catalog-substrate` Design phase. Extended at
//! Phase F (OAuth — see ADR-0005).
//!
//! Five variants, internally tagged on `kind`:
//!
//!   `none`              — no auth header injection. Required to be explicit for
//!                         `kind=tool` (implicit absence is rejected at register-time,
//!                         closing the "operator forgot the API key" footgun).
//!                         `kind=model` accepts `none` for LAN-local self-hosted
//!                         inference (Ollama, LM Studio) but rejects implicit absence.
//!   `header`            — inject `<header>: <env-var-resolved-value>`. Used for
//!                         `x-api-key`, custom headers, internal middleware tokens.
//!                         `force_replace` makes an unresolved credential fail
//!                         closed instead of forwarding without injection.
//!   `bearer`            — inject `Authorization: Bearer <env-var-resolved-value>`.
//!                         The `Bearer ` prefix is supplied by the runtime materializer,
//!                         not stored in the env var. `force_replace` has the
//!                         same fail-closed semantics as `header`.
//!   `oauth_pkce`        — OAuth 2.0 with PKCE (Proof Key for Code Exchange). First-time
//!                         auth via browser redirect; subsequent calls use the cached
//!                         access token (refreshed transparently by the daemon). See
//!                         ADR-0005 D1.
//!   `oauth_device_code` — OAuth 2.0 with device-code flow. First-time auth prints a
//!                         user_code + verification URL, polls the token endpoint for
//!                         completion. Used by codex / copilot / qwen-cli. See ADR-0005 D1.
//!
//! Static-credential variants (`none` / `header` / `bearer`) carry env-var **names**
//! only; translation to [`crate::secret::SecretRef`] happens at materialize-time.
//! OAuth variants carry public client metadata only — no secrets in the wire/DB
//! form. The actual refresh + access tokens live in the `oauth_sessions` table
//! sealed via AES-GCM (ADR-0005 D2).
//!
//! Sealed-cred-on-disk (`from_file_sealed:`) and external backends (Vault,
//! AWS Secrets Manager) remain accessible via the deprecated pre-Phase-E
//! bootstrap-from-yaml path until v0.3 removes it.

use crate::secret::SecretRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthSpec {
    None,
    Header {
        header: String,
        env_var: String,
        #[serde(default, skip_serializing_if = "is_false")]
        force_replace: bool,
    },
    Bearer {
        env_var: String,
        #[serde(default, skip_serializing_if = "is_false")]
        force_replace: bool,
    },
    /// OAuth 2.0 PKCE flow (RFC 7636). Used by anthropic-oauth,
    /// google-gemini-cli. First-time auth opens a browser to `auth_url`
    /// with a code-challenge; the operator-host loopback receives the
    /// auth code; daemon exchanges it at `token_url` and seals the
    /// refresh token in `oauth_sessions`.
    OauthPkce {
        client_id: String,
        /// Loopback URI the daemon's bootstrap CLI listens on.
        /// Conventionally `http://127.0.0.1:<port>/callback` with port
        /// chosen at bootstrap time.
        redirect_uri: String,
        scopes: Vec<String>,
        auth_url: String,
        token_url: String,
        /// Phase G: optional OAuth session label. Meaningful only on
        /// `agent_credential_overrides` rows — points the proxy hot
        /// path at a specific session under the registration's name.
        /// `None` (the default) means "use the
        /// [`crate::oauth::session::DEFAULT_SESSION_LABEL`] session"
        /// — the only label that exists on default-shaped catalogs.
        /// Always `None` on registration rows themselves; only set
        /// when an override redirects an agent to a non-default
        /// session.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_label: Option<String>,
    },
    /// OAuth 2.0 device-code flow (RFC 8628). Used by codex (ChatGPT
    /// Plus), GitHub Copilot, qwen-cli. First-time auth prints a
    /// user_code + verification URL; daemon polls `token_url` until the
    /// user completes the auth in a browser elsewhere.
    OauthDeviceCode {
        client_id: String,
        scopes: Vec<String>,
        device_url: String,
        token_url: String,
        /// Phase G: see [`AuthSpec::OauthPkce::session_label`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_label: Option<String>,
    },
}

impl AuthSpec {
    /// True iff this auth shape ever injects a header on a proxied
    /// request. OAuth variants return `true` because the daemon
    /// injects `Authorization: Bearer <access_token>` after refreshing
    /// the token cache.
    pub fn injects_header(&self) -> bool {
        !matches!(self, AuthSpec::None)
    }

    /// True iff this auth shape uses the OAuth flow (either PKCE or
    /// device-code). The proxy hot path treats OAuth distinctly from
    /// static-credential variants: it reads access tokens from the
    /// `oauth_sessions` cache rather than the static `resolved_creds`
    /// map, and triggers refresh-on-401-then-retry.
    pub fn is_oauth(&self) -> bool {
        matches!(
            self,
            AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. }
        )
    }

    /// Phase G: the OAuth session label this AuthSpec resolves to.
    /// `None` for non-OAuth variants. For OAuth variants, returns the
    /// custom label if one was set on the spec, else `None` to signal
    /// "fall back to [`crate::oauth::session::DEFAULT_SESSION_LABEL`]".
    /// Callers should resolve via `.session_label_or_default()`.
    pub fn oauth_session_label(&self) -> Option<&str> {
        match self {
            AuthSpec::OauthPkce { session_label, .. }
            | AuthSpec::OauthDeviceCode { session_label, .. } => session_label.as_deref(),
            _ => None,
        }
    }

    /// OAuth session label to actually use at hot-path resolution
    /// time, with `DEFAULT_SESSION_LABEL` as the fallback. Returns
    /// `None` for non-OAuth variants.
    pub fn session_label_or_default(&self) -> Option<&str> {
        if !self.is_oauth() {
            return None;
        }
        Some(
            self.oauth_session_label()
                .unwrap_or(crate::oauth::session::DEFAULT_SESSION_LABEL),
        )
    }

    /// Translate to a runtime [`SecretRef`] for the static-credential
    /// resolver. `None` and OAuth variants return `None` (they do not
    /// resolve via env-var indirection); `Header` / `Bearer` produce
    /// `SecretRef::FromEnv` with the variant's `env_var`.
    ///
    /// The `Bearer ` prefix is NOT added here — the proxy-side header
    /// injection adds it. Storing the prefix in the env var would
    /// contradict the canonical "the env var holds just the token"
    /// convention.
    pub fn to_secret_ref(&self) -> Option<SecretRef> {
        match self {
            AuthSpec::None | AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. } => None,
            AuthSpec::Header { env_var, .. } | AuthSpec::Bearer { env_var, .. } => {
                Some(SecretRef::FromEnv {
                    var: env_var.clone(),
                    prefix: None,
                })
            }
        }
    }

    /// Static auth registrations can opt into fail-closed replacement:
    /// if the configured credential cannot be resolved, Locksmith returns
    /// a 503 instead of forwarding the agent's placeholder credential or
    /// an unauthenticated upstream request.
    pub fn force_replace(&self) -> bool {
        match self {
            AuthSpec::Header { force_replace, .. } | AuthSpec::Bearer { force_replace, .. } => {
                *force_replace
            }
            AuthSpec::None | AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. } => false,
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}
